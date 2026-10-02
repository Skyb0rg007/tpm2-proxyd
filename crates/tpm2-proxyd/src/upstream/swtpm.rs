// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! Upstream transport backed by a swtpm software TPM.
//!
//! [`swtpm`](https://github.com/stefanberger/swtpm) exposes a TPM over two
//! sockets:
//!
//! - a **data channel** carrying the raw, self-framing TPM command/response byte
//!   stream (exactly what the proxy forwards), and
//! - a **control channel** for management commands, each a fresh connection
//!   carrying `[command code: u32 BE][payload]` and answered with
//!   `[result code: u32 BE][payload]`.
//!
//! Both may be Unix-domain (`type=unixio`) or TCP (`type=tcp`) sockets. Unlike
//! the kernel resource manager, swtpm speaks plain sockets, so this upstream is
//! fully async and needs no worker thread; the data connection is reconnected
//! after any I/O error or timeout so a desynchronized stream is never reused.
//!
//! swtpm has no resource manager, so every client shares the one TPM: sessions
//! are not isolated here, and transient objects are not flushed on disconnect.

use std::path::PathBuf;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};

use crate::tpm::{self, Command, HEADER_SIZE, Response};
use crate::upstream::{SessionId, Upstream, UpstreamError};

/// swtpm control command: initialize the TPM (`CMD_INIT`).
const CMD_INIT: u32 = 0x02;

/// A swtpm socket address, either a Unix path or a TCP `host:port`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SwtpmAddr {
    /// Unix-domain socket path (swtpm `type=unixio`).
    Unix(PathBuf),
    /// TCP `host:port` (swtpm `type=tcp`).
    Tcp(String),
}

impl SwtpmAddr {
    /// Parse an address from a CLI string.
    ///
    /// `unix:<path>` / `tcp:<host:port>` are explicit; otherwise a value
    /// containing `/` is treated as a Unix path and anything else as `host:port`.
    pub fn parse(value: &str) -> Self {
        if let Some(path) = value.strip_prefix("unix:") {
            Self::Unix(PathBuf::from(path))
        } else if let Some(hostport) = value.strip_prefix("tcp:") {
            Self::Tcp(hostport.to_owned())
        } else if value.contains('/') {
            Self::Unix(PathBuf::from(value))
        } else {
            Self::Tcp(value.to_owned())
        }
    }
}

impl std::fmt::Display for SwtpmAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unix(path) => write!(f, "unix:{}", path.display()),
            Self::Tcp(hostport) => write!(f, "tcp:{hostport}"),
        }
    }
}

/// Any byte stream usable as a swtpm channel.
trait Channel: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Channel for T {}

async fn connect(addr: &SwtpmAddr) -> std::io::Result<Box<dyn Channel>> {
    match addr {
        SwtpmAddr::Unix(path) => Ok(Box::new(UnixStream::connect(path).await?)),
        SwtpmAddr::Tcp(hostport) => Ok(Box::new(TcpStream::connect(hostport).await?)),
    }
}

/// Upstream transport that forwards commands to a swtpm instance.
pub struct SwtpmUpstream {
    server: SwtpmAddr,
    data: Option<Box<dyn Channel>>,
    timeout: Duration,
    max_response_size: usize,
}

impl SwtpmUpstream {
    /// Connect to a swtpm `server` data socket.
    ///
    /// When a `control` address is given, the swtpm is reset on startup
    /// (`CMD_INIT` followed by a `TPM2_Startup(CLEAR)`), leaving a clean, started
    /// TPM. Omit it to pass commands straight through to an already-running swtpm
    /// (started e.g. with `--flags startup-clear`). `timeout` bounds each
    /// transaction.
    pub async fn open(
        server: SwtpmAddr,
        control: Option<SwtpmAddr>,
        max_response_size: usize,
        timeout: Duration,
    ) -> Result<Self, SwtpmError> {
        let mut data = connect(&server).await.map_err(SwtpmError::Connect)?;

        if let Some(control) = control {
            let code = control_command(&control, CMD_INIT, &0u32.to_be_bytes(), timeout).await?;
            if code != 0 {
                return Err(SwtpmError::Control {
                    command: CMD_INIT,
                    code,
                });
            }
            // CMD_INIT runs `_TPM_Init`, leaving the TPM awaiting `TPM2_Startup`.
            // Downstream clients assume an already-started TPM (as they get from
            // the kernel resource manager), so bring it up here.
            startup(data.as_mut(), max_response_size, timeout).await?;
        }

        Ok(Self {
            server,
            data: Some(data),
            timeout,
            max_response_size,
        })
    }
}

impl Upstream for SwtpmUpstream {
    async fn transact(
        &mut self,
        _session: SessionId,
        command: &Command,
    ) -> Result<Response, UpstreamError> {
        if self.data.is_none() {
            let data = connect(&self.server)
                .await
                .map_err(UpstreamError::transport)?;
            self.data = Some(data);
        }
        let data = self.data.as_mut().expect("connected above");

        let exchanged = tokio::time::timeout(
            self.timeout,
            exchange(data.as_mut(), command.as_bytes(), self.max_response_size),
        )
        .await;

        let bytes = match exchanged {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(error)) => {
                // Drop the connection so the next command starts from a clean,
                // re-synchronized stream.
                self.data = None;
                return Err(UpstreamError::transport(error));
            }
            Err(_elapsed) => {
                self.data = None;
                return Err(UpstreamError::transport(SwtpmError::Timeout));
            }
        };

        Response::parse(bytes, self.max_response_size).map_err(Into::into)
    }
}

/// Write one command and read its complete, self-framed response.
async fn exchange<S: AsyncRead + AsyncWrite + Unpin + ?Sized>(
    data: &mut S,
    command: &[u8],
    max_response_size: usize,
) -> Result<Vec<u8>, SwtpmError> {
    data.write_all(command).await.map_err(SwtpmError::Io)?;
    data.flush().await.map_err(SwtpmError::Io)?;

    let mut header = [0u8; HEADER_SIZE];
    data.read_exact(&mut header).await.map_err(SwtpmError::Io)?;
    let size =
        tpm::packet_size_from_header(&header, max_response_size).map_err(SwtpmError::Malformed)?;

    let mut bytes = vec![0u8; size];
    bytes[..HEADER_SIZE].copy_from_slice(&header);
    data.read_exact(&mut bytes[HEADER_SIZE..])
        .await
        .map_err(SwtpmError::Io)?;
    Ok(bytes)
}

/// Send `TPM2_Startup(SU_CLEAR)` to bring a freshly initialized TPM up.
async fn startup<S: AsyncRead + AsyncWrite + Unpin + ?Sized>(
    data: &mut S,
    max_response_size: usize,
    timeout: Duration,
) -> Result<(), SwtpmError> {
    // tag = TPM_ST_NO_SESSIONS, size = 12, TPM_CC_Startup, TPM_SU_CLEAR.
    const STARTUP_CLEAR: [u8; 12] = [0x80, 0x01, 0, 0, 0, 0x0c, 0, 0, 0x01, 0x44, 0, 0];
    const TPM_RC_INITIALIZE: u32 = 0x100;

    let response = tokio::time::timeout(timeout, exchange(data, &STARTUP_CLEAR, max_response_size))
        .await
        .map_err(|_| SwtpmError::Timeout)??;

    let code = u32::from_be_bytes(
        response[6..10]
            .try_into()
            .expect("validated 10-byte header"),
    );
    // Success, or already started (e.g. when swtpm ran its own `startup-clear`).
    if code != 0 && code != TPM_RC_INITIALIZE {
        return Err(SwtpmError::Startup { code });
    }
    Ok(())
}

/// Run one swtpm control command on a fresh connection, returning its code.
async fn control_command(
    addr: &SwtpmAddr,
    command: u32,
    payload: &[u8],
    timeout: Duration,
) -> Result<u32, SwtpmError> {
    let run = async {
        let mut socket = connect(addr).await.map_err(SwtpmError::Connect)?;
        let mut request = Vec::with_capacity(size_of::<u32>() + payload.len());
        request.extend_from_slice(&command.to_be_bytes());
        request.extend_from_slice(payload);
        socket.write_all(&request).await.map_err(SwtpmError::Io)?;
        socket.flush().await.map_err(SwtpmError::Io)?;

        let mut code = [0u8; size_of::<u32>()];
        socket.read_exact(&mut code).await.map_err(SwtpmError::Io)?;
        Ok(u32::from_be_bytes(code))
    };
    tokio::time::timeout(timeout, run)
        .await
        .map_err(|_| SwtpmError::Timeout)?
}

/// Failure while talking to swtpm.
#[derive(Debug, thiserror::Error)]
pub enum SwtpmError {
    /// Connecting to a swtpm socket failed.
    #[error("failed to connect to swtpm socket: {0}")]
    Connect(#[source] std::io::Error),
    /// A swtpm socket I/O operation failed.
    #[error("swtpm socket I/O failed: {0}")]
    Io(#[source] std::io::Error),
    /// swtpm returned a malformed response header.
    #[error("swtpm returned a malformed response: {0}")]
    Malformed(#[source] crate::tpm::ParseError),
    /// `TPM2_Startup` after `CMD_INIT` returned a TPM error code.
    #[error("swtpm TPM2_Startup failed with code {code:#x}")]
    Startup {
        /// TPM response code.
        code: u32,
    },
    /// A swtpm control command returned a non-zero result code.
    #[error("swtpm control command {command:#x} failed with code {code:#x}")]
    Control {
        /// Control command code that failed.
        command: u32,
        /// Non-zero result code returned by swtpm.
        code: u32,
    },
    /// A swtpm transaction exceeded the configured timeout.
    #[error("swtpm transaction timed out")]
    Timeout,
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    };

    use tokio::net::UnixListener;

    use crate::testing::{command, echo_response};

    fn temp_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "tpm2-proxyd-swtpm-{}-{tag}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ))
    }

    /// Minimal fake swtpm data channel: read each self-framed command, reply with
    /// a success response echoing the command code into the body.
    fn serve_data(listener: UnixListener) {
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            loop {
                let mut header = [0u8; HEADER_SIZE];
                if stream.read_exact(&mut header).await.is_err() {
                    return;
                }
                let size = u32::from_be_bytes(header[2..6].try_into().unwrap()) as usize;
                let mut body = vec![0u8; size - HEADER_SIZE];
                stream.read_exact(&mut body).await.unwrap();
                let code = u32::from_be_bytes(header[6..10].try_into().unwrap());
                stream.write_all(&echo_response(code)).await.unwrap();
            }
        });
    }

    #[tokio::test]
    async fn forwards_commands_over_the_data_channel() {
        let path = temp_path("data");
        serve_data(UnixListener::bind(&path).unwrap());

        let mut upstream = SwtpmUpstream::open(
            SwtpmAddr::Unix(path.clone()),
            None,
            4096,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        let reply = upstream
            .transact(SessionId(0), &command(0x17b, &[]))
            .await
            .unwrap();
        assert_eq!(reply.as_bytes(), echo_response(0x17b));
        let reply = upstream
            .transact(SessionId(0), &command(0x17a, &[]))
            .await
            .unwrap();
        assert_eq!(reply.as_bytes(), echo_response(0x17a));

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn sends_cmd_init_on_the_control_channel() {
        let data_path = temp_path("init-data");
        let ctrl_path = temp_path("init-ctrl");
        serve_data(UnixListener::bind(&data_path).unwrap());

        // Fake control channel: record the command code, reply with success (0).
        let seen = Arc::new(AtomicU32::new(0));
        let ctrl_listener = UnixListener::bind(&ctrl_path).unwrap();
        let recorder = seen.clone();
        tokio::spawn(async move {
            let (mut stream, _) = ctrl_listener.accept().await.unwrap();
            let mut code = [0u8; 4];
            stream.read_exact(&mut code).await.unwrap();
            recorder.store(u32::from_be_bytes(code), Ordering::SeqCst);
            stream.write_all(&0u32.to_be_bytes()).await.unwrap();
        });

        let _upstream = SwtpmUpstream::open(
            SwtpmAddr::Unix(data_path.clone()),
            Some(SwtpmAddr::Unix(ctrl_path.clone())),
            4096,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        assert_eq!(seen.load(Ordering::SeqCst), CMD_INIT);

        let _ = std::fs::remove_file(&data_path);
        let _ = std::fs::remove_file(&ctrl_path);
    }

    #[test]
    fn parses_addresses() {
        assert_eq!(
            SwtpmAddr::parse("/run/swtpm/sock"),
            SwtpmAddr::Unix(PathBuf::from("/run/swtpm/sock"))
        );
        assert_eq!(
            SwtpmAddr::parse("unix:relative.sock"),
            SwtpmAddr::Unix(PathBuf::from("relative.sock"))
        );
        assert_eq!(
            SwtpmAddr::parse("localhost:2321"),
            SwtpmAddr::Tcp("localhost:2321".to_owned())
        );
        assert_eq!(
            SwtpmAddr::parse("tcp:127.0.0.1:2321"),
            SwtpmAddr::Tcp("127.0.0.1:2321".to_owned())
        );
    }
}
