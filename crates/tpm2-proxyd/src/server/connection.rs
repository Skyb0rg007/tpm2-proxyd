// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! Listener-independent downstream TPM command handling.
//!
//! [`serve_listener`] accepts [`ClientStream`] values from a [`Listener`],
//! runs each connection's hello, then serves its TPM commands. Neither API
//! assumes Unix sockets or TCP.

#![allow(dead_code)] // Wired into main once daemon construction is implemented.

use std::{future::Future, io, time::Duration};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::{
    broker::{Broker, BrokerError, Client},
    scheduler::Priority,
    server::{
        hello::{self, Hello, HelloStatus},
        peer::Peer,
        registry::ConnectionRegistry,
    },
    tpm::{self, Command, Response},
};

/// How long shutdown waits for in-flight connections to drain before aborting.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

/// How long to pause accepting after running out of file descriptors or
/// memory, so connections in flight can release some.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// How long a new connection has to send its hello.
pub(crate) const HELLO_TIMEOUT: Duration = Duration::from_secs(10);

/// A connected client capable of exchanging the hello and framed TPM packets.
pub trait ClientStream: Send + 'static {
    /// Read the client's hello.
    fn read_hello(&mut self) -> impl Future<Output = io::Result<Hello>> + Send;

    /// Answer the client's hello with a status and the granted priority.
    fn write_hello_reply(
        &mut self,
        status: HelloStatus,
        priority: Priority,
    ) -> impl Future<Output = io::Result<()>> + Send;

    /// Read the next command, or `None` for a clean EOF between commands.
    fn read_command(
        &mut self,
        max_command_size: usize,
    ) -> impl Future<Output = io::Result<Option<Command>>> + Send;

    /// Write one complete TPM response.
    fn write_response(
        &mut self,
        response: &Response,
    ) -> impl Future<Output = io::Result<()>> + Send;
}

impl<T> ClientStream for T
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    async fn read_hello(&mut self) -> io::Result<Hello> {
        let mut bytes = [0; hello::SIZE];
        self.read_exact(&mut bytes).await?;
        Hello::parse(bytes)
    }

    async fn write_hello_reply(
        &mut self,
        status: HelloStatus,
        priority: Priority,
    ) -> io::Result<()> {
        self.write_all(&status.reply(priority)).await?;
        self.flush().await
    }

    async fn read_command(&mut self, max_command_size: usize) -> io::Result<Option<Command>> {
        tpm::read_command(self, max_command_size).await
    }

    async fn write_response(&mut self, response: &Response) -> io::Result<()> {
        self.write_all(response.as_bytes()).await?;
        self.flush().await
    }
}

/// Stream accepted from a listener and the identity of its peer.
pub struct Accepted<S> {
    /// Connected client transport.
    pub stream: S,
    /// Authenticated identity used for policy decisions.
    pub peer: Peer,
}

/// Abstract source of admitted client connections.
pub trait Listener {
    /// Transport produced by this listener.
    type Stream: ClientStream;

    /// Accept and admit one client.
    ///
    /// Errors are the listener's own, as `accept` reports them. A listener that
    /// can't admit one particular client (for example, because it can't read
    /// the client's credentials) drops that client and keeps accepting.
    fn accept(&mut self) -> impl Future<Output = io::Result<Accepted<Self::Stream>>> + Send;
}

/// Low-level listener that yields a Tokio byte stream.
pub trait TokioListener {
    /// Connected Tokio stream type.
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    /// Accept one raw stream.
    fn accept_stream(&mut self) -> impl Future<Output = io::Result<Self::Stream>> + Send;
}

impl TokioListener for tokio::net::UnixListener {
    type Stream = tokio::net::UnixStream;

    async fn accept_stream(&mut self) -> io::Result<Self::Stream> {
        self.accept().await.map(|(stream, _)| stream)
    }
}

impl TokioListener for tokio::net::TcpListener {
    type Stream = tokio::net::TcpStream;

    async fn accept_stream(&mut self) -> io::Result<Self::Stream> {
        self.accept().await.map(|(stream, _)| stream)
    }
}

/// Test adapter for listeners whose clients share one static identity.
///
/// Transports that authenticate each peer implement [`Listener`] directly.
pub struct RawListener<L> {
    inner: L,
    peer: Peer,
}

impl<L> RawListener<L> {
    /// Wrap `inner`, assigning the supplied admission context to every client.
    ///
    /// This is intended for trusted/local raw listeners. Transports that
    /// authenticate each peer should implement [`Listener`] directly.
    pub fn new(inner: L, peer: Peer) -> Self {
        Self { inner, peer }
    }

    /// Recover the wrapped listener.
    pub fn into_inner(self) -> L {
        self.inner
    }
}

impl<L> Listener for RawListener<L>
where
    L: TokioListener + Send,
{
    type Stream = L::Stream;

    async fn accept(&mut self) -> io::Result<Accepted<Self::Stream>> {
        Ok(Accepted {
            stream: self.inner.accept_stream().await?,
            peer: self.peer.clone(),
        })
    }
}

/// Accept clients until shutdown and run each connection in its own task.
///
/// Client tasks only exchange the hello, parse, authorize, enqueue, and return
/// responses. The scheduler worker behind [`Broker`] remains the sole owner of
/// the upstream TCTI.
///
/// A failed `accept` stops the server only when the listening socket itself is
/// unusable; open connections are drained before the error is returned. Any
/// other failure is logged and accepting continues.
pub async fn serve_listener<L>(
    mut listener: L,
    broker: Broker,
    registry: ConnectionRegistry,
    max_command_size: usize,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<()>
where
    L: Listener,
{
    let mut tasks: JoinSet<()> = JoinSet::new();
    let mut result = Ok(());
    // Connections stop on the caller's shutdown or when the listener fails.
    let (stop, stopped) = watch::channel(false);

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                // The sender was dropped or signalled shutdown: stop accepting.
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let accepted = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => match AcceptFailure::of(&error) {
                        AcceptFailure::Fatal => {
                            result = Err(error);
                            break;
                        }
                        AcceptFailure::Exhausted => {
                            tracing::warn!(%error, "failed to accept a connection; pausing");
                            tokio::time::sleep(ACCEPT_BACKOFF).await;
                            continue;
                        }
                        AcceptFailure::Connection => {
                            tracing::debug!(%error, "failed to accept a connection");
                            continue;
                        }
                    },
                };
                let broker = broker.clone();
                let registry = registry.clone();
                let connection_shutdown = stopped.clone();
                tasks.spawn(async move {
                    if let Err(error) = serve_client(
                        accepted,
                        &broker,
                        &registry,
                        max_command_size,
                        connection_shutdown,
                    )
                    .await
                    {
                        tracing::debug!(%error, "downstream TPM connection closed with an error");
                    }
                });
            }
        }
    }

    let _ = stop.send(true);
    drain(tasks).await;
    result
}

/// How [`serve_listener`] treats a failed `accept`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AcceptFailure {
    /// The listening socket itself is unusable: stop serving.
    Fatal,
    /// Out of file descriptors or memory: pause, then keep accepting.
    Exhausted,
    /// A problem with the one connection being accepted: keep accepting.
    Connection,
}

impl AcceptFailure {
    fn of(error: &io::Error) -> Self {
        match error.raw_os_error() {
            Some(libc::EBADF | libc::EINVAL | libc::ENOTSOCK | libc::EFAULT) => Self::Fatal,
            Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM) => Self::Exhausted,
            _ => Self::Connection,
        }
    }
}

/// Wait for active connection tasks to finish, aborting any that outlast the
/// shutdown grace period. The tasks have been told to stop, so they stop after
/// their current in-flight command.
async fn drain(mut tasks: JoinSet<()>) {
    if tasks.is_empty() {
        return;
    }
    tracing::info!(active = tasks.len(), "draining active connections");
    let drained = tokio::time::timeout(SHUTDOWN_GRACE, async {
        while tasks.join_next().await.is_some() {}
    })
    .await;
    if drained.is_err() {
        tracing::warn!("shutdown grace period elapsed; aborting remaining connections");
        tasks.shutdown().await;
    }
}

/// Run one accepted connection: the hello, admission, then its commands.
///
/// The client has [`HELLO_TIMEOUT`] to send its hello. A connection is counted
/// against the registry's cap only once its hello is accepted.
async fn serve_client<S>(
    accepted: Accepted<S>,
    broker: &Broker,
    registry: &ConnectionRegistry,
    max_command_size: usize,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), ConnectionError>
where
    S: ClientStream,
{
    let Accepted { mut stream, peer } = accepted;

    let hello = tokio::select! {
        _ = shutdown.changed() => return Ok(()),
        hello = tokio::time::timeout(HELLO_TIMEOUT, stream.read_hello()) => {
            hello.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no hello received"))??
        }
    };
    if let Err(status) = hello.check() {
        stream.write_hello_reply(status, Priority(0)).await?;
        return Err(ConnectionError::Refused(status));
    }
    let _guard = match registry.register(peer.uid) {
        Ok(guard) => guard,
        Err(full) => {
            tracing::warn!(
                uid = peer.uid,
                pid = peer.pid,
                ?full,
                "connection limit reached; rejecting client"
            );
            stream
                .write_hello_reply(HelloStatus::Busy, Priority(0))
                .await?;
            return Err(ConnectionError::Refused(HelloStatus::Busy));
        }
    };
    let client = broker.admit(peer, hello.priority);
    stream
        .write_hello_reply(HelloStatus::Accepted, client.priority())
        .await?;

    serve_connection(stream, client, max_command_size, shutdown).await
}

/// Serve commands from one admitted client until EOF, shutdown, or failure.
///
/// A shutdown signal stops the connection at the next command boundary; a
/// command already in flight is allowed to finish (the TPM is non-preemptible).
pub async fn serve_connection<S>(
    mut stream: S,
    client: Client,
    max_command_size: usize,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), ConnectionError>
where
    S: ClientStream,
{
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            command = stream.read_command(max_command_size) => {
                match command? {
                    None => break,
                    Some(command) => {
                        let response = client.execute(command).await?;
                        stream.write_response(&response).await?;
                    }
                }
            }
        }
    }
    Ok(())
}

/// Failure while serving a downstream connection.
#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
    /// Downstream transport or packet framing failed.
    #[error("downstream I/O failed: {0}")]
    Io(#[from] io::Error),
    /// The server refused the client's hello.
    #[error("hello refused: {0:?}")]
    Refused(HelloStatus),
    /// Policy, scheduler, or upstream TCTI rejected the command.
    #[error("TPM command failed: {0}")]
    Broker(#[from] BrokerError),
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::{
        broker::Broker,
        policy::{Policy, PolicyConfig},
        scheduler::CommandScheduler,
        tpm::{DEFAULT_MAX_PACKET_SIZE, HEADER_SIZE},
        upstream::{SessionId, Upstream, UpstreamError},
    };

    use super::*;

    struct EchoUpstream {
        commands: Arc<Mutex<Vec<u32>>>,
    }

    #[async_trait::async_trait]
    impl Upstream for EchoUpstream {
        async fn transact(
            &mut self,
            _session: SessionId,
            command: &Command,
        ) -> Result<Response, UpstreamError> {
            self.commands.lock().unwrap().push(command.code().value());
            Ok(Response::parse(response(command.code().value()), DEFAULT_MAX_PACKET_SIZE).unwrap())
        }
    }

    fn command(code: u32) -> Vec<u8> {
        let mut command = Vec::from(0x8001u16.to_be_bytes());
        command.extend_from_slice(&10u32.to_be_bytes());
        command.extend_from_slice(&code.to_be_bytes());
        command
    }

    // A valid success response carrying the command code in its body, so the
    // routed-back response is identifiable.
    fn response(code: u32) -> Vec<u8> {
        let mut response = Vec::from(0x8001u16.to_be_bytes());
        response.extend_from_slice(&14u32.to_be_bytes());
        response.extend_from_slice(&0u32.to_be_bytes());
        response.extend_from_slice(&code.to_be_bytes());
        response
    }

    async fn read_packet(stream: &mut tokio::io::DuplexStream) -> Vec<u8> {
        let mut header = [0; HEADER_SIZE];
        stream.read_exact(&mut header).await.unwrap();
        let size = u32::from_be_bytes(header[2..6].try_into().unwrap()) as usize;
        let mut packet = vec![0; size];
        packet[..HEADER_SIZE].copy_from_slice(&header);
        stream.read_exact(&mut packet[HEADER_SIZE..]).await.unwrap();
        packet
    }

    #[tokio::test]
    async fn generic_stream_forwards_multiple_commands() {
        let commands = Arc::new(Mutex::new(Vec::new()));
        let scheduler = CommandScheduler::start(
            EchoUpstream {
                commands: commands.clone(),
            },
            8,
        );
        let broker = Broker::new(Policy::allow_all(), scheduler);
        let client_context = broker.admit(Peer::new(1000, 100), Priority(4));
        let (mut client, server) = tokio::io::duplex(256);
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);

        let server_task = tokio::spawn(serve_connection(
            server,
            client_context,
            DEFAULT_MAX_PACKET_SIZE,
            shutdown_rx,
        ));

        client.write_all(&command(0x17b)).await.unwrap();
        assert_eq!(read_packet(&mut client).await, response(0x17b));
        client.write_all(&command(0x17a)).await.unwrap();
        assert_eq!(read_packet(&mut client).await, response(0x17a));
        client.shutdown().await.unwrap();

        server_task.await.unwrap().unwrap();
        assert_eq!(*commands.lock().unwrap(), [0x17b, 0x17a]);
    }

    #[tokio::test]
    async fn denied_command_is_not_forwarded() {
        let commands = Arc::new(Mutex::new(Vec::new()));
        let scheduler = CommandScheduler::start(
            EchoUpstream {
                commands: commands.clone(),
            },
            8,
        );
        let broker = Broker::new(Policy::new(PolicyConfig::default()), scheduler);
        let client_context = broker.admit(Peer::new(1000, 100), Priority(4));
        let (mut client, server) = tokio::io::duplex(256);
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);

        let server_task = tokio::spawn(serve_connection(
            server,
            client_context,
            DEFAULT_MAX_PACKET_SIZE,
            shutdown_rx,
        ));

        client.write_all(&command(0x17b)).await.unwrap();
        assert!(matches!(
            server_task.await.unwrap(),
            Err(ConnectionError::Broker(BrokerError::Denied {
                command_code: 0x17b
            }))
        ));
        assert!(commands.lock().unwrap().is_empty());
    }

    /// Listener that replays scripted `accept` results, then waits forever.
    struct ScriptedListener(
        std::collections::VecDeque<io::Result<Accepted<tokio::io::DuplexStream>>>,
    );

    impl Listener for ScriptedListener {
        type Stream = tokio::io::DuplexStream;

        async fn accept(&mut self) -> io::Result<Accepted<Self::Stream>> {
            match self.0.pop_front() {
                Some(result) => result,
                None => std::future::pending().await,
            }
        }
    }

    fn accepted(stream: tokio::io::DuplexStream) -> io::Result<Accepted<tokio::io::DuplexStream>> {
        Ok(Accepted {
            stream,
            peer: Peer::new(1000, 100),
        })
    }

    fn start_serving(
        listener: ScriptedListener,
    ) -> (watch::Sender<bool>, tokio::task::JoinHandle<io::Result<()>>) {
        let scheduler = CommandScheduler::start(
            EchoUpstream {
                commands: Arc::default(),
            },
            8,
        );
        let broker = Broker::new(Policy::allow_all(), scheduler);
        let (shutdown, shutdown_rx) = watch::channel(false);
        let server = tokio::spawn(serve_listener(
            listener,
            broker,
            ConnectionRegistry::new(0, 0),
            DEFAULT_MAX_PACKET_SIZE,
            shutdown_rx,
        ));
        (shutdown, server)
    }

    #[tokio::test(start_paused = true)]
    async fn keeps_accepting_after_connection_and_resource_errors() {
        let (mut client, server_end) = tokio::io::duplex(256);
        let (shutdown, server) = start_serving(ScriptedListener(
            [
                Err(io::Error::from_raw_os_error(libc::ECONNABORTED)),
                Err(io::Error::from_raw_os_error(libc::EMFILE)),
                accepted(server_end),
            ]
            .into(),
        ));

        // The client accepted after both errors is served.
        client.write_all(b"TPXH\0\x01\0\0\0\0\0\x04").await.unwrap();
        let mut reply = [0u8; 12];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"TPXH\0\x01\0\0\0\0\0\x04");

        shutdown.send(true).unwrap();
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn stops_promptly_when_the_listening_socket_fails() {
        let (mut client, server_end) = tokio::io::duplex(256);
        let (_shutdown, server) = start_serving(ScriptedListener(
            [
                accepted(server_end),
                Err(io::Error::from_raw_os_error(libc::EBADF)),
            ]
            .into(),
        ));

        // The server returns the listener's error once its open connection has
        // been told to stop, well before the drain grace period would expire.
        let error = tokio::time::timeout(SHUTDOWN_GRACE / 2, server)
            .await
            .expect("server did not stop promptly")
            .unwrap()
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EBADF));

        // The open connection was closed rather than left running.
        let mut rest = Vec::new();
        client.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
    }
}
