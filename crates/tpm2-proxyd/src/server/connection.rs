// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! One client connection: the hello, admission, then its TPM commands.

use std::{io, time::Duration};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::watch;
use tpm2_protocol::data::TpmRcBase;

use crate::{
    broker::{Broker, BrokerError, Client},
    log_limit::{Kind, limited},
    peer::Peer,
    scheduler::Priority,
    server::{
        hello::{Hello, HelloStatus},
        registry::ConnectionRegistry,
    },
    tpm::{self, Response, resmgr_rc},
};

/// How long a new connection has to send its hello.
pub(crate) const HELLO_TIMEOUT: Duration = Duration::from_secs(10);

/// Run one accepted connection: the hello, admission, then its commands.
///
/// A connection counts against the registry's caps from the moment it's
/// accepted, so connections that never send a hello still use up their user's
/// slots rather than file descriptors without limit. One over a cap is
/// answered `Busy` straight away, without waiting for its hello. Otherwise the
/// client has [`HELLO_TIMEOUT`] to send its hello.
pub async fn serve_client(
    mut stream: impl AsyncRead + AsyncWrite + Unpin,
    peer: Peer,
    broker: &Broker,
    registry: &ConnectionRegistry,
    max_command_size: usize,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), ConnectionError> {
    let _guard = match registry.register(peer.uid) {
        Ok(guard) => guard,
        Err(full) => {
            limited!(
                warn,
                peer.uid,
                Kind::Busy,
                "connection limit reached; rejecting client",
                pid = peer.pid,
                ?full,
            );
            HelloStatus::Busy.reply(&mut stream, Priority(0)).await?;
            return Err(ConnectionError::Refused(HelloStatus::Busy));
        }
    };
    let hello = tokio::select! {
        _ = shutdown.changed() => return Ok(()),
        hello = tokio::time::timeout(HELLO_TIMEOUT, Hello::read(&mut stream)) => {
            hello.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no hello received"))??
        }
    };
    if let Err(status) = hello.check() {
        status.reply(&mut stream, Priority(0)).await?;
        return Err(ConnectionError::Refused(status));
    }
    let client = broker.admit(peer, hello.priority);
    HelloStatus::Accepted
        .reply(&mut stream, client.priority())
        .await?;

    serve_commands(stream, client, max_command_size, shutdown).await
}

/// Serve commands from one admitted client until EOF, shutdown, or failure.
///
/// A shutdown signal stops the connection at the next command boundary; a
/// command already in flight is allowed to finish (the TPM is non-preemptible).
async fn serve_commands(
    mut stream: impl AsyncRead + AsyncWrite + Unpin,
    client: Client,
    max_command_size: usize,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), ConnectionError> {
    loop {
        let command = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
                continue;
            }
            command = tpm::read_command(&mut stream, max_command_size) => command?,
        };
        let Some(command) = command else {
            return Ok(());
        };
        let response = match client.execute(command).await {
            Ok(response) => response,
            // The client gets an error response and may carry on; the broker
            // has logged the denial.
            Err(BrokerError::Denied { denial, .. }) => Response::error(denial.response_code()),
            Err(BrokerError::LockedOut { .. }) => Response::error(resmgr_rc(TpmRcBase::Lockout)),
            Err(error) => return Err(error.into()),
        };
        stream.write_all(response.as_bytes()).await?;
        stream.flush().await?;
    }
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
    use crate::{
        policy::Policy,
        testing::{FakeUpstream, broker, command_bytes, error_response},
        tpm::{DEFAULT_MAX_PACKET_SIZE, read_frame},
    };

    use super::*;

    #[tokio::test]
    async fn denied_command_gets_an_error_response_and_is_not_forwarded() {
        let upstream = FakeUpstream::echo();
        let forwarded = upstream.commands.clone();
        let broker = broker(Policy::from_json("{}", &[]), upstream, 0);
        let client = broker.admit(Peer::new(1000, 100), Priority(4));
        let (mut stream, server) = tokio::io::duplex(256);
        let (_shutdown, shutdown_rx) = watch::channel(false);
        let server = tokio::spawn(serve_commands(
            server,
            client,
            DEFAULT_MAX_PACKET_SIZE,
            shutdown_rx,
        ));

        // Each denial is answered, and the connection stays open.
        for code in [0x17b, 0x17a] {
            stream.write_all(&command_bytes(code, &[])).await.unwrap();
            let response = read_frame(&mut stream, DEFAULT_MAX_PACKET_SIZE).await;
            assert_eq!(response.unwrap().unwrap(), error_response(0x000b_0143));
        }
        stream.shutdown().await.unwrap();

        server.await.unwrap().unwrap();
        assert!(forwarded.lock().unwrap().is_empty());
    }
}
