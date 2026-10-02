// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! The client socket: listener, hello, and per-connection handling.
//!
//! [`serve`] accepts clients from the daemon's socket ([`socket`], default
//! `/run/tpm2-proxyd/tpm2-proxyd.sock`), which identifies each one by its
//! kernel credentials, and runs each connection ([`connection`]) in its own
//! task: the [`hello`], then the client's self-framing TPM command stream,
//! submitted through the [`crate::broker::Broker`]. See `docs/design.md`.

/// Per-connection handling: the hello, then TPM command/response streaming.
pub(crate) mod connection;
/// The hello that opens every connection.
pub(crate) mod hello;
/// Active downstream connection tracking and concurrency cap.
pub(crate) mod registry;
/// The listening Unix socket.
pub(crate) mod socket;

/// End-to-end smoke tests over a real Unix socket.
#[cfg(test)]
mod smoke;

use std::{future::Future, io, time::Duration};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::{broker::Broker, peer::Peer};
use registry::ConnectionRegistry;

/// How long shutdown waits for in-flight connections to drain before aborting.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

/// How long to pause accepting after running out of file descriptors or
/// memory, so connections in flight can release some.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// A source of client connections, each with its peer's identity.
pub trait Listener {
    /// A connected client's transport.
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    /// Accept one client.
    ///
    /// Errors are the listener's own, as `accept` reports them. A listener that
    /// can't admit one particular client (for example, because it can't read
    /// the client's credentials) drops that client and keeps accepting.
    fn accept(&mut self) -> impl Future<Output = io::Result<(Self::Stream, Peer)>> + Send;
}

/// Accept clients until shutdown and run each connection in its own task.
///
/// A failed `accept` stops the server only when the listening socket itself is
/// unusable; open connections are drained before the error is returned. Any
/// other failure is logged and accepting continues.
pub async fn serve(
    mut listener: impl Listener,
    broker: Broker,
    registry: ConnectionRegistry,
    max_command_size: usize,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<()> {
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
            // Reap finished connections, or the set grows with every one.
            Some(joined) = tasks.join_next(), if !tasks.is_empty() => {
                if let Err(error) = joined {
                    tracing::error!(%error, "connection task failed");
                }
            }
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
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
                let stopped = stopped.clone();
                tasks.spawn(async move {
                    let served = connection::serve_client(
                        stream,
                        peer,
                        &broker,
                        &registry,
                        max_command_size,
                        stopped,
                    )
                    .await;
                    if let Err(error) = served {
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

/// How [`serve`] treats a failed `accept`.
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

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    use crate::{
        policy::Policy,
        testing::{FakeUpstream, broker},
        tpm::DEFAULT_MAX_PACKET_SIZE,
    };

    use super::*;

    /// Listener that replays scripted `accept` results, then waits forever.
    struct ScriptedListener(VecDeque<io::Result<(DuplexStream, Peer)>>);

    impl Listener for ScriptedListener {
        type Stream = DuplexStream;

        async fn accept(&mut self) -> io::Result<(DuplexStream, Peer)> {
            match self.0.pop_front() {
                Some(result) => result,
                None => std::future::pending().await,
            }
        }
    }

    fn start_serving(
        script: impl Into<VecDeque<io::Result<(DuplexStream, Peer)>>>,
    ) -> (watch::Sender<bool>, tokio::task::JoinHandle<io::Result<()>>) {
        let (shutdown, shutdown_rx) = watch::channel(false);
        let server = tokio::spawn(serve(
            ScriptedListener(script.into()),
            broker(Policy::allow_all(), FakeUpstream::echo(), 0),
            ConnectionRegistry::new(0, 0),
            DEFAULT_MAX_PACKET_SIZE,
            shutdown_rx,
        ));
        (shutdown, server)
    }

    #[tokio::test(start_paused = true)]
    async fn keeps_accepting_after_connection_and_resource_errors() {
        let (mut client, server_end) = tokio::io::duplex(256);
        let (shutdown, server) = start_serving([
            Err(io::Error::from_raw_os_error(libc::ECONNABORTED)),
            Err(io::Error::from_raw_os_error(libc::EMFILE)),
            Ok((server_end, Peer::new(1000, 100))),
        ]);

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
        let (_shutdown, server) = start_serving([
            Ok((server_end, Peer::new(1000, 100))),
            Err(io::Error::from_raw_os_error(libc::EBADF)),
        ]);

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
