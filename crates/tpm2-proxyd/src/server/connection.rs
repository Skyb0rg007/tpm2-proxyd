// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! Listener-independent downstream TPM command handling.
//!
//! [`serve_listener`] accepts [`ClientStream`] values from a [`Listener`].
//! Neither API assumes Unix sockets, TCP, or Varlink: a future Varlink upgrade
//! handoff can implement the same traits without changing command scheduling.

#![allow(dead_code)] // Wired into main once daemon construction is implemented.

use std::{future::Future, io, time::Duration};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::{
    broker::{Broker, BrokerError, Client},
    scheduler::Priority,
    server::{peer::Peer, registry::ConnectionRegistry},
    tpm::{self, Command, Response},
};

/// How long shutdown waits for in-flight connections to drain before aborting.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

/// A connected client capable of exchanging framed TPM packets.
pub trait ClientStream: Send + 'static {
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
    async fn read_command(&mut self, max_command_size: usize) -> io::Result<Option<Command>> {
        tpm::read_command(self, max_command_size).await
    }

    async fn write_response(&mut self, response: &Response) -> io::Result<()> {
        self.write_all(response.as_bytes()).await?;
        self.flush().await
    }
}

/// Stream accepted from a listener and the fixed priority for its lifetime.
pub struct Accepted<S> {
    /// Connected client transport.
    pub stream: S,
    /// Authenticated identity used for policy decisions.
    pub peer: Peer,
    /// Scheduling priority requested by the client.
    pub requested_priority: Priority,
}

/// Abstract source of admitted client connections.
pub trait Listener {
    /// Transport produced by this listener.
    type Stream: ClientStream;

    /// Accept and admit one client.
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

/// Test adapter for listeners whose clients share one static identity/priority.
///
/// Transports with an admission handshake can implement [`Listener`] directly
/// and assign a different priority to each accepted stream.
pub struct RawListener<L> {
    inner: L,
    peer: Peer,
    requested_priority: Priority,
}

impl<L> RawListener<L> {
    /// Wrap `inner`, assigning the supplied admission context to every client.
    ///
    /// This is intended for trusted/local raw listeners. Transports that
    /// authenticate each peer should implement [`Listener`] directly.
    pub fn new(inner: L, peer: Peer, requested_priority: Priority) -> Self {
        Self {
            inner,
            peer,
            requested_priority,
        }
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
            requested_priority: self.requested_priority,
        })
    }
}

/// Accept clients forever and run each connection in its own task.
///
/// Client tasks only parse, authorize, enqueue, and return responses. The
/// scheduler worker behind [`Broker`] remains the sole owner of the upstream
/// TCTI.
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

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                // The sender was dropped or signalled shutdown: stop accepting.
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let accepted = accepted?;
                let peer = accepted.peer;
                let client = broker.admit(peer.clone(), accepted.requested_priority);
                let Some(guard) = registry.register(&peer, client.priority()) else {
                    tracing::warn!(uid = peer.uid, "connection limit reached; rejecting client");
                    continue;
                };
                let connection_shutdown = shutdown.clone();
                let stream = accepted.stream;
                tasks.spawn(async move {
                    let _guard = guard;
                    if let Err(error) =
                        serve_connection(stream, client, max_command_size, connection_shutdown)
                            .await
                    {
                        tracing::debug!(%error, "downstream TPM connection closed with an error");
                    }
                });
            }
        }
    }

    drain(tasks).await;
    Ok(())
}

/// Wait for active connection tasks to finish, aborting any that outlast the
/// shutdown grace period. The tasks observe the same shutdown signal, so they
/// stop after their current in-flight command.
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
}
