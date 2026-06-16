// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: BSD-2-Clause

//! Raw TPM command listener for Unix-domain sockets.
//!
//! This is the temporary TPM transport while Varlink protocol upgrades are
//! blocked upstream. It accepts already-framed TPM command bytes directly and
//! derives admission context from Unix peer credentials. Clients cannot request
//! their own priority; the listener asks for [`Priority::MAX`] and the broker's
//! policy cap for the peer's UID/GID determines the effective priority.

#![allow(dead_code)] // Main wiring is implemented in a later change.

use std::{io, path::Path};

use tokio::net::{UnixListener, UnixStream};

use crate::{
    scheduler::Priority,
    server::{
        connection::{Accepted, Listener},
        peer::Peer,
    },
};

/// Resolves a peer identity for an accepted Unix stream.
pub trait PeerResolver: Send + Sync + 'static {
    /// Resolve the peer identity.
    fn peer(&self, stream: &UnixStream) -> io::Result<Peer>;
}

/// Production peer resolver using Unix socket credentials.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnixPeerResolver;

impl PeerResolver for UnixPeerResolver {
    fn peer(&self, stream: &UnixStream) -> io::Result<Peer> {
        Peer::from_unix_stream(stream)
    }
}

/// Unix listener that speaks only the raw TPM byte-stream protocol.
#[derive(Debug)]
pub struct RawTpmListener<R = UnixPeerResolver> {
    inner: UnixListener,
    resolver: R,
}

impl RawTpmListener<UnixPeerResolver> {
    /// Bind a raw TPM Unix listener at `path`.
    pub fn bind(path: impl AsRef<Path>) -> io::Result<Self> {
        UnixListener::bind(path).map(Self::from_listener)
    }

    /// Wrap an existing Tokio Unix listener.
    pub fn from_listener(inner: UnixListener) -> Self {
        Self::from_listener_with_resolver(inner, UnixPeerResolver)
    }
}

impl<R> RawTpmListener<R>
where
    R: PeerResolver,
{
    /// Wrap an existing Tokio Unix listener with a custom peer resolver.
    pub fn from_listener_with_resolver(inner: UnixListener, resolver: R) -> Self {
        Self { inner, resolver }
    }

    /// Recover the wrapped Tokio listener.
    pub fn into_inner(self) -> UnixListener {
        self.inner
    }
}

impl<R> Listener for RawTpmListener<R>
where
    R: PeerResolver,
{
    type Stream = UnixStream;

    async fn accept(&mut self) -> io::Result<Accepted<Self::Stream>> {
        let (stream, _) = self.inner.accept().await?;
        accept_stream(&self.resolver, stream)
    }
}

fn accept_stream(
    resolver: &impl PeerResolver,
    stream: UnixStream,
) -> io::Result<Accepted<UnixStream>> {
    let peer = resolver.peer(&stream)?;
    Ok(Accepted {
        stream,
        peer,
        requested_priority: Priority::MAX,
    })
}

#[cfg(test)]
mod tests {
    use crate::{
        broker::Broker,
        policy::{Policy, PolicyConfig, PriorityRule, Subject},
        scheduler::CommandScheduler,
        tpm::{Command, DEFAULT_MAX_PACKET_SIZE, Response},
        upstream::{Upstream, UpstreamError},
    };

    use super::*;

    #[derive(Clone)]
    struct StaticPeerResolver(Peer);

    impl PeerResolver for StaticPeerResolver {
        fn peer(&self, _stream: &UnixStream) -> io::Result<Peer> {
            Ok(self.0.clone())
        }
    }

    struct EchoUpstream;

    impl Upstream for EchoUpstream {
        async fn transact(&mut self, command: &Command) -> Result<Response, UpstreamError> {
            let mut response = Vec::from(0x8001u16.to_be_bytes());
            response.extend_from_slice(&10u32.to_be_bytes());
            response.extend_from_slice(&command.header().code.to_be_bytes());
            Ok(Response::parse(response, DEFAULT_MAX_PACKET_SIZE).unwrap())
        }
    }

    #[tokio::test]
    async fn accepted_stream_comes_from_resolved_unix_peer() {
        let (client, server) = UnixStream::pair().unwrap();
        let peer = Peer {
            uid: 1000,
            primary_gid: 100,
            supplementary_gids: vec![42],
        };
        let accepted = accept_stream(&StaticPeerResolver(peer.clone()), server).unwrap();

        assert_eq!(accepted.peer, peer);
        assert_eq!(accepted.requested_priority, Priority::MAX);
        drop(client);
    }

    #[tokio::test]
    async fn unix_stream_uses_policy_to_determine_priority() {
        let (_probe, server) = UnixStream::pair().unwrap();
        let peer = Peer::new(1000, 100);
        let accepted = accept_stream(&StaticPeerResolver(peer), server).unwrap();

        let scheduler = CommandScheduler::start(EchoUpstream, 4);
        let policy = Policy::new(PolicyConfig {
            priority_rules: vec![PriorityRule {
                subject: Subject {
                    uid: Some(1000),
                    gid: None,
                },
                max_priority: 6,
            }],
            ..PolicyConfig::default()
        });
        let broker = Broker::new(policy, scheduler);
        let client = broker.admit(accepted.peer, accepted.requested_priority);

        assert_eq!(client.priority(), Priority(6));
    }
}
