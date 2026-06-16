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

use std::{
    fs, io,
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::Path,
};

use tokio::net::{UnixListener, UnixStream};

use crate::{
    scheduler::Priority,
    server::{
        connection::{Accepted, Listener},
        peer::Peer,
    },
};

/// Default mode for the temporary raw TPM socket.
pub const DEFAULT_SOCKET_MODE: u32 = 0o660;

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

    /// Prepare and bind a raw TPM Unix listener at `path`.
    ///
    /// This creates the parent directory, removes an existing stale socket, and
    /// applies [`DEFAULT_SOCKET_MODE`] after binding. Existing non-socket paths
    /// are rejected rather than overwritten.
    pub fn bind_prepared(path: impl AsRef<Path>) -> io::Result<Self> {
        Self::bind_prepared_with_mode(path, DEFAULT_SOCKET_MODE)
    }

    /// Like [`Self::bind_prepared`], but with an explicit socket file mode.
    pub fn bind_prepared_with_mode(path: impl AsRef<Path>, mode: u32) -> io::Result<Self> {
        let path = path.as_ref();
        prepare_socket_path(path)?;
        let listener = UnixListener::bind(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
        Ok(Self::from_listener(listener))
    }

    /// Wrap an existing Tokio Unix listener.
    pub fn from_listener(inner: UnixListener) -> Self {
        Self::from_listener_with_resolver(inner, UnixPeerResolver)
    }
}

fn prepare_socket_path(path: &Path) -> io::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }

    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => fs::remove_file(path),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("refusing to replace non-socket path {}", path.display()),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
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
    use std::{fs, path::PathBuf};

    use crate::{
        broker::Broker,
        policy::{Policy, PolicyConfig, PriorityRule, Subject},
        scheduler::CommandScheduler,
        tpm::{Command, DEFAULT_MAX_PACKET_SIZE, Response},
        upstream::{Upstream, UpstreamError},
    };

    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("tpm2-proxyd-{}-{name}", std::process::id()))
    }

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

    #[test]
    fn prepare_socket_path_creates_parent_directory() {
        let dir = temp_path("prepare-parent");
        let path = dir.join("nested").join("proxy.sock");
        let _cleanup = Cleanup(dir.clone());

        prepare_socket_path(&path).unwrap();

        assert!(path.parent().unwrap().is_dir());
    }

    #[test]
    fn prepared_bind_rejects_non_socket_path() {
        let dir = temp_path("non-socket");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("proxy.sock");
        let _cleanup = Cleanup(dir.clone());
        fs::write(&path, b"not a socket").unwrap();

        let error = RawTpmListener::bind_prepared(&path).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
    }

    struct Cleanup(PathBuf);

    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}
