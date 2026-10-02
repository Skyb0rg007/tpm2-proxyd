// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! Raw TPM command listener for Unix-domain sockets.
//!
//! Derives each client's identity from Unix peer credentials. The client
//! requests its priority in the hello (see `server::hello`), and the broker's
//! policy cap for the peer's UID/GID bounds it.

#![allow(dead_code)] // Main wiring is implemented in a later change.

use std::{
    fs, io,
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::Path,
};

use tokio::net::{UnixListener, UnixStream};

use crate::server::{
    connection::{Accepted, Listener},
    peer::Peer,
};

/// Where the listening socket came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketOrigin {
    /// Passed in by systemd socket activation; systemd owns the path.
    Activated,
    /// Bound by the daemon, which should remove the path when it exits.
    Bound,
}

/// Mode of a socket the daemon binds itself: like the socket unit's, every
/// local user may connect, and the policy decides what each may run.
pub const DEFAULT_SOCKET_MODE: u32 = 0o666;

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

/// Unix listener for downstream clients.
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

    /// Use a systemd socket-activation fd if one was passed, else bind `path`.
    ///
    /// With socket activation the listening socket is created (and its
    /// permissions/ownership set) by the `.socket` unit; otherwise the daemon
    /// binds `path` itself via [`Self::bind_prepared`].
    pub fn from_systemd_or_bind(path: impl AsRef<Path>) -> io::Result<(Self, SocketOrigin)> {
        if let Ok(mut fds) = crate::systemd::sd_listen_fds()
            && fds.len() == 1
        {
            let fd = fds.pop().expect("exactly one fd");
            let listener = std::os::unix::net::UnixListener::from(fd);
            listener.set_nonblocking(true)?;
            let listener = Self::from_listener(UnixListener::from_std(listener)?);
            return Ok((listener, SocketOrigin::Activated));
        }
        Ok((Self::bind_prepared(path)?, SocketOrigin::Bound))
    }
}

pub(crate) fn prepare_socket_path(path: &Path) -> io::Result<()> {
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
        loop {
            let (stream, _) = self.inner.accept().await?;
            match accept_stream(&self.resolver, stream) {
                Ok(accepted) => return Ok(accepted),
                // One client's credentials are unreadable: drop that client
                // rather than report a listener error.
                Err(error) => {
                    tracing::warn!(%error, "failed to read a client's credentials; dropping it");
                }
            }
        }
    }
}

fn accept_stream(
    resolver: &impl PeerResolver,
    stream: UnixStream,
) -> io::Result<Accepted<UnixStream>> {
    let peer = resolver.peer(&stream)?;
    Ok(Accepted { stream, peer })
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

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

    #[tokio::test]
    async fn accepted_stream_comes_from_resolved_unix_peer() {
        let (client, server) = UnixStream::pair().unwrap();
        let peer = Peer {
            uid: 1000,
            primary_gid: 100,
            supplementary_gids: vec![42],
            pid: None,
        };
        let accepted = accept_stream(&StaticPeerResolver(peer.clone()), server).unwrap();

        assert_eq!(accepted.peer, peer);
        drop(client);
    }

    /// Fails to resolve the first peer only.
    struct FailFirstResolver(std::sync::atomic::AtomicBool);

    impl PeerResolver for FailFirstResolver {
        fn peer(&self, _stream: &UnixStream) -> io::Result<Peer> {
            if self.0.swap(false, std::sync::atomic::Ordering::SeqCst) {
                Err(io::Error::other("credentials unavailable"))
            } else {
                Ok(Peer::new(1000, 100))
            }
        }
    }

    #[tokio::test]
    async fn unreadable_credentials_drop_only_that_client() {
        use tokio::io::AsyncReadExt;

        let dir = temp_path("unreadable-credentials");
        fs::create_dir_all(&dir).unwrap();
        let _cleanup = Cleanup(dir.clone());
        let path = dir.join("proxy.sock");
        let mut listener = RawTpmListener::from_listener_with_resolver(
            UnixListener::bind(&path).unwrap(),
            FailFirstResolver(true.into()),
        );
        let mut first = UnixStream::connect(&path).await.unwrap();
        let _second = UnixStream::connect(&path).await.unwrap();

        // The listener skips the first client and admits the second.
        let accepted = listener.accept().await.expect("listener kept accepting");
        assert_eq!(accepted.peer, Peer::new(1000, 100));

        // The first client was dropped.
        let mut byte = [0u8; 1];
        assert_eq!(first.read(&mut byte).await.unwrap(), 0);
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
