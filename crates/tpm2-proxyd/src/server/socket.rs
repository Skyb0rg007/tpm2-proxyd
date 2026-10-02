// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! The listening Unix socket.
//!
//! The socket comes from systemd socket activation or is bound by the daemon.
//! Each client's identity comes from its Unix peer credentials (see
//! [`Peer::from_unix_stream`]).

use std::{
    fs, io,
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::Path,
};

use tokio::net::{UnixListener, UnixStream};

use crate::{peer::Peer, server::Listener};

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
const SOCKET_MODE: u32 = 0o666;

/// The daemon's listening socket.
pub struct SocketListener(UnixListener);

impl SocketListener {
    /// Use a systemd socket-activation fd if one was passed, else bind `path`.
    ///
    /// With socket activation the listening socket is created (and its
    /// permissions/ownership set) by the `.socket` unit; otherwise the daemon
    /// binds `path` itself via [`Self::bind`].
    pub fn from_systemd_or_bind(path: &Path) -> io::Result<(Self, SocketOrigin)> {
        if let Ok(mut fds) = crate::systemd::sd_listen_fds()
            && fds.len() == 1
        {
            let fd = fds.pop().expect("exactly one fd");
            let listener = std::os::unix::net::UnixListener::from(fd);
            listener.set_nonblocking(true)?;
            let listener = Self(UnixListener::from_std(listener)?);
            return Ok((listener, SocketOrigin::Activated));
        }
        Ok((Self::bind(path)?, SocketOrigin::Bound))
    }

    /// Bind a listening socket at `path`.
    ///
    /// This creates the parent directory, removes an existing stale socket, and
    /// lets every user connect. Existing non-socket paths are rejected rather
    /// than overwritten.
    pub fn bind(path: &Path) -> io::Result<Self> {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)?;
        }
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_socket() => fs::remove_file(path)?,
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("refusing to replace non-socket path {}", path.display()),
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let listener = UnixListener::bind(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(SOCKET_MODE))?;
        Ok(Self(listener))
    }
}

impl Listener for SocketListener {
    type Stream = UnixStream;

    async fn accept(&mut self) -> io::Result<(UnixStream, Peer)> {
        loop {
            let (stream, _) = self.0.accept().await?;
            match Peer::from_unix_stream(&stream) {
                Ok(peer) => return Ok((stream, peer)),
                // One client's credentials are unreadable: drop that client
                // rather than report a listener error.
                Err(error) => {
                    tracing::warn!(%error, "failed to read a client's credentials; dropping it");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    /// A fresh directory, removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("tpm2-proxyd-{}-{name}", std::process::id()));
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[tokio::test]
    async fn bind_creates_the_parent_directory_and_replaces_a_stale_socket() {
        let dir = TempDir::new("bind-parent");
        let path = dir.0.join("nested").join("proxy.sock");

        drop(SocketListener::bind(&path).unwrap());
        // The first listener's socket file is left behind, as after a crash.
        SocketListener::bind(&path).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, SOCKET_MODE);
    }

    #[test]
    fn bind_rejects_a_non_socket_path() {
        let dir = TempDir::new("non-socket");
        fs::create_dir_all(&dir.0).unwrap();
        let path = dir.0.join("proxy.sock");
        fs::write(&path, b"not a socket").unwrap();

        let error = SocketListener::bind(&path).err().unwrap();

        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
    }
}
