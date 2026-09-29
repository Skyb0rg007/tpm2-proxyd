// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! Transport-independent peer identity.
//!
//! Unix listeners populate this from the credentials the kernel records for a
//! socket's peer (`SO_PEERCRED` and `SO_PEERGROUPS`). Other transports can
//! provide an authenticated identity during their own admission handshake.

#![allow(dead_code)] // Main wiring is implemented in a later change.

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};

use tokio::net::UnixStream;

/// Identity used by policy decisions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    /// Unix user ID.
    pub uid: u32,
    /// Unix primary group ID.
    pub primary_gid: u32,
    /// Unix supplementary group IDs.
    pub supplementary_gids: Vec<u32>,
    /// Process ID of the peer, when the transport provides it.
    pub pid: Option<u32>,
}

impl Peer {
    /// Construct a peer with no supplementary groups and an unknown PID.
    pub fn new(uid: u32, primary_gid: u32) -> Self {
        Self {
            uid,
            primary_gid,
            supplementary_gids: Vec::new(),
            pid: None,
        }
    }

    /// Return whether the peer belongs to `gid`.
    pub fn belongs_to(&self, gid: u32) -> bool {
        self.primary_gid == gid || self.supplementary_gids.contains(&gid)
    }

    /// Resolve peer identity from a connected Unix-domain stream.
    ///
    /// Everything comes from the credentials the kernel recorded when the peer
    /// connected: UID, primary GID, and PID from `SO_PEERCRED`, and the
    /// supplementary groups from `SO_PEERGROUPS`. Those are the groups the kernel
    /// itself checks the peer's permissions against, rather than the groups the
    /// user database assigns its user, and reading them never blocks on NSS.
    pub fn from_unix_stream(stream: &UnixStream) -> io::Result<Self> {
        let credentials = stream.peer_cred()?;
        let primary_gid = credentials.gid();
        let supplementary_gids = peer_groups(stream.as_fd())?
            .into_iter()
            .filter(|gid| *gid != primary_gid)
            .collect();
        Ok(Self {
            uid: credentials.uid(),
            primary_gid,
            supplementary_gids,
            pid: credentials.pid().map(|pid| pid as u32),
        })
    }
}

/// Read the supplementary groups of a Unix socket's peer (`SO_PEERGROUPS`,
/// Linux 4.13+), as recorded when it connected.
fn peer_groups(fd: BorrowedFd<'_>) -> io::Result<Vec<libc::gid_t>> {
    let mut groups: Vec<libc::gid_t> = Vec::new();
    loop {
        let mut len = size_of_val(groups.as_slice()) as libc::socklen_t;
        // SAFETY: `groups` has room for `len` bytes, and the kernel writes at
        // most `len` bytes.
        let rc = unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERGROUPS,
                groups.as_mut_ptr().cast(),
                &mut len,
            )
        };
        let count = len as usize / size_of::<libc::gid_t>();
        if rc == 0 {
            groups.truncate(count);
            return Ok(groups);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ERANGE) {
            return Err(error);
        }
        // The buffer was too small, and the kernel reported the size it needs.
        // The peer's recorded groups never change, so the retry fits.
        groups.resize(count, 0);
    }
}

#[cfg(test)]
mod tests {
    use rustix::process::{getgid, getgroups, getuid};

    use super::*;

    #[tokio::test]
    async fn resolves_the_peer_from_its_kernel_credentials() {
        // A socket pair's peer is this process, so the kernel's view of the
        // peer is this process's own credentials.
        let (ours, _theirs) = UnixStream::pair().unwrap();
        let peer = Peer::from_unix_stream(&ours).unwrap();

        assert_eq!(peer.uid, getuid().as_raw());
        assert_eq!(peer.primary_gid, getgid().as_raw());
        assert_eq!(peer.pid, Some(std::process::id()));
        let mut expected: Vec<u32> = getgroups()
            .unwrap()
            .into_iter()
            .map(|gid| gid.as_raw())
            .filter(|gid| *gid != peer.primary_gid)
            .collect();
        let mut actual = peer.supplementary_gids;
        expected.sort_unstable();
        actual.sort_unstable();
        assert_eq!(actual, expected);
    }
}
