// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: BSD-2-Clause

//! Transport-independent peer identity.
//!
//! Unix listeners populate this from `SO_PEERCRED` and supplementary group
//! lookup. Other transports can provide an authenticated identity during their
//! own admission handshake.

#![allow(dead_code)] // Main wiring is implemented in a later change.

use std::ffi::CString;
use std::io;

use nix::unistd::{Gid, Uid, User, getgrouplist};
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
    /// Supplementary groups are resolved from the system group database the same
    /// way `login` computes them: the peer's UID is mapped to a user name and
    /// then expanded with `getgrouplist`. If the UID has no passwd entry (e.g. a
    /// systemd `DynamicUser`), only the primary group is known.
    pub fn from_unix_stream(stream: &UnixStream) -> io::Result<Self> {
        let credentials = stream.peer_cred()?;
        let uid = credentials.uid();
        let primary_gid = credentials.gid();
        Ok(Self {
            uid,
            primary_gid,
            supplementary_gids: supplementary_gids(uid, primary_gid),
            pid: credentials.pid().map(|pid| pid as u32),
        })
    }
}

/// Resolve the configured supplementary groups for `uid`, excluding the primary.
///
/// Failures to consult the user/group database are non-fatal: the peer simply
/// has no supplementary groups for policy matching.
fn supplementary_gids(uid: u32, primary_gid: u32) -> Vec<u32> {
    let Ok(Some(user)) = User::from_uid(Uid::from_raw(uid)) else {
        return Vec::new();
    };
    let Ok(name) = CString::new(user.name) else {
        return Vec::new();
    };
    match getgrouplist(&name, Gid::from_raw(primary_gid)) {
        Ok(groups) => groups
            .into_iter()
            .map(Gid::as_raw)
            .filter(|gid| *gid != primary_gid)
            .collect(),
        Err(error) => {
            tracing::debug!(uid, %error, "failed to resolve supplementary groups");
            Vec::new()
        }
    }
}
