// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: BSD-2-Clause

//! Transport-independent peer identity.
//!
//! Unix listeners populate this from `SO_PEERCRED` and supplementary group
//! lookup. Other transports can provide an authenticated identity during their
//! own admission handshake.

#![allow(dead_code)] // Main wiring is implemented in a later change.

use std::io;

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
}

impl Peer {
    /// Construct a peer with no supplementary groups.
    pub fn new(uid: u32, primary_gid: u32) -> Self {
        Self {
            uid,
            primary_gid,
            supplementary_gids: Vec::new(),
        }
    }

    /// Return whether the peer belongs to `gid`.
    pub fn belongs_to(&self, gid: u32) -> bool {
        self.primary_gid == gid || self.supplementary_gids.contains(&gid)
    }

    /// Resolve peer identity from a connected Unix-domain stream.
    pub fn from_unix_stream(stream: &UnixStream) -> io::Result<Self> {
        let credentials = stream.peer_cred()?;
        Ok(Self {
            uid: credentials.uid(),
            primary_gid: credentials.gid(),
            supplementary_gids: Vec::new(),
        })
    }
}
