// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: BSD-2-Clause

//! Transport-independent peer identity.
//!
//! Unix listeners populate this from `SO_PEERCRED` and supplementary group
//! lookup. Other transports can provide an authenticated identity during their
//! own admission handshake.

#![allow(dead_code)] // Unix credential extraction is wired in with the listener.

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
}
