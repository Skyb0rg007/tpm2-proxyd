// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! Active downstream connection tracking.
//!
//! The registry assigns a stable id to each admitted connection, enforces an
//! optional concurrency cap, and exposes a snapshot for the Varlink
//! `ListConnections` control method. A [`ConnectionGuard`] removes its entry
//! when the connection task ends (including on panic), so the count stays
//! accurate without explicit deregistration.

#![allow(dead_code)] // Main wiring is implemented in a later change.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crate::scheduler::Priority;
use crate::server::peer::Peer;
use crate::varlink::ConnectionInfo;

/// Shared, cloneable registry of active connections.
#[derive(Clone)]
pub struct ConnectionRegistry {
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    next_id: u64,
    max_connections: usize,
    connections: BTreeMap<u64, ConnectionInfo>,
}

impl ConnectionRegistry {
    /// Create a registry capping concurrent connections at `max_connections`.
    ///
    /// A value of `0` means unlimited.
    pub fn new(max_connections: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                next_id: 1,
                max_connections,
                connections: BTreeMap::new(),
            })),
        }
    }

    /// Register a newly admitted connection.
    ///
    /// Returns `None` when the concurrency cap has been reached, in which case
    /// the caller should reject the connection.
    pub fn register(&self, peer: &Peer, priority: Priority) -> Option<ConnectionGuard> {
        let mut inner = self.inner.lock().unwrap();
        if inner.max_connections != 0 && inner.connections.len() >= inner.max_connections {
            return None;
        }
        let id = inner.next_id;
        inner.next_id += 1;
        inner.connections.insert(
            id,
            ConnectionInfo {
                id,
                uid: peer.uid,
                gid: peer.primary_gid,
                pid: peer.pid.unwrap_or(0),
                priority: i64::from(priority.0),
            },
        );
        Some(ConnectionGuard {
            registry: self.clone(),
            id,
        })
    }

    /// Number of currently active connections.
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().connections.len()
    }

    /// Whether there are no active connections.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Snapshot of active connections, ordered by id.
    pub fn snapshot(&self) -> Vec<ConnectionInfo> {
        self.inner
            .lock()
            .unwrap()
            .connections
            .values()
            .cloned()
            .collect()
    }

    fn remove(&self, id: u64) {
        self.inner.lock().unwrap().connections.remove(&id);
    }
}

/// Removes its connection from the registry when dropped.
pub struct ConnectionGuard {
    registry: ConnectionRegistry,
    id: u64,
}

impl ConnectionGuard {
    /// The registry id assigned to this connection.
    pub fn id(&self) -> u64 {
        self.id
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.registry.remove(self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(uid: u32) -> Peer {
        Peer::new(uid, 100)
    }

    #[test]
    fn tracks_and_releases_connections() {
        let registry = ConnectionRegistry::new(0);
        let a = registry.register(&peer(1000), Priority(3)).unwrap();
        let b = registry.register(&peer(1001), Priority(5)).unwrap();
        assert_eq!(registry.len(), 2);

        let snapshot = registry.snapshot();
        assert_eq!(snapshot.len(), 2);
        assert_eq!(snapshot[0].id, a.id());
        assert_eq!(snapshot[0].uid, 1000);
        assert_eq!(snapshot[1].priority, 5);

        drop(a);
        assert_eq!(registry.len(), 1);
        drop(b);
        assert!(registry.is_empty());
    }

    #[test]
    fn enforces_capacity() {
        let registry = ConnectionRegistry::new(1);
        let first = registry.register(&peer(1000), Priority(0)).unwrap();
        assert!(registry.register(&peer(1001), Priority(0)).is_none());
        drop(first);
        assert!(registry.register(&peer(1002), Priority(0)).is_some());
    }
}
