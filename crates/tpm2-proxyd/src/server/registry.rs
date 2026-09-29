// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! Active downstream connection tracking.
//!
//! The registry counts admitted connections and enforces an optional
//! concurrency cap. A [`ConnectionGuard`] releases its slot when the connection
//! task ends (including on panic), so the count stays accurate without explicit
//! deregistration.

use std::sync::{Arc, Mutex};

/// Shared, cloneable registry of active connections.
#[derive(Clone)]
pub struct ConnectionRegistry {
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    active: usize,
    max_connections: usize,
}

impl ConnectionRegistry {
    /// Create a registry capping concurrent connections at `max_connections`.
    ///
    /// A value of `0` means unlimited.
    pub fn new(max_connections: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                active: 0,
                max_connections,
            })),
        }
    }

    /// Register a newly admitted connection.
    ///
    /// Returns `None` when the concurrency cap has been reached, in which case
    /// the caller should reject the connection.
    pub fn register(&self) -> Option<ConnectionGuard> {
        let mut inner = self.inner.lock().unwrap();
        if inner.max_connections != 0 && inner.active >= inner.max_connections {
            return None;
        }
        inner.active += 1;
        Some(ConnectionGuard {
            registry: self.clone(),
        })
    }
}

/// Releases its connection's slot in the registry when dropped.
pub struct ConnectionGuard {
    registry: ConnectionRegistry,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.registry.inner.lock().unwrap().active -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_capacity() {
        let registry = ConnectionRegistry::new(1);
        let first = registry.register().unwrap();
        assert!(registry.register().is_none());
        drop(first);
        assert!(registry.register().is_some());
    }
}
