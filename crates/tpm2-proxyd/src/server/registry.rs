// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! Active downstream connection tracking.
//!
//! The registry counts admitted connections and enforces optional caps on
//! their total and on how many one UID may hold, so no single user can take
//! every slot. A [`ConnectionGuard`] releases its slot when the connection task
//! ends (including on panic), so the counts stay accurate without explicit
//! deregistration.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

/// Shared, cloneable registry of active connections.
#[derive(Clone)]
pub struct ConnectionRegistry {
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    active: usize,
    per_uid: HashMap<u32, usize>,
    max_connections: usize,
    max_per_uid: usize,
}

/// Which connection cap refused a registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Full {
    /// The total connection cap.
    Total,
    /// The per-UID connection cap.
    Uid,
}

impl ConnectionRegistry {
    /// Create a registry capping concurrent connections at `max_connections`
    /// in total and `max_per_uid` for each UID.
    ///
    /// A cap of `0` means unlimited.
    pub fn new(max_connections: usize, max_per_uid: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                active: 0,
                per_uid: HashMap::new(),
                max_connections,
                max_per_uid,
            })),
        }
    }

    /// Register a newly admitted connection from `uid`.
    ///
    /// Fails with the cap that's been reached, in which case the caller should
    /// reject the connection.
    pub fn register(&self, uid: u32) -> Result<ConnectionGuard, Full> {
        let mut inner = self.inner.lock().unwrap();
        if inner.max_connections != 0 && inner.active >= inner.max_connections {
            return Err(Full::Total);
        }
        let max_per_uid = inner.max_per_uid;
        let held = inner.per_uid.entry(uid).or_default();
        if max_per_uid != 0 && *held >= max_per_uid {
            return Err(Full::Uid);
        }
        *held += 1;
        inner.active += 1;
        Ok(ConnectionGuard {
            registry: self.clone(),
            uid,
        })
    }
}

/// Releases its connection's slot in the registry when dropped.
pub struct ConnectionGuard {
    registry: ConnectionRegistry,
    uid: u32,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let mut inner = self.registry.inner.lock().unwrap();
        inner.active -= 1;
        if let Some(held) = inner.per_uid.get_mut(&self.uid) {
            *held -= 1;
            if *held == 0 {
                inner.per_uid.remove(&self.uid);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_the_total_cap() {
        let registry = ConnectionRegistry::new(1, 0);
        let first = registry.register(1000).unwrap();
        assert_eq!(registry.register(1001).err(), Some(Full::Total));
        drop(first);
        assert!(registry.register(1001).is_ok());
    }

    #[test]
    fn enforces_the_per_uid_cap() {
        let registry = ConnectionRegistry::new(0, 2);
        let first = registry.register(1000).unwrap();
        let _second = registry.register(1000).unwrap();
        assert_eq!(registry.register(1000).err(), Some(Full::Uid));
        // Other users still get in.
        let _other = registry.register(1001).unwrap();
        drop(first);
        assert!(registry.register(1000).is_ok());
    }
}
