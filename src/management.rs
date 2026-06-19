// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: BSD-2-Clause

//! Backend for the Varlink control interface.
//!
//! [`Management`] implements [`crate::varlink::Control`] on top of the running
//! daemon: status comes from the [`Broker`] and connection [`ConnectionRegistry`],
//! and `ReloadPolicy` re-reads the policy file and atomically swaps it in. The
//! same [`Management::reload`] is reused by the `SIGHUP` handler.

#![allow(dead_code)] // Wired into main once daemon construction is implemented.

use std::path::{Path, PathBuf};

use anyhow::Context;

use crate::broker::Broker;
use crate::config::Config;
use crate::server::registry::ConnectionRegistry;
use crate::varlink::{Connections, Control, ControlFuture, PolicyReloaded, ServiceError, Status};

/// Daemon state exposed to the control interface.
#[derive(Clone)]
pub struct Management {
    broker: Broker,
    registry: ConnectionRegistry,
    config_path: PathBuf,
}

impl Management {
    /// Construct a management backend over the live daemon state.
    pub fn new(broker: Broker, registry: ConnectionRegistry, config_path: PathBuf) -> Self {
        Self {
            broker,
            registry,
            config_path,
        }
    }

    /// Reload the policy from disk and atomically replace it.
    ///
    /// Returns the new policy generation. Used by both `ReloadPolicy` and the
    /// `SIGHUP` handler.
    pub fn reload(&self) -> anyhow::Result<u64> {
        let policy = Config::load(&self.config_path)
            .with_context(|| format!("loading config {}", self.config_path.display()))?
            .policy();
        Ok(self.broker.replace_policy(policy))
    }

    /// Path to the policy configuration file.
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }
}

impl Control for Management {
    fn status(&self) -> ControlFuture<'_, Result<Status, ServiceError>> {
        let status = Status {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            active_connections: self.registry.len() as u64,
            policy_generation: self.broker.policy_generation(),
        };
        Box::pin(async move { Ok(status) })
    }

    fn reload_policy(&self) -> ControlFuture<'_, Result<PolicyReloaded, ServiceError>> {
        let result = self.reload();
        Box::pin(async move {
            match result {
                Ok(policy_generation) => Ok(PolicyReloaded { policy_generation }),
                Err(error) => Err(ServiceError::ReloadFailed {
                    reason: format!("{error:#}"),
                }),
            }
        })
    }

    fn connections(&self) -> ControlFuture<'_, Result<Connections, ServiceError>> {
        let connections = Connections {
            connections: self.registry.snapshot(),
        };
        Box::pin(async move { Ok(connections) })
    }
}
