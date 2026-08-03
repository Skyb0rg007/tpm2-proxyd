// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! Varlink control service for `website.soss.Tpm2Proxyd`.
//!
//! This module owns the wire-level interface and delegates daemon operations to
//! a [`Control`] implementation. Keeping the backend behind a small trait lets
//! the service be tested without constructing the TPM broker and keeps `zlink`
//! types out of the rest of the daemon.

#![allow(dead_code)] // Wired into main once daemon construction is implemented.

use std::{future::Future, path::PathBuf, pin::Pin};

use serde::{Deserialize, Serialize};
use zlink::introspect::{self, CustomType};

/// Name of the Varlink interface exported by the daemon.
pub const INTERFACE_NAME: &str = "website.soss.Tpm2Proxyd";

/// Future returned by [`Control`] operations.
pub type ControlFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Runtime status returned by [`Control::status`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, CustomType)]
pub struct Status {
    /// Daemon version.
    pub version: String,
    /// Number of active downstream TPM connections.
    pub active_connections: u64,
    /// Monotonically increasing generation of the loaded policy.
    pub policy_generation: u64,
}

/// Description of an active downstream TPM connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, CustomType)]
pub struct ConnectionInfo {
    /// Daemon-assigned connection identifier.
    pub id: u64,
    /// Unix user ID of the peer.
    pub uid: u32,
    /// Unix primary group ID of the peer.
    pub gid: u32,
    /// Process ID of the peer.
    pub pid: u32,
    /// Scheduling priority requested by the connection.
    pub priority: i64,
}

/// Reply from `ListConnections`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, CustomType)]
pub struct Connections {
    /// Active connections at the time of the call.
    pub connections: Vec<ConnectionInfo>,
}

/// Reply from `ReloadPolicy`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, CustomType)]
pub struct PolicyReloaded {
    /// Generation assigned to the newly loaded policy.
    pub policy_generation: u64,
}

/// Errors exposed by the control interface.
#[derive(Debug, Clone, PartialEq, Eq, zlink::ReplyError, introspect::ReplyError)]
#[zlink(interface = "website.soss.Tpm2Proxyd")]
pub enum ServiceError {
    /// The policy could not be reloaded.
    ReloadFailed {
        /// Human-readable failure reason.
        reason: String,
    },
    /// The daemon could not obtain its current state.
    StateUnavailable {
        /// Human-readable failure reason.
        reason: String,
    },
}

/// Backend used by the Varlink service.
///
/// Implementations should keep `status` and `connections` cheap. `reload_policy`
/// may perform file I/O and validation asynchronously.
pub trait Control: Send + Sync {
    /// Return a snapshot of daemon status.
    fn status(&self) -> ControlFuture<'_, Result<Status, ServiceError>>;

    /// Reload and atomically replace the active policy.
    fn reload_policy(&self) -> ControlFuture<'_, Result<PolicyReloaded, ServiceError>>;

    /// Return a snapshot of active downstream connections.
    fn connections(&self) -> ControlFuture<'_, Result<Connections, ServiceError>>;
}

/// `zlink` service implementing [`INTERFACE_NAME`].
pub struct VarlinkService {
    control: Box<dyn Control>,
}

impl VarlinkService {
    /// Construct a service backed by `control`.
    pub fn new(control: impl Control + 'static) -> Self {
        Self {
            control: Box::new(control),
        }
    }
}

#[zlink::service(
    interface = "website.soss.Tpm2Proxyd",
    types = [Status, ConnectionInfo, Connections, PolicyReloaded],
    vendor = "Skye Soss",
    product = "tpm2-proxyd",
    version = env!("CARGO_PKG_VERSION"),
    url = "https://github.com/Skyb0rg007/tpm2-proxyd"
)]
impl VarlinkService {
    async fn get_status(&self) -> Result<Status, ServiceError> {
        self.control.status().await
    }

    async fn reload_policy(&self) -> Result<PolicyReloaded, ServiceError> {
        self.control.reload_policy().await
    }

    async fn list_connections(&self) -> Result<Connections, ServiceError> {
        self.control.connections().await
    }
}

/// Bind `path` and serve the control interface until the server fails.
///
/// The returned future is not `Send` (the `zlink` server is single-task), so
/// run it on the main task with `tokio::select!` rather than `tokio::spawn`.
pub async fn run<C: Control + 'static>(path: PathBuf, control: C) -> zlink::Result<()> {
    let listener = zlink::unix::bind(path)?;
    zlink::Server::new(listener, VarlinkService::new(control))
        .run()
        .await
}

#[cfg(test)]
mod tests {
    use std::{
        os::unix::net::UnixStream,
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        },
    };

    use zlink::varlink_service::Proxy as _;

    use super::*;

    #[derive(Clone)]
    struct TestControl {
        generation: Arc<AtomicU64>,
    }

    impl Control for TestControl {
        fn status(&self) -> ControlFuture<'_, Result<Status, ServiceError>> {
            let generation = self.generation.load(Ordering::Relaxed);
            Box::pin(async move {
                Ok(Status {
                    version: "test".into(),
                    active_connections: 1,
                    policy_generation: generation,
                })
            })
        }

        fn reload_policy(&self) -> ControlFuture<'_, Result<PolicyReloaded, ServiceError>> {
            let generation = Arc::clone(&self.generation);
            Box::pin(async move {
                Ok(PolicyReloaded {
                    policy_generation: generation.fetch_add(1, Ordering::Relaxed) + 1,
                })
            })
        }

        fn connections(&self) -> ControlFuture<'_, Result<Connections, ServiceError>> {
            Box::pin(async {
                Ok(Connections {
                    connections: vec![ConnectionInfo {
                        id: 7,
                        uid: 1000,
                        gid: 1000,
                        pid: 42,
                        priority: 3,
                    }],
                })
            })
        }
    }

    #[zlink::proxy("website.soss.Tpm2Proxyd")]
    trait TestProxy {
        async fn get_status(&mut self) -> zlink::Result<Result<Status, ServiceError>>;
        async fn reload_policy(&mut self) -> zlink::Result<Result<PolicyReloaded, ServiceError>>;
        async fn list_connections(&mut self) -> zlink::Result<Result<Connections, ServiceError>>;
    }

    #[tokio::test]
    async fn serves_control_methods_and_introspection() {
        let (server_stream, client_stream) = UnixStream::pair().unwrap();
        server_stream.set_nonblocking(true).unwrap();
        client_stream.set_nonblocking(true).unwrap();
        let server_stream =
            zlink::unix::Stream::from(tokio::net::UnixStream::from_std(server_stream).unwrap());
        let client_stream =
            zlink::unix::Stream::from(tokio::net::UnixStream::from_std(client_stream).unwrap());

        let control = TestControl {
            generation: Arc::new(AtomicU64::new(4)),
        };
        let listener = zlink::ReadyListener::new(server_stream);
        let server = zlink::Server::new(listener, VarlinkService::new(control));

        tokio::select! {
            result = server.run() => panic!("server stopped unexpectedly: {result:?}"),
            result = async {
                let mut connection = zlink::Connection::new(client_stream);

                let status = connection.get_status().await.unwrap().unwrap();
                assert_eq!(status.policy_generation, 4);

                let reloaded = connection.reload_policy().await.unwrap().unwrap();
                assert_eq!(reloaded.policy_generation, 5);

                let connections = connection.list_connections().await.unwrap().unwrap();
                assert_eq!(connections.connections[0].uid, 1000);

                let info = connection.get_info().await.unwrap().unwrap();
                assert!(info.interfaces.iter().any(|name| name == INTERFACE_NAME));

                let description = connection
                    .get_interface_description(INTERFACE_NAME)
                    .await
                    .unwrap()
                    .unwrap();
                let interface = description.parse().unwrap();
                let methods: Vec<_> = interface.methods().map(|method| method.name()).collect();
                assert_eq!(methods, ["GetStatus", "ReloadPolicy", "ListConnections"]);
            } => result,
        }
    }
}
