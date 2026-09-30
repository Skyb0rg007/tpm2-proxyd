// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! Authorized command submission pipeline.
//!
//! The broker is the only path from a downstream client to the command
//! scheduler. It caps the connection priority and opens the client's upstream
//! session once at admission, checks every parsed command against the current
//! policy, and only then submits it to the serialized upstream worker.

#![allow(dead_code)] // Main/config wiring is implemented in a later change.

use std::sync::{
    Arc, RwLock,
    atomic::{AtomicU64, Ordering},
};

use crate::{
    policy::{Denial, Policy},
    scheduler::{CommandScheduler, ExecuteError, Priority, Session},
    server::peer::Peer,
    tpm::{Command, Response},
};

/// Shared broker state.
#[derive(Clone)]
pub struct Broker {
    policy: Arc<RwLock<Policy>>,
    generation: Arc<AtomicU64>,
    scheduler: CommandScheduler,
}

impl Broker {
    /// Construct a broker from an active policy and command scheduler.
    pub fn new(policy: Policy, scheduler: CommandScheduler) -> Self {
        Self {
            policy: Arc::new(RwLock::new(policy)),
            generation: Arc::new(AtomicU64::new(1)),
            scheduler,
        }
    }

    /// Atomically replace the active policy for future decisions.
    ///
    /// Returns the new policy generation. Connections already admitted keep
    /// their previously capped priority; subsequent commands use the new policy.
    pub fn replace_policy(&self, policy: Policy) -> u64 {
        *self.policy.write().unwrap() = policy;
        self.generation.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Current policy generation, bumped on every [`Self::replace_policy`].
    pub fn policy_generation(&self) -> u64 {
        self.generation.load(Ordering::Relaxed)
    }

    /// Admit a peer: cap its requested priority for the connection lifetime and
    /// open its upstream session, which closes when the [`Client`] is dropped.
    pub fn admit(&self, peer: Peer, requested_priority: Priority) -> Client {
        let policy = self.policy.read().unwrap();
        let priority = policy.cap_priority(&peer, requested_priority);
        tracing::info!(
            uid = peer.uid,
            gid = peer.primary_gid,
            pid = peer.pid,
            profile = policy.profile_name(&peer),
            requested_priority = requested_priority.0,
            priority = priority.0,
            "client admitted"
        );
        drop(policy);
        Client {
            broker: self.clone(),
            session: self.scheduler.open_session(),
            peer,
            priority,
        }
    }
}

/// Admitted client with a fixed, policy-bounded priority and its own upstream
/// session.
pub struct Client {
    broker: Broker,
    session: Session,
    peer: Peer,
    priority: Priority,
}

impl Client {
    /// Effective priority after policy capping.
    pub fn priority(&self) -> Priority {
        self.priority
    }

    /// Authorize and execute one parsed TPM command.
    pub async fn execute(&self, command: Command) -> Result<Response, BrokerError> {
        let authorized = self
            .broker
            .policy
            .read()
            .unwrap()
            .authorize(&self.peer, &command);
        if let Err(denial) = authorized {
            tracing::warn!(
                uid = self.peer.uid,
                pid = self.peer.pid,
                command = %command.code(),
                %denial,
                "command denied"
            );
            return Err(BrokerError::Denied {
                command_code: command.code().value(),
                denial,
            });
        }

        self.session
            .execute(self.priority, command)
            .await
            .map_err(Into::into)
    }
}

/// Failure from the authorization/dispatch pipeline.
#[derive(Debug, thiserror::Error)]
pub enum BrokerError {
    /// Policy denied this command.
    #[error("policy denied TPM command {command_code:#010x}: {denial}")]
    Denied {
        /// Denied TPM command code.
        command_code: u32,
        /// Why.
        denial: Denial,
    },
    /// Scheduler or upstream failure.
    #[error(transparent)]
    Execute(#[from] ExecuteError),
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use crate::{
        tpm::DEFAULT_MAX_PACKET_SIZE,
        upstream::{SessionId, Upstream, UpstreamError},
    };

    use super::*;

    struct CountingUpstream {
        count: Arc<AtomicUsize>,
        codes: Arc<Mutex<Vec<u32>>>,
    }

    #[async_trait::async_trait]
    impl Upstream for CountingUpstream {
        async fn transact(
            &mut self,
            _session: SessionId,
            command: &Command,
        ) -> Result<Response, UpstreamError> {
            self.count.fetch_add(1, Ordering::Relaxed);
            self.codes.lock().unwrap().push(command.code().value());
            let mut response = Vec::from(0x8001u16.to_be_bytes());
            response.extend_from_slice(&10u32.to_be_bytes());
            response.extend_from_slice(&0u32.to_be_bytes());
            Ok(Response::parse(response, DEFAULT_MAX_PACKET_SIZE).unwrap())
        }
    }

    fn command(code: u32) -> Command {
        let mut bytes = Vec::from(0x8001u16.to_be_bytes());
        bytes.extend_from_slice(&10u32.to_be_bytes());
        bytes.extend_from_slice(&code.to_be_bytes());
        Command::parse(bytes, DEFAULT_MAX_PACKET_SIZE).unwrap()
    }

    #[tokio::test]
    async fn denied_commands_never_reach_upstream() {
        let count = Arc::new(AtomicUsize::new(0));
        let scheduler = CommandScheduler::start(
            CountingUpstream {
                count: count.clone(),
                codes: Arc::new(Mutex::new(Vec::new())),
            },
            4,
        );
        let broker = Broker::new(Policy::from_json("{}", &[]), scheduler);
        let client = broker.admit(Peer::new(1000, 100), Priority(10));

        assert!(matches!(
            client.execute(command(0x17b)).await,
            Err(BrokerError::Denied {
                command_code: 0x17b,
                denial: Denial::NoProfile,
            })
        ));
        assert_eq!(count.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn policy_replacement_affects_subsequent_commands() {
        let count = Arc::new(AtomicUsize::new(0));
        let scheduler = CommandScheduler::start(
            CountingUpstream {
                count: count.clone(),
                codes: Arc::new(Mutex::new(Vec::new())),
            },
            4,
        );
        let broker = Broker::new(Policy::from_json("{}", &[]), scheduler);
        let client = broker.admit(Peer::new(1000, 100), Priority(0));

        assert!(client.execute(command(0x17b)).await.is_err());
        broker.replace_policy(Policy::allow_all());
        client.execute(command(0x17b)).await.unwrap();
        assert_eq!(count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn admission_caps_priority() {
        let scheduler = CommandScheduler::start(
            CountingUpstream {
                count: Arc::new(AtomicUsize::new(0)),
                codes: Arc::new(Mutex::new(Vec::new())),
            },
            4,
        );
        let policy = Policy::from_json(
            r#"{"rules": [{"subject": {"uid": 1000}, "profile": "all", "max_priority": 3}]}"#,
            &[("all", r#"{"commands": ["*"]}"#)],
        );
        let broker = Broker::new(policy, scheduler);

        assert_eq!(
            broker.admit(Peer::new(1000, 100), Priority(50)).priority(),
            Priority(3)
        );
    }
}
