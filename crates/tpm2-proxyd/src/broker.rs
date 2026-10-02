// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! Authorized command submission pipeline.
//!
//! The broker is the only path from a downstream client to the command
//! scheduler. It caps the connection priority and opens the client's upstream
//! session once at admission, checks every parsed command against the current
//! policy, and only then submits it to the serialized upstream worker. It also
//! counts the authorization failures in the TPM's responses that push it toward
//! dictionary-attack lockout (see [`crate::lockout`]).

#![allow(dead_code)] // Main/config wiring is implemented in a later change.

use std::sync::{
    Arc, RwLock,
    atomic::{AtomicU64, Ordering},
};

use crate::{
    lockout::{self, AuthFailures},
    policy::{Denial, Policy},
    scheduler::{CommandScheduler, ExecuteError, Priority, Session, TransactionGuard},
    server::peer::Peer,
    tpm::{Command, Response},
};

use tpm2_protocol::data::TpmCc;

/// Shared broker state.
#[derive(Clone)]
pub struct Broker {
    policy: Arc<RwLock<Policy>>,
    generation: Arc<AtomicU64>,
    scheduler: CommandScheduler,
    auth_failures: Arc<AuthFailures>,
}

impl Broker {
    /// Construct a broker from an active policy, command scheduler, and
    /// lockout failure tracker.
    pub fn new(policy: Policy, scheduler: CommandScheduler, auth_failures: AuthFailures) -> Self {
        Self {
            policy: Arc::new(RwLock::new(policy)),
            generation: Arc::new(AtomicU64::new(1)),
            scheduler,
            auth_failures: Arc::new(auth_failures),
        }
    }

    /// Authorization failures counted toward the TPM's lockout.
    #[cfg(test)]
    pub fn auth_failures(&self) -> &AuthFailures {
        &self.auth_failures
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
        // A cheap early refusal. The check that counts is the lockout guard's,
        // which runs in the scheduler right before the command is sent.
        if self.broker.auth_failures.is_locked_out(self.peer.uid) {
            return Err(self.locked_out(command.code()));
        }
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

        let code = command.code();
        let guard = LockoutGuard {
            auth_failures: self.broker.auth_failures.clone(),
            peer: self.peer.clone(),
            command: code,
            hierarchy: command.handles().iter().any(|&h| lockout::is_hierarchy(h)),
        };
        match self
            .session
            .execute(self.priority, command, Some(Box::new(guard)))
            .await
        {
            Ok(response) => Ok(response),
            Err(ExecuteError::Refused) => Err(self.locked_out(code)),
            Err(error) => Err(error.into()),
        }
    }

    fn locked_out(&self, command: TpmCc) -> BrokerError {
        tracing::debug!(
            uid = self.peer.uid,
            pid = self.peer.pid,
            %command,
            "command refused: user is locked out"
        );
        BrokerError::LockedOut {
            command_code: command.value(),
        }
    }
}

/// Applies the per-UID lockout in the scheduler worker: the check and the
/// count of the response happen in the same serial step, so concurrent
/// connections can't get more commands past the limit than it allows.
struct LockoutGuard {
    auth_failures: Arc<AuthFailures>,
    peer: Peer,
    command: TpmCc,
    /// Whether the command authorizes a hierarchy, whose wrong passwords the
    /// TPM reports as `TPM_RC_BAD_AUTH` without counting them.
    hierarchy: bool,
}

impl TransactionGuard for LockoutGuard {
    fn admit(&self) -> bool {
        !self.auth_failures.is_locked_out(self.peer.uid)
    }

    fn completed(&self, response: &Response) {
        let code = response.code();
        if lockout::is_auth_failure(code) {
            self.auth_failures.record(&self.peer, self.command);
        } else if self.hierarchy && lockout::is_bad_auth(code) {
            self.auth_failures
                .record_hierarchy(&self.peer, self.command);
        }
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
    /// The peer's UID reached the authorization failure limit.
    #[error("refused TPM command {command_code:#010x}: user is locked out")]
    LockedOut {
        /// Refused TPM command code.
        command_code: u32,
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
        let broker = Broker::new(
            Policy::from_json("{}", &[]),
            scheduler,
            AuthFailures::new(0, 0, std::time::Duration::ZERO),
        );
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
        let broker = Broker::new(
            Policy::from_json("{}", &[]),
            scheduler,
            AuthFailures::new(0, 0, std::time::Duration::ZERO),
        );
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
        let broker = Broker::new(
            policy,
            scheduler,
            AuthFailures::new(0, 0, std::time::Duration::ZERO),
        );

        assert_eq!(
            broker.admit(Peer::new(1000, 100), Priority(50)).priority(),
            Priority(3)
        );
    }

    /// Answers every command with `TPM_RC_AUTH_FAIL` for session 1.
    struct AuthFailUpstream;

    #[async_trait::async_trait]
    impl Upstream for AuthFailUpstream {
        async fn transact(
            &mut self,
            _session: SessionId,
            _command: &Command,
        ) -> Result<Response, UpstreamError> {
            let mut response = Vec::from(0x8001u16.to_be_bytes());
            response.extend_from_slice(&10u32.to_be_bytes());
            response.extend_from_slice(&0x98eu32.to_be_bytes());
            Ok(Response::parse(response, DEFAULT_MAX_PACKET_SIZE).unwrap())
        }
    }

    #[tokio::test]
    async fn counts_lockout_failures_per_uid() {
        let broker = Broker::new(
            Policy::allow_all(),
            CommandScheduler::start(AuthFailUpstream, 4),
            AuthFailures::new(0, 0, std::time::Duration::ZERO),
        );
        let first = broker.admit(Peer::new(1000, 100), Priority(0));
        let second = broker.admit(Peer::new(1001, 100), Priority(0));

        // The failure is still relayed to the client.
        let response = first.execute(command(0x17b)).await.unwrap();
        assert_eq!(response.code(), 0x98e);
        first.execute(command(0x17b)).await.unwrap();
        second.execute(command(0x17b)).await.unwrap();

        assert_eq!(broker.auth_failures().total(), 3);
        assert_eq!(broker.auth_failures().for_uid(1000), 2);
        assert_eq!(broker.auth_failures().for_uid(1001), 1);
    }

    #[tokio::test]
    async fn successful_commands_are_not_counted() {
        let broker = Broker::new(
            Policy::allow_all(),
            CommandScheduler::start(
                CountingUpstream {
                    count: Arc::new(AtomicUsize::new(0)),
                    codes: Arc::new(Mutex::new(Vec::new())),
                },
                4,
            ),
            AuthFailures::new(0, 0, std::time::Duration::ZERO),
        );
        let client = broker.admit(Peer::new(1000, 100), Priority(0));
        client.execute(command(0x17b)).await.unwrap();

        assert_eq!(broker.auth_failures().total(), 0);
    }

    #[tokio::test]
    async fn locked_out_uids_are_refused_without_reaching_upstream() {
        let broker = Broker::new(
            Policy::allow_all(),
            CommandScheduler::start(AuthFailUpstream, 4),
            AuthFailures::new(0, 2, std::time::Duration::ZERO),
        );
        let first = broker.admit(Peer::new(1000, 100), Priority(0));
        let second = broker.admit(Peer::new(1000, 100), Priority(0));
        let other = broker.admit(Peer::new(1001, 100), Priority(0));

        first.execute(command(0x17b)).await.unwrap();
        first.execute(command(0x17b)).await.unwrap();

        // Every connection from the locked-out UID is refused, and the refused
        // commands never reach the TPM, so they aren't counted.
        for client in [&first, &second] {
            assert!(matches!(
                client.execute(command(0x17b)).await,
                Err(BrokerError::LockedOut {
                    command_code: 0x17b
                })
            ));
        }
        assert_eq!(broker.auth_failures().for_uid(1000), 2);

        // Other users still reach the TPM.
        other.execute(command(0x17b)).await.unwrap();
        assert_eq!(broker.auth_failures().for_uid(1001), 1);
    }

    /// Answers every command with `TPM_RC_BAD_AUTH` for session 1.
    struct BadAuthUpstream;

    #[async_trait::async_trait]
    impl Upstream for BadAuthUpstream {
        async fn transact(
            &mut self,
            _session: SessionId,
            _command: &Command,
        ) -> Result<Response, UpstreamError> {
            Ok(Response::error(0x9a2))
        }
    }

    /// `TPM2_CreatePrimary` under the owner hierarchy with an empty password
    /// session; the parameters don't matter here.
    fn create_primary_owner() -> Command {
        let mut body = Vec::from(0x4000_0001u32.to_be_bytes());
        // Authorization area: one empty password session (TPM_RS_PW).
        body.extend_from_slice(&9u32.to_be_bytes());
        body.extend_from_slice(&0x4000_0009u32.to_be_bytes());
        body.extend_from_slice(&[0, 0, 0, 0, 0]);
        let mut bytes = Vec::from(0x8002u16.to_be_bytes());
        bytes.extend_from_slice(&(10 + body.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&0x131u32.to_be_bytes());
        bytes.extend_from_slice(&body);
        Command::parse(bytes, DEFAULT_MAX_PACKET_SIZE).unwrap()
    }

    #[tokio::test]
    async fn wrong_hierarchy_passwords_count_toward_the_uid_limit() {
        let broker = Broker::new(
            Policy::allow_all(),
            CommandScheduler::start(BadAuthUpstream, 4),
            AuthFailures::new(0, 2, std::time::Duration::ZERO),
        );
        let client = broker.admit(Peer::new(1000, 100), Priority(0));

        // BAD_AUTH for a command that doesn't authorize a hierarchy (an
        // object without DA protection, say) isn't counted.
        client.execute(command(0x17b)).await.unwrap();
        assert_eq!(broker.auth_failures().for_uid(1000), 0);

        for _ in 0..2 {
            let response = client.execute(create_primary_owner()).await.unwrap();
            assert_eq!(response.code(), 0x9a2);
        }
        assert!(matches!(
            client.execute(create_primary_owner()).await,
            Err(BrokerError::LockedOut { .. })
        ));
        // The TPM didn't count them, so neither does the total.
        assert_eq!(broker.auth_failures().total(), 0);
    }

    /// Answers every command with `TPM_RC_AUTH_FAIL` after a delay, counting
    /// the commands that reach it.
    struct SlowAuthFailUpstream {
        count: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl Upstream for SlowAuthFailUpstream {
        async fn transact(
            &mut self,
            _session: SessionId,
            _command: &Command,
        ) -> Result<Response, UpstreamError> {
            self.count.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            let mut response = Vec::from(0x8001u16.to_be_bytes());
            response.extend_from_slice(&10u32.to_be_bytes());
            response.extend_from_slice(&0x98eu32.to_be_bytes());
            Ok(Response::parse(response, DEFAULT_MAX_PACKET_SIZE).unwrap())
        }
    }

    #[tokio::test]
    async fn concurrent_connections_cannot_exceed_the_lockout_limit() {
        let count = Arc::new(AtomicUsize::new(0));
        let broker = Broker::new(
            Policy::allow_all(),
            CommandScheduler::start(
                SlowAuthFailUpstream {
                    count: count.clone(),
                },
                64,
            ),
            AuthFailures::new(0, 2, std::time::Duration::ZERO),
        );

        // Every command is submitted before any response comes back.
        let tasks: Vec<_> = (0..16)
            .map(|_| {
                let client = broker.admit(Peer::new(1000, 100), Priority(0));
                tokio::spawn(async move { client.execute(command(0x17b)).await })
            })
            .collect();
        let mut results = Vec::new();
        for task in tasks {
            results.push(task.await.unwrap());
        }

        assert_eq!(count.load(Ordering::Relaxed), 2);
        assert_eq!(broker.auth_failures().for_uid(1000), 2);
        let refused = results
            .iter()
            .filter(|result| matches!(result, Err(BrokerError::LockedOut { .. })))
            .count();
        assert_eq!(refused, 14);
    }
}
