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
//!
//! It also tracks which sessions each connection holds. The kernel resource
//! manager doesn't virtualize session handles, so any client can name any
//! session, and `TPM2_FlushContext` takes its handle as a parameter, where
//! profiles can't check it. A connection may flush only sessions it started
//! or loaded; anything else would let one user destroy another's session
//! mid-workflow.

use std::{
    collections::HashSet,
    sync::{Arc, Mutex, RwLock},
};

use crate::{
    lockout::{self, AuthFailures},
    log_limit::{Kind, limited},
    peer::Peer,
    policy::{Denial, Policy},
    scheduler::{CommandScheduler, ExecuteError, Priority, Session, TransactionGuard},
    tpm::{Command, Response},
};

use tpm2_protocol::data::TpmCc;

/// Shared broker state.
#[derive(Clone)]
pub struct Broker {
    policy: Arc<RwLock<Policy>>,
    scheduler: CommandScheduler,
    auth_failures: Arc<AuthFailures>,
}

impl Broker {
    /// Construct a broker from an active policy, command scheduler, and
    /// lockout failure tracker.
    pub fn new(policy: Policy, scheduler: CommandScheduler, auth_failures: AuthFailures) -> Self {
        Self {
            policy: Arc::new(RwLock::new(policy)),
            scheduler,
            auth_failures: Arc::new(auth_failures),
        }
    }

    /// Atomically replace the active policy for future decisions.
    ///
    /// Connections already admitted keep their previously capped priority;
    /// subsequent commands use the new policy.
    pub fn replace_policy(&self, policy: Policy) {
        *self.policy.write().unwrap() = policy;
    }

    /// Admit a peer: cap its requested priority for the connection lifetime and
    /// open its upstream session, which closes when the [`Client`] is dropped.
    pub fn admit(&self, peer: Peer, requested_priority: Priority) -> Client {
        let policy = self.policy.read().unwrap();
        let priority = policy.cap_priority(&peer, requested_priority);
        limited!(
            info,
            peer.uid,
            Kind::Admission,
            "client admitted",
            gid = peer.primary_gid,
            pid = peer.pid,
            profile = policy.profile_name(&peer),
            requested_priority = requested_priority.0,
            priority = priority.0,
        );
        drop(policy);
        Client {
            broker: self.clone(),
            session: self.scheduler.open_session(),
            peer,
            priority,
            tpm_sessions: Mutex::new(HashSet::new()),
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
    /// Handles of the TPM sessions this connection holds.
    tpm_sessions: Mutex<HashSet<u32>>,
}

/// Whether `handle` is an HMAC or policy session.
fn is_session(handle: u32) -> bool {
    matches!(handle >> 24, 0x02 | 0x03)
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
            .authorize(&self.peer, &command)
            .and_then(|()| match command.flush_handle() {
                Some(handle)
                    if is_session(handle)
                        && !self.tpm_sessions.lock().unwrap().contains(&handle) =>
                {
                    Err(Denial::NotOwnSession { handle })
                }
                _ => Ok(()),
            });
        if let Err(denial) = authorized {
            limited!(
                warn,
                self.peer.uid,
                Kind::Denial,
                "command denied",
                pid = self.peer.pid,
                command = %command.code(),
                %denial,
            );
            return Err(BrokerError::Denied {
                command_code: command.code().value(),
                denial,
            });
        }

        let code = command.code();
        let flushed = command.flush_handle();
        let sessions = command.sessions();
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
            Ok(response) => {
                self.track_sessions(code, flushed, &sessions, &response);
                Ok(response)
            }
            Err(ExecuteError::Refused) => Err(self.locked_out(code)),
            Err(error) => Err(error.into()),
        }
    }

    /// Update the connection's sessions after `response` to a command.
    fn track_sessions(
        &self,
        code: TpmCc,
        flushed: Option<u32>,
        sessions: &[(u32, bool)],
        response: &Response,
    ) {
        let mut held = self.tpm_sessions.lock().unwrap();
        // A session used without continueSession ends with the command. It
        // stays open if the command fails, but forgetting it then only stops
        // this connection flushing it, and the kernel flushes it on disconnect;
        // remembering a handle the TPM may hand to someone else would be worse.
        for (handle, keep) in sessions {
            if !keep {
                held.remove(handle);
            }
        }
        if response.code() != 0 {
            return;
        }
        match code {
            TpmCc::StartAuthSession | TpmCc::ContextLoad => {
                if let Some(handle) = response.first_handle().filter(|&h| is_session(h)) {
                    held.insert(handle);
                }
            }
            TpmCc::FlushContext => {
                if let Some(handle) = flushed {
                    held.remove(&handle);
                }
            }
            _ => {}
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
        self.auth_failures.record_response(
            &self.peer,
            self.command,
            self.hierarchy,
            response.code(),
        );
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
    use std::time::Duration;

    use crate::testing::{FakeUpstream, answering, broker, command, frame};

    use super::*;

    const GET_RANDOM: u32 = 0x17b;
    const AUTH_FAIL: u32 = 0x98e;

    #[tokio::test]
    async fn denied_commands_never_reach_upstream() {
        let upstream = FakeUpstream::echo();
        let forwarded = upstream.commands.clone();
        let broker = broker(Policy::from_json("{}", &[]), upstream, 0);
        let client = broker.admit(Peer::new(1000, 100), Priority(10));

        assert!(matches!(
            client.execute(command(GET_RANDOM, &[])).await,
            Err(BrokerError::Denied {
                command_code: GET_RANDOM,
                denial: Denial::NoProfile,
            })
        ));
        assert!(forwarded.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn policy_replacement_affects_subsequent_commands() {
        let upstream = FakeUpstream::echo();
        let forwarded = upstream.commands.clone();
        let broker = broker(Policy::from_json("{}", &[]), upstream, 0);
        let client = broker.admit(Peer::new(1000, 100), Priority(0));

        assert!(client.execute(command(GET_RANDOM, &[])).await.is_err());
        broker.replace_policy(Policy::allow_all());
        client.execute(command(GET_RANDOM, &[])).await.unwrap();
        assert_eq!(*forwarded.lock().unwrap(), [GET_RANDOM]);
    }

    #[tokio::test]
    async fn admission_caps_priority() {
        let policy = Policy::from_json(
            r#"{"rules": [{"subject": {"uid": 1000}, "profile": "all", "max_priority": 3}]}"#,
            &[("all", r#"{"commands": ["*"]}"#)],
        );
        let broker = broker(policy, FakeUpstream::echo(), 0);

        assert_eq!(
            broker.admit(Peer::new(1000, 100), Priority(50)).priority(),
            Priority(3)
        );
    }

    #[tokio::test]
    async fn counts_lockout_failures_per_uid() {
        let broker = broker(Policy::allow_all(), answering(AUTH_FAIL), 0);
        let first = broker.admit(Peer::new(1000, 100), Priority(0));
        let second = broker.admit(Peer::new(1001, 100), Priority(0));

        // The failure is still relayed to the client.
        let response = first.execute(command(GET_RANDOM, &[])).await.unwrap();
        assert_eq!(response.code(), AUTH_FAIL);
        first.execute(command(GET_RANDOM, &[])).await.unwrap();
        second.execute(command(GET_RANDOM, &[])).await.unwrap();

        assert_eq!(broker.auth_failures.total(), 3);
        assert_eq!(broker.auth_failures.for_uid(1000), 2);
        assert_eq!(broker.auth_failures.for_uid(1001), 1);
    }

    #[tokio::test]
    async fn locked_out_uids_are_refused_without_reaching_upstream() {
        let broker = broker(Policy::allow_all(), answering(AUTH_FAIL), 2);
        let first = broker.admit(Peer::new(1000, 100), Priority(0));
        let second = broker.admit(Peer::new(1000, 100), Priority(0));
        let other = broker.admit(Peer::new(1001, 100), Priority(0));

        first.execute(command(GET_RANDOM, &[])).await.unwrap();
        first.execute(command(GET_RANDOM, &[])).await.unwrap();

        // Every connection from the locked-out UID is refused, and the refused
        // commands never reach the TPM, so they aren't counted.
        for client in [&first, &second] {
            assert!(matches!(
                client.execute(command(GET_RANDOM, &[])).await,
                Err(BrokerError::LockedOut {
                    command_code: GET_RANDOM
                })
            ));
        }
        assert_eq!(broker.auth_failures.for_uid(1000), 2);

        // Other users still reach the TPM.
        other.execute(command(GET_RANDOM, &[])).await.unwrap();
        assert_eq!(broker.auth_failures.for_uid(1001), 1);
    }

    /// `TPM2_CreatePrimary` under the owner hierarchy with an empty password
    /// session; the parameters don't matter here.
    fn create_primary_owner() -> Command {
        let mut body = Vec::from(0x4000_0001u32.to_be_bytes());
        // Authorization area: one empty password session (TPM_RS_PW).
        body.extend_from_slice(&9u32.to_be_bytes());
        body.extend_from_slice(&0x4000_0009u32.to_be_bytes());
        body.extend_from_slice(&[0, 0, 0, 0, 0]);
        Command::parse(frame(0x8002, 0x131, &body), 4096).unwrap()
    }

    #[tokio::test]
    async fn wrong_hierarchy_passwords_count_toward_the_uid_limit() {
        // TPM_RC_BAD_AUTH for session 1.
        let broker = broker(Policy::allow_all(), answering(0x9a2), 2);
        let client = broker.admit(Peer::new(1000, 100), Priority(0));

        // BAD_AUTH for a command that doesn't authorize a hierarchy (an
        // object without DA protection, say) isn't counted.
        client.execute(command(GET_RANDOM, &[])).await.unwrap();
        assert_eq!(broker.auth_failures.for_uid(1000), 0);

        for _ in 0..2 {
            let response = client.execute(create_primary_owner()).await.unwrap();
            assert_eq!(response.code(), 0x9a2);
        }
        assert!(matches!(
            client.execute(create_primary_owner()).await,
            Err(BrokerError::LockedOut { .. })
        ));
        // The TPM didn't count them, so neither does the total.
        assert_eq!(broker.auth_failures.total(), 0);
    }

    #[tokio::test]
    async fn concurrent_connections_cannot_exceed_the_lockout_limit() {
        let upstream = answering(AUTH_FAIL).with_delay(Duration::from_millis(5));
        let forwarded = upstream.commands.clone();
        let broker = broker(Policy::allow_all(), upstream, 2);

        // Every command is submitted before any response comes back.
        let tasks: Vec<_> = (0..16)
            .map(|_| {
                let client = broker.admit(Peer::new(1000, 100), Priority(0));
                tokio::spawn(async move { client.execute(command(GET_RANDOM, &[])).await })
            })
            .collect();
        let mut refused = 0;
        for task in tasks {
            if let Err(BrokerError::LockedOut { .. }) = task.await.unwrap() {
                refused += 1;
            }
        }

        assert_eq!(forwarded.lock().unwrap().len(), 2);
        assert_eq!(broker.auth_failures.for_uid(1000), 2);
        assert_eq!(refused, 14);
    }
}
