// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: BSD-2-Clause

//! Authorized command submission pipeline.
//!
//! The broker is the only path from a downstream client to the command
//! scheduler. It caps the connection priority once at admission, checks every
//! parsed command against the current policy, and only then submits it to the
//! serialized upstream worker.

#![allow(dead_code)] // Main/config wiring is implemented in a later change.

use std::sync::{Arc, RwLock};

use crate::{
    policy::{Decision, Policy},
    scheduler::{CommandScheduler, ExecuteError, Priority},
    server::peer::Peer,
    tpm::{Command, Response},
};

/// Shared broker state.
#[derive(Clone)]
pub struct Broker {
    policy: Arc<RwLock<Policy>>,
    scheduler: CommandScheduler,
}

impl Broker {
    /// Construct a broker from an active policy and command scheduler.
    pub fn new(policy: Policy, scheduler: CommandScheduler) -> Self {
        Self {
            policy: Arc::new(RwLock::new(policy)),
            scheduler,
        }
    }

    /// Atomically replace the active policy for future decisions.
    pub fn replace_policy(&self, policy: Policy) {
        *self.policy.write().unwrap() = policy;
    }

    /// Admit a peer and cap its requested priority for the connection lifetime.
    pub fn admit(&self, peer: Peer, requested_priority: Priority) -> Client {
        let priority = self
            .policy
            .read()
            .unwrap()
            .cap_priority(&peer, requested_priority);
        Client {
            broker: self.clone(),
            peer,
            priority,
        }
    }
}

/// Admitted client with a fixed, policy-bounded priority.
#[derive(Clone)]
pub struct Client {
    broker: Broker,
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
        let code = command.code().value();
        let decision = self
            .broker
            .policy
            .read()
            .unwrap()
            .authorize(&self.peer, &command);
        if decision == Decision::Deny {
            return Err(BrokerError::Denied { command_code: code });
        }

        self.broker
            .scheduler
            .execute(self.priority, command)
            .await
            .map_err(Into::into)
    }
}

/// Failure from the authorization/dispatch pipeline.
#[derive(Debug, thiserror::Error)]
pub enum BrokerError {
    /// Policy denied this command.
    #[error("policy denied TPM command {command_code:#010x}")]
    Denied {
        /// Denied TPM command code.
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
        policy::{CommandRule, PolicyConfig, PriorityRule, Subject},
        tpm::DEFAULT_MAX_PACKET_SIZE,
        upstream::{Upstream, UpstreamError},
    };

    use super::*;

    struct CountingUpstream {
        count: Arc<AtomicUsize>,
        codes: Arc<Mutex<Vec<u32>>>,
    }

    #[async_trait::async_trait]
    impl Upstream for CountingUpstream {
        async fn transact(&mut self, command: &Command) -> Result<Response, UpstreamError> {
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
        let broker = Broker::new(Policy::new(PolicyConfig::default()), scheduler);
        let client = broker.admit(Peer::new(1000, 100), Priority(10));

        assert!(matches!(
            client.execute(command(0x17b)).await,
            Err(BrokerError::Denied {
                command_code: 0x17b
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
        let broker = Broker::new(Policy::new(PolicyConfig::default()), scheduler);
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
        let policy = Policy::new(PolicyConfig {
            command_rules: vec![CommandRule {
                subject: Subject::default(),
                commands: Vec::new(),
                decision: Decision::Allow,
            }],
            priority_rules: vec![PriorityRule {
                subject: Subject {
                    uid: Some(1000),
                    gid: None,
                },
                max_priority: 3,
            }],
            ..PolicyConfig::default()
        });
        let broker = Broker::new(policy, scheduler);

        assert_eq!(
            broker.admit(Peer::new(1000, 100), Priority(50)).priority(),
            Priority(3)
        );
    }
}
