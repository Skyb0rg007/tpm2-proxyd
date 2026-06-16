// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: BSD-2-Clause

//! On-disk configuration model and loading.
//!
//! This is a deliberately small, test-only JSON format. Long-term policy
//! updates are expected to arrive through the Varlink management interface once
//! protocol upgrade support exists upstream.

use std::{fs, io, path::Path};

use serde::{Deserialize, Serialize};
use tpm2_rs_base::constants::TpmCc;

use crate::policy::{CommandRule, Decision, Policy, PolicyConfig, PriorityRule, Subject};

/// Test configuration loaded from `--config=<path>`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Per-UID command grants and priority caps.
    pub users: Vec<UserRule>,
    /// Per-group command grants and priority caps.
    pub groups: Vec<GroupRule>,
}

/// Commands and priority assigned to a Unix user.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UserRule {
    /// Unix UID matched against connecting peers.
    pub uid: u32,
    /// TPM command codes this UID may execute; empty means every command.
    pub commands: Vec<u32>,
    /// Highest connection priority this UID may receive.
    pub priority: i32,
}

/// Commands and priority assigned to a Unix group.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupRule {
    /// Unix GID matched against primary and supplementary peer groups.
    pub gid: u32,
    /// TPM command codes this group may execute; empty means every command.
    pub commands: Vec<u32>,
    /// Highest connection priority this group may receive.
    pub priority: i32,
}

/// Configuration load error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Reading the config file failed.
    #[error("failed to read config {path}: {source}")]
    Read {
        /// Config file path.
        path: String,
        /// Underlying I/O error.
        source: io::Error,
    },
    /// Parsing the config file failed.
    #[error("failed to parse config {path}: {source}")]
    Parse {
        /// Config file path.
        path: String,
        /// Underlying JSON error.
        source: serde_json::Error,
    },
}

impl Config {
    /// Load a JSON configuration from disk.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref();
        let display = path.display().to_string();
        let data = fs::read_to_string(path).map_err(|source| Error::Read {
            path: display.clone(),
            source,
        })?;
        serde_json::from_str(&data).map_err(|source| Error::Parse {
            path: display,
            source,
        })
    }

    /// Compile this test configuration into the runtime policy model.
    pub fn policy_config(&self) -> PolicyConfig {
        let mut command_rules = Vec::with_capacity(self.users.len() + self.groups.len());
        let mut priority_rules = Vec::with_capacity(self.users.len() + self.groups.len());

        for rule in &self.users {
            let subject = Subject {
                uid: Some(rule.uid),
                gid: None,
            };
            command_rules.push(CommandRule {
                subject: subject.clone(),
                commands: rule.commands.iter().copied().map(TpmCc).collect(),
                decision: Decision::Allow,
            });
            priority_rules.push(PriorityRule {
                subject,
                max_priority: rule.priority,
            });
        }

        for rule in &self.groups {
            let subject = Subject {
                uid: None,
                gid: Some(rule.gid),
            };
            command_rules.push(CommandRule {
                subject: subject.clone(),
                commands: rule.commands.iter().copied().map(TpmCc).collect(),
                decision: Decision::Allow,
            });
            priority_rules.push(PriorityRule {
                subject,
                max_priority: rule.priority,
            });
        }

        PolicyConfig {
            default_decision: Decision::Deny,
            default_max_priority: 0,
            command_rules,
            priority_rules,
        }
    }

    /// Compile this test configuration into a runtime policy evaluator.
    pub fn policy(&self) -> Policy {
        Policy::new(self.policy_config())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{scheduler::Priority, server::peer::Peer, tpm::Command};

    fn command(code: u32) -> Command {
        let mut bytes = Vec::from(0x8001u16.to_be_bytes());
        bytes.extend_from_slice(&10u32.to_be_bytes());
        bytes.extend_from_slice(&code.to_be_bytes());
        Command::parse(bytes, 4096).unwrap()
    }

    #[test]
    fn deserializes_test_policy_format() {
        let config: Config = serde_json::from_str(
            r#"{
                "users": [{
                    "uid": 1000,
                    "commands": [379],
                    "priority": 7
                }],
                "groups": [{
                    "gid": 42,
                    "commands": [378, 379],
                    "priority": 3
                }]
            }"#,
        )
        .unwrap();

        assert_eq!(config.users[0].uid, 1000);
        assert_eq!(config.users[0].commands, [0x17b]);
        assert_eq!(config.groups[0].gid, 42);
        assert_eq!(config.groups[0].priority, 3);
    }

    #[test]
    fn compiles_user_rules_to_runtime_policy() {
        let policy = Config {
            users: vec![UserRule {
                uid: 1000,
                commands: vec![0x17b],
                priority: 7,
            }],
            groups: Vec::new(),
        }
        .policy();

        assert_eq!(
            policy.authorize(&Peer::new(1000, 100), &command(0x17b)),
            Decision::Allow
        );
        assert_eq!(
            policy.authorize(&Peer::new(1000, 100), &command(0x17a)),
            Decision::Deny
        );
        assert_eq!(
            policy.cap_priority(&Peer::new(1000, 100), Priority(100)),
            Priority(7)
        );
    }

    #[test]
    fn compiles_group_rules_to_runtime_policy() {
        let policy = Config {
            users: Vec::new(),
            groups: vec![GroupRule {
                gid: 42,
                commands: vec![0x17a],
                priority: 4,
            }],
        }
        .policy();
        let peer = Peer {
            uid: 1000,
            primary_gid: 100,
            supplementary_gids: vec![42],
        };

        assert_eq!(policy.authorize(&peer, &command(0x17a)), Decision::Allow);
        assert_eq!(policy.authorize(&peer, &command(0x17b)), Decision::Deny);
        assert_eq!(policy.cap_priority(&peer, Priority(100)), Priority(4));
    }

    #[test]
    fn rejects_unknown_fields() {
        let err = serde_json::from_str::<Config>(
            r#"{
                "users": [{
                    "uid": 1000,
                    "commands": [379],
                    "priority": 7,
                    "extra": true
                }]
            }"#,
        )
        .unwrap_err();

        assert!(err.to_string().contains("unknown field"));
    }
}
