// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: BSD-2-Clause

//! Per-peer TPM command authorization and priority limits.
//!
//! Command rules are evaluated in declaration order and the first matching rule
//! wins. A rule may match a UID, a group, both, or every peer; an empty command
//! list matches every TPM command. Priority rules use the same subject matching
//! and cap the priority fixed for a connection at admission time.

#![allow(dead_code)] // Main/config wiring is implemented in a later change.

use serde::{Deserialize, Serialize};

use crate::{scheduler::Priority, server::peer::Peer, tpm::Command};

/// Rule decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// Permit the command.
    Allow,
    /// Reject the command.
    Deny,
}

/// Subject selector shared by command and priority rules.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Subject {
    /// Match only this UID.
    pub uid: Option<u32>,
    /// Match peers belonging to this primary or supplementary group.
    pub gid: Option<u32>,
}

impl Subject {
    fn matches(&self, peer: &Peer) -> bool {
        self.uid.is_none_or(|uid| peer.uid == uid)
            && self.gid.is_none_or(|gid| peer.belongs_to(gid))
    }
}

/// One ordered command authorization rule.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct CommandRule {
    /// Peer selector.
    pub subject: Subject,
    /// TPM command codes matched by this rule; empty means all commands.
    pub commands: Vec<u32>,
    /// Decision returned when the rule matches.
    pub decision: Decision,
}

impl Default for CommandRule {
    fn default() -> Self {
        Self {
            subject: Subject::default(),
            commands: Vec::new(),
            decision: Decision::Deny,
        }
    }
}

/// One ordered connection-priority cap rule.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct PriorityRule {
    /// Peer selector.
    pub subject: Subject,
    /// Highest priority the matching peer may request.
    pub max_priority: i32,
}

/// Deserializable policy configuration.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyConfig {
    /// Decision when no command rule matches.
    pub default_decision: Decision,
    /// Priority cap when no priority rule matches.
    pub default_max_priority: i32,
    /// Ordered command rules.
    pub command_rules: Vec<CommandRule>,
    /// Ordered priority cap rules.
    pub priority_rules: Vec<PriorityRule>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            default_decision: Decision::Deny,
            default_max_priority: 0,
            command_rules: Vec::new(),
            priority_rules: Vec::new(),
        }
    }
}

/// Compiled policy evaluator.
#[derive(Clone, Debug)]
pub struct Policy {
    config: PolicyConfig,
}

impl Policy {
    /// Compile a policy configuration.
    pub fn new(config: PolicyConfig) -> Self {
        Self { config }
    }

    /// Convenience policy used by trusted/internal callers and tests.
    pub fn allow_all() -> Self {
        Self::new(PolicyConfig {
            default_decision: Decision::Allow,
            default_max_priority: i32::MAX,
            ..PolicyConfig::default()
        })
    }

    /// Decide whether `peer` may execute `command`.
    pub fn authorize(&self, peer: &Peer, command: &Command) -> Decision {
        self.config
            .command_rules
            .iter()
            .find(|rule| {
                rule.subject.matches(peer)
                    && (rule.commands.is_empty() || rule.commands.contains(&command.code().0))
            })
            .map_or(self.config.default_decision, |rule| rule.decision)
    }

    /// Bound a requested connection priority according to the first matching
    /// priority rule, or the default cap.
    pub fn cap_priority(&self, peer: &Peer, requested: Priority) -> Priority {
        let cap = self
            .config
            .priority_rules
            .iter()
            .find(|rule| rule.subject.matches(peer))
            .map_or(self.config.default_max_priority, |rule| rule.max_priority);
        Priority(requested.0.min(cap))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(code: u32) -> Command {
        let mut bytes = Vec::from(0x8001u16.to_be_bytes());
        bytes.extend_from_slice(&10u32.to_be_bytes());
        bytes.extend_from_slice(&code.to_be_bytes());
        Command::parse(bytes, 4096).unwrap()
    }

    #[test]
    fn first_matching_command_rule_wins() {
        let policy = Policy::new(PolicyConfig {
            command_rules: vec![
                CommandRule {
                    subject: Subject {
                        uid: Some(1000),
                        gid: None,
                    },
                    commands: vec![0x17b],
                    decision: Decision::Allow,
                },
                CommandRule {
                    subject: Subject::default(),
                    commands: vec![0x17b],
                    decision: Decision::Deny,
                },
            ],
            ..PolicyConfig::default()
        });

        assert_eq!(
            policy.authorize(&Peer::new(1000, 100), &command(0x17b)),
            Decision::Allow
        );
        assert_eq!(
            policy.authorize(&Peer::new(1001, 100), &command(0x17b)),
            Decision::Deny
        );
        assert_eq!(
            policy.authorize(&Peer::new(1000, 100), &command(0x17a)),
            Decision::Deny
        );
    }

    #[test]
    fn supplementary_groups_match_rules() {
        let policy = Policy::new(PolicyConfig {
            command_rules: vec![CommandRule {
                subject: Subject {
                    uid: None,
                    gid: Some(42),
                },
                commands: Vec::new(),
                decision: Decision::Allow,
            }],
            ..PolicyConfig::default()
        });
        let peer = Peer {
            uid: 1000,
            primary_gid: 100,
            supplementary_gids: vec![42],
        };

        assert_eq!(policy.authorize(&peer, &command(0x17b)), Decision::Allow);
    }

    #[test]
    fn requested_priority_is_capped_per_subject() {
        let policy = Policy::new(PolicyConfig {
            default_max_priority: 1,
            priority_rules: vec![PriorityRule {
                subject: Subject {
                    uid: Some(1000),
                    gid: None,
                },
                max_priority: 7,
            }],
            ..PolicyConfig::default()
        });

        assert_eq!(
            policy.cap_priority(&Peer::new(1000, 100), Priority(20)),
            Priority(7)
        );
        assert_eq!(
            policy.cap_priority(&Peer::new(1001, 100), Priority(20)),
            Priority(1)
        );
        assert_eq!(
            policy.cap_priority(&Peer::new(1000, 100), Priority(-2)),
            Priority(-2)
        );
    }

    #[test]
    fn policy_config_deserializes_from_json() {
        let config: PolicyConfig = serde_json::from_str(
            r#"{
                "default_decision": "deny",
                "default_max_priority": 1,
                "command_rules": [{
                    "subject": {"uid": 1000},
                    "commands": [379],
                    "decision": "allow"
                }],
                "priority_rules": [{
                    "subject": {"gid": 42},
                    "max_priority": 5
                }]
            }"#,
        )
        .unwrap();

        assert_eq!(config.command_rules[0].commands, [0x17b]);
        assert_eq!(config.priority_rules[0].max_priority, 5);
    }
}
