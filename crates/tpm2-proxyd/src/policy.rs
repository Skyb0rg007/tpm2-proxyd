// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! Per-peer TPM command authorization and priority limits.
//!
//! The policy file (`--config=<path>`) assigns each peer a command profile (see
//! [`crate::profile`]) and a priority cap:
//!
//! ```json
//! {
//!   "default_profile": "standard",
//!   "default_max_priority": 0,
//!   "rules": [
//!     { "subject": { "gid": 1001 }, "profile": "full", "max_priority": 10 }
//!   ]
//! }
//! ```
//!
//! Rules are evaluated in order and the first one whose subject matches the peer
//! wins. A subject may name a UID, a group (primary or supplementary), both, or,
//! if empty, every peer. A peer that matches no rule gets `default_profile`, or
//! no access at all if that's unset. A rule without `max_priority` uses
//! `default_max_priority`.
//!
//! Profiles are loaded from the `profiles` directory next to the policy file.
//! Loading fails if any profile the policy names is missing or invalid, and
//! `SIGHUP` reloads the policy and its profiles together.

use std::{collections::HashMap, fmt, fs, io, path::Path, sync::Arc};

use serde::Deserialize;

use crate::{
    profile::{Profile, Refusal},
    scheduler::Priority,
    server::peer::Peer,
    tpm::Command,
};

/// Peer selector.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
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

/// On-disk form of the policy file.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyConfig {
    /// Profile for peers no rule matches; unset means no access.
    pub default_profile: Option<String>,
    /// Priority cap for peers no rule matches, and for rules without one.
    pub default_max_priority: i32,
    /// Ordered rules; the first match wins.
    pub rules: Vec<Rule>,
}

/// One ordered policy rule.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Peer selector.
    #[serde(default)]
    pub subject: Subject,
    /// Profile for matching peers.
    pub profile: String,
    /// Priority cap for matching peers, if not `default_max_priority`.
    pub max_priority: Option<i32>,
}

/// Policy or profile load error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Reading a file failed.
    #[error("failed to read {path}: {source}")]
    Read {
        /// File path.
        path: String,
        /// Underlying I/O error.
        source: io::Error,
    },
    /// A file isn't a valid policy or profile.
    #[error("invalid {path}: {message}")]
    Invalid {
        /// File path.
        path: String,
        /// What's wrong with it.
        message: String,
    },
}

/// Why the policy denied a command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Denial {
    /// No rule or default gives the peer a profile.
    NoProfile,
    /// The peer's profile refused the command.
    Refused {
        /// Profile that refused it.
        profile: String,
        /// Why.
        refusal: Refusal,
    },
}

impl Denial {
    /// The response code the client gets for this denial.
    ///
    /// It's a TPM-format code in the resource-manager layer
    /// (`TSS2_RESMGR_RC_LAYER`), which tpm2-tss decodes as a TPM error the
    /// resource manager reported: `TPM_RC_COMMAND_CODE` for a command the peer
    /// may not run, `TPM_RC_HANDLE` with the handle's position for a handle it
    /// may not use.
    pub fn response_code(&self) -> u32 {
        const RESMGR_LAYER: u32 = 11 << 16;
        const TPM_RC_COMMAND_CODE: u32 = 0x143;
        const TPM_RC_HANDLE: u32 = 0x08b;
        RESMGR_LAYER
            | match self {
                Self::Refused {
                    refusal: Refusal::Handle { position, .. },
                    ..
                } => TPM_RC_HANDLE | ((*position as u32) << 8),
                _ => TPM_RC_COMMAND_CODE,
            }
    }
}

impl fmt::Display for Denial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoProfile => write!(f, "no profile"),
            Self::Refused { profile, refusal } => write!(f, "profile {profile}: {refusal}"),
        }
    }
}

/// Compiled policy evaluator.
#[derive(Clone, Debug)]
pub struct Policy {
    default_profile: Option<Arc<Profile>>,
    default_max_priority: i32,
    rules: Vec<CompiledRule>,
}

#[derive(Clone, Debug)]
struct CompiledRule {
    subject: Subject,
    profile: Arc<Profile>,
    max_priority: i32,
}

impl Policy {
    /// Load the policy file at `path` and the profiles it names from the
    /// `profiles` directory beside it.
    pub fn load(path: &Path) -> Result<Self, Error> {
        let display = path.display().to_string();
        let data = fs::read_to_string(path).map_err(|source| Error::Read {
            path: display.clone(),
            source,
        })?;
        let config = serde_json::from_str(&data).map_err(|error| Error::Invalid {
            path: display,
            message: error.to_string(),
        })?;
        let profiles = path.parent().unwrap_or(Path::new(".")).join("profiles");
        Self::compile(config, |name| Profile::load(&profiles, name))
    }

    /// Compile `config`, loading each profile it names once with `load`.
    pub fn compile(
        config: PolicyConfig,
        mut load: impl FnMut(&str) -> Result<Profile, Error>,
    ) -> Result<Self, Error> {
        let mut profiles = HashMap::new();
        let mut profile = |name: &str| -> Result<Arc<Profile>, Error> {
            if let Some(profile) = profiles.get(name) {
                return Ok(Arc::clone(profile));
            }
            let profile = Arc::new(load(name)?);
            profiles.insert(name.to_owned(), Arc::clone(&profile));
            Ok(profile)
        };

        let default_profile = config
            .default_profile
            .as_deref()
            .map(&mut profile)
            .transpose()?;
        let rules = config
            .rules
            .into_iter()
            .map(|rule| {
                Ok(CompiledRule {
                    profile: profile(&rule.profile)?,
                    subject: rule.subject,
                    max_priority: rule.max_priority.unwrap_or(config.default_max_priority),
                })
            })
            .collect::<Result<_, Error>>()?;
        Ok(Self {
            default_profile,
            default_max_priority: config.default_max_priority,
            rules,
        })
    }

    /// The profile and priority cap that apply to `peer`.
    fn lookup(&self, peer: &Peer) -> (Option<&Profile>, i32) {
        match self.rules.iter().find(|rule| rule.subject.matches(peer)) {
            Some(rule) => (Some(&rule.profile), rule.max_priority),
            None => (self.default_profile.as_deref(), self.default_max_priority),
        }
    }

    /// Name of the profile that applies to `peer`, if any.
    pub fn profile_name(&self, peer: &Peer) -> Option<&str> {
        self.lookup(peer).0.map(Profile::name)
    }

    /// Decide whether `peer` may execute `command`.
    pub fn authorize(&self, peer: &Peer, command: &Command) -> Result<(), Denial> {
        let profile = self.lookup(peer).0.ok_or(Denial::NoProfile)?;
        profile.check(command).map_err(|refusal| Denial::Refused {
            profile: profile.name().to_owned(),
            refusal,
        })
    }

    /// Bound a requested connection priority by the cap that applies to `peer`.
    pub fn cap_priority(&self, peer: &Peer, requested: Priority) -> Priority {
        Priority(requested.0.min(self.lookup(peer).1))
    }

    /// Compile a policy from JSON text and `(name, JSON)` profiles, for tests.
    #[cfg(test)]
    pub fn from_json(policy: &str, profiles: &[(&str, &str)]) -> Self {
        let config = serde_json::from_str(policy).expect("valid test policy");
        Self::compile(config, |name| {
            let (_, json) = profiles
                .iter()
                .find(|(candidate, _)| *candidate == name)
                .unwrap_or_else(|| panic!("no test profile {name}"));
            Ok(Profile::parse(name, json).expect("valid test profile"))
        })
        .expect("test policy compiles")
    }

    /// Policy allowing every peer every command at any priority, for tests.
    #[cfg(test)]
    pub fn allow_all() -> Self {
        Self::from_json(
            r#"{"default_profile": "all", "default_max_priority": 2147483647}"#,
            &[("all", r#"{"commands": ["*"], "handles": ["*"]}"#)],
        )
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

    const GET_RANDOM: u32 = 0x17b;
    const GET_CAPABILITY: u32 = 0x17a;

    const PROFILES: &[(&str, &str)] = &[
        ("random", r#"{"commands": ["TPM_CC_GetRandom"]}"#),
        ("all", r#"{"commands": ["*"]}"#),
    ];

    #[test]
    fn first_matching_rule_wins() {
        let policy = Policy::from_json(
            r#"{
                "default_profile": "random",
                "rules": [
                    {"subject": {"uid": 1000}, "profile": "all"},
                    {"subject": {"gid": 100}, "profile": "random"}
                ]
            }"#,
            PROFILES,
        );

        assert_eq!(
            policy.authorize(&Peer::new(1000, 100), &command(GET_CAPABILITY)),
            Ok(())
        );
        assert_eq!(
            policy.authorize(&Peer::new(1001, 100), &command(GET_CAPABILITY)),
            Err(Denial::Refused {
                profile: "random".into(),
                refusal: Refusal::Command,
            })
        );
        assert_eq!(policy.profile_name(&Peer::new(1001, 100)), Some("random"));
    }

    #[test]
    fn peers_without_a_profile_are_denied_everything() {
        let policy = Policy::from_json(
            r#"{"rules": [{"subject": {"uid": 1000}, "profile": "all"}]}"#,
            PROFILES,
        );

        assert_eq!(
            policy.authorize(&Peer::new(1001, 100), &command(GET_RANDOM)),
            Err(Denial::NoProfile)
        );
        assert_eq!(policy.profile_name(&Peer::new(1001, 100)), None);
    }

    #[test]
    fn supplementary_groups_match_rules() {
        let policy = Policy::from_json(
            r#"{"rules": [{"subject": {"gid": 42}, "profile": "all"}]}"#,
            PROFILES,
        );
        let peer = Peer {
            uid: 1000,
            primary_gid: 100,
            supplementary_gids: vec![42],
            pid: None,
        };

        assert_eq!(policy.authorize(&peer, &command(GET_RANDOM)), Ok(()));
    }

    #[test]
    fn requested_priority_is_capped_per_subject() {
        let policy = Policy::from_json(
            r#"{
                "default_profile": "random",
                "default_max_priority": 1,
                "rules": [
                    {"subject": {"uid": 1000}, "profile": "all", "max_priority": 7},
                    {"subject": {"uid": 1002}, "profile": "all"}
                ]
            }"#,
            PROFILES,
        );

        let cap = |uid, requested| policy.cap_priority(&Peer::new(uid, 100), Priority(requested));
        assert_eq!(cap(1000, 20), Priority(7));
        assert_eq!(cap(1000, -2), Priority(-2));
        // No rule: the default cap.
        assert_eq!(cap(1001, 20), Priority(1));
        // A rule without max_priority: also the default cap.
        assert_eq!(cap(1002, 20), Priority(1));
    }

    #[test]
    fn loads_profiles_from_beside_the_policy_file() {
        let dir = std::env::temp_dir().join(format!("tpm2-proxyd-policy-{}", std::process::id()));
        fs::create_dir_all(dir.join("profiles")).unwrap();
        fs::write(dir.join("policy.json"), r#"{"default_profile": "random"}"#).unwrap();
        fs::write(dir.join("profiles/random.json"), PROFILES[0].1).unwrap();
        let loaded = Policy::load(&dir.join("policy.json"));
        fs::write(dir.join("policy.json"), r#"{"default_profile": "missing"}"#).unwrap();
        let missing = Policy::load(&dir.join("policy.json"));
        fs::remove_dir_all(&dir).unwrap();

        assert_eq!(
            loaded
                .unwrap()
                .authorize(&Peer::new(1000, 100), &command(GET_RANDOM)),
            Ok(())
        );
        assert!(matches!(missing, Err(Error::Read { .. })), "{missing:?}");
    }

    #[test]
    fn denials_map_to_resource_manager_response_codes() {
        let refused = |refusal| Denial::Refused {
            profile: "test".into(),
            refusal,
        };
        assert_eq!(Denial::NoProfile.response_code(), 0x000b_0143);
        assert_eq!(refused(Refusal::Command).response_code(), 0x000b_0143);
        assert_eq!(
            refused(Refusal::Handle {
                position: 2,
                handle: 0x8100_0001
            })
            .response_code(),
            0x000b_028b
        );
    }

    #[test]
    fn rejects_invalid_policies() {
        let cases = [
            ("unknown field", r#"{"rules": [], "extra": true}"#),
            (
                "rule without a profile",
                r#"{"rules": [{"subject": {"uid": 1}}]}"#,
            ),
            ("old command_rules format", r#"{"command_rules": []}"#),
        ];
        for (name, json) in cases {
            assert!(
                serde_json::from_str::<PolicyConfig>(json).is_err(),
                "{name}"
            );
        }
    }
}
