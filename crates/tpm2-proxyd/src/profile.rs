// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! Command profiles: named sets of TPM commands a peer may run, and the handles
//! those commands may reference.
//!
//! No profiles are built in. Each one is a JSON file, `<name>.json`, in the
//! profiles directory next to the policy file (`/etc/tpm2-proxyd/profiles/` by
//! default), and names are written as the TPM specification spells them
//! (compared case-insensitively):
//!
//! ```json
//! {
//!   "handles": ["TPM_HT_TRANSIENT", "TPM_HT_HMAC_SESSION", "TPM_RH_NULL"],
//!   "commands": ["TPM_CC_GetRandom", "TPM_CC_CreatePrimary"],
//!   "command_handles": {
//!     "TPM_CC_CreatePrimary": ["TPM_RH_OWNER", "TPM_RH_NULL"]
//!   }
//! }
//! ```
//!
//! - `commands` lists the commands the profile allows; `"*"` allows every
//!   command the proxy recognizes.
//! - `handles` lists the handles those commands may reference: a handle type
//!   (`TPM_HT_*`) matches every handle of that type, a permanent handle
//!   (`TPM_RH_*`) matches only itself, and `"*"` matches any handle.
//! - `command_handles` replaces `handles` for the commands it names, each of
//!   which must also be in `commands`.
//!
//! Only the command's handle area is checked. Sessions in the authorization
//! area are left to the kernel resource manager, which gives every connection
//! its own set of transient objects and flushes the objects and sessions a
//! connection leaves loaded. It doesn't virtualize session handles, though,
//! and it stops tracking a session the client saves with `TPM2_ContextSave`,
//! so that session outlives the connection. A profile that lets users save
//! sessions lets them fill the TPM's session slots for everyone; the shipped
//! `standard` profile only lets them save transient objects.

use std::{
    collections::{HashMap, HashSet},
    fmt,
    path::Path,
    sync::LazyLock,
};

use serde::Deserialize;
use tpm2_protocol::data::{TpmCc, TpmHt, TpmRh};

use crate::{policy::Error, tpm::Command};

/// A compiled command profile.
#[derive(Clone, Debug)]
pub struct Profile {
    name: String,
    commands: Commands,
    handles: Handles,
    command_handles: HashMap<TpmCc, Handles>,
}

#[derive(Clone, Debug)]
enum Commands {
    All,
    Only(HashSet<TpmCc>),
}

/// Handles a command may reference.
#[derive(Clone, Debug, Default)]
struct Handles(Vec<HandleMatch>);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HandleMatch {
    Any,
    Type(u8),
    Exact(u32),
}

/// Why a profile refused a command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The profile doesn't allow the command.
    Command,
    /// The command references a handle the profile doesn't allow for it.
    Handle {
        /// The handle's position in the handle area, from 1.
        position: usize,
        /// The handle.
        handle: u32,
    },
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Command => write!(f, "command not in profile"),
            Self::Handle { handle, .. } => write!(f, "handle {handle:#010x} not allowed"),
        }
    }
}

/// On-disk form of a profile.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileFile {
    commands: Vec<String>,
    #[serde(default)]
    handles: Vec<String>,
    #[serde(default)]
    command_handles: HashMap<String, Vec<String>>,
}

impl Profile {
    /// Load the profile `name` from `dir/<name>.json`.
    pub fn load(dir: &Path, name: &str) -> Result<Self, Error> {
        let path = dir.join(format!("{name}.json"));
        let display = path.display().to_string();
        if !is_valid_name(name) {
            return Err(Error::Invalid {
                path: display,
                message: format!("invalid profile name {name:?}"),
            });
        }
        let data = std::fs::read_to_string(&path).map_err(|source| Error::Read {
            path: display.clone(),
            source,
        })?;
        Self::parse(name, &data).map_err(|message| Error::Invalid {
            path: display,
            message,
        })
    }

    /// Parse and compile a profile from its JSON text.
    pub fn parse(name: &str, json: &str) -> Result<Self, String> {
        let file: ProfileFile = serde_json::from_str(json).map_err(|error| error.to_string())?;

        let commands = if file.commands.iter().any(|command| command == "*") {
            Commands::All
        } else {
            let mut commands = HashSet::new();
            for command in &file.commands {
                if !commands.insert(command_code(command)?) {
                    return Err(format!("{command} is listed twice"));
                }
            }
            Commands::Only(commands)
        };

        let mut command_handles = HashMap::new();
        for (command, handles) in &file.command_handles {
            let code = command_code(command)?;
            if let Commands::Only(commands) = &commands
                && !commands.contains(&code)
            {
                return Err(format!(
                    "command_handles names {command}, which isn't in commands"
                ));
            }
            command_handles.insert(code, Handles::parse(handles)?);
        }

        Ok(Self {
            name: name.to_owned(),
            commands,
            handles: Handles::parse(&file.handles)?,
            command_handles,
        })
    }

    /// The profile's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Check `command` against this profile.
    pub fn check(&self, command: &Command) -> Result<(), Refusal> {
        let code = command.code();
        if let Commands::Only(commands) = &self.commands
            && !commands.contains(&code)
        {
            return Err(Refusal::Command);
        }
        let handles = self.command_handles.get(&code).unwrap_or(&self.handles);
        match command
            .handles()
            .iter()
            .enumerate()
            .find(|&(_, &handle)| !handles.allows(handle))
        {
            Some((index, &handle)) => Err(Refusal::Handle {
                position: index + 1,
                handle,
            }),
            None => Ok(()),
        }
    }
}

impl Handles {
    fn parse(names: &[String]) -> Result<Self, String> {
        names
            .iter()
            .map(|name| handle_match(name))
            .collect::<Result<_, _>>()
            .map(Self)
    }

    fn allows(&self, handle: u32) -> bool {
        self.0.iter().any(|allowed| match *allowed {
            HandleMatch::Any => true,
            HandleMatch::Type(ty) => handle >> 24 == u32::from(ty),
            HandleMatch::Exact(exact) => handle == exact,
        })
    }
}

/// Profile names become file names, so they can't name a path.
fn is_valid_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('.')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

fn command_code(name: &str) -> Result<TpmCc, String> {
    static CODES: LazyLock<HashMap<String, TpmCc>> = LazyLock::new(|| {
        (0x100..=0x1ff)
            .chain([0x2000_0000])
            .filter_map(|value| TpmCc::try_from(value).ok())
            .map(|code| (code.to_string().to_ascii_lowercase(), code))
            .collect()
    });
    CODES
        .get(&name.to_ascii_lowercase())
        .copied()
        .ok_or_else(|| format!("unknown command {name:?}"))
}

fn handle_match(name: &str) -> Result<HandleMatch, String> {
    static TYPES: LazyLock<HashMap<String, u8>> = LazyLock::new(|| {
        (0..=u8::MAX)
            .filter_map(|value| TpmHt::try_from(value).ok())
            .map(|ty| (ty.to_string().to_ascii_lowercase(), ty.value()))
            .collect()
    });
    static PERMANENT: LazyLock<HashMap<String, u32>> = LazyLock::new(|| {
        (0x4000_0000..=0x4000_01ff)
            .filter_map(|value| TpmRh::try_from(value).ok())
            .map(|handle| (handle.to_string().to_ascii_lowercase(), handle.value()))
            .collect()
    });
    if name == "*" {
        return Ok(HandleMatch::Any);
    }
    let lower = name.to_ascii_lowercase();
    if let Some(&ty) = TYPES.get(&lower) {
        return Ok(HandleMatch::Type(ty));
    }
    PERMANENT
        .get(&lower)
        .map(|&handle| HandleMatch::Exact(handle))
        .ok_or_else(|| format!("unknown handle {name:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(code: u32, handles: &[u32]) -> Command {
        let size = 10 + 4 * handles.len() as u32;
        let mut bytes = Vec::from(0x8001u16.to_be_bytes());
        bytes.extend_from_slice(&size.to_be_bytes());
        bytes.extend_from_slice(&code.to_be_bytes());
        for handle in handles {
            bytes.extend_from_slice(&handle.to_be_bytes());
        }
        Command::parse(bytes, 4096).unwrap()
    }

    const GET_RANDOM: u32 = 0x17b;
    const READ_PUBLIC: u32 = 0x173;
    const CREATE_PRIMARY: u32 = 0x131;
    const TRANSIENT: u32 = 0x8000_0001;
    const PERSISTENT: u32 = 0x8100_0001;
    const OWNER: u32 = 0x4000_0001;
    const PLATFORM: u32 = 0x4000_000c;

    fn profile() -> Profile {
        Profile::parse(
            "test",
            r#"{
                "handles": ["TPM_HT_TRANSIENT", "TPM_RH_NULL"],
                "commands": ["TPM_CC_GetRandom", "TPM_CC_ReadPublic", "tpm_cc_createprimary"],
                "command_handles": {
                    "TPM_CC_CreatePrimary": ["TPM_RH_OWNER"]
                }
            }"#,
        )
        .unwrap()
    }

    #[test]
    fn allows_listed_commands_with_allowed_handles() {
        let profile = profile();
        assert_eq!(profile.check(&command(GET_RANDOM, &[])), Ok(()));
        assert_eq!(profile.check(&command(READ_PUBLIC, &[TRANSIENT])), Ok(()));
        assert_eq!(profile.check(&command(CREATE_PRIMARY, &[OWNER])), Ok(()));
    }

    #[test]
    fn refuses_unlisted_commands() {
        // TPM2_GetCapability.
        assert_eq!(profile().check(&command(0x17a, &[])), Err(Refusal::Command));
    }

    #[test]
    fn refuses_handles_outside_the_profile() {
        let profile = profile();
        assert_eq!(
            profile.check(&command(READ_PUBLIC, &[PERSISTENT])),
            Err(Refusal::Handle {
                position: 1,
                handle: PERSISTENT
            })
        );
        // command_handles replaces the default handles rather than adding to
        // them, so a transient parent isn't allowed for CreatePrimary.
        assert_eq!(
            profile.check(&command(CREATE_PRIMARY, &[PLATFORM])),
            Err(Refusal::Handle {
                position: 1,
                handle: PLATFORM
            })
        );
    }

    #[test]
    fn wildcards_allow_everything() {
        let profile = Profile::parse("full", r#"{"commands": ["*"], "handles": ["*"]}"#).unwrap();
        assert_eq!(profile.check(&command(READ_PUBLIC, &[PERSISTENT])), Ok(()));
        assert_eq!(profile.check(&command(CREATE_PRIMARY, &[PLATFORM])), Ok(()));
    }

    #[test]
    fn rejects_invalid_profiles() {
        let cases = [
            ("unknown command", r#"{"commands": ["TPM_CC_Frobnicate"]}"#),
            ("numeric command", r#"{"commands": ["379"]}"#),
            (
                "unknown handle",
                r#"{"commands": [], "handles": ["TPM_HT_NOPE"]}"#,
            ),
            (
                "duplicate command",
                r#"{"commands": ["TPM_CC_GetRandom", "TPM_CC_GetRandom"]}"#,
            ),
            (
                "override for an unlisted command",
                r#"{"commands": [], "command_handles": {"TPM_CC_GetRandom": []}}"#,
            ),
            ("unknown field", r#"{"commands": [], "priority": 1}"#),
            ("missing commands", r#"{"handles": []}"#),
        ];
        for (name, json) in cases {
            assert!(Profile::parse("test", json).is_err(), "{name}");
        }
    }

    #[test]
    fn rejects_profile_names_that_are_paths() {
        for name in ["", "../standard", "a/b", ".hidden"] {
            assert!(
                matches!(
                    Profile::load(Path::new("/nonexistent"), name),
                    Err(Error::Invalid { .. })
                ),
                "{name:?}"
            );
        }
    }
}
