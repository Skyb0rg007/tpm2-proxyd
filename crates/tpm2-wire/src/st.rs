// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! The command/response tag (`TPM_ST_NO_SESSIONS` / `TPM_ST_SESSIONS`).

use crate::error::Error;

/// Command/response tag, indicating whether an authorization area follows
/// the handle area.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TpmSt {
    /// No authorization area follows the handle area.
    NoSessions = 0x8001,
    /// An authorization area (one or more sessions) follows the handle area.
    Sessions = 0x8002,
}

impl TpmSt {
    /// The raw `u16` tag value.
    #[must_use]
    pub const fn value(self) -> u16 {
        self as u16
    }
}

impl TryFrom<u16> for TpmSt {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self, Error> {
        match value {
            0x8001 => Ok(Self::NoSessions),
            0x8002 => Ok(Self::Sessions),
            other => Err(Error::InvalidTag(other)),
        }
    }
}
