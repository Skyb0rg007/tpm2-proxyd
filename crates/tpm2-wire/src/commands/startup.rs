// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! [TPM2.0 1.83] 9 Start-up

use crate::{error::Error, reader::Reader};

/// `TPM_SU`: the boot mode requested by `TPM2_Startup`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupType {
    /// `TPM_SU_CLEAR`: a normal, non-state-preserving boot.
    Clear,
    /// `TPM_SU_STATE`: resume from a prior `TPM2_Shutdown(STATE)`.
    State,
}

impl TryFrom<u16> for StartupType {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self, Error> {
        match value {
            0x0000 => Ok(Self::Clear),
            0x0001 => Ok(Self::State),
            other => Err(Error::InvalidValue {
                field: "startupType",
                value: u32::from(other),
            }),
        }
    }
}

/// [TPM2.0 1.83] 9.3 TPM2_Startup (Command). Zero handles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartupCommand {
    pub startup_type: StartupType,
}

impl StartupCommand {
    pub(crate) fn parse(parameters: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(parameters);
        let startup_type = StartupType::try_from(r.u16("startupType")?)?;
        r.finish("parameters")?;
        Ok(Self { startup_type })
    }
}
