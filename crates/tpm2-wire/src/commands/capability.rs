// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! [TPM2.0 1.83] 30 Capability Commands

use crate::{error::Error, reader::Reader};

/// `TPM_CAP`: the class of capability data being queried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    Algorithms,
    Handles,
    Commands,
    PpCommands,
    AuditCommands,
    Pcrs,
    TpmProperties,
    PcrProperties,
    EccCurves,
    AuthPolicies,
    Act,
}

impl TryFrom<u32> for Capability {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self, Error> {
        match value {
            0x0000_0000 => Ok(Self::Algorithms),
            0x0000_0001 => Ok(Self::Handles),
            0x0000_0002 => Ok(Self::Commands),
            0x0000_0003 => Ok(Self::PpCommands),
            0x0000_0004 => Ok(Self::AuditCommands),
            0x0000_0005 => Ok(Self::Pcrs),
            0x0000_0006 => Ok(Self::TpmProperties),
            0x0000_0007 => Ok(Self::PcrProperties),
            0x0000_0008 => Ok(Self::EccCurves),
            0x0000_0009 => Ok(Self::AuthPolicies),
            0x0000_000A => Ok(Self::Act),
            other => Err(Error::InvalidValue {
                field: "capability",
                value: other,
            }),
        }
    }
}

/// [TPM2.0 1.83] 30.2 TPM2_GetCapability (Command). Zero handles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetCapabilityCommand {
    pub capability: Capability,
    /// The first property (or handle, depending on `capability`) to return.
    pub property: u32,
    /// The maximum number of properties to return.
    pub property_count: u32,
}

impl GetCapabilityCommand {
    pub(crate) fn parse(parameters: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(parameters);
        let capability = Capability::try_from(r.u32("capability")?)?;
        let property = r.u32("property")?;
        let property_count = r.u32("propertyCount")?;
        r.finish("parameters")?;
        Ok(Self {
            capability,
            property,
            property_count,
        })
    }
}
