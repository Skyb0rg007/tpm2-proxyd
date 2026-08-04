// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! [TPM2.0 1.83] 11 Session Commands

use crate::{error::Error, handle::Handle, reader::Reader};

/// `TPM_SE`: the kind of session `TPM2_StartAuthSession` creates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionType {
    Hmac,
    Policy,
    Trial,
}

impl TryFrom<u8> for SessionType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Error> {
        match value {
            0x00 => Ok(Self::Hmac),
            0x01 => Ok(Self::Policy),
            0x03 => Ok(Self::Trial),
            other => Err(Error::InvalidValue {
                field: "sessionType",
                value: u32::from(other),
            }),
        }
    }
}

/// [TPM2.0 1.83] 11.1 TPM2_StartAuthSession (Command). Two handles.
///
/// `symmetric` (`TPMT_SYM_DEF_OBJECT`) is a tagged union this crate doesn't
/// decode yet, so it's exposed as the opaque range between `encrypted_salt`
/// and the fixed trailing `auth_hash` (`TPMI_ALG_HASH` is always the last 2
/// bytes of the parameter area, so that boundary needs no tag interpretation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartAuthSessionCommand<'a> {
    /// The handle of a decrypt key for salted sessions, or `TPM_RH_NULL`.
    pub tpm_key: Handle,
    /// The entity providing the authorization value, or `TPM_RH_NULL`.
    pub bind: Handle,
    pub nonce_caller: &'a [u8],
    pub encrypted_salt: &'a [u8],
    pub session_type: SessionType,
    /// Raw `TPMT_SYM_DEF_OBJECT` bytes; see the type-level docs.
    pub symmetric: &'a [u8],
    /// `TPMI_ALG_HASH` algorithm ID for the session.
    pub auth_hash: u16,
}

impl<'a> StartAuthSessionCommand<'a> {
    pub(crate) fn parse(handles: &[u8], parameters: &'a [u8]) -> Result<Self, Error> {
        let mut hr = Reader::new(handles);
        let tpm_key = hr.handle("tpmKey")?;
        let bind = hr.handle("bind")?;
        hr.finish("handles")?;

        let mut pr = Reader::new(parameters);
        let nonce_caller = pr.buffer("nonceCaller")?;
        let encrypted_salt = pr.buffer("encryptedSalt")?;
        let session_type = SessionType::try_from(pr.u8("sessionType")?)?;

        let remaining = pr.rest();
        if remaining.len() < 2 {
            return Err(Error::UnexpectedEof {
                field: "authHash",
                needed: 2,
                available: remaining.len(),
            });
        }
        let (symmetric, auth_hash_bytes) = remaining.split_at(remaining.len() - 2);
        let auth_hash = u16::from_be_bytes([auth_hash_bytes[0], auth_hash_bytes[1]]);

        Ok(Self {
            tpm_key,
            bind,
            nonce_caller,
            encrypted_salt,
            session_type,
            symmetric,
            auth_hash,
        })
    }
}
