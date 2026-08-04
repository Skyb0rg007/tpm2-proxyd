// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! A command's authorization area: zero or more authorization sessions.
//!
//! Present only on `Sessions`-tagged commands. It has no session count --
//! its total byte length (`authorizationSize`) is the only framing, so
//! sessions are read back-to-back until the area is exhausted.

use std::fmt;

use crate::{error::Error, handle::Handle, reader::Reader};

/// `TPMA_SESSION`: a command session's attribute bits.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SessionAttributes(pub u8);

impl SessionAttributes {
    /// The session's nonce and HMAC/policy digest are usable for the next
    /// command; without this the session is torn down after this response.
    pub const CONTINUE_SESSION: u8 = 0x01;
    pub const AUDIT_EXCLUSIVE: u8 = 0x02;
    pub const AUDIT_RESET: u8 = 0x04;
    pub const DECRYPT: u8 = 0x20;
    pub const ENCRYPT: u8 = 0x40;
    pub const AUDIT: u8 = 0x80;

    /// Whether every bit in `flags` is set.
    #[must_use]
    pub const fn contains(self, flags: u8) -> bool {
        self.0 & flags == flags
    }
}

/// One command authorization session (`TPMS_AUTH_COMMAND`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthCommandSession<'a> {
    /// The session handle, or `TPM_RS_PW` (`0x40000009`) for password
    /// authorization.
    pub session_handle: Handle,
    /// The caller's session nonce.
    pub nonce: &'a [u8],
    /// Session attribute flags.
    pub attributes: SessionAttributes,
    /// The HMAC (or plaintext password, for `TPM_RS_PW`) authorizing this
    /// command with `session_handle`.
    pub hmac: &'a [u8],
}

impl<'a> AuthCommandSession<'a> {
    fn parse(r: &mut Reader<'a>) -> Result<Self, Error> {
        let session_handle = r.handle("sessionHandle")?;
        let nonce = r.buffer("nonce")?;
        let attributes = SessionAttributes(r.u8("sessionAttributes")?);
        let hmac = r.buffer("hmac")?;
        Ok(Self {
            session_handle,
            nonce,
            attributes,
            hmac,
        })
    }
}

/// A command's authorization area, borrowed from the command buffer.
///
/// Iterate with [`AuthArea::iter`] (or `for session in area`).
#[derive(Debug, Clone, Copy)]
pub struct AuthArea<'a>(&'a [u8]);

impl<'a> AuthArea<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }

    /// Whether this area has no sessions (always true for a
    /// `NoSessions`-tagged command).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterates the sessions in this area.
    ///
    /// A malformed session yields `Some(Err(_))` and ends the iteration --
    /// once the byte stream desynchronizes there is no way to recover
    /// framing for whatever sessions might follow.
    #[must_use]
    pub fn iter(&self) -> AuthSessions<'a> {
        AuthSessions(self.0)
    }
}

impl<'a> IntoIterator for AuthArea<'a> {
    type Item = Result<AuthCommandSession<'a>, Error>;
    type IntoIter = AuthSessions<'a>;

    fn into_iter(self) -> Self::IntoIter {
        AuthSessions(self.0)
    }
}

/// Iterator over the sessions in an [`AuthArea`].
#[derive(Debug, Clone)]
pub struct AuthSessions<'a>(&'a [u8]);

impl<'a> Iterator for AuthSessions<'a> {
    type Item = Result<AuthCommandSession<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_empty() {
            return None;
        }
        let mut r = Reader::new(self.0);
        match AuthCommandSession::parse(&mut r) {
            Ok(session) => {
                self.0 = r.rest();
                Some(Ok(session))
            }
            Err(error) => {
                self.0 = &[];
                Some(Err(error))
            }
        }
    }
}

impl fmt::Debug for SessionAttributes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut set = f.debug_set();
        for (bit, name) in [
            (Self::CONTINUE_SESSION, "CONTINUE_SESSION"),
            (Self::AUDIT_EXCLUSIVE, "AUDIT_EXCLUSIVE"),
            (Self::AUDIT_RESET, "AUDIT_RESET"),
            (Self::DECRYPT, "DECRYPT"),
            (Self::ENCRYPT, "ENCRYPT"),
            (Self::AUDIT, "AUDIT"),
        ] {
            if self.contains(bit) {
                set.entry(&name);
            }
        }
        set.finish()
    }
}
