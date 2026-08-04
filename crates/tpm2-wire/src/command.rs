// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! The raw TPM 2.0 command envelope.
//!
//! A command on the wire is:
//!
//! ```text
//! tag (u16) | size (u32) | code (u32) | handles | [authorizationSize (u32) | authorization area] | parameters
//! ```
//!
//! The authorization area is present only when `tag == Sessions`. The handle
//! area's length is not self-describing -- it's a fixed count per command
//! code (see [`crate::TpmCc::handle_count`]). Everything after it is the
//! parameter area.

use crate::{
    cc::TpmCc, commands::CommandBody, error::Error, reader::Reader, session::AuthArea, st::TpmSt,
};

/// Size of the fixed TPM command/response header (tag, size, code).
pub const HEADER_SIZE: usize = 10;

/// A validated TPM 2.0 command, borrowing its bytes from the input buffer.
///
/// [`Command::parse`] validates only the envelope; it never inspects
/// parameter bytes -- call [`Command::body`] for that.
#[derive(Debug, Clone, Copy)]
pub struct Command<'a> {
    tag: TpmSt,
    code: TpmCc,
    handles: &'a [u8],
    auth_area: &'a [u8],
    parameters: &'a [u8],
}

impl<'a> Command<'a> {
    /// Parses and validates a complete TPM command from `bytes`.
    ///
    /// `bytes` must be exactly one complete command: its length must match
    /// the header's declared size exactly.
    ///
    /// # Errors
    ///
    /// See [`Error`] for the specific failure modes (short buffer, bad tag,
    /// size mismatch, unrecognized command code).
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);

        let tag = TpmSt::try_from(r.u16("tag")?)?;
        let size = r.u32("size")?;
        if (size as usize) < HEADER_SIZE {
            return Err(Error::SizeTooSmall(size));
        }
        if size as usize != bytes.len() {
            return Err(Error::SizeMismatch {
                declared: size,
                actual: bytes.len(),
            });
        }
        let code = TpmCc::try_from(r.u32("commandCode")?)?;

        let handles = r.bytes(usize::from(code.handle_count()) * 4, "handles")?;

        let auth_area = if tag == TpmSt::Sessions {
            let auth_size = r.u32("authorizationSize")? as usize;
            r.bytes(auth_size, "authorizationArea")?
        } else {
            &[]
        };

        let parameters = r.rest();

        Ok(Self {
            tag,
            code,
            handles,
            auth_area,
            parameters,
        })
    }

    /// The command/response tag.
    #[must_use]
    pub fn tag(&self) -> TpmSt {
        self.tag
    }

    /// The command code.
    #[must_use]
    pub fn code(&self) -> TpmCc {
        self.code
    }

    /// The raw handle area: `4 * code.handle_count()` bytes, each a
    /// big-endian `u32` handle.
    #[must_use]
    pub fn handles(&self) -> &'a [u8] {
        self.handles
    }

    /// The authorization area (empty for a `NoSessions`-tagged command).
    #[must_use]
    pub fn auth_area(&self) -> AuthArea<'a> {
        AuthArea::new(self.auth_area)
    }

    /// The raw parameter area.
    #[must_use]
    pub fn parameters(&self) -> &'a [u8] {
        self.parameters
    }

    /// Parses the handle and parameter areas into a typed [`CommandBody`].
    ///
    /// Returns [`CommandBody::Other`] (not an error) for any recognized
    /// command code this crate does not yet have a per-command decoder for.
    ///
    /// # Errors
    ///
    /// Returns `Err(Error)` if this command code *does* have a decoder and
    /// the handle/parameter bytes don't match its expected shape.
    pub fn body(&self) -> Result<CommandBody<'a>, Error> {
        CommandBody::parse(self.code, self.handles, self.parameters)
    }
}
