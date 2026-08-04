// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! Errors produced while parsing a TPM 2.0 command byte stream.

use std::fmt;

/// A failure encountered while parsing a TPM 2.0 command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The buffer ended before a required field could be read.
    UnexpectedEof {
        /// The field being read when the buffer ran out.
        field: &'static str,
        /// Bytes required to read the field.
        needed: usize,
        /// Bytes actually available.
        available: usize,
    },
    /// A field left unconsumed bytes behind after every expected field was
    /// read out of its containing area.
    TrailingData {
        /// The area that had bytes left over (e.g. `"handles"`, `"parameters"`).
        field: &'static str,
        /// Bytes left over.
        remaining: usize,
    },
    /// The command tag is not `TPM_ST_NO_SESSIONS` or `TPM_ST_SESSIONS`.
    InvalidTag(u16),
    /// The header's declared size is smaller than the 10-byte header itself.
    SizeTooSmall(u32),
    /// The header's declared size does not match the buffer length.
    SizeMismatch {
        /// Size declared by the header.
        declared: u32,
        /// Actual buffer length.
        actual: usize,
    },
    /// The command code is not a recognized TPM 2.0 command code.
    ///
    /// This is the firewall boundary: a code outside [`crate::TpmCc::ALL`]
    /// -- including any vendor-specific command code -- is rejected here,
    /// before handles or parameters are ever inspected.
    UnknownCommandCode(u32),
    /// A `TPM2B`-style length-prefixed field declared a size larger than the
    /// bytes remaining in its containing area.
    BufferTooLarge {
        /// Field name.
        field: &'static str,
        /// Declared size.
        declared: usize,
        /// Bytes available.
        available: usize,
    },
    /// A field held a value outside the range this crate understands.
    InvalidValue {
        /// Field name.
        field: &'static str,
        /// Raw value read.
        value: u32,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof {
                field,
                needed,
                available,
            } => write!(
                f,
                "unexpected end of buffer reading `{field}`: needed {needed} bytes, {available} available"
            ),
            Self::TrailingData { field, remaining } => {
                write!(f, "{remaining} unconsumed byte(s) after `{field}`")
            }
            Self::InvalidTag(tag) => write!(f, "invalid command tag {tag:#06x}"),
            Self::SizeTooSmall(size) => {
                write!(
                    f,
                    "declared packet size {size} is smaller than the 10-byte header"
                )
            }
            Self::SizeMismatch { declared, actual } => write!(
                f,
                "header declares size {declared}, but the buffer holds {actual} byte(s)"
            ),
            Self::UnknownCommandCode(code) => {
                write!(f, "unrecognized TPM command code {code:#010x}")
            }
            Self::BufferTooLarge {
                field,
                declared,
                available,
            } => write!(
                f,
                "`{field}` declares {declared} byte(s), but only {available} remain"
            ),
            Self::InvalidValue { field, value } => {
                write!(f, "`{field}` has an invalid value: {value:#x}")
            }
        }
    }
}

impl std::error::Error for Error {}
