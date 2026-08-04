// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! TPM handles: 4-byte values that name an object, hierarchy, NV index, or
//! session.

use std::fmt;

/// A raw TPM handle value.
///
/// The high byte is a `TPM_HT` handle-type tag (transient object, NV index,
/// hierarchy, session, PCR, ...), which this crate does not interpret --
/// policy code matches on exact values or ranges instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Handle(pub u32);

impl Handle {
    /// The raw `u32` handle value.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }
}

impl From<u32> for Handle {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl fmt::Display for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#010x}", self.0)
    }
}
