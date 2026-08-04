// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! [TPM2.0 1.83] 16 Random Number Generator

use crate::{error::Error, reader::Reader};

/// [TPM2.0 1.83] 16.1 TPM2_GetRandom (Command). Zero handles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetRandomCommand {
    /// Number of octets of randomness requested.
    pub bytes_requested: u16,
}

impl GetRandomCommand {
    pub(crate) fn parse(parameters: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(parameters);
        let bytes_requested = r.u16("bytesRequested")?;
        r.finish("parameters")?;
        Ok(Self { bytes_requested })
    }
}
