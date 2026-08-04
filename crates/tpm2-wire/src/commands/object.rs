// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! [TPM2.0 1.83] 12 Object Commands

use crate::{error::Error, handle::Handle, reader::Reader};

/// [TPM2.0 1.83] 12.4 TPM2_ReadPublic (Command). One handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadPublicCommand {
    /// The object whose public area is being read.
    pub object_handle: Handle,
}

impl ReadPublicCommand {
    pub(crate) fn parse(handles: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(handles);
        let object_handle = r.handle("objectHandle")?;
        r.finish("handles")?;
        Ok(Self { object_handle })
    }
}

/// [TPM2.0 1.83] 12.7 TPM2_Unseal (Command). One handle; authorization to
/// read it is carried in the command's authorization area, not here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsealCommand {
    /// The sealed data object being read.
    pub item_handle: Handle,
}

impl UnsealCommand {
    pub(crate) fn parse(handles: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(handles);
        let item_handle = r.handle("itemHandle")?;
        r.finish("handles")?;
        Ok(Self { item_handle })
    }
}
