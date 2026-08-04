// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! [TPM2.0 1.83] 31 Non-volatile Storage

use crate::{error::Error, handle::Handle, reader::Reader};

/// [TPM2.0 1.83] 31.7 TPM2_NV_Write (Command). Two handles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NvWriteCommand<'a> {
    pub auth_handle: Handle,
    /// The NV index being written.
    pub nv_index: Handle,
    /// The data to write.
    pub data: &'a [u8],
    /// Octet offset into the NV index.
    pub offset: u16,
}

impl<'a> NvWriteCommand<'a> {
    pub(crate) fn parse(handles: &[u8], parameters: &'a [u8]) -> Result<Self, Error> {
        let mut hr = Reader::new(handles);
        let auth_handle = hr.handle("authHandle")?;
        let nv_index = hr.handle("nvIndex")?;
        hr.finish("handles")?;

        let mut pr = Reader::new(parameters);
        let data = pr.buffer("data")?;
        let offset = pr.u16("offset")?;
        pr.finish("parameters")?;

        Ok(Self {
            auth_handle,
            nv_index,
            data,
            offset,
        })
    }
}

/// [TPM2.0 1.83] 31.13 TPM2_NV_Read (Command). Two handles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NvReadCommand {
    pub auth_handle: Handle,
    /// The NV index being read.
    pub nv_index: Handle,
    /// Number of octets to read.
    pub size: u16,
    /// Octet offset into the NV index.
    pub offset: u16,
}

impl NvReadCommand {
    pub(crate) fn parse(handles: &[u8], parameters: &[u8]) -> Result<Self, Error> {
        let mut hr = Reader::new(handles);
        let auth_handle = hr.handle("authHandle")?;
        let nv_index = hr.handle("nvIndex")?;
        hr.finish("handles")?;

        let mut pr = Reader::new(parameters);
        let size = pr.u16("size")?;
        let offset = pr.u16("offset")?;
        pr.finish("parameters")?;

        Ok(Self {
            auth_handle,
            nv_index,
            size,
            offset,
        })
    }
}
