// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! [TPM2.0 1.83] 28 Context Management

use crate::{error::Error, handle::Handle, reader::Reader};

/// [TPM2.0 1.83] 28.2 TPM2_ContextSave (Command). One handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextSaveCommand {
    /// The transient object, session, or sequence object being saved.
    pub saved_handle: Handle,
}

impl ContextSaveCommand {
    pub(crate) fn parse(handles: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(handles);
        let saved_handle = r.handle("savedHandle")?;
        r.finish("handles")?;
        Ok(Self { saved_handle })
    }
}

/// `TPMS_CONTEXT`: a saved object, sequence, or session context blob.
///
/// A nested TPM struct composes into its containing command's parser via a
/// `parse` function taking `&mut Reader<'a>` instead of a raw byte slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SavedContext<'a> {
    pub sequence: u64,
    pub saved_handle: Handle,
    /// The hierarchy the context was saved under (or a reserved value for a
    /// saved session). Left as a raw [`Handle`] rather than a closed
    /// hierarchy enum, since sessions legitimately populate this with
    /// values outside the hierarchy handle range.
    pub hierarchy: Handle,
    pub context_blob: &'a [u8],
}

impl<'a> SavedContext<'a> {
    pub(crate) fn parse(r: &mut Reader<'a>) -> Result<Self, Error> {
        let sequence = r.u64("sequence")?;
        let saved_handle = r.handle("savedHandle")?;
        let hierarchy = r.handle("hierarchy")?;
        let context_blob = r.buffer("contextBlob")?;
        Ok(Self {
            sequence,
            saved_handle,
            hierarchy,
            context_blob,
        })
    }
}

/// [TPM2.0 1.83] 28.3 TPM2_ContextLoad (Command).
///
/// Zero handles -- the object or session to load is described entirely by
/// the context blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextLoadCommand<'a> {
    pub context: SavedContext<'a>,
}

impl<'a> ContextLoadCommand<'a> {
    pub(crate) fn parse(parameters: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(parameters);
        let context = SavedContext::parse(&mut r)?;
        r.finish("parameters")?;
        Ok(Self { context })
    }
}

/// [TPM2.0 1.83] 28.4 TPM2_FlushContext (Command).
///
/// Zero handle-area handles: the handle being flushed needs no
/// authorization (always the caller's own object/session), so the spec
/// carries it in the parameter area instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlushContextCommand {
    pub flush_handle: Handle,
}

impl FlushContextCommand {
    pub(crate) fn parse(parameters: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(parameters);
        let flush_handle = r.handle("flushHandle")?;
        r.finish("parameters")?;
        Ok(Self { flush_handle })
    }
}

/// [TPM2.0 1.83] 28.5 TPM2_EvictControl (Command).
///
/// Two handles, plus the target persistent handle in the parameter area.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvictControlCommand {
    /// `TPM_RH_OWNER` or `TPM_RH_PLATFORM`.
    pub auth: Handle,
    /// The transient object being made persistent, or the persistent object
    /// being evicted.
    pub object_handle: Handle,
    /// The persistent handle to assign (when making an object persistent) or
    /// remove (when evicting one).
    pub persistent_handle: Handle,
}

impl EvictControlCommand {
    pub(crate) fn parse(handles: &[u8], parameters: &[u8]) -> Result<Self, Error> {
        let mut hr = Reader::new(handles);
        let auth = hr.handle("auth")?;
        let object_handle = hr.handle("objectHandle")?;
        hr.finish("handles")?;

        let mut pr = Reader::new(parameters);
        let persistent_handle = pr.handle("persistentHandle")?;
        pr.finish("parameters")?;

        Ok(Self {
            auth,
            object_handle,
            persistent_handle,
        })
    }
}
