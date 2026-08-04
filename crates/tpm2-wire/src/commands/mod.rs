// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! Typed, per-command views over a command's handle and parameter areas.
//!
//! Only a subset of TPM 2.0 command codes have a typed decoder here; the
//! rest parse as [`CommandBody::Other`], a raw view over the same bytes.
//! Modules are named and ordered after the TPM 2.0 Part 3 command sections.
//!
//! # Adding a new command
//!
//! 1. Check the handle count in [`crate::TpmCc::handle_count`] (it's
//!    hand-transcribed; fix it there if wrong) and the parameter layout in
//!    TPM 2.0 Part 3.
//! 2. Add a struct (one field per handle, typed [`crate::Handle`]; one per
//!    parameter) to the section's module, with `pub(crate) fn
//!    parse(handles: &[u8], parameters: &'a [u8]) -> Result<Self, Error>`
//!    (drop whichever arg is unused). Parse fields in wire order via
//!    [`crate::reader::Reader`] -- see any module here for the pattern. A
//!    nested spec struct gets its own `parse(r: &mut Reader<'a>)` (see
//!    `context.rs`'s `SavedContext`).
//! 3. Add the variant to [`CommandBody`] and an arm to
//!    [`CommandBody::parse`] and [`CommandBody::code`].
//!
//! A field this crate doesn't decode yet (usually a tagged union) can be
//! exposed as an opaque `&'a [u8]` instead of blocking the rest of the
//! command -- see `session.rs`'s `TPMT_SYM_DEF_OBJECT` handling.

// [TPM2.0 1.83] 9 Start-up
mod startup;
pub use startup::{StartupCommand, StartupType};

// [TPM2.0 1.83] 10 Testing
mod testing;
pub use testing::{GetTestResultCommand, SelfTestCommand};

// [TPM2.0 1.83] 11 Session Commands
mod session;
pub use session::{SessionType, StartAuthSessionCommand};

// [TPM2.0 1.83] 12 Object Commands
mod object;
pub use object::{ReadPublicCommand, UnsealCommand};

// [TPM2.0 1.83] 16 Random Number Generator
mod random;
pub use random::GetRandomCommand;

// [TPM2.0 1.83] 28 Context Management
mod context;
pub use context::{
    ContextLoadCommand, ContextSaveCommand, EvictControlCommand, FlushContextCommand, SavedContext,
};

// [TPM2.0 1.83] 30 Capability Commands
mod capability;
pub use capability::{Capability, GetCapabilityCommand};

// [TPM2.0 1.83] 31 Non-volatile Storage
mod nv_storage;
pub use nv_storage::{NvReadCommand, NvWriteCommand};

use crate::{cc::TpmCc, error::Error};

/// A command's handle and parameter areas, decoded into a per-command Rust
/// representation where this crate has one.
///
/// Every variant borrows from the original command buffer, so a
/// `CommandBody` is a fixed-size view, not an owned copy.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum CommandBody<'a> {
    ContextLoad(ContextLoadCommand<'a>),
    ContextSave(ContextSaveCommand),
    EvictControl(EvictControlCommand),
    FlushContext(FlushContextCommand),
    GetCapability(GetCapabilityCommand),
    GetRandom(GetRandomCommand),
    GetTestResult(GetTestResultCommand),
    NvRead(NvReadCommand),
    NvWrite(NvWriteCommand<'a>),
    ReadPublic(ReadPublicCommand),
    SelfTest(SelfTestCommand),
    StartAuthSession(StartAuthSessionCommand<'a>),
    Startup(StartupCommand),
    Unseal(UnsealCommand),
    /// A recognized command code with no typed decoder yet: its raw handle
    /// and parameter bytes, unparsed.
    Other {
        code: TpmCc,
        handles: &'a [u8],
        parameters: &'a [u8],
    },
}

impl<'a> CommandBody<'a> {
    pub(crate) fn parse(
        code: TpmCc,
        handles: &'a [u8],
        parameters: &'a [u8],
    ) -> Result<Self, Error> {
        Ok(match code {
            TpmCc::ContextLoad => Self::ContextLoad(ContextLoadCommand::parse(parameters)?),
            TpmCc::ContextSave => Self::ContextSave(ContextSaveCommand::parse(handles)?),
            TpmCc::EvictControl => {
                Self::EvictControl(EvictControlCommand::parse(handles, parameters)?)
            }
            TpmCc::FlushContext => Self::FlushContext(FlushContextCommand::parse(parameters)?),
            TpmCc::GetCapability => Self::GetCapability(GetCapabilityCommand::parse(parameters)?),
            TpmCc::GetRandom => Self::GetRandom(GetRandomCommand::parse(parameters)?),
            TpmCc::GetTestResult => Self::GetTestResult(GetTestResultCommand::parse(parameters)?),
            TpmCc::NvRead => Self::NvRead(NvReadCommand::parse(handles, parameters)?),
            TpmCc::NvWrite => Self::NvWrite(NvWriteCommand::parse(handles, parameters)?),
            TpmCc::ReadPublic => Self::ReadPublic(ReadPublicCommand::parse(handles)?),
            TpmCc::SelfTest => Self::SelfTest(SelfTestCommand::parse(parameters)?),
            TpmCc::StartAuthSession => {
                Self::StartAuthSession(StartAuthSessionCommand::parse(handles, parameters)?)
            }
            TpmCc::Startup => Self::Startup(StartupCommand::parse(parameters)?),
            TpmCc::Unseal => Self::Unseal(UnsealCommand::parse(handles)?),
            other => Self::Other {
                code: other,
                handles,
                parameters,
            },
        })
    }

    /// The command code this body was parsed from.
    #[must_use]
    pub fn code(&self) -> TpmCc {
        match self {
            Self::ContextLoad(_) => TpmCc::ContextLoad,
            Self::ContextSave(_) => TpmCc::ContextSave,
            Self::EvictControl(_) => TpmCc::EvictControl,
            Self::FlushContext(_) => TpmCc::FlushContext,
            Self::GetCapability(_) => TpmCc::GetCapability,
            Self::GetRandom(_) => TpmCc::GetRandom,
            Self::GetTestResult(_) => TpmCc::GetTestResult,
            Self::NvRead(_) => TpmCc::NvRead,
            Self::NvWrite(_) => TpmCc::NvWrite,
            Self::ReadPublic(_) => TpmCc::ReadPublic,
            Self::SelfTest(_) => TpmCc::SelfTest,
            Self::StartAuthSession(_) => TpmCc::StartAuthSession,
            Self::Startup(_) => TpmCc::Startup,
            Self::Unseal(_) => TpmCc::Unseal,
            Self::Other { code, .. } => *code,
        }
    }
}
