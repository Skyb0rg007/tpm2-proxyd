// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! Zero-copy, typed-view parsing of TPM 2.0 command byte streams.
//!
//! Every type here borrows from the input buffer and holds only `Copy`
//! scalars alongside those borrows, so parsing never allocates. There is
//! deliberately no marshal (Rust -> bytes) direction: if you already have
//! valid command bytes, forward them unchanged rather than reconstructing
//! them from a parsed [`CommandBody`].
//!
//! Two layers: [`Command::parse`] validates just the envelope (header,
//! handle area, auth area), which works for every recognized command code.
//! [`Command::body`] additionally decodes the handle/parameter areas into a
//! [`CommandBody`], falling back to [`CommandBody::Other`] for command codes
//! without a decoder yet -- see the [`commands`] module docs for adding one.
//!
//! Every decoder is a hand-written `fn parse(...)` built from
//! [`reader::Reader`]'s methods in wire order -- no declarative macro, no
//! derives beyond `std`'s. [`TpmCc`] is the one hand-maintained data table;
//! everything else grows by adding one module per command.

mod cc;
mod command;
pub mod commands;
mod error;
mod handle;
mod reader;
mod session;
mod st;

pub use cc::TpmCc;
pub use command::{Command, HEADER_SIZE};
pub use commands::CommandBody;
pub use error::Error;
pub use handle::Handle;
pub use session::{AuthArea, AuthCommandSession, AuthSessions, SessionAttributes};
pub use st::TpmSt;
