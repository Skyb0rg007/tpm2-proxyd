// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: BSD-2-Clause

//! Downstream Unix-socket listener and accept loop.
//!
//! Binds the proxy socket (default `/run/tpm2-proxyd/tpm2-proxyd.sock`), accepts
//! client connections, resolves each peer's credentials ([`peer`]), and spawns
//! a per-connection task ([`connection`]) wired to the [`crate::broker`]. This
//! is the transport/framing layer; the proxy decision logic lives in the
//! broker.

/// Per-client connection handling: command/response framing and request loop.
mod connection;
/// Peer credential (uid/gid/pid) resolution from the connected socket.
mod peer;
