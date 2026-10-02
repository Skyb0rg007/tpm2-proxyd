// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! The client socket: listener, hello, and per-connection handling.
//!
//! Binds the daemon's socket (default `/run/tpm2-proxyd/tpm2-proxyd.sock`),
//! accepts client connections, and resolves each peer's credentials ([`peer`]).
//!
//! Each connection opens with a [`hello`]. Once it is accepted, [`connection`]
//! parses the client's self-framing TPM command stream and submits commands to
//! [`crate::scheduler::CommandScheduler`]. See `docs/design.md`.

/// Per-connection handling: the hello, then TPM command/response streaming.
pub(crate) mod connection;
/// The hello that opens every connection.
pub(crate) mod hello;
/// Active downstream connection tracking and concurrency cap.
pub(crate) mod registry;
/// Raw Unix-domain socket TPM listener.
pub(crate) mod unix;

/// End-to-end smoke tests over a real Unix socket.
#[cfg(test)]
mod smoke;
