// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: BSD-2-Clause

//! The single Varlink socket: listener, dispatch, and connection upgrade.
//!
//! Binds the daemon's one socket (default
//! `/run/tpm2-proxyd/website.soss.Tpm2Proxyd`), accepts client connections, and
//! resolves each peer's credentials ([`peer`]). On each connection it serves the
//! `website.soss.Tpm2Proxyd` Varlink interface, routing control methods to
//! [`crate::management`].
//!
//! Once a transport has admitted a TPM client, [`connection`] parses its
//! self-framing TPM command stream and submits commands to
//! [`crate::scheduler::CommandScheduler`]. The listener API is transport
//! independent and supports raw Unix/TCP sockets now, with a future Varlink
//! upgrade handoff able to implement the same interface. See `docs/design.md`.

/// Post-upgrade per-connection handling: raw TPM command/response streaming.
pub(crate) mod connection;
/// Peer credential (uid/gid/pid) resolution from the connected socket.
pub(crate) mod peer;
/// Raw Unix-domain socket TPM listener.
pub(crate) mod unix;
