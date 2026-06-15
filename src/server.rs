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
//! When a client calls the access method (`RequestTpmAccess`) with the Varlink
//! `upgrade: true` flag, the server authorizes it via [`crate::broker`], sends
//! the reply, and then **upgrades** the connection: it stops speaking Varlink
//! and hands the raw socket to [`connection`], which streams TPM commands for
//! the rest of the connection's life. See `docs/design.md`.

/// Post-upgrade per-connection handling: raw TPM command/response streaming.
mod connection;
/// Peer credential (uid/gid/pid) resolution from the connected socket.
mod peer;
