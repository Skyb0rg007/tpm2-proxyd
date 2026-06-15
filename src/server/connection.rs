// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: BSD-2-Clause

//! Post-upgrade per-connection handling.
//!
//! Once [`crate::server`] has upgraded a connection (the client's
//! `RequestTpmAccess` call succeeded), the socket no longer speaks Varlink: it
//! carries a raw, self-framing TPM command byte stream (the 10-byte header
//! carries the total size). This module reads each command, dispatches it
//! through the [`crate::broker`] for the connection's peer and requested
//! priority, and writes the response back, mirroring the wire protocol the
//! `tss2-tcti-proxy` client module drives after its own upgrade handshake.
//!
//! It runs until the client disconnects. Because the broker schedules upstream
//! access ([`crate::scheduler`]), a request may block here while waiting for the
//! TPM lease; a command that exceeds the hard time limit fails and typically
//! ends the connection.
