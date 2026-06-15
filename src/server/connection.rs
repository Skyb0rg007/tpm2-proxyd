// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: BSD-2-Clause

//! Per-client connection handling.
//!
//! Reads the raw, self-framing TPM command byte stream from a downstream client
//! (the 10-byte header carries the total size), dispatches each command through
//! the [`crate::broker`] for the connection's peer, and writes the response
//! back. This mirrors the wire protocol implemented by the `tss2-tcti-proxy`
//! client module and runs until the client disconnects. Because the broker
//! schedules upstream access ([`crate::scheduler`]), a request may block here
//! while waiting for the connection's TPM time slice; a command that exceeds the
//! hard time limit fails and typically ends the connection.
