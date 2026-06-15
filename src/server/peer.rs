// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: BSD-2-Clause

//! Peer credential resolution.
//!
//! Reads the connected Unix socket's `SO_PEERCRED` (uid/gid/pid) to identify
//! the calling user. This identity is the subject of every [`crate::policy`]
//! decision, so it is established once at accept time and attached to the
//! connection.
