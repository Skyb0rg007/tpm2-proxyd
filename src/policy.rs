// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: BSD-2-Clause

//! Access-control rule model and evaluation engine.
//!
//! Defines the permission ruleset (loaded from [`crate::config`]) and maps a
//! `(peer identity, inspected command)` pair to an allow/deny decision. Rules
//! are keyed on the connecting user/group ([`crate::server::peer`]) and the
//! inspected command attributes ([`crate::tpm`]), such as the command code and
//! referenced handles.
