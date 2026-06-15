// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: BSD-2-Clause

//! Varlink (`zlink`) management interface.
//!
//! Exposes runtime control and inspection over a separate Varlink socket —
//! e.g. reloading the [`crate::policy`] ruleset, reporting status, and listing
//! active downstream connections. This is the administrative surface and is
//! kept distinct from the downstream TPM data path served by [`crate::server`].
