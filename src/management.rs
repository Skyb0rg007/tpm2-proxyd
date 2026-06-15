// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: BSD-2-Clause

//! Backend for the `website.soss.Tpm2Proxyd` control interface.
//!
//! Implements the administrative/inspection methods — e.g. reloading the
//! [`crate::policy`] ruleset, reporting status, and listing active connections —
//! for [`crate::varlink`] to expose over `zlink`. These share the daemon's single
//! socket with the TPM-access method; [`crate::server`] owns the socket and
//! routes control calls here, while an access call (`RequestTpmAccess`) upgrades
//! the connection to the raw TPM data path instead.
