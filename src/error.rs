// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: BSD-2-Clause

//! Crate-wide error and result types.
//!
//! Defines the daemon's `thiserror`-based error enum and a `Result` alias
//! covering configuration, I/O, TPM parsing, and upstream-transport failures.
//! `anyhow` is used for ad-hoc context at the top level (`main`).
