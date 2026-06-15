// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: BSD-2-Clause

//! Tracing/log subscriber initialization.
//!
//! Configures the `tracing` subscriber (level/filter from [`crate::cli`] and
//! the environment) and selects an output format appropriate for running under
//! systemd vs. an interactive terminal.
