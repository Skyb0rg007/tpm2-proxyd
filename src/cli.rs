// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: BSD-2-Clause

//! Command-line argument parsing for the daemon.
//!
//! Produces a parsed-options value consumed by `main`. Expected options include
//! the configuration file path, an optional downstream socket-path override, an
//! upstream TCTI override, and the log level/verbosity. Values set here take
//! precedence over the on-disk [`crate::config`].
