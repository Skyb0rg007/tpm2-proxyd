// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: BSD-2-Clause

//! On-disk configuration model and loading.
//!
//! Defines the daemon's configuration: the downstream socket path (default
//! `/run/tpm2-proxyd/tpm2-proxyd.sock`), the upstream TCTI selection, the
//! access/permission ruleset evaluated by [`crate::policy`], and the scheduling
//! parameters consumed by [`crate::scheduler`] — time-slice duration, the hard
//! per-command timeout, per-UID quota and its rolling-window length, and the
//! fairness policy (optionally overridable per user/group). Deserialized with
//! `serde`/`serde_json` and validated into the runtime form the `broker`
//! consumes.
