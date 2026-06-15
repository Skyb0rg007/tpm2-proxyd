// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: BSD-2-Clause

//! On-disk configuration model and loading.
//!
//! Defines the daemon's configuration: the Varlink socket path (default
//! `/run/tpm2-proxyd/website.soss.Tpm2Proxyd` — the single socket serving both
//! control and TPM access), the upstream TCTI selection, the access/permission
//! ruleset evaluated by [`crate::policy`], and the scheduling parameters
//! consumed by [`crate::scheduler`] — time-slice duration, the hard per-command
//! timeout, per-UID quota and its window length, the fairness policy, and the
//! maximum priority each user/group may request (all optionally overridable per
//! user/group). Deserialized with `serde`/`serde_json` and validated into the
//! runtime form the `broker` consumes.
