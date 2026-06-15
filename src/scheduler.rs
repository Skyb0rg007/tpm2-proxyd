// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: BSD-2-Clause

//! Upstream TPM access scheduler.
//!
//! The TPM is a serial, shared resource: it processes one command at a time and
//! every downstream client ultimately contends for the single [`crate::upstream`]
//! transport. This module arbitrates that access so no client can monopolize or
//! wedge the TPM. See `docs/design.md` for the full rationale.
//!
//! Access is modeled as a **TPM lease** that a client must hold to transmit a
//! command. The scheduler provides:
//!
//! - **Mutual exclusion** — exactly one lease grants exclusive use of upstream.
//! - **Wait queue + fairness** — blocked clients wait in a queue ordered by a
//!   configurable policy (FIFO initially; weighted fair-share across UIDs is the
//!   target), keyed on peer identity ([`crate::server::peer`]).
//! - **Time-slice accounting** — measures how long each client holds the lease
//!   and requeues it once its slice is spent, so others make progress.
//! - **Time limits / quotas** — per-UID budgets over a rolling window that
//!   throttle (delay) or reject clients exceeding their share; rejections become
//!   synthesized TPM "busy/yielded" responses via [`crate::tpm`].
//! - **Watchdog** — enforces the hard per-command timeout and reclaims a lease
//!   whose holder stalled or died.
//!
//! Scheduling decisions are made at command boundaries only: a TPM command is
//! non-preemptible, so a spent slice declines the client's *next* command rather
//! than interrupting one in flight. The hard per-command timeout is the sole
//! in-flight control and is applied via the TCTI `cancel` path in
//! [`crate::upstream`].
//!
//! Schedule parameters (slice duration, per-command timeout, per-UID quota and
//! window, fairness policy) come from [`crate::config`]. Timing is driven by
//! Tokio's clock.
