// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: BSD-2-Clause

//! Core proxy pipeline and shared runtime state.
//!
//! The broker owns the long-lived shared state — the compiled [`crate::policy`]
//! ruleset, the [`crate::scheduler`], and the [`crate::upstream`] connection —
//! and exposes the per-request operation that ties the daemon together: given a
//! connecting peer's identity and a raw command from a [`crate::server`]
//! connection, it
//!
//! 1. parses/inspects the command ([`crate::tpm`]),
//! 2. authorizes it for the peer ([`crate::policy`]),
//! 3. acquires a TPM time slice for the peer ([`crate::scheduler`]) — waiting
//!    its turn, since the TPM is serial,
//! 4. forwards it upstream ([`crate::upstream`]) when allowed, recording the
//!    elapsed time back to the scheduler and releasing the lease, and
//! 5. returns the response — or a synthesized TPM error response when denied,
//!    throttled, or timed out.
//!
//! This is access control and scheduling only; the broker performs no resource
//! virtualization or context management (this daemon is not a TAB/RM).
