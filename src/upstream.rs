// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: BSD-2-Clause

//! Upstream TCTI client.
//!
//! Connects to the physical TPM's resource manager (`/dev/tpmrm0`, or a
//! userland broker such as `tpm2-abrmd`) as selected by [`crate::config`], and
//! transmits/receives raw command and response byte streams on behalf of the
//! [`crate::broker`].
//!
//! The TPM is serial, so callers must already hold a lease from
//! [`crate::scheduler`] before transmitting; this module performs the actual
//! transport. It applies the hard per-command timeout and, on expiry, drives the
//! TCTI `cancel` path — the only in-flight control available for a
//! non-preemptible command. The choice of a shared upstream transport vs. one
//! per downstream client (which affects safe scheduling granularity) is made
//! here in concert with the scheduler; see `docs/design.md`.
