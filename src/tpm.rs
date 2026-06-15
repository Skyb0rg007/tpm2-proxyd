// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: BSD-2-Clause

//! TPM command/response inspection.
//!
//! Built on the `tpm2`/`tpm2-client`/`tpm2-impl` crates, this module parses the
//! TPM command header (tag, size, command code) and handle area into the form
//! [`crate::policy`] needs for authorization decisions, and inspects responses
//! (e.g. response code) on the way back. It also synthesizes TPM error
//! responses for the broker to return when a command is denied, throttled, or
//! times out (e.g. a `TPM_RC` "yielded"/busy response).
//!
//! Inspection only: this is not a resource manager and does not rewrite handles
//! or manage transient object/session contexts.
