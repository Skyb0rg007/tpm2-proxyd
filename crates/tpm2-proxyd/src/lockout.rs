// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! Tracking of authorization failures that count toward the TPM's
//! dictionary-attack lockout.
//!
//! The TPM keeps one dictionary-attack counter for everyone: every failed
//! authorization of a DA-protected entity increments it, and enough of them
//! lock the TPM for every user. The TPM reports such a failure as
//! `TPM_RC_AUTH_FAIL` (a failure without DA implications is `TPM_RC_BAD_AUTH`
//! instead). The proxy counts those responses in total and per UID, logs each
//! one, and warns once the total reaches a threshold.
//!
//! The counts live in memory for the daemon's lifetime and only ever grow; they
//! don't model the TPM's own counter, which decays over time and can be reset
//! with the lockout hierarchy's authorization.

use std::{collections::HashMap, sync::Mutex};

use tpm2_protocol::data::{TpmCc, TpmRc, TpmRcBase};

use crate::server::peer::Peer;

/// Default number of failures after which every further failure is logged as a
/// warning.
pub const DEFAULT_WARN_THRESHOLD: u64 = 10;

/// Whether `code` is a TPM response code that counted toward the lockout.
pub fn is_auth_failure(code: u32) -> bool {
    TpmRc::try_from(code).is_ok_and(|rc| rc.base() == TpmRcBase::AuthFail)
}

/// Failure counts since the daemon started.
pub struct AuthFailures {
    counts: Mutex<Counts>,
    warn_threshold: u64,
}

#[derive(Default)]
struct Counts {
    total: u64,
    by_uid: HashMap<u32, u64>,
}

impl AuthFailures {
    /// Start counting from zero, warning once the total reaches
    /// `warn_threshold` (`0` never warns).
    pub fn new(warn_threshold: u64) -> Self {
        Self {
            counts: Mutex::default(),
            warn_threshold,
        }
    }

    /// Record a failure `peer` caused by running `command`, and log it.
    pub fn record(&self, peer: &Peer, command: TpmCc) {
        let (total, uid_total) = {
            let mut counts = self.counts.lock().unwrap();
            counts.total += 1;
            let uid_total = counts.by_uid.entry(peer.uid).or_default();
            *uid_total += 1;
            let uid_total = *uid_total;
            (counts.total, uid_total)
        };

        if self.warn_threshold != 0 && total >= self.warn_threshold {
            tracing::warn!(
                uid = peer.uid,
                pid = peer.pid,
                command = %command,
                uid_failures = uid_total,
                total_failures = total,
                threshold = self.warn_threshold,
                "authorization failures toward the TPM lockout have reached the warning threshold"
            );
        } else {
            tracing::info!(
                uid = peer.uid,
                pid = peer.pid,
                command = %command,
                uid_failures = uid_total,
                total_failures = total,
                "authorization failure counted toward the TPM lockout"
            );
        }
    }

    /// Failures counted in total.
    #[cfg(test)]
    pub fn total(&self) -> u64 {
        self.counts.lock().unwrap().total
    }

    /// Failures counted for `uid`.
    #[cfg(test)]
    pub fn for_uid(&self, uid: u32) -> u64 {
        let counts = self.counts.lock().unwrap();
        counts.by_uid.get(&uid).copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_lockout_failures() {
        // TPM_RC_AUTH_FAIL, alone and for session 1.
        assert!(is_auth_failure(0x08e));
        assert!(is_auth_failure(0x98e));
        // TPM_RC_BAD_AUTH has no DA implications.
        assert!(!is_auth_failure(0x9a2));
        assert!(!is_auth_failure(0));
        // TPM_RC_AUTH_FAIL's value in another layer isn't from the TPM.
        assert!(!is_auth_failure(0x000b_008e));
    }

    #[test]
    fn counts_in_total_and_per_uid() {
        let failures = AuthFailures::new(0);
        failures.record(&Peer::new(1000, 100), TpmCc::Unseal);
        failures.record(&Peer::new(1000, 100), TpmCc::Unseal);
        failures.record(&Peer::new(1001, 100), TpmCc::Sign);

        assert_eq!(failures.total(), 3);
        assert_eq!(failures.for_uid(1000), 2);
        assert_eq!(failures.for_uid(1001), 1);
        assert_eq!(failures.for_uid(1002), 0);
    }
}
