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
//! A UID whose own count reaches the per-UID limit is locked out: the broker
//! refuses every further command from it without forwarding it. That keeps one
//! user from spending the TPM's whole failure budget and locking everyone else
//! out.
//!
//! Hierarchy authorization is exempt from the TPM's dictionary-attack
//! protection: a wrong owner, endorsement, platform or lockout password comes
//! back as `TPM_RC_BAD_AUTH` and the TPM doesn't count it, so guessing those
//! passwords would be limited only by how fast the TPM answers. Those failures
//! count toward the per-UID limit too (but not the total, which tracks the
//! TPM's own counter).
//!
//! Like the TPM's own counter, the counts recover: each forgets one failure per
//! recovery interval, and a locked-out UID is let back in once its count drops
//! below the limit. The counts live in memory, so a restart clears them. They
//! aren't read from the TPM, whose counter also recovers on its own schedule and
//! can be reset with the lockout hierarchy's authorization.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use tpm2_protocol::data::{TpmCc, TpmRc, TpmRcBase};

use crate::peer::Peer;

/// Default number of failures after which every further failure is logged as a
/// warning.
pub const DEFAULT_WARN_THRESHOLD: u64 = 10;

/// Default number of failures after which a UID is locked out.
pub const DEFAULT_UID_LIMIT: u64 = 5;

/// Default time for each count to forget one failure.
pub const DEFAULT_RECOVERY_INTERVAL: Duration = Duration::from_secs(600);

/// Response code for a command from a locked-out UID: `TPM_RC_LOCKOUT` in the
/// resource-manager layer, which tpm2-tss decodes as the TPM being in DA
/// lockout mode.
pub const RC_LOCKED_OUT: u32 = (11 << 16) | 0x921;

/// Whether `code` is a TPM response code that counted toward the lockout.
pub fn is_auth_failure(code: u32) -> bool {
    TpmRc::try_from(code).is_ok_and(|rc| rc.base() == TpmRcBase::AuthFail)
}

/// Whether `code` reports a wrong authorization the TPM doesn't count toward
/// its lockout (`TPM_RC_BAD_AUTH`).
pub fn is_bad_auth(code: u32) -> bool {
    TpmRc::try_from(code).is_ok_and(|rc| rc.base() == TpmRcBase::BadAuth)
}

/// Whether `handle` is a hierarchy whose authorization the TPM doesn't
/// protect against dictionary attacks: owner, lockout, endorsement, platform.
pub fn is_hierarchy(handle: u32) -> bool {
    matches!(
        handle,
        0x4000_0001 | 0x4000_000a | 0x4000_000b | 0x4000_000c
    )
}

/// Failure counts, recovering over time.
pub struct AuthFailures {
    counts: Mutex<Counts>,
    warn_threshold: u64,
    uid_limit: u64,
    recovery_interval: Duration,
}

struct Counts {
    total: Counter,
    by_uid: HashMap<u32, UidState>,
}

struct UidState {
    failures: Counter,
    locked_out: bool,
}

/// A failure count that forgets one failure per recovery interval.
struct Counter {
    count: u64,
    /// When the count last changed through recovery, or was empty.
    since: Instant,
}

impl Counter {
    fn new(now: Instant) -> Self {
        Self {
            count: 0,
            since: now,
        }
    }

    /// Forget one failure for each whole `interval` elapsed since the last
    /// recovery. A zero interval never recovers.
    fn recover(&mut self, interval: Duration, now: Instant) {
        if self.count == 0 {
            self.since = now;
            return;
        }
        if interval.is_zero() {
            return;
        }
        let elapsed = now.saturating_duration_since(self.since);
        let steps = u64::try_from(elapsed.as_nanos() / interval.as_nanos()).unwrap_or(u64::MAX);
        if steps >= self.count {
            self.count = 0;
            self.since = now;
        } else {
            self.count -= steps;
            // steps < count, which is small, so this can't overflow in practice.
            self.since += interval.saturating_mul(u32::try_from(steps).unwrap_or(u32::MAX));
        }
    }
}

impl AuthFailures {
    /// Start counting from zero. Once the total reaches `warn_threshold`,
    /// failures are logged as warnings; once a UID's count reaches `uid_limit`,
    /// the UID is locked out. Each count forgets one failure per
    /// `recovery_interval`. A zero disables the warning, the limit, or recovery.
    pub fn new(warn_threshold: u64, uid_limit: u64, recovery_interval: Duration) -> Self {
        Self {
            counts: Mutex::new(Counts {
                total: Counter::new(Instant::now()),
                by_uid: HashMap::new(),
            }),
            warn_threshold,
            uid_limit,
            recovery_interval,
        }
    }

    /// Record a failure toward the TPM's lockout that `peer` caused by running
    /// `command`, and log it.
    pub fn record(&self, peer: &Peer, command: TpmCc) {
        self.record_at(peer, command, Instant::now());
    }

    /// Record a wrong hierarchy authorization by `peer`, which counts toward
    /// its own limit but not the TPM's lockout, and log it.
    pub fn record_hierarchy(&self, peer: &Peer, command: TpmCc) {
        let now = Instant::now();
        let (uid_total, newly_locked_out) = {
            let mut counts = self.counts.lock().unwrap();
            self.count_for_uid(&mut counts, peer.uid, now)
        };
        tracing::warn!(
            uid = peer.uid,
            pid = peer.pid,
            command = %command,
            uid_failures = uid_total,
            "wrong hierarchy authorization"
        );
        if newly_locked_out {
            self.log_locked_out(peer, uid_total);
        }
    }

    fn record_at(&self, peer: &Peer, command: TpmCc, now: Instant) {
        let (total, uid_total, newly_locked_out) = {
            let mut counts = self.counts.lock().unwrap();
            counts.total.recover(self.recovery_interval, now);
            counts.total.count += 1;
            let total = counts.total.count;
            let (uid_total, newly_locked_out) = self.count_for_uid(&mut counts, peer.uid, now);
            (total, uid_total, newly_locked_out)
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
        if newly_locked_out {
            self.log_locked_out(peer, uid_total);
        }
    }

    /// Count one failure for `uid`. Returns its count and whether it has just
    /// been locked out.
    fn count_for_uid(&self, counts: &mut Counts, uid: u32, now: Instant) -> (u64, bool) {
        let state = counts.by_uid.entry(uid).or_insert_with(|| UidState {
            failures: Counter::new(now),
            locked_out: false,
        });
        self.refresh(uid, state, now);
        state.failures.count += 1;
        let newly_locked_out =
            !state.locked_out && self.uid_limit != 0 && state.failures.count >= self.uid_limit;
        state.locked_out |= newly_locked_out;
        (state.failures.count, newly_locked_out)
    }

    fn log_locked_out(&self, peer: &Peer, uid_total: u64) {
        tracing::warn!(
            uid = peer.uid,
            uid_failures = uid_total,
            limit = self.uid_limit,
            recovery_interval = ?self.recovery_interval,
            "user reached the authorization failure limit; refusing its commands until its failures recover"
        );
    }

    /// Whether `uid` is locked out.
    pub fn is_locked_out(&self, uid: u32) -> bool {
        self.is_locked_out_at(uid, Instant::now())
    }

    fn is_locked_out_at(&self, uid: u32, now: Instant) -> bool {
        let mut counts = self.counts.lock().unwrap();
        let Some(state) = counts.by_uid.get_mut(&uid) else {
            return false;
        };
        self.refresh(uid, state, now);
        let locked_out = state.locked_out;
        if state.failures.count == 0 {
            counts.by_uid.remove(&uid);
        }
        locked_out
    }

    /// Apply recovery to `uid`'s count, and let it back in once the count is
    /// below the limit again.
    fn refresh(&self, uid: u32, state: &mut UidState, now: Instant) {
        state.failures.recover(self.recovery_interval, now);
        if state.locked_out && state.failures.count < self.uid_limit {
            state.locked_out = false;
            tracing::info!(
                uid,
                uid_failures = state.failures.count,
                "user's authorization failures have recovered; accepting its commands again"
            );
        }
    }

    /// Failures currently counted in total, as of the last update.
    #[cfg(test)]
    pub fn total(&self) -> u64 {
        self.counts.lock().unwrap().total.count
    }

    /// Failures currently counted for `uid`, as of the last update.
    #[cfg(test)]
    pub fn for_uid(&self, uid: u32) -> u64 {
        let counts = self.counts.lock().unwrap();
        counts
            .by_uid
            .get(&uid)
            .map_or(0, |state| state.failures.count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINUTE: Duration = Duration::from_secs(60);

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
    fn recognizes_wrong_hierarchy_authorizations() {
        // TPM_RC_BAD_AUTH, alone and for session 1.
        assert!(is_bad_auth(0x0a2));
        assert!(is_bad_auth(0x9a2));
        assert!(!is_bad_auth(0x98e));
        for hierarchy in [0x4000_0001, 0x4000_000a, 0x4000_000b, 0x4000_000c] {
            assert!(is_hierarchy(hierarchy));
        }
        // TPM_RH_NULL and a transient object aren't.
        assert!(!is_hierarchy(0x4000_0007));
        assert!(!is_hierarchy(0x8000_0000));
    }

    #[test]
    fn counts_in_total_and_per_uid() {
        let failures = AuthFailures::new(0, 0, Duration::ZERO);
        failures.record(&Peer::new(1000, 100), TpmCc::Unseal);
        failures.record(&Peer::new(1000, 100), TpmCc::Unseal);
        failures.record(&Peer::new(1001, 100), TpmCc::Sign);

        assert_eq!(failures.total(), 3);
        assert_eq!(failures.for_uid(1000), 2);
        assert_eq!(failures.for_uid(1001), 1);
        assert_eq!(failures.for_uid(1002), 0);
    }

    #[test]
    fn locks_out_a_uid_at_its_limit() {
        let failures = AuthFailures::new(0, 2, Duration::ZERO);
        let peer = Peer::new(1000, 100);

        failures.record(&peer, TpmCc::Unseal);
        assert!(!failures.is_locked_out(1000));
        failures.record(&peer, TpmCc::Unseal);
        assert!(failures.is_locked_out(1000));
        // Other users aren't affected.
        assert!(!failures.is_locked_out(1001));
    }

    #[test]
    fn a_zero_limit_never_locks_out() {
        let failures = AuthFailures::new(0, 0, Duration::ZERO);
        for _ in 0..100 {
            failures.record(&Peer::new(1000, 100), TpmCc::Unseal);
        }
        assert!(!failures.is_locked_out(1000));
    }

    #[test]
    fn counts_forget_one_failure_per_interval() {
        let failures = AuthFailures::new(0, 0, MINUTE);
        let peer = Peer::new(1000, 100);
        let start = Instant::now();
        for _ in 0..3 {
            failures.record_at(&peer, TpmCc::Unseal, start);
        }

        failures.is_locked_out_at(1000, start + MINUTE - Duration::from_secs(1));
        assert_eq!(failures.for_uid(1000), 3);
        failures.is_locked_out_at(1000, start + MINUTE);
        assert_eq!(failures.for_uid(1000), 2);
        // Partial intervals carry over: 2.5 minutes in, two have recovered.
        failures.is_locked_out_at(1000, start + MINUTE * 5 / 2);
        assert_eq!(failures.for_uid(1000), 1);

        // The total recovers too, as of the next failure.
        failures.record_at(&Peer::new(1001, 100), TpmCc::Unseal, start + MINUTE * 2);
        assert_eq!(failures.total(), 2);
    }

    #[test]
    fn a_locked_out_uid_is_let_back_in_as_it_recovers() {
        let failures = AuthFailures::new(0, 2, MINUTE);
        let peer = Peer::new(1000, 100);
        let start = Instant::now();
        failures.record_at(&peer, TpmCc::Unseal, start);
        failures.record_at(&peer, TpmCc::Unseal, start);

        assert!(failures.is_locked_out_at(1000, start + MINUTE / 2));
        // One failure recovered leaves the count below the limit.
        assert!(!failures.is_locked_out_at(1000, start + MINUTE));

        // Failing again locks it out again.
        failures.record_at(&peer, TpmCc::Unseal, start + MINUTE);
        assert!(failures.is_locked_out_at(1000, start + MINUTE));
    }

    #[test]
    fn fully_recovered_uids_are_forgotten() {
        let failures = AuthFailures::new(0, 0, MINUTE);
        let start = Instant::now();
        failures.record_at(&Peer::new(1000, 100), TpmCc::Unseal, start);

        assert!(!failures.is_locked_out_at(1000, start + MINUTE));
        assert!(failures.counts.lock().unwrap().by_uid.is_empty());
    }
}
