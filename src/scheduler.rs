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
//!   configurable policy ([`Fairness::Fifo`] or [`Fairness::FairShare`]), keyed
//!   on peer identity ([`crate::server::peer`]).
//! - **Time-slice accounting** — measures how long each client holds the lease
//!   and uses that to weight fair-share selection so others make progress.
//! - **Time limits / quotas** — per-UID budgets over a window that reject
//!   clients exceeding their share; rejections become synthesized TPM
//!   "busy/yielded" responses via [`crate::tpm`].
//! - **Hard per-command timeout** — surfaced to [`crate::upstream`], which drives
//!   the TCTI `cancel` path (the only in-flight control for a non-preemptible
//!   command).
//!
//! Scheduling decisions are made at command boundaries only: a TPM command is
//! non-preemptible, so a spent slice/quota affects a client's *next* command
//! rather than interrupting one in flight.
//!
//! # Structure
//!
//! [`SchedulerCore`] is the pure, synchronous policy engine — all ordering,
//! slice accounting, and quota logic, parameterized on an injected `now` so it
//! is fully deterministic and unit-testable. [`Scheduler`] is a thin async
//! wrapper that turns the core's decisions into an awaitable [`Lease`] using a
//! `Notify`, and is what [`crate::broker`] uses.
//!
//! Schedule parameters come from [`SchedulerConfig`] (see [`crate::config`]).

#![allow(dead_code)] // wired into the broker in a later change

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

/// Unix user id of a connecting peer; the subject of scheduling decisions.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Uid(pub u32);

/// Ordering policy used to pick the next waiter when the lease is free.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Fairness {
    /// Strict first-come-first-served by enqueue time.
    Fifo,
    /// Prefer the waiter whose UID has consumed the fewest whole time slices in
    /// the current window; ties broken by enqueue time.
    FairShare,
}

/// Per-UID overrides of the global limits (e.g. for trusted system services).
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct UidLimits {
    /// Overrides [`SchedulerConfig::slice_ms`] for this UID.
    pub slice_ms: Option<u64>,
    /// Overrides [`SchedulerConfig::quota_ms`] for this UID (0 disables quota).
    pub quota_ms: Option<u64>,
}

/// Scheduling parameters, deserialized as part of [`crate::config`].
///
/// Durations are expressed in milliseconds for human-friendly config files.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SchedulerConfig {
    /// Fair-share scheduling quantum: the unit of TPM time used to weight
    /// [`Fairness::FairShare`] selection. Must be non-zero.
    pub slice_ms: u64,
    /// Hard per-command timeout; `0` disables it.
    pub command_timeout_ms: u64,
    /// Per-UID cumulative TPM-time budget per window; `0` disables the quota.
    pub quota_ms: u64,
    /// Length of the (tumbling) accounting window for slices and quota.
    pub quota_window_ms: u64,
    /// Ordering policy for waiters.
    pub fairness: Fairness,
    /// Per-UID limit overrides, keyed by UID.
    pub overrides: HashMap<u32, UidLimits>,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            slice_ms: 50,
            command_timeout_ms: 10_000,
            quota_ms: 0, // quota disabled by default
            quota_window_ms: 1_000,
            fairness: Fairness::FairShare,
            overrides: HashMap::new(),
        }
    }
}

/// Error returned by [`SchedulerConfig::validate`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("scheduler slice_ms must be non-zero")]
    ZeroSlice,
    #[error("scheduler quota requires a non-zero quota_window_ms")]
    ZeroWindow,
    #[error("scheduler override for uid {0} has a zero slice_ms")]
    ZeroOverrideSlice(u32),
}

impl SchedulerConfig {
    /// Reject configurations that would divide by zero or silently misbehave.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.slice_ms == 0 {
            return Err(ConfigError::ZeroSlice);
        }
        let quota_enabled = self.quota_ms > 0
            || self
                .overrides
                .values()
                .any(|o| o.quota_ms.is_some_and(|q| q > 0));
        if quota_enabled && self.quota_window_ms == 0 {
            return Err(ConfigError::ZeroWindow);
        }
        for (uid, o) in &self.overrides {
            if o.slice_ms == Some(0) {
                return Err(ConfigError::ZeroOverrideSlice(*uid));
            }
        }
        Ok(())
    }

    /// Accounting window length (at least 1ms so slice math never divides by 0).
    fn window(&self) -> Duration {
        Duration::from_millis(self.quota_window_ms.max(1))
    }

    /// Hard per-command timeout, if enabled.
    pub fn command_timeout(&self) -> Option<Duration> {
        (self.command_timeout_ms > 0).then(|| Duration::from_millis(self.command_timeout_ms))
    }

    fn slice_for(&self, uid: Uid) -> Duration {
        let ms = self
            .overrides
            .get(&uid.0)
            .and_then(|o| o.slice_ms)
            .unwrap_or(self.slice_ms)
            .max(1);
        Duration::from_millis(ms)
    }

    fn quota_for(&self, uid: Uid) -> Option<Duration> {
        let ms = self
            .overrides
            .get(&uid.0)
            .and_then(|o| o.quota_ms)
            .unwrap_or(self.quota_ms);
        (ms > 0).then(|| Duration::from_millis(ms))
    }
}

/// Opaque handle identifying a client's place in the scheduler.
pub type Ticket = u64;

/// Rejection returned when a client is over quota.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Denied {
    /// Earliest time the client's quota window will have room again.
    pub retry_after: Instant,
}

/// Result of [`SchedulerCore::enqueue`].
#[derive(Debug, PartialEq, Eq)]
pub enum Admission {
    /// Accepted into the wait queue; poll the ticket until it becomes holder.
    Queued(Ticket),
    /// Rejected: the client is over its quota.
    Denied(Denied),
}

struct Waiter {
    ticket: Ticket,
    uid: Uid,
    enqueued: Instant,
}

struct Holder {
    ticket: Ticket,
    uid: Uid,
    granted: Instant,
}

struct Usage {
    window_start: Instant,
    used: Duration,
}

/// Pure, synchronous scheduling-policy engine.
///
/// Every method takes the current time as `now`, so behavior is fully
/// deterministic and independent of the wall clock. [`Scheduler`] supplies
/// `Instant::now()`; tests supply explicit instants.
pub struct SchedulerCore {
    config: SchedulerConfig,
    holder: Option<Holder>,
    queue: VecDeque<Waiter>,
    usage: HashMap<Uid, Usage>,
    next_ticket: Ticket,
}

impl SchedulerCore {
    pub fn new(config: SchedulerConfig) -> Self {
        Self {
            config,
            holder: None,
            queue: VecDeque::new(),
            usage: HashMap::new(),
            next_ticket: 0,
        }
    }

    /// Request the lease. Enforces the quota up front, then enqueues the client
    /// and promotes the fair waiter if the lease is currently free.
    pub fn enqueue(&mut self, uid: Uid, now: Instant) -> Admission {
        if let Some(retry_after) = self.quota_exceeded(uid, now) {
            return Admission::Denied(Denied { retry_after });
        }
        let ticket = self.next_ticket;
        self.next_ticket += 1;
        self.queue.push_back(Waiter {
            ticket,
            uid,
            enqueued: now,
        });
        self.try_promote(now);
        Admission::Queued(ticket)
    }

    /// Returns `true` once `ticket` holds the lease.
    pub fn poll(&self, ticket: Ticket) -> bool {
        self.holder.as_ref().is_some_and(|h| h.ticket == ticket)
    }

    /// Release the lease held by `ticket`, charging the elapsed hold time to the
    /// holder's usage and promoting the next waiter.
    pub fn release(&mut self, ticket: Ticket, now: Instant) {
        let Some(holder) = self.holder.as_ref() else {
            return;
        };
        if holder.ticket != ticket {
            return;
        }
        let uid = holder.uid;
        let used = now.saturating_duration_since(holder.granted);
        self.add_usage(uid, used, now);
        self.holder = None;
        self.try_promote(now);
    }

    /// Give up a ticket. If it is the holder this behaves like [`Self::release`];
    /// otherwise it is removed from the wait queue (cancellation safety).
    pub fn cancel(&mut self, ticket: Ticket, now: Instant) {
        if self.holder.as_ref().is_some_and(|h| h.ticket == ticket) {
            self.release(ticket, now);
            return;
        }
        if let Some(pos) = self.queue.iter().position(|w| w.ticket == ticket) {
            self.queue.remove(pos);
        }
    }

    /// UID currently holding the lease, if any.
    pub fn holder_uid(&self) -> Option<Uid> {
        self.holder.as_ref().map(|h| h.uid)
    }

    /// Number of clients waiting (not counting the holder).
    pub fn waiting(&self) -> usize {
        self.queue.len()
    }

    /// Promote the fair next waiter into the lease, if it is free.
    fn try_promote(&mut self, now: Instant) {
        if self.holder.is_some() || self.queue.is_empty() {
            return;
        }
        let idx = match self.config.fairness {
            Fairness::Fifo => 0,
            Fairness::FairShare => self
                .queue
                .iter()
                .enumerate()
                .min_by_key(|(_, w)| (self.slices_used(w.uid, now), w.enqueued))
                .map(|(i, _)| i)
                .unwrap_or(0),
        };
        let w = self.queue.remove(idx).expect("index from non-empty queue");
        self.holder = Some(Holder {
            ticket: w.ticket,
            uid: w.uid,
            granted: now,
        });
    }

    /// Whole time slices `uid` has consumed in the current window (0 if the
    /// window has lapsed), used to weight fair-share selection.
    fn slices_used(&self, uid: Uid, now: Instant) -> u64 {
        let window = self.config.window();
        match self.usage.get(&uid) {
            Some(u) if now.saturating_duration_since(u.window_start) < window => {
                let slice = self.config.slice_for(uid).as_nanos().max(1);
                (u.used.as_nanos() / slice) as u64
            }
            _ => 0,
        }
    }

    /// `Some(retry_after)` if `uid` has exhausted its quota for the window.
    fn quota_exceeded(&mut self, uid: Uid, now: Instant) -> Option<Instant> {
        let quota = self.config.quota_for(uid)?;
        let window = self.config.window();
        let u = self.usage_window(uid, now);
        if u.used >= quota {
            Some(u.window_start + window)
        } else {
            None
        }
    }

    fn add_usage(&mut self, uid: Uid, used: Duration, now: Instant) {
        let u = self.usage_window(uid, now);
        u.used = u.used.saturating_add(used);
    }

    /// Fetch `uid`'s usage entry, resetting it first if its window has lapsed.
    fn usage_window(&mut self, uid: Uid, now: Instant) -> &mut Usage {
        let window = self.config.window();
        let u = self.usage.entry(uid).or_insert(Usage {
            window_start: now,
            used: Duration::ZERO,
        });
        if now.saturating_duration_since(u.window_start) >= window {
            u.window_start = now;
            u.used = Duration::ZERO;
        }
        u
    }
}

/// Async front-end over [`SchedulerCore`] handed to the broker.
///
/// [`Scheduler::acquire`] resolves once the caller holds the TPM lease, yielding
/// a [`Lease`] guard that releases on drop. Promotion is paired with
/// `Notify::notify_waiters` so a promoted-but-sleeping waiter is always woken.
pub struct Scheduler {
    core: Mutex<SchedulerCore>,
    notify: Notify,
}

impl Scheduler {
    pub fn new(config: SchedulerConfig) -> Self {
        Self {
            core: Mutex::new(SchedulerCore::new(config)),
            notify: Notify::new(),
        }
    }

    /// Hard per-command timeout for [`crate::upstream`] to apply, if configured.
    pub fn command_timeout(&self) -> Option<Duration> {
        self.core.lock().unwrap().config.command_timeout()
    }

    /// Wait until `uid` holds the TPM lease. Returns [`Denied`] immediately if
    /// the client is over quota. Cancellation-safe: dropping the returned future
    /// before it resolves removes the client from the wait queue.
    pub async fn acquire(&self, uid: Uid) -> Result<Lease<'_>, Denied> {
        let ticket = match self.core.lock().unwrap().enqueue(uid, Instant::now()) {
            Admission::Queued(t) => t,
            Admission::Denied(d) => return Err(d),
        };
        // enqueue may have promoted a different, sleeping waiter.
        self.notify.notify_waiters();

        let mut wait = WaitGuard {
            sched: self,
            ticket,
            armed: true,
        };
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            // Register before checking so a wakeup between the two isn't lost.
            notified.as_mut().enable();

            if self.core.lock().unwrap().poll(ticket) {
                wait.armed = false;
                return Ok(Lease {
                    sched: self,
                    ticket,
                });
            }
            notified.await;
        }
    }
}

/// Removes a still-queued ticket if the [`Scheduler::acquire`] future is dropped
/// before it acquires the lease.
struct WaitGuard<'a> {
    sched: &'a Scheduler,
    ticket: Ticket,
    armed: bool,
}

impl Drop for WaitGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.sched
                .core
                .lock()
                .unwrap()
                .cancel(self.ticket, Instant::now());
            self.sched.notify.notify_waiters();
        }
    }
}

/// Exclusive TPM-lease guard. Releasing (on drop) charges the elapsed hold time
/// to the holder's quota and promotes the next waiter.
pub struct Lease<'a> {
    sched: &'a Scheduler,
    ticket: Ticket,
}

impl Drop for Lease<'_> {
    fn drop(&mut self) {
        self.sched
            .core
            .lock()
            .unwrap()
            .release(self.ticket, Instant::now());
        self.sched.notify.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(base: Instant, ms: u64) -> Instant {
        base + Duration::from_millis(ms)
    }

    fn test_config() -> SchedulerConfig {
        SchedulerConfig {
            slice_ms: 10,
            command_timeout_ms: 1_000,
            quota_ms: 0,
            quota_window_ms: 1_000,
            fairness: Fairness::Fifo,
            overrides: HashMap::new(),
        }
    }

    fn ticket(a: Admission) -> Ticket {
        match a {
            Admission::Queued(t) => t,
            Admission::Denied(d) => panic!("unexpected denial: {d:?}"),
        }
    }

    // --- config ---

    #[test]
    fn config_defaults_round_trip_through_json() {
        let json = serde_json::to_string(&SchedulerConfig::default()).unwrap();
        let back: SchedulerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, SchedulerConfig::default());
        // Empty object falls back to defaults via `#[serde(default)]`.
        let empty: SchedulerConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(empty, SchedulerConfig::default());
    }

    #[test]
    fn config_validation_rejects_bad_values() {
        assert!(test_config().validate().is_ok());

        let mut zero_slice = test_config();
        zero_slice.slice_ms = 0;
        assert_eq!(zero_slice.validate(), Err(ConfigError::ZeroSlice));

        let mut zero_window = test_config();
        zero_window.quota_ms = 100;
        zero_window.quota_window_ms = 0;
        assert_eq!(zero_window.validate(), Err(ConfigError::ZeroWindow));

        let mut bad_override = test_config();
        bad_override.overrides.insert(
            5,
            UidLimits {
                slice_ms: Some(0),
                quota_ms: None,
            },
        );
        assert_eq!(
            bad_override.validate(),
            Err(ConfigError::ZeroOverrideSlice(5))
        );
    }

    // --- core: exclusion & ordering ---

    #[test]
    fn single_client_acquires_and_releases() {
        let mut c = SchedulerCore::new(test_config());
        let t0 = Instant::now();

        let t = ticket(c.enqueue(Uid(1), t0));
        assert!(c.poll(t));
        assert_eq!(c.holder_uid(), Some(Uid(1)));

        c.release(t, at(t0, 5));
        assert_eq!(c.holder_uid(), None);
        assert_eq!(c.waiting(), 0);
    }

    #[test]
    fn second_client_waits_until_release_fifo() {
        let mut c = SchedulerCore::new(test_config());
        let t0 = Instant::now();

        let a = ticket(c.enqueue(Uid(1), t0));
        let b = ticket(c.enqueue(Uid(2), t0));
        assert!(c.poll(a));
        assert!(!c.poll(b));
        assert_eq!(c.waiting(), 1);

        c.release(a, t0);
        // Releasing promotes the next FIFO waiter.
        assert_eq!(c.holder_uid(), Some(Uid(2)));
        assert!(c.poll(b));
    }

    #[test]
    fn fair_share_prefers_the_lighter_user() {
        let mut cfg = test_config();
        cfg.fairness = Fairness::FairShare;
        let mut c = SchedulerCore::new(cfg);
        let t0 = Instant::now();

        // User 1 runs a long command (100ms => 10 slices of 10ms).
        let a1 = ticket(c.enqueue(Uid(1), t0));
        assert!(c.poll(a1));
        c.release(a1, at(t0, 100));

        // Block the lease with an unrelated holder, then queue heavy user 1 and
        // light user 2 behind it.
        let blocker = ticket(c.enqueue(Uid(9), at(t0, 100)));
        assert!(c.poll(blocker));
        let _heavy = c.enqueue(Uid(1), at(t0, 100));
        let light = ticket(c.enqueue(Uid(2), at(t0, 100)));

        // On release, fair-share skips the heavy user in favor of user 2.
        c.release(blocker, at(t0, 100));
        assert_eq!(c.holder_uid(), Some(Uid(2)));
        assert!(c.poll(light));
    }

    #[test]
    fn cancel_removes_a_waiter() {
        let mut c = SchedulerCore::new(test_config());
        let t0 = Instant::now();

        let blocker = ticket(c.enqueue(Uid(9), t0));
        assert!(c.poll(blocker));
        let a = ticket(c.enqueue(Uid(1), t0));
        let b = ticket(c.enqueue(Uid(2), t0));
        assert_eq!(c.waiting(), 2);

        c.cancel(a, t0);
        assert_eq!(c.waiting(), 1);

        // The cancelled waiter is skipped; the next one is promoted.
        c.release(blocker, t0);
        assert_eq!(c.holder_uid(), Some(Uid(2)));
        assert!(c.poll(b));
    }

    // --- core: quotas ---

    #[test]
    fn quota_denies_over_budget_and_resets_after_window() {
        let mut cfg = test_config();
        cfg.quota_ms = 50;
        cfg.quota_window_ms = 1_000;
        let mut c = SchedulerCore::new(cfg);
        let t0 = Instant::now();

        // Consume 60ms of TPM time (> 50ms budget).
        let a = ticket(c.enqueue(Uid(1), t0));
        assert!(c.poll(a));
        c.release(a, at(t0, 60));

        // Next request within the window is denied; retry_after = window end.
        match c.enqueue(Uid(1), at(t0, 60)) {
            Admission::Denied(d) => assert_eq!(d.retry_after, at(t0, 1_000)),
            other => panic!("expected denial, got {other:?}"),
        }

        // A different user is unaffected.
        assert!(matches!(
            c.enqueue(Uid(2), at(t0, 60)),
            Admission::Queued(_)
        ));

        // After the window lapses, user 1 is admitted again.
        assert!(matches!(
            c.enqueue(Uid(1), at(t0, 1_000)),
            Admission::Queued(_)
        ));
    }

    #[test]
    fn per_uid_override_raises_quota() {
        let mut cfg = test_config();
        cfg.quota_ms = 50;
        cfg.overrides.insert(
            1,
            UidLimits {
                slice_ms: None,
                quota_ms: Some(1_000),
            },
        );
        let mut c = SchedulerCore::new(cfg);
        let t0 = Instant::now();

        let a = ticket(c.enqueue(Uid(1), t0));
        assert!(c.poll(a));
        c.release(a, at(t0, 60)); // 60ms, under the overridden 1000ms budget

        assert!(matches!(
            c.enqueue(Uid(1), at(t0, 60)),
            Admission::Queued(_)
        ));
    }

    // --- async wrapper ---

    #[tokio::test]
    async fn acquire_serializes_concurrent_clients() {
        use std::sync::Arc;

        let sched = Arc::new(Scheduler::new(test_config()));
        let lease = sched.acquire(Uid(1)).await.unwrap();

        let other = sched.clone();
        let waiter = tokio::spawn(async move {
            let _l = other.acquire(Uid(2)).await.unwrap();
        });

        // The second client cannot acquire while the first holds the lease.
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiter.is_finished());

        drop(lease);
        // Now it proceeds to completion.
        waiter.await.unwrap();
    }

    #[tokio::test]
    async fn acquire_rejects_when_over_quota() {
        let mut cfg = test_config();
        cfg.quota_ms = 10;
        cfg.quota_window_ms = 100_000;
        let sched = Scheduler::new(cfg);

        {
            let _lease = sched.acquire(Uid(1)).await.unwrap();
            tokio::time::sleep(Duration::from_millis(30)).await; // burn > 10ms
        }

        assert!(sched.acquire(Uid(1)).await.is_err());
    }

    #[tokio::test]
    async fn cancelled_waiter_does_not_block_others() {
        use std::sync::Arc;

        let sched = Arc::new(Scheduler::new(test_config()));
        let lease = sched.acquire(Uid(1)).await.unwrap();

        // Start a waiter, then drop its future (cancel) before it can acquire.
        {
            let fut = sched.acquire(Uid(2));
            tokio::pin!(fut);
            assert!(
                tokio::time::timeout(Duration::from_millis(10), &mut fut)
                    .await
                    .is_err()
            );
        } // fut dropped here -> WaitGuard removes the ticket

        drop(lease);

        // A fresh client acquires promptly despite the earlier cancellation.
        tokio::time::timeout(Duration::from_millis(100), sched.acquire(Uid(3)))
            .await
            .expect("should not time out")
            .unwrap();
    }
}
