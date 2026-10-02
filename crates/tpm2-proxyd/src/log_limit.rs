// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! Per-UID limits on the log lines a client can trigger at will.
//!
//! Admissions, refused connections and denied commands are each logged, and a
//! client can cause as many of them as it likes by reconnecting or resending.
//! Unchecked, one user could exceed journald's per-service rate limit, which
//! then drops messages from everyone, other users' denials included. Each UID
//! may log [`LIMIT`] lines of each kind per [`WINDOW`]; past that its lines
//! are counted instead, and the next one logged after the window reports how
//! many were held back.

use std::{
    collections::HashMap,
    sync::{LazyLock, Mutex},
    time::{Duration, Instant},
};

/// Lines of one kind each UID may log per window.
pub const LIMIT: u32 = 20;

/// The window over which [`LIMIT`] applies.
pub const WINDOW: Duration = Duration::from_secs(60);

/// Above this many tracked windows, expired ones are dropped.
const PRUNE_AT: usize = 4096;

/// A kind of client-triggered log line.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    /// A client admitted.
    Admission,
    /// A connection refused because a connection limit was reached.
    Busy,
    /// A command denied by policy.
    Denial,
}

/// Whether to log a line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Log it, noting how many lines were held back before it.
    Log {
        /// Lines of this kind from this UID not logged since the last one.
        suppressed: u64,
    },
    /// Don't log it; it's the first held back in this window, so say that
    /// further lines are being held back.
    StartSuppressing,
    /// Don't log it.
    Suppress,
}

struct Window {
    start: Instant,
    logged: u32,
    suppressed: u64,
}

/// Limits for every UID and kind.
pub struct LogLimiter {
    windows: Mutex<HashMap<(u32, Kind), Window>>,
    limit: u32,
    window: Duration,
}

impl LogLimiter {
    /// A limiter allowing `limit` lines of each kind per UID per `window`.
    pub fn new(limit: u32, window: Duration) -> Self {
        Self {
            windows: Mutex::new(HashMap::new()),
            limit,
            window,
        }
    }

    /// Whether `uid` may log a line of `kind` now.
    pub fn check(&self, uid: u32, kind: Kind) -> Verdict {
        self.check_at(uid, kind, Instant::now())
    }

    fn check_at(&self, uid: u32, kind: Kind, now: Instant) -> Verdict {
        let mut windows = self.windows.lock().unwrap();
        if windows.len() > PRUNE_AT {
            windows.retain(|_, window| {
                now.saturating_duration_since(window.start) < self.window || window.suppressed != 0
            });
        }
        let window = windows.entry((uid, kind)).or_insert(Window {
            start: now,
            logged: 0,
            suppressed: 0,
        });
        if now.saturating_duration_since(window.start) >= self.window {
            window.start = now;
            window.logged = 0;
        }
        if window.logged < self.limit {
            window.logged += 1;
            let suppressed = std::mem::take(&mut window.suppressed);
            return Verdict::Log { suppressed };
        }
        window.suppressed += 1;
        if window.suppressed == 1 {
            Verdict::StartSuppressing
        } else {
            Verdict::Suppress
        }
    }
}

/// The daemon's limiter.
pub static LIMITER: LazyLock<LogLimiter> = LazyLock::new(|| LogLimiter::new(LIMIT, WINDOW));

/// Log a client-triggered line for `uid` at `level` if its limit allows. The
/// `tracing` fields follow the message, each with a trailing comma; `uid` is
/// added.
macro_rules! limited {
    ($level:ident, $uid:expr, $kind:expr, $message:literal, $($field:tt)*) => {{
        let uid: u32 = $uid;
        match $crate::log_limit::LIMITER.check(uid, $kind) {
            $crate::log_limit::Verdict::Log { suppressed: 0 } => {
                tracing::$level!(uid, $($field)* $message)
            }
            $crate::log_limit::Verdict::Log { suppressed } => {
                tracing::$level!(uid, suppressed, $($field)* $message)
            }
            $crate::log_limit::Verdict::StartSuppressing => tracing::warn!(
                uid,
                kind = ?$kind,
                limit = $crate::log_limit::LIMIT,
                window = ?$crate::log_limit::WINDOW,
                "too many log lines from this user; holding back further ones"
            ),
            $crate::log_limit::Verdict::Suppress => {}
        }
    }};
}
pub(crate) use limited;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn holds_back_lines_past_the_limit_until_the_window_ends() {
        let limiter = LogLimiter::new(2, Duration::from_secs(60));
        let start = Instant::now();
        let check =
            |seconds| limiter.check_at(1000, Kind::Denial, start + Duration::from_secs(seconds));

        assert_eq!(check(0), Verdict::Log { suppressed: 0 });
        assert_eq!(check(1), Verdict::Log { suppressed: 0 });
        assert_eq!(check(2), Verdict::StartSuppressing);
        assert_eq!(check(3), Verdict::Suppress);
        // A new window: the next line reports what was held back.
        assert_eq!(check(61), Verdict::Log { suppressed: 2 });
        assert_eq!(check(62), Verdict::Log { suppressed: 0 });
    }

    #[test]
    fn limits_each_uid_and_kind_separately() {
        let limiter = LogLimiter::new(1, Duration::from_secs(60));
        let now = Instant::now();
        assert_eq!(
            limiter.check_at(1000, Kind::Denial, now),
            Verdict::Log { suppressed: 0 }
        );
        assert_eq!(
            limiter.check_at(1000, Kind::Denial, now),
            Verdict::StartSuppressing
        );
        assert_eq!(
            limiter.check_at(1001, Kind::Denial, now),
            Verdict::Log { suppressed: 0 }
        );
        assert_eq!(
            limiter.check_at(1000, Kind::Admission, now),
            Verdict::Log { suppressed: 0 }
        );
    }
}
