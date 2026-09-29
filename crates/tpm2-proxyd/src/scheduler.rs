// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! Non-preemptive upstream TPM command scheduler.
//!
//! The TPM is a serial resource: once a command is sent upstream, this daemon
//! does not attempt to cancel, time-slice, or preempt it. Client tasks enqueue
//! already-authorized commands with a fixed priority. A single worker owns the
//! upstream transport, drains pending commands in priority order, and completes
//! exactly one TPM transaction at a time.
//!
//! Each client submits through its own [`Session`], which tags its commands so
//! the upstream can keep per-client TPM state apart. Dropping the session tells
//! the upstream to release that state.

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::sync::Arc;
use std::sync::atomic::{self, AtomicU64};

use tokio::sync::{mpsc, oneshot};

use crate::tpm::{Command, Response};
use crate::upstream::{SessionId, Upstream, UpstreamError};

/// Scheduling priority for a client command.
///
/// Larger values run first. Commands at the same priority retain submission
/// order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Priority(pub i32);

impl Priority {
    /// Request the highest possible priority.
    ///
    /// Admission policy should cap this to the maximum allowed for the peer.
    pub const MAX: Self = Self(i32::MAX);
}

/// Handle to the TPM worker, used to open client sessions.
#[derive(Clone)]
pub struct CommandScheduler {
    commands: mpsc::Sender<QueuedCommand>,
    // Unbounded so that a session can always report its closure from `Drop`.
    closed: mpsc::UnboundedSender<SessionId>,
    next_session: Arc<AtomicU64>,
}

impl CommandScheduler {
    /// Start the single, non-preemptive upstream worker.
    ///
    /// `queue_capacity` bounds commands waiting to enter the scheduler. The
    /// worker owns `upstream`, so no second transaction can overlap it.
    pub fn start<U>(upstream: U, queue_capacity: usize) -> Self
    where
        U: Upstream,
    {
        assert!(queue_capacity > 0, "queue capacity must be non-zero");
        let (commands, receiver) = mpsc::channel(queue_capacity);
        let (closed, closed_receiver) = mpsc::unbounded_channel();
        tokio::spawn(run_command_worker(upstream, receiver, closed_receiver));
        Self {
            commands,
            closed,
            next_session: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Open a new upstream session for one client.
    pub fn open_session(&self) -> Session {
        Session {
            id: SessionId(self.next_session.fetch_add(1, atomic::Ordering::Relaxed)),
            commands: self.commands.clone(),
            closed: self.closed.clone(),
        }
    }
}

/// One client's upstream session; its upstream state is released on drop.
pub struct Session {
    id: SessionId,
    commands: mpsc::Sender<QueuedCommand>,
    closed: mpsc::UnboundedSender<SessionId>,
}

impl Session {
    /// Queue one command and wait until the upstream TCTI returns its response.
    pub async fn execute(
        &self,
        priority: Priority,
        command: Command,
    ) -> Result<Response, ExecuteError> {
        let (reply, response) = oneshot::channel();
        self.commands
            .send(QueuedCommand {
                priority,
                sequence: 0,
                session: self.id,
                command,
                reply,
            })
            .await
            .map_err(|_| ExecuteError::SchedulerStopped)?;

        response
            .await
            .map_err(|_| ExecuteError::SchedulerStopped)?
            .map_err(ExecuteError::Upstream)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.closed.send(self.id);
    }
}

/// Failure to execute a scheduled command.
#[derive(Debug, thiserror::Error)]
pub enum ExecuteError {
    /// The scheduler worker is no longer running.
    #[error("TPM command scheduler stopped")]
    SchedulerStopped,
    /// The upstream TCTI failed or returned a malformed response.
    #[error(transparent)]
    Upstream(#[from] UpstreamError),
}

struct QueuedCommand {
    priority: Priority,
    sequence: u64,
    session: SessionId,
    command: Command,
    reply: oneshot::Sender<Result<Response, UpstreamError>>,
}

impl PartialEq for QueuedCommand {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority && self.sequence == other.sequence
    }
}

impl Eq for QueuedCommand {}

impl PartialOrd for QueuedCommand {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for QueuedCommand {
    fn cmp(&self, other: &Self) -> Ordering {
        self.priority
            .cmp(&other.priority)
            // BinaryHeap pops the greatest item. Earlier sequence numbers win
            // within a priority band, so reverse the sequence comparison.
            .then_with(|| other.sequence.cmp(&self.sequence))
    }
}

async fn run_command_worker<U>(
    mut upstream: U,
    mut receiver: mpsc::Receiver<QueuedCommand>,
    mut closed: mpsc::UnboundedReceiver<SessionId>,
) where
    U: Upstream,
{
    let mut queue = BinaryHeap::new();
    let mut next_sequence = 0u64;

    loop {
        // Release disconnected clients' upstream state before the next
        // transaction.
        while let Ok(session) = closed.try_recv() {
            upstream.close(session).await;
        }

        if queue.is_empty() {
            tokio::select! {
                Some(session) = closed.recv() => upstream.close(session).await,
                command = receiver.recv() => match command {
                    Some(command) => push_command(&mut queue, command, &mut next_sequence),
                    None => break,
                },
            }
            continue;
        }

        // Collect every command currently waiting before choosing the next one.
        // New arrivals cannot preempt the command selected below.
        while let Ok(command) = receiver.try_recv() {
            push_command(&mut queue, command, &mut next_sequence);
        }

        let command = queue.pop().expect("queue is non-empty");
        // Nobody is waiting for this command's response: its client went away
        // while it was queued, and its session may already be closed.
        if command.reply.is_closed() {
            continue;
        }
        let result = upstream.transact(command.session, &command.command).await;
        let _ = command.reply.send(result);
    }
}

fn push_command(
    queue: &mut BinaryHeap<QueuedCommand>,
    mut command: QueuedCommand,
    next_sequence: &mut u64,
) {
    command.sequence = *next_sequence;
    *next_sequence = next_sequence.wrapping_add(1);
    queue.push(command);
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    fn raw_command(code: u32) -> Command {
        let mut bytes = Vec::from(0x8001u16.to_be_bytes());
        bytes.extend_from_slice(&10u32.to_be_bytes());
        bytes.extend_from_slice(&code.to_be_bytes());
        Command::parse(bytes, 4096).unwrap()
    }

    // A valid success response (`TPM_RC_SUCCESS`) carrying the command code in
    // its body so each command's response is identifiable in assertions.
    fn success_response(code: u32) -> Response {
        let mut bytes = Vec::from(0x8001u16.to_be_bytes());
        bytes.extend_from_slice(&14u32.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&code.to_be_bytes());
        Response::parse(bytes, 4096).unwrap()
    }

    #[derive(Debug, PartialEq)]
    enum Event {
        Transact(SessionId, u32),
        Close(SessionId),
    }

    /// Records every upstream call and holds the first transaction until
    /// `release_first` gets a permit, so tests can queue commands behind it.
    struct RecordingUpstream {
        events: Arc<Mutex<Vec<Event>>>,
        first_started: Option<oneshot::Sender<()>>,
        release_first: Arc<tokio::sync::Semaphore>,
    }

    /// A scheduler over a [`RecordingUpstream`], plus the handles to observe
    /// and release it.
    struct Harness {
        scheduler: CommandScheduler,
        events: Arc<Mutex<Vec<Event>>>,
        first_started: oneshot::Receiver<()>,
        release_first: Arc<tokio::sync::Semaphore>,
    }

    impl Harness {
        fn start() -> Self {
            let events = Arc::new(Mutex::new(Vec::new()));
            let release_first = Arc::new(tokio::sync::Semaphore::new(0));
            let (started, first_started) = oneshot::channel();
            let scheduler = CommandScheduler::start(
                RecordingUpstream {
                    events: events.clone(),
                    first_started: Some(started),
                    release_first: release_first.clone(),
                },
                8,
            );
            Self {
                scheduler,
                events,
                first_started,
                release_first,
            }
        }
    }

    #[async_trait::async_trait]
    impl Upstream for RecordingUpstream {
        async fn transact(
            &mut self,
            session: SessionId,
            command: &Command,
        ) -> Result<Response, UpstreamError> {
            self.events
                .lock()
                .unwrap()
                .push(Event::Transact(session, command.code().value()));
            if let Some(started) = self.first_started.take() {
                let _ = started.send(());
                self.release_first.acquire().await.unwrap().forget();
            }
            Ok(success_response(command.code().value()))
        }

        async fn close(&mut self, session: SessionId) {
            self.events.lock().unwrap().push(Event::Close(session));
        }
    }

    /// Give spawned submissions time to reach the worker's queue.
    async fn let_submissions_queue() {
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn command_scheduler_serializes_and_prioritizes_waiters() {
        let Harness {
            scheduler,
            events,
            first_started: started,
            release_first,
        } = Harness::start();

        let first_session = scheduler.open_session();
        let first = tokio::spawn(async move {
            first_session
                .execute(Priority(0), raw_command(0x17b))
                .await
                .unwrap()
        });
        started.await.unwrap();

        let low_session = scheduler.open_session();
        let low = tokio::spawn(async move {
            low_session
                .execute(Priority(1), raw_command(0x17a))
                .await
                .unwrap()
        });
        let high_session = scheduler.open_session();
        let high = tokio::spawn(async move {
            high_session
                .execute(Priority(10), raw_command(0x17c))
                .await
                .unwrap()
        });

        // Let both submissions reach the worker while the first transaction is
        // non-preemptibly blocked upstream.
        let_submissions_queue().await;
        release_first.add_permits(1);

        assert_eq!(
            first.await.unwrap().as_bytes(),
            success_response(0x17b).as_bytes()
        );
        assert_eq!(
            high.await.unwrap().as_bytes(),
            success_response(0x17c).as_bytes()
        );
        assert_eq!(
            low.await.unwrap().as_bytes(),
            success_response(0x17a).as_bytes()
        );
        let transacted: Vec<u32> = events
            .lock()
            .unwrap()
            .iter()
            .filter_map(|event| match event {
                Event::Transact(_, code) => Some(*code),
                Event::Close(_) => None,
            })
            .collect();
        assert_eq!(transacted, [0x17b, 0x17c, 0x17a]);
    }

    #[tokio::test]
    async fn disconnected_session_is_closed_and_never_transacted_again() {
        let Harness {
            scheduler,
            events,
            first_started: started,
            release_first,
        } = Harness::start();
        let first_session = scheduler.open_session();
        let gone_session = scheduler.open_session();
        let later_session = scheduler.open_session();
        let (first_id, gone_id, later_id) = (first_session.id, gone_session.id, later_session.id);

        let first = tokio::spawn(async move {
            first_session
                .execute(Priority(0), raw_command(0x17b))
                .await
                .unwrap()
        });
        started.await.unwrap();

        // Queue a command behind the blocked transaction, then disconnect its
        // client before the worker reaches it.
        let gone =
            tokio::spawn(
                async move { gone_session.execute(Priority(10), raw_command(0x17a)).await },
            );
        let_submissions_queue().await;
        gone.abort();
        assert!(gone.await.unwrap_err().is_cancelled());

        release_first.add_permits(1);
        first.await.unwrap();
        // A later, lower-priority command completing proves the worker has
        // moved past the disconnected client's queued command.
        later_session
            .execute(Priority(0), raw_command(0x17c))
            .await
            .unwrap();

        let events = events.lock().unwrap();
        assert!(events.contains(&Event::Transact(first_id, 0x17b)));
        assert!(events.contains(&Event::Transact(later_id, 0x17c)));
        let gone_events: Vec<_> = events
            .iter()
            .filter(|event| matches!(event, Event::Transact(id, _) | Event::Close(id) if *id == gone_id))
            .collect();
        assert_eq!(gone_events, [&Event::Close(gone_id)]);
    }
}
