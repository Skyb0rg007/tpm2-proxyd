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

use std::cmp::Ordering;
use std::collections::BinaryHeap;

use tokio::sync::{mpsc, oneshot};

use crate::tpm::{Command, Response};
use crate::upstream::{Upstream, UpstreamError};

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

/// Handle used by client tasks to submit commands to the TPM worker.
#[derive(Clone)]
pub struct CommandScheduler {
    sender: mpsc::Sender<QueuedCommand>,
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
        let (sender, receiver) = mpsc::channel(queue_capacity);
        tokio::spawn(run_command_worker(upstream, receiver));
        Self { sender }
    }

    /// Queue one command and wait until the upstream TCTI returns its response.
    pub async fn execute(
        &self,
        priority: Priority,
        command: Command,
    ) -> Result<Response, ExecuteError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(QueuedCommand {
                priority,
                sequence: 0,
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

async fn run_command_worker<U>(mut upstream: U, mut receiver: mpsc::Receiver<QueuedCommand>)
where
    U: Upstream,
{
    let mut queue = BinaryHeap::new();
    let mut next_sequence = 0u64;

    loop {
        if queue.is_empty() {
            let Some(command) = receiver.recv().await else {
                break;
            };
            push_command(&mut queue, command, &mut next_sequence);
        }

        // Collect every command currently waiting before choosing the next one.
        // New arrivals cannot preempt the command selected below.
        while let Ok(command) = receiver.try_recv() {
            push_command(&mut queue, command, &mut next_sequence);
        }

        let command = queue.pop().expect("queue is non-empty");
        let result = upstream.transact(&command.command).await;
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

    struct RecordingUpstream {
        calls: Arc<Mutex<Vec<u32>>>,
        first_started: Option<oneshot::Sender<()>>,
        release_first: Arc<tokio::sync::Semaphore>,
    }

    #[async_trait::async_trait]
    impl Upstream for RecordingUpstream {
        async fn transact(&mut self, command: &Command) -> Result<Response, UpstreamError> {
            let is_first = self.calls.lock().unwrap().is_empty();
            self.calls.lock().unwrap().push(command.code().value());
            if is_first {
                if let Some(started) = self.first_started.take() {
                    let _ = started.send(());
                }
                self.release_first.acquire().await.unwrap().forget();
            }
            Ok(success_response(command.code().value()))
        }
    }

    #[tokio::test]
    async fn command_scheduler_serializes_and_prioritizes_waiters() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let release_first = Arc::new(tokio::sync::Semaphore::new(0));
        let (first_started, started) = oneshot::channel();
        let scheduler = CommandScheduler::start(
            RecordingUpstream {
                calls: calls.clone(),
                first_started: Some(first_started),
                release_first: release_first.clone(),
            },
            8,
        );

        let first_scheduler = scheduler.clone();
        let first = tokio::spawn(async move {
            first_scheduler
                .execute(Priority(0), raw_command(0x17b))
                .await
                .unwrap()
        });
        started.await.unwrap();

        let low_scheduler = scheduler.clone();
        let low = tokio::spawn(async move {
            low_scheduler
                .execute(Priority(1), raw_command(0x17a))
                .await
                .unwrap()
        });
        let high_scheduler = scheduler.clone();
        let high = tokio::spawn(async move {
            high_scheduler
                .execute(Priority(10), raw_command(0x17c))
                .await
                .unwrap()
        });

        // Let both submissions reach the worker while the first transaction is
        // non-preemptibly blocked upstream.
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
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
        assert_eq!(*calls.lock().unwrap(), [0x17b, 0x17c, 0x17a]);
    }
}
