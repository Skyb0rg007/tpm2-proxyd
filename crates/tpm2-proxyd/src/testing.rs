// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! Fixtures shared by the unit tests.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use crate::{
    broker::Broker,
    lockout::AuthFailures,
    policy::Policy,
    scheduler::CommandScheduler,
    tpm::{Command, DEFAULT_MAX_PACKET_SIZE, HEADER_SIZE, Response},
    upstream::{SessionId, Upstream, UpstreamError},
};

/// A TPM packet: `tag`, its total size, `code` (a command or response code),
/// then `body`.
pub fn frame(tag: u16, code: u32, body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::from(tag.to_be_bytes());
    bytes.extend_from_slice(&((HEADER_SIZE + body.len()) as u32).to_be_bytes());
    bytes.extend_from_slice(&code.to_be_bytes());
    bytes.extend_from_slice(body);
    bytes
}

/// A command without sessions: `code`, then `handles` as its handle area.
pub fn command_bytes(code: u32, handles: &[u32]) -> Vec<u8> {
    let body: Vec<u8> = handles.iter().flat_map(|h| h.to_be_bytes()).collect();
    frame(0x8001, code, &body)
}

/// [`command_bytes`], parsed.
pub fn command(code: u32, handles: &[u32]) -> Command {
    Command::parse(command_bytes(code, handles), DEFAULT_MAX_PACKET_SIZE).unwrap()
}

/// A successful response carrying `code` in its body, so each command's
/// response can be told apart.
pub fn echo_response(code: u32) -> Vec<u8> {
    frame(0x8001, 0, &code.to_be_bytes())
}

/// A header-only response with response code `rc`.
pub fn error_response(rc: u32) -> Vec<u8> {
    Response::error(rc).as_bytes().to_vec()
}

/// An upstream that answers each command with `answer(code)`, after `delay`,
/// and records the codes it was sent in `commands`.
pub struct FakeUpstream<F> {
    answer: F,
    delay: Duration,
    pub commands: Arc<Mutex<Vec<u32>>>,
}

impl<F: Fn(u32) -> Vec<u8> + Send + 'static> FakeUpstream<F> {
    pub fn new(answer: F) -> Self {
        Self {
            answer,
            delay: Duration::ZERO,
            commands: Arc::default(),
        }
    }

    pub fn with_delay(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }
}

impl FakeUpstream<fn(u32) -> Vec<u8>> {
    /// Answers every command with [`echo_response`].
    pub fn echo() -> Self {
        Self::new(echo_response)
    }
}

/// An upstream answering every command with response code `rc`.
pub fn answering(rc: u32) -> FakeUpstream<impl Fn(u32) -> Vec<u8> + Send + 'static> {
    FakeUpstream::new(move |_| error_response(rc))
}

impl<F: Fn(u32) -> Vec<u8> + Send + 'static> Upstream for FakeUpstream<F> {
    async fn transact(
        &mut self,
        _session: SessionId,
        command: &Command,
    ) -> Result<Response, UpstreamError> {
        let code = command.code().value();
        self.commands.lock().unwrap().push(code);
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
        Ok(Response::parse(
            (self.answer)(code),
            DEFAULT_MAX_PACKET_SIZE,
        )?)
    }
}

/// A broker enforcing `policy` in front of `upstream`, locking out a UID after
/// `uid_limit` authorization failures (0 = never).
pub fn broker(policy: Policy, upstream: impl Upstream, uid_limit: u64) -> Broker {
    Broker::new(
        policy,
        CommandScheduler::start(upstream, 64),
        AuthFailures::new(0, uid_limit, Duration::ZERO),
    )
}
