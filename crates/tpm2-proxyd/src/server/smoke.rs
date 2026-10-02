// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! End-to-end smoke tests over a real Unix socket.
//!
//! These drive the whole downstream server stack — accept, `SO_PEERCRED`
//! resolution, the hello, policy, scheduler, the connection registry, and
//! graceful shutdown — over an actual `UnixListener`/`UnixStream` pair, with a fake
//! upstream standing in for `/dev/tpmrm0`. They cover the wire path that unit
//! tests (which use in-memory duplex streams and mock listeners) cannot.

#![cfg(test)]

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::watch;

use crate::broker::Broker;
use crate::lockout::AuthFailures;
use crate::policy::Policy;
use crate::scheduler::CommandScheduler;
use crate::server::connection::{HELLO_TIMEOUT, serve_listener};
use crate::server::registry::ConnectionRegistry;
use crate::server::unix::RawTpmListener;
use crate::tpm::{Command, DEFAULT_MAX_PACKET_SIZE, HEADER_SIZE, Response};
use crate::upstream::{SessionId, Upstream, UpstreamError};

const GET_RANDOM: u32 = 0x17b;
const GET_TEST_RESULT: u32 = 0x17c;
const GET_CAPABILITY: u32 = 0x17a;
const TPM_RC_FAILURE: u32 = 0x101;

/// Priority cap the test policy gives every peer.
const MAX_PRIORITY: i32 = 10;

/// Version 1 hello with no flags, requesting `priority`.
fn hello(priority: i32) -> [u8; 12] {
    hello_bytes(1, 0, priority)
}

fn hello_bytes(version: u16, flags: u16, priority: i32) -> [u8; 12] {
    let mut bytes = [0u8; 12];
    bytes[..4].copy_from_slice(b"TPXH");
    bytes[4..6].copy_from_slice(&version.to_be_bytes());
    bytes[6..8].copy_from_slice(&flags.to_be_bytes());
    bytes[8..].copy_from_slice(&priority.to_be_bytes());
    bytes
}

/// Version 1 reply with `status` and the granted `priority`.
fn reply(status: u16, priority: i32) -> [u8; 12] {
    hello_bytes(1, status, priority)
}

const ACCEPTED: u16 = 0;
const UNSUPPORTED: u16 = 1;
const BUSY: u16 = 2;

/// Fake TPM: `GetTestResult` fails with a TPM error code, everything else
/// succeeds with a response echoing the command code into its body.
struct FakeTpm;

#[async_trait::async_trait]
impl Upstream for FakeTpm {
    async fn transact(
        &mut self,
        _session: SessionId,
        command: &Command,
    ) -> Result<Response, UpstreamError> {
        let bytes = if command.code().value() == GET_TEST_RESULT {
            error_response(TPM_RC_FAILURE)
        } else {
            success_response(command.code().value())
        };
        Ok(Response::parse(bytes, DEFAULT_MAX_PACKET_SIZE).unwrap())
    }
}

fn command(code: u32) -> Vec<u8> {
    let mut bytes = Vec::from(0x8001u16.to_be_bytes());
    bytes.extend_from_slice(&10u32.to_be_bytes());
    bytes.extend_from_slice(&code.to_be_bytes());
    bytes
}

fn success_response(code: u32) -> Vec<u8> {
    let mut bytes = Vec::from(0x8001u16.to_be_bytes());
    bytes.extend_from_slice(&14u32.to_be_bytes());
    bytes.extend_from_slice(&0u32.to_be_bytes());
    bytes.extend_from_slice(&code.to_be_bytes());
    bytes
}

fn error_response(rc: u32) -> Vec<u8> {
    let mut bytes = Vec::from(0x8001u16.to_be_bytes());
    bytes.extend_from_slice(&10u32.to_be_bytes());
    bytes.extend_from_slice(&rc.to_be_bytes());
    bytes
}

async fn read_hello_reply(stream: &mut UnixStream) -> [u8; 12] {
    let mut reply = [0u8; 12];
    stream.read_exact(&mut reply).await.unwrap();
    reply
}

/// Assert the server closed the connection without sending anything more.
///
/// A server that closes with unread client bytes pending makes the kernel
/// reset the connection rather than end it cleanly, so a reset counts as
/// closed.
async fn assert_closed(stream: &mut UnixStream) {
    let mut rest = Vec::new();
    match stream.read_to_end(&mut rest).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
        Err(error) => panic!("reading until close: {error}"),
    }
    assert!(
        rest.is_empty(),
        "unexpected bytes before close: {rest:02x?}"
    );
}

async fn read_packet(stream: &mut UnixStream) -> Option<Vec<u8>> {
    let mut header = [0u8; HEADER_SIZE];
    if stream.read_exact(&mut header).await.is_err() {
        return None;
    }
    let size = u32::from_be_bytes(header[2..6].try_into().unwrap()) as usize;
    let mut packet = vec![0u8; size];
    packet[..HEADER_SIZE].copy_from_slice(&header);
    stream.read_exact(&mut packet[HEADER_SIZE..]).await.unwrap();
    Some(packet)
}

/// Policy allowing only `GetRandom` and `GetTestResult` for any peer, at
/// priorities up to [`MAX_PRIORITY`].
fn policy() -> Policy {
    Policy::from_json(
        &format!(r#"{{"default_profile": "test", "default_max_priority": {MAX_PRIORITY}}}"#),
        &[(
            "test",
            r#"{"commands": ["TPM_CC_GetRandom", "TPM_CC_GetTestResult"]}"#,
        )],
    )
}

struct Harness {
    socket: std::path::PathBuf,
    shutdown: watch::Sender<bool>,
    server: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Harness {
    fn start(max_connections: usize) -> Self {
        let socket = std::env::temp_dir().join(format!(
            "tpm2-proxyd-smoke-{}-{}.sock",
            std::process::id(),
            fastrand_suffix(),
        ));
        let scheduler = CommandScheduler::start(FakeTpm, 8);
        let broker = Broker::new(
            policy(),
            scheduler,
            AuthFailures::new(0, 0, std::time::Duration::ZERO),
        );
        let registry = ConnectionRegistry::new(max_connections, 0);
        let listener = RawTpmListener::bind_prepared(&socket).unwrap();
        let (shutdown, shutdown_rx) = watch::channel(false);
        let server = tokio::spawn(serve_listener(
            listener,
            broker,
            registry,
            DEFAULT_MAX_PACKET_SIZE,
            shutdown_rx,
        ));
        Self {
            socket,
            shutdown,
            server,
        }
    }

    /// Connect without sending a hello.
    async fn connect_raw(&self) -> UnixStream {
        UnixStream::connect(&self.socket).await.unwrap()
    }

    /// Connect and complete the hello, requesting the highest priority.
    async fn connect(&self) -> UnixStream {
        let mut stream = self.connect_raw().await;
        stream.write_all(&hello(i32::MAX)).await.unwrap();
        assert_eq!(
            read_hello_reply(&mut stream).await,
            reply(ACCEPTED, MAX_PRIORITY)
        );
        stream
    }

    async fn shutdown(self) {
        self.shutdown.send(true).unwrap();
        self.server.await.unwrap().unwrap();
        let _ = std::fs::remove_file(&self.socket);
    }
}

// Avoid an extra dependency for a unique-enough socket suffix.
fn fastrand_suffix() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

#[tokio::test]
async fn forwards_allowed_commands_and_relays_tpm_errors() {
    let harness = Harness::start(0);
    let mut client = harness.connect().await;

    // Permitted command: success response routed back verbatim.
    client.write_all(&command(GET_RANDOM)).await.unwrap();
    assert_eq!(
        read_packet(&mut client).await.unwrap(),
        success_response(GET_RANDOM)
    );

    // Permitted command whose TPM returns an error: the error response is
    // relayed byte-for-byte rather than dropped.
    client.write_all(&command(GET_TEST_RESULT)).await.unwrap();
    assert_eq!(
        read_packet(&mut client).await.unwrap(),
        error_response(TPM_RC_FAILURE)
    );

    drop(client);
    harness.shutdown().await;
}

#[tokio::test]
async fn denied_command_gets_an_error_response() {
    let harness = Harness::start(0);
    let mut client = harness.connect().await;

    // The policy denies the command: the client gets TPM_RC_COMMAND_CODE in
    // the resource-manager layer, and the connection stays usable.
    client.write_all(&command(GET_CAPABILITY)).await.unwrap();
    assert_eq!(
        read_packet(&mut client).await.unwrap(),
        error_response(0x000b_0143)
    );
    client.write_all(&command(GET_RANDOM)).await.unwrap();
    assert_eq!(
        read_packet(&mut client).await.unwrap(),
        success_response(GET_RANDOM)
    );

    drop(client);

    harness.shutdown().await;
}

#[tokio::test]
async fn shutdown_signal_drains_idle_connections() {
    let harness = Harness::start(0);
    let idle = harness.connect().await;
    let silent = harness.connect_raw().await;

    // Shutdown must return promptly even though one client never sent a
    // command and the other never sent its hello. The bound is below the
    // server's drain grace period, so waiting out that period fails the test.
    tokio::time::timeout(Duration::from_secs(5), harness.shutdown())
        .await
        .expect("shutdown did not drain promptly");
    drop((idle, silent));
}

#[tokio::test]
async fn enforces_the_connection_cap() {
    let harness = Harness::start(1);
    // The first connection's accepted hello means it holds the only slot.
    let mut first = harness.connect().await;

    // A second connection is refused as busy, then closed.
    let mut second = harness.connect_raw().await;
    second.write_all(&hello(i32::MAX)).await.unwrap();
    assert_eq!(read_hello_reply(&mut second).await, reply(BUSY, 0));
    assert_closed(&mut second).await;

    // The first connection still works.
    first.write_all(&command(GET_RANDOM)).await.unwrap();
    assert_eq!(
        read_packet(&mut first).await.unwrap(),
        success_response(GET_RANDOM)
    );

    drop(first);
    harness.shutdown().await;
}

#[tokio::test]
async fn connections_without_a_hello_count_against_the_cap() {
    let harness = Harness::start(1);
    // An idle connection that never sends its hello still takes the slot...
    let _idle = harness.connect_raw().await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // ...so the next one is refused at once, before it even sends a hello.
    let mut second = harness.connect_raw().await;
    let busy = tokio::time::timeout(HELLO_TIMEOUT / 2, read_hello_reply(&mut second))
        .await
        .expect("refused without waiting for the hello timeout");
    assert_eq!(busy, reply(BUSY, 0));
    assert_closed(&mut second).await;

    harness.shutdown().await;
}

#[tokio::test]
async fn refuses_unsupported_hellos() {
    let harness = Harness::start(0);
    let cases = [
        ("unknown version", hello_bytes(2, 0, 0)),
        ("unknown flag", hello_bytes(1, 1, 0)),
    ];
    for (name, hello) in cases {
        let mut client = harness.connect_raw().await;
        client.write_all(&hello).await.unwrap();
        assert_eq!(
            read_hello_reply(&mut client).await,
            reply(UNSUPPORTED, 0),
            "{name}"
        );
        assert_closed(&mut client).await;
    }
    harness.shutdown().await;
}

#[tokio::test]
async fn hello_reply_grants_the_requested_priority_up_to_the_cap() {
    let harness = Harness::start(0);
    let cases = [
        ("below the cap", 3, 3),
        ("negative", -5, -5),
        ("above the cap", MAX_PRIORITY + 1, MAX_PRIORITY),
    ];
    for (name, requested, granted) in cases {
        let mut client = harness.connect_raw().await;
        client.write_all(&hello(requested)).await.unwrap();
        assert_eq!(
            read_hello_reply(&mut client).await,
            reply(ACCEPTED, granted),
            "{name}"
        );
    }
    harness.shutdown().await;
}

#[tokio::test]
async fn closes_connections_that_skip_the_hello() {
    let harness = Harness::start(0);
    let mut client = harness.connect_raw().await;

    // A bare TPM command isn't a hello: no reply, no response, just a close.
    client.write_all(&command(GET_RANDOM)).await.unwrap();
    assert_closed(&mut client).await;

    harness.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn closes_connections_that_never_send_a_hello() {
    let harness = Harness::start(0);
    let mut client = harness.connect_raw().await;

    // Time is paused and auto-advances while everything waits, so this doesn't
    // take real time. Without a hello timeout, the read would outlast the bound.
    tokio::time::timeout(HELLO_TIMEOUT * 2, assert_closed(&mut client))
        .await
        .expect("server kept a connection that never sent a hello");

    harness.shutdown().await;
}
