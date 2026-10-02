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

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::watch;

use crate::policy::Policy;
use crate::server::connection::HELLO_TIMEOUT;
use crate::server::registry::ConnectionRegistry;
use crate::server::serve;
use crate::server::socket::SocketListener;
use crate::testing::{FakeUpstream, broker, command_bytes, echo_response, error_response};
use crate::tpm::{DEFAULT_MAX_PACKET_SIZE, read_frame};

const GET_RANDOM: u32 = 0x17b;
const GET_TEST_RESULT: u32 = 0x17c;
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
fn fake_tpm(code: u32) -> Vec<u8> {
    if code == GET_TEST_RESULT {
        error_response(TPM_RC_FAILURE)
    } else {
        echo_response(code)
    }
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

/// Send `code` and return the response.
async fn transact(stream: &mut UnixStream, code: u32) -> Vec<u8> {
    stream.write_all(&command_bytes(code, &[])).await.unwrap();
    read_frame(stream, DEFAULT_MAX_PACKET_SIZE)
        .await
        .unwrap()
        .unwrap()
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
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let socket = std::env::temp_dir().join(format!(
            "tpm2-proxyd-smoke-{}-{}.sock",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        let listener = SocketListener::bind(&socket).unwrap();
        let (shutdown, shutdown_rx) = watch::channel(false);
        let server = tokio::spawn(serve(
            listener,
            broker(policy(), FakeUpstream::new(fake_tpm), 0),
            ConnectionRegistry::new(max_connections, 0),
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

#[tokio::test]
async fn forwards_allowed_commands_and_relays_tpm_errors() {
    let harness = Harness::start(0);
    let mut client = harness.connect().await;

    // Permitted command: success response routed back verbatim.
    assert_eq!(
        transact(&mut client, GET_RANDOM).await,
        echo_response(GET_RANDOM)
    );

    // Permitted command whose TPM returns an error: the error response is
    // relayed byte-for-byte rather than dropped.
    assert_eq!(
        transact(&mut client, GET_TEST_RESULT).await,
        error_response(TPM_RC_FAILURE)
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
    assert_eq!(
        transact(&mut first, GET_RANDOM).await,
        echo_response(GET_RANDOM)
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

    // A TPM command isn't a hello: no reply, no response, just a close. Pad it
    // to the hello's 12 bytes so the server sees the wrong magic rather than
    // waiting for more, and closes well before the hello timeout.
    let mut bytes = command_bytes(GET_RANDOM, &[]);
    bytes.resize(12, 0);
    client.write_all(&bytes).await.unwrap();
    tokio::time::timeout(HELLO_TIMEOUT / 2, assert_closed(&mut client))
        .await
        .expect("closed on the bad magic, not the hello timeout");

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
