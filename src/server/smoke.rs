// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: BSD-2-Clause

//! End-to-end smoke tests over a real Unix socket.
//!
//! These drive the whole downstream server stack — accept, `SO_PEERCRED`
//! resolution, policy, scheduler, the connection registry, and graceful
//! shutdown — over an actual `UnixListener`/`UnixStream` pair, with a fake
//! upstream standing in for `/dev/tpmrm0`. They cover the wire path that unit
//! tests (which use in-memory duplex streams and mock listeners) cannot.

#![cfg(test)]

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::watch;

use crate::broker::Broker;
use crate::policy::{CommandRule, Decision, Policy, PolicyConfig, Subject};
use crate::scheduler::CommandScheduler;
use crate::server::connection::serve_listener;
use crate::server::registry::ConnectionRegistry;
use crate::server::unix::RawTpmListener;
use crate::tpm::{Command, DEFAULT_MAX_PACKET_SIZE, HEADER_SIZE, Response};
use crate::upstream::{Upstream, UpstreamError};

const GET_RANDOM: u32 = 0x17b;
const GET_TEST_RESULT: u32 = 0x17c;
const GET_CAPABILITY: u32 = 0x17a;
const TPM_RC_FAILURE: u32 = 0x101;

/// Fake TPM: `GetTestResult` fails with a TPM error code, everything else
/// succeeds with a response echoing the command code into its body.
struct FakeTpm;

#[async_trait::async_trait]
impl Upstream for FakeTpm {
    async fn transact(&mut self, command: &Command) -> Result<Response, UpstreamError> {
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

/// Policy allowing only `GetRandom` and `GetTestResult` for any peer.
fn policy() -> Policy {
    Policy::new(PolicyConfig {
        default_decision: Decision::Deny,
        default_max_priority: i32::MAX,
        command_rules: vec![CommandRule {
            subject: Subject::default(),
            commands: vec![
                tpm2_protocol::data::TpmCc::GetRandom,
                tpm2_protocol::data::TpmCc::GetTestResult,
            ],
            decision: Decision::Allow,
        }],
        priority_rules: Vec::new(),
    })
}

struct Harness {
    socket: std::path::PathBuf,
    shutdown: watch::Sender<bool>,
    registry: ConnectionRegistry,
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
        let broker = Broker::new(policy(), scheduler);
        let registry = ConnectionRegistry::new(max_connections);
        let listener = RawTpmListener::bind_prepared(&socket).unwrap();
        let (shutdown, shutdown_rx) = watch::channel(false);
        let server = tokio::spawn(serve_listener(
            listener,
            broker,
            registry.clone(),
            DEFAULT_MAX_PACKET_SIZE,
            shutdown_rx,
        ));
        Self {
            socket,
            shutdown,
            registry,
            server,
        }
    }

    async fn connect(&self) -> UnixStream {
        UnixStream::connect(&self.socket).await.unwrap()
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
async fn denied_command_closes_the_connection() {
    let harness = Harness::start(0);
    let mut client = harness.connect().await;

    client.write_all(&command(GET_CAPABILITY)).await.unwrap();
    // The policy denies the command, so the server closes the connection
    // without replying.
    assert!(read_packet(&mut client).await.is_none());

    harness.shutdown().await;
}

#[tokio::test]
async fn shutdown_signal_drains_idle_connections() {
    let harness = Harness::start(0);
    let client = harness.connect().await;

    // Let the server register the connection.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(harness.registry.len(), 1);

    // Shutdown must return even though the client is idle (never sent a command).
    harness.shutdown().await;
    drop(client);
}

#[tokio::test]
async fn enforces_the_connection_cap() {
    let harness = Harness::start(1);
    let mut first = harness.connect().await;

    // The first connection occupies the only slot.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(harness.registry.len(), 1);

    // A second connection is accepted then immediately dropped by the server.
    let mut second = harness.connect().await;
    second.write_all(&command(GET_RANDOM)).await.unwrap();
    assert!(read_packet(&mut second).await.is_none());

    // The first connection still works.
    first.write_all(&command(GET_RANDOM)).await.unwrap();
    assert_eq!(
        read_packet(&mut first).await.unwrap(),
        success_response(GET_RANDOM)
    );

    drop(first);
    harness.shutdown().await;
}
