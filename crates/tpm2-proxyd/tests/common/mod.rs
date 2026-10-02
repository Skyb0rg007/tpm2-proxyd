// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! Shared harness for the end-to-end test suite.
//!
//! Each [`TestEnv`] spins up a **fresh** swtpm software TPM and a **fresh**
//! `tpm2-proxyd` wired to it, and drives the proxy over its socket: the hello,
//! then the same self-framing TPM byte stream the downstream TCTI module speaks. Both child
//! processes are killed and the temp directory removed on drop, and are also set
//! to die with the test process via a parent-death signal so a crashing test
//! never leaks a swtpm.
//!
//! Requires `swtpm` on `PATH` (provided by the Nix development shell).

#![allow(dead_code)] // Each test binary uses a subset of the helpers.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rustix::process::{Signal, getuid, set_parent_process_death_signal};

/// TPM command tag with no authorization sessions (`TPM_ST_NO_SESSIONS`).
pub const NO_SESSIONS: u16 = 0x8001;
/// TPM command tag with authorization sessions (`TPM_ST_SESSIONS`).
pub const SESSIONS: u16 = 0x8002;
/// `TPM_RC_SUCCESS`.
pub const TPM_RC_SUCCESS: u32 = 0x0000;
/// `TPM_RC_INITIALIZE` — returned when the TPM is (already) started.
pub const TPM_RC_INITIALIZE: u32 = 0x0100;

/// TPM command codes used by the suite.
pub mod cc {
    pub const STARTUP: u32 = 0x0000_0144;
    pub const SELF_TEST: u32 = 0x0000_0143;
    pub const INCREMENTAL_SELF_TEST: u32 = 0x0000_0142;
    pub const GET_TEST_RESULT: u32 = 0x0000_017c;
    pub const GET_CAPABILITY: u32 = 0x0000_017a;
    pub const GET_RANDOM: u32 = 0x0000_017b;
    pub const STIR_RANDOM: u32 = 0x0000_0146;
    pub const READ_CLOCK: u32 = 0x0000_0181;
    pub const PCR_READ: u32 = 0x0000_017e;
    pub const READ_PUBLIC: u32 = 0x0000_0173;
    pub const CLEAR: u32 = 0x0000_0126;
    pub const CONTEXT_SAVE: u32 = 0x0000_0162;
    pub const START_AUTH_SESSION: u32 = 0x0000_0176;
    pub const FLUSH_CONTEXT: u32 = 0x0000_0165;
}

/// `TPM_CAP` values for `GetCapability`.
pub mod cap {
    pub const ALGS: u32 = 0x0;
    pub const HANDLES: u32 = 0x1;
    pub const COMMANDS: u32 = 0x2;
    pub const PCRS: u32 = 0x5;
    pub const TPM_PROPERTIES: u32 = 0x6;
}

/// Build a TPM command frame: tag, total size, command code, body.
pub fn frame(tag: u16, command_code: u32, body: &[u8]) -> Vec<u8> {
    let size = (10 + body.len()) as u32;
    let mut bytes = Vec::with_capacity(size as usize);
    bytes.extend_from_slice(&tag.to_be_bytes());
    bytes.extend_from_slice(&size.to_be_bytes());
    bytes.extend_from_slice(&command_code.to_be_bytes());
    bytes.extend_from_slice(body);
    bytes
}

pub fn get_random(bytes: u16) -> Vec<u8> {
    frame(NO_SESSIONS, cc::GET_RANDOM, &bytes.to_be_bytes())
}
pub fn get_test_result() -> Vec<u8> {
    frame(NO_SESSIONS, cc::GET_TEST_RESULT, &[])
}
pub fn read_clock() -> Vec<u8> {
    frame(NO_SESSIONS, cc::READ_CLOCK, &[])
}
pub fn stir_random() -> Vec<u8> {
    frame(NO_SESSIONS, cc::STIR_RANDOM, &0u16.to_be_bytes())
}
pub fn incremental_self_test() -> Vec<u8> {
    // TPML_ALG with count = 0 (test nothing).
    frame(NO_SESSIONS, cc::INCREMENTAL_SELF_TEST, &0u32.to_be_bytes())
}
pub fn startup_clear() -> Vec<u8> {
    // TPM_SU_CLEAR.
    frame(NO_SESSIONS, cc::STARTUP, &0u16.to_be_bytes())
}
pub fn read_public(handle: u32) -> Vec<u8> {
    frame(NO_SESSIONS, cc::READ_PUBLIC, &handle.to_be_bytes())
}
/// An unbound, unsalted HMAC session using SHA-256.
pub fn start_auth_session() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0x4000_0007u32.to_be_bytes()); // tpmKey: TPM_RH_NULL
    body.extend_from_slice(&0x4000_0007u32.to_be_bytes()); // bind: TPM_RH_NULL
    body.extend_from_slice(&16u16.to_be_bytes()); // nonceCaller
    body.extend_from_slice(&[0x5a; 16]);
    body.extend_from_slice(&0u16.to_be_bytes()); // encryptedSalt
    body.push(0x00); // TPM_SE_HMAC
    body.extend_from_slice(&0x0010u16.to_be_bytes()); // symmetric: TPM_ALG_NULL
    body.extend_from_slice(&0x000bu16.to_be_bytes()); // authHash: TPM_ALG_SHA256
    frame(NO_SESSIONS, cc::START_AUTH_SESSION, &body)
}
pub fn flush_context(handle: u32) -> Vec<u8> {
    frame(NO_SESSIONS, cc::FLUSH_CONTEXT, &handle.to_be_bytes())
}
/// The first handle in a response's handle area.
pub fn response_handle(response: &[u8]) -> u32 {
    u32::from_be_bytes(response[10..14].try_into().expect("response has a handle"))
}
pub fn context_save(handle: u32) -> Vec<u8> {
    frame(NO_SESSIONS, cc::CONTEXT_SAVE, &handle.to_be_bytes())
}
/// `TPM2_Clear` authorized by the lockout hierarchy with an empty password.
pub fn clear() -> Vec<u8> {
    let mut body = Vec::from(0x4000_000au32.to_be_bytes()); // TPM_RH_LOCKOUT
    // Authorization area: one empty password session (TPM_RS_PW).
    body.extend_from_slice(&9u32.to_be_bytes());
    body.extend_from_slice(&0x4000_0009u32.to_be_bytes());
    body.extend_from_slice(&[0, 0, 0, 0, 0]);
    frame(SESSIONS, cc::CLEAR, &body)
}
pub fn get_capability(capability: u32, property: u32, count: u32) -> Vec<u8> {
    let mut body = Vec::with_capacity(12);
    body.extend_from_slice(&capability.to_be_bytes());
    body.extend_from_slice(&property.to_be_bytes());
    body.extend_from_slice(&count.to_be_bytes());
    frame(NO_SESSIONS, cc::GET_CAPABILITY, &body)
}
pub fn pcr_read_sha256(pcr: u8) -> Vec<u8> {
    // TPML_PCR_SELECTION { count = 1, [{ SHA256, sizeofSelect = 3, bitmap }] }.
    let mut bitmap = [0u8; 3];
    bitmap[(pcr / 8) as usize] = 1 << (pcr % 8);
    let mut body = Vec::new();
    body.extend_from_slice(&1u32.to_be_bytes());
    body.extend_from_slice(&0x000Bu16.to_be_bytes()); // TPM_ALG_SHA256
    body.push(3);
    body.extend_from_slice(&bitmap);
    frame(NO_SESSIONS, cc::PCR_READ, &body)
}

/// The TPM response code from a 10-byte response header.
pub fn response_code(response: &[u8]) -> u32 {
    u32::from_be_bytes(
        response[6..10]
            .try_into()
            .expect("response has a 10-byte header"),
    )
}

/// Whether a response is `TPM_RC_SUCCESS`.
pub fn is_success(response: &[u8]) -> bool {
    response_code(response) == TPM_RC_SUCCESS
}

/// The current process UID, used to scope the proxy policy to this test.
pub fn current_uid() -> u32 {
    getuid().as_raw()
}

/// The proxy's response to a command the policy denies: `TPM_RC_COMMAND_CODE`
/// in the resource-manager layer.
pub const RC_COMMAND_DENIED: u32 = 0x000b_0143;
/// The proxy's response to `TPM2_FlushContext` of a session the connection
/// doesn't hold: `TPM_RC_HANDLE + TPM_RC_P + TPM_RC_1` in the resource-manager
/// layer.
pub const RC_NOT_OWN_SESSION: u32 = 0x000b_01cb;
/// The proxy's response to a command whose first handle the policy denies:
/// `TPM_RC_HANDLE + TPM_RC_1` in the resource-manager layer.
pub const RC_HANDLE_1_DENIED: u32 = 0x000b_018b;

/// A profile allowing every command with any handles.
pub const ALL_PROFILE: (&str, &str) = ("all", r#"{"commands": ["*"], "handles": ["*"]}"#);

/// A policy giving the current user `profile`, at priorities up to 100.
pub fn policy_for_current_user(profile: &str) -> String {
    format!(
        r#"{{"rules": [{{"subject": {{"uid": {}}}, "profile": "{profile}", "max_priority": 100}}]}}"#,
        current_uid()
    )
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A running swtpm + `tpm2-proxyd`, torn down on drop.
pub struct TestEnv {
    dir: PathBuf,
    swtpm: Child,
    proxy: Child,
    socket: PathBuf,
}

impl TestEnv {
    /// Start a fresh swtpm and proxy enforcing `policy_json`, with `profiles`
    /// given as `(name, JSON)` pairs.
    pub fn start(policy_json: &str, profiles: &[(&str, &str)]) -> Self {
        let unique = format!(
            "{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let dir = std::env::temp_dir().join(format!("tpm2-proxyd-e2e-{unique}"));
        let state = dir.join("state");
        std::fs::create_dir_all(&state).expect("create state dir");

        let data = dir.join("swtpm.sock");
        let ctrl = dir.join("swtpm.sock.ctrl");
        let socket = dir.join("proxy.sock");
        let policy = dir.join("policy.json");
        std::fs::write(&policy, policy_json).expect("write policy");
        std::fs::create_dir(dir.join("profiles")).expect("create profiles dir");
        for (name, json) in profiles {
            std::fs::write(dir.join(format!("profiles/{name}.json")), json).expect("write profile");
        }

        let swtpm_log = dir.join("swtpm.log");
        let swtpm = spawn(
            "swtpm",
            &[
                "socket".into(),
                "--tpm2".into(),
                "--tpmstate".into(),
                format!("dir={}", state.display()),
                "--server".into(),
                format!("type=unixio,path={}", data.display()),
                "--ctrl".into(),
                format!("type=unixio,path={}", ctrl.display()),
            ],
            &swtpm_log,
        );
        wait_for_socket(
            &data,
            Duration::from_secs(10),
            "swtpm data channel",
            &swtpm_log,
        );
        wait_for_socket(
            &ctrl,
            Duration::from_secs(10),
            "swtpm control channel",
            &swtpm_log,
        );
        // Give swtpm a moment to begin accepting after binding.
        std::thread::sleep(Duration::from_millis(50));

        let proxy_log = dir.join("proxy.log");
        let proxy = spawn(
            env!("CARGO_BIN_EXE_tpm2-proxyd"),
            &[
                format!("--config={}", policy.display()),
                format!("--socket={}", socket.display()),
                format!("--swtpm-server=unix:{}", data.display()),
                format!("--swtpm-ctrl=unix:{}", ctrl.display()),
            ],
            &proxy_log,
        );
        wait_for_socket(&socket, Duration::from_secs(15), "tpm2-proxyd", &proxy_log);

        Self {
            dir,
            swtpm,
            proxy,
            socket,
        }
    }

    /// Start with an allow-all policy for the current user.
    pub fn start_allow_all() -> Self {
        Self::start(&policy_for_current_user("all"), &[ALL_PROFILE])
    }

    /// The proxy's socket path.
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Open a new client connection to the proxy and complete the hello.
    pub fn connect(&self) -> Client {
        let mut stream = UnixStream::connect(&self.socket)
            .unwrap_or_else(|error| panic!("connect to proxy {}: {error}", self.socket.display()));
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .expect("set read timeout");
        // Version 1 hello with no flags, requesting the highest priority; the
        // reply must be "accepted", granting the policy's cap of 100.
        stream
            .write_all(b"TPXH\0\x01\0\0\x7f\xff\xff\xff")
            .expect("send hello");
        let mut reply = [0u8; 12];
        stream.read_exact(&mut reply).expect("read hello reply");
        assert_eq!(&reply, b"TPXH\0\x01\0\0\0\0\0\x64", "hello refused");
        Client { stream }
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        let _ = self.proxy.kill();
        let _ = self.swtpm.kill();
        let _ = self.proxy.wait();
        let _ = self.swtpm.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A client connection to the proxy.
pub struct Client {
    stream: UnixStream,
}

impl Client {
    /// Send a command and read its response.
    ///
    /// Returns `None` if the proxy closed the connection without replying — for
    /// example when the command code is rejected.
    pub fn transact(&mut self, command: &[u8]) -> Option<Vec<u8>> {
        self.stream.write_all(command).ok()?;
        self.stream.flush().ok()?;

        let mut header = [0u8; 10];
        self.stream.read_exact(&mut header).ok()?;
        let size = u32::from_be_bytes(header[2..6].try_into().unwrap()) as usize;

        let mut response = vec![0u8; size];
        response[..10].copy_from_slice(&header);
        self.stream.read_exact(&mut response[10..]).ok()?;
        Some(response)
    }
}

fn spawn(program: &str, args: &[String], log: &Path) -> Child {
    let log_file = std::fs::File::create(log).expect("create child log");
    let stderr = log_file.try_clone().expect("clone child log");

    let mut command = Command::new(program);
    command
        .args(args)
        .env("RUST_LOG", "warn")
        .stdin(Stdio::null())
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(stderr));

    unsafe {
        command.pre_exec(|| {
            set_parent_process_death_signal(Some(Signal::KILL)).map_err(std::io::Error::from)
        });
    }

    command
        .spawn()
        .unwrap_or_else(|error| panic!("failed to spawn {program}: {error}"))
}

fn wait_for_socket(path: &Path, timeout: Duration, what: &str, log: &Path) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let logs = std::fs::read_to_string(log).unwrap_or_default();
    panic!(
        "{what}: socket {} did not appear within {timeout:?}\n--- log ---\n{logs}",
        path.display(),
    );
}
