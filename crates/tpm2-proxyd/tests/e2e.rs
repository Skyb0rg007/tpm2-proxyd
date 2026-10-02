// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! End-to-end tests: real client → tpm2-proxyd → real swtpm.
//!
//! Each test gets its own fresh swtpm + proxy (see [`common`]). They cover
//! commands that succeed at the TPM, commands the TPM itself rejects (errors
//! relayed verbatim), commands the proxy policy blocks, concurrent load
//! exercising the scheduler, and the real TCTI module as the client.

mod common;

use std::ffi::CString;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tss2_tcti_proxy::abi::{TSS2_RC_SUCCESS, TctiContext, TctiContextCommonV2};

use common::cap;

/// A representative spread of no-authorization commands should all succeed once
/// the proxy has started the TPM.
#[test]
fn no_auth_commands_succeed() {
    let env = common::TestEnv::start_allow_all();
    let mut client = env.connect();

    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("GetRandom", common::get_random(16)),
        ("GetTestResult", common::get_test_result()),
        ("ReadClock", common::read_clock()),
        ("StirRandom", common::stir_random()),
        ("IncrementalSelfTest", common::incremental_self_test()),
        ("PCR_Read(SHA256)", common::pcr_read_sha256(0)),
        (
            "GetCapability(properties)",
            common::get_capability(cap::TPM_PROPERTIES, 0x100, 8),
        ),
        (
            "GetCapability(algorithms)",
            common::get_capability(cap::ALGS, 0, 32),
        ),
        (
            "GetCapability(commands)",
            common::get_capability(cap::COMMANDS, 0x11f, 64),
        ),
        (
            "GetCapability(handles)",
            common::get_capability(cap::HANDLES, 0x8000_0000, 16),
        ),
        (
            "GetCapability(pcrs)",
            common::get_capability(cap::PCRS, 0, 1),
        ),
    ];

    for (name, command) in cases {
        let response = client
            .transact(&command)
            .unwrap_or_else(|| panic!("{name}: proxy closed the connection"));
        assert!(
            common::is_success(&response),
            "{name}: expected success, got rc={:#06x}",
            common::response_code(&response),
        );
    }
}

/// TPM-level errors are relayed back to the client byte-for-byte rather than
/// being swallowed by the proxy.
#[test]
fn relays_tpm_error_responses() {
    let env = common::TestEnv::start_allow_all();
    let mut client = env.connect();

    // The proxy already issued TPM2_Startup on connect, so a second one is
    // rejected by the TPM with a specific, known code.
    let response = client
        .transact(&common::startup_clear())
        .expect("second Startup should still get a response");
    assert_eq!(
        common::response_code(&response),
        common::TPM_RC_INITIALIZE,
        "second Startup should be rejected with TPM_RC_INITIALIZE",
    );

    // ReadPublic of an unloaded transient handle is a TPM error.
    let response = client
        .transact(&common::read_public(0x8000_0000))
        .expect("ReadPublic should still get a response");
    assert!(
        !common::is_success(&response),
        "ReadPublic of an unloaded handle should fail; rc={:#06x}",
        common::response_code(&response),
    );

    // The connection survives error responses and keeps working.
    let response = client
        .transact(&common::get_random(8))
        .expect("connection stayed open");
    assert!(common::is_success(&response));
}

/// Commands the policy does not allow are blocked by the proxy, which answers
/// them with an error instead of forwarding them to the TPM.
#[test]
fn policy_blocks_disallowed_commands() {
    let env = common::TestEnv::start(
        &common::policy_for_current_user("random"),
        &[("random", r#"{"commands": ["TPM_CC_GetRandom"]}"#)],
    );
    let mut client = env.connect();

    // The allowed command works.
    let response = client
        .transact(&common::get_random(8))
        .expect("GetRandom is allowed");
    assert!(common::is_success(&response));

    // A disallowed command is answered with an error.
    let response = client
        .transact(&common::get_capability(cap::TPM_PROPERTIES, 0x100, 1))
        .expect("the proxy answers a denied command");
    assert_eq!(
        common::response_code(&response),
        common::RC_COMMAND_DENIED,
        "GetCapability should be blocked by policy",
    );

    // The same connection can still run allowed commands afterwards.
    assert!(client.transact(&common::get_random(8)).is_some());
}

/// The `standard` profile shipped in `dist/profiles` loads, allows ordinary
/// commands on the caller's own objects, and refuses commands that change
/// shared TPM state or touch handles outside the caller's connection.
#[test]
fn shipped_standard_profile() {
    let standard = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../dist/profiles/standard.json"
    ))
    .expect("read the shipped standard profile");
    let env = common::TestEnv::start(
        &common::policy_for_current_user("standard"),
        &[("standard", &standard)],
    );
    let mut client = env.connect();

    let response = client.transact(&common::get_random(8)).unwrap();
    assert!(common::is_success(&response));
    let response = client
        .transact(&common::get_capability(cap::TPM_PROPERTIES, 0x100, 1))
        .unwrap();
    assert!(common::is_success(&response));

    // TPM2_Clear, authorized by the lockout hierarchy: not in the profile.
    let clear = common::clear();
    let response = client.transact(&clear).unwrap();
    assert_eq!(common::response_code(&response), common::RC_COMMAND_DENIED);

    // TPM2_ReadPublic of a persistent handle: an allowed command, but the
    // profile doesn't allow persistent handles.
    let response = client.transact(&common::read_public(0x8100_0001)).unwrap();
    assert_eq!(common::response_code(&response), common::RC_HANDLE_1_DENIED);

    // TPM2_ContextSave of a session: the kernel would stop tracking a saved
    // session, which then holds a TPM session slot until reset. Saving a
    // transient object is still allowed (this one doesn't exist, so the TPM
    // itself answers with an error).
    let response = client.transact(&common::context_save(0x0200_0000)).unwrap();
    assert_eq!(common::response_code(&response), common::RC_HANDLE_1_DENIED);
    let response = client.transact(&common::context_save(0x8000_0000)).unwrap();
    assert_ne!(common::response_code(&response), common::RC_HANDLE_1_DENIED);
}

/// Unrecognized command codes are rejected at the proxy's parse boundary and
/// never reach the TPM.
#[test]
fn rejects_unrecognized_command_codes() {
    let env = common::TestEnv::start_allow_all();
    let mut client = env.connect();

    let vendor = common::frame(common::NO_SESSIONS, 0x2000_0001, &[]);
    assert!(
        client.transact(&vendor).is_none(),
        "an unknown command code should be rejected",
    );
}

/// Many connections issuing commands at once are all served correctly. This
/// drives the broker, the connection registry, and the single serialized
/// upstream worker under concurrency — the scheduling path that prioritizes and
/// orders queued commands. (Per-connection priority *ordering* is covered by the
/// scheduler's unit tests, since the raw socket gives every connection from one
/// UID the same policy-capped priority.)
#[test]
fn parallel_commands_are_all_served() {
    const CONNECTIONS: usize = 12;
    const PER_CONNECTION: usize = 10;

    let env = common::TestEnv::start_allow_all();
    let completed = Arc::new(AtomicUsize::new(0));

    std::thread::scope(|scope| {
        for _ in 0..CONNECTIONS {
            let env = &env;
            let completed = Arc::clone(&completed);
            scope.spawn(move || {
                let mut client = env.connect();
                for _ in 0..PER_CONNECTION {
                    let response = client
                        .transact(&common::get_random(8))
                        .expect("connection stayed open under load");
                    assert!(
                        common::is_success(&response),
                        "GetRandom under load failed: rc={:#06x}",
                        common::response_code(&response),
                    );
                    completed.fetch_add(1, Ordering::Relaxed);
                }
            });
        }
    });

    assert_eq!(
        completed.load(Ordering::Relaxed),
        CONNECTIONS * PER_CONNECTION,
        "every concurrent command should complete successfully",
    );
}

/// The TCTI module that clients load talks to the daemon: its hello, with a
/// requested priority from the config string, is accepted and a command
/// round-trips through the proxy to the TPM. This is what keeps the module and
/// the daemon agreeing on the wire protocol.
#[test]
fn tcti_module_round_trips_through_the_proxy() {
    let env = common::TestEnv::start_allow_all();
    let info = unsafe { &*tss2_tcti_proxy::Tss2_Tcti_Info() };
    let config = CString::new(format!(
        "path={},priority=7",
        env.socket().to_str().unwrap()
    ))
    .unwrap();

    // Two-phase init, as tpm2-tss's loader does it: query the context size,
    // then initialize a buffer of that size.
    let mut size = 0;
    let rc = unsafe { (info.init)(std::ptr::null_mut(), &mut size, config.as_ptr()) };
    assert_eq!(rc, TSS2_RC_SUCCESS, "size query");
    let mut buffer = vec![0u64; size.div_ceil(8)];
    let ctx = buffer.as_mut_ptr().cast::<TctiContext>();
    let rc = unsafe { (info.init)(ctx, &mut size, config.as_ptr()) };
    assert_eq!(rc, TSS2_RC_SUCCESS, "init");

    let common = unsafe { &*ctx.cast::<TctiContextCommonV2>() };
    let command = common::get_random(8);
    let rc = unsafe { (common.v1.transmit)(ctx, command.len(), command.as_ptr()) };
    assert_eq!(rc, TSS2_RC_SUCCESS, "transmit");
    let mut response = [0u8; 4096];
    let mut size = response.len();
    let rc = unsafe { (common.v1.receive)(ctx, &mut size, response.as_mut_ptr(), 20_000) };
    assert_eq!(rc, TSS2_RC_SUCCESS, "receive");
    unsafe { (common.v1.finalize)(ctx) };

    let response = &response[..size];
    assert!(
        common::is_success(response),
        "GetRandom through the TCTI module failed: rc={:#06x}",
        common::response_code(response),
    );
}
