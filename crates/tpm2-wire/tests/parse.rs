// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

use tpm2_wire::{Command, CommandBody, Error, Handle, SessionAttributes, TpmCc, TpmSt};

fn header(tag: u16, size: u32, code: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(10);
    v.extend_from_slice(&tag.to_be_bytes());
    v.extend_from_slice(&size.to_be_bytes());
    v.extend_from_slice(&code.to_be_bytes());
    v
}

fn no_sessions_raw(code: u32, handles: &[u32], parameters: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    for h in handles {
        body.extend_from_slice(&h.to_be_bytes());
    }
    body.extend_from_slice(parameters);
    let size = 10 + body.len() as u32;
    let mut bytes = header(TpmSt::NoSessions.value(), size, code);
    bytes.extend_from_slice(&body);
    bytes
}

fn no_sessions(code: TpmCc, handles: &[u32], parameters: &[u8]) -> Vec<u8> {
    no_sessions_raw(code.value(), handles, parameters)
}

fn with_session(code: TpmCc, handles: &[u32], sessions: &[u8], parameters: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    for h in handles {
        body.extend_from_slice(&h.to_be_bytes());
    }
    body.extend_from_slice(&(sessions.len() as u32).to_be_bytes());
    body.extend_from_slice(sessions);
    body.extend_from_slice(parameters);
    let size = 10 + body.len() as u32;
    let mut bytes = header(TpmSt::Sessions.value(), size, code.value());
    bytes.extend_from_slice(&body);
    bytes
}

/// A `TPM_RS_PW` (password) authorization session: no real nonce or HMAC.
fn password_session() -> Vec<u8> {
    let mut s = Vec::new();
    s.extend_from_slice(&0x4000_0009u32.to_be_bytes());
    s.extend_from_slice(&0u16.to_be_bytes()); // nonce size
    s.push(0); // attributes
    s.extend_from_slice(&0u16.to_be_bytes()); // hmac size
    s
}

#[test]
fn parses_get_random_with_no_handles() {
    let bytes = no_sessions(TpmCc::GetRandom, &[], &32u16.to_be_bytes());
    let cmd = Command::parse(&bytes).unwrap();

    assert_eq!(cmd.tag(), TpmSt::NoSessions);
    assert_eq!(cmd.code(), TpmCc::GetRandom);
    assert!(cmd.handles().is_empty());
    assert!(cmd.auth_area().is_empty());

    match cmd.body().unwrap() {
        CommandBody::GetRandom(get_random) => assert_eq!(get_random.bytes_requested, 32),
        other => panic!("unexpected body: {other:?}"),
    }
}

#[test]
fn parses_evict_control_with_a_password_session() {
    let session = password_session();
    let bytes = with_session(
        TpmCc::EvictControl,
        &[0x4000_0001, 0x8100_0000],
        &session,
        &0x8100_0001u32.to_be_bytes(),
    );
    let cmd = Command::parse(&bytes).unwrap();
    assert_eq!(cmd.tag(), TpmSt::Sessions);

    let sessions: Vec<_> = cmd.auth_area().iter().collect::<Result<_, _>>().unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].session_handle, Handle(0x4000_0009));
    assert!(sessions[0].nonce.is_empty());
    assert!(
        !sessions[0]
            .attributes
            .contains(SessionAttributes::CONTINUE_SESSION)
    );

    match cmd.body().unwrap() {
        CommandBody::EvictControl(evict) => {
            assert_eq!(evict.auth, Handle(0x4000_0001));
            assert_eq!(evict.object_handle, Handle(0x8100_0000));
            assert_eq!(evict.persistent_handle, Handle(0x8100_0001));
        }
        other => panic!("unexpected body: {other:?}"),
    }
}

#[test]
fn parses_nv_write() {
    let data = [0xDEu8, 0xAD, 0xBE, 0xEF];
    let mut parameters = Vec::new();
    parameters.extend_from_slice(&(data.len() as u16).to_be_bytes());
    parameters.extend_from_slice(&data);
    parameters.extend_from_slice(&16u16.to_be_bytes()); // offset

    let bytes = no_sessions(TpmCc::NvWrite, &[0x4000_0001, 0x0150_0001], &parameters);
    let cmd = Command::parse(&bytes).unwrap();

    match cmd.body().unwrap() {
        CommandBody::NvWrite(write) => {
            assert_eq!(write.auth_handle, Handle(0x4000_0001));
            assert_eq!(write.nv_index, Handle(0x0150_0001));
            assert_eq!(write.data, &data);
            assert_eq!(write.offset, 16);
        }
        other => panic!("unexpected body: {other:?}"),
    }
}

#[test]
fn parses_context_load() {
    let mut parameters = Vec::new();
    parameters.extend_from_slice(&7u64.to_be_bytes()); // sequence
    parameters.extend_from_slice(&0x8000_0001u32.to_be_bytes()); // savedHandle
    parameters.extend_from_slice(&0x4000_0001u32.to_be_bytes()); // hierarchy
    let blob = [1u8, 2, 3, 4, 5];
    parameters.extend_from_slice(&(blob.len() as u16).to_be_bytes());
    parameters.extend_from_slice(&blob);

    let bytes = no_sessions(TpmCc::ContextLoad, &[], &parameters);
    let cmd = Command::parse(&bytes).unwrap();

    match cmd.body().unwrap() {
        CommandBody::ContextLoad(load) => {
            assert_eq!(load.context.sequence, 7);
            assert_eq!(load.context.saved_handle, Handle(0x8000_0001));
            assert_eq!(load.context.hierarchy, Handle(0x4000_0001));
            assert_eq!(load.context.context_blob, &blob);
        }
        other => panic!("unexpected body: {other:?}"),
    }
}

#[test]
fn unrecognized_but_valid_commands_still_split_handles_generically() {
    // Certify has no typed variant, but the generic parser must still split
    // its 2 handles correctly using only TpmCc::handle_count.
    let bytes = no_sessions(TpmCc::Certify, &[0x8000_0001, 0x8000_0002], &[0xAA, 0xBB]);
    let cmd = Command::parse(&bytes).unwrap();
    assert_eq!(cmd.handles().len(), 8);

    match cmd.body().unwrap() {
        CommandBody::Other {
            code,
            handles,
            parameters,
        } => {
            assert_eq!(code, TpmCc::Certify);
            assert_eq!(handles.len(), 8);
            assert_eq!(parameters, &[0xAA, 0xBB]);
        }
        other => panic!("unexpected body: {other:?}"),
    }
}

#[test]
fn parses_start_auth_session_recovering_auth_hash_around_opaque_symmetric() {
    let mut parameters = Vec::new();
    let nonce = [0xAAu8; 16];
    parameters.extend_from_slice(&(nonce.len() as u16).to_be_bytes());
    parameters.extend_from_slice(&nonce);
    parameters.extend_from_slice(&0u16.to_be_bytes()); // encryptedSalt: empty
    parameters.push(0x01); // sessionType: Policy
    parameters.extend_from_slice(&0x0010u16.to_be_bytes()); // symmetric.algorithm = TPM_ALG_NULL
    parameters.extend_from_slice(&0x000Bu16.to_be_bytes()); // authHash = TPM_ALG_SHA256

    let bytes = with_session(
        TpmCc::StartAuthSession,
        &[0x4000_0007, 0x4000_0007],
        &password_session(),
        &parameters,
    );
    let cmd = Command::parse(&bytes).unwrap();

    match cmd.body().unwrap() {
        CommandBody::StartAuthSession(session) => {
            assert_eq!(session.tpm_key, Handle(0x4000_0007));
            assert_eq!(session.bind, Handle(0x4000_0007));
            assert_eq!(session.nonce_caller, &nonce);
            assert!(session.encrypted_salt.is_empty());
            assert_eq!(
                session.session_type,
                tpm2_wire::commands::SessionType::Policy
            );
            assert_eq!(session.symmetric, &0x0010u16.to_be_bytes());
            assert_eq!(session.auth_hash, 0x000B);
        }
        other => panic!("unexpected body: {other:?}"),
    }
}

#[test]
fn iterates_multiple_auth_sessions() {
    let mut sessions = password_session();
    sessions.extend_from_slice(&password_session());

    let bytes = with_session(
        TpmCc::FlushContext,
        &[],
        &sessions,
        &0x8000_0001u32.to_be_bytes(),
    );
    let cmd = Command::parse(&bytes).unwrap();

    let parsed: Vec<_> = cmd.auth_area().iter().collect::<Result<_, _>>().unwrap();
    assert_eq!(parsed.len(), 2);
    assert!(
        parsed
            .iter()
            .all(|s| s.session_handle == Handle(0x4000_0009))
    );
}

#[test]
fn tpm_cc_all_is_sorted_and_round_trips_through_try_from() {
    // Regression test for the sortedness invariant try_from's binary search relies on.
    assert!(
        TpmCc::ALL
            .windows(2)
            .all(|pair| pair[0].value() < pair[1].value())
    );

    for &cc in TpmCc::ALL {
        assert_eq!(TpmCc::try_from(cc.value()), Ok(cc));
    }
}

#[test]
fn rejects_unknown_command_code() {
    let bytes = no_sessions_raw(0xDEAD_BEEF, &[], &[]);
    assert!(matches!(
        Command::parse(&bytes),
        Err(Error::UnknownCommandCode(0xDEAD_BEEF))
    ));
}

#[test]
fn rejects_size_mismatch() {
    let mut bytes = no_sessions(TpmCc::GetTestResult, &[], &[]);
    bytes[2..6].copy_from_slice(&99u32.to_be_bytes()); // corrupt the declared size field
    assert!(matches!(
        Command::parse(&bytes),
        Err(Error::SizeMismatch { .. })
    ));
}

#[test]
fn rejects_invalid_tag() {
    let mut bytes = no_sessions(TpmCc::GetTestResult, &[], &[]);
    bytes[0..2].copy_from_slice(&0x1234u16.to_be_bytes());
    assert!(matches!(
        Command::parse(&bytes),
        Err(Error::InvalidTag(0x1234))
    ));
}

#[test]
fn rejects_short_buffer() {
    assert!(matches!(
        Command::parse(&[0x80, 0x01, 0x00]),
        Err(Error::UnexpectedEof { .. })
    ));
}
