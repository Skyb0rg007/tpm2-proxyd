// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! TPM command and response framing.
//!
//! TPM packets are self-framing. Both commands and responses begin with a
//! 10-byte, big-endian header containing a tag, total packet size, and a
//! command/response code. This module validates that header before a packet is
//! admitted to the scheduler or returned to a client.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt};
use tpm2_protocol::{
    TpmError,
    data::{TpmCc, TpmRcBase, TpmSt},
    frame::TpmCommand as WireCommand,
};

/// Size of a TPM command or response header.
pub const HEADER_SIZE: usize = 10;

/// Conservative default bound for packets accepted from either direction.
pub const DEFAULT_MAX_PACKET_SIZE: usize = 1024 * 1024;

/// A response code the proxy answers with itself rather than forwarding the
/// command: the TPM-format code `base` in the resource-manager layer
/// (`TSS2_RESMGR_RC_LAYER`), which tpm2-tss decodes as a TPM error the
/// resource manager reported.
pub const fn resmgr_rc(base: TpmRcBase) -> u32 {
    (11 << 16) | base.value()
}

/// Validated TPM command bytes, their parsed command code, and the handles in
/// their handle area.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Command {
    code: TpmCc,
    handles: Vec<u32>,
    bytes: Vec<u8>,
}

impl Command {
    /// Validate a complete TPM command.
    ///
    /// The proxy is a firewall in front of the TPM: it only admits commands it
    /// can decode and inspect. `WireCommand::cast` resolves the command code
    /// against the `tpm2-protocol` dispatch table, so any unrecognized code —
    /// including vendor-specific command codes — is rejected here, before policy,
    /// scheduling, or forwarding. This default-deny stance over the command
    /// vocabulary is intentional; see `docs/design.md` ("Recognized commands
    /// only").
    pub fn parse(bytes: Vec<u8>, max_size: usize) -> Result<Self, ParseError> {
        validate_frame(&bytes, max_size)?;
        let frame = WireCommand::cast(&bytes)?;
        let code = frame.cc()?;
        let handles = frame
            .handles()?
            .as_chunks::<4>()
            .0
            .iter()
            .map(|&handle| u32::from_be_bytes(handle))
            .collect();
        Ok(Self {
            code,
            handles,
            bytes,
        })
    }

    /// Parsed TPM command code.
    pub fn code(&self) -> TpmCc {
        self.code
    }

    /// Handles in the command's handle area, in order. Session handles in the
    /// authorization area aren't included.
    pub fn handles(&self) -> &[u32] {
        &self.handles
    }

    /// The four bytes after the handle area, as a big-endian `u32`.
    fn after_handles(&self) -> Option<u32> {
        let start = HEADER_SIZE + 4 * self.handles.len();
        let bytes = self.bytes.get(start..start + 4)?;
        Some(u32::from_be_bytes(bytes.try_into().expect("four bytes")))
    }

    /// The handle `TPM2_FlushContext` would flush (its first parameter), or
    /// `None` for any other command.
    pub fn flush_handle(&self) -> Option<u32> {
        (self.code == TpmCc::FlushContext)
            .then(|| self.after_handles())
            .flatten()
    }

    /// The sessions in the authorization area, each with whether the command
    /// keeps it open (`continueSession`). Empty for a command without one.
    pub fn sessions(&self) -> Vec<(u32, bool)> {
        const CONTINUE_SESSION: u8 = 0x01;
        let mut sessions = Vec::new();
        if self.bytes[..2] != TpmSt::Sessions.value().to_be_bytes() {
            return sessions;
        }
        let Some(size) = self.after_handles() else {
            return sessions;
        };
        let start = HEADER_SIZE + 4 * self.handles.len() + 4;
        let mut rest = self
            .bytes
            .get(start..start + size as usize)
            .unwrap_or_default();
        // TPMS_AUTH_COMMAND: handle, nonce (TPM2B), attributes, hmac (TPM2B).
        let sized = |bytes: &[u8]| -> Option<usize> {
            let size = u16::from_be_bytes(bytes.get(..2)?.try_into().ok()?) as usize;
            (bytes.len() >= 2 + size).then_some(2 + size)
        };
        while rest.len() >= 4 {
            let handle = u32::from_be_bytes(rest[..4].try_into().expect("four bytes"));
            let Some(nonce) = sized(&rest[4..]) else {
                break;
            };
            let Some(&attributes) = rest.get(4 + nonce) else {
                break;
            };
            let Some(hmac) = sized(&rest[5 + nonce..]) else {
                break;
            };
            sessions.push((handle, attributes & CONTINUE_SESSION != 0));
            rest = &rest[5 + nonce + hmac..];
        }
        sessions
    }

    /// Complete encoded command.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Validated TPM response bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response(Vec<u8>);

impl Response {
    /// A header-only response carrying `code`, for errors the proxy reports
    /// itself instead of forwarding the command.
    pub fn error(code: u32) -> Self {
        let mut bytes = Vec::with_capacity(HEADER_SIZE);
        bytes.extend_from_slice(&TpmSt::NoSessions.value().to_be_bytes());
        bytes.extend_from_slice(&(HEADER_SIZE as u32).to_be_bytes());
        bytes.extend_from_slice(&code.to_be_bytes());
        Self(bytes)
    }

    /// Validate a complete TPM response's framing: its size and tag.
    ///
    /// The response code isn't checked against the codes the TCG defines. The
    /// kernel resource manager answers with its own layered codes (such as
    /// `TPM_RC_COMMAND_CODE` in the resource-manager layer for a command the
    /// TPM lacks), and TPMs may return vendor codes; either way the client
    /// gets the response unchanged.
    pub fn parse(bytes: Vec<u8>, max_size: usize) -> Result<Self, ParseError> {
        validate_frame(&bytes, max_size)?;
        Ok(Self(bytes))
    }

    /// The first handle in a successful response's handle area, which is
    /// where commands such as `TPM2_StartAuthSession` and `TPM2_ContextLoad`
    /// return the handle they created.
    pub fn first_handle(&self) -> Option<u32> {
        let bytes = self.0.get(HEADER_SIZE..HEADER_SIZE + 4)?;
        Some(u32::from_be_bytes(bytes.try_into().expect("four bytes")))
    }

    /// The response code from the header.
    pub fn code(&self) -> u32 {
        u32::from_be_bytes(self.0[6..10].try_into().expect("header is validated"))
    }

    /// Complete encoded response.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// TPM packet validation failure.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParseError {
    /// Packet is shorter than the fixed TPM header.
    #[error("TPM packet is shorter than the {HEADER_SIZE}-byte header")]
    ShortHeader,
    /// The tag is neither `TPM_ST_NO_SESSIONS` nor `TPM_ST_SESSIONS`.
    #[error("invalid TPM tag {0:#06x}")]
    InvalidTag(u16),
    /// Header declares a packet shorter than the header itself.
    #[error("TPM packet declares invalid size {0}")]
    InvalidSize(u32),
    /// Packet exceeds the configured input bound.
    #[error("TPM packet size {size} exceeds maximum {max}")]
    TooLarge {
        /// Declared packet size.
        size: usize,
        /// Configured maximum.
        max: usize,
    },
    /// Complete packet length differs from the header.
    #[error("TPM packet declares size {declared}, but contains {actual} bytes")]
    SizeMismatch {
        /// Size from the TPM header.
        declared: u32,
        /// Actual buffer length.
        actual: usize,
    },
    /// TPM protocol validation failed.
    #[error("malformed TPM packet: {0}")]
    Protocol(#[from] TpmError),
}

/// Read one self-framed TPM packet (a command or a response) from `stream`,
/// checking only its declared size.
///
/// `Ok(None)` is returned only when the stream reaches EOF between packets.
pub async fn read_frame(
    stream: &mut (impl AsyncRead + Unpin + ?Sized),
    max_size: usize,
) -> io::Result<Option<Vec<u8>>> {
    let mut header = [0u8; HEADER_SIZE];
    if stream.read(&mut header[..1]).await? == 0 {
        return Ok(None);
    }
    stream.read_exact(&mut header[1..]).await?;

    let size = declared_size(&header, max_size).map_err(invalid_data)?;
    let mut bytes = vec![0u8; size as usize];
    bytes[..HEADER_SIZE].copy_from_slice(&header);
    stream.read_exact(&mut bytes[HEADER_SIZE..]).await?;
    Ok(Some(bytes))
}

/// Read and validate one command from an async byte stream.
///
/// `Ok(None)` is returned only when the stream reaches EOF between commands.
pub async fn read_command(
    stream: &mut (impl AsyncRead + Unpin),
    max_size: usize,
) -> io::Result<Option<Command>> {
    let Some(bytes) = read_frame(stream, max_size).await? else {
        return Ok(None);
    };
    Command::parse(bytes, max_size)
        .map(Some)
        .map_err(invalid_data)
}

/// The size a TPM header declares, if it's within bounds.
fn declared_size(bytes: &[u8], max_size: usize) -> Result<u32, ParseError> {
    if bytes.len() < HEADER_SIZE {
        return Err(ParseError::ShortHeader);
    }
    let size = u32::from_be_bytes(bytes[2..6].try_into().expect("slice length checked"));
    if size < HEADER_SIZE as u32 {
        return Err(ParseError::InvalidSize(size));
    }
    if size as usize > max_size {
        return Err(ParseError::TooLarge {
            size: size as usize,
            max: max_size,
        });
    }
    Ok(size)
}

/// Check a complete packet's size and tag.
fn validate_frame(bytes: &[u8], max_size: usize) -> Result<(), ParseError> {
    let size = declared_size(bytes, max_size)?;
    if size as usize != bytes.len() {
        return Err(ParseError::SizeMismatch {
            declared: size,
            actual: bytes.len(),
        });
    }
    let tag = u16::from_be_bytes(bytes[..2].try_into().expect("slice length checked"));
    match TpmSt::try_from(tag) {
        Ok(TpmSt::NoSessions | TpmSt::Sessions) => Ok(()),
        _ => Err(ParseError::InvalidTag(tag)),
    }
}

fn invalid_data(error: ParseError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{command_bytes, frame};

    fn command(code: u32, body: &[u8]) -> Vec<u8> {
        frame(TpmSt::NoSessions.value(), code, body)
    }

    #[test]
    fn parses_the_command_code_and_handle_area() {
        // TPM2_ReadPublic takes one handle.
        let read_public = Command::parse(command_bytes(0x173, &[0x8000_0001]), 4096).unwrap();
        assert_eq!(read_public.code(), TpmCc::ReadPublic);
        assert_eq!(read_public.handles(), [0x8000_0001]);

        let get_random = Command::parse(command(0x17b, &[0, 8]), 4096).unwrap();
        assert_eq!(get_random.code(), TpmCc::GetRandom);
        assert!(get_random.handles().is_empty());
    }

    #[test]
    fn rejects_a_truncated_handle_area() {
        assert!(matches!(
            Command::parse(command(0x173, &[0x80, 0]), 4096),
            Err(ParseError::Protocol(_))
        ));
    }

    #[test]
    fn rejects_invalid_tag_and_size() {
        let mut invalid_tag = command(0x17b, &[]);
        invalid_tag[..2].copy_from_slice(&0x1234u16.to_be_bytes());
        assert_eq!(
            Command::parse(invalid_tag, 4096),
            Err(ParseError::InvalidTag(0x1234))
        );

        let mut wrong_size = command(0x17b, &[]);
        wrong_size[2..6].copy_from_slice(&11u32.to_be_bytes());
        assert_eq!(
            Command::parse(wrong_size, 4096),
            Err(ParseError::SizeMismatch {
                declared: 11,
                actual: 10,
            })
        );
    }

    #[test]
    fn finds_the_handle_flush_context_flushes() {
        let flush = Command::parse(command(0x165, &0x0200_0001u32.to_be_bytes()), 4096).unwrap();
        assert_eq!(flush.flush_handle(), Some(0x0200_0001));
        let other = Command::parse(command(0x17b, &8u16.to_be_bytes()), 4096).unwrap();
        assert_eq!(other.flush_handle(), None);
    }

    #[test]
    fn lists_the_sessions_in_the_authorization_area() {
        // TPM2_Unseal of 0x80000001 with an HMAC session that ends with the
        // command (attributes 0) and a password session that continues.
        let mut body = Vec::from(0x8000_0001u32.to_be_bytes());
        let mut auth = Vec::new();
        auth.extend_from_slice(&0x0200_0000u32.to_be_bytes());
        auth.extend_from_slice(&[0, 2, 0xaa, 0xbb, 0x00, 0, 1, 0xcc]);
        auth.extend_from_slice(&0x4000_0009u32.to_be_bytes());
        auth.extend_from_slice(&[0, 0, 0x01, 0, 0]);
        body.extend_from_slice(&(auth.len() as u32).to_be_bytes());
        body.extend_from_slice(&auth);
        let bytes = frame(TpmSt::Sessions.value(), 0x15e, &body);
        let unseal = Command::parse(bytes, 4096).unwrap();
        assert_eq!(
            unseal.sessions(),
            [(0x0200_0000, false), (0x4000_0009, true)]
        );
    }

    #[test]
    fn responses_keep_codes_the_tcg_doesnt_define() {
        // TPM_RC_COMMAND_CODE in the resource-manager layer, as the kernel
        // answers for a command the TPM lacks, and a vendor-defined code.
        for code in [0x000b_0143, 0x0000_0520] {
            let bytes = Response::error(code).as_bytes().to_vec();
            assert_eq!(Response::parse(bytes, 4096).unwrap().code(), code);
        }
    }

    #[test]
    fn rejects_responses_with_an_invalid_tag() {
        let mut bytes = Response::error(0).as_bytes().to_vec();
        bytes[..2].copy_from_slice(&0x1234u16.to_be_bytes());
        assert_eq!(
            Response::parse(bytes, 4096),
            Err(ParseError::InvalidTag(0x1234))
        );
    }

    #[tokio::test]
    async fn reads_back_to_back_commands() {
        let first = command(0x17b, &[0, 8]);
        let second = command(0x17a, &[]);
        let input = [first.clone(), second.clone()].concat();
        let mut input = &input[..];

        for expected in [first, second] {
            let command = read_command(&mut input, 4096).await.unwrap().unwrap();
            assert_eq!(command.as_bytes(), expected);
        }
        assert!(read_command(&mut input, 4096).await.unwrap().is_none());
    }
}
