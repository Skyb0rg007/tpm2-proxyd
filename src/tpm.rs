// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: BSD-2-Clause

//! TPM command and response framing.
//!
//! TPM packets are self-framing. Both commands and responses begin with a
//! 10-byte, big-endian header containing a tag, total packet size, and a
//! command/response code. This module validates that header before a packet is
//! admitted to the scheduler or returned to a client.

#![allow(dead_code)] // Wired into main once daemon construction is implemented.

pub mod linux;

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt};
use tpm2_client::{CmdHeader, RespHeader};
use tpm2_rs_base::{
    TpmiStCommandTag,
    commands::TpmCommand,
    constants::TpmCc,
    marshal::{Marshalable, UnmarshalBuf},
};

/// Size of a TPM command or response header.
pub const HEADER_SIZE: usize = 10;

/// Conservative default bound for packets accepted from either direction.
pub const DEFAULT_MAX_PACKET_SIZE: usize = 1024 * 1024;

/// Validated TPM command bytes and their parsed command code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Command {
    code: TpmCc,
    bytes: Vec<u8>,
}

impl Command {
    /// Validate a complete TPM command.
    pub fn parse(bytes: Vec<u8>, max_size: usize) -> Result<Self, ParseError> {
        let header = parse_command_header(&bytes, max_size)?;
        if header.size as usize != bytes.len() {
            return Err(ParseError::SizeMismatch {
                declared: header.size,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            code: header.code,
            bytes,
        })
    }

    /// Parsed TPM command code.
    pub fn code(&self) -> TpmCc {
        self.code
    }

    /// Return whether this packet carries command type `C`.
    pub fn is<C: TpmCommand>(&self) -> bool {
        self.code == C::CMD_CODE
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
    /// Validate a complete TPM response.
    pub fn parse(bytes: Vec<u8>, max_size: usize) -> Result<Self, ParseError> {
        let size = parse_packet_size(&bytes, max_size)?;
        if size != bytes.len() {
            return Err(ParseError::SizeMismatch {
                declared: size as u32,
                actual: bytes.len(),
            });
        }
        Ok(Self(bytes))
    }

    /// Complete encoded response.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consume the response and return its encoded bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// Read the packet size declared by a TPM header.
pub fn packet_size_from_header(header: &[u8], max_size: usize) -> Result<usize, ParseError> {
    parse_packet_header(header, max_size).map(|header| header.size as usize)
}

/// TPM packet validation failure.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParseError {
    /// Packet is shorter than the fixed TPM header.
    #[error("TPM packet is shorter than the {HEADER_SIZE}-byte header")]
    ShortHeader,
    /// Command tag is not valid for a TPM 2.0 command.
    #[error("invalid TPM command tag {0:#06x}")]
    InvalidCommandTag(u16),
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
}

/// Read and validate one command from an async byte stream.
///
/// `Ok(None)` is returned only when the stream reaches EOF between commands.
pub async fn read_command(
    stream: &mut (impl AsyncRead + Unpin),
    max_size: usize,
) -> io::Result<Option<Command>> {
    let mut header = [0u8; HEADER_SIZE];
    let read = stream.read(&mut header[..1]).await?;
    if read == 0 {
        return Ok(None);
    }
    stream.read_exact(&mut header[1..]).await?;

    let parsed = parse_command_header(&header, max_size).map_err(invalid_data)?;
    let mut bytes = vec![0u8; parsed.size as usize];
    bytes[..HEADER_SIZE].copy_from_slice(&header);
    stream.read_exact(&mut bytes[HEADER_SIZE..]).await?;

    Ok(Some(Command {
        code: parsed.code,
        bytes,
    }))
}

fn parse_command_header(bytes: &[u8], max_size: usize) -> Result<CmdHeader, ParseError> {
    if bytes.len() < HEADER_SIZE {
        return Err(ParseError::ShortHeader);
    }
    let mut buffer = UnmarshalBuf::new(bytes);
    let header = CmdHeader::try_unmarshal(&mut buffer).map_err(|_| ParseError::ShortHeader)?;
    if !matches!(
        header.tag,
        TpmiStCommandTag::NoSessions | TpmiStCommandTag::Sessions
    ) {
        return Err(ParseError::InvalidCommandTag(header.tag.0));
    }
    validate_packet_size(header.size, max_size)?;
    Ok(header)
}

fn parse_packet_size(bytes: &[u8], max_size: usize) -> Result<usize, ParseError> {
    parse_packet_header(bytes, max_size).map(|header| header.size as usize)
}

fn parse_packet_header(bytes: &[u8], max_size: usize) -> Result<RespHeader, ParseError> {
    if bytes.len() < HEADER_SIZE {
        return Err(ParseError::ShortHeader);
    }
    let mut buffer = UnmarshalBuf::new(bytes);
    let header = RespHeader::try_unmarshal(&mut buffer).map_err(|_| ParseError::ShortHeader)?;
    validate_packet_size(header.size, max_size)?;
    Ok(header)
}

fn validate_packet_size(size: u32, max_size: usize) -> Result<(), ParseError> {
    if size < HEADER_SIZE as u32 {
        return Err(ParseError::InvalidSize(size));
    }
    if size as usize > max_size {
        return Err(ParseError::TooLarge {
            size: size as usize,
            max: max_size,
        });
    }
    Ok(())
}

fn invalid_data(error: ParseError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpm2_rs_base::constants::TpmSt;

    fn command(code: u32, body: &[u8]) -> Vec<u8> {
        let size = (HEADER_SIZE + body.len()) as u32;
        let mut bytes = Vec::from(TpmSt::NoSessions.0.to_be_bytes());
        bytes.extend_from_slice(&size.to_be_bytes());
        bytes.extend_from_slice(&code.to_be_bytes());
        bytes.extend_from_slice(body);
        bytes
    }

    #[test]
    fn parses_command_header() {
        let command = Command::parse(command(0x17b, &[0, 8]), 4096).unwrap();
        assert_eq!(command.code(), TpmCc::GetRandom);
        assert!(command.is::<tpm2_rs_base::commands::GetRandomCmd>());
    }

    #[test]
    fn rejects_invalid_tag_and_size() {
        let mut invalid_tag = command(0x17b, &[]);
        invalid_tag[..2].copy_from_slice(&0x1234u16.to_be_bytes());
        assert_eq!(
            Command::parse(invalid_tag, 4096),
            Err(ParseError::InvalidCommandTag(0x1234))
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

    #[tokio::test]
    async fn reads_back_to_back_commands() {
        let first = command(0x17b, &[0, 8]);
        let second = command(0x17a, &[]);
        let mut input = Vec::new();
        input.extend_from_slice(&first);
        input.extend_from_slice(&second);
        let mut input = &input[..];

        assert_eq!(
            read_command(&mut input, 4096)
                .await
                .unwrap()
                .unwrap()
                .as_bytes(),
            first
        );
        assert_eq!(
            read_command(&mut input, 4096)
                .await
                .unwrap()
                .unwrap()
                .as_bytes(),
            second
        );
        assert!(read_command(&mut input, 4096).await.unwrap().is_none());
    }
}
