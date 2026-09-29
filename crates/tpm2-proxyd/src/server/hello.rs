// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! The hello: the first message on every client connection.
//!
//! Before its first TPM command, a client sends a [`Hello`] naming the protocol
//! version and the options it wants, and the server answers with a
//! [`HelloStatus`]. Only after an accepted hello does the connection carry the
//! self-framing TPM command/response stream. Fields are big-endian, like TPM
//! fields:
//!
//! ```text
//! client → server:  magic "TPXH" (4) | version u16 | flags u16
//! server → client:  magic "TPXH" (4) | version u16 | status u16
//! ```
//!
//! A connection that doesn't start with the magic isn't speaking this
//! protocol, so the server closes it without replying. Every other refusal gets
//! a reply, then a close. Unknown flags are refused rather than ignored, so a
//! client never silently loses an option it depends on.
//!
//! The TCTI module (`crates/tcti`) implements the client side and must stay in
//! sync.

use std::io;

/// Magic that opens both the hello and its reply.
pub const MAGIC: [u8; 4] = *b"TPXH";
/// Protocol version this server speaks.
pub const VERSION: u16 = 1;
/// Size of the hello and of its reply.
pub const SIZE: usize = 8;
/// Flags this server understands. None are defined yet; auto-encryption
/// (`docs/auto-encrypt.md`) is expected to be the first.
const KNOWN_FLAGS: u16 = 0;

/// A client's hello.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hello {
    /// Protocol version the client speaks.
    pub version: u16,
    /// Options the client requests.
    pub flags: u16,
}

impl Hello {
    /// Parse a hello, failing if it doesn't start with [`MAGIC`].
    pub fn parse(bytes: [u8; SIZE]) -> io::Result<Self> {
        if bytes[..4] != MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "connection did not start with a hello",
            ));
        }
        Ok(Self {
            version: u16::from_be_bytes([bytes[4], bytes[5]]),
            flags: u16::from_be_bytes([bytes[6], bytes[7]]),
        })
    }

    /// Check that this server supports the requested version and flags.
    pub fn check(&self) -> Result<(), HelloStatus> {
        if self.version != VERSION || self.flags & !KNOWN_FLAGS != 0 {
            Err(HelloStatus::Unsupported)
        } else {
            Ok(())
        }
    }
}

/// The server's answer to a hello.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum HelloStatus {
    /// The connection may send TPM commands.
    Accepted = 0,
    /// Unknown protocol version or flag.
    Unsupported = 1,
    /// The server's connection limit is reached.
    Busy = 2,
}

impl HelloStatus {
    /// Encode the reply carrying this status.
    pub fn reply(self) -> [u8; SIZE] {
        let mut bytes = [0; SIZE];
        bytes[..4].copy_from_slice(&MAGIC);
        bytes[4..6].copy_from_slice(&VERSION.to_be_bytes());
        bytes[6..].copy_from_slice(&(self as u16).to_be_bytes());
        bytes
    }
}
