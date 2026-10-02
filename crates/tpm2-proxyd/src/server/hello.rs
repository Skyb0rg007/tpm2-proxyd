// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! The hello: the first message on every client connection.
//!
//! Before its first TPM command, a client sends a [`Hello`] naming the protocol
//! version, the options it wants, and the scheduling priority it requests. The
//! server answers with a [`HelloStatus`] and the priority it granted: the
//! request capped by the policy for the peer, fixed for the connection's
//! lifetime. Only after an accepted hello does the connection carry the
//! self-framing TPM command/response stream. Fields are big-endian, like TPM
//! fields:
//!
//! ```text
//! client → server:  magic "TPXH" (4) | version u16 | flags u16  | priority i32
//! server → client:  magic "TPXH" (4) | version u16 | status u16 | priority i32
//! ```
//!
//! Higher priorities run first. A client that doesn't care asks for
//! `i32::MAX`, the highest the policy allows it. A refusal's reply carries
//! priority 0.
//!
//! A connection that doesn't start with the magic isn't speaking this
//! protocol, so the server closes it without replying. Every other refusal gets
//! a reply, then a close. Unknown flags are refused rather than ignored, so a
//! client never silently loses an option it depends on.
//!
//! The TCTI module (`crates/tcti`) implements the client side and must stay in
//! sync.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::scheduler::Priority;

/// Magic that opens both the hello and its reply.
const MAGIC: [u8; 4] = *b"TPXH";
/// Protocol version this server speaks.
const VERSION: u16 = 1;
/// Size of the hello and of its reply.
const SIZE: usize = 12;
/// Flags this server understands. None are defined yet.
const KNOWN_FLAGS: u16 = 0;

/// A client's hello.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hello {
    /// Protocol version the client speaks.
    pub version: u16,
    /// Options the client requests.
    pub flags: u16,
    /// Scheduling priority the client requests, before the policy cap.
    pub priority: Priority,
}

impl Hello {
    /// Read a hello from `stream`, failing if it doesn't start with [`MAGIC`].
    pub async fn read(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<Self> {
        let mut bytes = [0; SIZE];
        stream.read_exact(&mut bytes).await?;
        if bytes[..4] != MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "connection did not start with a hello",
            ));
        }
        Ok(Self {
            version: u16::from_be_bytes([bytes[4], bytes[5]]),
            flags: u16::from_be_bytes([bytes[6], bytes[7]]),
            priority: Priority(i32::from_be_bytes([
                bytes[8], bytes[9], bytes[10], bytes[11],
            ])),
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
    /// Send the reply carrying this status and the granted `priority`.
    pub async fn reply(
        self,
        stream: &mut (impl AsyncWrite + Unpin),
        priority: Priority,
    ) -> io::Result<()> {
        let mut bytes = [0; SIZE];
        bytes[..4].copy_from_slice(&MAGIC);
        bytes[4..6].copy_from_slice(&VERSION.to_be_bytes());
        bytes[6..8].copy_from_slice(&(self as u16).to_be_bytes());
        bytes[8..].copy_from_slice(&priority.0.to_be_bytes());
        stream.write_all(&bytes).await?;
        stream.flush().await
    }
}
