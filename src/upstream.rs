// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: BSD-2-Clause

//! Serialized upstream TPM transport.
//!
//! The scheduler owns one [`Upstream`] and invokes it for exactly one command
//! at a time. No timeout or cancellation is applied: once a transaction starts,
//! it runs until the upstream TCTI returns.

#![allow(dead_code)] // Wired into main once daemon construction is implemented.

use std::error::Error;

use async_trait::async_trait;

use crate::tpm::{Command, Response};

/// Error returned when an upstream transaction cannot produce a valid response.
#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    /// The TCTI transaction failed.
    #[error("upstream TCTI transaction failed: {0}")]
    Transport(#[source] Box<dyn Error + Send + Sync>),
    /// The TCTI returned a malformed TPM response.
    #[error("upstream TCTI returned a malformed response: {0}")]
    MalformedResponse(#[from] crate::tpm::ParseError),
}

/// A TPM transport capable of one complete command/response transaction.
#[async_trait]
pub trait Upstream: Send + 'static {
    /// Send `command` and wait for its response.
    async fn transact(&mut self, command: &Command) -> Result<Response, UpstreamError>;
}

/// Adapter for a synchronous `tpm2-client` connection/TCTI.
///
/// The scheduler's single worker is the sole owner of this value, preserving
/// the TCTI transmit/receive sequence.
pub struct TctiConnection<C> {
    connection: C,
    response_buffer: Vec<u8>,
    max_response_size: usize,
}

impl<C> TctiConnection<C> {
    /// Wrap a TCTI connection and allocate its reusable response buffer.
    pub fn new(connection: C, max_response_size: usize) -> Self {
        Self {
            connection,
            response_buffer: vec![0; max_response_size],
            max_response_size,
        }
    }

    /// Recover the wrapped connection.
    pub fn into_inner(self) -> C {
        self.connection
    }
}

#[async_trait]
impl<C> Upstream for TctiConnection<C>
where
    C: tpm2_client::connection::Connection + Send + 'static,
    C::Error: Error + Send + Sync + 'static,
{
    async fn transact(&mut self, command: &Command) -> Result<Response, UpstreamError> {
        let response = self
            .connection
            .transact(command.as_bytes(), &mut self.response_buffer)
            .map_err(|error| UpstreamError::Transport(Box::new(error)))?;
        Response::parse(response.to_vec(), self.max_response_size).map_err(Into::into)
    }
}
