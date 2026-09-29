// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! Serialized upstream TPM transport.
//!
//! The scheduler owns one [`Upstream`] and invokes it for exactly one command
//! at a time. The concrete transport, [`TpmDeviceUpstream`], forwards commands
//! to the Linux kernel resource manager (`/dev/tpmrm0`) through `tpm2-device`.
//!
//! `tpm2-device`'s [`TpmDevice`] is a synchronous, `!Send` value whose
//! transaction call blocks until the TPM replies, so it is owned by a dedicated
//! worker thread. The async [`Upstream`] handle is a cheap, `Send` channel into
//! that thread.
//!
//! `tpm2-device` only exposes a *typed* transaction (`TpmDevice::transmit`),
//! which marshals a [`TpmFrame`] plus its authorization sessions and returns a
//! typed response (or a [`TpmRc`] error). A proxy forwards opaque bytes, so this
//! module bridges the two: an incoming command frame is split into its raw
//! handle and parameter areas (wrapped in [`PassthroughFrame`], a [`TpmFrame`]
//! that re-marshals those bytes verbatim) and its decoded authorization
//! sessions. On success the raw response bytes are returned unchanged; a TPM
//! error code is rebuilt into the byte-identical 10-byte error response the TPM
//! would have sent.

#![allow(dead_code)] // Wired into main once daemon construction is implemented.

/// Upstream transport backed by a swtpm software TPM over sockets.
pub mod swtpm;

use std::{error::Error, path::Path, sync::mpsc, thread, time::Duration};

use async_trait::async_trait;
use tokio::sync::oneshot;
use tpm2_device::{TpmDevice, TpmDeviceError, TpmPosixDevice};
use tpm2_protocol::{
    TpmMarshal, TpmResult, TpmSized, TpmWriter,
    basic::TpmUint32,
    constant::TPM_MAX_COMMAND_SIZE,
    data::{Tpm2bAuth, Tpm2bNonce, TpmCc, TpmRc, TpmSt, TpmaSession, TpmsAuthCommand},
    frame::{TpmCommand as WireCommand, TpmFrame, TpmMarshalBody},
};

use crate::tpm::{Command, HEADER_SIZE, Response};

/// Error returned when an upstream transaction cannot produce a valid response.
#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    /// The TPM device transaction failed.
    #[error("upstream TPM device transaction failed: {0}")]
    Transport(#[source] Box<dyn Error + Send + Sync>),
    /// The TPM device returned a malformed TPM response.
    #[error("upstream TPM device returned a malformed response: {0}")]
    MalformedResponse(#[from] crate::tpm::ParseError),
    /// The upstream worker thread is no longer running.
    #[error("upstream TPM device worker stopped")]
    WorkerStopped,
}

/// A TPM transport capable of one complete command/response transaction.
#[async_trait]
pub trait Upstream: Send + 'static {
    /// Send `command` and wait for its response.
    async fn transact(&mut self, command: &Command) -> Result<Response, UpstreamError>;
}

/// Upstream transport backed by a `tpm2-device` [`TpmDevice`] on a worker thread.
pub struct TpmDeviceUpstream {
    requests: mpsc::Sender<DeviceRequest>,
    max_response_size: usize,
}

struct DeviceRequest {
    command: Vec<u8>,
    reply: oneshot::Sender<Result<Vec<u8>, UpstreamError>>,
}

impl TpmDeviceUpstream {
    /// Open `path` (such as `/dev/tpmrm0`) and start the upstream worker thread.
    ///
    /// `command_timeout` is the hard per-command time limit: `tpm2-device`
    /// abandons a transaction whose response does not arrive within it, which
    /// frees the worker (and the clients queued behind it) from a wedged TPM.
    ///
    /// The TPM device is opened on the worker thread itself, since [`TpmDevice`]
    /// cannot cross threads. This call blocks until the device is open, so a
    /// failure to open it is reported synchronously.
    pub fn open(
        path: impl AsRef<Path>,
        max_response_size: usize,
        command_timeout: Duration,
    ) -> Result<Self, TpmDeviceError> {
        let path = path.as_ref().to_path_buf();
        let (requests, incoming) = mpsc::channel::<DeviceRequest>();
        let (ready_tx, ready_rx) = mpsc::channel::<Result<(), TpmDeviceError>>();

        thread::Builder::new()
            .name("tpm-device".to_owned())
            .spawn(move || {
                let mut device = match TpmPosixDevice::builder()
                    .with_path(&path)
                    .with_timeout(command_timeout)
                    .build()
                {
                    Ok(transport) => {
                        let _ = ready_tx.send(Ok(()));
                        TpmDevice::new(Box::new(transport))
                    }
                    Err(error) => {
                        let _ = ready_tx.send(Err(error));
                        return;
                    }
                };
                drop(ready_tx);

                while let Ok(request) = incoming.recv() {
                    let result = forward(&mut device, &request.command);
                    let _ = request.reply.send(result);
                }
            })
            .map_err(TpmDeviceError::Io)?;

        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                requests,
                max_response_size,
            }),
            Ok(Err(error)) => Err(error),
            Err(_) => Err(TpmDeviceError::NotAvailable),
        }
    }
}

#[async_trait]
impl Upstream for TpmDeviceUpstream {
    async fn transact(&mut self, command: &Command) -> Result<Response, UpstreamError> {
        let (reply, response) = oneshot::channel();
        self.requests
            .send(DeviceRequest {
                command: command.as_bytes().to_vec(),
                reply,
            })
            .map_err(|_| UpstreamError::WorkerStopped)?;

        let bytes = response.await.map_err(|_| UpstreamError::WorkerStopped)??;
        Response::parse(bytes, self.max_response_size).map_err(Into::into)
    }
}

/// Forward one validated command frame through the typed device transaction.
fn forward(device: &mut TpmDevice, command: &[u8]) -> Result<Vec<u8>, UpstreamError> {
    let request = PassthroughCommand::decode(command)
        .map_err(|error| UpstreamError::Transport(Box::new(error)))?;

    match device.transmit(&request.frame, &request.sessions) {
        // On success `transmit` hands back a borrowed view of the raw response
        // bytes; forward them unchanged.
        Ok(response) => Ok(response.as_bytes().to_vec()),
        // A TPM error code is returned as an error rather than a response. The
        // wire response for any error is a bare header (tag, size 10, code), so
        // rebuilding it is byte-identical to what the TPM emitted.
        Err(TpmDeviceError::TpmRc(rc)) => Ok(error_response(rc)),
        Err(error) => Err(UpstreamError::Transport(Box::new(error))),
    }
}

/// Synthesize the 10-byte error response a TPM returns for `rc`.
fn error_response(rc: TpmRc) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEADER_SIZE);
    bytes.extend_from_slice(&TpmSt::NoSessions.value().to_be_bytes());
    bytes.extend_from_slice(&(HEADER_SIZE as u32).to_be_bytes());
    bytes.extend_from_slice(&rc.value().to_be_bytes());
    bytes
}

/// A command frame split into the pieces `TpmDevice::transmit` consumes.
struct PassthroughCommand {
    frame: PassthroughFrame,
    sessions: Vec<TpmsAuthCommand>,
}

impl PassthroughCommand {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let command = WireCommand::cast(bytes).map_err(DecodeError::Frame)?;
        let cc = command.cc().map_err(DecodeError::Frame)?;
        let handles = command.handles().map_err(DecodeError::Frame)?.to_vec();
        let parameters = command.parameters().map_err(DecodeError::Frame)?.to_vec();
        let sessions = if command.tag().map_err(DecodeError::Frame)? == TpmSt::Sessions {
            decode_sessions(command.auth_area().map_err(DecodeError::Frame)?)?
        } else {
            Vec::new()
        };

        let handle_count = handles.len() / core::mem::size_of::<u32>();
        Ok(Self {
            frame: PassthroughFrame {
                cc,
                handle_count,
                handles,
                parameters,
            },
            sessions,
        })
    }
}

/// A [`TpmFrame`] that re-marshals a command's raw handle and parameter bytes.
///
/// `TpmDevice::transmit` rebuilds the command envelope (tag, size, command code)
/// and the authorization area from the sessions it is given, then asks the frame
/// to marshal its handle and parameter areas. Emitting the original bytes there
/// reproduces the command exactly.
#[derive(Debug)]
struct PassthroughFrame {
    cc: TpmCc,
    handle_count: usize,
    handles: Vec<u8>,
    parameters: Vec<u8>,
}

impl TpmSized for PassthroughFrame {
    const SIZE: usize = TPM_MAX_COMMAND_SIZE;

    fn len(&self) -> usize {
        self.handles.len() + self.parameters.len()
    }
}

impl TpmMarshalBody for PassthroughFrame {
    fn marshal_handles(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        writer.write_bytes(&self.handles)
    }

    fn marshal_parameters(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        writer.write_bytes(&self.parameters)
    }
}

impl TpmMarshal for PassthroughFrame {
    fn marshal(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        self.marshal_handles(writer)?;
        self.marshal_parameters(writer)
    }
}

impl TpmFrame for PassthroughFrame {
    fn cc(&self) -> TpmCc {
        self.cc
    }

    fn handles(&self) -> usize {
        self.handle_count
    }
}

/// Decode a command authorization area into owned sessions.
///
/// `tpm2-protocol` only offers borrowed wire views over received bytes, so the
/// owned [`TpmsAuthCommand`] values `transmit` needs are rebuilt field by field.
/// Re-marshalling them reproduces the original authorization bytes.
fn decode_sessions(mut auth: &[u8]) -> Result<Vec<TpmsAuthCommand>, DecodeError> {
    let mut sessions = Vec::new();
    while !auth.is_empty() {
        let (session, rest) = decode_session(auth)?;
        sessions.push(session);
        auth = rest;
    }
    Ok(sessions)
}

fn decode_session(buf: &[u8]) -> Result<(TpmsAuthCommand, &[u8]), DecodeError> {
    let (handle, buf) = take::<4>(buf).ok_or(DecodeError::AuthArea)?;
    let (nonce, buf) = take_sized(buf)?;
    let (attributes, buf) = take::<1>(buf).ok_or(DecodeError::AuthArea)?;
    let (hmac, buf) = take_sized(buf)?;

    let session = TpmsAuthCommand {
        session_handle: TpmUint32::new(u32::from_be_bytes(handle)),
        nonce: Tpm2bNonce::try_from(nonce).map_err(|_| DecodeError::AuthArea)?,
        session_attributes: TpmaSession::from_bits_truncate(attributes[0]),
        hmac: Tpm2bAuth::try_from(hmac).map_err(|_| DecodeError::AuthArea)?,
    };
    Ok((session, buf))
}

/// Split a fixed-size prefix off `buf`.
fn take<const N: usize>(buf: &[u8]) -> Option<([u8; N], &[u8])> {
    if buf.len() < N {
        return None;
    }
    let (head, tail) = buf.split_at(N);
    Some((head.try_into().expect("slice length checked"), tail))
}

/// Split a 16-bit length-prefixed `TPM2B` field off `buf`.
fn take_sized(buf: &[u8]) -> Result<(&[u8], &[u8]), DecodeError> {
    let (size, buf) = take::<2>(buf).ok_or(DecodeError::AuthArea)?;
    let size = u16::from_be_bytes(size) as usize;
    if buf.len() < size {
        return Err(DecodeError::AuthArea);
    }
    Ok(buf.split_at(size))
}

/// Failure to split an incoming command into the parts `transmit` requires.
#[derive(Debug, thiserror::Error)]
enum DecodeError {
    /// The command frame envelope is malformed.
    #[error("malformed TPM command frame: {0}")]
    Frame(tpm2_protocol::TpmError),
    /// The command authorization area is malformed.
    #[error("malformed TPM command authorization area")]
    AuthArea,
}
