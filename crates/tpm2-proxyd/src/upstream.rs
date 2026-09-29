// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! Serialized upstream TPM transport.
//!
//! The scheduler owns one [`Upstream`] and invokes it for exactly one command
//! at a time. The concrete transport, [`TpmDeviceUpstream`], forwards commands
//! to the Linux kernel resource manager (`/dev/tpmrm0`) through `tpm2-device`.
//!
//! `tpm2-device`'s [`TpmPosixDevice`] is a synchronous, `!Send` value whose
//! receive call blocks until the TPM replies, so it is owned by a dedicated
//! worker thread. The async [`Upstream`] handle is a cheap, `Send` channel into
//! that thread.
//!
//! Commands are forwarded through the device's raw [`TpmTransport`] interface:
//! the command frame is written unchanged and the TPM's response frame
//! (including any error response) is returned unchanged.

#![allow(dead_code)] // Wired into main once daemon construction is implemented.

/// Upstream transport backed by a swtpm software TPM over sockets.
pub mod swtpm;

use std::{error::Error, path::Path, sync::mpsc, thread, time::Duration};

use async_trait::async_trait;
use tokio::sync::oneshot;
use tpm2_device::{TpmDeviceError, TpmPosixDevice, TpmTransport};

use crate::tpm::{Command, Response};

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

/// Upstream transport backed by a `tpm2-device` [`TpmPosixDevice`] on a worker thread.
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
    /// The TPM device is opened on the worker thread itself, since
    /// [`TpmPosixDevice`] cannot cross threads. This call blocks until the
    /// device is open, so a failure to open it is reported synchronously.
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
                    Ok(device) => {
                        let _ = ready_tx.send(Ok(()));
                        device
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

/// Forward one validated command frame and return the raw response frame.
fn forward(device: &mut impl TpmTransport, command: &[u8]) -> Result<Vec<u8>, UpstreamError> {
    let mut response = Vec::new();
    device
        .send(command)
        .and_then(|()| device.recv(&mut response))
        .map_err(|error| UpstreamError::Transport(Box::new(error)))?;
    Ok(response)
}
