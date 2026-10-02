// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! Serialized upstream TPM transport.
//!
//! The scheduler owns one [`Upstream`] and invokes it for exactly one command
//! at a time. Each command belongs to a [`SessionId`], one per downstream
//! client, so an upstream can keep each client's TPM state isolated.
//!
//! The concrete transport, [`TpmDeviceUpstream`], forwards commands to the Linux
//! kernel resource manager (`/dev/tpmrm0`) through `tpm2-device`, opening a
//! separate device handle per session. The kernel resource manager gives every
//! open handle its own space of transient objects and sessions, and flushes
//! that space when the handle is closed, so one client can neither see nor
//! exhaust another's resources, and nothing a client leaves loaded outlives
//! its connection.
//!
//! `tpm2-device`'s [`TpmPosixDevice`] is a synchronous, `!Send` value whose
//! receive call blocks until the TPM replies, so every session's device is
//! owned by one dedicated worker thread. The async [`Upstream`] handle is a
//! cheap, `Send` channel into that thread.
//!
//! Commands are forwarded through the device's raw [`TpmTransport`] interface:
//! the command frame is written unchanged and the TPM's response frame
//! (including any error response) is returned unchanged.

/// Upstream transport backed by a swtpm software TPM over sockets.
pub mod swtpm;

use std::{
    collections::{HashMap, hash_map::Entry},
    error::Error,
    path::Path,
    sync::mpsc,
    thread,
    time::Duration,
};

use async_trait::async_trait;
use tokio::sync::oneshot;
use tpm2_device::{TpmDeviceError, TpmPosixDevice, TpmTransport};

use crate::tpm::{Command, Response};

/// The largest command the kernel accepts on `/dev/tpmrm0` (`TPM_BUFSIZE`).
pub const DEVICE_MAX_COMMAND_SIZE: usize = 4096;

/// `TPM_RC_COMMAND_SIZE` in the resource-manager layer, the answer to a
/// command too large for the kernel.
pub const RC_COMMAND_TOO_LARGE: u32 = (11 << 16) | 0x142;

/// Identifies one downstream client's upstream session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SessionId(pub u64);

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

impl UpstreamError {
    fn transport(error: impl Error + Send + Sync + 'static) -> Self {
        Self::Transport(Box::new(error))
    }
}

/// A TPM transport capable of one complete command/response transaction.
#[async_trait]
pub trait Upstream: Send + 'static {
    /// Send `command` on behalf of `session` and wait for its response.
    ///
    /// The first command of a session opens whatever upstream state the
    /// session needs.
    async fn transact(
        &mut self,
        session: SessionId,
        command: &Command,
    ) -> Result<Response, UpstreamError>;

    /// Release `session`'s upstream state; its client has disconnected.
    ///
    /// The default does nothing, for upstreams that do not isolate sessions.
    async fn close(&mut self, _session: SessionId) {}
}

/// Upstream transport backed by per-session `tpm2-device` [`TpmPosixDevice`]s
/// on a worker thread.
pub struct TpmDeviceUpstream {
    requests: mpsc::Sender<DeviceRequest>,
    max_response_size: usize,
}

enum DeviceRequest {
    Transact {
        session: SessionId,
        command: Vec<u8>,
        reply: oneshot::Sender<Result<Vec<u8>, UpstreamError>>,
    },
    Close(SessionId),
}

impl TpmDeviceUpstream {
    /// Check that `path` (such as `/dev/tpmrm0`) can be opened and start the
    /// upstream worker thread.
    ///
    /// `command_timeout` is the hard per-command time limit: `tpm2-device`
    /// abandons a transaction whose response does not arrive within it, and
    /// the client gets an error. That bounds how long the client waits, not
    /// how long the TPM is busy: closing the abandoned handle waits in the
    /// kernel for the command to finish, so the commands queued behind it
    /// still wait for the TPM.
    ///
    /// Session devices are opened lazily on the worker thread, since
    /// [`TpmPosixDevice`] cannot cross threads. The device is also opened once
    /// here, so a missing device or a permission problem is reported at startup
    /// rather than on the first client's command.
    pub fn open(
        path: impl AsRef<Path>,
        max_response_size: usize,
        command_timeout: Duration,
    ) -> Result<Self, TpmDeviceError> {
        let path = path.as_ref().to_path_buf();
        drop(open_device(&path, command_timeout)?);

        let (requests, incoming) = mpsc::channel::<DeviceRequest>();
        thread::Builder::new()
            .name("tpm-device".to_owned())
            .spawn(move || run_device_worker(&path, command_timeout, &incoming))
            .map_err(TpmDeviceError::Io)?;

        Ok(Self {
            requests,
            max_response_size,
        })
    }
}

#[async_trait]
impl Upstream for TpmDeviceUpstream {
    async fn transact(
        &mut self,
        session: SessionId,
        command: &Command,
    ) -> Result<Response, UpstreamError> {
        // The kernel would refuse the write with E2BIG, failing the session;
        // answer as a TPM would instead, and the client may carry on.
        if command.as_bytes().len() > DEVICE_MAX_COMMAND_SIZE {
            return Ok(Response::error(RC_COMMAND_TOO_LARGE));
        }
        let (reply, response) = oneshot::channel();
        self.requests
            .send(DeviceRequest::Transact {
                session,
                command: command.as_bytes().to_vec(),
                reply,
            })
            .map_err(|_| UpstreamError::WorkerStopped)?;

        let bytes = response.await.map_err(|_| UpstreamError::WorkerStopped)??;
        Response::parse(bytes, self.max_response_size).map_err(Into::into)
    }

    async fn close(&mut self, session: SessionId) {
        let _ = self.requests.send(DeviceRequest::Close(session));
    }
}

fn open_device(path: &Path, timeout: Duration) -> Result<TpmPosixDevice, TpmDeviceError> {
    TpmPosixDevice::builder()
        .with_path(path)
        .with_timeout(timeout)
        .build()
}

/// Serve device requests until every [`TpmDeviceUpstream`] handle is dropped.
///
/// A session's device is opened by its first `Transact`, so the scheduler must
/// never forward a command for a session after closing it (it skips commands
/// whose client has gone), or the reopened handle would never be closed.
fn run_device_worker(path: &Path, timeout: Duration, incoming: &mpsc::Receiver<DeviceRequest>) {
    let mut devices = HashMap::new();

    while let Ok(request) = incoming.recv() {
        match request {
            DeviceRequest::Transact {
                session,
                command,
                reply,
            } => {
                let result = transact(&mut devices, path, timeout, session, &command);
                let failed = result.is_err();
                let _ = reply.send(result);
                // After a failed transaction (such as a timeout) the handle may
                // be mid-command, so close it rather than reuse it; the
                // client's connection ends with the error anyway. Closing
                // waits in the kernel for an abandoned command to finish, so
                // it happens after the client has its answer.
                if failed {
                    drop(devices.remove(&session));
                }
            }
            // Dropping the device closes its handle, and the kernel resource
            // manager flushes everything the session left loaded.
            DeviceRequest::Close(session) => drop(devices.remove(&session)),
        }
    }
}

/// Forward `command` on `session`'s device, opening the device if needed.
/// After a failure the caller closes the device.
fn transact(
    devices: &mut HashMap<SessionId, TpmPosixDevice>,
    path: &Path,
    timeout: Duration,
    session: SessionId,
    command: &[u8],
) -> Result<Vec<u8>, UpstreamError> {
    let device = match devices.entry(session) {
        Entry::Occupied(entry) => entry.into_mut(),
        Entry::Vacant(entry) => {
            entry.insert(open_device(path, timeout).map_err(UpstreamError::transport)?)
        }
    };
    forward(device, command)
}

/// Forward one validated command frame and return the raw response frame.
fn forward(device: &mut impl TpmTransport, command: &[u8]) -> Result<Vec<u8>, UpstreamError> {
    let mut response = Vec::new();
    device
        .send(command)
        .and_then(|()| device.recv(&mut response))
        .map_err(UpstreamError::transport)?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn answers_commands_too_large_for_the_kernel() {
        // The command never reaches the device, so any openable file will do.
        let mut upstream =
            TpmDeviceUpstream::open("/dev/null", 4096, Duration::from_secs(1)).unwrap();
        // TPM2_GetRandom padded past the kernel's limit.
        let size = DEVICE_MAX_COMMAND_SIZE + 2;
        let mut bytes = Vec::from(0x8001u16.to_be_bytes());
        bytes.extend_from_slice(&(size as u32).to_be_bytes());
        bytes.extend_from_slice(&0x17bu32.to_be_bytes());
        bytes.resize(size, 0);
        let command = Command::parse(bytes, crate::tpm::DEFAULT_MAX_PACKET_SIZE).unwrap();

        let response = upstream.transact(SessionId(0), &command).await.unwrap();
        assert_eq!(response.code(), RC_COMMAND_TOO_LARGE);
    }
}
