// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: BSD-2-Clause

//! Serialized upstream TPM transport.
//!
//! The scheduler owns one [`Upstream`] and invokes it for exactly one command
//! at a time. No timeout or cancellation is applied: once a transaction starts,
//! it runs until the upstream TCTI returns.

#![allow(dead_code)] // Wired into main once daemon construction is implemented.

use std::{
    error::Error,
    fs::{File, OpenOptions},
    future::Future,
    io::{self, Read, Write},
    path::Path,
};

use crate::tpm::{Command, HEADER_SIZE, Response};

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
pub trait Upstream: Send + 'static {
    /// Send `command` and wait for its response.
    fn transact(
        &mut self,
        command: &Command,
    ) -> impl Future<Output = Result<Response, UpstreamError>> + Send;
}

/// Raw Linux TPM character-device connection, such as `/dev/tpmrm0`.
///
/// Linux TPM devices accept one complete TPM command byte stream on write and
/// return one complete TPM response byte stream on read. The kernel resource
/// manager (`/dev/tpmrm0`) remains responsible for resource virtualization; this
/// proxy only serializes and authorizes access before forwarding commands.
pub struct LinuxTpmDevice {
    device: File,
}

impl LinuxTpmDevice {
    /// Open a Linux TPM device for raw command/response transactions.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        Ok(Self {
            device: OpenOptions::new().read(true).write(true).open(path)?,
        })
    }

    /// Wrap an already-open device handle.
    pub fn from_file(device: File) -> Self {
        Self { device }
    }

    /// Recover the wrapped device handle.
    pub fn into_inner(self) -> File {
        self.device
    }
}

impl tpm2_client::connection::Connection for LinuxTpmDevice {
    type Error = DeviceError;

    fn transact<'a>(&mut self, cmd: &[u8], rsp: &'a mut [u8]) -> Result<&'a mut [u8], Self::Error> {
        transact_device(&mut self.device, cmd, rsp)
    }
}

fn transact_device<'a>(
    device: &mut (impl Read + Write),
    cmd: &[u8],
    rsp: &'a mut [u8],
) -> Result<&'a mut [u8], DeviceError> {
    device.write_all(cmd)?;
    device.flush()?;

    let mut header = [0; HEADER_SIZE];
    device.read_exact(&mut header)?;
    let size = u32::from_be_bytes([header[2], header[3], header[4], header[5]]) as usize;
    if size < HEADER_SIZE {
        return Err(DeviceError::InvalidResponseSize(size));
    }
    if size > rsp.len() {
        return Err(DeviceError::ResponseBufferTooSmall {
            needed: size,
            available: rsp.len(),
        });
    }

    rsp[..HEADER_SIZE].copy_from_slice(&header);
    device.read_exact(&mut rsp[HEADER_SIZE..size])?;
    Ok(&mut rsp[..size])
}

/// Error returned by [`LinuxTpmDevice`].
#[derive(Debug, thiserror::Error)]
pub enum DeviceError {
    /// Linux device I/O failed.
    #[error("Linux TPM device I/O failed: {0}")]
    Io(#[from] io::Error),
    /// The device returned a response size smaller than a TPM header.
    #[error("Linux TPM device returned invalid response size {0}")]
    InvalidResponseSize(usize),
    /// The provided response buffer cannot hold the complete response.
    #[error("Linux TPM response requires {needed} bytes, but buffer has {available}")]
    ResponseBufferTooSmall {
        /// Response size reported by the TPM header.
        needed: usize,
        /// Caller-provided response buffer length.
        available: usize,
    },
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

#[cfg(test)]
mod tests {
    use super::*;

    struct ScriptedDevice {
        response: io::Cursor<Vec<u8>>,
        written: Vec<u8>,
        fail_write: bool,
    }

    impl ScriptedDevice {
        fn new(response: Vec<u8>) -> Self {
            Self {
                response: io::Cursor::new(response),
                written: Vec::new(),
                fail_write: false,
            }
        }
    }

    impl Read for ScriptedDevice {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.response.read(buf)
        }
    }

    impl Write for ScriptedDevice {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.fail_write {
                return Err(io::Error::other("write failed"));
            }
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn response(size: u32) -> Vec<u8> {
        let mut response = Vec::from(0x8001u16.to_be_bytes());
        response.extend_from_slice(&size.to_be_bytes());
        response.extend_from_slice(&0u32.to_be_bytes());
        if size as usize > response.len() {
            response.resize(size as usize, 0xaa);
        }
        response
    }

    #[test]
    fn linux_tpm_device_transaction_writes_command_and_reads_response() {
        let command = [1, 2, 3, 4];
        let expected = response(14);
        let mut device = ScriptedDevice::new(expected.clone());
        let mut buffer = [0; 32];

        let actual = transact_device(&mut device, &command, &mut buffer).unwrap();

        assert_eq!(device.written, command);
        assert_eq!(actual, expected);
    }

    #[test]
    fn linux_tpm_device_rejects_short_response_size() {
        let mut device = ScriptedDevice::new(response(9));
        let mut buffer = [0; 32];

        assert!(matches!(
            transact_device(&mut device, &[1, 2], &mut buffer),
            Err(DeviceError::InvalidResponseSize(9))
        ));
    }

    #[test]
    fn linux_tpm_device_rejects_oversized_response() {
        let mut device = ScriptedDevice::new(response(14));
        let mut buffer = [0; 12];

        assert!(matches!(
            transact_device(&mut device, &[1, 2], &mut buffer),
            Err(DeviceError::ResponseBufferTooSmall {
                needed: 14,
                available: 12
            })
        ));
    }
}
