// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: BSD-2-Clause

//! Linux TPM character-device transport.

use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    path::Path,
};

use crate::tpm::{self, HEADER_SIZE};

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
    let size = tpm::packet_size_from_header(&header, usize::MAX)?;
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
    /// The device returned a malformed TPM response header.
    #[error("Linux TPM device returned malformed response header: {0}")]
    MalformedResponse(#[from] crate::tpm::ParseError),
    /// The provided response buffer cannot hold the complete response.
    #[error("Linux TPM response requires {needed} bytes, but buffer has {available}")]
    ResponseBufferTooSmall {
        /// Response size reported by the TPM header.
        needed: usize,
        /// Caller-provided response buffer length.
        available: usize,
    },
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
            Err(DeviceError::MalformedResponse(
                crate::tpm::ParseError::InvalidSize(9)
            ))
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
