// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! A small borrowing cursor used to hand-parse each command's fields.
//!
//! Every command decoder in [`crate::commands`] is written directly against
//! [`Reader`]'s methods, called in wire order -- no macro, no generated
//! marshal/unmarshal trait.

use crate::{error::Error, handle::Handle};

/// A cursor over a borrowed byte slice, consumed field by field.
///
/// Every read method advances the cursor and returns an owned scalar or a
/// sub-slice borrowed from the buffer -- never a copy.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    /// The unconsumed remainder of the buffer.
    pub(crate) fn rest(&self) -> &'a [u8] {
        self.buf
    }

    fn take(&mut self, n: usize, field: &'static str) -> Result<&'a [u8], Error> {
        if self.buf.len() < n {
            return Err(Error::UnexpectedEof {
                field,
                needed: n,
                available: self.buf.len(),
            });
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    pub(crate) fn u8(&mut self, field: &'static str) -> Result<u8, Error> {
        Ok(self.take(1, field)?[0])
    }

    pub(crate) fn u16(&mut self, field: &'static str) -> Result<u16, Error> {
        let bytes = self.take(2, field)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    pub(crate) fn u32(&mut self, field: &'static str) -> Result<u32, Error> {
        let bytes = self.take(4, field)?;
        Ok(u32::from_be_bytes(
            bytes.try_into().expect("length checked by take()"),
        ))
    }

    pub(crate) fn u64(&mut self, field: &'static str) -> Result<u64, Error> {
        let bytes = self.take(8, field)?;
        Ok(u64::from_be_bytes(
            bytes.try_into().expect("length checked by take()"),
        ))
    }

    /// Reads a raw 4-byte TPM handle.
    pub(crate) fn handle(&mut self, field: &'static str) -> Result<Handle, Error> {
        self.u32(field).map(Handle)
    }

    /// Reads a `TPMI_YES_NO`: a single byte that must be exactly `0` or `1`.
    pub(crate) fn yes_no(&mut self, field: &'static str) -> Result<bool, Error> {
        match self.u8(field)? {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(Error::InvalidValue {
                field,
                value: u32::from(other),
            }),
        }
    }

    /// Borrows the next `n` bytes.
    pub(crate) fn bytes(&mut self, n: usize, field: &'static str) -> Result<&'a [u8], Error> {
        self.take(n, field)
    }

    /// Reads a `TPM2B`-style field: a big-endian `u16` size followed by that
    /// many bytes, returned as a borrowed slice over just the payload.
    pub(crate) fn buffer(&mut self, field: &'static str) -> Result<&'a [u8], Error> {
        let size = self.u16(field)? as usize;
        if self.buf.len() < size {
            return Err(Error::BufferTooLarge {
                field,
                declared: size,
                available: self.buf.len(),
            });
        }
        self.bytes(size, field)
    }

    /// Confirms the buffer has been fully consumed.
    ///
    /// `field` names the area being closed out (e.g. `"parameters"`), used
    /// only for the [`Error::TrailingData`] this returns if bytes remain.
    pub(crate) fn finish(self, field: &'static str) -> Result<(), Error> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(Error::TrailingData {
                field,
                remaining: self.buf.len(),
            })
        }
    }
}
