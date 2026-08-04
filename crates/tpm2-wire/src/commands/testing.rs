// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! [TPM2.0 1.83] 10 Testing

use crate::{error::Error, reader::Reader};

/// [TPM2.0 1.83] 10.2 TPM2_SelfTest (Command). Zero handles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfTestCommand {
    /// If true, test everything; if false, test only algorithms that have
    /// not yet been tested.
    pub full_test: bool,
}

impl SelfTestCommand {
    pub(crate) fn parse(parameters: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(parameters);
        let full_test = r.yes_no("fullTest")?;
        r.finish("parameters")?;
        Ok(Self { full_test })
    }
}

/// [TPM2.0 1.83] 10.4 TPM2_GetTestResult (Command). Zero handles, no
/// parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GetTestResultCommand;

impl GetTestResultCommand {
    pub(crate) fn parse(parameters: &[u8]) -> Result<Self, Error> {
        Reader::new(parameters).finish("parameters")?;
        Ok(Self)
    }
}
