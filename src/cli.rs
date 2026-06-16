// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: BSD-2-Clause

//! Command-line argument parsing for the daemon.

use std::{env, ffi::OsString, path::PathBuf};

/// Parsed command-line options.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    /// Explicit test configuration file path.
    pub config: PathBuf,
}

/// Command-line parse error.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// The required `--config=<path>` option was not present.
    #[error("missing required --config=<path>")]
    MissingConfig,
    /// The `--config` option appeared more than once.
    #[error("duplicate --config=<path>")]
    DuplicateConfig,
    /// The `--config=` value was empty.
    #[error("--config=<path> must not be empty")]
    EmptyConfig,
    /// The caller used `--config` without the required `=<path>` form.
    #[error("use --config=<path>, not --config <path>")]
    ConfigRequiresEquals,
    /// An unrecognized argument was present.
    #[error("unknown argument {0}")]
    UnknownArgument(String),
}

impl Options {
    /// Parse options from the process command line.
    pub fn parse_env() -> Result<Self, Error> {
        Self::parse_from(env::args_os())
    }

    /// Parse options from an iterator, including argv[0].
    pub fn parse_from<I, S>(args: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let mut config = None;
        for arg in args.into_iter().skip(1).map(Into::into) {
            if arg == "--config" {
                return Err(Error::ConfigRequiresEquals);
            }

            let display = arg.to_string_lossy();
            let Some(path) = display.strip_prefix("--config=") else {
                return Err(Error::UnknownArgument(display.into_owned()));
            };
            if config.is_some() {
                return Err(Error::DuplicateConfig);
            }
            if path.is_empty() {
                return Err(Error::EmptyConfig);
            }
            config = Some(PathBuf::from(path));
        }

        Ok(Self {
            config: config.ok_or(Error::MissingConfig)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_required_config_argument() {
        let options = Options::parse_from(["tpm2-proxyd", "--config=/tmp/policy.json"]).unwrap();

        assert_eq!(options.config, PathBuf::from("/tmp/policy.json"));
    }

    #[test]
    fn rejects_missing_config_argument() {
        assert_eq!(
            Options::parse_from(["tpm2-proxyd"]).unwrap_err(),
            Error::MissingConfig
        );
    }

    #[test]
    fn rejects_config_without_equals() {
        assert_eq!(
            Options::parse_from(["tpm2-proxyd", "--config", "/tmp/policy.json"]).unwrap_err(),
            Error::ConfigRequiresEquals
        );
    }

    #[test]
    fn rejects_duplicate_config_argument() {
        assert_eq!(
            Options::parse_from([
                "tpm2-proxyd",
                "--config=/tmp/one.json",
                "--config=/tmp/two.json"
            ])
            .unwrap_err(),
            Error::DuplicateConfig
        );
    }
}
