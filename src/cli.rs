// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: BSD-2-Clause

//! Command-line argument parsing for the daemon.

use std::{env, ffi::OsString, path::PathBuf};

/// Default temporary raw TPM socket path.
pub const DEFAULT_RAW_SOCKET_PATH: &str = "/run/tpm2-proxyd/tpm2-proxyd.sock";
/// Default upstream Linux TPM resource-manager device.
pub const DEFAULT_UPSTREAM_TPM_PATH: &str = "/dev/tpmrm0";
/// Default number of commands that may wait for the upstream worker.
pub const DEFAULT_QUEUE_DEPTH: usize = 64;

/// Parsed command-line options.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    /// Explicit test configuration file path.
    pub config: PathBuf,
    /// Temporary raw TPM Unix socket path.
    pub socket: PathBuf,
    /// Upstream Linux TPM device path.
    pub upstream: PathBuf,
    /// Maximum accepted TPM command or response size.
    pub max_packet_size: usize,
    /// Maximum number of queued TPM commands.
    pub queue_depth: usize,
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
    /// An option with a single value appeared more than once.
    #[error("duplicate {0}")]
    DuplicateOption(String),
    /// The `--config=` value was empty.
    #[error("--config=<path> must not be empty")]
    EmptyConfig,
    /// An option value was empty.
    #[error("{0} must not be empty")]
    EmptyOption(String),
    /// The caller used `--config` without the required `=<path>` form.
    #[error("use --config=<path>, not --config <path>")]
    ConfigRequiresEquals,
    /// The caller used an option without the required `=<value>` form.
    #[error("use {0}=<value>, not {0} <value>")]
    OptionRequiresEquals(String),
    /// A numeric option did not parse as a positive integer.
    #[error("{option} must be a positive integer, got {value}")]
    InvalidPositiveInteger {
        /// Option name.
        option: String,
        /// Rejected value.
        value: String,
    },
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
        let mut socket = None;
        let mut upstream = None;
        let mut max_packet_size = None;
        let mut queue_depth = None;

        for arg in args.into_iter().skip(1).map(Into::into) {
            if arg == "--config" {
                return Err(Error::ConfigRequiresEquals);
            }
            for option in [
                "--socket",
                "--upstream",
                "--max-packet-size",
                "--queue-depth",
            ] {
                if arg == option {
                    return Err(Error::OptionRequiresEquals(option.into()));
                }
            }

            let display = arg.to_string_lossy();
            if let Some(path) = display.strip_prefix("--config=") {
                if config.is_some() {
                    return Err(Error::DuplicateConfig);
                }
                if path.is_empty() {
                    return Err(Error::EmptyConfig);
                }
                config = Some(PathBuf::from(path));
                continue;
            }
            if let Some(path) = display.strip_prefix("--socket=") {
                set_path(&mut socket, "--socket", path)?;
                continue;
            }
            if let Some(path) = display.strip_prefix("--upstream=") {
                set_path(&mut upstream, "--upstream", path)?;
                continue;
            }
            if let Some(value) = display.strip_prefix("--max-packet-size=") {
                set_positive_usize(&mut max_packet_size, "--max-packet-size", value)?;
                continue;
            }
            if let Some(value) = display.strip_prefix("--queue-depth=") {
                set_positive_usize(&mut queue_depth, "--queue-depth", value)?;
                continue;
            }

            return Err(Error::UnknownArgument(display.into_owned()));
        }

        Ok(Self {
            config: config.ok_or(Error::MissingConfig)?,
            socket: socket.unwrap_or_else(|| PathBuf::from(DEFAULT_RAW_SOCKET_PATH)),
            upstream: upstream.unwrap_or_else(|| PathBuf::from(DEFAULT_UPSTREAM_TPM_PATH)),
            max_packet_size: max_packet_size.unwrap_or(crate::tpm::DEFAULT_MAX_PACKET_SIZE),
            queue_depth: queue_depth.unwrap_or(DEFAULT_QUEUE_DEPTH),
        })
    }
}

fn set_path(slot: &mut Option<PathBuf>, option: &str, value: &str) -> Result<(), Error> {
    if slot.is_some() {
        return Err(Error::DuplicateOption(option.into()));
    }
    if value.is_empty() {
        return Err(Error::EmptyOption(option.into()));
    }
    *slot = Some(PathBuf::from(value));
    Ok(())
}

fn set_positive_usize(slot: &mut Option<usize>, option: &str, value: &str) -> Result<(), Error> {
    if slot.is_some() {
        return Err(Error::DuplicateOption(option.into()));
    }
    let parsed = value
        .parse()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| Error::InvalidPositiveInteger {
            option: option.into(),
            value: value.into(),
        })?;
    *slot = Some(parsed);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_required_config_argument() {
        let options = Options::parse_from(["tpm2-proxyd", "--config=/tmp/policy.json"]).unwrap();

        assert_eq!(options.config, PathBuf::from("/tmp/policy.json"));
        assert_eq!(options.socket, PathBuf::from(DEFAULT_RAW_SOCKET_PATH));
        assert_eq!(options.upstream, PathBuf::from(DEFAULT_UPSTREAM_TPM_PATH));
        assert_eq!(options.max_packet_size, crate::tpm::DEFAULT_MAX_PACKET_SIZE);
        assert_eq!(options.queue_depth, DEFAULT_QUEUE_DEPTH);
    }

    #[test]
    fn parses_runtime_overrides() {
        let options = Options::parse_from([
            "tpm2-proxyd",
            "--config=/tmp/policy.json",
            "--socket=/tmp/proxy.sock",
            "--upstream=/tmp/tpmrm0",
            "--max-packet-size=8192",
            "--queue-depth=32",
        ])
        .unwrap();

        assert_eq!(options.socket, PathBuf::from("/tmp/proxy.sock"));
        assert_eq!(options.upstream, PathBuf::from("/tmp/tpmrm0"));
        assert_eq!(options.max_packet_size, 8192);
        assert_eq!(options.queue_depth, 32);
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

    #[test]
    fn rejects_non_positive_runtime_numbers() {
        assert_eq!(
            Options::parse_from([
                "tpm2-proxyd",
                "--config=/tmp/policy.json",
                "--queue-depth=0"
            ])
            .unwrap_err(),
            Error::InvalidPositiveInteger {
                option: "--queue-depth".into(),
                value: "0".into()
            }
        );
    }

    #[test]
    fn rejects_duplicate_runtime_options() {
        assert_eq!(
            Options::parse_from([
                "tpm2-proxyd",
                "--config=/tmp/policy.json",
                "--socket=/tmp/one.sock",
                "--socket=/tmp/two.sock"
            ])
            .unwrap_err(),
            Error::DuplicateOption("--socket".into())
        );
    }
}
