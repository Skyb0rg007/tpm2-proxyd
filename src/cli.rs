// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: BSD-2-Clause

//! Command-line argument parsing for the daemon.

use std::{env, ffi::OsString, path::PathBuf};

use clap::Parser;

/// Default temporary raw TPM socket path.
pub const DEFAULT_RAW_SOCKET_PATH: &str = "/run/tpm2-proxyd/tpm2-proxyd.sock";
/// Default upstream Linux TPM resource-manager device.
pub const DEFAULT_UPSTREAM_TPM_PATH: &str = "/dev/tpmrm0";
/// Default number of commands that may wait for the upstream worker.
pub const DEFAULT_QUEUE_DEPTH: usize = 64;

/// Parsed command-line options.
#[derive(Clone, Debug, Parser, PartialEq, Eq)]
#[command(version, about)]
pub struct Options {
    /// Explicit test configuration file path.
    #[arg(long, require_equals = true, value_name = "PATH", value_parser = parse_path)]
    pub config: PathBuf,
    /// Temporary raw TPM Unix socket path.
    #[arg(
        long,
        require_equals = true,
        value_name = "PATH",
        default_value = DEFAULT_RAW_SOCKET_PATH,
        value_parser = parse_path
    )]
    pub socket: PathBuf,
    /// Upstream Linux TPM device path.
    #[arg(
        long,
        require_equals = true,
        value_name = "PATH",
        default_value = DEFAULT_UPSTREAM_TPM_PATH,
        value_parser = parse_path
    )]
    pub upstream: PathBuf,
    /// Maximum accepted TPM command or response size.
    #[arg(
        long,
        require_equals = true,
        value_name = "BYTES",
        default_value_t = crate::tpm::DEFAULT_MAX_PACKET_SIZE,
        value_parser = parse_positive_usize
    )]
    pub max_packet_size: usize,
    /// Maximum number of queued TPM commands.
    #[arg(
        long,
        require_equals = true,
        value_name = "COUNT",
        default_value_t = DEFAULT_QUEUE_DEPTH,
        value_parser = parse_positive_usize
    )]
    pub queue_depth: usize,
}

impl Options {
    /// Parse options from the process command line.
    pub fn parse_env() -> clap::error::Result<Self> {
        Self::parse_from(env::args_os())
    }

    /// Parse options from an iterator, including argv[0].
    pub fn parse_from<I, S>(args: I) -> clap::error::Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString> + Clone,
    {
        Self::try_parse_from(args)
    }
}

fn parse_path(value: &str) -> Result<PathBuf, String> {
    if value.is_empty() {
        Err("path must not be empty".into())
    } else {
        Ok(PathBuf::from(value))
    }
}

fn parse_positive_usize(value: &str) -> Result<usize, String> {
    value
        .parse()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| "value must be a positive integer".into())
}

#[cfg(test)]
mod tests {
    use clap::error::ErrorKind;

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
            Options::parse_from(["tpm2-proxyd"]).unwrap_err().kind(),
            ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn rejects_config_without_equals() {
        assert_eq!(
            Options::parse_from(["tpm2-proxyd", "--config", "/tmp/policy.json"])
                .unwrap_err()
                .kind(),
            ErrorKind::NoEquals
        );
    }

    #[test]
    fn rejects_duplicate_config_argument() {
        assert_eq!(
            Options::parse_from([
                "tpm2-proxyd",
                "--config=/tmp/one.json",
                "--config=/tmp/two.json",
            ])
            .unwrap_err()
            .kind(),
            ErrorKind::ArgumentConflict
        );
    }

    #[test]
    fn rejects_non_positive_runtime_numbers() {
        assert_eq!(
            Options::parse_from([
                "tpm2-proxyd",
                "--config=/tmp/policy.json",
                "--queue-depth=0",
            ])
            .unwrap_err()
            .kind(),
            ErrorKind::ValueValidation
        );
    }

    #[test]
    fn rejects_duplicate_runtime_options() {
        assert_eq!(
            Options::parse_from([
                "tpm2-proxyd",
                "--config=/tmp/policy.json",
                "--socket=/tmp/one.sock",
                "--socket=/tmp/two.sock",
            ])
            .unwrap_err()
            .kind(),
            ErrorKind::ArgumentConflict
        );
    }
}
