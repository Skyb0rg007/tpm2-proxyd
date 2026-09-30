// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! Command-line argument parsing for the daemon.

use std::{env, ffi::OsString, path::PathBuf};

use clap::Parser;

/// Default policy configuration file path.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/tpm2-proxyd/policy.json";
/// Default client socket path.
pub const DEFAULT_SOCKET_PATH: &str = "/run/tpm2-proxyd/tpm2-proxyd.sock";
/// Default upstream Linux TPM resource-manager device.
pub const DEFAULT_UPSTREAM_TPM_PATH: &str = "/dev/tpmrm0";
/// Default number of commands that may wait for the upstream worker.
pub const DEFAULT_QUEUE_DEPTH: usize = 64;
/// Default cap on concurrent connections from one UID.
pub const DEFAULT_MAX_CONNECTIONS_PER_UID: usize = 16;
/// Default hard per-command timeout, in seconds.
pub const DEFAULT_COMMAND_TIMEOUT_SECS: u64 = 120;

/// Parsed command-line options.
#[derive(Clone, Debug, Parser, PartialEq, Eq)]
#[command(version, about = "Per-user access-control proxy for a TPM 2.0 device")]
pub struct Options {
    /// Policy configuration file path.
    #[arg(
        long,
        require_equals = true,
        value_name = "PATH",
        default_value = DEFAULT_CONFIG_PATH,
        value_parser = parse_path
    )]
    pub config: PathBuf,
    /// Client Unix socket path.
    #[arg(
        long,
        require_equals = true,
        value_name = "PATH",
        default_value = DEFAULT_SOCKET_PATH,
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
    /// Use a swtpm data socket as the upstream instead of `--upstream`.
    ///
    /// Accepts `unix:<path>`, `tcp:<host:port>`, a path, or `host:port`.
    #[arg(long, require_equals = true, value_name = "ADDR")]
    pub swtpm_server: Option<String>,
    /// swtpm control socket. When set, the TPM is initialized (CMD_INIT) on
    /// startup, so downstream clients must issue TPM2_Startup.
    #[arg(long, require_equals = true, value_name = "ADDR")]
    pub swtpm_ctrl: Option<String>,
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
    /// Maximum number of concurrent downstream connections (0 = unlimited).
    #[arg(
        long,
        require_equals = true,
        value_name = "COUNT",
        default_value_t = 0,
        value_parser = clap::value_parser!(usize)
    )]
    pub max_connections: usize,
    /// Maximum number of concurrent downstream connections from one UID
    /// (0 = unlimited).
    #[arg(
        long,
        require_equals = true,
        value_name = "COUNT",
        default_value_t = DEFAULT_MAX_CONNECTIONS_PER_UID,
        value_parser = clap::value_parser!(usize)
    )]
    pub max_connections_per_uid: usize,
    /// Number of authorization failures toward the TPM's dictionary-attack
    /// lockout after which each further failure is logged as a warning
    /// (0 = never warn).
    #[arg(
        long,
        require_equals = true,
        value_name = "COUNT",
        default_value_t = crate::lockout::DEFAULT_WARN_THRESHOLD,
        value_parser = clap::value_parser!(u64)
    )]
    pub auth_failure_warn_threshold: u64,
    /// Hard per-command timeout, in seconds.
    #[arg(
        long,
        require_equals = true,
        value_name = "SECONDS",
        default_value_t = DEFAULT_COMMAND_TIMEOUT_SECS,
        value_parser = parse_positive_u64
    )]
    pub command_timeout_secs: u64,
}

impl Options {
    /// The hard per-command timeout as a [`std::time::Duration`].
    pub fn command_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.command_timeout_secs)
    }
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

fn parse_positive_u64(value: &str) -> Result<u64, String> {
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
    fn applies_defaults_without_arguments() {
        let options = Options::parse_from(["tpm2-proxyd"]).unwrap();

        assert_eq!(options.config, PathBuf::from(DEFAULT_CONFIG_PATH));
        assert_eq!(options.socket, PathBuf::from(DEFAULT_SOCKET_PATH));
        assert_eq!(options.upstream, PathBuf::from(DEFAULT_UPSTREAM_TPM_PATH));
        assert_eq!(options.max_packet_size, crate::tpm::DEFAULT_MAX_PACKET_SIZE);
        assert_eq!(options.queue_depth, DEFAULT_QUEUE_DEPTH);
        assert_eq!(options.max_connections, 0);
        assert_eq!(
            options.auth_failure_warn_threshold,
            crate::lockout::DEFAULT_WARN_THRESHOLD
        );
        assert_eq!(
            options.max_connections_per_uid,
            DEFAULT_MAX_CONNECTIONS_PER_UID
        );
        assert_eq!(options.command_timeout_secs, DEFAULT_COMMAND_TIMEOUT_SECS);
    }

    #[test]
    fn parses_explicit_config_argument() {
        let options = Options::parse_from(["tpm2-proxyd", "--config=/tmp/policy.json"]).unwrap();

        assert_eq!(options.config, PathBuf::from("/tmp/policy.json"));
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
            "--max-connections-per-uid=0",
        ])
        .unwrap();

        assert_eq!(options.socket, PathBuf::from("/tmp/proxy.sock"));
        assert_eq!(options.upstream, PathBuf::from("/tmp/tpmrm0"));
        assert_eq!(options.max_packet_size, 8192);
        assert_eq!(options.queue_depth, 32);
        assert_eq!(options.max_connections_per_uid, 0);
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
