// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! Command-line argument parsing for the daemon.

use std::{path::PathBuf, str::FromStr};

use clap::Parser;

/// Default policy configuration file path.
const DEFAULT_CONFIG_PATH: &str = "/etc/tpm2-proxyd/policy.json";
/// Default client socket path.
const DEFAULT_SOCKET_PATH: &str = "/run/tpm2-proxyd/tpm2-proxyd.sock";
/// Default upstream Linux TPM resource-manager device.
const DEFAULT_UPSTREAM_TPM_PATH: &str = "/dev/tpmrm0";
/// Default number of commands that may wait for the upstream worker.
const DEFAULT_QUEUE_DEPTH: usize = 64;
/// Default cap on concurrent connections from one UID.
const DEFAULT_MAX_CONNECTIONS_PER_UID: usize = 16;
/// Default cap on concurrent downstream connections in total. Each holds a
/// socket and, once it sends a command, a `/dev/tpmrm0` handle, so this keeps
/// the daemon's file descriptors well within its open-file limit.
const DEFAULT_MAX_CONNECTIONS: usize = 1024;
/// Default hard per-command timeout, in seconds.
const DEFAULT_COMMAND_TIMEOUT_SECS: u64 = 120;

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
    /// swtpm control socket. When set, the TPM is reset on startup (CMD_INIT
    /// followed by TPM2_Startup); otherwise commands go straight through to an
    /// already-started swtpm.
    #[arg(long, require_equals = true, value_name = "ADDR")]
    pub swtpm_ctrl: Option<String>,
    /// Maximum accepted TPM command or response size.
    #[arg(
        long,
        require_equals = true,
        value_name = "BYTES",
        default_value_t = crate::tpm::DEFAULT_MAX_PACKET_SIZE,
        value_parser = parse_positive::<usize>
    )]
    pub max_packet_size: usize,
    /// Size of the buffer of TPM commands on their way to the scheduler.
    #[arg(
        long,
        require_equals = true,
        value_name = "COUNT",
        default_value_t = DEFAULT_QUEUE_DEPTH,
        value_parser = parse_positive::<usize>
    )]
    pub queue_depth: usize,
    /// Maximum number of concurrent downstream connections (0 = unlimited).
    #[arg(
        long,
        require_equals = true,
        value_name = "COUNT",
        default_value_t = DEFAULT_MAX_CONNECTIONS,
    )]
    pub max_connections: usize,
    /// Maximum number of concurrent downstream connections from one UID
    /// (0 = unlimited).
    #[arg(
        long,
        require_equals = true,
        value_name = "COUNT",
        default_value_t = DEFAULT_MAX_CONNECTIONS_PER_UID,
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
    )]
    pub auth_failure_warn_threshold: u64,
    /// Number of authorization failures toward the TPM's dictionary-attack
    /// lockout after which a UID's commands are all refused until its failures
    /// recover (0 = unlimited).
    #[arg(
        long,
        require_equals = true,
        value_name = "COUNT",
        default_value_t = crate::lockout::DEFAULT_UID_LIMIT,
    )]
    pub auth_failure_limit: u64,
    /// Seconds for each authorization failure count to forget one failure,
    /// like the TPM's lockout interval (0 = never recover).
    #[arg(
        long,
        require_equals = true,
        value_name = "SECONDS",
        default_value_t = crate::lockout::DEFAULT_RECOVERY_INTERVAL.as_secs(),
    )]
    pub auth_failure_recovery_secs: u64,
    /// Hard per-command timeout, in seconds.
    #[arg(
        long,
        require_equals = true,
        value_name = "SECONDS",
        default_value_t = DEFAULT_COMMAND_TIMEOUT_SECS,
        value_parser = parse_positive::<u64>
    )]
    pub command_timeout_secs: u64,
}

fn parse_path(value: &str) -> Result<PathBuf, String> {
    if value.is_empty() {
        Err("path must not be empty".into())
    } else {
        Ok(PathBuf::from(value))
    }
}

fn parse_positive<T: FromStr + Default + PartialOrd>(value: &str) -> Result<T, String> {
    value
        .parse()
        .ok()
        .filter(|value| *value > T::default())
        .ok_or_else(|| "value must be a positive integer".into())
}

#[cfg(test)]
mod tests {
    use clap::error::ErrorKind;

    use super::*;

    fn parse(args: &[&str]) -> clap::error::Result<Options> {
        Options::try_parse_from(std::iter::once("tpm2-proxyd").chain(args.iter().copied()))
    }

    #[test]
    fn parses_runtime_overrides() {
        let options = parse(&[
            "--config=/tmp/policy.json",
            "--socket=/tmp/proxy.sock",
            "--upstream=/tmp/tpmrm0",
            "--max-packet-size=8192",
            "--queue-depth=32",
            "--max-connections-per-uid=0",
        ])
        .unwrap();

        assert_eq!(options.config, PathBuf::from("/tmp/policy.json"));
        assert_eq!(options.socket, PathBuf::from("/tmp/proxy.sock"));
        assert_eq!(options.upstream, PathBuf::from("/tmp/tpmrm0"));
        assert_eq!(options.max_packet_size, 8192);
        assert_eq!(options.queue_depth, 32);
        assert_eq!(options.max_connections_per_uid, 0);
    }

    #[test]
    fn rejects_malformed_arguments() {
        let cases = [
            (&["--config", "/tmp/policy.json"][..], ErrorKind::NoEquals),
            (
                &["--socket=/tmp/one.sock", "--socket=/tmp/two.sock"],
                ErrorKind::ArgumentConflict,
            ),
            (&["--queue-depth=0"], ErrorKind::ValueValidation),
            (&["--command-timeout-secs=0"], ErrorKind::ValueValidation),
            (&["--config="], ErrorKind::ValueValidation),
        ];
        for (args, kind) in cases {
            assert_eq!(parse(args).unwrap_err().kind(), kind, "{args:?}");
        }
    }
}
