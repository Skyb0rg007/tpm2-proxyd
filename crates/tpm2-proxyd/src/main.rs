// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! `tpm2-proxyd` — the TPM2 Proxy Broker daemon.
//!
//! The daemon sits between downstream TCTI clients and the upstream Linux TPM
//! resource manager (`/dev/tpmrm0`). It inspects each TPM command, enforces a
//! configurable per-user access/permission policy, schedules access to the
//! serial TPM, and forwards allowed commands upstream. See `CLAUDE.md` and
//! `docs/design.md`.
//!
//! It serves one Unix socket (default `/run/tpm2-proxyd/tpm2-proxyd.sock`).
//! Each connection opens with a hello (see `server::hello`), then carries the
//! self-framing TPM command/response byte stream from the downstream
//! `tss2-tcti-proxy` module.
//!
//! Request flow:
//!
//! ```text
//!   client ──socket──▶ server ──▶ broker ──inspect──────────▶ tpm
//!                                   ├──authorize──────────▶ policy
//!                                   ├──acquire (priority)─▶ scheduler
//!                                   └──forward────────────▶ upstream ──▶ TPM
//! ```
//!
//! `cli` supplies settings, `policy` loads the policy file, and `systemd` provides socket
//! activation, readiness, and watchdog integration. `SIGHUP` reloads the policy.

/// Core proxy pipeline and shared runtime state: inspect → authorize → forward.
mod broker;
/// Command-line argument parsing.
mod cli;
/// Tracking of authorization failures toward the TPM's lockout.
mod lockout;
/// Per-UID limits on the log lines a client can trigger at will.
mod log_limit;
/// Access-control rule model, policy file loading, and evaluation engine.
mod policy;
/// Command profiles loaded from the profiles directory.
mod profile;
/// Non-preemptive upstream TPM command scheduler.
mod scheduler;
/// Downstream Unix-socket listener and per-connection handling.
mod server;
/// Systemd socket activation, readiness, and watchdog integration.
mod systemd;
/// TPM command/response inspection.
mod tpm;
/// Upstream client that talks to the physical TPM's resource manager.
mod upstream;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::Context;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::watch;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ExitCode {
    // Parse before installing the logger so clap handles --help/--version/usage
    // errors itself, with the right exit codes, rather than logging them.
    let options = cli::Options::parse_env().unwrap_or_else(|error| error.exit());

    init_tracing();
    match run(options).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(error = format!("{error:#}"), "tpm2-proxyd failed");
            let _ = systemd::sd_notify(&format!("STATUS=failed: {error}"));
            ExitCode::FAILURE
        }
    }
}

async fn run(options: cli::Options) -> anyhow::Result<()> {
    let policy = policy::Policy::load(&options.config)?;

    let (scheduler, upstream_label) = start_scheduler(&options).await?;
    let broker = broker::Broker::new(
        policy,
        scheduler,
        lockout::AuthFailures::new(
            options.auth_failure_warn_threshold,
            options.auth_failure_limit,
            Duration::from_secs(options.auth_failure_recovery_secs),
        ),
    );
    let registry = server::registry::ConnectionRegistry::new(
        options.max_connections,
        options.max_connections_per_uid,
    );

    raise_open_file_limit(options.max_connections);
    let (listener, origin) = server::unix::RawTpmListener::from_systemd_or_bind(&options.socket)
        .with_context(|| format!("binding raw TPM socket {}", options.socket.display()))?;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    spawn_signal_handlers(shutdown_tx, broker.clone(), options.config.clone())?;
    spawn_watchdog();

    let _ = systemd::sd_notify("READY=1");
    tracing::info!(
        socket = %options.socket.display(),
        upstream = upstream_label,
        "tpm2-proxyd ready",
    );

    let result = server::connection::serve_listener(
        listener,
        broker,
        registry,
        options.max_packet_size,
        shutdown_rx,
    )
    .await
    .context("serving TPM socket");

    let _ = systemd::sd_notify("STOPPING=1");
    // Under socket activation systemd owns the path and keeps listening on it
    // across restarts, so only remove a socket the daemon bound itself.
    if origin == server::unix::SocketOrigin::Bound {
        let _ = std::fs::remove_file(&options.socket);
    }
    tracing::info!("tpm2-proxyd stopped");

    result
}

/// File descriptors kept free for everything but client connections: the
/// listener, the upstream, logging, systemd's notify socket.
const RESERVED_FDS: u64 = 64;

/// Raise the soft open-file limit to the hard limit, and warn if it still
/// can't cover `max_connections` (0 = unlimited). Each connection holds its
/// socket and, once it sends a command, its own `/dev/tpmrm0` handle; running
/// out stops the daemon accepting anyone. systemd's default soft limit is
/// 1024, against a much higher hard limit, and the daemon doesn't use
/// `select(2)`, so it has no reason to stay under the soft one.
fn raise_open_file_limit(max_connections: usize) {
    use rustix::process::{Resource, getrlimit, setrlimit};

    let mut limit = getrlimit(Resource::Nofile);
    if limit.current != limit.maximum {
        limit.current = limit.maximum;
        if let Err(error) = setrlimit(Resource::Nofile, limit) {
            tracing::warn!(%error, "failed to raise the open-file limit");
        }
    }
    // `None` is unlimited.
    let Some(soft) = getrlimit(Resource::Nofile).current else {
        return;
    };
    let needed = (max_connections as u64)
        .saturating_mul(2)
        .saturating_add(RESERVED_FDS);
    if max_connections == 0 || soft < needed {
        tracing::warn!(
            open_file_limit = soft,
            max_connections,
            "the open-file limit may run out before the connection limit is reached"
        );
    }
}

/// Open the configured upstream (swtpm socket or kernel TPM device) and start
/// the command scheduler. Returns the scheduler and a label for logging.
async fn start_scheduler(
    options: &cli::Options,
) -> anyhow::Result<(scheduler::CommandScheduler, String)> {
    if let Some(server) = &options.swtpm_server {
        let server = upstream::swtpm::SwtpmAddr::parse(server);
        let control = options
            .swtpm_ctrl
            .as_deref()
            .map(upstream::swtpm::SwtpmAddr::parse);
        let label = format!("swtpm {server}");
        let upstream = upstream::swtpm::SwtpmUpstream::open(
            server,
            control,
            options.max_packet_size,
            options.command_timeout(),
        )
        .await
        .with_context(|| format!("connecting to {label}"))?;
        Ok((
            scheduler::CommandScheduler::start(upstream, options.queue_depth),
            label,
        ))
    } else {
        let upstream = upstream::TpmDeviceUpstream::open(
            &options.upstream,
            options.max_packet_size,
            options.command_timeout(),
        )
        .with_context(|| format!("opening upstream TPM device {}", options.upstream.display()))?;
        Ok((
            scheduler::CommandScheduler::start(upstream, options.queue_depth),
            options.upstream.display().to_string(),
        ))
    }
}

/// Install a `tracing` subscriber driven by `RUST_LOG` (default `info`).
fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}

/// Spawn SIGTERM/SIGINT (shutdown) and SIGHUP (policy reload) handlers.
fn spawn_signal_handlers(
    shutdown: watch::Sender<bool>,
    broker: broker::Broker,
    config_path: PathBuf,
) -> anyhow::Result<()> {
    let mut sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
    let mut sigint = signal(SignalKind::interrupt()).context("installing SIGINT handler")?;
    tokio::spawn(async move {
        let signal = tokio::select! {
            _ = sigterm.recv() => "SIGTERM",
            _ = sigint.recv() => "SIGINT",
        };
        tracing::info!(signal, "shutting down");
        let _ = shutdown.send(true);
    });

    let mut sighup = signal(SignalKind::hangup()).context("installing SIGHUP handler")?;
    tokio::spawn(async move {
        while sighup.recv().await.is_some() {
            tracing::info!("received SIGHUP; reloading policy");
            match reload_policy(&broker, &config_path) {
                Ok(generation) => tracing::info!(generation, "policy reloaded"),
                Err(error) => tracing::error!(error = format!("{error:#}"), "policy reload failed"),
            }
        }
    });

    Ok(())
}

/// Re-read the policy file and atomically swap it in, returning the new
/// policy generation.
fn reload_policy(broker: &broker::Broker, config_path: &Path) -> anyhow::Result<u64> {
    let policy = policy::Policy::load(config_path)?;
    Ok(broker.replace_policy(policy))
}

/// Spawn the systemd watchdog keep-alive task, if a watchdog is configured.
fn spawn_watchdog() {
    let Ok(Some(timeout)) = systemd::sd_watchdog_enabled() else {
        return;
    };
    // Ping at half the watchdog interval, as recommended by `sd_watchdog_enabled(3)`.
    let interval = Duration::from_micros(timeout.get() / 2);
    tracing::info!(?interval, "systemd watchdog enabled");
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            let _ = systemd::sd_notify("WATCHDOG=1");
        }
    });
}
