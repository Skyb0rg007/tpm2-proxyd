// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: BSD-2-Clause

//! `tpm2-proxyd` — the TPM2 Proxy Broker daemon.
//!
//! The daemon sits between downstream TCTI clients and the upstream Linux TPM
//! resource manager (`/dev/tpmrm0`). It inspects each TPM command, enforces a
//! configurable per-user access/permission policy, schedules access to the
//! serial TPM, and forwards allowed commands upstream. See `CLAUDE.md` and
//! `docs/design.md`.
//!
//! It exposes two Unix sockets:
//!
//! - a **raw TPM socket** (default `/run/tpm2-proxyd/tpm2-proxyd.sock`) carrying
//!   the self-framing TPM command/response byte stream from the downstream
//!   `tss2-tcti-proxy` module, and
//! - a **Varlink control socket** (default
//!   `/run/tpm2-proxyd/website.soss.Tpm2Proxyd`) for status, connection listing,
//!   and policy reload.
//!
//! (The design's eventual single Varlink protocol-upgrade socket is blocked on
//! upstream `zlink` support; the raw socket is the interim TPM transport.)
//!
//! Request flow on the raw socket:
//!
//! ```text
//!   client ──raw TPM socket──▶ server ──▶ broker ──inspect──────────▶ tpm
//!                                 │           ├──authorize──────────▶ policy
//!                                 │           ├──acquire (priority)─▶ scheduler
//!                                 │           └──forward────────────▶ upstream ──▶ TPM
//!                                 └──control methods──▶ management (Varlink)
//! ```
//!
//! `cli` and `config` supply settings, `management` backs the Varlink control
//! methods, and `systemd` provides socket activation, readiness, and watchdog
//! integration.

/// Core proxy pipeline and shared runtime state: inspect → authorize → forward.
mod broker;
/// Command-line argument parsing.
mod cli;
/// On-disk configuration model and loading.
mod config;
/// Backend for the Varlink control interface.
mod management;
/// Access-control rule model and evaluation engine.
mod policy;
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
/// Varlink (`zlink`) protocol types and control service.
mod varlink;

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
    let policy = config::Config::load(&options.config)
        .with_context(|| format!("loading config {}", options.config.display()))?
        .policy();

    let upstream = upstream::TpmDeviceUpstream::open(
        &options.upstream,
        options.max_packet_size,
        options.command_timeout(),
    )
    .with_context(|| format!("opening upstream TPM device {}", options.upstream.display()))?;

    let scheduler = scheduler::CommandScheduler::start(upstream, options.queue_depth);
    let broker = broker::Broker::new(policy, scheduler);
    let registry = server::registry::ConnectionRegistry::new(options.max_connections);
    let management =
        management::Management::new(broker.clone(), registry.clone(), options.config.clone());

    let listener = server::unix::RawTpmListener::from_systemd_or_bind(&options.socket)
        .with_context(|| format!("binding raw TPM socket {}", options.socket.display()))?;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    spawn_signal_handlers(shutdown_tx, management.clone())?;
    spawn_watchdog();

    let control_socket = match options.control_socket() {
        Some(path) => {
            server::unix::prepare_socket_path(path)
                .with_context(|| format!("preparing control socket {}", path.display()))?;
            Some(path.to_path_buf())
        }
        None => {
            tracing::info!("Varlink control interface disabled");
            None
        }
    };

    let _ = systemd::sd_notify("READY=1");
    tracing::info!(
        socket = %options.socket.display(),
        upstream = %options.upstream.display(),
        "tpm2-proxyd ready",
    );

    let serve = server::connection::serve_listener(
        listener,
        broker,
        registry,
        options.max_packet_size,
        shutdown_rx,
    );

    // The Varlink server is not `Send`, so it runs on this task alongside the
    // listener rather than in a spawned task. A clean listener shutdown ends the
    // daemon; the control future is then dropped.
    let result = match control_socket {
        Some(path) => {
            tracing::info!(socket = %path.display(), "serving Varlink control interface");
            tokio::select! {
                served = serve => served.context("serving raw TPM socket"),
                control = varlink::run(path, management) => {
                    control.context("Varlink control service stopped")
                }
            }
        }
        None => serve.await.context("serving raw TPM socket"),
    };

    let _ = systemd::sd_notify("STOPPING=1");
    // The daemon owns the raw socket only when it bound the path itself; under
    // socket activation systemd owns it, so removal is best-effort.
    let _ = std::fs::remove_file(&options.socket);
    tracing::info!("tpm2-proxyd stopped");

    result
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
    management: management::Management,
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
            match management.reload() {
                Ok(generation) => tracing::info!(generation, "policy reloaded"),
                Err(error) => tracing::error!(error = format!("{error:#}"), "policy reload failed"),
            }
        }
    });

    Ok(())
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
