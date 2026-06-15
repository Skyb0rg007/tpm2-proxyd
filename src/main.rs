// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: BSD-2-Clause

//! `tpm2-proxyd` — the TPM2 Proxy Broker daemon.
//!
//! The daemon sits between downstream TCTI clients and an upstream TCTI: it
//! reads raw TPM commands from clients, inspects them, enforces a configurable
//! per-user access/permission policy, and forwards allowed commands upstream to
//! the physical TPM's resource manager. See `CLAUDE.md` for the big picture and
//! the per-module docs below for each component's responsibility.
//!
//! The TPM is a serial, shared resource (one command at a time), so the broker
//! must also schedule client access — fair time slices and hard time limits —
//! before forwarding upstream. See `docs/design.md`.
//!
//! Request flow:
//!
//! ```text
//!   client ──unix socket──▶ server ──▶ broker ──inspect──────▶ tpm
//!                                          │
//!                                          ├──authorize──────▶ policy
//!                                          │
//!                                          ├──acquire slice──▶ scheduler
//!                                          │
//!                                          └──forward────────▶ upstream ──▶ TPM
//! ```
//!
//! `cli` and `config` supply settings, `management` exposes a Varlink control
//! interface, and `error`/`logging` are cross-cutting concerns.

/// Core proxy pipeline and shared runtime state: inspect → authorize → forward.
mod broker;
/// Command-line argument parsing.
mod cli;
/// On-disk configuration model and loading.
mod config;
/// Crate-wide error and result types.
mod error;
/// Tracing/log subscriber initialization.
mod logging;
/// Varlink (`zlink`) management interface.
mod management;
/// Access-control rule model and evaluation engine.
mod policy;
/// Upstream TPM access scheduler: time slices and time limits.
mod scheduler;
/// Downstream Unix-socket listener and per-connection handling.
mod server;
/// TPM command/response inspection (built on the `tpm2` crates).
mod tpm;
/// Upstream TCTI client (talks to the physical TPM's resource manager).
mod upstream;

// NOTE: minimal entry point so the crate still builds while the modules are
// scaffolding. Wiring comes later: parse CLI args (`cli`), initialize tracing
// (`logging`), load the configuration (`config`), construct the `scheduler` and
// `broker`, start the `management` interface, and run the `server` accept loop
// on a Tokio runtime.
fn main() {}
