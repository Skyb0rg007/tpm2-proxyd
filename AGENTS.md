<!--
SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>

SPDX-License-Identifier: Apache-2.0
-->

# AGENTS.md

This file provides guidance to AI agents when working with code in this repository.
`CLAUDE.md` is a symlink to this file.

## What this is

`tpm2-proxyd` is a Linux system service implementing a TPM Command Transmission
Interface (TCTI) proxy. It sits between downstream clients and an upstream TPM:
it inspects each TPM command, checks it against a configurable per-user access
and permission policy, and conditionally forwards it upstream. The goal is
fine-grained per-user access to a physical TPM, analogous to Windows TBS.

Critical distinction: this is **not** a TPM Access Broker / Resource Manager
(TAB/RM). It does no resource virtualization or context swapping. Downstream
clients reach the physical TPM through the kernel resource manager
(`/dev/tpmrm0`); this proxy only does access control and scheduling on top of
that. Don't add resource-manager responsibilities here.

The MVP pipeline is implemented and verified end to end (`tpm2_getrandom` →
TCTI module → daemon → `/dev/tpmrm0`). Current work is on richer policy: see
the "Policy" section below.

See `docs/design.md` for the architecture, the request pipeline, and the
scheduling model (the TPM is serial, so the daemon serializes and prioritizes
client access; commands are never preempted).

## Workspace layout

A Cargo workspace (virtual root `Cargo.toml`, `default-members` is only the
daemon) with crates under `crates/`:

- `crates/tpm2-proxyd` — the daemon (see below).
- `crates/tcti` — package `tss2-tcti-proxy`, a `cdylib` (plus `rlib` for
  tests). The downstream side: a C-ABI TCTI module loaded by tpm2-tss's
  dynamic loader (`tctildr`) into client processes. It forwards the raw TPM
  command/response byte stream to the daemon over a Unix socket (path from the
  TCTI config string, default `/run/tpm2-proxyd/tpm2-proxyd.sock`).

### The daemon (`crates/tpm2-proxyd/src/`)

Request flow (also drawn in `main.rs`'s module docs):
`server` (accept, `SO_PEERCRED`/`SO_PEERGROUPS` peer identity, connection
registry) →
`broker` (caps priority at admission, authorizes each command against `policy`,
logs admissions and denials)
→ `scheduler` (single worker, priority-ordered, one TPM transaction at a time,
per-client sessions) → `upstream` (the TPM).

- One Unix socket (default `/run/tpm2-proxyd/tpm2-proxyd.sock`) speaking a
  custom binary protocol: each connection opens with a 12-byte hello
  (`server/hello.rs`: magic, version, flags, requested priority; the reply
  carries a status and the policy-capped priority granted), then
  carries the raw, self-framing TPM command/response stream. There is no
  control interface; don't add Varlink or D-Bus. New per-connection options go
  in the hello's flags. The hello is spelled out in `docs/design.md`.
- Upstreams: `TpmDeviceUpstream` (`/dev/tpmrm0` via `tpm2-device`, the
  default) and `upstream/swtpm.rs` (`--swtpm-server=<addr>`, optional
  `--swtpm-ctrl=<addr>`), used by the end-to-end tests.
- The `/dev/tpmrm0` leg uses `tpm2-device`'s `TpmPosixDevice` through its raw
  `TpmTransport` interface (`send`/`recv`): command bytes go out unchanged and
  the TPM's response bytes, error responses included, come back unchanged.
  Keep using `tpm2-device` for this rather than a hand-rolled `File`
  transport. `TpmPosixDevice` is `!Send` and blocks, so all of them live on one
  dedicated worker thread behind a `Send` channel handle.
- Each client gets its own `/dev/tpmrm0` handle: `Broker::admit` opens a
  scheduler `Session`, commands carry its `SessionId`, and dropping the session
  (on disconnect) closes the handle, so the kernel RM isolates clients and
  flushes whatever they leave loaded. Don't go back to one shared fd: abandoned
  objects pile up and exhaust the kernel RM's 3-objects-per-fd limit. The swtpm
  upstream can't isolate sessions and ignores them.
- `lockout.rs` counts `TPM_RC_AUTH_FAIL` responses (the ones that count
  toward the TPM's dictionary-attack lockout) in total and per UID, and logs
  them, warning past `--auth-failure-warn-threshold`. A UID's count also
  includes `TPM_RC_BAD_AUTH` from commands naming a hierarchy, which the TPM
  doesn't rate-limit. The broker's `LockoutGuard` checks and records in the
  scheduler worker, around each transaction, so concurrent commands can't
  race past `--auth-failure-limit`; at the limit every command from the UID is
  refused (`TPM_RC_LOCKOUT` in the resource-manager layer).
  Counts recover like the TPM's: one failure per
  `--auth-failure-recovery-secs`, applied lazily when a count is read or
  updated. They're in memory only.
- `systemd` provides socket activation, `sd_notify` readiness, and watchdog.
  `SIGHUP` re-reads the policy file and its profiles and swaps them in
  atomically.

### Policy

- **Current:** `policy.json` (`policy.rs`, example
  `dist/policy.example.json`) gives each peer a profile name and a priority cap
  through first-match rules on UID/GID, with `default_profile` and
  `default_max_priority` as the fallback. A profile (`profile.rs`) is
  `profiles/<name>.json` beside the policy file: allowed commands plus the
  handles they may reference in their handle area, by `TPM_HT_*` type or
  `TPM_RH_*` handle, optionally per command, all named as the spec spells them.
  **No profiles are built into the binary**; `dist/profiles/standard.json` is
  installed with the service. Keep it that way.
- The handle check relies on the per-client `/dev/tpmrm0` fd: the kernel RM
  already isolates transient objects, so profiles only need to keep users away
  from shared state (persistent handles, NV, hierarchies, PCRs, clock, DA).
  Don't add in-memory ownership tracking for transient handles. Sessions are
  the exception: the kernel doesn't virtualize their handles and forgets a
  session the client saves, which then holds a TPM session slot until reset,
  so `standard` only allows `ContextSave` on transient handles. And since any
  client can name any session, the broker tracks each connection's sessions
  and refuses `FlushContext` of anyone else's.
- A denied command gets a header-only response with a TPM-format code in the
  resource-manager layer (`Denial::response_code`: `TPM_RC_COMMAND_CODE`, or
  `TPM_RC_HANDLE` + position) and the connection stays open. tpm2-tss decodes
  layer 11 as TPM-format ("rmt"), which is why it's not a TSS-format
  `TSS2_RESMGR_RC_NOT_PERMITTED`.
- **Planned:** `docs/policy-language.md` (declarative, default-deny YAML policy
  language) and `dist/policy.safe-limited.yaml` (an example in it). Supporting
  analysis is in `docs/command-policy.md`, `docs/unprivileged-command-policy.md`
  and `docs/tpm2-protocol-commands.md`.

### The TCTI module (`crates/tcti/src/lib.rs`)

The whole C ABI is reimplemented in Rust `#[repr(C)]` structs (`abi` module),
mirroring `references/tpm2-tss/include/tss2/tss2_tcti.h` — there is no C code or
`bindgen`. If you change a struct/signature, re-check it against that header.

- Exported symbol: `Tss2_Tcti_Info` → `&'static TctiInfo`. This is what the
  loader resolves (`TSS2_TCTI_INFO_SYMBOL`).
- Context is a V2 context (`magic`, `version`, then the 8 function pointers);
  the common ABI block MUST stay first in `ProxyContext` so the loader's
  pointer offsets line up. The caller allocates the context, so it stays POD —
  store the socket as a `RawFd`, not an owned `UnixStream`.
- `init` is two-phase: `ctx == NULL` reports `*size`; otherwise it initializes
  in place, connects the socket, and exchanges the hello; a refused hello fails
  `init`. A TRANSMIT/RECEIVE state machine mirrors tpm2-tss's `tcti-common`.
- The wire protocol (the hello, then the raw TPM byte stream) must stay in sync
  with the daemon (`server/hello.rs`, `server/connection.rs`). The e2e test
  `tcti_module_round_trips_through_the_proxy` drives this module against the
  real daemon to catch drift.

Cargo emits `libtss2_tcti_proxy.so` (underscores). The loader searches for
`libtss2-tcti-<name>.so`, so install/symlink it as `libtss2-tcti-proxy.so` to
load by name (`--tcti=proxy:<sockpath>`); a full path works regardless.

### Packaging (`dist/`)

systemd `.service`/`.socket` units, a sysusers file, the man page source
(`tpm2-proxyd.8.adoc`, built with asciidoctor), the default policy
(`policy.example.json`, installed as `/etc/tpm2-proxyd/policy.json`) and
profiles (`profiles/`, installed to `/etc/tpm2-proxyd/profiles/`), `install.sh`,
and `smoke-test.sh` (a live test against the host TPM that runs a key workflow
under the `standard` profile; see `docs/smoke-test.md`).

The raw socket is `tss:tss 0666`: any local user may connect, and the daemon's
policy decides per connection. Never gate clients by the `tss` group; its
members can open `/dev/tpmrm0` directly and bypass the policy.

## Key dependencies (and why they matter for architecture)

- `tpm2-protocol` / `tpm2-device` — crates.io crates from the
  `jarkkojs/tpm2-library` GitHub monorepo (formerly the `tpm-protocol` GitLab
  group, now gone). `tpm2-protocol` provides TPM marshalling and the command views
  the daemon uses to inspect traffic; `tpm2-device` is the `/dev/tpmrm0`
  transport. Bump them together (`tpm2-device` depends on `tpm2-protocol`).
- `tokio` — async runtime for handling concurrent downstream connections.

## Reference material

`references/` contains read-only upstream source checkouts and notes for
consultation, not part of the build. It is excluded from git by
`.git/info/exclude`.

- `references/tpm2-library/` — the upstream monorepo
  (https://github.com/jarkkojs/tpm2-library), checked out at the tag matching
  `Cargo.lock`. Its `crates/` holds the sources of the dependencies above
  (`protocol/`, `device/`) and their siblings: `crypto/` (TPM crypto
  routines), `vtpm/` (a saved-context cache), `policy-language/` (a TPM policy
  expression language), `tpmkey/` (TPM 2.0 key ASN.1 files), and `sh/`
  (`tpm2sh`, a CLI that is the model for integrating
  `tpm2-protocol`/`tpm2-device`).
- `references/tpm-rs/` — the `tpm-rs` project (formerly a dependency, no longer
  used); `docs/coding-style.md` has its conventions.
- `references/tpm2-abrmd/` — the C resource-manager broker; the closest prior art
  for the daemon/IPC/connection-management design (note: it uses D-Bus).
- `references/tpm2-tss/` — the reference TSS/TCTI implementation; authoritative
  for TCTI semantics.
- `references/tbs-design.md` — TBS-inspired policy requirements.
- `references/tpm2-tools-workflows.{md,sh}` and
  `references/tpm2-tools-workflows.observed.md` — common tpm2-tools workflows,
  a script to capture their TPM command sequences, and the observed results.
- `references/todo.md` — the MVP release todo list.
- `references/systemd-memory-pressure.html` — systemd's memory pressure
  handling spec.
- `references/conventional-commits.md` — the commit message convention
  (enforced by commitlint).

Any additional references obtained from the network should be added to this
directory and listed here.

## Build, test, format

The development environment is a Nix flake (`nix develop`, or direnv). It
provides `swtpm`, which the end-to-end tests need on `PATH`.

```sh
cargo build --workspace          # --workspace is needed to build the TCTI .so
cargo test --workspace           # all tests (CI uses `cargo nextest run --workspace`)
cargo test <name>                # single test by name substring
cargo clippy --workspace --all-targets -- -D warnings
cargo run -- --help
nix build                        # package build (nix/tpm2-proxyd.nix)
```

A plain `cargo build` only builds `default-members` (the daemon), not the TCTI
`cdylib`; forgetting `--workspace` shows up as a `dlopen` "cannot open shared
object file" error.

Tests: in-crate unit tests, `crates/tpm2-proxyd/src/server/smoke.rs` (full
server stack over a real Unix socket with a fake upstream),
`crates/tpm2-proxyd/tests/e2e.rs` (real client → daemon → fresh swtpm per
test), and `tests/apps/` (shell scripts driving tpm2-openssl and
tpm2-pkcs11 + OpenSSH through the daemon under the `standard` profile; they fail
on any denial). The app tests need a kernel RM upstream, not swtpm: the apps
leave objects loaded on exit and swtpm runs out of slots. Run them with
`nix develop .#apps --command tests/apps/run.sh` (host `/dev/tpmrm0`) or the
`app-tests` flake check (NixOS VM with a vTPM; needs KVM; not in CI). Keep them
from failing authorizations against a real TPM: that counts toward its
dictionary-attack lockout.

The Nix package reads `Cargo.lock` directly (`cargoLock.lockFile`), so there is
no vendor hash to refresh when dependencies change.

## Commits and pre-commit checks

Commit messages follow Conventional Commits (`.commitlintrc.mjs`).

AI-assisted commits end with an `Assisted-by:` trailer naming the model ID,
e.g. `Assisted-by: claude-opus-5-5`. Don't add `Co-Authored-By:` or
`Claude-Session:` trailers.

`.pre-commit-config.yaml` enforces (run `pre-commit run --all-files`); CI
(`.github/workflows/ci.yml`) runs build, nextest, clippy, `treefmt --ci`, and
`reuse lint`:
- `treefmt` — multiplexes `rustfmt` (`*.rs`) and `nixfmt` (`*.nix`). Note
  `.rustfmt.toml` sets `skip_children = true` and `edition = 2024`.
- `reuse lint` — every file must carry SPDX license/copyright headers
  (Apache-2.0). New files need the SPDX header block; files that can't carry
  one inline are annotated in `REUSE.toml`.
- `editorconfig-checker` — see `.editorconfig` (LF, final newline, no trailing
  whitespace; 2-space indent for `*.nix`).
