<!--
SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>

SPDX-License-Identifier: Apache-2.0
-->

# Changelog

## 0.1.0 (unreleased)

The first release: per-user access control for a local TPM 2.0, in front of the
kernel resource manager (`/dev/tpmrm0`).

- **Daemon** (`tpm2-proxyd`): accepts clients on a Unix socket, identifies each
  by `SO_PEERCRED`/`SO_PEERGROUPS`, checks every command against its policy, and
  forwards allowed commands to the TPM one at a time in priority order. Each
  client gets its own `/dev/tpmrm0` handle, so the kernel resource manager
  isolates clients' transient objects and sessions and flushes them on
  disconnect.
- **TCTI module** (`libtss2-tcti-proxy.so`): lets any tpm2-tss client, such as
  tpm2-tools, talk to the daemon with `--tcti=proxy:<socket>` or
  `--tcti=proxy:path=<socket>,priority=<n>`.
- **Policy**: `/etc/tpm2-proxyd/policy.json` gives each user or group a profile
  and a priority cap. Profiles (`/etc/tpm2-proxyd/profiles/<name>.json`) list
  the allowed commands and the handles they may reference. The `standard`
  profile, installed by default, covers unprivileged key, sealing, signing and
  attestation workflows while keeping users away from state they share:
  persistent handles, NV indices, hierarchies and PCR values. `SIGHUP` reloads
  the policy and profiles.
- **Denials** return a TPM error response in the resource-manager layer and
  leave the connection open, and are logged with the peer's UID and PID.
- **Lockout tracking**: authorization failures that count toward the TPM's
  dictionary-attack lockout are counted in total and per user and logged, with
  a warning once the total reaches `--auth-failure-warn-threshold` (default
  10).
- **Limits**: a hard per-command timeout (`--command-timeout-secs`), and caps on
  connections in total (`--max-connections`) and per user
  (`--max-connections-per-uid`, default 16).
- **Packaging**: systemd socket and service units with socket activation,
  readiness and watchdog; a sysusers file; a man page; `dist/install.sh`.

Known limitations:

- A user can push the TPM into dictionary-attack lockout by repeatedly failing
  authorization for their own DA-protected objects. The proxy logs these
  failures but doesn't prevent them.
- Saved context files are possession-based: another user who obtains one can
  load it, although using the object still needs its authorization.
- Commands the proxy doesn't recognize, including vendor commands, close the
  connection instead of getting an error response.
