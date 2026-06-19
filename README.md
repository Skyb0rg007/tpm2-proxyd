<!--
SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>

SPDX-License-Identifier: Apache-2.0
-->

# TPM2 Proxy Broker

`tpm2-proxyd` is a Linux system service that implements a TPM Command
Transmission Interface ([TCTI][]) proxy. It inspects TPM commands from
downstream clients, checks them against a configurable per-user access and
permission list, schedules access to the (serial) TPM, and conditionally
forwards them to an upstream TCTI.

The primary use is fine-grained per-user access to a physical TPM, similar to how
Windows's [TBS][] works.

Note: this service is **not** a [TPM Access Broker][TAB]. Downstream clients
still reach the physical TPM through the Linux kernel resource manager
(`/dev/tpmrm0`, recommended) or the userland [tpm2-abrmd][]; this proxy only adds
access control on top. It acts as a firewall in front of the TPM: commands whose
code it does not recognize (including vendor-specific command codes) are rejected
before forwarding.

## How it fits together

```text
  client ──libtss2-tcti-proxy.so──▶ /run/tpm2-proxyd/tpm2-proxyd.sock
                                        │  (tpm2-proxyd: policy + scheduling)
                                        ▼
                                    /dev/tpmrm0
```

- **Daemon** (`tpm2-proxyd`): opens `/dev/tpmrm0`, serves a raw TPM Unix socket,
  enforces policy, and forwards allowed commands. It also serves a Varlink
  control socket for status/reload.
- **TCTI module** (`libtss2-tcti-proxy.so`): loaded into client processes by
  tpm2-tss's dynamic loader; forwards the raw command/response byte stream to the
  daemon socket.

## Building

A Nix dev shell provides the toolchain and dependencies:

```sh
nix-shell --run "cargo build --release"
```

This produces `target/release/tpm2-proxyd` and
`target/release/libtss2_tcti_proxy.so`.

## Installing

```sh
sudo ./dist/install.sh
```

The script installs the daemon, the TCTI module (renamed to the loader's
expected `libtss2-tcti-proxy.so`), the systemd units, a system user, a man page,
and an example policy at `/etc/tpm2-proxyd/policy.json`. Then:

```sh
# Add users who may reach the proxy to the socket group (default: tss):
sudo usermod -aG tss alice
sudo systemctl enable --now tpm2-proxyd.socket
```

The `tpm2-proxyd.socket` unit owns the listening socket (`0660`, group `tss`); the
daemon starts on first connection via socket activation. Edit
`SocketGroup=`/`SupplementaryGroups=` in the units to match your distribution's
TPM group.

## Configuring policy

Policy is a JSON file (default `/etc/tpm2-proxyd/policy.json`). Rules grant
specific TPM command codes (decimal `TPM_CC` values; an empty list means *all*
commands) to a UID or GID, and cap the scheduling priority that peer may receive.
The default decision is **deny**.

```json
{
  "users": [
    { "uid": 1000, "commands": [379, 378], "priority": 5 }
  ],
  "groups": [
    { "gid": 1001, "commands": [], "priority": 1 }
  ]
}
```

`379`/`378` are `TPM_CC_GetRandom` / `TPM_CC_GetCapability`. Reload after editing
without dropping connections:

```sh
sudo systemctl reload tpm2-proxyd      # or: kill -HUP <pid>
```

Already-connected clients keep their previously capped priority; subsequent
commands use the new policy.

## Using it from a client

Point any tpm2-tss client at the proxy TCTI:

```sh
tpm2_getrandom --tcti=proxy:/run/tpm2-proxyd/tpm2-proxyd.sock 8
# or, once libtss2-tcti-proxy.so is on the loader search path:
export TPM2TOOLS_TCTI=proxy:/run/tpm2-proxyd/tpm2-proxyd.sock
```

## Using swtpm instead of a hardware TPM

For development and testing, the proxy can talk to a [swtpm][] software TPM over
its socket interface instead of `/dev/tpmrm0`:

```sh
swtpm socket --tpm2 --tpmstate dir=/tmp/swtpm \
  --server type=unixio,path=/tmp/swtpm/sock \
  --ctrl type=unixio,path=/tmp/swtpm/sock.ctrl --flags startup-clear &

tpm2-proxyd --config=policy.json --socket=/tmp/proxy.sock \
  --swtpm-server=unix:/tmp/swtpm/sock
```

`--swtpm-server` accepts `unix:<path>`, `tcp:<host:port>`, a path, or
`host:port`. Pass `--swtpm-ctrl=<addr>` to have the proxy reset and start the
swtpm itself (CMD_INIT + `TPM2_Startup`) on launch; otherwise start swtpm with
`--flags startup-clear` so the TPM is already up. `dist/smoke-test.sh` exercises
this whole path.

[swtpm]: https://github.com/stefanberger/swtpm

## Command-line options

See `tpm2-proxyd --help` or `man 8 tpm2-proxyd`. Common options:
`--config`, `--socket`, `--control-socket` (empty to disable), `--upstream`,
`--swtpm-server`/`--swtpm-ctrl`, `--max-connections`, `--command-timeout-secs`.
Logging is controlled by `RUST_LOG` (default `info`).

## Control interface

The Varlink interface `website.soss.Tpm2Proxyd` (default socket
`/run/tpm2-proxyd/website.soss.Tpm2Proxyd`) exposes `GetStatus`,
`ListConnections`, and `ReloadPolicy`. For example, with `varlink`:

```sh
varlink call /run/tpm2-proxyd/website.soss.Tpm2Proxyd/website.soss.Tpm2Proxyd.GetStatus '{}'
```

## Development

```sh
nix-shell --run "cargo test --workspace"
nix-shell --run "pre-commit run --all-files"   # treefmt, reuse, editorconfig
```

See `docs/design.md` for the architecture conventions.

[TCTI]: https://trustedcomputinggroup.org/resource/tss-tcti-specification/
[TBS]: https://learn.microsoft.com/en-us/windows/win32/tbs/tpm-base-services-portal
[TAB]: https://trustedcomputinggroup.org/resource/tss-tab-and-resource-manager/
[tpm2-abrmd]: https://github.com/tpm2-software/tpm2-abrmd
