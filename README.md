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

- **Daemon** (`tpm2-proxyd`): opens `/dev/tpmrm0`, serves a Unix socket,
  enforces policy, and forwards allowed commands. `SIGHUP` reloads the policy.
- **TCTI module** (`libtss2-tcti-proxy.so`): loaded into client processes by
  tpm2-tss's dynamic loader; opens each connection with a hello, then forwards
  the raw command/response byte stream to the daemon socket. See
  `docs/design.md` for the protocol.

## Building

A Nix dev shell provides the toolchain and dependencies:

```sh
nix develop --command cargo build --release
```

This produces `target/release/tpm2-proxyd` and
`target/release/libtss2_tcti_proxy.so`.

Build the Nix package itself with `nix build`, or run the daemon directly with
`nix run -- --help`.

## Installing

```sh
sudo ./dist/install.sh
```

The script installs the daemon, the TCTI module (renamed to the loader's
expected `libtss2-tcti-proxy.so`), the systemd units, a system user, a man page,
and an example policy at `/etc/tpm2-proxyd/policy.json`. Then:

```sh
sudo systemctl enable --now tpm2-proxyd.socket
```

The `tpm2-proxyd.socket` unit owns the listening socket (`tss:tss`, mode
`0666`), and the daemon starts on first connection via socket activation. Any
local user may connect; the policy then decides, per connection, what that peer
may run, and peers that match no rule are denied everything. Do **not** add
proxy users to `tss`: members of the TPM device group can open `/dev/tpmrm0`
directly and bypass the proxy's policy. If your distribution's TPM group is not
`tss`, edit `SupplementaryGroups=` in the service unit (and the socket's owner)
to match.

## Configuring policy

Policy is a JSON file (default `/etc/tpm2-proxyd/policy.json`) with two ordered
rule lists. Each rule's `subject` matches a `uid`, a `gid` (primary or
supplementary), both, or, if empty, every peer.

- `command_rules` allow or deny TPM command codes (decimal `TPM_CC` values; an
  empty or omitted list means *all* commands). The first matching rule wins;
  otherwise `default_decision` applies (default **deny**).
- `priority_rules` cap the scheduling priority a peer may receive. The first
  matching rule wins; otherwise `default_max_priority` applies (default `0`).

```json
{
  "command_rules": [
    { "subject": { "uid": 1000 }, "commands": [379, 378], "decision": "allow" },
    { "subject": { "gid": 1001 }, "decision": "allow" }
  ],
  "priority_rules": [
    { "subject": { "uid": 1000 }, "max_priority": 5 },
    { "subject": { "gid": 1001 }, "max_priority": 1 }
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

The config string after `proxy:` is either a bare socket path or
comma-separated settings: `path=<socket>` and `priority=<n>`, the scheduling
priority to request (higher runs first). By default a client asks for the
highest priority its policy allows; the policy's `priority_rules` cap whatever
it asks for. For example, to run a background job below interactive clients:

```sh
tpm2_getrandom --tcti=proxy:priority=0 8
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
`--config`, `--socket`, `--upstream`,
`--swtpm-server`/`--swtpm-ctrl`, `--max-connections`, `--command-timeout-secs`.
Logging is controlled by `RUST_LOG` (default `info`).

## Development

```sh
nix develop --command cargo test --workspace
nix develop --command pre-commit run --all-files   # treefmt, reuse, editorconfig
```

See `docs/design.md` for the architecture conventions.

[TCTI]: https://trustedcomputinggroup.org/resource/tss-tcti-specification/
[TBS]: https://learn.microsoft.com/en-us/windows/win32/tbs/tpm-base-services-portal
[TAB]: https://trustedcomputinggroup.org/resource/tss-tab-and-resource-manager/
[tpm2-abrmd]: https://github.com/tpm2-software/tpm2-abrmd
