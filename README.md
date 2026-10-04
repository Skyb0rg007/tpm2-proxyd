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
nix develop --command cargo build --release --workspace
```

This produces `target/release/tpm2-proxyd` and
`target/release/libtss2_tcti_proxy.so`. The `--workspace` matters: a plain
`cargo build` builds only the daemon, not the TCTI module.

Build the Nix package itself with `nix build` (the daemon, the TCTI module as
`lib/libtss2-tcti-proxy.so`, the systemd units and the man page), or run the
daemon directly with `nix run -- --help`.

## Installing

Build as your own user, then install the result as root:

```sh
cargo build --release --workspace
sudo ./dist/install.sh
```

The script doesn't build anything (running cargo as root would leave a
root-owned `target/`); it fails if the release build is missing. It installs the
daemon, the TCTI module (renamed to the loader's expected
`libtss2-tcti-proxy.so`, in tpm2-tss's library directory so the loader finds it
by name), the systemd units, a system user, a man page (if `asciidoctor` is
installed), a policy at `/etc/tpm2-proxyd/policy.json` that gives every user the
`standard` profile, and that profile at
`/etc/tpm2-proxyd/profiles/standard.json`. It doesn't overwrite a policy or
profile that's already there. `PREFIX`, `LIBDIR`, `UNITDIR`, `MANDIR` and
`DESTDIR` override where things go; see the script's header. Then:

```sh
sudo systemctl enable --now tpm2-proxyd.socket
```

The `tpm2-proxyd.socket` unit owns the listening socket (`tss:tss`, mode
`0666`), and the daemon starts on first connection via socket activation. Any
local user may connect; the policy then decides, per connection, what that peer
may run. One user may hold at most 16 connections at once
(`--max-connections-per-uid`), so no one user can take every slot. Do **not** add
proxy users to `tss`: members of the TPM device group can open `/dev/tpmrm0`
directly and bypass the proxy's policy. If your distribution's TPM group is not
`tss`, edit `SupplementaryGroups=` in the service unit (and the socket's owner)
to match.

### NixOS

The flake provides a NixOS module, `nixosModules.default`:

```nix
{
  inputs.tpm2-proxyd.url = "github:Skyb0rg007/tpm2-proxyd";

  outputs = { nixpkgs, tpm2-proxyd, ... }: {
    nixosConfigurations.machine = nixpkgs.lib.nixosSystem {
      modules = [
        tpm2-proxyd.nixosModules.default
        {
          services.tpm2-proxyd = {
            enable = true;
            # Point tpm2-tools, tpm2-pkcs11 and tpm2-openssl at the proxy.
            tctiEnvironment.enable = true;
            settings.rules = [
              { subject.gid = 1001; profile = "admin"; max_priority = 10; }
            ];
            profiles.admin = ./admin.json;
          };
        }
      ];
    };
  };
}
```

It enables the socket, writes the policy (`settings`, the same JSON as
`policy.json`, defaulting to everyone under `standard`) and any extra
`profiles` under `/etc/tpm2-proxyd/`, and turns on `security.tpm2`. Changing the
policy or a profile reloads the daemon on switch without dropping its
connections. `extraArgs` passes further command-line options. On NixOS the
tpm2-tss loader can't find the TCTI module by name, so clients need its full
path: `tctiEnvironment.enable` sets the usual TCTI variables, and
`config.services.tpm2-proxyd.tcti` holds the string for anything else.

## Configuring policy

Policy has two parts, both under `/etc/tpm2-proxyd/`:

- **Profiles** (`profiles/<name>.json`) say which TPM commands may run and which
  handles those commands may reference. Nothing is built into the daemon; it
  ships one profile, `standard`, which is also the default.
- **The policy** (`policy.json`) says which profile and priority cap each peer
  gets.

```json
{
  "default_profile": "standard",
  "default_max_priority": 0,
  "rules": [
    { "subject": { "gid": 1001 }, "profile": "admin", "max_priority": 10 }
  ]
}
```

Rules are checked in order and the first whose `subject` matches wins. A subject
names a `uid`, a `gid` (primary or supplementary), both, or, if empty, every
peer. A peer no rule matches gets `default_profile`, or no access at all if it's
unset. A rule without `max_priority` uses `default_max_priority` (default `0`).
Loading fails if the policy names a profile that doesn't exist, so the example
above also needs `admin.json`.

Use rules to grant more than the default, not to restrict a user below it. A
user with subordinate IDs (`/etc/subuid`, set up by default on many
distributions) can connect from a user namespace as one of those UIDs, or
without some of their groups, and then gets the default whatever the rules
say about them. Make `default_profile` the least any local user may have.

A profile lists commands and handles by their TPM specification names:

```json
{
  "handles": ["TPM_HT_TRANSIENT", "TPM_HT_HMAC_SESSION", "TPM_HT_POLICY_SESSION", "TPM_RH_NULL"],
  "commands": ["TPM_CC_GetRandom", "TPM_CC_CreatePrimary", "TPM_CC_Sign"],
  "command_handles": {
    "TPM_CC_CreatePrimary": ["TPM_RH_OWNER", "TPM_RH_NULL"]
  }
}
```

- `commands` lists the commands the profile allows; `"*"` allows every command
  the proxy recognizes. `{"commands": []}` allows nothing.
- `handles` lists the handles any allowed command may reference in its handle
  area: a handle type (`TPM_HT_*`) allows every handle of that type, a permanent
  handle (`TPM_RH_*`) allows just itself, and `"*"` allows any handle.
- `command_handles` replaces `handles` for particular commands.

The shipped `standard` profile covers ordinary unprivileged use: capability, PCR
and random reads; sessions; creating, loading and using the caller's own keys
and sealed objects; hashing, signing, encryption and quotes. It allows only
transient objects, sessions and the null hierarchy, plus the owner and
endorsement hierarchies for `CreatePrimary`, so it can't touch persistent keys,
NV indices, PCR values or hierarchy settings, all of which every user shares.
Each connection gets its own `/dev/tpmrm0` handle, so the kernel resource
manager keeps one client's transient objects out of another's reach and flushes
what it leaves loaded. Session handles aren't virtualized, so the daemon only
lets a connection flush sessions it holds, and `standard` doesn't let users save
sessions, which the kernel would then never flush.

A denied command isn't forwarded. The client gets an error response in the
resource-manager layer, which tpm2-tools prints as, for example,
`rmt:error(2.0): command code not supported` or `rmt:handle(1):the handle is not
correct for the use`, and the connection stays open. Denials are logged with the
peer's UID and PID.

Reload the policy and profiles after editing, without dropping connections:

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
highest priority its policy allows; the matching rule's `max_priority` (or the
policy's `default_max_priority`) caps whatever it asks for. For example, to run
a background job below interactive clients:

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
`--flags startup-clear` so the TPM is already up. `MODE=swtpm dist/smoke-test.sh`
exercises this whole path with tpm2-tools (see `docs/smoke-test.md`).

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

`tests/apps` runs real TPM applications through the proxy under the shipped
`standard` profile, and fails if the daemon denies anything they send:
tpm2-openssl (signing, and TLS 1.2/1.3 with TPM server and client keys) and
tpm2-pkcs11 (provisioned with `tpm2_ptool`, then used by OpenSSH directly and
through `ssh-agent`). They need a kernel resource manager upstream, since these
applications rely on it to flush what they leave loaded, so they run against
`/dev/tpmrm0` (transient objects only, no failed authorizations) or in a NixOS
VM with a virtual TPM:

```sh
nix develop .#apps --command tests/apps/run.sh     # against the host TPM
nix build .#checks.x86_64-linux.app-tests          # in a VM (needs KVM)
```

See `docs/design.md` for the architecture conventions.

[TCTI]: https://trustedcomputinggroup.org/resource/tss-tcti-specification/
[TBS]: https://learn.microsoft.com/en-us/windows/win32/tbs/tpm-base-services-portal
[TAB]: https://trustedcomputinggroup.org/resource/tss-tab-and-resource-manager/
[tpm2-abrmd]: https://github.com/tpm2-software/tpm2-abrmd
