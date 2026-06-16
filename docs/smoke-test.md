<!--
SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>

SPDX-License-Identifier: BSD-2-Clause
-->

# End-to-end smoke test

This check proves the minimal raw-socket path:

```text
tpm2-tss tool -> tss2-tcti-proxy -> raw daemon socket -> policy -> scheduler -> /dev/tpmrm0 -> response
```

It requires:

- access to a Linux TPM resource-manager device, normally `/dev/tpmrm0`;
- `tpm2-tools` installed;
- permission for the daemon process to open `/dev/tpmrm0`;
- permission for the client process to connect to the raw proxy socket.

Build the daemon and TCTI:

```sh
cargo build
```

Create a test policy that allows the current user to run `TPM2_GetRandom`
(`TPM_CC_GetRandom`, command code `0x0000017b`, decimal `379`):

```sh
cat > /tmp/tpm2-proxyd-smoke.json <<EOF
{
  "users": [
    {
      "uid": $(id -u),
      "commands": [379],
      "priority": 10
    }
  ]
}
EOF
```

Start the daemon in one terminal:

```sh
cargo run -- \
  --config=/tmp/tpm2-proxyd-smoke.json \
  --socket=/tmp/tpm2-proxyd.sock \
  --upstream=/dev/tpmrm0
```

In a second terminal, expose the debug-built TCTI under the filename expected by
the tpm2-tss loader:

```sh
ln -sf "$PWD/target/debug/libtss2_tcti_proxy.so" /tmp/libtss2-tcti-proxy.so
export LD_LIBRARY_PATH="/tmp${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
```

Run a TPM command through the proxy:

```sh
tpm2_getrandom --tcti=proxy:/tmp/tpm2-proxyd.sock 8 >/tmp/tpm2-proxyd-random.bin
test "$(wc -c </tmp/tpm2-proxyd-random.bin)" -eq 8
```

The command succeeds only if the TCTI can connect to the daemon socket, the
daemon authorizes `TPM2_GetRandom` for the connecting UID/GID, the scheduler
forwards the command to `/dev/tpmrm0`, and a TPM response is returned.

To confirm policy denial, remove command `379` from the config, restart the
daemon, and rerun `tpm2_getrandom`. The command should fail before reaching the
upstream TPM.
