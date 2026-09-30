#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: Apache-2.0
#
# End-to-end verification: run the daemon on a throwaway socket and drive it
# through the proxy TCTI with tpm2-tools, against either a kernel TPM device or a
# swtpm software TPM.
#
#   MODE       device | swtpm | auto (default: auto)
#   UPSTREAM   TPM device for MODE=device (default /dev/tpmrm0)
#
# In "auto" mode it uses the TPM device when accessible, else swtpm if installed.
# Requires tpm2-tools and a build of this project.
#
# Exits non-zero on any failure.

set -euo pipefail

MODE="${MODE:-auto}"
UPSTREAM="${UPSTREAM:-/dev/tpmrm0}"
here="$(cd "$(dirname "$0")/.." && pwd)"

if ! command -v tpm2_getrandom >/dev/null; then
  echo "SKIP: tpm2-tools (tpm2_getrandom) not installed." >&2
  exit 0
fi

if [ "$MODE" = auto ]; then
  if [ -r "$UPSTREAM" ] && [ -w "$UPSTREAM" ]; then
    MODE=device
  elif command -v swtpm >/dev/null; then
    MODE=swtpm
  else
    echo "SKIP: no accessible TPM device and swtpm not installed." >&2
    exit 0
  fi
fi

echo "Building release..."
cargo build --release --workspace --manifest-path "$here/Cargo.toml" >/dev/null

tcti_lib="$here/target/release/libtss2_tcti_proxy.so"
daemon="$here/target/release/tpm2-proxyd"

workdir="$(mktemp -d)"
sock="$workdir/tpm2-proxyd.sock"
policy="$workdir/policy.json"
# Give this user the shipped standard profile, at a high priority.
printf '{"rules":[{"subject":{"uid":%s},"profile":"standard","max_priority":100}]}\n' \
  "$(id -u)" >"$policy"
mkdir "$workdir/profiles"
cp "$here/dist/profiles/standard.json" "$workdir/profiles/"

swtpm_pid=""
daemon_pid=""
cleanup() {
  [ -n "$daemon_pid" ] && kill "$daemon_pid" 2>/dev/null || true
  [ -n "$swtpm_pid" ] && kill "$swtpm_pid" 2>/dev/null || true
  rm -rf "$workdir"
}
trap cleanup EXIT

upstream_args=()
if [ "$MODE" = swtpm ]; then
  command -v swtpm >/dev/null || { echo "FAIL: swtpm not installed." >&2; exit 1; }
  data="$workdir/swtpm.sock"
  ctrl="$workdir/swtpm.sock.ctrl"
  mkdir -p "$workdir/state"
  echo "Starting swtpm..."
  swtpm socket --tpm2 --tpmstate dir="$workdir/state" \
    --server type=unixio,path="$data" --ctrl type=unixio,path="$ctrl" &
  swtpm_pid=$!
  for _ in $(seq 1 50); do [ -S "$data" ] && [ -S "$ctrl" ] && break; sleep 0.1; done
  [ -S "$data" ] || { echo "FAIL: swtpm did not create $data" >&2; exit 1; }
  # Let the proxy reset and start the freshly created TPM.
  upstream_args=(--swtpm-server="unix:$data" --swtpm-ctrl="unix:$ctrl")
  echo "Starting tpm2-proxyd against swtpm..."
else
  upstream_args=(--upstream="$UPSTREAM")
  echo "Starting tpm2-proxyd against $UPSTREAM..."
fi

RUST_LOG="${RUST_LOG:-info}" "$daemon" \
  --config="$policy" --socket="$sock" "${upstream_args[@]}" &
daemon_pid=$!

for _ in $(seq 1 50); do
  [ -S "$sock" ] && break
  sleep 0.1
done
[ -S "$sock" ] || { echo "FAIL: daemon did not create $sock" >&2; exit 1; }

echo "Requesting 8 random bytes through the proxy..."
# Use the built module by full path so the test runs without installing the
# loader-named symlink. Once installed, "proxy:$sock" works by name.
out="$(tpm2_getrandom --tcti="$tcti_lib:$sock" --hex 8 2>"$workdir/err")" || {
  echo "FAIL: tpm2_getrandom through proxy failed:" >&2
  cat "$workdir/err" >&2
  exit 1
}

if [ "${#out}" -ne 16 ]; then
  echo "FAIL: expected 16 hex chars, got '$out'" >&2
  exit 1
fi

tcti="$tcti_lib:$sock"
work="$workdir/keys"
mkdir "$work"

echo "Creating, loading, and signing with a key under the standard profile..."
{
  tpm2_createprimary --tcti="$tcti" -C o -c "$work/primary.ctx" &&
    tpm2_create --tcti="$tcti" -C "$work/primary.ctx" -G ecc \
      -u "$work/key.pub" -r "$work/key.priv" &&
    tpm2_load --tcti="$tcti" -C "$work/primary.ctx" \
      -u "$work/key.pub" -r "$work/key.priv" -c "$work/key.ctx" &&
    echo "tpm2-proxyd" >"$work/message" &&
    tpm2_sign --tcti="$tcti" -c "$work/key.ctx" -g sha256 \
      -o "$work/message.sig" "$work/message"
} >/dev/null 2>"$workdir/err" || {
  echo "FAIL: key workflow through proxy failed:" >&2
  cat "$workdir/err" >&2
  exit 1
}

echo "Checking that the standard profile refuses a persistent handle..."
if tpm2_readpublic --tcti="$tcti" -c 0x81000001 >/dev/null 2>"$workdir/err"; then
  echo "FAIL: reading persistent handle 0x81000001 was not refused" >&2
  exit 1
fi
if ! grep -q "rmt:handle(1)" "$workdir/err"; then
  echo "FAIL: expected a resource-manager handle error, got:" >&2
  cat "$workdir/err" >&2
  exit 1
fi

echo "PASS ($MODE): proxied TPM2_GetRandom returned $out; key workflow ran; persistent handle refused"
