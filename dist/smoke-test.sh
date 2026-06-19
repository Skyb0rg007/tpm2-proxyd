#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Manual end-to-end verification against a real (or kernel-RM-backed swtpm) TPM.
# Runs the daemon on a throwaway socket and drives it through the proxy TCTI with
# tpm2-tools. Requires: a TPM resource manager device, tpm2-tools, and a build of
# this project (libtss2_tcti_proxy.so + tpm2-proxyd).
#
#   UPSTREAM   TPM device to proxy (default /dev/tpmrm0)
#
# Exits non-zero on any failure.

set -euo pipefail

UPSTREAM="${UPSTREAM:-/dev/tpmrm0}"
here="$(cd "$(dirname "$0")/.." && pwd)"

if [ ! -e "$UPSTREAM" ]; then
  echo "SKIP: upstream TPM device $UPSTREAM not present." >&2
  exit 0
fi
if ! command -v tpm2_getrandom >/dev/null; then
  echo "SKIP: tpm2-tools (tpm2_getrandom) not installed." >&2
  exit 0
fi

echo "Building release..."
cargo build --release --workspace --manifest-path "$here/Cargo.toml" >/dev/null

tcti_lib="$here/target/release/libtss2_tcti_proxy.so"
daemon="$here/target/release/tpm2-proxyd"

workdir="$(mktemp -d)"
sock="$workdir/tpm2-proxyd.sock"
policy="$workdir/policy.json"
# Allow this user every command (empty command list = all), high priority.
printf '{"users":[{"uid":%s,"commands":[],"priority":100}]}\n' "$(id -u)" >"$policy"

cleanup() {
  [ -n "${daemon_pid:-}" ] && kill "$daemon_pid" 2>/dev/null || true
  rm -rf "$workdir"
}
trap cleanup EXIT

echo "Starting tpm2-proxyd against $UPSTREAM..."
RUST_LOG="${RUST_LOG:-info}" "$daemon" \
  --config="$policy" --socket="$sock" --upstream="$UPSTREAM" --control-socket= &
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

echo "PASS: proxied TPM2_GetRandom returned $out"
