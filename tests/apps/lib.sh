# shellcheck shell=bash
# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: Apache-2.0
#
# Shared harness for the application tests: start a tpm2-proxyd on a throwaway
# socket in front of a TPM device, and point the TPM software under test at it
# through the proxy TCTI. Source it from a test script, then call
# `start_proxy`.
#
# The upstream has to be a kernel resource manager (/dev/tpmrm*): these
# applications leave objects loaded when they exit and count on the RM to
# flush them, which swtpm can't do, so it runs out of object slots. The tests
# create only transient objects and never fail an authorization, so they
# leave no state behind and don't touch the dictionary-attack counter, which
# makes them safe to run against the host TPM.
#
#   UPSTREAM       TPM device (default /dev/tpmrm0)
#   PROFILE        profile the test user gets (default: standard, from
#                  dist/profiles)
#   TPM2_PROXYD    daemon binary (default: built with cargo)
#   TCTI_PROXY     proxy TCTI module (default: built with cargo)
#   KEEP_WORKDIR   if set, keep the scratch directory and its logs
#
# After `start_proxy`, `$TCTI` is the TCTI config string for the proxy and
# `$workdir` is a scratch directory removed on exit. A test exits 0 on
# success, 77 when skipped, and anything else on failure.

set -euo pipefail

UPSTREAM="${UPSTREAM:-/dev/tpmrm0}"
PROFILE="${PROFILE:-standard}"
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

log() { echo "[$test_name] $*" >&2; }
fail() {
  log "FAIL: $*"
  exit 1
}
# Exit status 77 marks a skipped test, as in automake.
skip() {
  log "SKIP: $*"
  exit 77
}
need() {
  local tool
  for tool in "$@"; do
    command -v "$tool" >/dev/null || skip "$tool not installed"
  done
}

# Run a command with its output captured to `$workdir/<name>.log`, dumping
# the log and failing the test if it exits non-zero. Stdin is /dev/null, so a
# password prompt fails rather than hangs.
step() {
  local name="$1"
  shift
  log "$name"
  "$@" </dev/null >"$workdir/$name.log" 2>&1 || {
    cat "$workdir/$name.log" >&2
    fail "$name"
  }
}

test_name="$(basename "$0" .sh)"
workdir="$(mktemp -d "${TMPDIR:-/tmp}/tpm2-proxyd-$test_name.XXXXXX")"
_pids=()
_cleanup_hooks=()
_cleanup() {
  local status=$?
  local hook i
  for hook in "${_cleanup_hooks[@]}"; do "$hook" || true; done
  # Newest first: helpers before the daemon.
  for ((i = ${#_pids[@]} - 1; i >= 0; i--)); do stop "${_pids[i]}"; done
  if [ "$status" -ne 0 ] && [ "$status" -ne 77 ] && [ -f "$workdir/proxy.log" ]; then
    log "daemon log:"
    tail -n 50 "$workdir/proxy.log" >&2
  fi
  if [ -n "${KEEP_WORKDIR:-}" ]; then
    log "kept $workdir"
  else
    rm -rf "$workdir"
  fi
}
trap _cleanup EXIT

# Stop a background process, killing it if it doesn't exit within a second.
stop() {
  local _
  kill "$1" 2>/dev/null || return 0
  for _ in $(seq 1 10); do
    kill -0 "$1" 2>/dev/null || break
    sleep 0.1
  done
  kill -9 "$1" 2>/dev/null || true
  wait "$1" 2>/dev/null || true
}

# Start a background helper that's stopped at exit if it's still running.
# Its PID is in $! afterwards.
spawn() {
  "$@" &
  _pids+=($!)
}

# Give a helper started with `spawn` up to 5 seconds to exit on its own, then
# stop it.
reap() {
  local _ i
  for _ in $(seq 1 50); do
    kill -0 "$1" 2>/dev/null || break
    sleep 0.1
  done
  stop "$1"
  for i in "${!_pids[@]}"; do
    [ "${_pids[i]}" != "$1" ] || unset '_pids[i]'
  done
  _pids=("${_pids[@]}")
}

# Register a function to run at exit, before the daemon is stopped.
on_exit() { _cleanup_hooks+=("$1"); }

# Wait up to 5 seconds for a socket to appear, showing the creator's log
# (if given) when it doesn't.
wait_for_socket() {
  local _
  for _ in $(seq 1 50); do
    [ -S "$1" ] && return 0
    sleep 0.1
  done
  [ -z "${2:-}" ] || cat "$2" >&2
  fail "$1 did not appear"
}

start_proxy() {
  [ -r "$UPSTREAM" ] && [ -w "$UPSTREAM" ] || skip "$UPSTREAM not accessible"
  if [ -z "${TPM2_PROXYD:-}" ] || [ -z "${TCTI_PROXY:-}" ]; then
    log "building tpm2-proxyd"
    cargo build --quiet --workspace --manifest-path "$repo/Cargo.toml"
    TPM2_PROXYD="${TPM2_PROXYD:-$repo/target/debug/tpm2-proxyd}"
    TCTI_PROXY="${TCTI_PROXY:-$repo/target/debug/libtss2_tcti_proxy.so}"
  fi

  mkdir "$workdir/profiles"
  cp "$repo"/dist/profiles/*.json "$workdir/profiles/"
  [ -f "$workdir/profiles/$PROFILE.json" ] || fail "no profile $PROFILE"
  printf '{"rules":[{"subject":{"uid":%s},"profile":"%s","max_priority":100}]}\n' \
    "$(id -u)" "$PROFILE" >"$workdir/policy.json"

  log "starting tpm2-proxyd ($UPSTREAM, profile $PROFILE)"
  RUST_LOG="${RUST_LOG:-info}" "$TPM2_PROXYD" --config="$workdir/policy.json" \
    --socket="$workdir/proxy.sock" --upstream="$UPSTREAM" \
    >"$workdir/proxy.log" 2>&1 &
  _pids+=($!)
  wait_for_socket "$workdir/proxy.sock" "$workdir/proxy.log"

  # The module by full path, so nothing needs installing.
  TCTI="$TCTI_PROXY:$workdir/proxy.sock"
  export TPM2TOOLS_TCTI="$TCTI"
}

# Fail if the daemon denied any command: the profile is missing something the
# application needs, even if the application coped without it.
expect_no_denials() {
  if grep 'command denied' "$workdir/proxy.log" >&2; then
    fail "the daemon denied commands under profile $PROFILE"
  fi
}
