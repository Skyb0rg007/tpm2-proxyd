#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: Apache-2.0
#
# Build and install tpm2-proxyd, its downstream TCTI module, and the systemd
# integration. Run as root (or with a DESTDIR for packaging).
#
# Environment overrides:
#   DESTDIR   staging root for packaging (default empty = install to live system)
#   PREFIX    install prefix for the binary (default /usr)
#   LIBDIR    directory for the TCTI shared library (default $PREFIX/lib)
#   UNITDIR   systemd unit directory (default /usr/lib/systemd/system)
#   MANDIR    man page directory (default $PREFIX/share/man)

set -euo pipefail

DESTDIR="${DESTDIR:-}"
PREFIX="${PREFIX:-/usr}"
LIBDIR="${LIBDIR:-$PREFIX/lib}"
UNITDIR="${UNITDIR:-/usr/lib/systemd/system}"
MANDIR="${MANDIR:-$PREFIX/share/man}"

here="$(cd "$(dirname "$0")/.." && pwd)"

echo "Building release artifacts..."
cargo build --release --workspace --manifest-path "$here/Cargo.toml"
asciidoctor -b manpage -o "$here/target/release/tpm2-proxyd.8" \
  "$here/dist/tpm2-proxyd.8.adoc"

install -Dm0755 "$here/target/release/tpm2-proxyd" \
  "$DESTDIR$PREFIX/bin/tpm2-proxyd"

# tpm2-tss's loader searches for libtss2-tcti-<name>.so (with a dash), but Cargo
# emits libtss2_tcti_proxy.so (with underscores); install it under the loader
# name so `--tcti=proxy:<sock>` resolves.
install -Dm0644 "$here/target/release/libtss2_tcti_proxy.so" \
  "$DESTDIR$LIBDIR/libtss2-tcti-proxy.so"

install -Dm0644 "$here/dist/tpm2-proxyd.service" "$DESTDIR$UNITDIR/tpm2-proxyd.service"
install -Dm0644 "$here/dist/tpm2-proxyd.socket" "$DESTDIR$UNITDIR/tpm2-proxyd.socket"
install -Dm0644 "$here/dist/tpm2-proxyd.sysusers" \
  "$DESTDIR/usr/lib/sysusers.d/tpm2-proxyd.conf"
install -Dm0644 "$here/target/release/tpm2-proxyd.8" \
  "$DESTDIR$MANDIR/man8/tpm2-proxyd.8"

# Install an example policy without clobbering an existing one.
config="$DESTDIR/etc/tpm2-proxyd/policy.json"
if [ ! -e "$config" ]; then
  install -Dm0644 "$here/dist/policy.example.json" "$config"
  echo "Installed default policy at /etc/tpm2-proxyd/policy.json (edit before use)."
else
  echo "Keeping existing policy at /etc/tpm2-proxyd/policy.json."
fi

if [ -z "$DESTDIR" ]; then
  echo "Creating system user and reloading systemd..."
  systemd-sysusers /usr/lib/sysusers.d/tpm2-proxyd.conf
  systemctl daemon-reload
  echo "Enable with: systemctl enable --now tpm2-proxyd.socket"
fi

echo "Done."
