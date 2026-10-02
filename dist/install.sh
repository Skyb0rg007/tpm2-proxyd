#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: Apache-2.0
#
# Install tpm2-proxyd, its downstream TCTI module, and the systemd integration
# from an existing release build. Build first, as your own user:
#
#   cargo build --release --workspace
#
# then run this as root (or with a DESTDIR for packaging). It doesn't build
# anything itself: under sudo, cargo is usually not on the PATH, and a build as
# root would leave a root-owned target/.
#
# Environment overrides:
#   DESTDIR   staging root for packaging (default empty = install to live system)
#   PREFIX    install prefix for the binary (default /usr)
#   LIBDIR    directory for the TCTI shared library (default: tpm2-tss's libdir,
#             where its loader looks; else $PREFIX/lib)
#   UNITDIR   systemd unit directory (default /usr/lib/systemd/system)
#   MANDIR    man page directory (default $PREFIX/share/man)

set -euo pipefail

DESTDIR="${DESTDIR:-}"
PREFIX="${PREFIX:-/usr}"

# The directory tpm2-tss's own libraries are in. Its TCTI loader dlopen()s
# libtss2-tcti-<name>.so by bare name, so the module must be on the dynamic
# linker's search path, which is /usr/lib64 rather than /usr/lib on lib64
# distributions.
tss_libdir() {
  local dir lib
  if dir="$(pkg-config --variable=libdir tss2-tctildr 2>/dev/null)" && [ -n "$dir" ]; then
    echo "$dir"
    return
  fi
  lib="$(ldconfig -p 2>/dev/null | awk '/libtss2-tctildr\.so/ { print $NF; exit }')" || true
  if [ -n "$lib" ]; then
    dirname "$lib"
    return
  fi
  echo "$PREFIX/lib"
}

LIBDIR="${LIBDIR:-$(tss_libdir)}"
UNITDIR="${UNITDIR:-/usr/lib/systemd/system}"
MANDIR="${MANDIR:-$PREFIX/share/man}"

here="$(cd "$(dirname "$0")/.." && pwd)"
release="$here/target/release"

for artifact in tpm2-proxyd libtss2_tcti_proxy.so; do
  if [ ! -e "$release/$artifact" ]; then
    echo "error: $release/$artifact is missing." >&2
    echo "Build it first, as your own user (not root):" >&2
    echo "  cargo build --release --workspace" >&2
    exit 1
  fi
done

if [ -z "$DESTDIR" ] && [ "$(id -u)" -ne 0 ]; then
  echo "error: installing to the live system needs root (or set DESTDIR)." >&2
  exit 1
fi

staging="$(mktemp -d)"
trap 'rm -rf "$staging"' EXIT

install -Dm0755 "$release/tpm2-proxyd" "$DESTDIR$PREFIX/bin/tpm2-proxyd"

# tpm2-tss's loader searches for libtss2-tcti-<name>.so (with a dash), but Cargo
# emits libtss2_tcti_proxy.so (with underscores); install it under the loader
# name so `--tcti=proxy:<sock>` resolves.
install -Dm0644 "$release/libtss2_tcti_proxy.so" \
  "$DESTDIR$LIBDIR/libtss2-tcti-proxy.so"

# Point the unit at where the binary actually went.
sed "s|^ExecStart=/usr/bin/tpm2-proxyd|ExecStart=$PREFIX/bin/tpm2-proxyd|" \
  "$here/dist/tpm2-proxyd.service" >"$staging/tpm2-proxyd.service"
install -Dm0644 "$staging/tpm2-proxyd.service" "$DESTDIR$UNITDIR/tpm2-proxyd.service"
install -Dm0644 "$here/dist/tpm2-proxyd.socket" "$DESTDIR$UNITDIR/tpm2-proxyd.socket"
install -Dm0644 "$here/dist/tpm2-proxyd.sysusers" \
  "$DESTDIR/usr/lib/sysusers.d/tpm2-proxyd.conf"

if command -v asciidoctor >/dev/null; then
  asciidoctor -b manpage -o "$staging/tpm2-proxyd.8" "$here/dist/tpm2-proxyd.8.adoc"
  install -Dm0644 "$staging/tpm2-proxyd.8" "$DESTDIR$MANDIR/man8/tpm2-proxyd.8"
else
  echo "warning: asciidoctor not found; not installing the man page." >&2
fi

# Install an example policy without clobbering an existing one.
config="$DESTDIR/etc/tpm2-proxyd/policy.json"
if [ ! -e "$config" ]; then
  install -Dm0644 "$here/dist/policy.example.json" "$config"
  echo "Installed default policy at /etc/tpm2-proxyd/policy.json (edit before use)."
else
  echo "Keeping existing policy at /etc/tpm2-proxyd/policy.json."
fi

# Install the shipped profiles, keeping any the administrator has edited.
for profile in "$here"/dist/profiles/*.json; do
  target="$DESTDIR/etc/tpm2-proxyd/profiles/$(basename "$profile")"
  if [ ! -e "$target" ]; then
    install -Dm0644 "$profile" "$target"
  else
    echo "Keeping existing profile at ${target#"$DESTDIR"}."
  fi
done

if [ -z "$DESTDIR" ]; then
  echo "Updating the linker cache, creating the system user, reloading systemd..."
  ldconfig
  systemd-sysusers /usr/lib/sysusers.d/tpm2-proxyd.conf
  systemctl daemon-reload
  echo "Enable with: systemctl enable --now tpm2-proxyd.socket"
fi

echo "Done."
