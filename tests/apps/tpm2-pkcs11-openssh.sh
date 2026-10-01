#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: Apache-2.0
#
# tpm2-pkcs11 through the proxy, driven by OpenSSH: provision a PKCS#11 token
# with tpm2_ptool, then log in to an sshd with its keys, both directly
# (PKCS11Provider) and through ssh-agent.
#
# sshd runs as the test user in inetd mode (`sshd -i`) as the client's
# ProxyCommand, so it needs neither root nor a port.
#
# Needs tpm2_ptool, OpenSSH, and the tpm2-pkcs11 module; set TPM2_PKCS11_MODULE
# to its path if it isn't in the linker cache or a usual library directory.

# shellcheck source=tests/apps/lib.sh
source "$(dirname "$0")/lib.sh"
need tpm2_ptool ssh ssh-keygen ssh-agent ssh-add
sshd="$(command -v sshd || true)"
[ -n "$sshd" ] || skip "sshd not installed"
module="${TPM2_PKCS11_MODULE:-}"
if [ -z "$module" ]; then
  module="$( (ldconfig -p 2>/dev/null || true) |
    awk '$1 == "libtpm2_pkcs11.so" || $1 == "libtpm2_pkcs11.so.0" { print $NF; exit }')"
fi
if [ -z "$module" ]; then
  for module in /usr/lib*/libtpm2_pkcs11.so* /usr/lib*/*/libtpm2_pkcs11.so* \
    /usr/lib*/pkcs11/libtpm2_pkcs11.so ""; do
    [ -e "$module" ] && break
  done
fi
[ -n "$module" ] && [ -e "$module" ] || skip "libtpm2_pkcs11.so not found (set TPM2_PKCS11_MODULE)"
# OpenSSH wants an absolute, canonical path.
module="$(realpath "$module")"

start_proxy
export TPM2_PKCS11_TCTI="$TCTI"
export TPM2_PKCS11_STORE="$workdir/store"
mkdir "$TPM2_PKCS11_STORE"
cd "$workdir"

userpin=123456
sopin=87654321

# Provision a token with an ECC and an RSA key. The parent is a transient
# primary: making it persistent needs TPM2_EvictControl, which the standard
# profile denies.
step "tpm2_ptool init" tpm2_ptool init --transient-parent=tpm2-tools-default
step "tpm2_ptool addtoken" tpm2_ptool addtoken --pid=1 --label=ssh \
  --userpin="$userpin" --sopin="$sopin"
step "tpm2_ptool addkey ecc256" tpm2_ptool addkey --label=ssh --key-label=ecc \
  --userpin="$userpin" --algorithm=ecc256
step "tpm2_ptool addkey rsa2048" tpm2_ptool addkey --label=ssh --key-label=rsa \
  --userpin="$userpin" --algorithm=rsa2048

log "ssh-keygen -D"
ssh-keygen -D "$module" </dev/null >authorized_keys 2>ssh-keygen.log || {
  cat ssh-keygen.log >&2
  fail "ssh-keygen -D"
}
[ "$(grep -c '^ecdsa-sha2-nistp256 ' authorized_keys)" -eq 1 ] ||
  fail "the token has no ECDSA key: $(cat authorized_keys)"
[ "$(grep -c '^ssh-rsa ' authorized_keys)" -eq 1 ] ||
  fail "the token has no RSA key: $(cat authorized_keys)"
chmod 600 authorized_keys

step "ssh-keygen host key" ssh-keygen -q -t ed25519 -N '' -f host_key
cat >sshd_config <<CONF
HostKey $workdir/host_key
AuthorizedKeysFile $workdir/authorized_keys
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
StrictModes no
PidFile none
LogLevel VERBOSE
CONF
printf 'localhost %s\n' "$(cat host_key.pub)" >known_hosts

# The PIN prompt goes to an askpass helper.
printf '#!/bin/sh\necho %s\n' "$userpin" >askpass
chmod +x askpass
export SSH_ASKPASS="$workdir/askpass" SSH_ASKPASS_REQUIRE=force DISPLAY=:0

ssh_opts=(
  -F none
  -o "ProxyCommand=$sshd -i -f $workdir/sshd_config -E $workdir/sshd.log"
  -o UserKnownHostsFile="$workdir/known_hosts"
  -o StrictHostKeyChecking=yes
  -o BatchMode=no
  -o PasswordAuthentication=no
  -o KbdInteractiveAuthentication=no
  # Only the token's keys: none of the user's key files. (IdentitiesOnly
  # would also drop the token's keys, which aren't files.)
  -o IdentityFile=none
)

# Log in with one of the token's keys, by its signature algorithm, and check
# sshd accepted that key.
login() {
  local label="$1" algorithm="$2" keytype fingerprint
  shift 2
  case "$algorithm" in
  rsa-*) keytype=ssh-rsa ;;
  *) keytype="$algorithm" ;;
  esac
  fingerprint="$(grep "^$keytype " authorized_keys | ssh-keygen -lf - | awk '{print $2}')"
  : >sshd.log
  # Verbose, for the log shown on failure.
  step "$label" ssh -v "${ssh_opts[@]}" -o PubkeyAcceptedAlgorithms="$algorithm" \
    "$@" localhost echo logged-in
  grep -qx logged-in "$workdir/$label.log" || fail "$label: no shell output"
  grep -F "Accepted publickey for $(id -un) " sshd.log | grep -qF " $fingerprint" || {
    cat sshd.log >&2
    fail "$label: sshd didn't accept the token's $keytype key ($fingerprint)"
  }
}

login "ssh PKCS11Provider ecdsa" ecdsa-sha2-nistp256 -o IdentityAgent=none \
  -o PKCS11Provider="$module"
login "ssh PKCS11Provider rsa" rsa-sha2-256 -o IdentityAgent=none \
  -o PKCS11Provider="$module"

# ssh-agent only loads providers matching its allowlist.
eval "$(ssh-agent -s -P "$(dirname "$module")/*")" >/dev/null
stop_agent() { ssh-agent -k >/dev/null 2>&1; }
on_exit stop_agent
step "ssh-add -s" ssh-add -s "$module"
step "ssh-add -L" ssh-add -L
[ "$(grep -c . "ssh-add -L.log")" -eq 2 ] || fail "ssh-agent didn't load both keys"
login "ssh via ssh-agent ecdsa" ecdsa-sha2-nistp256 -o IdentityAgent="$SSH_AUTH_SOCK"
login "ssh via ssh-agent rsa" rsa-sha2-512 -o IdentityAgent="$SSH_AUTH_SOCK"

expect_no_denials
log PASS
