#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: Apache-2.0
#
# tpm2-openssl (the OpenSSL 3 TPM provider) through the proxy: create EC and
# RSA keys in the TPM, sign with them and verify in software, then serve TLS
# 1.2 and 1.3 with a TPM server key, with and without a TPM client key.
#
# Needs openssl and the tpm2 provider; set OPENSSL_MODULES if the provider
# isn't in OpenSSL's default module directory.

# shellcheck source=tests/apps/lib.sh
source "$(dirname "$0")/lib.sh"
need openssl
openssl list -providers -provider tpm2 >/dev/null 2>&1 ||
  skip "the tpm2 OpenSSL provider isn't loadable (set OPENSSL_MODULES)"

start_proxy
export TPM2OPENSSL_TCTI="$TCTI"
tpm=(-provider tpm2 -provider default)
cd "$workdir"
echo "signed through tpm2-proxyd" >message

# A TPM key, its public key, and a self-signed certificate. `alg` is EC or
# RSA, the rest are genpkey -pkeyopt options. A key with a password reads it
# from $pass.
genkey() {
  local name="$1" alg="$2"
  shift 2
  local opts=() opt
  for opt in "$@"; do opts+=(-pkeyopt "$opt"); done
  local passin=()
  if [ -n "${pass:-}" ]; then
    opts+=(-pkeyopt "user-auth:$pass")
    passin=(-passin "pass:$pass")
  fi
  step "$name: generate" openssl genpkey "${tpm[@]}" -algorithm "$alg" \
    "${opts[@]}" -out "$name.key"
  grep -q 'BEGIN TSS2 PRIVATE KEY' "$name.key" || fail "$name.key is not a TPM key"
  step "$name: export public key" openssl pkey "${tpm[@]}" -in "$name.key" \
    "${passin[@]}" -pubout -out "$name.pub"
  step "$name: self-signed certificate" openssl req "${tpm[@]}" -new -x509 \
    -key "$name.key" "${passin[@]}" -subj "/CN=$name" -days 1 -out "$name.crt"
}

# Sign with the TPM, verify with the default provider alone.
sign_verify() {
  local name="$1"
  shift
  step "$name: sign" openssl dgst "${tpm[@]}" -sha256 -sign "$name.key" "$@" \
    -out "$name.sig" message
  step "$name: verify" openssl dgst -sha256 -verify "$name.pub" "$@" \
    -signature "$name.sig" message
  echo tampered >>message
  if openssl dgst -sha256 -verify "$name.pub" "$@" -signature "$name.sig" \
    message </dev/null >/dev/null 2>&1; then
    fail "$name: signature verified over a tampered message"
  fi
  echo "signed through tpm2-proxyd" >message
}

genkey ec EC group:P-256
genkey rsa RSA bits:2048
genkey client EC group:P-256
pass=hunter2 genkey authed EC group:P-256

sign_verify ec
sign_verify rsa
sign_verify rsa -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest
step "authed: sign" openssl dgst "${tpm[@]}" -sha256 -sign authed.key \
  -passin pass:hunter2 -out authed.sig message
step "authed: verify" openssl dgst -sha256 -verify authed.pub \
  -signature authed.sig message

# The TLS endpoints keep their keys in the TPM but prefer software digests.
# Otherwise tpm2-openssl hashes the handshake transcript in the TPM, and the
# hash sequences it duplicates along the way run into the kernel resource
# manager's limit of three loaded objects per open /dev/tpmrm0, with or
# without the proxy.
tls_tpm=("${tpm[@]}" -propquery '?provider=default')

# One TLS connection over a Unix socket to an `openssl s_server -www`, which
# answers with an HTTP status page. `server` names the server key; further
# arguments go to s_client, and make the server require a client certificate.
tls() {
  local label="$1" server="$2" version="$3"
  shift 3
  # Relative: OpenSSL fails to format long socket paths.
  local sock=tls.sock server_args=() pid
  rm -f "$sock"
  if [ "$#" -gt 0 ]; then
    server_args=(-Verify 1 -verify_return_error -CAfile client.crt)
  fi
  openssl s_server "${tls_tpm[@]}" -unix "$sock" -naccept 1 -www "$version" \
    -key "$server.key" -cert "$server.crt" "${server_args[@]}" \
    >tls-server.log 2>&1 &
  pid=$!
  wait_for_socket "$sock" tls-server.log
  log "$label"
  printf 'GET / HTTP/1.0\r\n\r\n' |
    openssl s_client "${tls_tpm[@]}" -unix "$sock" "$version" -quiet -brief \
      -CAfile "$server.crt" -verify_hostname "$server" -verify_return_error \
      "$@" >tls-client.out 2>tls-client.log || true
  wait "$pid" || true
  if ! grep -q '^HTTP/1.0 200 ok' tls-client.out; then
    cat tls-server.log tls-client.log >&2
    fail "$label"
  fi
  grep -q "^Protocol version: TLSv$(tls_version "$version")\$" tls-client.log ||
    fail "$label: negotiated $(grep -m1 '^Protocol version:' tls-client.log)"
}

# -tls1_3 -> 1.3
tls_version() {
  local v="${1#-tls}"
  echo "${v/_/.}"
}

for version in -tls1_3 -tls1_2; do
  name="TLS $(tls_version "$version")"
  tls "$name, TPM EC server key" ec "$version"
  tls "$name, TPM RSA server key" rsa "$version"
  tls "$name, TPM server and client keys" ec "$version" \
    -cert client.crt -key client.key
done

expect_no_denials
log PASS
