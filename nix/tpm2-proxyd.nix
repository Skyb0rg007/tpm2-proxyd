# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: Apache-2.0

{
  lib,
  rustPlatform,
  asciidoctor,
  pkg-config,
  openssl,
  swtpm,
  installShellFiles,
  coreutils,
}:
rustPlatform.buildRustPackage (finalAttrs: {
  pname = "tpm2-proxyd";
  version = "0.1.0";
  src = lib.sources.cleanSource ../.;

  cargoLock.lockFile = ../Cargo.lock;

  # The workspace's default members are only the daemon; build the TCTI module
  # (crates/tcti) too, so the cargo install hook ships libtss2_tcti_proxy.so.
  cargoBuildFlags = [ "--workspace" ];

  nativeBuildInputs = [
    asciidoctor
    pkg-config
    installShellFiles
  ];
  buildInputs = [ openssl ];

  nativeCheckInputs = [
    swtpm
  ];

  postBuild = ''
    asciidoctor -b manpage -o tpm2-proxyd.8 dist/tpm2-proxyd.8.adoc
  '';

  postInstall = ''
    # tpm2-tss's loader looks for libtss2-tcti-<name>.so; Cargo names it with
    # underscores.
    ln -s libtss2_tcti_proxy.so "$out/lib/libtss2-tcti-proxy.so"

    install -Dm0644 dist/tpm2-proxyd.service \
      "$out/lib/systemd/system/tpm2-proxyd.service"
    substituteInPlace "$out/lib/systemd/system/tpm2-proxyd.service" \
      --replace-fail "ExecStart=/usr/bin/tpm2-proxyd" "ExecStart=$out/bin/tpm2-proxyd" \
      --replace-fail "ExecReload=/bin/kill" "ExecReload=${coreutils}/bin/kill"
    install -Dm0644 dist/tpm2-proxyd.socket \
      "$out/lib/systemd/system/tpm2-proxyd.socket"
    install -Dm0644 dist/tpm2-proxyd.sysusers \
      "$out/lib/sysusers.d/tpm2-proxyd.conf"
    installManPage tpm2-proxyd.8
    install -Dm0644 dist/policy.example.json \
      "$out/share/tpm2-proxyd/policy.json"
    install -Dm0644 -t "$out/share/tpm2-proxyd/profiles" dist/profiles/*.json
  '';

  meta = {
    description = "Proxy service for TPM2 Commands";
    homepage = "https://github.com/Skyb0rg007/tpm2-proxyd";
    mainProgram = "tpm2-proxyd";
    license = lib.licenses.asl20;
    platforms = lib.platforms.linux;
    maintainers = [
      {
        name = "Skye Soss";
        email = "skye@soss.website";
        github = "Skyb0rg007";
        githubId = 30806179;
      }
    ];
  };
})
