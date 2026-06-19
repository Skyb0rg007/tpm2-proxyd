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
}:
rustPlatform.buildRustPackage (finalAttrs: {
  pname = "tpm2-proxyd";
  version = "0.1.0";
  src = lib.sources.cleanSource ../.;

  cargoHash = "sha256-DYSL7JUo5dxFpudvTJuL3p5dT+iGWmRV8/nwkXN7SXY=";

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
    install -Dm0644 dist/tpm2-proxyd.service \
      "$out/lib/systemd/system/tpm2-proxyd.service"
    install -Dm0644 dist/tpm2-proxyd.socket \
      "$out/lib/systemd/system/tpm2-proxyd.socket"
    install -Dm0644 dist/tpm2-proxyd.sysusers \
      "$out/lib/sysusers.d/tpm2-proxyd.conf"
    installManPage tpm2-proxyd.8
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
