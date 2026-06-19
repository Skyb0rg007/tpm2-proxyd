# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: Apache-2.0

{
  lib,
  rustPlatform,
  pkg-config,
  openssl,
}:
rustPlatform.buildRustPackage (finalAttrs: {
  pname = "tpm2-proxyd";
  version = "0.1.0";
  src = lib.sources.cleanSource ../.;

  cargoHash = "sha256-YkOzkXctxJaLJ6nwUV31IbliRrx95TqOZiBW++ifhlw=";

  nativeBuildInputs = [ pkg-config ];
  buildInputs = [ openssl ];

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
