# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: BSD-2-Clause

{
  pkgs ? import <nixpkgs> { },
}:
pkgs.mkShell {
  # tpm2-crypto (pulled in by tpm2-device) links against OpenSSL via openssl-sys.
  nativeBuildInputs = [
    pkgs.pkg-config
  ];
  buildInputs = [
    pkgs.openssl
  ];
  packages = [
    pkgs.tpm2-tss
    pkgs.cargo
    pkgs.rustc
    pkgs.rustfmt
    pkgs.editorconfig-checker
    pkgs.reuse
    pkgs.treefmt
    pkgs.pre-commit
    pkgs.nixfmt
    pkgs.clippy
  ];
}
