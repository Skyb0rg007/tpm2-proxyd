# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: Apache-2.0

{
  pkgs ? import <nixpkgs> { },
}:
let
  tpm2-proxyd = pkgs.callPackage ./nix/tpm2-proxyd.nix { };
in
pkgs.mkShell {
  inputsFrom = [ tpm2-proxyd ];
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
    pkgs.cargo-license
    pkgs.cargo-nextest
    pkgs.commitlint
    pkgs.asciidoctor
    pkgs.swtpm
  ];
}
