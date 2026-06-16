# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: BSD-2-Clause

{
  pkgs ? import <nixpkgs> { },
}:
pkgs.mkShell {
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
