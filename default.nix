# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: Apache-2.0

{
  pkgs ? import <nixpkgs> { },
}:
pkgs.callPackage ./nix/tpm2-proxyd.nix { }
