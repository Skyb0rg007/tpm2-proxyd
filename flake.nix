# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: Apache-2.0

{
  description = "Proxy service for TPM2 commands";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      forAllSystems = nixpkgs.lib.genAttrs [
        "aarch64-linux"
        "x86_64-linux"
      ];
      pkgsFor = system: import nixpkgs { inherit system; };
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          tpm2-proxyd = pkgs.callPackage ./nix/tpm2-proxyd.nix { };
        in
        {
          inherit tpm2-proxyd;
          default = tpm2-proxyd;
        }
      );

      checks = forAllSystems (system: {
        inherit (self.packages.${system}) tpm2-proxyd;
      });

      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          default = pkgs.mkShell {
            inputsFrom = [ self.packages.${system}.tpm2-proxyd ];
            packages = [
              pkgs.asciidoctor
              pkgs.cargo
              pkgs.cargo-license
              pkgs.cargo-nextest
              pkgs.clippy
              pkgs.commitlint
              pkgs.editorconfig-checker
              pkgs.nixfmt
              pkgs.pre-commit
              pkgs.reuse
              pkgs.rustc
              pkgs.rustfmt
              pkgs.swtpm
              pkgs.tpm2-tss
              pkgs.treefmt
            ];
          };
        }
      );

      formatter = forAllSystems (system: (pkgsFor system).nixfmt);
    };
}
