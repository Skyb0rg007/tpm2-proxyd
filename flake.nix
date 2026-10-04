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

      nixosModules.default =
        { lib, pkgs, ... }:
        {
          imports = [ ./nix/module.nix ];
          services.tpm2-proxyd.package =
            lib.mkDefault
              self.packages.${pkgs.stdenv.hostPlatform.system}.tpm2-proxyd;
        };

      checks = forAllSystems (system: {
        inherit (self.packages.${system}) tpm2-proxyd;
        app-tests = (pkgsFor system).callPackage ./nix/app-tests.nix {
          inherit (self.packages.${system}) tpm2-proxyd;
        };
        module = (pkgsFor system).callPackage ./nix/module-test.nix {
          inherit (self.packages.${system}) tpm2-proxyd;
        };
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

          # The default shell plus the applications tests/apps drives.
          apps = pkgs.mkShell {
            inputsFrom = [ self.devShells.${system}.default ];
            packages = [
              pkgs.openssh
              pkgs.openssl
              pkgs.tpm2-pkcs11.bin
            ];
            OPENSSL_MODULES = "${pkgs.tpm2-openssl}/lib/ossl-modules";
            TPM2_PKCS11_MODULE = "${pkgs.tpm2-pkcs11}/lib/libtpm2_pkcs11.so";
          };
        }
      );

      formatter = forAllSystems (system: (pkgsFor system).nixfmt);
    };
}
