# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: Apache-2.0

# The application tests (tests/apps) in a NixOS VM whose virtual TPM sits
# behind the kernel resource manager, run as an unprivileged member of the
# tss group.
{
  lib,
  testers,
  tpm2-proxyd,
  openssh,
  openssl,
  tpm2-openssl,
  tpm2-pkcs11,
}:
let
  tests = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../tests/apps
      ../dist/profiles
    ];
  };
  env = lib.concatStringsSep " " [
    "PATH=${
      lib.makeBinPath [
        openssh
        openssl
        tpm2-pkcs11.bin
      ]
    }:$PATH"
    "OPENSSL_MODULES=${tpm2-openssl}/lib/ossl-modules"
    "TPM2_PKCS11_MODULE=${tpm2-pkcs11}/lib/libtpm2_pkcs11.so"
    "TPM2_PROXYD=${lib.getExe tpm2-proxyd}"
    "TCTI_PROXY=${tpm2-proxyd}/lib/libtss2-tcti-proxy.so"
    "REQUIRE_ALL=1"
  ];
in
testers.runNixOSTest {
  name = "tpm2-proxyd-apps";

  nodes.machine = {
    virtualisation.tpm.enable = true;
    security.tpm2.enable = true;
    users.users.alice = {
      isNormalUser = true;
      extraGroups = [ "tss" ];
    };
  };

  testScript = ''
    machine.wait_for_unit("multi-user.target")
    machine.succeed("test -c /dev/tpmrm0")
    machine.succeed("su - alice -c '${env} bash ${tests}/tests/apps/run.sh' >&2")
  '';
}
