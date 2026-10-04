# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: Apache-2.0

# The NixOS module in a VM with a virtual TPM: unprivileged users reach the
# TPM only through the socket-activated daemon, each under their own profile.
{
  lib,
  testers,
  tpm2-proxyd,
  tpm2-tools,
}:
testers.runNixOSTest {
  name = "tpm2-proxyd-module";

  nodes.machine = {
    imports = [ ./module.nix ];

    virtualisation.tpm.enable = true;
    environment.systemPackages = [ tpm2-tools ];

    services.tpm2-proxyd = {
      enable = true;
      package = tpm2-proxyd;
      tctiEnvironment.enable = true;
      settings = {
        default_profile = "standard";
        default_max_priority = 0;
        rules = [
          {
            subject.uid = 1001;
            profile = "random";
          }
        ];
      };
      # tpm2-tools reads the TPM's capabilities before anything else.
      profiles.random.commands = [
        "TPM_CC_GetCapability"
        "TPM_CC_GetRandom"
      ];
    };

    # The same system with bob under the default profile.
    specialisation.new-policy.configuration = {
      services.tpm2-proxyd.settings.rules = lib.mkForce [ ];
    };

    users.users = {
      alice = {
        isNormalUser = true;
        uid = 1000;
      };
      bob = {
        isNormalUser = true;
        uid = 1001;
      };
    };
  };

  testScript = ''
    def as_user(user, command):
        return f"su - {user} -c '{command}'"

    machine.wait_for_unit("tpm2-proxyd.socket")
    machine.succeed("test -c /dev/tpmrm0")

    with subtest("the socket is open to everyone, the device isn't"):
        machine.succeed("test \"$(stat -c '%a %U %G' /run/tpm2-proxyd/tpm2-proxyd.sock)\" = '666 tss tss'")
        machine.fail(as_user("alice", "test -w /dev/tpmrm0"))

    with subtest("users reach the TPM through the proxy by default"):
        machine.succeed(as_user("alice", "tpm2_getrandom --hex 8"))
        machine.wait_for_unit("tpm2-proxyd.service")
        machine.succeed(as_user("alice", "tpm2_readclock"))

    with subtest("each user gets their own profile"):
        machine.succeed(as_user("bob", "tpm2_getrandom --hex 8"))
        machine.fail(as_user("bob", "tpm2_readclock"))
        # Denied by the policy before it reaches the TPM.
        machine.fail(as_user("alice", "tpm2_clear -c l"))
        machine.succeed("journalctl -u tpm2-proxyd.service | grep -q 'command denied'")

    with subtest("a policy change reloads the daemon rather than restarting it"):
        pid = machine.succeed("systemctl show -P MainPID tpm2-proxyd.service").strip()
        machine.succeed("/run/booted-system/specialisation/new-policy/bin/switch-to-configuration test")
        machine.wait_until_succeeds("journalctl -u tpm2-proxyd.service | grep -q 'policy reloaded'")
        t.assertEqual(pid, machine.succeed("systemctl show -P MainPID tpm2-proxyd.service").strip())
        machine.succeed(as_user("bob", "tpm2_readclock"))
  '';
}
