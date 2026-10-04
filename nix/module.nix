# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: Apache-2.0

# NixOS module for tpm2-proxyd. The systemd units come from the package
# (dist/tpm2-proxyd.{service,socket}); this only enables them and supplies the
# configuration.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.tpm2-proxyd;
  json = pkgs.formats.json { };

  configDir = "/etc/tpm2-proxyd";
  socket = "/run/tpm2-proxyd/tpm2-proxyd.sock";

  policyFile = json.generate "tpm2-proxyd-policy.json" cfg.settings;
  # A profile is a file (a path, string or derivation) or its settings.
  profileFile =
    name: profile:
    if lib.isStringLike profile then
      profile
    else
      json.generate "tpm2-proxyd-profile-${name}.json" profile;
  profileFiles = lib.mapAttrs profileFile cfg.profiles;

  tctiVariables = [
    "TPM2TOOLS_TCTI"
    "TPM2_PKCS11_TCTI"
    "TPM2OPENSSL_TCTI"
  ];
in
{
  options.services.tpm2-proxyd = {
    enable = lib.mkEnableOption ''
      tpm2-proxyd, which gives local users access to the TPM through a per-user
      policy. It listens on `${socket}` and starts on the first connection'';

    package = lib.mkOption {
      type = lib.types.package;
      description = "The tpm2-proxyd package.";
      defaultText = lib.literalExpression "tpm2-proxyd.packages.\${system}.tpm2-proxyd";
    };

    settings = lib.mkOption {
      inherit (json) type;
      default = {
        default_profile = "standard";
        default_max_priority = 0;
        rules = [ ];
      };
      example = lib.literalExpression ''
        {
          default_profile = "standard";
          default_max_priority = 0;
          rules = [
            { subject.gid = 1001; profile = "admin"; max_priority = 10; }
          ];
        }
      '';
      description = ''
        The policy, written to `${configDir}/policy.json`. Rules are matched in
        order by UID and GID (numeric) and give each peer a profile and a
        priority cap; a peer no rule matches gets `default_profile`, or no
        access if that is unset. See tpm2-proxyd(8).

        Changing it reloads the daemon without dropping its connections.
      '';
    };

    profiles = lib.mkOption {
      type = with lib.types; attrsOf (either path json.type);
      example = lib.literalExpression ''
        {
          random = { commands = [ "TPM_CC_GetRandom" ]; };
          admin = ./profiles/admin.json;
        }
      '';
      description = ''
        Command profiles, by name: each either a profile's settings or a JSON
        file, written to `${configDir}/profiles/<name>.json`. The package's
        `standard` profile is included unless overridden. See tpm2-proxyd(8).

        Changing them reloads the daemon without dropping its connections.
      '';
    };

    extraArgs = lib.mkOption {
      type = with lib.types; listOf str;
      default = [ ];
      example = [
        "--max-connections-per-uid=32"
        "--auth-failure-limit=10"
      ];
      description = ''
        Extra command-line arguments for the daemon. Each takes the form
        `--name=value`. See tpm2-proxyd(8).
      '';
    };

    tcti = lib.mkOption {
      type = lib.types.str;
      readOnly = true;
      default = "${cfg.package}/lib/libtss2-tcti-proxy.so:${socket}";
      defaultText = lib.literalExpression ''"''${cfg.package}/lib/libtss2-tcti-proxy.so:${socket}"'';
      description = ''
        The TCTI configuration string for clients of the proxy, with the TCTI
        module by its full path: on NixOS the tpm2-tss loader doesn't find it
        by name. Use it to point a service at the proxy, as in
        `environment.TPM2TOOLS_TCTI = config.services.tpm2-proxyd.tcti`.
      '';
    };

    tctiEnvironment.enable = lib.mkEnableOption ''
      pointing TPM software at the proxy by default, by setting
      ${lib.concatMapStringsSep ", " (name: "`${name}`") tctiVariables} to
      {option}`services.tpm2-proxyd.tcti` for every user'';
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        # The packaged units name the group: the service joins it to open
        # /dev/tpmrm0, and the socket is owned by it.
        assertion = config.security.tpm2.tssGroup == "tss";
        message = "services.tpm2-proxyd requires security.tpm2.tssGroup to be \"tss\".";
      }
      {
        assertion = !(cfg.tctiEnvironment.enable && config.security.tpm2.tctiEnvironment.enable);
        message = ''
          services.tpm2-proxyd.tctiEnvironment and security.tpm2.tctiEnvironment
          both set the TCTI environment variables; enable only one.
        '';
      }
    ];

    # The tss group, and udev rules giving it /dev/tpmrm0.
    security.tpm2.enable = true;

    services.tpm2-proxyd.profiles.standard = lib.mkDefault "${cfg.package}/share/tpm2-proxyd/profiles/standard.json";

    environment.etc = {
      "tpm2-proxyd/policy.json".source = policyFile;
    }
    // lib.mapAttrs' (
      name: file: lib.nameValuePair "tpm2-proxyd/profiles/${name}.json" { source = file; }
    ) profileFiles;

    environment.systemPackages = [ cfg.package ];
    environment.variables = lib.mkIf cfg.tctiEnvironment.enable (
      lib.genAttrs tctiVariables (_: cfg.tcti)
    );

    users.users.tpm2-proxyd = {
      isSystemUser = true;
      group = "tpm2-proxyd";
      description = "TPM2 Proxy Broker daemon";
    };
    users.groups.tpm2-proxyd = { };

    systemd.packages = [ cfg.package ];
    systemd.sockets.tpm2-proxyd.wantedBy = [ "sockets.target" ];
    systemd.services.tpm2-proxyd = {
      serviceConfig.ExecStart = [
        ""
        (lib.escapeShellArgs (
          [
            (lib.getExe cfg.package)
            "--config=${configDir}/policy.json"
          ]
          ++ cfg.extraArgs
        ))
      ];
      # The daemon re-reads the policy and profiles on SIGHUP.
      reloadTriggers = [ policyFile ] ++ lib.attrValues profileFiles;
    };
  };
}
