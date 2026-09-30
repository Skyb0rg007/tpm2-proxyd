<!--
SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>

SPDX-License-Identifier: Apache-2.0
-->

# tpm2-proxyd Policy Language

This document designs a future declarative policy language for `tpm2-proxyd`. It
is not the small JSON format currently parsed by
`crates/tpm2-proxyd/src/policy.rs`. The goal is to describe a policy model rich
enough to make local multi-user TPM access safe: not just "may this UID send
command code X?", but "may this subject send this command with these handles,
parameters, object templates, and ownership relationships?"

The language is deliberately declarative. Administrators describe subjects,
namespaces, resource ownership rules, and command predicates. The daemon parses
that data into a typed in-memory rule tree. Policy evaluation must not run
arbitrary code.

## Design Goals

- **Default deny.** Unknown commands, unknown fields, unknown predicates, and
  untracked resources are denied unless a rule explicitly says otherwise.
- **Parameter-aware authorization.** Rules can match command handles, command
  parameters, authorization handles, object templates, NV attributes, PCR
  selections, and policy sessions.
- **Ownership-aware authorization.** The daemon can allow destructive operations
  only when the target resource is owned by the caller, by the caller's
  connection, or by a configured namespace.
- **Auditable decisions.** Every allow or deny result should identify the rule
  that decided it and the inputs that mattered.
- **No general-purpose scripting.** The policy format should be finite,
  deterministic, side-effect-free, and statically validated on reload.
- **Stable over TPM evolution.** Newly recognized TPM commands should not become
  implicitly available to unprivileged users.

## File Format

The recommended user-facing format is YAML:

- Comments are useful for local security policy.
- Nested maps make command-specific predicates readable.
- The daemon should still deserialize into `deny_unknown_fields`-style typed
  structures and reject unknown keys.

JSON and TOML could represent the same model, but YAML is the clearest default
for shipped examples. The policy language should treat YAML as syntax only; the
semantic model is the typed schema below.

## Top-Level Shape

```yaml
version: 1

defaults:
  decision: deny
  priority: 0
  unknown_resources: deny
  audit: deny

subjects: {}
namespaces: {}
limits: {}
rules: []
```

### `version`

Required integer. Version `1` is the language described here. The daemon should
reject policies with unsupported major versions.

### `defaults`

Global fallback behavior.

- `decision`: `allow` or `deny`; production policies should use `deny`.
- `priority`: maximum scheduling priority when no priority rule matches.
- `unknown_resources`: `allow` or `deny`; production policies should use
  `deny`.
- `audit`: one of `none`, `allow`, `deny`, `all`.

### `subjects`

Named subject selectors reusable from rules.

```yaml
subjects:
  admins:
    any:
      - uid: 0
      - group: tpm-admins

  local_users:
    group: tpm-users

  system_services:
    any:
      - uid: tpm2-proxyd
      - group: systemd-journal
```

Subject selector fields:

- `uid`: numeric UID or local user name.
- `gid`: numeric GID.
- `group`: local group name.
- `supplementary_group`: numeric GID or group name.
- `process_label`: optional future LSM label match, such as SELinux/AppArmor.
- `executable`: optional future executable path or measured identity.
- `all`: list of selectors that must all match.
- `any`: list of selectors where at least one must match.
- `not`: selector that must not match.

User and group names are resolved at policy-load time. A reload should fail if a
named subject cannot be resolved, unless the rule explicitly sets
`missing: ignore`.

### `namespaces`

Namespaces define handle ranges or resource sets assigned to subjects.

```yaml
namespaces:
  persistent:
    user_keys:
      range: "0x81010000..0x8101ffff"
      owner: peer_uid

  nv:
    user_nv:
      range: "0x01810000..0x0181ffff"
      owner: peer_uid

  pcr:
    user_readable:
      banks: [sha256, sha384]
      indexes: [0, 1, 2, 3, 4, 5, 6, 7, 11]
```

Namespace types:

- `persistent`: TPM persistent object handles.
- `nv`: TPM NV index handles.
- `pcr`: PCR bank/index sets.
- `transient`: tracked transient object categories.
- `session`: tracked session categories.

Namespace ownership strategies:

- `peer_uid`: owned by the UID that created or defined it.
- `peer_gid`: owned by the matching GID.
- `connection`: owned by the connection that created it.
- `static`: owned by the named subject in the namespace.
- `shared`: readable or usable by matching subjects, but mutable only by a
  separate owner rule.

For high-assurance operation, persistent and NV ownership should be keyed by both
handle number and public name. A handle alone can be reused after reboot or after
out-of-band TPM access.

### `limits`

Limits bound resource consumption and scheduling.

```yaml
limits:
  default:
    max_priority: 0
    command_timeout: 30s
    max_command_size: 4096
    max_connections: 2
    max_transient_objects: 8
    max_sessions: 4
    rate:
      window: 1m
      commands: 120
```

Per-subject limits can be selected from rules or referenced by name. Duration
values should support `ms`, `s`, and `m` suffixes.

## Rules

Rules are evaluated in declaration order. The first rule whose subject, command,
and predicates match returns its `decision`. If no rule matches, `defaults` are
used.

```yaml
rules:
  - id: users-read-capabilities
    decision: allow
    subject: local_users
    commands: [GetCapability, GetRandom, PCR_Read]
    where:
      all:
        - pcr_selection.in_namespace: pcr.user_readable
    audit: allow
```

Rule fields:

- `id`: required stable identifier used in logs and diagnostics.
- `decision`: `allow` or `deny`.
- `subject`: inline selector or name from `subjects`.
- `commands`: list of TPM command names, numeric command IDs, command classes, or
  `["*"]`.
- `where`: optional predicate tree.
- `priority`: optional max priority for matching connections or commands.
- `limits`: optional named or inline limits for the matching subject.
- `audit`: optional `none`, `allow`, `deny`, or `all`.

Command names use the Rust enum variant names from
`tpm2_protocol::data::TpmCc`, such as `GetRandom`, `FlushContext`, or
`NvUndefineSpace`. The loader may also accept TPM spec spellings such as
`TPM_CC_GetRandom`, but it should normalize to enum names internally.

## Command Classes

Rules can reference command classes to avoid error-prone long command lists.
Classes are daemon-defined, versioned, and expanded at policy-load time.

Recommended classes:

- `capability_read`: `GetCapability`, `ReadPublic`, `NV_ReadPublic`,
  `NV_ReadPublic2`, `ReadClock`, `GetTestResult`, `ECC_Parameters`.
- `random`: `GetRandom`, `StirRandom`.
- `pcr_read`: `PCR_Read`.
- `pcr_mutate`: `PCR_Extend`, `PCR_Event`, `PCR_Reset`, `PCR_Allocate`,
  `PCR_SetAuthPolicy`, `PCR_SetAuthValue`.
- `object_create`: `Create`, `CreatePrimary`, `CreateLoaded`, `Load`,
  `LoadExternal`, `Import`.
- `object_use`: `Sign`, `RSA_Decrypt`, `RSA_Encrypt`, `ECDH_ZGen`,
  `ECDH_KeyGen`, `ZGen_2Phase`, `HMAC`, `EncryptDecrypt`, `EncryptDecrypt2`,
  `Unseal`, `Quote`, `Certify`, `CertifyCreation`.
- `object_destroy`: `FlushContext`, `EvictControl`.
- `nv_read`: `NV_Read`, `NV_ReadPublic`, `NV_ReadPublic2`, `NV_Certify`.
- `nv_mutate`: `NV_DefineSpace`, `NV_DefineSpace2`, `NV_UndefineSpace`,
  `NV_UndefineSpaceSpecial`, `NV_Write`, `NV_WriteLock`, `NV_ReadLock`,
  `NV_Increment`, `NV_SetBits`, `NV_Extend`, `NV_ChangeAuth`,
  `NV_GlobalWriteLock`.
- `session`: `StartAuthSession`, all `Policy*` commands.
- `admin`: hierarchy, clear, dictionary-attack, audit, firmware, physical
  presence, vendor, attached-component, and platform-control commands.

Classes should be conservative. If a new TPM command is added to
`tpm2-protocol`, it should not silently enter an unprivileged class without a
policy-language version update.

## Predicate Language

`where` is a declarative predicate tree. It supports logical combinators and
typed predicates.

```yaml
where:
  all:
    - target.kind: transient
    - target.owned_by: peer
    - target.tracked: true
```

Logical forms:

- `all`: every child predicate must match.
- `any`: at least one child predicate must match.
- `not`: child predicate must not match.

All predicate names are fixed by the daemon. Unknown predicates are load errors.

### Peer Predicates

- `peer.uid`: exact UID.
- `peer.gid`: primary GID.
- `peer.in_group`: primary or supplementary group.
- `peer.is_admin`: true if subject matched an administrator selector.
- `peer.label`: optional LSM/process label.

### Handle Predicates

Handle aliases are command-specific. Common aliases:

- `target`: the main handle being operated on.
- `object`: object being used.
- `parent`: parent object.
- `auth`: authorization handle.
- `persistent`: persistent handle argument.
- `nv_index`: NV index argument.
- `session`: policy or HMAC session handle.

Predicates:

- `<alias>.kind`: `transient`, `persistent`, `session`, `sequence`, `nv_index`,
  `pcr`, `hierarchy`, `permanent`, or `attached_component`.
- `<alias>.tracked`: boolean.
- `<alias>.owned_by`: `peer`, `connection`, a subject name, or `any`.
- `<alias>.not_owned_by`: same values as `owned_by`.
- `<alias>.in_namespace`: namespace reference such as `persistent.user_keys`.
- `<alias>.public_name`: exact public name digest, for pinned objects.
- `<alias>.attributes`: required object or NV attributes.
- `<alias>.empty`: true if the daemon has verified that the persistent/NV handle
  is unused.

Destructive commands should almost always require `tracked: true` and
`owned_by: peer` or an administrator subject.

### Authorization Predicates

- `auth_handles.all_owned_by`: owner required for all authorization handles.
- `auth_handles.any_owned_by`: owner required for at least one authorization
  handle.
- `auth_hierarchy.in`: allowed hierarchy handles.
- `requires_admin_auth`: boolean derived by command parser.
- `sessions.all_owned_by`: owner required for all referenced sessions.

### Object Template Predicates

Used for `Create`, `CreatePrimary`, `CreateLoaded`, `Load`, `LoadExternal`, and
`Import`.

- `template.type`: `rsa`, `ecc`, `keyed_hash`, `symcipher`, or `data`.
- `template.name_alg.in`: allowed name algorithms.
- `template.attributes.require`: required `TPMA_OBJECT` flags.
- `template.attributes.forbid`: forbidden `TPMA_OBJECT` flags.
- `template.rsa_bits.in`: allowed RSA key sizes.
- `template.ecc_curve.in`: allowed ECC curves.
- `template.scheme.in`: allowed signing/encryption schemes.
- `template.symmetric.in`: allowed symmetric algorithms.
- `load_external.private_allowed`: boolean.

Example:

```yaml
where:
  all:
    - parent.owned_by: peer
    - template.type: ecc
    - template.ecc_curve.in: [nist_p256, nist_p384]
    - template.attributes.require: [fixedTPM, fixedParent, sensitiveDataOrigin]
    - template.attributes.forbid: [decrypt]
```

### NV Predicates

- `nv_index.in_namespace`: namespace reference.
- `nv_index.owned_by`: owner selector.
- `nv_index.public_read`: boolean derived from attributes.
- `nv_index.attributes.require`: required NV attributes.
- `nv_index.attributes.forbid`: forbidden NV attributes.
- `nv_index.size.max`: maximum data size.
- `nv_index.write_locked`: boolean.
- `nv_index.read_locked`: boolean.

### PCR Predicates

- `pcr_selection.in_namespace`: namespace reference.
- `pcr_selection.banks.in`: allowed hash banks.
- `pcr_selection.indexes.in`: allowed PCR indexes.
- `pcr_selection.mutates`: boolean.

### Command Parameter Predicates

Some commands need narrow parameter checks:

- `bytes_requested.max`: for `GetRandom`.
- `capability.in`: for `GetCapability`.
- `hash_alg.in`: for `Hash`, sequence commands, and templates.
- `flush_target.kind`: for `FlushContext`.
- `evict.operation`: `persist` or `evict`.
- `context.kind`: for `ContextSave` and `ContextLoad`.

Command-specific aliases and predicates must be documented by the daemon. A
policy that uses a predicate not valid for the matched command should fail to
load, rather than evaluate false silently.

## Resource Tracking Semantics

The policy engine needs a provenance database, separate from TPM resource
management:

- On successful `CreatePrimary`, `Load`, `LoadExternal`, `CreateLoaded`,
  `StartAuthSession`, `HashSequenceStart`, `HMAC_Start`, and similar commands,
  record returned transient/session/sequence handles with peer and connection
  ownership.
- On successful `FlushContext`, remove the tracked handle.
- On successful `EvictControl` persist operation, record the persistent handle
  owner, source object public name, and namespace.
- On successful `EvictControl` evict operation, remove the persistent record.
- On successful `NV_DefineSpace`, record NV ownership and public attributes.
- On successful `NV_UndefineSpace`, remove the NV record.
- On connection close, remove connection-scoped transient/session/sequence
  records.

No virtual handle rewriting is implied. The proxy records ownership of real TPM
handles observed in successful command responses. Because external processes may
touch the TPM outside the proxy, untracked or stale resources must be treated
according to `defaults.unknown_resources`, which should be `deny` for ordinary
users.

## Evaluation Algorithm

For each command:

1. Parse the TPM command header and command body into a typed command view.
2. Reject unknown or unsupported commands before policy evaluation.
3. Resolve the peer identity and matching named subjects.
4. Build a policy input object containing command code, command class, handles,
   parsed parameters, authorization handles, tracked resource metadata, limits,
   and peer identity.
5. Evaluate rules in order.
6. If a rule matches, return its decision and audit metadata.
7. If no rule matches, return `defaults.decision`.
8. Forward only allowed commands upstream.
9. If the TPM response succeeds, update resource tracking state for commands
   that create, load, persist, flush, define, or undefine resources.

Policy reload should be atomic. Existing tracked resource state should survive a
reload, but rules should be revalidated against the new schema and command-class
definitions before becoming active.

## Safe Defaults

A safe unprivileged profile should:

- allow capability reads, bounded random bytes, and selected PCR reads;
- allow object creation/loading only with constrained templates;
- allow use and flush only for tracked resources owned by the peer;
- deny destructive commands against untracked resources;
- deny hierarchy, platform, clear, firmware, vendor, and physical-presence
  commands;
- allow persistent and NV writes only inside assigned namespaces;
- deny persistent/NV replacement unless the existing resource is owned by the
  peer;
- cap priority and command rate for ordinary users.

## Why Not a Scripting Language?

A scripting language would make policies expressive, but it would also make
authorization harder to audit and harder to bound. TPM command authorization runs
inside a privileged service on the hot path for every command. Policy evaluation
should therefore be deterministic, finite, and validated before reload.

If the declarative language later needs more expressive boolean conditions, a
small non-Turing-complete expression language such as CEL could be embedded only
inside `where.expr` fields. Even then, the values exposed to expressions should
be typed TPM policy inputs, not arbitrary daemon internals, and expression
evaluation should have strict cost limits.
