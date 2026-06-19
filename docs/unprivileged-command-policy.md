<!--
SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>

SPDX-License-Identifier: Apache-2.0
-->

# Unprivileged TPM2 Command Policy Matrix

This document classifies every TPM command currently listed in
`docs/tpm2-protocol-commands.md` and describes how `tpm2-proxyd` should handle
it when granting access to unprivileged local users.

The core rule is: command-code allowlists are not enough. Many TPM commands are
safe only when every referenced handle, NV index, session, or persistent object
belongs to the caller or is explicitly marked shared.

## Policy Terms

- **Unrestricted:** safe to allow for ordinary users with basic size, timeout,
  and rate limits. The command does not modify shared TPM state or operate on
  another caller's resource.
- **Bounded read:** safe to allow only for selected capabilities, PCRs, handle
  ranges, or response sizes. It is read-only but may reveal platform state.
- **Tracked-owner:** allow only when every object/session/sequence handle being
  used was created or loaded through the proxy and is owned by the current
  connection or by the same UID policy identity.
- **User namespace:** allow only inside a configured per-user/per-group namespace
  such as a persistent-handle range or NV-index range. Replacement/deletion must
  require prior recorded ownership.
- **Template-limited:** allow only when object templates, algorithms, attributes,
  key sizes, curves, and schemes match an administrator-approved profile.
- **Admin-only:** reserve for root or an explicit TPM administrator group.
- **Deny:** do not expose to unprivileged users. This includes vendor,
  firmware-update, platform-control, physical-presence, and unmodeled attached
  component operations.

Ownership can mean either **connection-owned** (created on this socket) or
**peer-owned** (created by another process with the same UID or policy identity).
A deployment should choose which scope it trusts. Peer-owned policy requires a
durable provenance database keyed by handle/name, not just the raw handle value.

## Windows TBS Comparison Comments

Microsoft's public TBS documentation describes the relevant unprivileged policy
surface as command blocking: Windows 8 and later allow standard users to access
TBS, but restrict command execution; for TPM 2.0 the blocking logic is inverted
into an allowlist, and newer Windows releases fix the TPM 2.0 allowlist in the
TPM driver instead of exposing it through mutable registry policy. The same
documentation also describes context-bound resource virtualization for keys and
sessions. Those virtual-handle mechanics are not counted as differences here:
when TBS can make a command safe by restricting it to resources created in the
caller's context, this matrix treats that as equivalent to `tpm2-proxyd`
tracked-owner handling.

The commands below are handled differently in this document because the proposed
Linux policy needs conditions that are not expressible by TBS's documented
standard-user command-code allow/block model. Commands not listed here are either
aligned at the command-code level, differ only in implementation mechanics such
as handle virtualization, or need confirmation against a tested Windows build's
fixed driver allowlist.

Sources: Microsoft, "Command Blocking",
<https://learn.microsoft.com/en-us/windows/win32/tbs/command-blocking>;
Microsoft, "Using TBS",
<https://learn.microsoft.com/en-us/windows/win32/tbs/using-tbs>; Microsoft,
"Resource Virtualization",
<https://learn.microsoft.com/en-us/windows/win32/tbs/resource-virtualization>.

| Command | TBS comparison comment |
| --- | --- |
| `TPM_CC_ECC_Parameters` | This policy may restrict curve IDs. TBS command blocking can allow or block the command, but does not expose per-curve policy in the documented standard-user model. |
| `TPM_CC_Hash` | This policy restricts input size and hierarchy/ticket choices. TBS command blocking is command-code scoped. |
| `TPM_CC_TestParms` | This policy may restrict algorithms and parameter shapes. TBS command blocking cannot express an approved-parameter subset. |
| `TPM_CC_EC_Ephemeral` | This policy restricts curves and rate. TBS command blocking cannot express per-curve access. |
| `TPM_CC_IncrementalSelfTest` | This policy allows only approved algorithms and rate-limited use. TBS command blocking can only allow or block the command for standard users. |
| `TPM_CC_SelfTest` | This policy allows the command only with denial-of-service controls. TBS command blocking is not a per-caller rate policy. |
| `TPM_CC_MakeCredential` | This policy restricts target names to public, owned, or approved objects. TBS command blocking cannot express target-name policy. |
| `TPM_CC_NV_ReadPublic` | This policy limits NV metadata reads to configured ranges. TBS does not virtualize NV storage and its command blocking does not express per-user NV namespaces. |
| `TPM_CC_ReadPublic` | This policy can hide unowned object metadata unless the object is shared. TBS can isolate virtualized context resources, but command blocking does not express object-metadata privacy policy. |
| `TPM_CC_RSA_Encrypt` | This policy restricts key ownership/sharing, schemes, and input sizes. TBS command blocking cannot express scheme or size predicates. |
| `TPM_CC_VerifySignature` | This policy restricts verification keys and schemes. TBS command blocking cannot express per-key or per-scheme constraints. |
| `TPM_CC_GetCapability` | This policy allows only selected capabilities and may hide handle enumeration. TBS command blocking cannot express per-capability or per-property filtering. |
| `TPM_CC_GetTestResult` | This policy treats the result as a rate-limited diagnostic read. TBS command blocking has no documented per-caller diagnostic-rate predicate. |
| `TPM_CC_PCR_Read` | This policy restricts PCR banks and indexes. TBS command blocking cannot express PCR-selection policy. |
| `TPM_CC_ECC_Encrypt` | This policy restricts keys, curves, schemes, and input sizes. TBS command blocking cannot express those parameter predicates. |
| `TPM_CC_NV_ReadPublic2` | Same difference as `TPM_CC_NV_ReadPublic`: this policy has NV range rules, while TBS command blocking is command-code scoped. |
| `TPM_CC_SequenceComplete` | This policy distinguishes ordinary sequence completion from PCR/event completion paths. TBS command blocking cannot express that destination-handle distinction. |
| `TPM_CC_Duplicate` | This policy requires approved export and target-parent rules. TBS context ownership can isolate handles, but command blocking cannot express duplication/export policy. |
| `TPM_CC_Load` | This policy ties loaded objects back to prior create/import records or approved import profiles. TBS can virtualize loaded handles, but command blocking cannot validate that provenance relationship. |
| `TPM_CC_Quote` | This policy restricts PCR selections as well as signing keys. TBS command blocking cannot express PCR-selection constraints. |
| `TPM_CC_RSA_Decrypt` | This policy restricts schemes and input sizes in addition to key ownership. TBS command blocking cannot express those predicates. |
| `TPM_CC_SequenceUpdate` | This policy caps sequence chunk sizes. TBS command blocking cannot express per-command payload limits. |
| `TPM_CC_Sign` | This policy restricts signing schemes and digest sizes. TBS command blocking cannot express those predicates. |
| `TPM_CC_ContextLoad` | This policy allows only saved contexts previously emitted to the same policy identity and matching recorded metadata. TBS virtualization covers its own context resources, but command blocking cannot express cross-command saved-context provenance. |
| `TPM_CC_ContextSave` | This policy records saved-context provenance for later authorization. TBS command blocking does not expose that provenance rule as policy. |
| `TPM_CC_ECDH_KeyGen` | This policy requires an allowed key and treats returned material under local ownership rules. TBS command blocking cannot express key-sharing policy beyond context isolation. |
| `TPM_CC_EncryptDecrypt` | This policy restricts modes and buffer sizes. TBS command blocking cannot express symmetric-mode or size predicates. |
| `TPM_CC_PolicyCommandCode` | This policy requires the embedded command code to be one the caller may execute. TBS command blocking cannot inspect policy-session construction at that level. |
| `TPM_CC_PolicyCounterTimer` | This policy restricts clock/counter operands and offsets. TBS command blocking cannot express operand-level policy. |
| `TPM_CC_PolicyCpHash` | This policy requires the cpHash to correspond to a command the caller may execute. TBS command blocking cannot derive or validate that policy intent. |
| `TPM_CC_PolicyLocality` | This policy restricts permitted localities. TBS command blocking cannot express locality-set policy. |
| `TPM_CC_PolicyNameHash` | This policy restricts referenced names to owned, shared, or approved resources. TBS command blocking cannot express name-set policy. |
| `TPM_CC_PolicyOr` | This policy restricts accepted branch digests. TBS command blocking cannot express an approved policy-branch set. |
| `TPM_CC_PolicyTicket` | This policy restricts ticket sources and authorizing keys. TBS command blocking cannot express ticket-source policy. |
| `TPM_CC_StartAuthSession` | This policy restricts bind, salt, and session-count behavior. TBS virtualizes sessions, but command blocking cannot express bind/salt predicates. |
| `TPM_CC_PolicyPCR` | This policy restricts PCR banks and indexes. TBS command blocking cannot express PCR-selection policy. |
| `TPM_CC_PolicyDuplicationSelect` | This policy restricts selected object and parent names. TBS command blocking cannot express duplication-target policy inside a policy session. |
| `TPM_CC_Commit` | This policy rate-limits use of limited ECC commit counters and restricts keys/curves. TBS command blocking cannot express counter-budget or curve policy. |
| `TPM_CC_ZGen_2Phase` | This policy restricts keys, sessions, and curves. TBS command blocking cannot express those parameter predicates. |
| `TPM_CC_PolicyNvWritten` | This policy restricts referenced NV indexes to owned, shared, or approved namespaces. TBS command blocking cannot express NV ownership policy. |
| `TPM_CC_PolicyTemplate` | This policy accepts only approved template digests. TBS command blocking cannot express object-template policy. |
| `TPM_CC_EncryptDecrypt2` | Same difference as `TPM_CC_EncryptDecrypt`: this policy restricts modes and buffer sizes, which TBS command blocking cannot express. |
| `TPM_CC_ECC_Decrypt` | This policy restricts curves, schemes, and input sizes. TBS command blocking cannot express those predicates. |
| `TPM_CC_PolicyCapability` | This policy restricts capability operands. TBS command blocking cannot express per-capability policy inside a policy session. |
| `TPM_CC_PolicyParameters` | This policy requires parameter references to match commands the caller may execute. TBS command blocking cannot express that relationship. |
| `TPM_CC_EvictControl` | This policy creates per-user persistent-handle namespaces and owned-handle deletion rules. TBS command blocking cannot express persistent-handle namespaces. |
| `TPM_CC_NV_UndefineSpace` | This policy allows deletion only for owned NV indexes inside an allowed namespace. TBS does not virtualize NV storage and command blocking cannot express per-user NV ownership. |
| `TPM_CC_NV_DefineSpace` | This policy restricts NV index ranges, sizes, and attributes. TBS command blocking cannot express NV namespace or attribute policy. |
| `TPM_CC_NV_Increment` | This policy allows mutation only of owned counter indexes. TBS command blocking cannot express per-index ownership. |
| `TPM_CC_NV_SetBits` | This policy allows mutation only of owned bit-field indexes. TBS command blocking cannot express per-index ownership. |
| `TPM_CC_NV_Extend` | This policy allows mutation only of owned extend indexes. TBS command blocking cannot express per-index ownership. |
| `TPM_CC_NV_Write` | This policy allows writes only to owned NV indexes with size/rate limits. TBS command blocking cannot express per-index write policy. |
| `TPM_CC_NV_WriteLock` | This policy prevents users from locking shared or untracked indexes. TBS command blocking cannot express per-index lock ownership. |
| `TPM_CC_NV_ChangeAuth` | This policy allows authorization changes only for owned NV indexes. TBS command blocking cannot express per-index ownership. |
| `TPM_CC_PolicyNV` | This policy restricts the authorizing NV index to owned, public-readable, or shared indexes. TBS command blocking cannot express NV-index predicates inside policy construction. |
| `TPM_CC_NV_Read` | This policy distinguishes owned, shared, and public-readable indexes. TBS command blocking cannot express per-index read policy. |
| `TPM_CC_NV_ReadLock` | This policy prevents users from read-locking shared or untracked indexes. TBS command blocking cannot express per-index lock ownership. |
| `TPM_CC_NV_Certify` | This policy combines NV read policy with signing-key policy. TBS command blocking cannot express that multi-resource predicate. |
| `TPM_CC_PolicyAuthorizeNV` | This policy restricts the authorizing NV index to owned, shared, or administrator-approved indexes. TBS command blocking cannot express NV-index predicates inside policy construction. |
| `TPM_CC_NV_DefineSpace2` | Same difference as `TPM_CC_NV_DefineSpace`: this policy restricts NV ranges, sizes, and attributes. |
| `TPM_CC_CreatePrimary` | This policy restricts hierarchy, auth, policy, algorithms, and object attributes before recording ownership. TBS can virtualize returned handles, but command blocking cannot express template policy. |
| `TPM_CC_Create` | This policy restricts parent ownership and object templates. TBS command blocking cannot express object-template policy. |
| `TPM_CC_Import` | This policy restricts imported-object templates and duplication policy. TBS command blocking cannot express import-profile policy. |
| `TPM_CC_LoadExternal` | This policy treats public-only and private external loads differently and constrains templates. TBS command blocking cannot express that distinction. |
| `TPM_CC_CreateLoaded` | This policy restricts parent/hierarchy and object template before recording ownership. TBS command blocking cannot express template policy. |

## Command Handling Groups

The groups below contain the same commands as `docs/tpm2-protocol-commands.md`, but sorted by the default policy shape recommended for unprivileged access.

### Unrestricted (8 commands)

These commands may be exposed to ordinary users with generic size, timeout, queue-depth, and rate limits.

| Command | Rationale and required conditions |
| --- | --- |
| `TPM_CC_StirRandom` | Accepts entropy into the TPM RNG; allow with size/rate limits. |
| `TPM_CC_ECC_Parameters` | Returns public curve parameters; allow with rate limits. |
| `TPM_CC_GetRandom` | Does not touch caller resources or durable state; cap requested bytes and rate. |
| `TPM_CC_Hash` | Stateless hashing; cap input size and restrict hierarchy/ticket choices to safe values such as null or an allowed hierarchy. |
| `TPM_CC_ReadClock` | Read-only TPM clock/counter state; allow with rate limits. |
| `TPM_CC_HashSequenceStart` | Starts a hash/event sequence; record returned sequence handle and cap per-peer sequence count. |
| `TPM_CC_TestParms` | Tests algorithm parameter support; allow with rate limits. |
| `TPM_CC_EC_Ephemeral` | Generates public ephemeral ECC material; restrict curves and rate. |

### Bounded read (12 commands)

These commands are read-only or public-key style operations, but should be constrained to approved capabilities, handles, PCR selections, algorithms, or response sizes.

| Command | Rationale and required conditions |
| --- | --- |
| `TPM_CC_IncrementalSelfTest` | Can be allowed with rate limits and an approved algorithm list; it consumes TPM time but does not grant resource access. |
| `TPM_CC_SelfTest` | Can be allowed with rate limits; repeated tests can be a denial-of-service vector. |
| `TPM_CC_MakeCredential` | Can be allowed for public/approved target names; restrict to objects/public names the caller is allowed to reference. |
| `TPM_CC_NV_ReadPublic` | Allow for configured NV ranges or public metadata; avoid unrestricted enumeration if handle privacy matters. |
| `TPM_CC_ReadPublic` | Allow for peer-owned objects and explicitly shared public handles; unrestricted object metadata reads may leak handle usage. |
| `TPM_CC_RSA_Encrypt` | Public-key operation; allow with public/owned/shared RSA keys, approved schemes, and size limits. |
| `TPM_CC_VerifySignature` | Public-key operation; allow with public/owned/shared verification keys and approved schemes. |
| `TPM_CC_GetCapability` | Allow selected capabilities such as algorithms, commands, PCRs, TPM properties, and ECC curves; restrict handle enumeration if needed. |
| `TPM_CC_GetTestResult` | Read-only self-test status; allow with rate limits. |
| `TPM_CC_PCR_Read` | Allow only configured PCR banks/indexes; PCRs may reveal platform state. |
| `TPM_CC_ECC_Encrypt` | Public-key style operation; allow only with public/owned/shared ECC keys, approved curves/schemes, and size limits. |
| `TPM_CC_NV_ReadPublic2` | Same as `NV_ReadPublic`: allow configured NV ranges or public metadata; avoid unrestricted enumeration if needed. |

### Tracked-owner (48 commands)

These commands may touch loaded objects, sessions, sequences, or sensitive authorizing handles. Allow them only when all relevant resources are tracked and owned by the current connection or peer identity, or are explicitly shared.

| Command | Rationale and required conditions |
| --- | --- |
| `TPM_CC_SequenceComplete` | Allow only for sequence handles owned by the peer; if it extends into a hierarchy/PCR path, require admin or an explicit PCR policy. |
| `TPM_CC_ActivateCredential` | Allow only when activated object and key handles are tracked and owned/explicitly shared for the peer. |
| `TPM_CC_Certify` | Allow only when certified object and signing key are owned by the peer or explicitly shared. |
| `TPM_CC_CertifyCreation` | Allow only for tracked-owner object and signing key; creation data should correspond to the owned object. |
| `TPM_CC_Duplicate` | Allow only for objects owned by the peer and approved target parents; require template/export policy to avoid leaking protected keys. |
| `TPM_CC_GetTime` | Requires a signing key; allow only when the privacy-sensitive signing key is owned by the peer or explicitly shared. |
| `TPM_CC_GetSessionAuditDigest` | Allow only for audit sessions owned by the peer and signing keys owned/shared for that peer. |
| `TPM_CC_ObjectChangeAuth` | Allow only for objects owned by the peer, with parent authorization also owned/shared as appropriate. |
| `TPM_CC_PolicySecret` | Allow only when the authorizing entity is owned by the peer or explicitly shared for this policy use. |
| `TPM_CC_Rewrap` | Allow only for peer-owned duplicated material and approved old/new parent handles. |
| `TPM_CC_ECDH_ZGen` | Allow only with a peer-owned or explicitly shared ECC key. |
| `TPM_CC_HMAC` | Allow only with a peer-owned or explicitly shared keyed-hash object; cap input size. |
| `TPM_CC_Load` | Parent must be tracked-owner; loaded object's public template/name must match a prior owned create/import record or approved import profile. |
| `TPM_CC_Quote` | Signing key must be owned/shared; PCR selection must be in an allowed read namespace. |
| `TPM_CC_RSA_Decrypt` | Allow only with a peer-owned decrypt key; cap input size and approved schemes. |
| `TPM_CC_HMAC_Start` | Key must be owned/shared; record returned sequence handle as peer-owned. |
| `TPM_CC_SequenceUpdate` | Sequence handle must be owned by the peer; cap chunk size. |
| `TPM_CC_Sign` | Signing key must be owned/shared; restrict schemes and digest sizes. |
| `TPM_CC_Unseal` | Sealed object must be owned by the peer; otherwise this can disclose another user's secret. |
| `TPM_CC_PolicySigned` | Policy session must be owned; signing/authorizing key must be owned/shared for this policy use. |
| `TPM_CC_ContextLoad` | Allow only for saved contexts previously emitted to the same peer identity and matching recorded object/session metadata. |
| `TPM_CC_ContextSave` | Allow only for peer-owned transient/session handles; record saved context provenance. |
| `TPM_CC_ECDH_KeyGen` | ECC key must be owned/shared; record no new persistent state beyond returned data. |
| `TPM_CC_EncryptDecrypt` | Symmetric key must be owned/shared; cap buffer sizes and allowed modes. |
| `TPM_CC_FlushContext` | Allow only for transient, session, or sequence handles owned by the current connection or peer identity. |
| `TPM_CC_PolicyAuthorize` | Policy session must be owned; authorizing key/name must be owned/shared or administrator-approved. |
| `TPM_CC_PolicyAuthValue` | Policy session must be owned by the peer. |
| `TPM_CC_PolicyCommandCode` | Policy session must be owned; command code should be allowed by the caller's policy profile. |
| `TPM_CC_PolicyCounterTimer` | Policy session must be owned; operand/offset should be bounded to supported safe clock/counter fields. |
| `TPM_CC_PolicyCpHash` | Policy session must be owned; cpHash should correspond to commands the caller is allowed to execute. |
| `TPM_CC_PolicyLocality` | Policy session must be owned; permitted localities should be administrator-defined. |
| `TPM_CC_PolicyNameHash` | Policy session must be owned; referenced names should be owned/shared or otherwise allowed. |
| `TPM_CC_PolicyOr` | Policy session must be owned; approved branch digests should be constrained to administrator-accepted policies. |
| `TPM_CC_PolicyTicket` | Policy session must be owned; ticket source/key should be owned/shared or administrator-approved. |
| `TPM_CC_StartAuthSession` | Allow with bounded session count; bind/encrypt/salt handles must be owned/shared or null; record returned session handle. |
| `TPM_CC_PolicyPCR` | Policy session must be owned; PCR selection must be in an allowed read namespace. |
| `TPM_CC_PolicyRestart` | Policy session must be owned by the peer. |
| `TPM_CC_PolicyDuplicationSelect` | Policy session must be owned; selected object/parent names must be owned/shared or administrator-approved. |
| `TPM_CC_PolicyGetDigest` | Policy session must be owned by the peer. |
| `TPM_CC_Commit` | ECC key must be owned/shared; cap concurrent use because commit counters can be limited. |
| `TPM_CC_PolicyPassword` | Policy session must be owned by the peer. |
| `TPM_CC_ZGen_2Phase` | ECC key/session inputs must be owned/shared and use approved curves. |
| `TPM_CC_PolicyNvWritten` | Policy session must be owned; referenced NV index should be owned/shared or in an allowed namespace. |
| `TPM_CC_PolicyTemplate` | Policy session must be owned; template digest should match an approved object profile. |
| `TPM_CC_EncryptDecrypt2` | Symmetric key must be owned/shared; cap buffer sizes and allowed modes. |
| `TPM_CC_ECC_Decrypt` | ECC decrypt key must be owned/shared; cap input sizes and approved schemes. |
| `TPM_CC_PolicyCapability` | Policy session must be owned; capability operands should be restricted to allowed read capabilities. |
| `TPM_CC_PolicyParameters` | Policy session must be owned; parameter references should correspond to commands the caller may execute. |

### User namespace (15 commands)

These commands operate on durable persistent handles or NV indexes. Allow them only inside configured per-user/per-group namespaces and only when replacement, mutation, or deletion targets recorded ownership.

| Command | Rationale and required conditions |
| --- | --- |
| `TPM_CC_EvictControl` | Persist only tracked-owner transient objects into an empty per-user persistent range; evict only persistent handles recorded as owned by the peer. |
| `TPM_CC_NV_UndefineSpace` | Allow only for tracked NV indexes owned by the peer and inside an allowed NV namespace. |
| `TPM_CC_NV_DefineSpace` | Allow only inside a per-user NV range, with size limits and safe attributes; record ownership on success. |
| `TPM_CC_NV_Increment` | Allow only for tracked-owner counter NV indexes inside the caller's namespace. |
| `TPM_CC_NV_SetBits` | Allow only for tracked-owner bit-field NV indexes inside the caller's namespace. |
| `TPM_CC_NV_Extend` | Allow only for tracked-owner extend NV indexes inside the caller's namespace. |
| `TPM_CC_NV_Write` | Allow only for tracked-owner NV indexes inside the caller's namespace, with size/rate limits. |
| `TPM_CC_NV_WriteLock` | Allow only for tracked-owner NV indexes; locking a shared or untracked index can deny service to others. |
| `TPM_CC_NV_ChangeAuth` | Allow only for tracked-owner NV indexes inside the caller's namespace. |
| `TPM_CC_PolicyNV` | Allow only when the policy session is owned by the peer and the NV index is owned, public-readable, or explicitly shared. |
| `TPM_CC_NV_Read` | Allow for owned NV indexes, explicitly shared indexes, or indexes with safe public-read attributes. |
| `TPM_CC_NV_ReadLock` | Allow only for tracked-owner NV indexes; locking reads of shared/untracked indexes can deny service. |
| `TPM_CC_NV_Certify` | NV index must be owned/shared/readable; signing key must be owned/shared; PCR/qualifying inputs bounded. |
| `TPM_CC_PolicyAuthorizeNV` | Policy session must be owned; authorizing NV index must be owned/shared or administrator-approved. |
| `TPM_CC_NV_DefineSpace2` | Same as `NV_DefineSpace`: per-user range, size limits, safe attributes, and ownership recording. |

### Template-limited (5 commands)

These commands create, load, or import objects. Allow them only when parent handles and object templates match administrator-approved profiles, then record ownership after success.

| Command | Rationale and required conditions |
| --- | --- |
| `TPM_CC_CreatePrimary` | Allow only for approved hierarchies, auth values, policies, algorithms, and object attributes; record returned handle as owned. |
| `TPM_CC_Create` | Parent must be tracked-owner; object template must match approved key/data profiles; record created object metadata. |
| `TPM_CC_Import` | Parent must be tracked-owner; imported object template and duplication policy must be approved; record ownership on load/create flow. |
| `TPM_CC_LoadExternal` | Public-only verification objects can be broadly allowed; loading private external objects needs approved template and peer ownership tracking. |
| `TPM_CC_CreateLoaded` | Parent/hierarchy must be owned/shared or allowed; template must be approved; record returned handle as owned. |

### Admin-only (30 commands)

These commands affect global TPM, hierarchy, platform, PCR, clock, audit, lockout, or attached-component state and should be reserved for root or an explicit TPM administrator role.

| Command | Rationale and required conditions |
| --- | --- |
| `TPM_CC_NV_UndefineSpaceSpecial` | Deletes NV using platform authorization. Ordinary users must use `NV_UndefineSpace` and only for owned NV indexes. |
| `TPM_CC_HierarchyControl` | Enables/disables TPM hierarchies and affects all users. |
| `TPM_CC_ChangeEPS` | Rotates the endorsement primary seed and invalidates hierarchy-derived objects globally. |
| `TPM_CC_ChangePPS` | Rotates the platform primary seed and affects platform hierarchy state globally. |
| `TPM_CC_Clear` | Resets owner-controlled TPM state and authorization values. |
| `TPM_CC_ClearControl` | Controls whether `Clear` is permitted. |
| `TPM_CC_ClockSet` | Changes TPM clock state used by attestations. |
| `TPM_CC_HierarchyChangeAuth` | Changes hierarchy authorization values shared by the system. |
| `TPM_CC_PCR_Allocate` | Changes PCR bank allocation and platform measurement layout. |
| `TPM_CC_PCR_SetAuthPolicy` | Changes PCR authorization policy. |
| `TPM_CC_PP_Commands` | Changes physical-presence command requirements. |
| `TPM_CC_SetPrimaryPolicy` | Changes hierarchy policy for primary-object creation. |
| `TPM_CC_ClockRateAdjust` | Changes TPM clock behavior. |
| `TPM_CC_NV_GlobalWriteLock` | Locks writes across all NV indexes honoring the global lock. |
| `TPM_CC_GetCommandAuditDigest` | Reveals/attests command audit state; keep with audit administrators unless a read-only audit role is defined. |
| `TPM_CC_DictionaryAttackLockReset` | Modifies global lockout state. |
| `TPM_CC_DictionaryAttackParameters` | Modifies global lockout policy. |
| `TPM_CC_PCR_Event` | Extends PCRs and changes platform measurement state. |
| `TPM_CC_PCR_Reset` | Resets PCR values and can affect attestation decisions. |
| `TPM_CC_SetAlgorithmSet` | Changes TPM-wide algorithm set state where supported. |
| `TPM_CC_SetCommandCodeAuditStatus` | Changes command audit configuration. |
| `TPM_CC_Startup` | Daemon/upstream initialization responsibility, not a user command. |
| `TPM_CC_Shutdown` | Changes TPM shutdown state for all users. |
| `TPM_CC_PCR_Extend` | Mutates PCRs and therefore platform attestation state. |
| `TPM_CC_PCR_SetAuthValue` | Changes PCR authorization value. |
| `TPM_CC_EventSequenceComplete` | Completes an event sequence and extends PCRs, mutating platform measurement state. |
| `TPM_CC_PolicyPhysicalPresence` | Physical-presence policy should not be satisfiable by ordinary users through the proxy. |
| `TPM2_ACT_SetTimeout` | Changes attached-component timer state. |
| `TPM_CC_SetCapability` | Changes TPM capability state where supported. |
| `TPM_CC_ReadOnlyControl` | Controls TPM read-only state and affects all users. |

### Deny (8 commands)

These commands should not be exposed to unprivileged users unless a future site-specific policy model can inspect and constrain them safely.

| Command | Rationale and required conditions |
| --- | --- |
| `TPM_CC_FieldUpgradeStart` | Firmware update path; do not expose through an unprivileged proxy policy. |
| `TPM_CC_FieldUpgradeData` | Firmware update data path. |
| `TPM_CC_FirmwareRead` | Firmware update/read path; do not expose to unprivileged users. |
| `TPM_CC_AcGetCapability` | Attached-component capability space is platform-specific and not modeled for unprivileged access. |
| `TPM_CC_AcSend` | Sends commands to attached components; requires platform-specific policy not present in the proxy. |
| `TPM_CC_Policy_AC_SendSelect` | Attached-component policy predicate; deny until AC resources are modeled. |
| `TPM_CC_Policy_TransportSPDM` | SPDM transport binding requires platform/session semantics not modeled for ordinary users. |
| `TPM_CC_Vendor_TCG_Test` | Vendor/test command; deny by default unless a site-specific administrator policy models it explicitly. |

## Implementation Notes

- The proxy must update provenance only after a TPM response succeeds. A denied
  or failed create/load/define operation must not create ownership records.
- For all **tracked-owner** decisions, untracked handles should be denied to
  ordinary users. This is the main protection against one user flushing,
  changing, duplicating, or unsealing another user's object.
- For all **user namespace** decisions, handle ranges need to be configured
  before deployment. Persistent and NV ownership records should include both the
  handle and the public name/attributes to detect reuse or out-of-band changes.
- For all **template-limited** decisions, template parsing needs to happen before
  forwarding and should reject unknown algorithms, dangerous attributes, and
  parent/hierarchy combinations outside the user's profile.
- Commands marked **unrestricted** still need generic limits: command size,
  response size, command timeout, queue depth, rate limiting, and audit logging
  for abuse investigations.
