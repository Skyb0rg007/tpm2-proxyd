<!--
SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>

SPDX-License-Identifier: Apache-2.0
-->

# Command Policy

> **Status:** The first release doesn't implement the state model below. Each
> client now has its own `/dev/tpmrm0` handle, so the kernel resource manager
> already confines transient objects and sessions to the connection that created
> them and flushes them when it closes. The release uses stateless profiles
> instead (see "Access policy" in [design.md](design.md)): the shipped `standard`
> profile allows the workflow commands listed at the end of this document, with
> handles limited to transient objects, sessions and the null hierarchy (plus the
> owner and endorsement hierarchies for `CreatePrimary`). The per-identity
> provenance and parameter checks below remain candidates for later releases.

This document describes the first-release command policy shape for
`tpm2-proxyd`. The release target is intentionally narrow: support
unprivileged workflows that are analogous to what can be done through Windows
TBS, while avoiding operations that require site-specific durable ownership
configuration such as NV-index namespaces or persistent-handle namespaces.

The proxy should still reject TPM traffic it cannot parse. The policy surface is
therefore the intersection of:

- commands recognized by the TPM protocol parser,
- commands needed by the supported workflow set, and
- commands whose parameters can be checked safely with in-memory state.

## State Model

Policy is static for the first release, but authorization is not stateless. The
proxy keeps in-memory state so later commands can be tied back to resources that
were created, loaded, saved, or started by the same caller.

The word **identity** means the current policy identity for a peer. Initially
this is the peer UID, but the model should leave room for other authentication
forms later.

### Per-Connection State

Each downstream connection has:

- peer credentials and resolved identity,
- the associated upstream TCTI/resource-manager connection,
- scheduler priority and rate-limit accounting,
- command timeout and in-flight command tracking,
- request/response size accounting,
- an exact set of live transient object handles,
- an exact set of live session handles,
- an exact set of live sequence handles,
- metadata for handles observed through successful commands.

The handle sets are exact sets, not numeric ranges. TPM transient handle values
can be reused after flush/load operations, so the proxy must track lifetimes:
insert after successful handle creation, remove after successful flush or
completion, and clear connection-owned state when the connection closes.

For each live object handle, store the policy-relevant public metadata known to
the proxy:

- handle value and handle kind,
- owner identity and connection ID,
- public name, when available,
- parent handle/name, when relevant,
- object type, key size, curve, algorithms, schemes, and attributes,
- whether the object is signing, decrypt, keyed-hash/HMAC, or sealed-data use.

For each live session handle, store:

- handle value and session kind,
- owner identity and connection ID,
- bind/salt handle information when available,
- whether the session is used as an authorization session,
- policy-session facts that are needed for later command checks.

### Per-Identity State

Some useful `tpm2-tools` workflows cross process boundaries by saving context
files and loading them in a later command. Possession of a context file must not
be treated as authorization. The proxy therefore keeps per-identity context
provenance in memory:

- a fingerprint of the saved context blob or another stable opaque identifier,
- the identity that saved it,
- the original connection ID,
- the original handle kind,
- copied object/session metadata,
- the public name, when available,
- whether the context is still loadable under proxy policy.

`ContextLoad` is allowed for an unprivileged caller only when the presented
context matches a provenance record for that identity. If the daemon restarts
and loses this in-memory state, old context files are untrusted and must be
denied for unprivileged use.

This state does not need to be durable for the first release. Users can recreate
primaries and reload keys from their public/private blobs after a daemon restart.

### Response-Driven Updates

The proxy updates state only after a successful TPM response. A failed command
must not create or mutate ownership/provenance records.

Important transitions:

- `CreatePrimary`, `Load`, and future `CreateLoaded`/`LoadExternal` success add
  a live object handle to the connection set.
- `Create` success records created object metadata that can later be checked
  when the object is loaded under an approved parent.
- `StartAuthSession` success adds a live session handle.
- `ContextSave` success records per-identity context provenance.
- `ContextLoad` success restores a live object/session handle only from matching
  context provenance.
- `FlushContext` success removes the flushed object, session, or sequence handle
  from the connection set.

## Observed First-Release Workflow Commands

The commands below are the TPM commands observed in
`references/tpm2-tools-workflows.observed.md` after excluding persistent-handle
and NV-index workflows. They form the practical first-release command set for
TBS-like unprivileged use.

| Command | Policy handling and required state |
| --- | --- |
| `TPM_CC_GetCapability` | Allow selected capability classes only. Filter or deny handle enumeration if it would reveal resources outside the caller's view. Needs no ownership state, but should use response-size and rate limits. |
| `TPM_CC_GetRandom` | Allow with requested-byte and rate limits. Needs no ownership state. |
| `TPM_CC_PCR_Read` | Allow only configured PCR banks and indexes. Needs PCR selection checks and rate limits. |
| `TPM_CC_StartAuthSession` | Allow with per-connection session-count limits. Bind/salt handles must be null or owned/allowed. On success, add the returned session handle to the connection's live session set. |
| `TPM_CC_CreatePrimary` | Allow only approved hierarchies, templates, algorithms, attributes, key sizes, auth settings, and policies. On success, add the returned transient object handle and object metadata to the connection's live handle set. |
| `TPM_CC_Create` | Parent must be owned/allowed and the requested template must match policy. On success, record created public/private object metadata under the identity so a later `Load` can be checked against the same parent and approved template. |
| `TPM_CC_Load` | Parent must be owned/allowed. The public/private blobs must match a prior allowed `Create`/import record or an approved load profile. On success, add the returned transient object handle and public metadata to the connection's live handle set. |
| `TPM_CC_ContextSave` | Allow only for live object/session handles owned by the current connection or identity. On success, record per-identity context provenance for the saved blob and copied handle metadata. |
| `TPM_CC_ContextLoad` | Allow only when the context blob matches an in-memory provenance record for the current identity. On success, add the restored object/session handle to the current connection's live handle set with the saved metadata. |
| `TPM_CC_ReadPublic` | Allow for live objects owned by the current connection/identity and for explicitly safe public handles. The response can be used to confirm object name and metadata. |
| `TPM_CC_FlushContext` | Allow only for live object, session, or sequence handles in the current connection set or otherwise owned by the current identity. On success, remove the handle from live state. |
| `TPM_CC_Hash` | Allow with input-size limits and restricted hierarchy/ticket choices. Needs no durable state, but the hierarchy parameter must be checked. |
| `TPM_CC_Sign` | Signing key handle must be live and owned/allowed. Enforce digest size, hash algorithm, and signing scheme against stored object metadata. |
| `TPM_CC_RSA_Encrypt` | Public-key operation. Allow only with a live or explicitly allowed RSA key and approved scheme/input size. Does not require private-use authorization, but the key metadata must permit the operation. |
| `TPM_CC_RSA_Decrypt` | Decrypt key handle must be live and owned/allowed. Enforce scheme and input-size limits against stored object metadata. |
| `TPM_CC_HMAC` | HMAC key handle must be live and owned/allowed. Enforce allowed hash algorithms and input-size limits against stored object metadata. |
| `TPM_CC_Unseal` | Sealed-data object handle must be live and owned/allowed. This command releases sensitive data, so untracked or cross-identity handles must be denied. |
| `TPM_CC_Quote` | Signing key handle must be live and owned/allowed. PCR selection must be in the configured allowed PCR set, and signing scheme/hash must match policy and stored object metadata. |

Commands outside this observed set are not part of the first-release
unprivileged workflow target unless another document explicitly adds them with
the state required to authorize them safely.
