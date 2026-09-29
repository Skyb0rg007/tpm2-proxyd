<!--
SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>

SPDX-License-Identifier: Apache-2.0
-->

# Proposal: transparent parameter encryption

Status: proposal, not implemented.

A downstream client that sends TPM commands without an encrypting session has
its parameters, and the TPM's responses, cross the bus to the TPM in plaintext.
This proposal lets a client ask for encryption when it connects. The proxy then
adds a salted, encrypting session on the client's behalf, encrypting each
command's parameters before forwarding and decrypting the response before
returning it. The client's TPM commands and responses are unchanged.

It is feasible, but narrower than it sounds. It is also the largest
architectural change the daemon would take on. Today the proxy forwards each
command's bytes unchanged. This would make it own a TPM session per client and
rewrite every command and response it touches.

## Threat model

The only leg this protects is proxy → TPM: the SPI/LPC/I²C bus to a discrete
TPM. That bus is where passive sniffing and active interposer attacks happen,
such as recovering a disk key from a sniffed `TPM2_Unseal` response.

- **Client → proxy:** a Unix socket inside one kernel. It is already protected;
  nothing to do.
- **Firmware TPMs** (Intel PTT, AMD fTPM): there is no external bus, so they
  gain close to nothing. The feature should be opt-in, for discrete TPMs.
- **Kernel protection:** the kernel's own bus protection
  (`CONFIG_TCG_TPM2_HMAC`) covers only commands the kernel itself issues, not
  userspace traffic through `/dev/tpmrm0`, so the two don't overlap.

## Requesting encryption

Encryption is chosen per connection, before the first command, and fixed for
the connection's life, like its priority. The server knows the client's choice
before it schedules anything, so it can set up the session during admission and
refuse the connection outright if it can't.

### A request is a requirement

A client that asks for encryption either gets it or is refused. The proxy never
downgrades silently:
- **At admission:** if the feature is disabled, no pinned salt key is available
  (see [Salt key](#salt-key)), policy forbids it, or the TPM has no free session
  slot, the proxy refuses the connection.
- **Mid-connection:** if the proxy's session is lost, it recreates it. If that
  fails, it closes the connection rather than forward the next command in
  plaintext.

A client that wants encryption only when it's available can retry without it.

### On the wire

- **Varlink (the target transport):** `RequestTpmAccess` gains an
  `encrypt: bool` parameter next to `priority`, and replies with an error
  instead of upgrading when the request is refused.
- **Raw socket (the interim transport):** the client may send a hello before its
  first command. Hello fields are big-endian, like TPM fields.

  | Field | Size | Value |
  | --- | --- | --- |
  | `magic` | 4 | `"TPXH"` |
  | `version` | 2 | `1` |
  | `flags` | 2 | bit 0: encrypt; other bits must be zero |

  The server replies with `magic` (`"TPXH"`) and a 4-byte `status`:
  - `0`: accepted;
  - `1`: forbidden by policy;
  - `2`: unavailable: feature disabled or no pinned salt key;
  - `3`: out of TPM resources;
  - `4`: malformed hello, unknown version, or unknown flag.

  After any nonzero status, the server closes the connection. Rejecting unknown
  flags means a future option a client depends on is never silently ignored.

  The hello is optional, so existing clients keep working. A TPM command starts
  with the tag byte `0x80` (or `0x00` for TPM 1.2), never `'T'`, so the server
  tells the two apart from the first byte. A connection without a hello gets the
  defaults.
- **TCTI config string:** `tss2-tcti-proxy` takes comma-separated `key=value`
  options, in the style of tpm2-tss's own TCTIs: for example
  `proxy:path=/run/tpm2-proxyd/tpm2-proxyd.sock,encrypt=yes`. A string without
  `=` is still read as the socket path. With `encrypt=yes`, the module sends the
  hello from `init` and waits for the reply, so a refused request fails `init`
  with `TSS2_TCTI_RC_NOT_PERMITTED`. The client never gets as far as sending a
  command in plaintext.

### Policy

Like priority, the policy has the final say:

| Client asks | Policy | Result |
| --- | --- | --- |
| No | default | Off |
| No | `force` | On; the client isn't told |
| Yes | default or `force` | On, or refused if the proxy can't |
| Yes | `forbid` | Refused |

`force` lets an administrator protect clients that can't be changed. `forbid`
reserves the TPM's limited sessions (see
[Resource and performance cost](#resource-and-performance-cost)) for chosen
users.

## Mechanism

The per-client upstream sessions already exist: the device worker keeps state
per `SessionId` (see [design.md](design.md#interaction-with-upstream-connection-mapping)).
Auto-encryption adds one TPM session to that state.

1. **Session setup.** When a connection is admitted with encryption on, the
   proxy starts the session on that client's `/dev/tpmrm0` handle before
   replying to the request, using `TPM2_StartAuthSession` with:
   - an HMAC session;
   - `symmetric = AES-128-CFB`;
   - a salt encrypted to a pinned key (see [Salt key](#salt-key));
   - no bind entity.

   The proxy derives the session key with `KDFa`.
2. **Commands.** For an eligible command (see [Eligibility](#eligibility)), the
   proxy:
   - switches the tag to `TPM_ST_SESSIONS` if it was `TPM_ST_NO_SESSIONS`, and
     inserts the authorization-size field;
   - appends its session to the authorization area, with `continueSession`,
     `decrypt` if the first command parameter is to be encrypted, and `encrypt`
     if the first response parameter is to be;
   - encrypts the first command parameter;
   - computes the session HMAC over the command-parameter hash (cpHash) and the
     nonces, with a fresh caller nonce;
   - fixes up `commandSize`.
3. **Responses.** For a successful response, the proxy:
   - verifies the session HMAC over the response-parameter hash (rpHash). A
     mismatch is a tampered or corrupted response, so the proxy returns an error
     instead;
   - decrypts the first response parameter;
   - removes its session from the response authorization area;
   - stores the new TPM nonce;
   - if the client sent no sessions, restores the `TPM_ST_NO_SESSIONS` form,
     which means removing the `parameterSize` field and the authorization area;
   - fixes up `responseSize`.

   Error responses carry no session area and are passed through unchanged.

Every command the proxy forwards has already been fully decoded, because
unrecognized command codes are rejected at the parse boundary (see
[design.md](design.md#recognized-commands-only)). So the handle counts and
parameter layouts come from `tpm2-protocol`. Policy decisions are still made on
the plaintext command the client sent.

## Eligibility

The TPM and the session rules limit which commands and clients this can cover.

### First parameter only, and only a sized buffer

A session can encrypt only the *first* parameter in each direction, and only
when that parameter is a sized buffer (`TPM2B`). Otherwise the TPM rejects the
attribute with `TPM_RC_ATTRIBUTES`. The proxy needs a table, derived from the
command definitions, recording for each command whether its first command
and/or response parameter qualifies.

What this covers:

| Direction | Commands |
| --- | --- |
| Command | `Create`, `CreatePrimary`, `CreateLoaded` (sensitive data and new auth values); `LoadExternal`, `Import`, `NV_Write`, `Hash`, `HMAC`, `EncryptDecrypt2`, `RSA_Decrypt`, `Sign` |
| Response | `Unseal`, `GetRandom`, `NV_Read`, `RSA_Decrypt`, `EncryptDecrypt2` |

What stays in plaintext:
- all handles and command codes;
- every parameter after the first;
- commands whose first parameter is not a sized buffer, such as `PCR_Extend`,
  whose digests stay in plaintext.

### Clients using HMAC sessions are left alone

The TPM computes the command and response HMACs over the *encrypted* parameter
bytes. If the proxy encrypted a command from a client that authorizes with its
own HMAC session, the client's HMAC would no longer match. The same goes for
decrypting the response, which breaks the client's response check. So the proxy
must not add encryption when the client's authorization area contains any of:

- an HMAC session;
- a policy session that has run `PolicyAuthValue`, which makes it carry an HMAC;
- a session with the `audit` attribute;
- a session that already sets `decrypt` or `encrypt`.

Clients that use HMAC sessions can enable encryption themselves. Auto-encryption
is for clients that send commands without sessions or with password sessions.
On a connection with encryption on, commands like these pass through with only
the client's own protection. That isn't a downgrade: the client chose its own
sessions for those commands.

### Session limits

- A command carries at most three sessions, so a client already using three
  gets no encryption.
- The kernel resource manager gives each open `/dev/tpmrm0` handle three session
  slots. The proxy's session takes one, leaving the client two.

## Password authorization is not covered

A password session carries the password in plaintext in the authorization area,
and parameter encryption does not touch the authorization area. So for
`tpm2_unseal -p secret` the unsealed data would be encrypted but the password
that guards it would not. Without closing that gap, the protection is complete
only where authorization values are empty. That is common for the owner
hierarchy on Linux, but not for sealed secrets.

Closing it means turning each password session into an HMAC session under the
proxy's session. The proxy has the password, but it would also need:

- **The Name of each authorized entity.** `TPM2_ReadPublic` or
  `TPM2_NV_ReadPublic`, cached per handle; a permanent handle's Name is the
  handle itself. A forged Name only makes the TPM's HMAC check fail; it leaks
  nothing.
- **The special cases:**
  - the `*ChangeAuth` family, whose HMAC key changes during the command;
  - `PolicySecret`;
  - one proxy session per authorized handle when a command authorizes two
    handles.

This is the genuinely hard part, and where most of the risk is. It is phase 2.

## Salt key

An unsalted, unbound session gives no confidentiality: its key comes only from
nonces that cross the bus in plaintext. The salt must be encrypted to a TPM key
whose public part the proxy knows *independently of the bus*. If the proxy used
the output of a runtime `ReadPublic`, an active interposer could substitute its
own key.

- **Default: systemd's SRK.** `systemd-tpm2-setup` (systemd 255+) provisions a
  storage root key at persistent handle `0x81000001` and records its public key
  under `/run/systemd/` (`tpm2-srk-public-key.*`). The proxy would salt to that
  handle and check the TPM's `ReadPublic` answer against the stored public key.
  A persistent key does not use up the client's transient-object slots.
- **Alternative: a configured key Name**, pinned by the administrator.
- **Passive-only threat model:** trust on first use of the key is acceptable,
  but it should be an explicit configuration choice.

The salt is RSA-OAEP or ECDH with `KDFe` under the label `"SECRET"`, depending
on the SRK's type.

## Resource and performance cost

- **Session setup.** Each encrypted connection costs one `StartAuthSession` at
  admission. That includes an asymmetric operation on the TPM, which takes tens
  to hundreds of milliseconds on a discrete TPM, and it runs on the serial
  scheduler at the client's priority, delaying other clients. Clients that don't
  ask pay nothing.
- **Per command.** Roughly 70 extra bytes, an HMAC on each side, and AES-CFB.
  This is small next to the TPM's own latency.
- **Active sessions.** TPMs typically allow around 64 active sessions in total,
  which caps concurrent encrypted connections. The alternative, a new session
  per command, pays the asymmetric cost on every command. The proposal is a
  session per connection. When the TPM has no free session slot, a new request
  is refused; established sessions are never dropped to make room.
- **Context gap.** A session idle for a long time while other clients churn
  sessions can hit `TPM_RC_CONTEXT_GAP`. The proxy recreates the session on any
  session error, and closes the connection if it can't.
- **Client interference.** A client can see the proxy's session handle through
  `GetCapability(TPM_CAP_HANDLES)`. The policy should deny `FlushContext` and
  the context commands on that handle, and the proxy should recreate the session
  if it disappears anyway.

## Implementation notes

- **Crypto.**
  - `tpm2-crypto` already provides `KDFa`, `KDFe` and HMAC.
  - Its salt-encryption helpers hard-code the `"DUPLICATE"` label, so salting
    needs a `"SECRET"` variant, which is a small upstream change.
  - AES-CFB comes from `openssl`, which `tpm2-crypto` already depends on.
  - `tpm2-device` has a `StartAuthSession` builder that accepts an encrypted
    salt.
- **Marshalling.** The daemon currently only parses. Rewriting needs
  marshalling of the handle area, the authorization area and the first
  parameter; `tpm2-protocol` has both directions.
- **Where it lives.**
  - The session and the rewriting belong in the device worker, next to each
    session's `TpmPosixDevice`.
  - The raw-socket listener reads the optional hello (`server/unix.rs`,
    `server/connection.rs`).
  - `Broker::admit` combines the request with policy, as it already does for
    priority, and asks the scheduler to open an encrypted session.
  - The TCTI module parses the new config string and sends the hello.
  - The swtpm upstream would need the same layer for the end-to-end tests to
    cover it.
- **Configuration.**
  - A global switch, off by default, enables the feature and names the salt key.
    Without it, every request is refused with status `2`.
  - Per-user `force` and `forbid` go in the policy, next to the priority rules.

## Phases

1. **Parameter encryption for clients with no sessions or only password
   sessions**, salted to the pinned SRK. This includes the hello, the TCTI
   `encrypt=yes` option, and policy `force`/`forbid`. This is contained and
   testable. It fully protects the common case where authorization values are
   empty, and it protects outputs such as unsealed data and `GetRandom`
   everywhere.
2. **Turning password sessions into HMAC sessions**, which closes the password
   gap. Most of the complexity is here.

## Testing

End-to-end tests against swtpm can check both sides:
- the client sees unchanged behaviour and responses;
- the upstream transcript never contains the known plaintext of an encrypted
  parameter.

Response HMAC verification can be tested by corrupting a byte on the upstream
side.

Admission can be tested without a TPM, using the smoke test's fake upstream:
- hello accepted, refused by policy, and malformed;
- a connection without a hello still works;
- `force` encrypts a client that sent no hello;
- a TCTI `init` with `encrypt=yes` fails when the request is refused.

## Open questions

- Confirm against swtpm how the TPM's nonce advances after an error response,
  which carries no session area. The proxy must not reuse its own nonce, and
  must keep the TPM's.
- Whether to filter the proxy's session handle out of `GetCapability` responses,
  rather than only denying commands that name it.
- How to detect a firmware TPM reliably enough to default the feature off
  there, or whether to leave that choice entirely to the administrator.
- Whether the hello should also carry a requested priority, so the raw socket
  matches `RequestTpmAccess` before the Varlink upgrade lands.
