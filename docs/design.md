<!--
SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>

SPDX-License-Identifier: Apache-2.0
-->

# tpm2-proxyd design

`tpm2-proxyd` is an access-control proxy that sits between downstream TCTI
clients and an upstream TCTI (the kernel resource manager `/dev/tpmrm0` or
`tpm2-abrmd`). It inspects each TPM command, enforces a per-user
access/permission policy, and forwards allowed commands upstream. It is **not**
a resource manager: it does not virtualize transient objects or sessions.

## Transport: one socket, a custom binary protocol

The daemon serves one Unix socket, `/run/tpm2-proxyd/tpm2-proxyd.sock` by
default, created by the daemon or by systemd socket activation. The socket is
`tss:tss 0666`: any local user may connect, and the policy decides per
connection. The peer's identity comes from the credentials the kernel recorded
when it connected: UID, GID and PID from `SO_PEERCRED`, and supplementary groups
from `SO_PEERGROUPS`. Group rules therefore match the groups the connecting
process actually holds, which are the groups the kernel checks its permissions
against, not the groups the user database assigns its user. Reading them never
consults NSS, so a slow user database can't stall accepting clients.

Every connection opens with a **hello**, then carries TPM traffic:

1. **Hello.** The client sends 12 bytes: the magic `"TPXH"`, a `u16` protocol
   version (currently `1`), `u16` flags, and the `i32` scheduling priority it
   requests. The server answers with 12 bytes: `"TPXH"`, its own version, a
   `u16` status, and the `i32` priority it granted (`0` on a refusal). Fields
   are big-endian, like TPM fields.

   | Status | Meaning |
   | --- | --- |
   | `0` | Accepted: the connection may send TPM commands. |
   | `1` | Unsupported: unknown version or flag. |
   | `2` | Busy: the connection limit (`--max-connections`, or `--max-connections-per-uid` for the peer's UID) is reached. |

   A connection counts against those limits from the moment it is accepted,
   so connections that never send a hello still use up their user's slots.
   One over a limit gets the `Busy` reply straight away, before the server
   reads its hello. After any refusal the server closes the connection. A
   connection that doesn't open with the magic isn't speaking this protocol,
   so the server closes it without replying, as it does a connection that
   sends nothing within 10 seconds.

   No flags are defined yet, and unknown flags are refused rather than ignored,
   so a client never silently loses an option it depends on. New per-connection
   options are expected to become flags.
2. **TPM commands.** After an accepted hello, the connection is a self-framing
   TPM command/response stream for the rest of its life: each command and
   response is sent verbatim, and the 10-byte TPM header carries the length.

The downstream `tss2-tcti-proxy` module sends the hello from its `init`, so a
refused connection fails `init` with a TCTI error rather than failing on the
first command.

The hello negotiates the connection's priority: the server grants the requested
priority, capped by the policy's limit for the peer's UID/GID, and the grant is
fixed for the connection's lifetime. Higher priorities run first. A client that
doesn't care requests `i32::MAX`, the highest its policy allows; the TCTI module
does this unless its config string sets `priority=`. The policy is reloaded on
`SIGHUP`; there is no control interface for status or reloads.

## Request pipeline

Once a connection's hello is accepted, each TPM command flows through:

```text
  connection ──▶ server ──▶ broker ──inspect──────────▶ tpm
                              │
                              ├──authorize──────────▶ policy
                              │
                              ├──acquire (priority)─▶ scheduler
                              │
                              └──forward────────────▶ upstream ──▶ TPM
```

- `server` owns the socket: it accepts connections, runs the hello, and then
  runs the per-connection TPM stream. Peer identity comes from `SO_PEERCRED` and `SO_PEERGROUPS`.
- `broker` runs the per-command pipeline and owns shared state.
- `policy` answers allow/deny for a `(peer, command)` through the peer's
  profile and bounds the priority a peer may request.
- `scheduler` decides *when* an allowed command may run, honoring the
  connection's requested priority (see below).
- `upstream` is the single, serialized transport to the physical TPM.

### Access policy

The policy file assigns each peer a **profile** and a priority cap by ordered,
first-match rules that select a UID, a primary or supplementary GID, both, or
every peer. A peer that matches no rule gets the default profile, or no access
if there isn't one.

Rules can safely grant more than the default, but not restrict a user below it.
A user with subordinate ID ranges (`/etc/subuid`, `/etc/subgid`, which
`useradd` sets up by default on many distributions) can connect from a user
namespace, where `SO_PEERCRED` reports one of their subordinate UIDs and they
may have shed supplementary groups. Such a peer matches neither a rule for
their own UID nor one for a group they dropped, and gets the default. For the
same reason each subordinate UID has its own connection cap and failure count.
The default profile should therefore be the least any local user may have,
with rules granting more to the UIDs or groups that need it.

A profile is a JSON file in the profiles directory beside the policy file; none
are built into the daemon, and the `standard` profile is installed with the
service. A profile lists the commands it allows and the handles those commands
may reference in their handle area, by handle type (`TPM_HT_*`) or specific
permanent handle (`TPM_RH_*`), optionally per command. The authorization area
isn't checked.

This handle check is enough because each client has its own `/dev/tpmrm0`
handle. The kernel resource manager gives every handle its own space of
transient objects, so a client can't name another client's objects, and it
flushes the objects and sessions a client leaves loaded when it disconnects.
What the kernel doesn't isolate is state all users share: persistent handles,
NV indices, hierarchy authorization and settings, PCR values, the clock, and
the dictionary-attack lockout. A profile keeps users away from that state by
not allowing the commands that change it and the handles that name it. The
`standard` profile allows only transient objects, sessions and the null
hierarchy, plus the owner and endorsement hierarchies for `CreatePrimary`.

Sessions are only partly isolated. The kernel doesn't virtualize session
handles, and once a client saves a session with `TPM2_ContextSave` the kernel
stops tracking it, so it is never flushed and holds one of the TPM's few
session slots (typically 64) until the TPM resets. A user allowed to save
sessions could fill every slot, so `standard` lets `ContextSave` name only
transient objects. The cost is that a session can't be carried from one
process to the next (`tpm2_startauthsession -S`); a session used within one
process is unaffected.

For the same reason any client can name any session, and `TPM2_FlushContext`
takes its handle as a parameter, where profiles can't check it. The broker
therefore tracks the sessions each connection holds: those it started
(`StartAuthSession`) or loaded (`ContextLoad`), minus those it flushed or used
without `continueSession`. Flushing any other session is denied with
`TPM_RC_HANDLE` for parameter 1 in the resource-manager layer, so one user
can't end another's session mid-workflow.

A denied command isn't forwarded. The client gets a header-only error response
in the resource-manager layer (`TSS2_RESMGR_RC_LAYER`) carrying a TPM-format
code, which tpm2-tss decodes as a TPM error the resource manager reported:
`TPM_RC_COMMAND_CODE` for a command the profile doesn't allow, or
`TPM_RC_HANDLE` with the handle's position for a handle it doesn't allow. The
connection stays open, and the denial is logged with the peer's UID and PID.

A client can cause as many denials, admissions and refused connections as it
likes, so the log lines for them are limited per UID: 20 of each kind a minute,
after which one warning says further ones are held back, and the next line
logged reports how many were. Otherwise one user could push the daemon past
journald's rate limit, which would drop everyone's messages, other users'
denials included.

Connection priority is capped by the same rules. The cap is applied once when a
client is admitted, so the effective priority remains fixed for the connection
lifetime. `SIGHUP` reloads the policy and its profiles together and swaps them in
atomically; if any file fails to load, the old policy stays. Subsequent commands
use the replacement policy, while already admitted connections retain their
previously capped priority.

Longer term, permissions may be determined and granted through Polkit, with
profiles remaining the daemon's enforcement model.

Known limitations of the profile model:

- **Dictionary-attack lockout is shared.** A user who repeatedly fails
  authorization for their own DA-protected object pushes the whole TPM into
  lockout. The proxy limits how many failures each user may cause (see
  below), but several users under their limits can still add up to the TPM's,
  and the proxy doesn't read the TPM's own limit. Refusing to create or load
  objects without `noDA` would close it, but that needs template inspection.
- **Saved contexts are possession-based.** A context file saved by one user can
  be loaded by another who obtains it, although using the object still needs
  its authorization.

### Lockout failure tracking

The TPM reports a failed authorization that counts toward its dictionary-attack
lockout as `TPM_RC_AUTH_FAIL` (a failure without DA implications is
`TPM_RC_BAD_AUTH`). The broker checks each response the TPM returns and counts
those failures in total and per UID, in memory. Every failure is logged with the
peer's UID and PID, the command, and both counts; once the total reaches
`--auth-failure-warn-threshold` (default 10), each further failure is logged as
a warning instead. The response is relayed to the client unchanged.

Hierarchy authorization is exempt from the TPM's dictionary-attack protection,
so a wrong owner, endorsement, platform or lockout password comes back as
`TPM_RC_BAD_AUTH` and the TPM neither counts it nor slows down. Left alone, any
user allowed `CreatePrimary` could guess the owner password as fast as the TPM
answers. The broker therefore also counts `TPM_RC_BAD_AUTH` responses to
commands whose handle area names one of those hierarchies toward the UID's
count, logged as a warning, though not toward the total, which tracks the TPM's
own counter.

A UID whose count reaches `--auth-failure-limit` (default 5) is locked out: the
scheduler worker refuses every command from any of its connections without
forwarding it, checking right before each command is sent so commands already
queued count too, and the client gets `TPM_RC_LOCKOUT` in the resource-manager layer, which
tpm2-tss decodes as the TPM being in DA lockout mode. This keeps one user from
spending the TPM's whole failure budget.

Like the TPM's own counter, the counts recover: each forgets one failure every
`--auth-failure-recovery-secs` (default 600), and a locked-out UID is let back
in as soon as its count is below the limit again, so a lockout lasts about one
interval unless the user keeps failing. Being locked out and being let back in
are both logged. The counts aren't read from the TPM, whose counter recovers on
its own schedule and can be reset through the lockout hierarchy, and a daemon
restart clears them.

### Recognized commands only

The proxy acts as a firewall in front of the TPM: it only forwards traffic it
can parse and reason about. Every command is decoded against the `tpm2-protocol`
command dispatch table before any policy decision is made, so a command whose
code is not a recognized TPM 2.0 command code — including **vendor-specific
command codes** — is rejected outright at the parse boundary
(`tpm::Command::parse`), before it ever reaches policy, the scheduler, or the
upstream TPM.

This is intentional, and a direct consequence of the firewall posture: an
unrecognized command cannot be inspected, so it cannot be authorized, and the
default-deny stance extends to the command vocabulary itself. Forwarding
vendor-specific or otherwise unrecognized commands is a deliberate non-goal (see
[Non-goals](#non-goals)); a downstream client that needs them must talk to the
kernel resource manager directly rather than through the proxy.

## Scheduling: the TPM is a shared, serial resource

A TPM processes **one command at a time**. Every downstream client ultimately
contends for a single upstream transport, so the daemon must arbitrate access.
Naive first-come-first-served forwarding is not enough, for two reasons:

1. **Monopolization.** Individual commands can be slow (RSA key generation,
   policy sessions, NV writes can each take hundreds of milliseconds to
   seconds). A busy or hostile client issuing a stream of expensive commands can
   starve every other client indefinitely.
2. **Hangs.** A command can stall (hardware wedged, upstream not responding).
   Because the resource is serial, one stuck command blocks the whole system.

The daemon therefore treats upstream TPM access as a scheduled resource with
**time slices** (fair-share scheduling) and **time limits** (hard bounds).

### Non-preemptibility

A TPM command, once transmitted, cannot be paused or rewound. The only
in-flight control available is the TCTI `cancel` operation, which *asks* the TPM
to abort and is not guaranteed to be honored quickly. Consequently:

- **Scheduling decisions happen at command boundaries**, not mid-command. A time
  slice bounds how long a client may *keep* the TPM across consecutive commands;
  it is enforced by declining to start the client's *next* command once the
  slice is spent, never by interrupting a running one.
- A separate **hard per-command time limit** guards against hangs: the upstream
  transmit/receive is wrapped in a timeout, and on expiry the command fails and
  its connection ends. Nothing cancels the command in the TPM, so the TPM stays
  busy with it, and the commands queued behind it still wait.

### The scheduler model

The `scheduler` module mediates all upstream access. Conceptually a client must
hold a **TPM lease** to transmit a command:

The initial implementation schedules complete commands through a single
upstream worker. It chooses the highest-priority queued command, preserves FIFO
order within the same priority, and never preempts an in-flight transaction. A
**hard per-command timeout** is active (enforced by `tpm2-device`, configurable
via `--command-timeout-secs`): the client of a wedged transaction gets an error
instead of waiting forever. It bounds that client's wait, not the TPM's: closing
the abandoned `/dev/tpmrm0` handle waits in the kernel for the command to
finish (the kernel applies its own command duration limits), and the clients
queued behind it wait for that too. A **concurrent connection
cap** (`--max-connections`) and a per-UID cap (`--max-connections-per-uid`)
bound resource use. Per-UID quotas and time-slice
accounting remain planned rather than active in this command path.

- **Mutual exclusion.** Exactly one lease exists; holding it grants exclusive
  use of `upstream`. Released after the response (or timeout).
- **Wait queue + priority + fairness.** Clients blocked on the lease wait in a
  queue ordered first by the connection's **priority**, set at admission, then
  by a configurable fairness policy within a
  priority band (FIFO initially; weighted fair-share across UIDs is the intended
  target so no single user dominates its band). The requested priority is fixed
  for the life of the connection and is capped by `policy` per
  user/group, so a client cannot simply demand top priority.
- **Time-slice accounting.** The scheduler measures wall-clock time each client
  holds the lease. When a client's slice is exhausted it must go to the back of
  the queue before its next command, letting others make progress. A lease may
  span several quick commands within one slice to preserve continuity for
  clients with an active auth/HMAC session.
- **Time limits / quotas.** Per-UID budgets over an accounting window reject
  (synthesized `TPM_RC` "yielded"/busy response via `tpm`) clients that exceed
  their fair share, independent of momentary contention. The initial
  implementation uses a tumbling window (the budget resets when the window
  lapses); a denial reports when the window next resets.
- **Watchdog.** A background task enforces the hard per-command timeout and
  reclaims a lease whose holder died or stalled.

### Where time bounds come from

`config` supplies the schedule parameters, with sensible defaults:

- time-slice duration (per lease holder),
- hard per-command timeout (hang protection),
- per-UID quota and its window length,
- scheduling/fairness policy selection,
- the maximum priority each user/group may request at admission.

Limits may be overridable per user/group so trusted services can be given larger
slices, higher quotas, or higher priority than ordinary interactive clients.

### Interaction with upstream connection mapping

How downstream clients map onto upstream transports affects safe scheduling
granularity:

- **Shared upstream fd:** transient objects and sessions are global, so
  interleaving two clients' related commands can corrupt their state. This
  forces coarser, session-aware slices.
- **Per-client upstream fd to `/dev/tpmrm0`:** the kernel RM isolates each fd's
  transient context, allowing fine-grained, per-command interleaving. The TPM
  hardware is still serial, so the scheduler is still required — but slices can
  be short without breaking client sessions.

The daemon uses **per-client upstream fds**. At admission the broker opens a
scheduler `Session` for the client, and every queued command carries its session
id. `TpmDeviceUpstream` opens a separate `/dev/tpmrm0` handle for each session
on that session's first command and closes it when the client disconnects. The
kernel RM then flushes whatever the client left loaded, so abandoned objects
never accumulate. (With one shared fd they did, and the kernel RM's per-fd limit
of three transient objects was exhausted after a few ordinary `tpm2-tools`
runs.) A command still queued when its client disconnects is dropped, not
forwarded.

The swtpm upstream, used for testing, has no resource manager and cannot isolate
clients; there, every session shares the one TPM.

## Non-goals

- Resource management (handle virtualization, context swap) — delegated to the
  kernel RM or `tpm2-abrmd`.
- Cancelling an in-flight command: once sent, it runs to completion in the
  TPM.
- Forwarding vendor-specific or otherwise unrecognized command codes — only
  commands the proxy can decode and inspect are forwarded; everything else is
  rejected at the parse boundary (see [Recognized commands only](#recognized-commands-only)).
