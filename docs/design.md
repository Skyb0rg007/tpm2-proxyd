<!--
SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>

SPDX-License-Identifier: BSD-2-Clause
-->

# tpm2-proxyd design

`tpm2-proxyd` is an access-control proxy that sits between downstream TCTI
clients and an upstream TCTI (the kernel resource manager `/dev/tpmrm0` or
`tpm2-abrmd`). It inspects each TPM command, enforces a per-user
access/permission policy, and forwards allowed commands upstream. It is **not**
a resource manager: it does not virtualize transient objects or sessions.

## Transport: a single Varlink socket

The daemon exposes exactly **one** socket: a Varlink socket at
`/run/tpm2-proxyd/website.soss.Tpm2Proxyd`, implementing the
`website.soss.Tpm2Proxyd` interface. Both administration and TPM access happen
over this one socket — there is no separate raw byte-stream socket.

It serves two kinds of traffic:

1. **Control methods** — ordinary Varlink calls for administration and
   inspection (status, reloading policy, listing active clients, …), handled by
   `management`. A client that only issues control methods never touches the TPM
   data path.
2. **TPM access** — a client calls the access method, e.g.
   `RequestTpmAccess(priority: <level>)`, with the Varlink `upgrade: true` flag.
   On success the server replies and then **upgrades** the connection: Varlink
   message framing is dropped and the socket becomes a raw, self-framing TPM
   command/response stream for the rest of its life (the 10-byte TPM header
   carries the length). This upgraded connection is what the downstream
   `tss2-tcti-proxy` module drives.

   **Implementation status:** planned, but blocked on upstream `zlink` support
   for handing an upgraded connection to the service. The control methods are
   implemented in the meantime; TPM access will be added when that API is
   available.

   Until then, the daemon can expose a raw Unix-domain TPM socket as a temporary
   TPM-only transport. That listener accepts self-framing TPM command bytes
   directly, derives the peer UID/GID from Unix socket credentials, and leaves
   the connection priority entirely to policy rules for that UID/GID.

Requesting access explicitly — with a priority — before upgrading means the
server learns the client's intent and scheduling priority up front and pairs it
with the peer identity (`SO_PEERCRED`, read from the connected socket) for policy
and scheduling decisions.

## Request pipeline

Once a connection has upgraded, each TPM command flows through:

```text
  upgraded ──▶ server ──▶ broker ──inspect──────────▶ tpm
  connection                 │
                             ├──authorize──────────▶ policy
                             │
                             ├──acquire (priority)─▶ scheduler
                             │
                             └──forward────────────▶ upstream ──▶ TPM
```

- `server` owns the single Varlink socket: it accepts connections, dispatches
  control methods to `management`, performs the upgrade on an access request, and
  then runs the per-connection raw TPM stream. Peer identity comes from
  `SO_PEERCRED`.
- `management` implements the control methods of the `website.soss.Tpm2Proxyd`
  interface.
- `broker` runs the per-command pipeline and owns shared state.
- `policy` answers allow/deny for a `(peer, command)` and bounds the priority a
  peer may request.
- `scheduler` decides *when* an allowed command may run, honoring the
  connection's requested priority (see below).
- `upstream` is the single, serialized transport to the physical TPM.

### Access policy

The initial policy engine is implemented as ordered, first-match rules. Rules
can select a UID, a primary or supplementary GID, and one or more TPM command
codes; an empty command-code list matches every command. The policy defaults to
deny when no command rule matches.

Connection priority is bounded separately by ordered UID/GID cap rules. The cap
is applied once when a client is admitted, so the effective priority remains
fixed for the connection lifetime. The active policy can be atomically replaced;
subsequent commands use the replacement policy, while already admitted
connections retain their previously capped priority.

Handle-specific command rules remain future work.

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
  transmit/receive is wrapped in a timeout, and on expiry the scheduler issues a
  TCTI `cancel` and fails that command (and likely the connection).

### The scheduler model

The `scheduler` module mediates all upstream access. Conceptually a client must
hold a **TPM lease** to transmit a command:

The initial implementation schedules complete commands through a single
upstream worker. It chooses the highest-priority queued command, preserves FIFO
order within the same priority, and never preempts an in-flight transaction.
Timeouts, quotas, and time-slice accounting remain planned rather than active
in this command path.

- **Mutual exclusion.** Exactly one lease exists; holding it grants exclusive
  use of `upstream`. Released after the response (or timeout).
- **Wait queue + priority + fairness.** Clients blocked on the lease wait in a
  queue ordered first by the **priority** the connection requested at
  `RequestTpmAccess` time, then by a configurable fairness policy within a
  priority band (FIFO initially; weighted fair-share across UIDs is the intended
  target so no single user dominates its band). The requested priority is fixed
  for the life of the upgraded connection and is capped by `policy` per
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
- the maximum priority each user/group may request at `RequestTpmAccess`.

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

This mapping choice is owned by `upstream`/`scheduler` and is left open here; the
scheduler interface is designed to support either.

## Non-goals

- Resource management (handle virtualization, context swap) — delegated to the
  kernel RM or `tpm2-abrmd`.
- Guaranteeing cancellation of an in-flight command — best-effort via TCTI
  `cancel` only.
