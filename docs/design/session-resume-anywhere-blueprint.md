# Mesh-wide reusable sessions

Status: **implemented in the working tree** · Updated: 2026-07-15

This document is the lifecycle and security contract for Onyx Server session resume. A
session credential identifies one reusable logical session. It is not a lease on a
single socket and it does not transfer ownership from one client or node to another.

## Required behavior

One logical session may have any number of simultaneous live attachments, subject to
the configured per-account bound. Those attachments may be on the same daemon or on
different daemons in the secured mesh.

- Attaching a client never disconnects an existing attachment.
- Every attachment inherits the logical session's identity and channel state.
- Direct and channel events are delivered to every live attachment.
- Any attachment may send messages, join, part, and otherwise participate.
- A tokenless EXTERNAL reattachment does not emit a second logical JOIN or
  re-announce an existing derived operator prefix such as `MODE #root +Y kain`.
- A join or part made on one local attachment is reflected across its local siblings.
- Detaching one socket does not publish a logical PART, QUIT, MONITOR-offline event,
  nick delay, or WHOWAS entry while another local attachment remains or a portable
  remote replica may still be live.
- Losing the local nick owner hands the identity and channel state to a local sibling
  atomically, without an offline gap.

## Credential model

The three credential types are intentionally separate:

| Credential | Purpose | Command path | Lifetime |
|---|---|---|---|
| `sst_...` | Authenticate an account without replaying a password | SASL `SESSION-TOKEN` / `SESSIONTOKEN` | Account-service policy |
| 32 hex chars | Attach to one exact logical session on its origin daemon | `SESSION TOKEN`, then `SESSION RESUME` | While the logical session remains in `SessionStore` |
| Mesh-sealed hex | Attach to that logical session on any secured mesh node | `SESSION MTOKEN`, then `SESSION RESUME` | 12 hours, absolute mesh wall clock |

Account authentication normally does not select a device session. The client must
present the exact local or portable session credential. The narrow compatibility
exception is a possession-verified SASL EXTERNAL login: a client such as WeeChat that
cannot send `SESSION RESUME` may attach automatically when its authenticated account
and requested nick identify a reusable logical session. Across any number of secured
mesh peers, that selection is a total order over matching tokens (live local
attachments, then live mesh attachment leases, then detached/portable replicas;
newer signon/issued time and higher replica revision within a tier; token bytes as
the final tie-break). Explicit `SESSION RESUME` remains exact-credential and never
auto-picks. Malformed state, unstaged mesh authority, or allocation pressure still
fail closed without minting a competing token. Merely presenting a certificate, or
authenticating with PLAIN, SCRAM, or a session token, never enables this lookup.

The first EXTERNAL attachment proactively publishes its signed portable session state
without revealing a reclaim credential to the client. A later EXTERNAL attachment can
therefore select the same unique account-and-nick session on another secured mesh
node, and concurrent EXTERNAL registrations re-scan before minting so an N-node mesh
converges on one logical session instead of one token per peer. Explicit local and
portable credentials remain reusable capabilities: successful use adds an attachment
and does not rotate, consume, or invalidate the credential. `SESSION MTOKEN` includes
`expires=<unix-seconds>` so clients can discard stale portable state without decoding
the sealed value.

## Lifecycle

```text
logical session + stable token
  | SESSION TOKEN reveals the local token
  | MTOKEN issuance marks this token portable and offers a live snapshot
  v
0..N local attachments + 0..N mesh attachments
  | each successful RESUME adds an attachment
  | staged signed snapshots remain reusable until their bounded TTL
  | peer establishment/reconnect re-offers live and detached portable state
  v
last local socket detaches
  | exact snapshot is retained locally
  | portable state is offered to established secured peers
  | remote attachments remain authorized for the carried identity/channels
  v
later RESUME restores or joins the same logical session
```

For a detached local ghost, restore binds the new client to the token before removing
the ghost. For a live sibling, Onyx Server snapshots the current state, attaches the new
client to the same token group, and leaves the source client untouched. For a staged
mesh replica, restore borrows the signed snapshot; it does not remove it, so other
clients can attach with the same valid MTOKEN.

Helix USR2 adoption preserves duplicate same-token rows, attachment state, detached
snapshots, the portable bit, and staged replicas. Preserved mesh links immediately
re-offer portable sessions so process-local authenticated-peer route bindings are
rebuilt after re-exec.

## Reply and retry contract

Successful forms include:

- `SESSION RESUME: already attached to this session`
- `SESSION RESUME: attached to live session`
- `SESSION RESUME: session restored`
- `SESSION RESUME: attached to live mesh session`
- `SESSION RESUME: attached to replicated mesh session`
- `SESSION RESUME: session restored (cross-server)`

There is no `SESSION_ATTACHED` failure: an already-live session is the normal
multi-attachment path.

Only terminal credential failures use `FAIL SESSION`:

- malformed, unverifiable, expired, or wrong-account credential: `INVALID_TOKEN`
- no matching logical session at the authoritative local origin: `NO_SESSION`

Retryable outcomes use `WARN SESSION` and preserve the credential:

- origin peer is partitioned: `ORIGIN_UNREACHABLE`
- snapshot, registry, or restore work could not complete: `TEMPORARILY_UNAVAILABLE`

Onyx normally sends `SESSION RESUME <stored>` followed immediately by `SESSION TOKEN`.
After a retryable result or redirect, Onyx Server suppresses that next token response once
and emits `RESUME_CREDENTIAL_PRESERVED`. This prevents the reconnecting client from
overwriting a still-valid credential. A second explicit `SESSION TOKEN` deliberately
requests the credential for the current attachment. Successful attachment clears the
preservation state.

## Mesh replication and authorization

- Only a session for which an MTOKEN was issued, or whose connection completed
  possession-verified SASL EXTERNAL, is replicated.
- EXTERNAL portability is offered proactively so legacy clients can resume by a
  unique account-and-nick match without implementing an MTOKEN command surface.
- MTOKEN issuance offers the live snapshot immediately; waiting for detach would make
  simultaneous cross-node attachment impossible.
- Snapshot offers are Ed25519-signed and travel only over Mooring-authenticated S2S
  links. The receiver pins the signer to the authenticated peer key and verifies the
  inner and outer account binding before staging.
- Offers use a strictly increasing, token-scoped epoch. Replayed or reordered offers
  cannot replace newer state, while a newly verified signed offer may supersede a
  tombstone left by a legacy one-shot peer during a rolling upgrade.
- Staged replicas are bounded globally by `sessions.max_pending_migrations`, per
  account by `sessions.max_per_account`, and by the portable credential lifetime.
- A restored remote attachment may continue speaking after the origin socket detaches.
  The narrow authorization exception requires the exact random session token, the
  authenticated peer to which the origin actually offered that token, and a current
  portable snapshot whose account, nick, channel, and member modes match. General
  cross-node nick/account claims still pass through the ordinary anti-spoof checks.

`SESSION_MIGRATE_CONSUMED` and consumed-token tombstones exist only for rolling
compatibility with older one-shot peers. Modern successful attachment never emits a
consume notice and never deletes a reusable replica. Receiving a legacy consume notice
cannot strand current attachments; a fresh verified offer reactivates the replica.

## Operational boundaries

`sessions.migrate_on_detach=false` disables proactive live and detached snapshot
offers, including reconnect anti-entropy. It is a rolling-deploy kill switch; local
same-node resume remains available. `sessions.max_pending_migrations` bounds staged
reusable replicas and compatibility tombstones.

The local SessionStore retention policy is separate from the 12-hour portable
credential lifetime. A cold restart still loses in-memory session state. Use Helix
USR2 for a session-preserving upgrade and follow the rollback boundary in
`docs/RUNBOOK.md`.

## Verification ownership

- Session groups, reusable replica storage, and USR2 carry: `zig build test-helix`
- S2S frame admission and secured queues: `zig build test-mesh`
- Parser and boot projection: `zig build test-config`
- Local and real secured-mesh multi-client acceptance: `zig build test-server`
