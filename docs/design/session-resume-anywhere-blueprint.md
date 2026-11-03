# Mesh-wide reusable sessions

Status: **living implementation contract** · Reconciled: 2026-11-03

This document is the lifecycle and security contract for Onyx Server session resume. A
session credential identifies one reusable logical session. It is not a lease on a
single socket and it does not transfer ownership from one client or node to another.

## Required behavior

These are production invariants to preserve during implementation and verification.
They do not override credential destination, expiry, account, revocation or
retained-state checks described below.

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

Credential families are intentionally separate. The detailed issuer/verifier
matrix is [credential domains](../reference/credential-domains.md).

| Credential | Purpose and destination | Command path | Lifetime |
|---|---|---|---|
| `sst_...` | Authenticate an account; does not select a logical or physical session. | `SESSIONTOKEN` issues; SASL `SESSION-TOKEN` verifies. | Durable account-service policy, normally 30 days; reissue rotates current binding. |
| Bare 32-hex local token | Reuse a retained logical group on its local daemon. It does not select one physical attachment. | `SESSION TOKEN`, then `SESSION RESUME`. | Retained SessionStore/lifecycle authority, not an embedded TTL. |
| `srm2l.<group>.<attachment>` | Select exact local physical restore under its logical group/account. | Composite `SESSION TOKEN`, then `SESSION RESUME`. | Retained group and attachment authority. |
| Legacy mesh-sealed SRM1 | Portable logical-session reclaim subject to origin/replica policy and reachability; can redirect. | `SESSION MTOKEN`, then `SESSION RESUME`. | 12 hours, absolute mesh Unix milliseconds. |
| `srm2m.<sealed>.<attachment>` / SRM2 | Signed exact attachment claim; current issuance binds destination to issuer, so another node redirects rather than independently restoring it. | Composite `SESSION MTOKEN`, then `SESSION RESUME`. | Signed issue/expiry and retained authority; default maximum 12 hours. |

Composite issuance is configurable and defaults off. Envelope parsing is not
signature verification. The live SRM2 exact-restore path does not activate the
codec's separate destination countersignature/consume replay machinery. A live
portable exact credential can therefore produce a valid REDIRECT; it must never
silently fall through to creating a new attachment on the receiving node.

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
converges on one logical session instead of one token per peer. Legacy logical local/portable credentials remain reusable capabilities: successful
attachment does not consume the whole logical group. Composite exact-restore
credentials additionally select the physical attachment and enforce issuer and
destination rules; they are not permission to create another arbitrary attachment. `SESSION MTOKEN` includes
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
client to the same token group, and leaves the source client untouched. For an eligible staged legacy mesh replica, restore borrows the signed snapshot;
it does not consume the logical replica. Composite exact restore follows its
issuer/destination path instead of treating that replica as a new physical slot.

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

Replies depend on the credential family. A `FAIL SESSION` reply does **not**
by itself prove that every supplied credential is invalid or consumed:

| Result | Meaning and client action |
|---|---|
| `FAIL SESSION INVALID_TOKEN` | Malformed, unverifiable, expired, wrong-account or invalid-route credential. Correct the credential/authentication; it is not an automatic retry-preservation result. |
| `FAIL SESSION NO_SESSION` | No matching logical session at its authoritative origin. This differs from a missing selected physical attachment. |
| `FAIL SESSION SESSION_REVOKED` | The logical group is denied by current revocation/restart-required state. Do not treat this as successful restore. |
| `FAIL SESSION NO_ATTACHMENT` | An exact composite credential selects no retained matching physical attachment. Account login and logical-session membership are separate questions. |
| `FAIL SESSION ATTACHMENT_IN_USE` | The selected exact attachment is still active. Its credential may remain valid; exact restore does not create a sibling or steal the live socket. Retry only after the attachment is reclaimable or deliberately choose a separate supported attachment path. |
| `WARN SESSION ORIGIN_UNREACHABLE` | A legacy mesh origin is disconnected; retain the credential and retry after convergence. |
| `WARN SESSION TEMPORARILY_UNAVAILABLE` | Snapshot/registry/restore could not complete safely; retain the credential and retry. |
| `SESSION REDIRECT: ...` | Reconnect to the specified trusted issuer/origin for that credential's restore scope; this node has not restored it. |

The reusable logical-session path may add an attachment while siblings stay
live. Composite exact restore targets one physical attachment and has the busy,
missing and revoked outcomes above. Those paths must not be conflated. Busy
`FAIL` does not call the one-response preservation hook; clients must not discard
a still-valid busy credential merely because its result used `FAIL`.

Onyx normally sends `SESSION RESUME <stored>` followed immediately by `SESSION TOKEN`.
After a WARN retryable restore result or redirect, Onyx Server suppresses that next token response once
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
credential lifetime. A cold restart loses in-memory live session and attachment
state. Durable account `SESSION-TOKEN` can restore account login after a cold
restart; it does not recover the old TCP socket, exact attachment or lost in-memory
message custody. Use compatible Helix for connection-preserving maintenance and
follow the [runbook](../RUNBOOK.md) refusal/rollback boundary. Recording and other
uncheckpointed owners can require refusal before exec.

## Verification ownership

- Session groups, reusable replica storage, and USR2 carry: `zig build test-helix`
- S2S frame admission and secured queues: `zig build test-mesh`
- Parser and boot projection: `zig build test-config`
- Local and real secured-mesh multi-client acceptance: `zig build test-server`

## Client example and evidence scope

After a protected connection authenticates the same account:

```irc
SESSION TOKEN
SESSION MTOKEN
```

Store the returned credentials privately. On reconnect, issue
`SESSION RESUME <exact-stored-credential>` and process success, WARN, FAIL or
REDIRECT before replacing stored state. Do not substitute an `sst_` login token
for that resume credential, or discard a still-valid credential on retryable
`TEMPORARILY_UNAVAILABLE`/`ORIGIN_UNREACHABLE`.

The [2026-11-03 release acceptance](../audit/release-and-test-speed-2026-11-03.md)
proved pre-cold durable account-token login recovery, multi-client event checks,
local composite restore, and cross-node redirect followed by origin restore.
That bounded acceptance does not prove arbitrary-node composite exact migration.
Source: `src/daemon/sessions.zig`, `src/proto/session_resume_credential.zig`,
`src/proto/session_reclaim_attachment.zig`, and the live SESSION/replica handlers
in `src/daemon/server.zig`. Current Helix relation validation also carries physical
connection authority separately from logical token rows.
