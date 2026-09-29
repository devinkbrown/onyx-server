<!-- SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com> -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Onyx Server — gap roadmap (2026-09-29)

**Audience:** the person deciding what the daemon builds next.
**Source of truth:** the tree at `99974787`, whose Zig sources are byte-identical
to `ae78d490` (`0.7.0`). The four commits after that baseline are documentation
only. Live fleet record: both nodes run `0.7.0+ae78d490`
(`docs/ops/release-v0.7.0-feature-activation.md`).

This file is the missing-feature map. It does not replace
`docs/ROADMAP-2026-Q4.md`, `docs/FEATURE-ROADMAP.md`, or
`docs/releases/0.7-MAJOR-ROADMAP.md`. Those remain the historical 0.7 plans.
Where they disagree with this file about *what is already in the tree*, this
file wins, because it was checked against current source. Where they name a
track this file still lists (PX, KX, IX, HX), that track is still open: no Zig
file has changed since those plans were left unmarked.

Measured this pass: **851** Zig files, **598,630** lines, `src/daemon/server.zig`
**102,407** lines. Same figures the 2026-09-06 reconciliation published.

---

## 0. Verdict

Onyx Server is already a large IRC/IRCX mesh daemon: Armor TLS, Mooring,
Undertow, Helix, reusable sessions, local search, group-control admission,
a media plane, and a two-node production mesh. The work that is *missing* is
not another subsystem. It is four things the current tree claims, stages, or
leaves on the floor:

1. **Durability.** A lot of user-visible state is a RAM table with a comment
   that says "persistent" or "survives reconnect." Reconnect of a socket is not
   a process restart, and a Helix `USR2` is not a cold boot. History rides
   Helix. Memos, gags, vhosts, flood/reputation, shuns, and password-reset
   tokens do not.
2. **Staged authority that cannot be turned on.** OCG2 `project` and `mint`
   fail boot. MESSAGE_V2 defaults to `compat` (receive and forward, author the
   legacy form), and its "durable" outbox survives Helix only, not a power
   loss. Account databases are per node. Nick trust is a session-replica proof
   for one live attachment, not a mesh-wide account directory. Ripple's
   witnessed-death machine is a library the daemon timer does not call.
3. **Libraries with no daemon caller.** Histograms, cron, circuit breakers,
   GCRA, ICE-as-an-agent, TURN, RaptorQ, XOR/cuckoo filters, and the generic
   audit ring are real Zig modules that nothing in `src/daemon/` calls.
4. **Product surfaces a modern network is expected to have,** and this one does
   not: slowmode, threads, scheduled messages, retention, appeals, outbound
   webhooks, raid correlation, unfurls, standards-browser WebRTC, call
   recording, and a reactor that runs on anything but Linux.

Do not open a new crypto stack, a new mesh, or a new history codec to get
there. Wire, persist, and activate what is already written. Split
`server.zig` only along a seam that one of those slices forces.

---

## 1. Already in the tree

Leave these alone unless a gap item below names a residual.

| Area | What ships | Evidence |
| --- | --- | --- |
| IRC core | Registration, `PRIVMSG`/`NOTICE`/`TAGMSG`, modes, bans, `KNOCK`, `CREATE`, `RENAME`, `TEMPMODE`, `CHATHISTORY`, `MARKREAD`, `MONITOR`, `METADATA`, `REDACT`, `EDIT` | `docs/reference/commands/_index.md` |
| IRCX verbs | `IRCX`, `DATA`, `REQUEST`, `REPLY`, `WHISPER`, `PROP`, `ACCESS`, `SACCESS`, `AUTH`, `EVENT`, `MODEX`, `LISTX` registered | `docs/releases/0.7-MAJOR-ROADMAP.md` §2; `src/daemon/modules/ircx.zig` |
| Search | Local `SEARCH` behind `draft/search`, membership check, rate limit, bounded intersect | `src/daemon/modules/messaging.zig`, `server.zig` `handleSearch` |
| Reactions / reply tag | `+draft/react` and `+draft/reply` on `TAGMSG` | `src/proto/activity.zig`, `src/proto/msgedit.zig` |
| Sessions | Multi-attach, local token, mesh `MTOKEN`, Helix carry, EXTERNAL canonical pick | `docs/design/session-resume-anywhere-blueprint.md` |
| MESSAGE_V2 machinery | Signed codec, Lotus ingest, replay guard, outbox, Helix activation record. Default mode is `compat` | `docs/design/message-v2-exact-once.md`, `src/daemon/relay_v2_activation.zig` |
| Event Spine v2 | Signed mesh oper events, capability bit, Helix checkpoint | `docs/design/event-spine-mesh-v2.md` (status: shipped) |
| E2EE group control | Opaque `E2EEGROUP` admission, on by default. Daemon is not a content member | `e2ee_group_mesh_authority.zig`; activation record |
| Nick collision policy | Strangers lose to a stable UID. A same-account short-circuit requires a negotiated `SESSION_REPLICA_V2` proof for a live local attachment of that exact token. Replicated `identity.key.*` / `identity.residence.*` props are not an authority source | `server.zig` `residenceTrusted` |
| Accounts | SASL PLAIN / EXTERNAL / SCRAM-SHA-256, OroStore accounts, TOTP confirmed secrets in `.props`, WebAuthn creds module, `KEYTRANS` node-local MMR | `services.zig`, `totp_auth.zig`, `key_transparency.zig` |
| Abuse primitives | Warden `WARD ADD/DEL/LIST/TEST`, Koshi filter, DNSBL, clones, shun, spamtrap, IP reputation, connection classes | `warden.zig`, `content_filter.zig`, `conn_class.zig` |
| Operator | SASL elevation (`OPER` password path returns `491`), `GRANT`/`REVOKE`/`GRANTS`, `AUDIT` + ProofMark verify | `docs/reference/commands/oper-moderation.md` |
| TLS | TLS 1.3, TLS 1.2 with Extended Master Secret required, ECH accept/reject + `retry_configs`, mTLS, raw public keys, delegated credentials, OCSP stapling, opt-in CRL/SCT, X25519MLKEM768, ML-DSA/SLH-DSA *verify* | `src/crypto/`, `docs/reference/glossary.md` (EMS) |
| Armor CLI | `x509`, `genpkey`, `pkey`, `req`, `dgst`, `verify`, `rand`, `ciphers`, `asn1parse`, `ocsp`, `crl`, in-memory `s_client` | `src/cli/` |
| Media | UDP SFU, ICE-lite STUN, DTLS-SRTP, native CadenceVox/CadenceVis, spatial ABR on the native leg, caption ring, NACK/RTX cache inside `MediaTransport` | `media_plane.zig`, `server.zig` `mediaAbrSelection` |
| Helix | `USR2`, sealed memfd, capsule kinds through `handoff_manifest` (17) | `src/daemon/helix/capsule.zig` |
| Metrics that exist | Ten Prometheus counters/gauges, including `onyx_s2s_links_active` vs `onyx_s2s_tcp_active` | `src/daemon/server_stats.zig` `rows` |
| WASM host | Fuel-metered interpreter, capability checks, `message_pre_deliver` hook, `OROWASM` inspect | `src/wasm/host/` |
| Live gates already on | Discoverable network, WebTransport `:4433`, kTLS TX, STS, media MAC + DTLS, SQPOLL, inbound webhooks on loopback `:9140`, Web Push, DNSBL, backups of the account snap | `docs/ops/release-v0.7.0-feature-activation.md` |

---

## 2. How to read an item

- **Id** — stable for this document. One id, one outcome.
- **Accept** — the observable that closes it. A helper test is not the accept.
- **Size** — `S` one focused change, `M` a subsystem, `L` cross-subsystem, `XL` its own release.
- **Owner** — from `.agents/ROSTER.md`. `onyx-server-integrator` is the only writer of `src/daemon/server.zig`.
- Client work lives in `/home/kain/onyx`. Items marked **server-first** change a capability, token, or authority rule. Items marked **client-half** are blocked on the Onyx repo.

Invariant bar on every item: reactor 0 owns shared timers; mesh identity is the node `shortId`; cross-host order is a wall-clock HLC; Helix layout changes bump the capsule and keep a legacy decode; untrusted input fails closed; secrets compare in constant time.

---

## 3. Wave 0 — make the claims survive a restart

These are the highest-leverage gaps because the commands already exist and the
data already has a shape. Users lose it on `USR2` or on a cold start.

### GAP-D1 — Cold history

**Size L.** Lotus (`src/proto/lotus.zig`) is an in-memory ring and performs no
I/O. `CapsuleKind.history` carries that ring, plus the `SIDX` search checkpoint,
across Helix only (`helix/capsule.zig`, `helix/history_checkpoint.zig`). A cold
restart starts an empty `CHATHISTORY` and an empty `SEARCH`.

**Accept:** a killed-and-restarted node restores bounded channel and DM history
for every target that was inside the retention window, with the same msgids.
Search hits the restored rows. E2EE ciphertext is stored as ciphertext and is
not indexed as text. Restore is allocation-failure atomic. A USR2 of the same
image still round-trips.

**Home:** OroStore or a sibling WAL, `CapsuleKind.history` unchanged in meaning,
`src/daemon/search_index.zig`.

### GAP-D2 — Offline memos die with the process

**Size M.** `src/daemon/memo.zig` says "in-memory + bounded; a WAL/snapshot
backing can be layered later." `CapsuleKind` has no memo kind.
`helix/memo_capsule.zig` is not maintained. Memos ride `memo_durable.zig` and
the OroStore `memos` family. `CapsuleKind` still has no memo kind.

The same pattern covers other codecs that describe themselves as the upgrade
payload and are not sealed and not `CapsuleKind`s: `read_marker_capsule.zig`,
`whowas_capsule.zig`, `chathistory_cursor_capsule.zig`,
`bouncer_buffer_capsule.zig`, `account_capsule.zig`. `ratelimit_capsule.zig`
is not maintained.
Read markers are a process-local store. Bouncer rewind on `JOIN` uses that
marker. After USR2, offline memos are gone, `MARKREAD` positions reset, WHOWAS
is empty, and connect throttles are zero. Channel text in Lotus still crosses
Helix.

**Accept:** a memo sent to an offline account is delivered after a cold restart
and after a USR2. `MARKREAD` for an account is the same marker after USR2 and
is visible to that account's attachment on the other node (the mesh half is
GAP-P16). The mailbox bounds stay. A mesh `MEMO_PUSH` hint still fires when
the account attaches on either node. WHOWAS either rides a real capsule or the
codec file is deleted so it stops claiming the upgrade path.

### GAP-D3 — Gags, vhosts, and "persistent" RAM sets

**Size M.** `gag_set.zig` documents a gag that survives reconnection and then
says the module performs no I/O. Nothing under `src/daemon/helix/` references
it, so a USR2 drops the set. `guise.Registry` (vhosts) lives on `LinuxServer`
with no capsule kind and no OroStore family in use (`store.zig` `vhosts` is
test-only).

**Accept:** `MODE +z` gags and granted vhosts are still in force after USR2 and
after cold start. Reconnect behavior stays as it is.

### GAP-D4 — Abuse state does not survive upgrade

**Size L.** Flood buckets die with the connection by design
(`flood_guard.zig`: "a per-account abuse score that survived reconnects would
be a separate axis; this module does not model it"). Reputation, clone tables,
gags, shuns, spamtraps, and Koshi patterns are RAM. `ratelimit_capsule.zig`
is not maintained, and it was not a `CapsuleKind`.
`SPAMTRAP LIST` reports counts, not the recent trips. There is no oper dump of
reputation rows, flood buckets, or the gag set.

**Accept:** three separate outcomes, shipped as separate slices if needed:

1. An oper can ask why a live connection was throttled, shunned, DNSBL-marked,
   or reputation-decayed, from current RAM (`WARD` already answers ward match;
   this is the other engines).
2. Shun, spamtrap, Koshi, and reputation rows survive USR2. Cold start reloads
   them from a bounded store.
3. A per-account score survives reconnect and is a different axis from the
   per-connection token bucket. It never replaces the connection guard.

### GAP-D5 — Credential and recovery splits

**Size M.** PLAIN account records are in OroStore. Confirmed TOTP secrets are
mirrored to `.props`. Pending TOTP enrollments, `REGISTER` verify tokens, and
`RESETPASS` tokens are in-memory (`server.zig` on `reset_store`: "in-memory
only, like `account_verifies`"). SCRAM is documented as an in-memory companion
of the PLAIN record (`services.zig`). CertFP bind has the same comment, with
`durable_credential_props` as a third path.

**Accept:** one restart story. A verify or reset token issued before a crash is
either still valid until its TTL or explicitly invalidated and the user can
request another. SCRAM and CertFP binds that the server advertised before the
crash still work after it. Pending enrollments may stay RAM if the accept says
so.

### GAP-D6 — Backup covers the account snap, not the product

**Size M.** `[backup]` copies the OroStore snapshot and the chanstats snapshot
(`server.zig` backup path). It does not copy history, search, memos, vhosts,
webhook TSVs, or abuse tables. Webhooks persist only when `webhook_store_path`
is set. Event Spine history persists only when `oper.event_history_path` is
set; empty means process lifetime (`server.zig` ~1673).

**Accept:** `onyx-server` can verify a backup set and restore it into a scratch
directory. The set lists every family it includes and every family it
deliberately excludes. A restore drill is a documented command, not a hope.

### GAP-D7 — Mail and password reset are best-effort

**Size M.** `mail_sender.zig` has no retry. Its TLS trust-anchor set is empty,
so a verified session to a real relay needs `insecure_skip_verify`. Live nodes
keep mail disabled because no relay is configured
(`release-v0.7.0-feature-activation.md`). `setAccountEmailPending` failure is
swallowed after the RAM token exists.

**Accept:** a configured relay with a non-empty trust store delivers or records
a durable failure. Tokens are not issued when the pending-address write fails.
Live mail stays off until that relay exists. This item does not enable mail on
the fleet by itself.

### GAP-D8 — Web Push is lossy and Linux-only

**Size S.** `webpush.zig` caps the queue (256) and drops on overflow. The
non-Linux build disables the worker.

**Accept:** overflow is a metric and an oper event, not a silent drop. The
subscription rows in `.props` stay. Delivery remains at-least-attempted, with
the drop counted. A portable backend (Wave 6) either implements the worker or
keeps the explicit disable.

---

## 4. Wave 1 — authorities the binary refuses to turn on

The live pair is healthy with these held. Holding them is correct. Leaving the
code permanently unable to leave the hold is the gap.

### GAP-A1 — OCG2 projection and mint

**Size XL.** `ocg2RuntimeModeSupported` returns true only for `disabled` and
`observe` (`src/daemon/config_boot.zig`). `project` and `mint` are parsed and
then rejected so a restart cannot half-apply them. Observe restores a durable
image, checks a bounded reconciliation, and changes no privileges. The issuer
module can mint permits in tests; the boot path cannot. Live config keeps OCG2
disabled. Today's operators are the config `OperRegistry` plus mesh
`GRANT`/`REVOKE` (OCG1), optionally reloaded from `oper_grants_path`.

**Accept:** `projection_enabled = true` boots, projects durable authority onto
live sessions, and rolls back to the previous image on failure. Every
transition is on the audit trail. `mint` stays available only on the configured
authority node, refuses a private key in TOML, and revokes mesh-wide. A DST
covers project across restart. Until that accept exists, the keys stay rejected
at boot — that part is already right.

### GAP-A2 — MESSAGE_V2 authoring is still compat, and "durable" means Helix

**Size L.** `relay_v2_activation.Mode` defaults to `compat`: peers receive and
forward v2, and the node authors the legacy representation. `active` requires
a non-zero epoch and a full roster digest, and a node that has been active may
not hot-downgrade (`relay_v2_activation.zig`). The transactional admit path is
implemented (`docs/design/message-v2-exact-once.md`). That document's "durable"
is a retransmit-until-ACK obligation that survives `USR2`. It is not a disk
WAL. A cold restart of a node that already acknowledged upstream and still owes
a downstream hop drops the last copy, and it empties the replay watermarks, so
the next boot is not the same accepted set.

Required nodes for authoring are this node plus direct `[mesh].trust_roots`,
not "every node that exists." An empty or colliding root set disables the
durable membership path. The activation roster is not a signed ready
certificate, and changing the roster after activation is not implemented.
`require_secured` defaults false; v2 authoring, oper grants, and Event Spine
v2 run on a Mooring `SecuredLink`. A plaintext peer still relays legacy
`MESSAGE`. The live pair is secured. A fresh node is not, until someone sets
the flag.

**Accept:** a seeded DST shows one accepted id across partition and USR2, with
no duplicate delivery and no silent legacy fallthrough once the mode is
`active`. A separate accept, GAP-D1's sibling, is a crash log: after power
loss the owed hops are still owed, or the design states that power loss may
drop the tail and the client must tolerate it. Both live nodes then stage the
same epoch and roster and flip `relay_v2_authoring` to `active` in a
documented order. Compat remains the default for a node that has not staged
the plan. New configs that set a mesh peer without `require_secured` fail
`--check-config` or print a doctor warning (GAP-O4).

### GAP-A3 — Same-account nick coexistence is a session replica, not an identity prop

**Size L.** `residenceTrusted` (`server.zig`) returns `trusted` only when the
peer negotiated `SESSION_REPLICA_V2` and this node has a live local attachment
of that same portable token whose signed origin entry binds account, nick, and
token. The comment at that function is explicit: replicated `identity.key.*`
and `identity.residence.*` props are retired as an account-authority source,
because a Byzantine peer could publish both the key and a proof it signs.
Display of an origin-authenticated account (WHOIS, oper prefix) is a wider
path and stays `account_trusted = false` for collisions.

So two devices of one person, on two nodes, still UID-rename on a third node
unless a session-replica proof for that exact token is live here. Enrolling an
identity key does not, by itself, close it. The blueprint's "design only"
header is stale. The blueprint's *product* accept is not met.

**Accept:** two honest attachments of one account appear under the real nick
on every other secured node, and a forged `account=` without the replica proof
is UID-renamed. A compromised home node lying about its own users stays the
deferred residual, written down, not silently "fixed" by trusting props again.

### GAP-A4 — Event Spine replay is optional on disk

**Size S.** Mesh v2 forwarding is implemented. `event_history_path` empty means
the replay ring dies with the process. The oper console that shows another
node's flood verdicts is a client surface (Onyx C-03 / C-18) on top of a feed
the server already has.

**Accept:** the reference config sets a path, boot reloads it, and a USR2 keeps
it. An oper subscribed on one node can replay a bounded window of the other
node's signed events after that node restarts. Partition healing does not
duplicate a signed id.

### GAP-A5 — `defer_taskrun` cannot be enabled on the live boot

**Size M.** The flag parses and the ring probe fails closed. On the deployed
four-reactor image, rings are created before worker threads bind, so every
reactor returned `InvalidThread`. The kernels also reject
`SQPOLL | DEFER_TASKRUN | SINGLE_ISSUER` with `EINVAL`. Live config keeps
SQPOLL on and `defer_taskrun` off
(`release-v0.7.0-feature-activation.md`).

**Accept:** either the ring is created on the thread that will run it and the
flag combination the kernel accepts is the one the config can express, with a
regression test for the live four-reactor shape; or the flag is rejected at
`--check-config` whenever `sqpoll` is on, with the kernel reason in the error.
The live nodes stay on the safe side until that test exists.

### GAP-A6 — kTLS RX rekey closes the connection

**Size M.** Live kTLS is `tx` on purpose. `tls_conn.rekeyKtlsRx` reinstalls
`TLS_RX` for a KeyUpdate that does not ask for a reply. A KeyUpdate with
`request_peer` closes: `LinuxServer.handleKtlsRxControl` has no `TLS_TX`
reinstall and no server KeyUpdate reply. TLS 1.2 kTLS derivation is also
unwritten (`tls_conn.zig`).

**Accept:** a TLS 1.3 peer can rekey in both directions while kTLS RX is on,
without a reconnect, proven against the kernel. Until then `[tls] ktls` stays
`tx` on the fleet, and `txrx` remains a documented footgun. TLS 1.2 kTLS stays
cut under the modern-only posture unless a kernel round-trip proves it.

### GAP-A7 — New listeners have no Helix checkpoint

**Size M.** Turning on WebTransport `:4433` required a cold restart because
Helix has no exact checkpoint for a listener that did not exist in the
predecessor (`release-v0.7.0-feature-activation.md`).

**Accept:** adding or removing a configured listener either adopts across USR2
or `--check-config` / the upgrade command refuses with "cold restart required"
before the signal is sent. The operator never discovers this from a failed
adopt.

### GAP-A8 — OCSP staple fetch does not verify the responder's TLS

**Size S.** `ocsp_staple.fetchAndPublish` posts with
`insecure_skip_verify = true`. The OCSP response signature is checked. The
HTTPS transport is not. Live OCSP is off because the deployed leaves publish
no responder URI.

**Accept:** the fetch uses the daemon trust store. A bad certificate fails the
fetch and keeps the previous staple. Signature checks stay as they are. The
fleet stays off while the leaves have no URI.

### GAP-A9 — Accounts, nick registrations, and channel registrations are node-local

**Size XL.** OroStore on each node holds that node's accounts. No S2S services
frame carries `REGISTER` / nick reg / channel reg. Device *keys* replicate as
signed entity props (`E2EEKEY` → `e2ee.device.*`). Key transparency stays
node-local. A client that already holds an `MTOKEN` can attach on the other
node without that node's password file. A fresh `SASL`/`IDENTIFY` on the other
node cannot see the account. Operators do not have one directory.

**Accept:** an account registered on eshmaki can `IDENTIFY` on ircx.us, and a
channel registration's AKICK and access list are the same list on both, after
anti-entropy, with a fail-closed rule when the two stores disagree. Password
verifiers replicate as verifiers, not as plaintext. This is the largest
product hole in the mesh, and it is independent of GAP-A3.

### GAP-A10 — A partition longer than the attachment lease looks like a quit

**Size M.** A remote attachment suppresses the logical `QUIT`/`PART` only while
a live attachment lease is visible. The lease TTL is 90 seconds, refreshed
about every 30. A retained session offer is not enough. A partition longer
than the lease, or a peer that never negotiated attachment-lease v2, makes the
home node emit the logical quit while the other socket is still up.

**Accept:** a partitioned attachment stays logically present until the session
TTL or an explicit detach, and it does not flap through `QUIT` and `JOIN` when
the lease refresh is merely late. A truly dead peer still converges. Liveness
stays on the local clock, not on "a newer HLC means dead."

### GAP-A11 — Ripple and Concord are libraries; the daemon re-bursts the world

**Size L.** `S2sPeer.tick` is what emits gossip and repair summaries. The
daemon timer calls `probeRtt` (`maybeProbeMeshPeerRtt` on the maintenance
reactor). It does not call `tick`. `ripple.zig`'s witnessed-death machine and
`ConcordSync` are not on the live loop. `NETHEALTH` fills every established
peer as alive and then renders Ripple. `witness_quorum` floors at 2, so a
two-node mesh cannot bury its only peer through that machine anyway. Indirect
death and suspect/dead do not happen. Multi-hop registry entries are not
gossiped.

Live repair is a full World re-burst about every 30 seconds
(`membership_resync_interval_ms`) plus `MEMBERSHIP_SYNC` on secured links.
`nick_claim.zig` runs inside `convergence.zig`, which the daemon does not
import. The route table's rule is that a remote member cannot take a nick a
local client holds, unless it is the same trusted account (GAP-A3). Two nodes
can each show their own local holder as the winner until the next resync. A
lost `PART` on a secured link waits for the next authenticated sync.

**Accept:** either the daemon drives one gossip/repair tick from reactor 0,
with a DST where a partitioned 3-node mesh converges membership and nicks
without a full world copy, or the architecture docs stop calling Ripple the
live failure detector and describe the 30-second re-burst as the mechanism,
including its cost as the mesh grows. The two-node fleet's `links_active=1`
path can stay the ping-timeout detector. Do not claim witnessed quorum on a
pair that cannot form one.

---

## 5. Wave 2 — an operator can see and steer the node

`/metrics` publishes ten counters and gauges (`server_stats.zig` `rows`).
`STATS m` counts commands. Channel JSON exists when a directory is configured.
That is the whole production observability surface.

### GAP-O1 — Histograms

**Size M.** `hdr_histogram.zig`, `ddsketch.zig`, `tdigest.zig`, and
`substrate/metrics.zig` are imported from `substrate/root.zig` only. No daemon
file records a latency bucket.

**Accept:** `/metrics` grows histograms for TLS handshake, `PRIVMSG` fan-out,
Mooring RTT, and media relay, merged on reactor 0. A dashboard can tell a
slow node from a dead peer. Cardinality is bounded.

### GAP-O2 — Link health beyond up/down

**Size M.** `link_health.zig` exists. The gauges an operator actually has are
`onyx_s2s_tcp_active` and `onyx_s2s_links_active`. They already distinguish
"TCP open" from "Mooring up." They do not show RTT, send backlog, last
anti-entropy round, or "we are partitioned" versus "the peer is down."

**Accept:** one oper command and the same Prometheus text expose those four
facts per peer. Ripple suspicion and value-sync stay different fields. A
"still here" liveness update is never gated on a newer HLC.

### GAP-O3 — Flight recorder is 256 events behind `DEBUG`

**Size S.** `server.zig` holds `trace_recorder: tracelog.FlightRecorder(256)`,
dumped by oper `DEBUG`. `substrate/tracing.zig` (OTel-style NDJSON) has no
daemon caller. `qlog.zig` is used by `substrate/transport_stack.zig`, which the
daemon does not import. `transport.qlog_capacity` is not applied.

**Accept:** a fault (panic path, reactor give-up, Mooring death) writes the
recorder to a bounded file the operator named. Export format is one of qlog or
the existing tracelog. A second exporter waits until the first one has a
reader.

### GAP-O4 — `onyx-server doctor`

**Size M.** `--check-config` answers "does this parse." It does not answer
"why is `links_active` 0 while `tcp_active` is 1," "is the OCSP worker pointed
at a leaf with no URI," or "is `defer_taskrun` combined with SQPOLL on a kernel
that returns `EINVAL`."

**Accept:** one command, read-only, prints a fixed list of checks against the
loaded config and, when a metrics URL is given, the live gauges. Each check is
pass, fail, or skipped, with the file or gauge it used. No network action
except the metrics GET the operator asked for.

### GAP-O5 — REHASH dry-run

**Size S.** REHASH applies. There is no diff of wards, classes, limits, and
listener set against the running image.

**Accept:** `REHASH DRY` prints the changes and applies none. A listener add
still reports GAP-A7's cold-restart requirement.

### GAP-O6 — Raid shield

**Size L.** Per-IP and per-connection limits exist. A raid that arrives as one
user per address, mesh-wide, does not. `admission.zig`, `count_min_sketch.zig`,
`topk.zig`, and `gcra.zig` have no daemon caller.

**Accept:** reactor 0 correlates join shape across Mooring peers, raises one
signed Event Spine verdict, and can engage a channel or network slowmode
(GAP-C2) that relaxes on its own. A single popular channel's normal growth
does not trip it. The sketches stay bounded.

### GAP-O7 — Mooring circuit breaker

**Size M.** `circuit_breaker.zig` has no daemon caller. A peer that accepts TCP
and fails the handshake, or that stalls anti-entropy, can sit in
`tcp_active` without a backoff that the operator can see.

**Accept:** repeated handshake or stall failures open a breaker, log one line,
and retry with the existing backoff helper. An open breaker is a gauge. It
never accepts an unsigned frame to "keep the link up."

### GAP-O8 — Mesh ACL filters

**Size M.** `bloom.zig`, `xor_filter.zig`, and `cuckoo_filter.zig` have no
daemon caller. Bans replicate as full lists.

**Accept:** a compact filter of network bans is what a peer exchanges first;
a hit is confirmed against the authoritative list before anyone is refused.
False positives re-check. The filter is not the authority.

### GAP-O9 — Two-person rule

**Size M.** One elevated session can `DIE`, `RESTART`, or mesh-scope a ban.
`oper_session_provenance.zig` knows who is who. Nothing requires a second
operator.

**Accept:** a config flag makes those commands wait for a second distinct oper
inside a time window. The flag defaults off. Both approvals and the action land
on the audit trail. A single-oper network is unchanged.

### GAP-O10 — Policy rollback

**Size M.** ProofMark records carry `policy_version`, and the live signer
writes the constant `1`. Wards and filters have no generation and no undo.

**Accept:** ward, filter, class, and ban generations are numbered. An oper can
roll the last generation back. The version in the proof matches the generation
that was live.

### GAP-O11 — Outbound webhooks

**Size M.** Inbound `POST /api/webhooks/<id>/<token>` is live on loopback
`:9140`. Nothing pushes Event Spine events out. `audit_trail.zig` is exported
from `daemon/root.zig` and has no production caller; oper audit is a different
ring (`svc_operaudit.zig`).

**Accept:** an oper registers an outbound URL, a secret, and a category mask.
Delivery retries with a cap, signs the body, and refuses link-local and
loopback targets unless the config explicitly allows them. Inbound webhooks
stay as they are.

### GAP-O12 — Bot capabilities

**Size M.** `bot_registry.zig` records whether an account may announce, to
which scope, and how often per hour. It is not a capability token. A bot is
either ordinary or oper.

**Accept:** a bot account holds scoped, expiring grants (speak in a channel,
post a webhook, read history) that are listed and revoked. The grant is not an
oper bit. USR2 keeps it.

---

## 6. Wave 3 — the conversation product

IRCX verbs are registered. The 0.7 IX track (conformance matrix, MODEX names,
LISTX filters, WHISPER/DATA hardening, ACCESS completeness, auditorium and
hidden and knock on the mesh, PROP policy, non-oper EVENT types, AUTH-versus-SASL
table, HELP/ISUPPORT honesty) was never closed. Zig has not changed since that
table was written as open work. **GAP-P0** is that table, done as one matrix
plus tests, not as ten speculative rewrites. Explicit divergences (`TACCESS`,
`BTPROP`, Comic Chat avatar `DATA`, `OPFORCE`) stay divergences and get a row
that says so.

### GAP-P0a — 005 and CHANMODES hide features the daemon already has

**Size S.** Live `005` is `protocol_inventory.isupport_tokens` plus
`buildIsupportTokens`. That list has no `CHATHISTORY`, `ELIST`, `SAFELIST`,
`TARGMAX`, `EXCEPTS`, `INVEX`, `MAXPROP`, `MAXACCESS`, `MAXCODEPAGE`, or
`MAXLANGUAGE`. `proto/isupport.zig` defines a richer default and nothing in the
daemon calls `emitDefault` / `emitFromLimits`. Its `PREFIX` and `CHANMODES`
also disagree with the live tokens (`PREFIX=(YQqov)*!.@+`). Treat that file as
a dead builder.

`CHANMODES` omits modes the mode table implements: `p` private, `h` hidden,
`u` knock, `a` auth-only, `d` cloneable, `E` clone, `r` registered, `z`
service, `x` auditorium, `w` nowhisper. Clients that learn modes from `005`
will not offer auditorium, hidden, knock, or auth-only. Halloy-style clients
that key history off `CHATHISTORY=` will not see a history limit.

**Accept:** every mode and limit the daemon enforces is either in the
advertised token, derived from the same table the enforcer uses, or listed as
a divergence. `proto/isupport.zig`'s stale defaults are deleted or made to
compile-fail if they drift. One test renders `005` and checks `CHATHISTORY` and
`x`.

### GAP-P0b — SASL stops at the password when 2FA is on

**Size M.** A `PLAIN` or SCRAM success on a 2FA account is failed with
"log in with IDENTIFY … `<code>`" (`dispatch.zig`). There is no SASL
continuation for the second factor, so a 2FA account cannot finish
`AUTHENTICATE`. WebAuthn is a post-registration `WEBAUTHN` ceremony, absent
from the SASL mechanism list, and inert unless `[webauthn] rp_id` and
`origins` are set. OAuth is local JWT verification against a configured HMAC
or JWKS, with no discovery. An unknown account name with no forbid reservation
is not blocked, so a valid token can bind a session that never `REGISTER`d.
`OAUTHBEARER` and `ANONYMOUS` cannot elevate oper. `PASS` sets a seen-bit and
does not check a server password.

**Accept:** a 2FA account completes SASL with a second challenge, or the
capability value advertises that 2FA accounts must use `IDENTIFY` and clients
are told before they start `AUTHENTICATE`. OAuth either refuses unknown
accounts or the config says "auto-provision" on purpose. `PASS` either gains a
real server-password check or the command reference keeps saying it is only a
marker, which it already does — then the gap is just the 2FA and OAuth rows.

### GAP-P0c — WHOIS, WHOWAS, KNOCK, LISTX, and reactions are thinner than the command list

**Size M.**

- `WHOWAS` stores `host = "localhost"`, drops the account in the reply, caps
  the ring at 256 and the reply at 16, and does not record a mesh quit. Its
  Helix codec is not sealed (GAP-D2).
- Remote `WHOIS` fills identity lines from the roster and leaves idle, away,
  and TLS-secure unreplicated.
- `KNOCK` notifies local ops and then always sends `711` to the knocker, even
  when no op on this node was online. Remote ops get an optional `MEMBER`
  event, not `710`.
- `LIST` / `LISTX` use an empty topic and creation time `0` for a channel that
  exists only on the other node. A short window can show a remote `+s`/`+h`
  channel before the mode burst.
- Reactions: `activity.zig` describes a stored CRDT. `pushReactionActivity`
  emits `ACTIVITY` only to current subscribers and returns if there are none.
  A `TAGMSG` may keep a history row. There is no queryable tally.
  `draft/reply` is the same client-tag relay (GAP-P1).
- `cap-notify` is advertised. The set is static, so `CAP NEW` / `CAP DEL`
  never fire. `proto/cap_notify.zig` is not imported by the daemon.
- Classic IRCX AUTH packages `Anon`, `GateKeeper`, and `GateKeeperPassport`
  parse and then map to "unknown package." Remote `SYS`/`ADM` DATA tags fail
  closed even for an oper (`policy_is_oper = false`).
- `draft/multiline` reassembles inbound batches and does not split the
  server's own long replies.
- `announce_board.zig` is imported by `server.zig` and never called.
  `BOTGRANT` records the account in `bot_registry` so `isBot` matches the
  grant; that registry does not build WHOIS 335 or answer `!` commands.
  `+B` / WHOIS `335` are live. The in-channel bot surface is `!weather` /
  `!news`.
- `oper` message-tag is absent. `draft/whoami` is absent from the live
  capability list. `file-upload` exists only on the stale `proto/cap.zig`
  table, which is not the live registry.

**Accept:** each bullet is a test that matches the user-visible behavior, and
the command page says the limit in one sentence. The ones worth implementing,
in order: `CHATHISTORY` in `005` (GAP-P0a), remote LISTX topic, WHOWAS account
and real host, KNOCK that does not claim delivery it did not do, and a
reaction tally that survives a subscriber joining late.

### GAP-P16 — Read markers are this process

**Size M.** `MARKREAD` keys a process-local map by account or nick. Nothing
relays it over S2S. The Helix codec is not on the seal path. `onyx/bouncer`
rewind depends on the marker, so a USR2 or a resume on the other node replays
history the user already read.

**Accept:** the marker survives USR2 and is the same value on every attachment
of that account. A bouncer rewind after upgrade does not dump the whole ring.

The items below are absent as products. Tags and commands that look similar
are named so they are not rebuilt.

### GAP-P1 — Threads

**Size L.** `+draft/reply` is a tag on a message (`proto/msgedit.zig`). There is
no thread id, no membership of a thread, and no history scope that is a thread.

**Accept:** a thread has a stable id, a root msgid, a bounded reply list, and
it survives USR2 and, once GAP-D1 exists, cold start. Clients that only
understand the tag still see the reply tag.

### GAP-P2 — Slowmode

**Size S.** No `slowmode` command, mode, or module. Per-connection flood is a
different control.

**Accept:** a channel mode or PROP sets a minimum gap between a member's
messages. Oper and a configured voice exemption exist. The gap survives USR2.
A raid shield (GAP-O6) can set it and clear it.

### GAP-P3 — Scheduled delivery

**Size M.** `substrate/cron.zig` parses five-field expressions and computes the
next fire. No other Zig file imports it. `TEMPMODE` schedules mode reversions
only (`svc_tempmode.zig`).

**Accept:** a user or oper can defer a channel message or an oper action until
a timestamp or a cron fire. Reactor 0 fires it once. A replay after USR2 does
not send it twice. The memo and history paths that store the body are the
durable ones from Wave 0.

### GAP-P4 — Retention

**Size M.** History is a fixed ring (512 targets × 256 in the server's
`HistoryStore`). Nothing expresses "forget this channel after N days," and
nothing deletes search rows, push payloads, and history together.

**Accept:** a channel PROP sets a TTL. Expiry removes the Lotus row, the search
ids, and any memo that was only a copy of that message. E2EE rooms expire
ciphertext the same way. The daemon does not need the plaintext to forget it.

### GAP-P5 — Mesh search

**Size L.** Local `SEARCH` works. It does not ask another node. Semantic
search does not exist. Call transcripts are a 128-entry RAM ring cleared when
the call ends (`transcript.zig`), so they are not in the index.

**Accept:** a search on one node returns hits from targets the user can see on
any node, each hit authorized on its own, with a hard cap. Ciphertext bodies
are skipped. Transcript search is a later flag on the same command once
transcripts are durable.

### GAP-P6 — Unfurl proxy

**Size M.** No `unfurl` symbol in the Zig tree. Clients that fetch URLs
themselves leak the user's address and open an SSRF if a bot does it from the
server later.

**Accept:** an opt-in daemon fetch returns a bounded title/description/image
for `https` URLs, with a deny list for private, link-local, and loopback
addresses, a size cap, and no cookie jar. Default off. The user's client can
refuse the preview.

### GAP-P7 — Appeals

**Size M.** A ban closes the socket. There is no rate-limited appeal object, no
`appeal.zig`, and no oper queue.

**Accept:** a banned user on a new connection can file one structured appeal
per window without joining the network. An oper lists, answers, and the answer
is audited. The appeal path cannot send channel traffic.

### GAP-P8 — Challenge ladder

**Size M.** `VERIFY` is an email code for `REGISTER`. It is not a challenge for
a suspicious connection. No captcha vendor belongs in-tree.

**Accept:** a connection that trips reputation or the raid shield can be asked
for a daemon-issued challenge (proof of work or an oper-configured question)
before `001`. Failure delays. Success is not an account. The ladder is
pluggable behind one function so a later method replaces the first without a
wire break.

### GAP-P9 — First-message hold and quarantine

**Size S.** Koshi can block a line. Nothing holds a new account's first N
messages for review, and nothing moves a joiner into a quarantine channel.

**Accept:** a channel PROP holds first messages for an oper to release or drop.
Quarantine is an explicit oper action with a reason on the audit trail.

### GAP-P10 — Rich lines, components, slash registry

**Size L.** Messages are text plus tags. Bots have no registered slash verb
with a typed argument schema. Buttons and structured actions do not exist.

**Accept:** a bot registers a command name, a short help line, and a bounded
argument list through a daemon command. Invocation is an ordinary `PRIVMSG` or
a dedicated verb that the bot's grant (GAP-O12) allows. Interactive buttons
wait until the command registry is dull.

### GAP-P11 — IRCX client contract

**Size L, mostly the Onyx repo, server-first where the wire is thin.** The
daemon already emits LISTX, MODEX, WHISPER, PROP, ACCESS, and EVENT. The
client still meets several of those as inbound-only or advanced-settings
(`docs/releases/0.7-MAJOR-ROADMAP.md` CX-1…CX-10). Server work inside this item
is whatever GAP-P0's matrix marks as missing for those screens: mesh-wide
LISTX, auditorium `+x` NAMES, hidden `+h`, and non-oper EVENT types.

**Accept:** a matrix row is either "handler at file:line, test name" or
"divergence, reason." The client work stays in `/home/kain/onyx`.

### GAP-P12 — HTTP read API

**Size M.** Metrics and webhooks are the only HTTP. There is no read-only
channel export for a logged-in account.

**Accept:** a loopback or explicitly bound HTTPS route returns history the
account can already see via `CHATHISTORY`, with the same authz. It is not a
second admin API.

---

## 7. Wave 4 — calls

The media plane is real and on in production: native MAC required, WebSocket
media MAC required, DTLS-SRTP on, DTLS 1.3 flag on. Several of those flags are
ahead of the validation comments in the source.

### GAP-V1 — DTLS 1.3 is enabled and not browser-proven

**Size M.** `media_plane.zig` says the RFC 9147 transcript interop points are
not browser-validated. `dtls13_server` carries the same caveat. The live TOML
sets `dtls13 = true`, with 1.2 as the fallback when a peer does not offer 1.3.

**Accept:** one unmodified browser completes a DTLS 1.3 handshake against this
daemon and media flows, or the live flag goes back to off and the code comment
stays. Same-library tests do not close this item.

Source `[media].dtls13` defaults off, and `dtls13_server.zig` keeps the
transcript caveat (`browser_interop_caveat_held`). With that flag off, a
DTLS 1.2 ClientHello still gets `HelloVerifyRequest`. Unmodified Chromium
150.0.7871.128 launches and has no DTLS client mode, so no handshake is
claimed and no media flowed. The live fleet TOML was not changed. The
heading stays unmarked.

### GAP-V2 — An unmodified browser can join

**Size XL.** Signaling is IRC `MEDIA`, not SDP. The SFU terminates DTLS-SRTP.
Browser WebSocket Cadence is opaque and is not bridged into RTP
(`docs/architecture/03-media.md`). `media_bridge.zig` rewraps native↔RTP headers
and does not transcode. `substrate/ice_agent.zig` is not imported by the
daemon; the plane does ICE-lite STUN. `substrate/turn.zig` is framing without
sockets.

**Accept:** a stock browser joins a room using the documented signaling, audio
is intelligible, and a failure shows up as a numeric rather than a silent UDP
black hole. Native Cadence stays the preferred path for Onyx. TURN is either
wired with an allocation API and an auth secret, or explicitly cut.

### GAP-V3 — Per-receiver simulcast on the RTP leg

**Size L.** Native spatial ABR exists: `mediaAbrSelection` calls
`simulcast_select.selectStable` with three spatial rungs and temporal layer 0.
`native_media_link.zig` still forwards on a spatial ceiling plus keyframe.
Temporal SVC is not in the Cadence container. The RTP SFU has no RID selector.
RTX as its own SSRC is marked deferred in `media_plane.zig`; a retransmit cache
inside `MediaTransport` does exist.

**Accept:** two receivers of one publisher can sit on different spatial layers
without forcing each other up or down. Congestion input is a measured signal
(`twcc.zig` / the existing ABR hint), not a constant. A deferred RTX SSRC is
either implemented or the cache's limits are documented as the product.

### GAP-V4 — Recording with consent

**Size L.** No recording path. Captions are a client-pushed ring
(`MEDIA TRANSCRIPT`), not an ASR, and they vanish when the call ends.

**Accept:** a recording starts only when every current member has a visible
consent bit, stops when a member joins who has not consented, and the daemon
stores ciphertext or an oper-visible artifact whose existence is announced in
the room. A hidden recorder cannot be configured.

### GAP-V5 — Call quality forensics

**Size M.** Depends on GAP-O1. Per-call loss, RTT, and layer are not a
queryable object. `media_stats_agg.zig` and `qlog` are substrate.

**Accept:** a participant or oper can read a bounded quality summary for the
current call. The summary does not include key material.

### GAP-V6 — Speaking queue and spatial audio

**Size M / L.** No raise-hand protocol. No spatial positions. Both are product
layers on the existing room.

**Accept:** a `MEDIA` subcommand or PROP lists a queue the room can see, and
the sender's client is what enforces "you are not at the head." Spatial audio
is a later PROP of positions the server forwards and does not interpret.

### GAP-V7 — FEC and epoch keys stay unwired until a call needs them

**Size M when pulled.** `raptorq.zig`, `reed_solomon.zig`, `red_fec.zig`, and
`media_epoch_key.zig` have no daemon caller. `bbr.zig`, `cc_cubic.zig`, and
`l4s.zig` are in the same state.

**Accept:** do not import them until GAP-V3 has a congestion signal that is
wrong without FEC. Then one FEC scheme, behind the native leg, with a test
that a lossy sim still plays audio.

---

## 8. Wave 5 — fortress

Group *control* frames are live. Group *content* secrecy is a client property.
The daemon must stay unable to read it.

### GAP-K1 — Client group E2EE journey

**Size L, client-half, server already admits controls.** The server accept is
the one in `docs/design/message-v2-exact-once.md` and the E2EE activation note:
exact-once control frames, replay guard survives USR2, member removal changes
the epoch the clients will use, daemon never sees group plaintext.

**Accept:** an Onyx room can be set `encryption-policy=required`, a removed
member cannot decrypt the next message, and a node operator cannot. This item
closes in the client repo. Server bugs found while doing it are in-scope.

### GAP-K2 — Key transparency across the mesh

**Size L.** `KEYTRANS` appends to a node-local MMR and can prove inclusion on
that node. It is not a consistency proof between eshmaki and ircx.us, and it
does not anchor residence keys.

**Accept:** a client verifies a device key against a log both nodes serve
identically, or each node serves a signed head the other has stored. A
revocation on one node is visible on the other after anti-entropy. A missing
log fails closed for clients that require it and stays invisible for clients
that do not.

### GAP-K3 — ProofMark federation

**Size L.** `AUDIT PROOF` verifies a local detached signature. The ring is RAM,
cap 512. `policy_version` is the constant 1. There is no Merkle chain of
moderation proofs and no mesh forward of the proof object beyond the oper
event text.

**Accept:** a third party with the node public key verifies a ban or kick
without asking the operator to screenshot a notice. Proofs survive restart.
The chain detects a removed entry.

### GAP-K4 — Sealed rooms

**Size XL.** A channel whose membership the server can enumerate is the current
model, and NAMES depends on it. A room the server cannot enumerate is a
different product.

**Accept:** a design that names what the server still must see (routing,
abuse, Helix) and what it must not (the member list in the clear), plus a
fail-closed prototype that does not weaken ordinary channels. Do not start
this before GAP-K1 is boring.

The prototype is the channel PROP `membership-visibility`. Absent and
`ordinary` keep today's `NAMES`, `WHO`, and `WHOX` lists, including a bare
`NAMES`. `sealed` answers `MEMBERSHIP_SEALED` and does not emit the member
list or an empty end-of-list. Any other value is rejected. A stored value the
server does not understand refuses the roster. Delivery still uses the channel
name, a `KICK` still names its one target, and the world membership used to
route stays. Helix does not publish that membership as a clear roster. No new
`CapsuleKind`. The GAP-K1 client journey stays open. The heading stays unmarked.

### GAP-K5 — Post-quantum signatures

**Size L when a profile exists.** `ml_dsa.zig` and `slh_dsa.zig` verify. They
do not sign. TLS `SignatureScheme` has no ML-DSA or SLH code point.
CertificateVerify signs Ed25519, ECDSA P-256, or RSA-PSS-SHA256. Hybrid
certificate profiles are not ratified here.

**Accept:** signing arrives with ACVP `sigGen` vectors, or the verify-only
posture is written down as the permanent 1.x choice. No private hybrid profile.

### GAP-K6 — TLS interop breadth

**Size M each, do not block the product.**

| Gap | Evidence |
| --- | --- |
| ECH combined with HelloRetryRequest | Server raises `EchHrrUnsupported`; client raises `HelloRetryRequestUnsupported`. `retry_configs` on reject exists. |
| HPKE AEAD for ECH is ChaCha20-Poly1305 only | BoringSSL-style AES-GCM ECH configs cannot be opened. |
| Key shares are X25519, P-256, X25519MLKEM768 | `x448`, `secp384r1`, `secp521r1` are not key shares. P-384 ECDSA *verify* for certificates does exist. |
| AES-CCM suites are named and `isAllowed` is false | Intentional unless a caller appears. |
| Cert compression is zlib only | brotli and zstd are ignored. |
| `armor s_server` and `armor enc` exit 3 | `src/cli/stub_cmds.zig`. `enc` stays exit 3: there is no openssl-enc KDF and this tree will not invent one. |
| `armor s_client` live `-connect` | `s_client_cmd.run` returns `NotImplemented` after building a client. `handshakeInMemory` works. |
| In-daemon CRL CDP and CT-log fetch | Callers pass DER. Default policy is fail-open unless `require_crl` / `require_sct`. ACME forces those off. |
| `enforce_cert_signature_algorithms` defaults off | Chain scheme checks run only when the flag is set. |
| BoGo lane | `tools/bogo/expected-baseline.txt` is 24 pass / 3 skip. The exploratory full corpus is not that lane. Disabled tests include ECH, HRR, resumption, 0-RTT, mTLS, DC, P-384, P-521, DTLS. |
| Multi-certificate TOML | `[[tls.sni]]` parses in `config_format.zig` and the listener selects `sni_certs`. `[[tls.ech_keys]]` remains the ECH list. |
| Delegated-credential mint and rotation | Both roles verify a presented DC. Nothing in-tree mints or rotates one. |
| CLI sandbox | The armor CLI calls none of Landlock, seccomp, pledge, or unveil. Daemon Linux landlock and seccomp live in `kernel_linux.zig` (GAP-X3). pledge and unveil are absent. |

**Accept:** each row is either implemented with a test or moved to the cut list
in section 12 with a reason. BoGo's accept is a pinned runner whose
`DisabledTests` name a reason per entry. A 24/3 baseline stays honest.

### GAP-K7 — Forward-secure history rekey and metadata-min mode

**Size XL.** Not started. A retained ciphertext from an old epoch is readable
by anyone who held that epoch's key. Metadata-min mode (hiding nicks, sizes,
and timing from the server) fights NAMES, search, and abuse.

**Accept:** a written threat boundary first. Implementation follows only if
GAP-K1 and GAP-P4 are done and the boundary still demands it.

---

## 9. Wave 6 — the daemon is Linux-only

### GAP-X1 — Portable reactor

**Size XL.** `Server` is `LinuxServer` on Linux and `PortableServer` elsewhere.
`PortableServer.init` opens the native `IoBackend`, listens, and `runOnce`
accepts and answers through `processLine`. Clocks, entropy, and pid are
already portable (`substrate/platform.zig`). Helix `USR2` adoption stays on
`LinuxServer`.

`substrate/io/ring.zig` is an unfinished prototype: no connect, poll, or cancel,
and it does not register provided buffers with the kernel. The production ring
is the private Ringlane inside `server.zig`. Do not promote the prototype by
renaming it.

**Accept:** an `IoBackend` with accept, recv, send, poll, cancel, and timeout.
Linux keeps today's ring. Windows IOCP and one BSD kqueue implement the same
trait and fail closed on a missing op. Helix `USR2` stays Linux. Other kernels
refuse a USR2 capsule instead of adopting it wrong. A `zig build` of the daemon
succeeds for `x86_64-linux` and at least one non-Linux triple.

FreeBSD 14.5-RELEASE-p1 executed the shipped kqueue submit
(`GAP-X1 freebsd kqueue submitted=6 errno=0`). OpenBSD 7.9 executed the
shipped kqueue accept and recv twice
(`GAP-X1 openbsd kqueue submitted=1 accepted=6 bytes=8 errno=0`), then pledge
(`GAP-X3 openbsd pledge result=ok errno=0`). Windows 11 22H2 WinPE, build
22621.525, executed the shipped IOCP submit twice
(`GAP-X1 windows iocp submitted=6`, `GUEST_EXIT:0`). The same boots dequeued
Registered I/O (`GAP-X3 windows rio dequeue=1 bytes=4 status=0`). On Linux,
`PortableServer` answered `PING lane` with `PONG` through `processLine` on
ringlane (the GAP-X1 test, twice, 0 leaked). NetBSD and DragonFly are out of
scope. The witnessed non-Linux `onyx-server` processes are FreeBSD 14.5
kqueue (`0.7.0+ddf11915`, three PONGs, capability mode), OpenBSD 7.9 kqueue
(`0.7.0+ddf11915`, three PONGs, after pledge), and Windows 11 22H2 WinPE IOCP
(`0.7.0+d4ea0097`, three PONGs, job flags `0x2400`). The headings stay
unmarked. Live `IDENTIFY` and live `relay_v2_authoring=active` stay unmet.

### GAP-X2 — `server.zig` strangler, only as a seam is touched

**Size XL, sliced.** 102,407 lines in one file. A mechanical split is how
reviews die. Extractions that pay for themselves:

1. Ringlane submission and completion (unblocks GAP-X1).
2. The delivery / SendQ path.
3. One command family at a time (media, search, oper), each behind the existing
   module thunks in `src/daemon/modules/`.

**Accept:** each extraction is behavior-identical under the focused test for
that family, and `server.zig` shrinks by the moved lines. `onyx-server-integrator`
remains the only writer of whatever file still owns the reactor loop.

### GAP-X3 — Kernel features, after the backend they belong to

None of these strings appear in `src/**/*.zig` except the kqueue comment on
`PortableServer`. They are real gaps, and they are per-OS. Ship them on the
kernel that has them. Do not fake them with a compile-time zero.

| OS | Missing | Notes |
| --- | --- | --- |
| Linux | Landlock, seccomp, `TCP_FASTOPEN`, `TCP_USER_TIMEOUT`, `SO_INCOMING_CPU`, `IORING_OP_MSG_RING`, `openat2` `RESOLVE_*`, `pidfd`, `close_range`, `MADV_DONTDUMP` / `MADV_WIPEONFORK` on secrets | `eventfd` already wakes shards. kTLS TX is live. Multishot accept/recv, provided buffer rings, `send_zc`, and fixed files are `RingFeatures` defaulting false and are not projected from config. |
| FreeBSD | `TCP_TXTLS_ENABLE` ran on FreeBSD 14.5-RELEASE-p1: `GAP-X3 freebsd ktls result=ok errno=0` after `kern.ipc.tls.enable=1`. With that sysctl at 0 the same setsockopt returned errno 45. `SO_REUSEPORT_LB` and Capsicum are in that module | AES-GCM is `CRYPTO_AES_NIST_GCM_16` (25). ChaCha20-Poly1305 is 41. Linux `SO_REUSEPORT` is not the FreeBSD load-balancing option. The heading stays unmarked. |
| OpenBSD | `pledge` / `unveil` ran on OpenBSD 7.9 (`kern.osrelease=7.9`): `GAP-X3 openbsd pledge result=ok errno=0`, with `/etc`, `/usr`, `/var`, and `/tmp` present | The armor CLI applies none (section 12). The daemon unveils `/etc` r, `/usr` r, `/var` rwc, `/tmp` rwc, then pledges `stdio rpath wpath cpath inet dns`. Off OpenBSD this is `MissingOp` before either call. The heading stays unmarked. |
| Windows | On Windows 11 22H2 WinPE build 22621.525, `dequeueRegistered` called the table `Iocp.open` had loaded. Twice: `GAP-X3 windows rio dequeue=1 bytes=4 status=0` with `GUEST_EXIT:0`, and the same runs submitted `GAP-X1 windows iocp submitted=6`. `ioctlsocket(FIONBIO)` on the registered socket returned 10045 (`WSAEOPNOTSUPP`); that socket connects on a second thread | GUID `8509e081-96dd-4005-b165-9e2ee8c79e3f`, SIO `0xC8000024`, flags `WSA_FLAG_OVERLAPPED` \| `WSA_FLAG_REGISTERED_IO`. A short or null table is `MissingOp` and the completion port is closed. The dequeue is `RIOSend` plus `RIODequeueCompletion` of four bytes, then the accepted socket reads those bytes. IOCP recv and send stay `IOCTL_AFD_RECEIVE` (`0x12017`) and `IOCTL_AFD_SEND` (`0x1201F`). No kTLS claim. The heading stays unmarked. |

**Explicitly out,** even if a benchmark post suggests them: XDP / AF_XDP, BPF
as a firewall, `IP_TRANSPARENT` / `TPROXY`, `SCHED_FIFO`, `TCP_CORK`, and
`IORING_REGISTER_BUFFERS` for IRC payloads. Multishot recv and provided buffer
rings wait for a Helix ownership design of their own; they rewrite which thread
may touch a buffer the successor might inherit.

### GAP-X4 — Per-OS benchmarks

**Size M.** `zig build bench` and `zig build bench-live` exist
(`docs/audit/bench-baseline-0.7.0-rc.1.md`, `bench-live-0.7.0-rc.1.md`). They
are Linux numbers. SQPOLL is on in production without a published before/after
in the release record.

**Accept:** one table, Linux first, with and without SQPOLL, TLS on and off,
one shard and four, JOIN+PRIVMSG RTT and RSS. Non-Linux rows appear when
GAP-X1 can run the same recipe. No number without the command that produced it.

### GAP-X5 — Hot path cost, measured

**Size M.** `ConnState` size, channel fan-out, and cross-shard `DeliverBuf`
are called out in the Q4 performance track and are still unpaid. `command_usage`
counts invocations and bytes (`STATS m`) and does not record time.

**Accept:** a bench names the bytes per connection and the microseconds per
fan-out recipient before and after any shrink. A shrink that changes the Helix
client capsule is a version bump, not a silent layout edit.

---

## 10. Wave 7 — substrate that is waiting for a caller

Import these when a wave above needs them. Reimplementing them is the failure
mode.

| Module | Waiting for |
| --- | --- |
| `cron.zig` | GAP-P3 |
| `ddsketch.zig`, `hdr_histogram.zig`, `tdigest.zig` | GAP-O1 |
| `circuit_breaker.zig` | GAP-O7 |
| `gcra.zig`, `count_min_sketch.zig`, `topk.zig`, `admission.zig` | GAP-O6, GAP-P2 |
| `xor_filter.zig`, `cuckoo_filter.zig`, `bloom.zig` | GAP-O8 |
| `tracing.zig`, `qlog.zig` | GAP-O3 |
| `ice_agent.zig`, `pmtud.zig`, `turn.zig` | GAP-V2 |
| `raptorq.zig`, `reed_solomon.zig`, `media_epoch_key.zig` | GAP-V7 |
| `twcc.zig`, `bbr.zig`, `cc_cubic.zig` | GAP-V3, if the native ABR hint is not enough |
| `egwalker.zig`, `crdt_text.zig` | GAP-N1 (canvas), not before |
| `roaring.zig` | an unread-set or ACL set that is actually large |
| `sparse_merkle.zig` | only if anti-entropy outgrows the Merkle already in Undertow |
| `rendezvous_hash.zig` | GAP-N6 homing |
| `audit_trail.zig`, `oper_override.zig` | GAP-O10 / GAP-O9, or delete them if the live audit ring is the one that stays |
| Helix codecs with no kind: `memo_capsule`, `away_capsule`, `whowas_capsule`, and `ratelimit_capsule` are not maintained. `ban_capsule` stays for DST while live bans ride the world checkpoint. `CapsuleKind` is still 1 through 17 | GAP-D2, GAP-D3, GAP-D4. The second codec was removed. No new `CapsuleKind` was added |

`wal.zig` is not the missing store. OroStore already is a checksummed WAL plus
snapshot (default 16 MiB/record, 256 MiB WAL). The gap is which families are
actually written (GAP-D1…D6), not a second WAL.

---

## 11. Wave 8 — moonshots

Worth remembering. Not scheduled. Each one needs a design note before code,
because each one fights an invariant above.

| Id | Item | Why it waits |
| --- | --- | --- |
| GAP-N1 | Collaborative canvas / CRDT document inside a channel | `crdt_text` / `egwalker` are idle. Needs retention, authz, and a client. |
| GAP-N2 | Time-travel / deterministic replay of a room | Needs durable history (GAP-D1) and a recorded seed. `fault_loom.zig` is the tool, not the product. |
| GAP-N3 | Protocol bridges (other chat systems) | `media_bridge.zig` is an RTP header rewrap. A bridge is a new trust boundary. |
| GAP-N4 | Translation | No translator in tree. Captions are not a translation pipeline. Client-side, provenance-labeled, if it happens at all. |
| GAP-N5 | Autonomous mesh: discover peers, reweight links, heal with no oper | Peer lists are configured. GAP-O7 is the manual version. Autonomy that accepts a frame it should reject is a failure. |
| GAP-N6 | Geographic homing and adaptive shard move | `rendezvous_hash.zig` is idle. Moving a session across shards has to preserve the Helix and reactor-0 rules. |
| GAP-N7 | Read-replica history nodes and tiered storage | After GAP-D1 and GAP-P4. A replica that can answer `CHATHISTORY` without being a full mesh member. |
| GAP-N8 | Formal proof of CRDT merge laws | Property tests exist (`concord_props.zig`, `merkle_props.zig`, `ripple_props.zig`). A machine-checked proof is research. |
| GAP-N9 | Programmable rooms on OroWasm | The host, fuel, and one `message_pre_deliver` hook exist. Room-scoped apps with a permission prompt do not. |
| GAP-N10 | Edge nodes, connection hibernation, metadata-min transport | Capacity work after the two-node fleet is dull to operate. |
| GAP-N11 | Forum mode, RSVP events, bookmarks, digests | Product skins on GAP-P1 and GAP-D1. |
| GAP-N12 | Coverage-guided fuzzing as a CI job | Deterministic fuzz harnesses exist (`tls_fuzz.zig`). A corpus-growing fuzzer is not wired as a required gate. `zig build test-dst` exists and filters DST names; a campaign runner with an operator-supplied seed range is the remaining piece of the old "no dst step" item, which is stale. |
| GAP-N13 | Public `v0.7.0` tag and a reproducible artifact note | The fleet runs `ae78d490`. No GitHub tag is recorded. Tagging is a release act, not a feature, and it waits on a human. |

---

## 12. Cuts (do not build)

| Cut | Reason |
| --- | --- |
| `armor enc` openssl-compatible format | AEAD substrate only. Exit 3 stays. |
| TURN relay allocation | No sockets and no auth secret. `MEDIA TURN` fails `TURN_CUT`. `substrate/turn.zig` stays framing-only. |
| ECH with HelloRetryRequest | An accepted ECH inner that needs a retry fails `EchHrrUnsupported`. An ECH client fails `HelloRetryRequestUnsupported`. No ClientHello2 re-seal. |
| AES-GCM HPKE for ECH | `hpke.aead_id` stays ChaCha20-Poly1305 `0x0003`. Any other AEAD fails `UnsupportedEchSuite`. |
| x448, P-384, and P-521 key shares | The ClientHello offers X25519, P-256, and X25519MLKEM768 only. P-384 ECDSA certificate verify stays. |
| AES-CCM cipher suites | Named, and `isAllowed` is false. No caller. |
| brotli and zstd certificate compression | `pickSupported` returns zlib only. |
| `armor s_server` | Exit 3. No standalone listener socket. |
| `armor s_client -connect` | `run` returns `NotImplemented` after the client is built. `handshakeInMemory` stays. |
| In-daemon CRL and CT fetch | Callers pass DER. `require_crl` defaults false and `require_sct` defaults 0. No CDP or CT URL fetch. |
| `enforce_cert_signature_algorithms` on by default | The default stays off. The chain check runs only when the flag is set. |
| BoGo beyond the pinned 24/3 lane | `DisabledTests` names a reason per entry. A missing BoringSSL checkout is not a pass. |
| Delegated-credential mint and rotation | A presented credential is verified. Nothing mints or rotates one. |
| CLI Landlock, seccomp, pledge, and unveil | The armor CLI applies none. Daemon Linux landlock and seccomp stay on the GAP-X3 path. pledge and unveil are absent. |
| Full DTLS listener for IRC | Media-plane DTLS-SRTP is the DTLS this daemon has. |
| PQ hybrid certificates of our own design | 1.x stays verify-only. No private hybrid profile (GAP-K5). |
| Adopting `substrate/io/ring.zig` as the server | Unfinished, and it is not the live ring. |
| Multishot recv, buf rings, `send_zc` inside 0.8 | Helix buffer ownership. Separate project after GAP-X1. |
| XDP, BPF firewall, TPROXY, `SCHED_FIFO` | Not the IRC problem. |
| WEBIRC, identd, STARTTLS | Clean-room exclusions in the Codex contract. |
| Services as fake pseudoclient users | Services are real commands. |
| In-daemon CT-log gossip behaving as a CA | Operator-supplied pins, or GAP-K6's fetch, nothing smarter. |
| A second flood guard | `flood_guard.zig` replaced the earlier three. Extend it with GAP-D4's account axis. |
| A second WAL beside OroStore | GAP-D* writes the families. |
| Competitive clones of another network's bridge protocol | GAP-N3 if ever, from our wire, not from theirs. |

---

## 13. Order

The waves are the order. Inside a wave, the first slice is the one whose accept
fits in one focused `zig build test-*` plus a named new test.

| When | Ids | Why this order |
| --- | --- | --- |
| Now | GAP-V1, GAP-A5, GAP-A6, GAP-A8 | Live flags and live kernel behavior. Validation or an honest off-switch. |
| Next | GAP-D1, GAP-D2, GAP-D3, GAP-D5 | Users already use history, memos, gags, vhosts, and account recovery. |
| Then | GAP-A9, GAP-A10, GAP-A11 | One account directory, no false quit on a 90s lease, and an honest failure detector. A9 is the long one. |
| Then | GAP-A2 | Flip authoring only after a DST, then on the fleet with a human. State whether power loss may drop the tail. |
| Then | GAP-O1, GAP-O2, GAP-O4 | So the fleet flip is visible. |
| Then | GAP-A1 | OCG2 project is the long authority arc. Observe stays until the accept exists. |
| With the first slices | GAP-P0a, GAP-P16 | `005` already lies about history and IRCX modes. Read markers are the bouncer's memory. |
| Then | GAP-P0b, GAP-P0c, GAP-P2, GAP-P4, GAP-O6 | SASL 2FA, WHOIS/LISTX honesty, slowmode, retention, raid shield. |
| Parallel, one owner | GAP-X2 step 1, then GAP-X1 | Portability starts at the ring seam, not at a Windows `#ifdef` in the monolith. |
| Later | Wave 4 rest, Wave 5, Wave 8 | Calls beyond the browser proof, fortress, moonshots. |

Human-only, whenever a slice is actually deployed: Helix `USR2` when the image
token allows, cold restart one node at a time otherwise, GitHub push last.
This roadmap does not authorize a deploy.

FreeBSD 14.5-RELEASE-p1 executed the shipped kqueue submit
(`GAP-X1 freebsd kqueue submitted=6 errno=0`) and kernel TLS
(`GAP-X3 freebsd ktls result=ok errno=0` with `kern.ipc.tls.enable=1`).
OpenBSD 7.9 executed the shipped kqueue accept and recv twice
(`GAP-X1 openbsd kqueue submitted=1 accepted=6 bytes=8 errno=0`) and the
shipped pledge (`GAP-X3 openbsd pledge result=ok errno=0`). Windows 11 22H2
WinPE, build 22621.525, executed the shipped IOCP submit twice
(`GAP-X1 windows iocp submitted=6`, `GUEST_EXIT:0`) and dequeued Registered I/O
twice (`GAP-X3 windows rio dequeue=1 bytes=4 status=0`) through the table
`Iocp.open` loaded. Those same kernels later answered process `PING`/`PONG`: FreeBSD
kqueue `0.7.0+ddf11915`, OpenBSD kqueue `0.7.0+ddf11915`, and Windows IOCP
`0.7.0+d4ea0097`. NetBSD and DragonFly are out of scope. The live `IDENTIFY`
sentence (eshmaki.me / ircx.us) and the live `relay_v2_authoring=active` flip
stay unmet. Wine is not a Windows kernel, and commit `838ee337` does not close
GAP-X3. Headings stay unmarked, and the roadmap stays open.

### First three slices a worker can pick up

1. **GAP-V1 decision record and, if the browser test fails, the config hold.**
   Smallest live risk. Files: media docs, and `dtls13` only if the hold becomes
   a code default. Do not weaken the 1.2 path.
2. **GAP-A5.** Make `--check-config` reject `sqpoll` plus `defer_taskrun` on
   the combination the live kernel rejects, with a test. Files:
   `config_format.zig` / `config_boot.zig` and the ring probe. One owner.
3. **GAP-P0a.** Advertise `CHATHISTORY` and the IRCX modes the daemon already
   enforces, from the same tables the handlers use. One `005` test. Highest
   user-visible fix that does not need a new store.
4. **GAP-D2.** Persist `MemoBox` through OroStore `.props` or a real capsule
   kind, with a USR2 test and a cold-restart test. Leaves `server.zig` to the
   integrator for the boot hook only. Read markers (GAP-P16) are the same
   shape and can follow in the same capsule pass.

---

## 14. Documents that are stale on purpose of this audit

| Document | What to believe instead |
| --- | --- |
| `docs/research/tls-feature-gaps.md` (2026-07-11) | EMS is implemented and required. `armor ocsp` / `crl` exist. The KX and PQ-sign rows in GAP-K6 are the part that is still true. |
| `docs/design/e2ee-everywhere-blueprint.md` header "blueprint, not an implementation" | The *MLS content* design is still a blueprint. The *control-plane* authority is in tree and on by default. |
| `docs/design/account-attribution-blueprint.md` "all a follow-up" | The prop-based design was superseded in `residenceTrusted`: only a negotiated `SESSION_REPLICA_V2` proof for a live local attachment returns `trusted`. Identity props are replicated and are not authority. The product accept (two devices, one nick, every node) is GAP-A3. The account *database* is still per-node (GAP-A9). |
| Glossary / architecture "Ripple decides who is dead" | `S2sPeer.tick` is not on the daemon timer. Live liveness is ping plus the direct-link partition detector, and membership repair is a ~30s world re-burst (GAP-A11). |
| `docs/ROADMAP-2026-Q4.md` S-03 "spine is node-local" | `docs/design/event-spine-mesh-v2.md` says the mesh path shipped. Residual is GAP-A4 (disk) and the client console. |
| Q4 S-06 "no server search" | `SEARCH` is registered and handled. Residual is GAP-P5 and GAP-D1. |
| Q4 S-12 still open as P0 | Group control activation is recorded as live. Residual is GAP-K1 in the client. |
| Q4 S-15 "no `zig build dst`" | `build.zig` has `test-dst`. Residual is GAP-N12's seed-range campaign. |
| Q4 S-19 session continuity as future work | The session blueprint's status is implemented. Residuals are GAP-A3 and GAP-D*. |
| Q4 S-21 as if the codec were missing | The codec and the admit transaction exist. Residual is GAP-A2. |
| Q4 S-23 "delegated OCSP responders are a follow-up" | TLS roadmap execution log marks delegated responders done. Residual is CDP fetch and GAP-A8. |
| `docs/features/GAME-CHANGERS-50.md` GS-12 "need a WAL" | OroStore is the WAL. |
| Same file, "search needs a new verb" | Corrected in that file's own preface. Mesh federation is GAP-P5. |
| `docs/architecture/00-overview.md` exploit-suite paragraph "not shipped behavior" | `zig build test-exploit` exists and the 0.7 record says 158/158 classified. The `src/security/exploit/` tree from the blueprint still does not. The gate is the test filter. |
| Invented-features catalog "confirmed absent" | Still absent: slowmode, thread objects, scheduled messages, human-verification challenges, bridges, translation, appeals, retention, per-account abuse score, outbound webhooks, histogram export. Present now: local search, local ProofMark, node-local KEYTRANS, Web Push, inbound webhooks, and session-replica nick trust (GAP-A3). |

---

## 15. Cross-repo contracts that block a user-visible close

Server ships first for each of these. The client repo is `/home/kain/onyx`.

| Server gap | Client work it unblocks |
| --- | --- |
| GAP-A3 / GAP-A9 | One nick for two devices, and `IDENTIFY` of the same account on either node |
| GAP-P0a / GAP-P0b | Clients that trust `005`, and 2FA that can finish inside SASL |
| GAP-P16 | Bouncer unread state that survives upgrade and node move |
| GAP-K1 | Group E2EE room setup, member list, rekey on remove |
| GAP-K2 | Trust center that verifies a device against the log |
| GAP-P0c / GAP-P11 | LISTX browser, MODEX names, WHISPER compose, auditorium roster |
| GAP-P5 | Search that is more than the local vault |
| GAP-O1 / GAP-O2 | Oper desk mesh page |
| GAP-V2 | A browser call button that does not require the native codec |
| GAP-D1 / GAP-P4 | Vault retention that matches the server instead of fighting it |

Capability and token additions stay server-first. A client-only reinterpretation
of an existing tag can ship client-first.

---

## 16. Audit findings (2026-09-29)

Recorded from the Armor TLS audit and the mesh scale audit. These ids are not
in the section 13 order. The AEAD stream counter wrap is already fixed and is
not restated here. None of the Armor rows below are fixed in the tree this
section was written against.

### GAP-K8 — HelloRetryRequest PSK binder covers the wrong transcript

**Size M.** `tls_server.zig` `verifyPskBinderT` hashes only the truncated
ClientHello. After HelloRetryRequest the client binder
(`tls_client.zig`, the PSK binder transcript) is
`message_hash(ClientHello1) || HRR || truncated ClientHello2`. A valid binder
fails, `tryAcceptPsk` returns null, and the server continues a certificate
handshake instead of aborting (RFC 8446 §4.2.11.2) or resuming. A binder that
omits the retry transcript is the one the server accepts.

**Accept:** an HRR resumption with a correct binder resumes, and a binder that
omits ClientHello1 or the HelloRetryRequest is rejected. A regression drives
the shipped server and client functions.

### GAP-K9 — EndOfEarlyData is not in the handshake transcript

**Size M.** `processAcceptedEarlyRecords` requires `EndOfEarlyData` and then
sets `early_data_done` without appending it. The client emits the message in
`start` and also never appends it before `writeClientFinishedRecord` or the
resumption master secret. RFC 8446 §4.4.1 places that message after the server
Finished and before the client Finished.

**Accept:** accepted 0-RTT puts `EndOfEarlyData` on both transcripts. The
client Finished and the resumption PSK cover it. A transcript that differs
only by that message fails Finished verification.

### GAP-K10 — 0-RTT is accepted again when nothing records the binder

**Size M.** When `replay_guard` is null, the 0-RTT check sets `replay_ok` to
true (`tls_server.zig`, the early-data branch in ClientHello). `ticketAgeWithinWindow`
returns fresh when `ticket_age_add` is missing or `issued_unix_ms` is 0, and
the age check does not run when `now_unix_seconds` is null. `max_early_data_size`
defaults to 0; once a ticket advertises early data, this branch still accepts.

**Accept:** with early data enabled, a second copy of the same 0-RTT flight is
rejected when no `ReplayGuard` is installed, when the ticket has no age add or
no issue time, and when no clock is set. 1-RTT resumption of an unexpired
ticket still completes.

### GAP-K11 — Trust-anchor constraints never bind the path

**Size M.** `verifyChainToTrustAnchors` (`tls_client.zig`) enforces CA,
`keyCertSign`, name constraints, and path length only for certificates inside
the presented chain. On a DN and signature match it returns without reading
the anchor's name constraints or `pathLenConstraint`. RFC 5280 initializes
both from the trust anchor, which a normal TLS chain omits. In-chain
`enforceNameConstraints` is called with the leaf only, so an intermediate's
own dNSName is not checked against the CA that constrained it.

**Accept:** a name-constrained or pathLen-0 anchor rejects a leaf outside the
constraint and a non-self-issued intermediate the path length forbids, even
when the anchor is not resent in the chain. An intermediate whose own dNSName
falls outside its issuer's permitted subtree, or inside an excluded subtree,
is rejected. The same chain still verifies when every certificate is inside
the constraints.

### GAP-K12 — A leaf that forbids digitalSignature still verifies

**Size S.** The leaf check in `verifyChainToTrustAnchors` stops at EKU
`serverAuth`. When `keyUsage` is present and `digitalSignature` is clear,
verification continues. An issuer in the chain is already rejected when
`keyCertSign` is clear.

**Accept:** a leaf whose `keyUsage` omits `digitalSignature` fails before
CertificateVerify. A leaf with no `keyUsage` extension, and a leaf that sets
the bit, still verifies.

### GAP-K13 — Application traffic sequence numbers wrap

**Size M.** Server `app_write_seq` / `app_read_seq` and the client counterparts
are bare `u64` increments. `Seq64.next` in `tls.zig` refuses to emit the
maximum so a nonce cannot wrap, and these seal/open paths do not call it. The
shipping daemon is built ReleaseFast, which does not trap the overflow.

**Accept:** the record after `2^64 - 1` under one application traffic key
fails closed on both the client and the server. Nonce 0 is not reused. A
regression calls the shipped seal or open path, not a copied counter.

### GAP-K14 — Critical CRL and SCT extensions are treated as understood

**Size S.** `extensionOidIsSupported` in `x509.zig` returns true for
`cRLDistributionPoints` (2.5.29.31) and the CT SCT list
(1.3.6.1.4.1.11129.2.4.2). `parseExtensions` does not interpret either OID and
does not mark it handled, so `rejectUnsupportedCriticalExtension` does not
fire. RFC 5280 §4.2 requires a verifier that does not process a critical
extension to reject the certificate.

**Accept:** a critical CRL distribution point or a critical embedded SCT list
fails closed. A non-critical copy of either extension may still be ignored.
This does not turn on live CRL or CT fetch (GAP-K6).

### GAP-K15 — An IP literal matches a DNS name

**Size M.** `dnsNameMatchesCert` compares `server_name` only to `san_dns`.
`dnsPatternMatches` treats a left-most `*.` label as one DNS label and does
not reject an address. `san_ips` is parsed in `x509.zig` and then ignored.
RFC 9525: an IP verify name matches an `iPAddress` SAN only.

**Accept:** `1.2.3.4` does not match a dNSName of that text or `*.2.3.4`. It
matches an `iPAddress` SAN of that address. A DNS name still matches `san_dns`,
including a single-label wildcard, and still does not match an `iPAddress`.

### GAP-K16 — The client offers a ticket past its lifetime

**Size S.** A stored ticket is offered, and may carry 0-RTT, with no check
that `ticket_age_ms` is within `ticket_lifetime` (seconds) or the 7-day cap.
`ResumeOffer.ticket_lifetime` is stored and not read on the offer path
(`tls_client.zig`).

**Accept:** a ticket older than its advertised lifetime, or older than seven
days, is not offered and is not used for early data. A ticket inside both
bounds is still offered.

### GAP-K17 — Ticket lifetime is the current config, and missing issue times never expire

**Size S.** `tryAcceptPsk` enforces lifetime only when a clock is set and
`issued_unix_ms` truncates to a non-zero second count. The window is
`effectiveTicketLifetimeSeconds` of the accepting node's current
`ticket_lifetime_seconds`. The lifetime advertised when the ticket was minted
is not sealed in the ticket.

**Accept:** a ticket minted with no issue time is rejected once a clock is
configured. Lengthening `ticket_lifetime_seconds`, or opening the ticket on a
peer with a longer config and the same ticket key, does not keep the PSK
alive past the lifetime that was advertised at mint. A ticket inside that
sealed lifetime still resumes.

### GAP-K18 — Turning 0-RTT off does not bind tickets already sealed with a limit

**Size S.** The 0-RTT gate reads the sealed ticket's `max_early_data_size`
(`accepted_early_data_limit`), not `config.max_early_data_size`. The config
comment says zero disables acceptance. The accept path does not read that
field. New tickets are sealed from the config; old tickets are not.

**Accept:** `max_early_data_size = 0` refuses early data for every ticket,
including one sealed earlier with a positive limit and one sealed by another
node that shares the ticket key. A non-zero config still accepts early data
only up to the smaller of the config and the sealed limit.

### GAP-M1 — A version vector refuses the 65th replica

**Size M.** `VersionVector.max_entries` is 64. `increment` returns
`error.CapacityExceeded` at the 65th replica (`clock.zig`). `member_compact.max_context`
is the same 64 and rejects a larger context as `Oversize`. The vector is a
value type: callers copy it and read `entries` directly, and several size
wire buffers from `max_entries`. Growing the two files alone leaves those
callers wrong. The mesh scale audit did not own this pair; the Codex lane
confirmed the ceiling and made no edit.

**Accept:** 65 replicas merge and round-trip through `member_compact` without
`CapacityExceeded` or `Oversize`. Callers that copy a vector or size a buffer
from the entry count still build. A gossip sample size of 64 that still stores
every member is not this item.

### GAP-M2 — Mesh ceilings the scale audit did not confirm

**Size S.** Three candidates were reported and the confirm pass rejected all
three as a hard lock at 64.

| Candidate | What the code does | Why confirm rejected it |
| --- | --- | --- |
| `route_table.zig` `addMember` | The 65th distinct node returns `error.ChannelFanoutFull` when `len == nodes.len`. `nodes.len` is `Config.max_nodes_per_channel` (default 64). | TOML admits `4..4096`. A config above 64 inserts the 65th node. |
| `membership_view.zig` `add passiveEntry` | At `passive_capacity` the next distinct node overwrites `passive[rng.index]` and the previous node leaves the view. Default capacity 64. | `mesh.gossip.view_passive_capacity` admits `active+1..4096`. |
| `gossip_views.zig` `add passive` | Same overwrite at `passive_max` (default 64). | `passive_view_max=128` is accepted. |

Gossip rounds, the server registry, mesh topology, and the partition detector
produced no finding in that pass. `server_registry` already defaults to 512.

**Accept:** leave these three alone unless a test shows a path that still
refuses or overwrites at 64 after the operator ceiling is raised above 64.
Do not replace the partition detector's adjacency matrix under this id. The
drop-on-full behavior of a full passive view, at whatever capacity is
configured, stays the view's eviction rule.
