<!-- SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com> -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Multi-reactor timer-guard audit — 0.7

**Status:** complete, 4 P0 fixes open · **Author:** onyx-server-mesh · **Date:** 2026-09-01
**Base:** `main` at `c221033` — **every `file:line` below was resolved against `git show HEAD:…`,
not the working tree.** The tree was dirty with concurrent Wave 1 work (`server.zig` +142,
`registry.zig` +201, `s2s_frame.zig` +9, `tls_*.zig`) while this audit ran, and those insertions
shift working-tree line numbers by up to 24 past `server.zig:20774`. Re-resolve before quoting.

**Deliverable for:** [`../releases/0.7-RELEASE-PLAN.md`](../releases/0.7-RELEASE-PLAN.md). *That plan
was revised while this audit ran*; against the current revision this document is the enumeration
feedstock for **[P0-3 — ≥2-reactor DST over the timer guards](../releases/0.7-RELEASE-PLAN.md#p0--must-land-before-070)**
(owners onyx-server-dst + onyx-server-reactor, dispatched as **W1-2**), and the standing evidence for
**[R-5](../releases/0.7-RELEASE-PLAN.md#9-risks-severity-tagged)**: *"multi-reactor timer guards pass
vacuously at `count == 1`, so a dropped or inverted guard reproduces the roster-decay bug with the
entire suite green."*

P0-3 scopes itself to "the ~30 `rx() == &reactors[0]` guard sites." **§2.1 below names 29 of them
individually** — that is the list the DST must exercise. It also names **two functions the estimate
misses** ([P0-TG-2](#p0-tg-2)), which are guarded only by their call site and so are invisible to a
grep for the guard expression. Per [§7](../releases/0.7-RELEASE-PLAN.md#7-dependency-graph-and-build-order),
P0-3 sits in Phase 3 — "widen the ceiling" — which is exactly the phase that converts every latent
gap here into a live one.

**Scope:** every periodic timer and maintenance callback in the daemon. **Read-only** — this
document changes no code. The one code change permitted by the task is a cross-link line added to
the release plan.

**Totals: 46 periodic tasks audited · 4 P0 fixes.**

---

## 1. Why the guard exists

`[limits].num_shards` defaults to **1** (`src/daemon/server.zig:1902`) and clamps to
`[1, shard_mod.max_shards]` (`server.zig:4266-4270`). At one shard every guard question is moot.
Above one shard, three facts combine:

1. **The timer is per-reactor.** `armTimer` keeps exactly one `submitTimeout` in flight *per
   reactor ring* (`server.zig:6072-6078`), so `onTimerTick` (`server.zig:6170`) fires on **every
   reactor thread** on the `[limits].sweep_interval_ms` cadence — N shards means N concurrent
   ticks.
2. **Reactors own disjoint client tables, but share everything else.** `self.rx()` resolves the
   calling thread's reactor (`server.zig:4253-4255`); `rx().clients` is reactor-local, while the
   `World`, the mesh route table, every `last_*_ms` throttle counter, and the published stats
   tables are single shared instances.
3. **S2S peer links live only on `reactors[0]`.** Every mesh maintenance task therefore has real
   work to do on exactly one reactor and nothing to do on the others.

The failure that follows is not a data race — `onCompletion` takes `world.lockWrite` once around
the whole completion (`server.zig:4257-4266`), so ticks serialize. It is **guard theft**: a
sibling reactor that holds no peer links *consumes a shared throttle counter while doing zero
work*, starving reactor 0's real work below its intended cadence. This shipped once already as
the roster-decay netsplit — the receiver stopped seeing membership re-affirmation inside
`stale_member_ttl_ms` and reaped every live peer-homed member, producing empty `NAMES`, a missing
remote-oper prefix, and `401` on cross-node `PRIVMSG`. The recovery is in `d86e1f0` and `744360e`,
and the reasoning is preserved as a load-bearing comment block at `server.zig:6239-6252`.

**The rule.** When a periodic task touches peer links or a shared counter, **both the work and the
counter-advance gate on `self.rx() == &self.reactors[0]`.** Never advance a shared guard on a
reactor that performs no work. The membership resync (`server.zig:6284-6295`) and the oper-grant
refresh (`server.zig:6264-6267`) are the reference implementations: the `if` on the counter sits
*inside* the reactor-0 block, not beside it.

### 1.1 The guard is weaker than it looks

`current_reactor` is a `threadlocal` initialised to `null` (`server.zig:3245`), and `rx()` falls
back to `&self.reactors[0]` when it is unset (`server.zig:4253-4255`). Therefore
`self.rx() == &self.reactors[0]` reads **true on any thread that never entered a reactor loop** —
a background worker, a test helper, or a future off-reactor completion callback. The guard proves
"I am reactor 0's thread *or* I am not a reactor thread at all," which is not the same claim. See
[P0-TG-4](#p0-tg-4).

---

## 2. Class A — the reactor timer (`onTimerTick`, `server.zig:6170-6303`)

Fires on **every reactor**, once per `sweep_interval_ms`. 43 distinct maintenance tasks.

### 2.1 Reactor-0 gated — correct today (29 tasks)

For every row below, the failure mode **if the guard were removed** is stated; all are currently
guarded. `call-site` = gated by an `if` in `onTimerTick`; `internal` = the function's own first
statement; `both` = defence in depth.

| # | Task | HEAD line | Guard | Failure mode at N>1 without it |
| --- | --- | --- | --- | --- |
| A1 | USR2 upgrade poll → `deferUpgrade(.signal)` | `6187-6189` | call-site | `upgrade_signal_requested.swap` consumed by a reactor that owns neither the listener nor the carried connections — one `SIGUSR2` produces a partial or failed upgrade instead of one zero-drop handoff. |
| A2 | `maybeReloadAcmeTls` | `6190` → `48520` | call-site | Live `config.tls_*` swapped from a reactor whose siblings are mid-handshake; see [P0-TG-3](#p0-tg-3). |
| A3 | `maybeSwapOcspStaple` | `6191` → `48505` | call-site + atomic | Staple generation rotated and freed off the owning reactor; see [P0-TG-3](#p0-tg-3). |
| A4 | `nick_delay.sweep` | `6202` | call-site | Shared nick-delay holds evicted concurrently with `hold`/`check`/`release` under the same world lock — a released nick becomes claimable in a window the reservation was meant to cover. |
| A5 | `tickOcg2Runtime` | `6205` → `6143-6144` | **both** | The OCG2 observer's monotonic-origin seam is per-reactor; a sibling tick would compare `nowU64()` against another thread's primed origin and trip `failMonotonicRollback` — a one-way terminal authority failure. |
| A6 | `conn_throttle.prune` | `6206` | call-site | Per-IP throttle state pruned N× per interval; a decayed entry is evicted before its window closes, weakening connection throttling. |
| A7 | `login_throttle.sweep` | `6208` | call-site | Same shape for login throttling — records evicted to floor early, softening brute-force resistance. |
| A8 | `pending_migrations.sweep` | `6215` | call-site | Staged cross-mesh migration capsules aged against the wrong tick, so a capsule can outlive the mesh reclaim token that is its only consumer. |
| A9 | `sweepSessionReplicaStore` | `6216` | call-site | Destructive Store expiry driven from a reactor that cannot reach the retry key snapshot; the last retry key can disappear under OOM. |
| A10 | `retryDeferredRelayV2` | `6217` | call-site | Relay v2 retry duplicated across shards. |
| A11 | `retryRelayV2Outbox` | `6218` | call-site | Outbox drained N× — duplicate relay egress. |
| A12 | `retryE2eeGroupCustody` | `6219` | call-site | E2EE group custody re-driven concurrently; exact-once replay metadata is the invariant at risk. |
| A13 | `access.pruneExpired` | `6226` | call-site | IRCX ACCESS reclaim races the JOIN gate that matches on any shard. |
| A14 | `sweepMeshAutoConnect` | `6229` → `29340-29342` | **internal** | `mesh_dial_cursor` / `mesh_boot_remaining` advanced by a reactor that cannot open a peer link — the rotating dial cursor walks past every configured `[mesh].connect` peer without dialling, so a dropped link is never re-dialled. |
| A15 | `maybeProbeMeshPeerRtt` | `6233` → `49232` | call-site **only** | **See [P0-TG-2](#p0-tg-2).** `last_peer_rtt_probe_ms` is advanced at `49236` *before* iterating `rx().clients.slots` at `49238` — textbook guard theft: RTT probing stops entirely while the counter keeps moving. |
| A16 | `publishPeerCount` | `6238` → `49072` | call-site **only** | **See [P0-TG-2](#p0-tg-2).** Iterates `rx().clients` at `49079` and then *overwrites* the shared `mesh_peer_names` / `mesh_peer_node_ids` / `mesh_peer_public_keys` tables — a sibling reactor publishes zero peers, wiping mesh identity for every shard's `LUSERS`/`MESH` read. |
| A17 | Oper-grant refresh → `rebroadcastLocalOpers` | `6264-6267` | call-site, counter **inside** | Minted grants expire after `oper_grant_ttl_ms`; a stolen guard means no re-mint, so a still-logged-in oper's `*` prefix decays on every peer. **Reference implementation.** |
| A18 | `refreshPortableSessionReplicasV2` | `6268-6273` | call-site, counter inside | Portable session replicas go stale; resume after a shard move fails. |
| A19 | `refreshAttachedSessionReplicaLeases` | `6274-6283` | call-site, counter inside | Attachment leases lapse unrenewed → false-offline window for an attached session. |
| A20 | Membership resync → `resyncMeshStateToPeers` | `6284-6286` | call-site, counter inside | **The paid-for bug.** Re-burst starved below `membership_resync_interval_ms` → receiver reaps live peer-homed members → empty `NAMES`, missing remote-oper prefix, `401` on cross-node `PRIVMSG`. **Reference implementation.** |
| A21 | Stale-member reap → `pruneStaleMeshMembers` | `6294` | call-site, same counter | Additive anti-entropy never reaps a remote member whose `PART`/`QUIT` was lost → permanently lingering ghosts in every peer's `RouteTable`. |
| A22 | `retryDirtySessionReplicaTokens` | `6296` | call-site | Dirty replica tokens retried from a shard that does not own them. |
| A23 | `retryDirtySessionReplicaProjections` | `6297` | call-site | As above for projections. |
| A24 | `retrySessionReplicaStoreStages` | `6298` | call-site | Staged Store writes retried N×. |
| A25 | `resumeSessionReplicaReplays` | `6299` | call-site | Replay resumed concurrently — the exact-once replay guarantee is what breaks. |
| A26 | `retryOrphanedLocalSessionReplicaRevokes` | `6300` | call-site | Orphaned revokes retried N×. |
| A27 | `retryWebhookResumeIfPending` | `6180` → `5258-5259` | **internal** | `webhook_resume_pending` consumed off reactor 0, whose delivery path routes cross-shard via `deliverTagged`; post-upgrade webhook resume silently no-ops. |
| A28 | Event-history snapshot → `saveEventHistory` | `6517-6521` | call-site, counter inside | The event ring is shared; N reactors would race N redundant `tmp+rename` snapshots of the same target. |
| A29 | `event_collapse.flush` | `6527-6541` | call-site | Flood-collapse summaries are published at `>= warn` to bypass the collapser; N reactors emit N duplicate summaries per window. |

### 2.2 Reactor-local by design — correct on every reactor (7 tasks)

These *must* run on every reactor. Each is scoped to `rx().clients` or filters by `shard_id`, so
running them only on reactor 0 would be the bug.

| # | Task | HEAD line | Scoping proof |
| --- | --- | --- | --- |
| B1 | `abortPoisonedDeliveries` | `6178` → `9704`, `9711-9715` | Walks `rx().clients.slots` only. A poisoned delivery is a stream-integrity failure on *this* shard's connection. |
| B2 | `drainAttachmentSpoolForCurrentReactor` | `6179` → `10229-10248` | Shared spool under `attachment_delivery_mu`, but `10236` skips any record whose `id.shard != rx().shard_id`. Name states the contract. |
| B3 | `retryFailedSessionHandoffs` | `6192` → `6309-6312` | Iterates `rx().clients.slots`; slot storage is stable while iterating. |
| B4 | `sweepTimeouts` | `6193` → `7107-7109` | Registration/idle/ping timeouts against `rx().clients`. |
| B5 | `sweepDeferredSessionAutojoins` | `6194` → `24026-24039` | Deferred E2EE resume autojoin against `rx().clients`. |
| B6 | `retryDirtyLocalChannelProjections` | `6199` → `23850-23864` | Shared dirty queue, but `projectLocalChannelProjection` is owner-reactor scoped and foreign rows stay a verification barrier. Deliberately every-reactor so a shard-1+ attachment cannot leave the shared journal (and the UPGRADE preflight) dirty forever — documented at `6195-6198`. |
| B7 | `access.now_seconds` refresh | `6225` | Idempotent same-value write of a clock field, deliberately on every reactor because a JOIN gate may match on any shard. Only the *reclaim* half (A13) is reactor-0 gated. |

### 2.3 Reactor-agnostic shared state — ungated, assessed (7 tasks)

These touch shared state from any reactor with **no** reactor-0 gate. Each was assessed
individually; two are safe by construction, one is safe by a shard-aware lookup, and one is a P0.

| # | Task | HEAD line | Verdict | Reasoning |
| --- | --- | --- | --- | --- |
| C1 | `sweepSessionDropTransactions` | `6174` → `40651-40681` | **Safe** | Mutates the shared `session_drop_journal` from any reactor, but the requester-liveness probe is `connFor` (`10081-10084`), which indexes `self.reactors[id.shard]` — **shard-aware**, so a precommit whose requester lives on shard 2 is not misread as `requester_gone` by reactor 0. Repeat visits are idempotent through the transaction state machine under the completion-wide world lock. |
| C2 | `sweepTempModes` | `6221` → `7065-7083` | **Safe** | Reads shared `temp_modes` and mutates shared `world` channel flags, but `broadcastChannel` (`10635-10653`) walks `world.memberIterator` and delivers via `deliverTimed` inside a `beginWakeBatch`/`endWakeBatch` pair that coalesces **cross-shard** wakes — so the `-<mode>` line reaches clients on every shard regardless of which reactor swept. `due()` + `sweep()` are atomic within one lock-held tick. |
| C3 | chanstats flush (`index.json` + `<slug>.json`) | `6457-6510` | **Low** | Shared throttle `chanstats_last_write_ms` (`6459-6460`); the reactor that advances the counter also does the whole flush, so there is no guard theft. All inputs are shared (`world`, `chanstats`, `meshUserCount`, `globalMemberCount`), so any reactor produces the same bytes. Serialized against the `recordHistory*` feed by the completion-wide lock. |
| C4 | `writeStatusJson` | `6507` → `6860-6863` | **Safe** | `currentNodeHealth` (`6831-6852`) reads `peer_health.slots` plus the `partition_*` fields — server-level shared state, not reactor-local — so the status feed is identical from any reactor. |
| C5 | `maybeRunBackups` | `6511` → `6709-6710` | **Safe** | Internal reactor-0 guard *and* the `backup_last_write_ms` advance sits behind it (`6713-6716`). Correct pattern; listed here only because its call site is ungated. |
| C6 | `refreshMetricsSnapshot` | `6546-6553` → `4901-4908` | **Low** | Shared throttle `metrics_last_refresh_ms`; the advancing reactor does the work. Inputs are `self.stats` (atomics), `currentNodeHealth` (shared), and the E2EE group gauges — none reactor-local, so the `/metrics` snapshot is shard-independent. |
| C7 | **Web-stats render** (`[stats].web_dir`) | `6556-6607` | **P0** | Shared throttle at `6560-6561`, then the population loop at **`6573`** iterates **`self.rx().clients`** — reactor-local. See [P0-TG-1](#p0-tg-1). |

---

## 3. Class B — off-reactor periodic loops (3 tasks)

These are dedicated threads, not reactor ticks, so their cadence is **invariant in `num_shards`**.
They matter to this audit only through their hand-off into the reactor.

| # | Loop | Cadence | Hand-off | Guard posture |
| --- | --- | --- | --- | --- |
| D1 | OCSP staple scheduler — `ocsp_staple.zig:136`, `:154`, `:158` | `check_interval_ms`, default 15 min (`ocsp_staple.zig:42`) | Writes `ocsp_staple_incoming` under `ocsp_staple_lock`, then sets `ocsp_staple_pending` (`server.zig:48490-48493`) | Worker never touches listener state. Consumed by A3 on reactor 0. **Rotation/free is [P0-TG-3](#p0-tg-3).** |
| D2 | ACME renewal checker — `acme_renewal.zig:65`, `:86`, `:88` | `[acme].check_interval_ms` (`acme_renewal.zig:73`) | Sets `acme_reload_requested` (`server.zig:48480`) | Consumed by A2 on reactor 0. **Cert-generation free is [P0-TG-3](#p0-tg-3).** |
| D3 | Media plane pump — `media_plane.zig:240`, `:342` | Wakes every 250 ms via the socket recv timeout (`media_plane.zig:224`) so it can observe the stop flag | Sole owner of the DTLS terminator and the SRTCP crypto hub; off-thread RTCP egress is queued and drained on the pump (`media_plane.zig:392`), fingerprint table under `fp_mutex` (`:144-145`) | **No reactor guard needed or wanted** — one pump per plane, independent of shard count. Stop/join before the socket closes (`:327-334`). Verification item M-1 below. |

**Not periodic.** `webpush.zig`, `webhook_http.zig`, `mail_sender.zig`, `geo_services.zig`,
`rdns.zig`, `dnsbl_resolver.zig`, `metrics_http.zig`, `webtransport_listener.zig`,
`acme_http01_listener.zig`, and `native_media_transport.zig` all spawn threads, but their
`nanosleep` calls are backoff/yield inside request-driven work, not an interval timer. Only D1 and
D2 use an interval loop (`sleepInterruptible(check_interval_ms, …)`); only D3 uses a timed socket
wake. Excluded from the count.

---

## 4. P0 fixes

Four. This task is **audit-document only**, and the release plan independently forbids the fixes
landing now: *"**No task in Wave 1 may edit `src/daemon/server.zig`**"*
([§11 collision notes](../releases/0.7-RELEASE-PLAN.md#11-wave-1-dispatch-table)), because that file
is reserved for W1-0's downstream follow-up and already carries uncommitted working-tree changes.
Every fix below therefore lands **after Wave 1**, through whoever owns the `server.zig` slice then,
with the named agent driving the design and review.

<a id="p0-tg-1"></a>
### P0-TG-1 — Web-stats and `LUSERS` peaks count only one shard's clients

**Owner: onyx-server-reactor** (per-reactor client-table ownership) · **lands via zig-coder**
(`server.zig` slice) · **Severity: HIGH · Confidence: CONFIRMED**

`maybeWriteStats` clears its shared throttle at `server.zig:6560-6561`, then counts the population
by iterating `self.rx().clients.iterator()` at **`server.zig:6573`** — the *calling* reactor's
table. `clients`, `opers`, and the GeoIP country tally therefore describe one shard. That
undercount then escapes into shared, monotonic state:

- `stats_peak_clients` is raised from the shard-local figure (`server.zig:6592`);
- the sparkline ring `stats_history` is appended from it (`server.zig:6600-6602`);
- `stats_peak_clients` feeds **`LUSERS`** — `local_max` (255/265), `global_max` (251/266), and
  `RPL_STATSCONN` 250 `highest_connections` (`server.zig:6655`, `:34783-34788`).

At N shards the public status page and the country breakdown under-report the node by roughly
`(N-1)/N`, and because the peak is a high-water mark, **`LUSERS` reports a permanently wrong
all-time peak** that no later correct sample can repair. `@max(users, stats_peak_clients)` masks
the *current* figure only.

This is the exact class already fixed for `LINKS`, where the source comment records the lesson
verbatim: *"S2S peer links live ONLY on reactor 0; iterate it directly (under the world lock) so
LINKS finds every peer regardless of which shard answered this query — previously `self.rx()`
missed peers on shards 1..N"* (`server.zig:48905-48908`).

**Fix.** Iterate every reactor's table (`for (self.reactors) |*r| … r.clients.iterator()`) under
the world lock the completion already holds, exactly as `handleLinks` (`:48908`) and
`meshPeerLinkedByDial` (`:48968`) do. Gating the render to reactor 0 *without* widening the
iteration would keep the undercount and merely make it deterministic — the iteration is the fix,
not the guard.

**Accept.** A `num_shards = 2` test that registers clients on both shards and asserts the rendered
`clients` count and `stats_peak_clients` equal the node total, not the shard total.

<a id="p0-tg-2"></a>
### P0-TG-2 — `publishPeerCount` and `maybeProbeMeshPeerRtt` have no internal guard

**Owner: onyx-server-mesh** · **lands via zig-coder** (`server.zig` slice) ·
**Severity: HIGH (latent) · Confidence: CONFIRMED**

Both are mesh maintenance over `reactors[0]`-only peer links, and both are protected by **nothing
but their call site**:

- `publishPeerCount` (`server.zig:49072`) iterates `self.rx().clients` (`:49079`) and then
  **overwrites** the shared `mesh_peer_names` / `mesh_peer_name_lens` / `mesh_peer_node_ids` /
  `mesh_peer_public_keys` tables under `mesh_peer_identity_mu`, zero-filling the tail. Called from
  a non-zero reactor it publishes **zero peers**, erasing mesh peer identity for every shard's
  cross-shard `LUSERS`/`MESH` read until the next reactor-0 tick.
- `maybeProbeMeshPeerRtt` (`server.zig:49232`) advances `last_peer_rtt_probe_ms` at **`:49236`,
  before** iterating `rx().clients.slots` at `:49238`. That is guard theft in its purest form: the
  counter moves, no peer is probed, and `status.json`/`MESH` RTT goes stale indefinitely.

Contrast the four functions that carry their own guard as the first statement:
`sweepMeshAutoConnect` (`:29342`), `tickOcg2Runtime` (`:6144`), `retryWebhookResumeIfPending`
(`:5259`), `maybeRunBackups` (`:6710`). A6/A15/A16 are one refactor — moving a call, adding a
second caller, or a Wave 2 extraction of the tick — away from reproducing the roster-decay bug.

**Fix.** Add `if (self.rx() != &self.reactors[0]) return;` as the first statement of both, and
switch both iterations to `self.reactors[0].clients` (the `handleLinks` idiom) so correctness no
longer depends on *which thread* called. For `maybeProbeMeshPeerRtt`, keep the counter advance
after the guard.

**Accept.** Calling either directly with `current_reactor = &server.reactors[1]` at
`num_shards = 2` must leave `mesh_peer_names` and `last_peer_rtt_probe_ms` untouched. **These two
are the highest-value targets in [P0-3](../releases/0.7-RELEASE-PLAN.md#p0--must-land-before-070)'s
≥2-reactor DST**, precisely because they are the two that a grep for `rx() == &self.reactors[0]`
does not find.

<a id="p0-tg-3"></a>
### P0-TG-3 — One-generation deferred free of TLS/OCSP material is a single-reactor argument

**Owner: armor-tls** (with onyx-server-crypto-reviewer sign-off) · **Severity: HIGH ·
Confidence: PLAUSIBLE — reasoned from the lifetime argument and a confirmed by-slice capture; not
exercised by a test**

`maybeSwapOcspStaple` (`server.zig:48505-48518`) rotates the staple and frees the
generation-before-last:

```
48512:  self.config.tls_ocsp_staple = next;
48513:  // Defer the free by one generation (see `reload_tls_prev`): a handshake
48514:  // that captured the old staple slice must not read freed bytes.
48515:  if (self.ocsp_staple_prev) |old| self.allocator.free(old);
48516:  self.ocsp_staple_prev = self.ocsp_staple_owned;
48517:  self.ocsp_staple_owned = next;
```

The stated rationale (also at `server.zig:4206-4214`) is that one extra retained generation covers
"an in-flight handshake that captured the staple slice." `serverTlsConfig` does capture it **by
slice**, not by copy — `if (self.config.tls_ocsp_staple) |staple| cfg.ocsp_staple = staple;`
(`server.zig:5607`) — and **TLS handshakes run on every reactor.**

At `num_shards = 1` the deferral is airtight: the thread performing the free is the same thread
that drives handshakes, so a captured slice has either been released or was never taken. At N>1
that coincidence disappears. A handshake in progress on reactor 3 can hold generation *k* while
reactor 0, two swaps later, frees it — a **use-after-free of attacker-visible TLS material** on a
path that has no lock coupling it to the swap. `reload_tls_prev` (`server.zig:4185`, freed at
`:48607-48609`, reached from A2 and from `REHASH`) carries the identical argument for the whole
cert/key generation.

Nothing observed says this reproduces today: the swap only occurs when a worker publishes, and the
window is one handshake against two staple intervals. But the *reason it is safe* is single-reactor
shaped, and 0.7 exists to move operators off `num_shards = 1`.

**Fix (for armor-tls to choose).** Either bound the generation lifetime by an actual
release signal (epoch/refcount over in-flight handshakes, as `substrate/ebr.zig` already models),
or copy the staple into the per-handshake config so no cross-thread slice is ever captured, or
retire generations from the reactor that captured them. Confirm the same disposition for
`reload_tls_prev`.

**Accept.** A stated, tested lifetime rule that does not depend on the freeing thread being the
only handshake thread. **It must be settled before [Phase 3 — "widen the ceiling"](../releases/0.7-RELEASE-PLAN.md#7-dependency-graph-and-build-order)
makes a higher shard count the recommended configuration**, since that phase is what supplies the
second handshake thread the current argument assumes away. It belongs in the same armor-tls review
as [P0-4](../releases/0.7-RELEASE-PLAN.md#p0--must-land-before-070) (the in-flight TLS hardening),
and it is the one finding here that is a memory-safety question rather than an observability one —
so it should not wait on P0-3's DST to be believed.

<a id="p0-tg-4"></a>
### P0-TG-4 — Make the guard mean what it says, and make the check mechanical

**Owner: onyx-server-reactor** · **lands via zig-coder** (`server.zig` slice) ·
**Severity: MEDIUM, but P0 because it is what makes P0-3's DST able to fail · Confidence: CONFIRMED**

Two gaps in enforcement:

1. **`rx()` fails open.** `current_reactor` is `threadlocal … = null` (`server.zig:3245`) and
   `rx()` returns `&self.reactors[0]` when unset (`:4253-4255`), so
   `self.rx() == &self.reactors[0]` is **true on any non-reactor thread**. Every guard in §2.1 is
   therefore bypassable by a future off-reactor caller — and
   [P0-2](../releases/0.7-RELEASE-PLAN.md#p0--must-land-before-070) introduces exactly that class by
   exposing `defer_taskrun` + `SINGLE_ISSUER` as config keys. (Multishot, the other such caller, is
   deferred to 0.8 under [R-3](../releases/0.7-RELEASE-PLAN.md#9-risks-severity-tagged).) Provide an
   explicit predicate — e.g.
   `fn isMaintenanceReactor(self) bool { return current_reactor == &self.reactors[0]; }`, comparing
   the threadlocal directly and refusing the `null` fallback — and use it for every guard in §2.1.
   `server.zig:11832` and `:37439` already compare `current_reactor` directly, so the idiom exists
   in-tree.
2. **The rule is a comment, not a check.** The reasoning lives in prose at
   `server.zig:6239-6252`, where a comment cannot fail a build. Add the cheap mechanical half that
   [P0-3](../releases/0.7-RELEASE-PLAN.md#p0--must-land-before-070)'s seeded DST can then deepen: a
   test that runs `onTimerTick` on `reactors[1]` of a two-shard server and asserts **no shared
   `last_*_ms` counter moved** (`last_membership_resync_ms`, `last_oper_grant_refresh_ms`,
   `last_peer_rtt_probe_ms`, `last_session_replica_refresh_ms`,
   `last_session_attachment_lease_refresh_ms`, `event_history_last_write_ms`,
   `backup_last_write_ms`). That single assertion catches the whole guard-theft class, including
   any task added after this audit. The multi-reactor test harness already exists — e.g.
   `server.zig:65806-65836` and `:86670-86678` drive `current_reactor` across two shards.

**Accept.** `zig build test-server` carries the counter-immobility test; §2.1's guards route
through the explicit predicate.

---

## 5. Verification items — not P0, hand off with the audit

| # | Item | Owner | Why it is not P0 |
| --- | --- | --- | --- |
| **M-1** | Confirm the media pump's shard-independence holds once P0-2 lands: the pump is the sole DTLS/SRTCP owner (`media_plane.zig:342`, `:392`, `:474`) and reaches native channel members through the bridge (`:106-110`). Verify no path from the pump reads `rx()`-scoped state, which would resolve to `reactors[0]` via the `null` fallback rather than the owning shard. | onyx-server-media | The pump's own cadence is invariant in `num_shards`; nothing observed shows it consuming a reactor-scoped table. Bounded read, not a finding. |
| **M-2** | Duplicate-work cost, not correctness: C3/C6 let an arbitrary reactor perform the chanstats and `/metrics` renders. Correct today (all inputs shared, and the advancing reactor does the work), but each render walks every channel and every stats family under the completion-wide `world.lockWrite`, so at N>1 the render can land on a shard whose tick is otherwise cheap. Measure before deciding. | onyx-server-perf | Depends on [P0-1](../releases/0.7-RELEASE-PLAN.md#p0--must-land-before-070)'s bench baseline. Do not "optimize" this before it is measured. |
| **M-3** | Seeded DST for the guard class: partition + heal at `num_shards = 2` asserting membership converges within `membership_resync_interval_ms`, plus USR2-under-fault at N>1. §4's fixes are unit-testable, but the *starvation* mode only appears over time under load. | onyx-server-dst | The invariant is designed here; the seeded `Sim`/`fault_loom` harness **is** [P0-3](../releases/0.7-RELEASE-PLAN.md#p0--must-land-before-070), dispatched as W1-2 — this row is that task's input, not a competing item. |

---

## 6. What ran

```
zig build test-mesh          # gate command for this task
```

**Result: RED — and not attributable to this audit, which changed no code.** The working tree was
dirty with concurrent Wave 1 work while the gate ran, and the compiler reported:

```
src/daemon/registry.zig:912:52: error: use of undeclared identifier 'countStats'
src/proto/s2s_frame.zig:1:1: error: file contents changed during update
```

`file contents changed during update` is the compiler observing another writer mutating
`s2s_frame.zig` mid-build, and `registry.zig:912` is a mid-edit state of a file this task does not
own (`registry.zig` +201 uncommitted). Both files are outside this task's read-only slice. **This audit's own
citations were therefore resolved against `git show HEAD:src/daemon/server.zig` rather than the
working tree**, and the gate must be re-run by whoever lands the Wave 2 fixes on a tree that is
not mid-edit.

Nothing in §2–§4 depends on the build result: every claim is a source citation at `c221033`.

---

## 7. Confidence

**CONFIRMED** (read at HEAD and cited above): the per-reactor timer arming
(`server.zig:6072-6078`); the 43 Class A tasks and each one's guard state; the shard-local
iteration at `server.zig:6573` and its escape into `stats_peak_clients`/`LUSERS`
(`:6592`, `:6600-6602`, `:6655`, `:34783-34788`); the absence of an internal guard in
`publishPeerCount` (`:49072-49079`) and `maybeProbeMeshPeerRtt` (`:49232-49238`), and its presence
in `sweepMeshAutoConnect` (`:29342`), `tickOcg2Runtime` (`:6144`),
`retryWebhookResumeIfPending` (`:5259`), `maybeRunBackups` (`:6710`); the shard-aware `connFor`
(`:10081-10084`) that makes C1 safe; the cross-shard `broadcastChannel` (`:10635-10653`) that makes
C2 safe; `rx()`'s `null` → `reactors[0]` fallback (`:3245`, `:4253-4255`); the by-slice staple
capture at `:5607` against the deferred free at `:48515`; the three off-reactor interval loops.

**PLAUSIBLE — verify before acting:**

1. **[P0-TG-3](#p0-tg-3) reproduces at N>1.** The by-slice capture and the free are both confirmed;
   the *interleaving* — a handshake on shard k holding generation *j* across two swaps on
   reactor 0 — was reasoned from the lifetime argument, not observed. Highest-stakes open item
   here, and the only one that is a memory-safety question rather than an observability one.
2. **The Class A count is exhaustive for `onTimerTick`.** Derived by enumerating every executable
   statement in `server.zig:6170-6303` and expanding `maybeWriteStats`. A maintenance task reached
   *indirectly* from one of those 43 (a sweep that itself calls a second sweep) would not appear as
   its own row.

**Not checked:** whether the media pump consumes any `rx()`-scoped state (M-1); the render cost of
C3/C6 at N>1 (M-2, needs P0-1); behaviour under actual load at `num_shards > 1` (M-3, needs P0-3);
the `s2s_peer.zig` inbound signing gate, whose file is mid-edit by another Wave 1 worker and which
is a fail-closed question rather than a timer-guard one.
