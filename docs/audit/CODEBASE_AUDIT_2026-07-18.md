# Onyx Server Full-Codebase Security & Correctness Audit

> **Historical audit snapshot.** This review is pinned to `f558447` / `0.5.6`
> and records the source and deployment assumptions visible on 2026-07-18. It
> is not a current release or vulnerability-coverage statement. The current
> source/live distinction, image hash, and mesh health are maintained in
> [`docs/ops/onyx-server-paths.md`](../ops/onyx-server-paths.md); current attack
> coverage is tracked by `zig build test-exploit` and the Q4 roadmap.

**Date:** 2026-07-18
**Revision audited:** `f558447` — *"fix: TLS/crypto audit hardening"* (v0.5.6)
**Method:** Read-only static trace, adversarial. Six independent Fable-model auditors, one per subsystem, several fanning out their own sub-auditors. No build, sanitizer, or live multi-reactor run.
**Scope:** The entire daemon except the crypto/TLS substrate (`src/crypto/tls*`, `x509`, `kx`, AEAD, …), which was covered by the preceding 6-pass Armor audit whose fixes are the audited commit.

---

## Executive summary

**No CRITICAL findings. No HIGH finding is reachable on the currently deployed binary.** The production pair (0.5.5+12ac590) is safe; the crypto core, the MESSAGE_V2 durability authorities, the io_uring reactor concurrency model, and the daemon command/session surface all trace sound.

Two HIGH items are *latent or federation-gated* — neither is a remote-unauthenticated bug:

1. **Helix `.tls_session` capsule widened without a version bump** — the exact class as the shipped netsplit bug, recurring in a different capsule. Latent because the deployed binary post-dates the widening and the exact-manifest handoff contract already cold-refuses any predecessor old enough to seal the short layout. **Must be fixed before the next release cadence.**
2. **Mesh anti-entropy repair merges channel CRDT state with no per-record origin signature** — an *already-admitted, trust-rooted* Byzantine peer could forge channel membership/mode via `REPAIR_RESPONSE`. Gated by MeshPass + `[mesh].trust_roots`; a documented-deferred gap in the signed-frame model.

The rest are resource-growth caps, capsule version-range hygiene, secure-zeroization of key material across USR2, and robustness (fail-closed instead of crash/spin) items. The single most *reachable* finding is a slow, unauthenticated SCRAM-salt memory leak (MEDIUM).

### Findings by severity

| Severity | Count | Reachable at HEAD? |
|---|---|---|
| CRITICAL | 0 | — |
| HIGH | 2 | No (1 latent, 1 federation-gated) |
| MEDIUM | 11 | Mixed (1 unauth-reachable; rest admitted-peer / operator / OOM-only) |
| LOW | 11 | Mostly no (future-consumer / test-only / cost) |
| INFO | 1 | Documented default |

### Subsystem coverage

| Subsystem | Verdict |
|---|---|
| Daemon core — server/dispatch/sessions/world | **Clean** |
| Mesh — Undertow CRDT / Mooring S2S | 1 HIGH, 1 MEDIUM, 2 LOW |
| Helix USR2 hot-upgrade + capsules | 1 HIGH, 5 MEDIUM, 6 LOW/nit |
| io_uring reactor + sharded threading + kTLS | 2 MEDIUM, 3 LOW |
| Storage / WAL / MESSAGE_V2 durability | 2 MEDIUM, 1 LOW |
| Protocol wire / warden / media | 1 LOW, 1 INFO |

---

## HIGH

### H1 — `.tls_session` capsule widened with no version bump (Helix) — CONFIRMED, latent
**`src/daemon/helix/tls_snapshot.zig:113` · registry `src/daemon/helix/capsule.zig:119`**
`tls_snapshot.encode` appends two trailing kTLS-flag bytes (commits `512da47`/`26624cf`), but the capsule registry still reads `{current=1, min=1, max=1}` with no mirrored `schema_version`. Two incompatible layouts share version 1, distinguishable only by length. Adoption uses strict `decodeCurrent` (`server.zig:24985`) with mandatory flag reads, so an arena sealed by a genuine pre-kTLS v1 binary would hit `Truncated → InvalidInheritedHandoff → whole-handoff abort → every carried connection dropped`.
**Why not reachable:** the deployed binary post-dates the widening, and the 2026-07-17 exact-manifest contract (`clients` 5/5/5 + capability-token probe) cold-refuses any predecessor old enough to seal the short layout.
**Fix:** bump `.tls_session` to `{current=2, min=1}` + add the mirror const + route adoption through a version-aware decode (mirror the `.s2s_link` v4 pattern, which the audit confirms is done correctly).

### H2 — Anti-entropy repair backfill has no per-record origin authentication (Mesh) — DEFERRED (verified-narrow, tripwire-guarded), 2026-07-18
**`src/substrate/undertow/anti_entropy_repair.zig:164` (`applyRepairResponse`), via `s2s_peer.zig:3697`; the WIDER class also covers `BURST` `s2s_peer.zig:1137` + `DELTA` `:1138`/`mergeDelta:3654`**
`REPAIR_RESPONSE`/`BURST`/`DELTA` records merge foreign channel-CRDT facts into the per-link `self.state` shadow (`ChannelCrdt`, keyed `replica_id = local_node_id`, channel `#undertow`) with only immediate-hop link trust — no per-record origin pubkey/signature. `BURST`/`DELTA` are not even routed through `verifiedPayload` (frame-signing gate); only MeshPass admits them.
**Decision (design trace, 2026-07-18):** closing the class properly = per-fact signatures on the CRDT + wire-version bumps on all three frames (`signed_frame.zig:126-133` prescribes storing the original signer's `(pubkey,sig)` per fact) — a multi-day convergence-core change. **DEFERRED as over-scoped for the actual risk.** Full source trace (all 9 reads of `self.state`) confirms the forged state feeds NO third-party authority: the only local-effect read is `refreshChannelRoute` (`s2s_peer.zig:3706`), which reads member LIVENESS only (`entry.adds.items.len`) and keys the route on `self.remote_node_id`, never on `dot.replica_id` and never on `self.state.modes`. `dot.replica_id` and `self.state.modes` have zero readers. Client-visible membership/oper/modes flow through the SEPARATE, origin-gated `MEMBERSHIP` + `CHANNEL_MODE_STATE` paths. The shadow is per-link (never re-served to a third node authoritatively) and is NOT carried in the Helix `.s2s_link` capsule (rebuilt via re-burst post-USR2). So a Byzantine MeshPass-admitted peer forging facts gains nothing beyond honestly asserting its own routing presence.
**Correction (adversarial review, 2026-07-18):** `refreshChannelRoute` opens with node-GLOBAL `routes.removeNode(self.remote_node_id)` (`route_table.zig:1928`, wiping `channel_members`+`nick_to_node` that NAMES/delivery/401/WHOIS read) then re-adds only the inert node-set entry — reachable on the UNAUTHENTICATED `DELTA` path with `live==0`. Self-LIMITED (remote_node_id is immutably handshake-bound, `s2s_peer.zig:3539-3543`), so a peer can only evict its OWN node's roster until re-burst — but this is the shipped member-staleness-prune outage shape (empty NAMES / 401). Tracked below as a SEPARATE correctness item; per-fact signing does NOT fix it.
**Trigger to revisit (build the per-fact signing then):** the moment ANY consumer reads `self.state.members[].dot.replica_id` OR `self.state.modes` for an authority/attribution decision, OR the shadow becomes a delivered user channel — at which point the forgery stops being inert. A committed `onyx-server-dst` seeded Byzantine tripwire test (see build plan) fails on exactly that regression.

---

## MEDIUM

### M1 — SCRAM salt leak, unauthenticated-reachable (Storage) — CONFIRMED · *most reachable finding*
**`src/daemon/scram_store.zig:475` (+`:499`)** — `lookup`/`lookup512` dupe the account salt into `self.lookup_salts`, freed only at `deinit`. SCRAM server-first returns the salt *before* proof verification, so any client knowing one valid account name leaks 16–32 B per SASL-SCRAM start into a process-lifetime list → slow unbounded growth. **Fix:** give the returned salt a per-exchange lifetime (caller-owned dupe / arena); drop store-lifetime retention.

### M2 — Cross-shard delivery retry-spins burn 8192 iterations under the world lock (Reactor) — CONFIRMED
**`src/daemon/server.zig:9062-9107` (`enqueueDeliveryMaybeCloseEx`)** — the pool-exhaustion/inbox-full retry spins can never succeed: the only paths that free `DeliverBuf`s / inbox slots run under the same `world.lockWrite` the sender holds. Once a target shard's pool is full, both spin loops exhaust (~8192 `spinLoopHint`) and poison-disconnect the recipient anyway — while stalling every other reactor on the world lock. A large fan-out to a wedged shard becomes an overload amplifier. **Fix:** poison on first acquire/push failure (identical outcome, minus the stall), matching `enqueueCloseOnOwner:9000`.

### M3 — `channel_mode_state_clocks` grows unbounded per channel name (Mesh) — CONFIRMED
**`src/substrate/undertow/s2s_peer.zig:2515`** — `StringHashMapUnmanaged(u64)` dupes a channel-name key per distinct `CHANNEL_MODE_STATE` frame, no cap/eviction (freed only at peer `deinit`). An admitted signing peer streaming unbounded distinct channel names exhausts memory. **Fix:** bound with an LRU/cap like `message_relay.SeenSet`.

### M4 — `chanstats.channel()` has no channel-count cap (Storage) — CONFIRMED
**`src/daemon/chanstats.zig:193`** — per-channel sub-tables are capped (`userOf` → `max_users_per_channel`) but the channel *count* is not; a burst of unique channels within one `stats_interval_ms` spikes memory and emits one JSON file each before the ≤64/flush pruner catches up. Bounded in steady state by the 256 MB load cap. **Fix:** add a `max_channels` ceiling (reject / LRU-evict).

### M5 — Helix registry advertises legacy ranges adoption refuses (Helix) — CONFIRMED
**`src/daemon/helix/capsule.zig:114` / `:138`** — `.sessions` and `.ws_session` promise `min_supported=1` "version-aware decode," but adoption pins `header.version == current` exactly and calls `decodeCurrent`; the legacy arms are dead. A pre-bump predecessor's capsule → fail-closed whole-handoff refusal (availability, not safety). Only `.s2s_link` truly honors its range. **Fix:** either honor the ranges or tighten them to exact and correct the comments.

### M6 — Missing-arena degradation silently converts hot upgrade to cold boot and reports success (Helix) — PLAUSIBLE
**`src/daemon/server.zig:24100-24109`** — manifest present + trusted but arena fd absent → all carried sockets closed, fresh boot, no error — contradicting the startup-fatal posture applied to a malformed manifest 4 lines later. **Fix:** treat as the fatal/refuse path (or at minimum log the downgrade).

### M7 — No secure-zeroization in the Helix secret lifecycle (Helix) — CONFIRMED
**`src/daemon/helix/` (zero `secureZero` hits)** — TLS 1.3/1.2 traffic secrets, ticket keys, Mooring record keys, and every adoption-side `capsule.decodeReader` heap dupe are freed unwiped, so key material lingers in freed heap across every USR2. Local-memory disclosure only. **Fix:** wipe secret-bearing buffers before free, matching the substrate's stated secure-zero bar.

### M8 — Container `validate` accepts entry versions above the local max (Helix) — CONFIRMED
**`src/daemon/helix/capsule.zig:238-244`** — discards `negotiate`'s clamp (`_ = try negotiate(...)`); `supports` checks only range *overlap*, so an entry claiming `version=9,min=1,max=9` passes `decodeStream`. Fail-closed rests entirely on each per-kind decoder's `else => UnsupportedVersion` (all present today) — a future decoder with progressive `if (version >= N)` arms would mis-parse. **Fix:** reject `header.version > local.max_supported` in `validate`.

### M9 — `readArena` reads the whole inherited memfd with no size cap (Helix) — CONFIRMED
**`src/daemon/helix/live.zig:623-645`** — allocation sized purely by inherited-fd content before `decodeStream`; a corrupt predecessor image can OOM the successor before validation. Trust boundary is the prior binary. **Fix:** cap the arena read at a sane ceiling before allocating.

### M10 — `catch unreachable` on inherited bytes (Helix) — CONFIRMED
**`src/daemon/server.zig:24502`** (`session_snapshot.decodeCurrent(...) catch unreachable`, World-projection second pass) — dead only because an identical decode succeeded in a preceding loop over the same slice; any drift between the two loops turns a malformed capsule into a mid-adoption panic instead of a transactional abort. **Fix:** propagate the error into the existing abort path.

### M11 — `submitSend` documents a false buffer-lifetime contract (Reactor) — CONFIRMED, latent
**`src/substrate/io/ring.zig:381-384`** — doc claims "the kernel copies the bytes during submission, so the caller may free … immediately." `IORING_OP_SEND` does *not* copy at submission; an async-punted send reads the user buffer at execution time. Not live (the daemon's own `ringlane` latches `send_armed` and never frees while armed), but the first future consumer that trusts the doc ships a UAF. **Fix:** reword to "keep `buffer` stable and live until the matching send CQE is reaped."

---

## LOW / INFO (abridged)

- **L1** `s2s_peer.zig:3026/3113` — dead `errdefer` (every step is `catch return`, a void return): a mid-sequence OOM leaks duped strings. Propagate with `try` (both fns are `!void`). *OOM-only.*
- **L2** `event_history.zig` snapshot uses in-place `O_TRUNC` write, not tmp+rename; torn write degrades to an empty REPLAY ring (loader fail-closed). Consistency fix.
- **L3** `toml.zig:402/621/669` — unbounded parser recursion; a deeply nested malformed config crashes a *running* daemon on REHASH instead of a typed `ParseError`. Operator-controlled input, not wire-reachable. Thread a depth counter.
- **L4** `reactor_fabric.zig:105` — the fabric's per-shard wake eventfds are dead in the live daemon (server wakes via `Reactor.wake`); N wasted fds + a misleading module doc. Remove or wire.
- **L5** `ktls.zig:377` — a data-less `TLS_GET_RECORD_TYPE` cmsg edge could read the next cmsg's header byte (in-bounds); unreachable today (kernel always writes `CMSG_LEN(1)`). Require `clen >= align(hdr)+1`. *PLAUSIBLE.*
- **L6** `session_snapshot.zig:351` — tolerant-`decode` tail misalignment (would be Critical if reachable; production uses `decodeCurrent`, so test/legacy-only).
- **L7** `server.zig:25613` — carried oper grants (and their revocation tombstones) silently dropped if the registry is at capacity (`_ = upsert(g)`). *PLAUSIBLE.*
- **L8** `server.zig:23823` — `listener_fds` alloc-failure refusal does a void `return` and skips the "deferred UPGRADE failed" log (cleanup itself correct).
- **L9** Unknown `mesh_checkpoint` magic rows are `continue`d by every selector; protection rests solely on `handoff_relations.validateCurrent` — a future sealer-side magic added without updating it becomes silent state loss.
- **L10** `mooring_handshake.zig:824` — early length-mismatch return in `constantTimeEqlBytes` leaks the configured `mesh_pass` length via timing (PSK; body compare is constant-time). Nit.
- **L11 (perf)** `deliver_handle.zig:111` / `reactor_fabric.zig:118` — `DeliverPool`'s ~1 MB `bufs` is a comptime default embedded per instantiation and copied by value per shard at init. Routed to perf.
- **Doc/nits:** stale capsule-version comments (`session_snapshot.zig:59`, `session_capsule.zig:147` "v2" vs computed v3, `server.zig:25344` "skipped" vs fatal), `s2s_snapshot.decodeInternal` dead `strict_current` param, `migration_journal.zig:73` O(n²) prune.
- **INFO** native-media MAC defaults to `require_mac=false` (documented legacy-compat; fail-closed when enabled). Hardening-posture note.

---

## Verified clean (high-value surfaces that traced sound)

- **MESSAGE_V2 durability** (event_log / outbox / replay_guard / attachment_spool): validate-before-stage (magic/version/BLAKE3/bounds/canonical-order/dup), per-wire cryptographic re-verification, atomic `replaceFromCheckpoint`, config compared against operator-owned expected, outbox checksum-domain rotation, allocation-failure-atomic prepared/commit split; USR2 adoption runs `relayV2RestoreRelationValid` before publish.
- **WAL/store:** snapshot-durable-then-truncate ordering, post-apply compaction, CRC-before-apply replay, clean stop at torn/oversize record, oversize-WAL reject (no OOM).
- **Reactor core:** buffer-address stability (inline `ConnState`, slab reserved to max, `send_overflow` never handed to kernel), exhaustive completion decode + exact-generation cancel, wake-strictly-after-enqueue, `DeliverBuf` release-exactly-once (tagged Treiber head kills ABA, Vyukov MPMC orderings correct), reactor-0-gated maintenance timers, kTLS attach only on drained clean-record boundary.
- **Daemon core:** CRLF/NUL rejection + param-arity guards on the command surface, fail-closed cross-account session-token reclaim (timing-safe compares, `EvictedSession` by value), staged-before-commit World roster mutation with `errdefer` rollback (no OOM half-join), NICK→MONITOR inline-buffer snapshot.
- **Helix (the parts done right):** `.s2s_link` v4 versioning (registry mirrors `schema_version`, explicit v1–v4 arms, fail-closed `else`, cross-version tests, `peekFd`-and-close on decode failure), transactional adoption order (ticket-key at staged-swap edge with rollback errdefer), fd-leak discipline (centralized manifest, close-exactly-once, CLOEXEC re-armed), no-plaintext-adoption fail-closed `was_secured`/`was_websocket` joins, constant-time `migration_token`.
- **Mesh:** MeshPass `(allowed & required)==required` inside encrypted M1, Ed25519 `verifyStrict` over canonical CoilPack, wall-clock HLC LWW, receiver-local staleness stamps (zombie-GC fix intact), shortId identity re-verified at daemon, nick-collision rename-to-UID, record-nonce uniqueness per direction.
- **Protocol/warden/media:** media MAC constant-time compare + HKDF `(channel,participant)` binding + `require_mac ⟹ key` invariant, datagram/frame reassembly bounds, irc_line CRLF-smuggling guards, cloak keyed-HMAC with per-call key wipe, warden mesh-wire line-injection guard, per-connection flood/clone/spam/dnsbl isolation with injected clock.

---

## Prioritized remediation

**Before the next USR2 release (hygiene against the netsplit class):**
- H1 — `.tls_session` v2 bump + mirror const + version-aware decode.
- M5 — resolve the `.sessions`/`.ws_session` range-vs-adoption drift (honor or tighten).
- M8 — reject over-max versions in container `validate`.

**Next hardening pass (mostly small, high-confidence):**
- M1 — SCRAM salt per-exchange lifetime (the one unauth-reachable leak).
- M2 — delete the dead delivery retry-spins (overload amplifier).
- M3, M4 — add the missing growth caps (`channel_mode_state_clocks`, `chanstats` channels).
- M7 — secure-zero the Helix secret lifecycle.
- M6, M9, M10 — fail-closed the missing-arena / uncapped-readArena / catch-unreachable Helix edges.
- M11 + L-doc — correct the `submitSend` contract and the stale capsule-version comments.

**Federation threat-model (design decision required):**
- H2 — per-record origin signatures on anti-entropy repair records + a Byzantine-repair DST. Decide whether to close now or keep the documented deferral.

**Deploy note:** this audit found no reachable CRITICAL/HIGH at HEAD, so shipping v0.5.6 (the TLS-audit fixes) does not introduce a break. H1 is orthogonal to that deploy — the currently deployed binary already carries the widened `.tls_session` layout, so a USR2 from it to v0.5.6 seals/adopts consistently; the v2 bump is release hygiene, not a deploy blocker.
