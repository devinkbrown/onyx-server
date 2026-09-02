# Game Changers 50 — unified feature catalog (Onyx Server + Onyx)

**Status:** architecture proposal, uncommitted. **Docs only — no code implied by this file.**
**Repos:** `/home/kain/onyx-server` (Zig IRC/IRCX daemon) · `/home/kain/onyx` (SolidJS web client)
**Author:** stack-architect · **Date:** 2026-09-01

This is **50 features total across both products**, not 50 per repo. Every entry carries a
scope label (`Server` / `Client` / `Both`), an implementation home cited to real paths at
HEAD, an owning agent, complexity, target release, dependencies, and — where it crosses the
wire — a protocol note plus deploy order.

## How this catalog was built (and what makes it credible)

Two passes over real source, not memory:

1. **De-duplication pass.** Read `docs/ROADMAP-2026-Q4.md` in both repos (server items S-01…S-30,
   client items C-01…C-31, cross-cutting contracts X-1…X-12), `onyx/docs/era3-40-game-changers.md`,
   and `docs/features/INVENTED-FEATURES-CATALOG.md` (**F-01…F-68**). This file does not restate the
   roadmap. Where an entry here *does* overlap an existing F-item, that overlap is **declared
   explicitly** below rather than dressed up as novel — see § Relationship to F-01…F-68.
2. **Built-but-unexposed pass.** A large fraction of `onyx-server/src/substrate/` is mature,
   tested Zig with **zero consumers outside `substrate/`**. Verified by consumer count: `lotus`,
   `seq_crdt`, `egwalker`, `vad`, `dtx`, `sparse_merkle`, `minhash`, `cron`, `gcra`, `ratelimit`,
   `circuit_breaker`, `rendezvous_hash`, `range_coder`, `raptorq`, `reed_solomon`, `ice_agent`,
   `pmtud`, `media_epoch_key`, `roaring`, `count_min_sketch`, `hyperloglog`, `wal`, `admission`,
   `rateless`, `sketch`, `topk` — **all 0 consumers outside `src/substrate/`**.

That second finding is the thesis of this catalog: **Onyx's biggest wins are not new
algorithms — they are product surfaces over algorithms it already owns.** Roughly half of
these 50 are "wire an existing substrate module to a user-visible or operator-visible
surface," which is why so many land at M rather than XL.

Two monoliths also shape the plan: `src/daemon/server.zig` is **102,026 lines at HEAD** (`f9ed9bc`)
and `onyx/src/lib/store/store.ts` is **18,225 lines at HEAD** (`6c88eafa`). Both files carry
uncommitted working-tree changes, and both roadmaps quote slightly different figures (L-01 says
102,152; C-02 says 18,335) — treat all such counts as approximate and re-measure before acting.
Both are load-bearing seams that throttle
every other feature's velocity, so both appear as first-class entries (GS-01, GC-01) rather
than as background cleanup.

## Relationship to F-01…F-68 (`INVENTED-FEATURES-CATALOG.md`)

That catalog answers *"what could the daemon do that it cannot do today?"* — 68 feature concepts,
server-scoped. This catalog answers a different question: *"what are the highest-leverage things to
build across **both** products, and what already-built substrate makes them cheap?"*

Where they meet, this file is the **implementation plan**, not a second idea. Declared overlaps:

| This entry | Overlaps | Relationship |
|---|---|---|
| GS-02 Sketch Telemetry Plane | **F-39** Deep metrics: histograms, not just counters | Same goal. This entry adds the *substrate wiring plan* — `ddsketch`/`hdr_histogram`/`tdigest` already exist with 0 external consumers, plus the multi-reactor merge-owner design F-39 does not specify. |
| GS-05 Scheduled Automation | **F-03** Scheduled operator actions · **F-52** Scheduled & deferred delivery | Same goal; F-52 already notes `cron.zig` has no scheduler consuming it. This entry supplies the single-reactor-owner + USR2-idempotence contract. |
| GB-03 Transparency Ledger | **F-43** Audit log with tamper-evident chaining · **F-61** Key transparency with client-verifiable proofs · **F-08** Proofmark federation | Same goal. **Reframed:** `src/daemon/proofmark.zig` already produces signed moderation proofs, so this is *chaining existing proofmarks into an MMR + a client-side inclusion-proof verifier*, not a new proof format. |
| GB-04 Programmable Rooms | **F-26** WASM extension sandbox for policy hooks | F-26 is policy hooks; this is *room-scoped user-facing apps* on the same host. Shares the permission model — build F-26's host once, serve both. |
| GB-06 Raid Shield | **F-18** Raid-shape detector (+ F-16, F-17) | F-18 is the detector; this adds **mesh-wide coordination** of the verdict plus the client banner. Build F-18 first, then this. |
| GB-07 Live Captions | **F-37** Live captions with translation hooks | The F-catalog itself records live captions as **already shipping server-side** (`src/daemon/transcript.zig`, `MEDIA TRANSCRIPT`). This entry is therefore only the **client last mile** — the smallest scope of the three. |
| GB-08 Device Attestation | **F-61** Key transparency | Adjacent: F-61 proves key history; this makes the *device set* authoritative and mesh-revocable. |
| GS-06 Rendezvous Homing | **F-13** Geographic routing hints · **F-66** Adaptive shard rebalancing | This is the hashing mechanism both need. Build once, consume twice. |
| GS-16 qlog Export | **F-42** Distributed trace export (OpenTelemetry) · **F-40** Flight-recorder export | Different wire formats, same plumbing. Pick one exporter; qlog suits the transport/media path, OTel the command path. |
| GC-14 Media Room UX | **F-34** Spatial audio rooms | F-34 is the server capability; this is the client surface for it. |
| GB-05, GB-09, GB-10, GB-13, GB-14, GB-15, GS-01, GS-04, GS-07, GS-11…GS-15, GS-17…GS-20, all GC-* | — | No F-item equivalent found. |

**Seven premises were corrected** after checking HEAD — the last four during an adversarial refute
pass that found this document's *"does a surface for this already exist?"* search had been far weaker
than its *"does anything import this substrate module?"* search. They are recorded so nobody
re-invents them:

| Corrected | Reality at HEAD |
|---|---|
| "Content matching is limited / a performance cliff" | **False.** `src/daemon/content_filter.zig` (Koshi) already builds an Aho-Corasick automaton (`content_filter.zig:13,45,108`) giving O(text) matching regardless of pattern count. GS-18 was **replaced** with a genuinely absent feature. |
| "Admission is scattered with no policy plane" | **Overstated.** Connection classes already exist as config (`etc/onyx-server.reference.toml:473-485`) with a global accept-time rate gate (`:436`). GS-03 is re-scoped to *unify enforcement + make refusals auditable*, not to invent classes. |
| "Live captions are missing" | **False on BOTH sides.** The server ships `src/daemon/transcript.zig`; the client ships `src/shell/voice/overlays/CaptionsOverlay.tsx` (268 lines) with `MEDIA CAPTION`/`MEDIA TRANSCRIPT` parsed at `onyx/src/lib/store/store.ts:10444-10473` and a passing `role="log"` live-region test in `VoiceOverlays.test.tsx` — including the exact live-region-scoping case GC-08 listed as outstanding. GB-07 was **replaced**. |
| "The client needs a Theme Studio" | **False.** `onyx/src/theme/ThemeStudio.tsx` **already exists at 2,854 lines** with the generative palette factory, live preview, JSON import/export, and AA-clean-by-construction contrast; sharing ships too (`ThemeImportDialog.tsx`, `lib/theme/themeShare.ts`). GC-09 was **replaced**. |
| "Search needs a new `SEARCH` verb and index" | **False.** `src/daemon/search_index.zig` (559 lines, durable `SIDX` checkpoints) exists and `SEARCH` is **registered** at `src/daemon/modules/messaging.zig:68`, with the `draft/search` gate, channel-membership authz, rate limiting, and a bounded envelope already implemented. GB-10 was **re-scoped** to mesh federation only. |
| "An append-only inclusion-proof log must be built" | **Mostly false.** `src/daemon/key_transparency.zig` (1,300 lines) already appends event digests to a **Merkle Mountain Range** with `proof()`/`verifyInclusion()`, and is on the wire as `KEYTRANS` (`src/daemon/modules/accounts.zig:156`). Only *moderation actions as a leaf type* are missing. GB-03 was **re-scoped** and dropped from the Top 10. |

---

## Top 10 must-ship for 0.7

Ranked by (user/operator impact) × (leverage on other features) ÷ (delivery risk).

> **Revised after the refute pass.** The original list ranked Live Captions at #2 and the
> Transparency Ledger at #5; both were substantially already built (see the corrected-premises
> table). They are replaced below by two items whose absence was verified by searching for the
> *product surface*, not just the substrate module.

| # | ID | Feature | Scope | Why it's top-10 |
|---|----|---------|-------|-----------------|
| 1 | **GS-01** | server.zig Strangler | Server | 102k-line file gates every other server feature's review, test, and merge velocity. Highest leverage item in either repo. |
| 2 | **GB-06** | Raid Shield | Both | Self-hosters' #1 operational fear. Four unexposed modules (`admission`, `count_min_sketch`, `topk`, `gcra`) already do the math. |
| 3 | **GC-01** | store.ts Strangler | Client | 18.2k-line store is the client's equivalent throttle; every client entry below gets cheaper after it. |
| 4 | **GS-03** | Class-based Admission Fabric | Server | Turns admission from ad-hoc checks into one auditable policy plane; prerequisite for GB-06. |
| 5 | **GC-09** | Vault Encryption at Rest | Client | **Replaces GB-03.** The IndexedDB history vault has no at-rest encryption — a shared or lost device exposes all cached channel history, drafts, and the outbox. Verified absent in `historyVault.ts`. |
| 6 | **GS-02** | Sketch Telemetry Plane | Server | You cannot operate or tune what you cannot measure; `ddsketch`/`hdr_histogram`/`tdigest` are built and idle. Unblocks GS-08, GS-15, GS-20. |
| 7 | **GB-14** | Consent-Gated Unfurl Proxy | Both | Closes a live privacy/SSRF surface. Client half (`unfurlPrivacy.ts`) already exists; zero unfurl code exists anywhere in the Zig tree. |
| 8 | **GC-02** | Extension Sandbox Host | Client | `extensions/` ships a manifest and action list with **no isolation host** (4 files, zero `iframe`/`Worker`/`postMessage` hits). Ship the sandbox before third-party code, not after. |
| 9 | **GS-11** | Link Supervision (circuit breaker) | Server | Mesh links currently lack breaker/backoff discipline; this is the difference between a degraded node and a cascading mesh outage. |
| 10 | **GS-18** | Mesh ACL Filters | Server | **Replaces GB-07.** Compact probabilistic ban/ACL filters gossiped between nodes — no F-item or roadmap equivalent, and `xor_filter`/`cuckoo_filter`/`bloom` are all built and idle. |

**Scope breakdown:** 15 `Both` · 20 `Server` · 15 `Client` = **50**.

---

# Part I — `Both` (15): full-stack differentiators

These are the entries where Onyx's mesh + E2EE + Event-Spine + self-host story compounds.
Every one carries a wire note and a **client-first deploy order** (onyx is the live consumer).

### GB-01 — Loom
**Pitch:** CRDT-backed collaborative documents and canvases that live inside a channel, not beside it.
**Scope:** `Both`
**Why game-changing:** A room can co-author a runbook, an incident timeline, or a design sketch
without leaving chat or trusting a third-party SaaS. On a self-hosted mesh the document
replicates the same way messages do — offline edits merge on reconnect, no server arbitration.
**Novelty:** category-defining (no IRC-lineage daemon ships CRDT documents).
**Implementation home:** server `src/substrate/egwalker.zig`, `src/substrate/crdt_text.zig`,
`src/substrate/seq_crdt.zig` (all 0 external consumers) over `src/substrate/lotus.zig`'s causal DAG
(`egwalker.zig` already builds on `lotus.zig`), new `src/daemon/modules/loom.zig`;
client new `src/lib/loom/` + `src/shell/Loom*.tsx`.
**Note:** overlaps **F-55** (persistent channel canvas) in spirit — F-55 is a canvas surface, this is
the CRDT document layer underneath it. Build this, get F-55 nearly free.
**Owning agents:** zig-coder + onyx-server-mesh (server), solidjs-coder + onyx-store (client).
**Complexity:** XL · **Target:** post-0.7
**Dependencies:** GS-01 (module home), GC-01 (store slice), GB-05 shares the causal-DAG plumbing.
**Wire/protocol:** new `onyx/loom` CAP; edits ride a new Event-Spine event kind carrying
`{doc_id, origin_shortId, HLC, op}`. Ops are **value writes** → LWW/HLC path. Deploy client-first;
with the CAP absent the server must not emit loom events at all (byte-identical when off).

### GB-02 — Ambient Rooms
**Pitch:** Always-on, near-zero-bitrate voice presence — hear the room breathe without joining a call.
**Scope:** `Both`
**Why game-changing:** The social texture of a shared office without a meeting. VAD+DTX means a
silent participant costs almost nothing, so a room can idle at 30 people all day.
**Novelty:** differentiated.
**Implementation home:** server `src/substrate/vad.zig`, `src/substrate/dtx.zig`,
`src/substrate/audio_mix.zig` (all unexposed) + the existing media plane; client
`src/lib/cadence-media/` (extend `MediaEngine.ts`, `voiceActivity.ts`), `src/shell/CallsHub.tsx`.
**Owning agents:** onyx-server-media + zig-coder; onyx-media + solidjs-coder.
**Complexity:** L · **Target:** 0.7 P1
**Dependencies:** GS-20 (playout/jitter discipline), GS-10 (epoch keys for long-lived sessions).
**Wire/protocol:** extends the media EVENT plane with an `ambient` session class; DTX gaps must
not be read as disconnects. Old clients see a normal (if quiet) media session.

### GB-03 — Verifiable Transparency Ledger
**Pitch:** Every oper and moderation action lands in an append-only Merkle log any member can verify.
**Scope:** `Both`
**Why game-changing:** The hardest promise a self-hosted network can make is "we didn't quietly
delete your message or shadow-ban you." `src/daemon/proofmark.zig` **already produces signed
moderation proofs** (actor/action/target/policy-version/reason-digest over a stable binary
transcript) — but a signed proof only proves *this action happened*, not *that no action was hidden*.
Chaining proofmarks into an append-only MMR closes that gap: a user requests an inclusion proof and
verifies client-side, and the operator cannot rewrite or omit history without detection.
**Novelty:** differentiated. **Reframed** from "new proof format" to "chain the existing
proofmarks + ship the client verifier" — overlaps F-43 and F-61; see § Relationship to F-01…F-68.
**Implementation home:** server `src/daemon/proofmark.zig` (**exists — the leaf format**),
`src/substrate/merkle_mountain_range.zig`, `src/substrate/sparse_merkle.zig` (**0 external
consumers**), new `src/daemon/ledger.zig`, surfaced via `src/daemon/modules/oper_security.zig`;
client new `src/lib/ledger/` + a Trust Center tab (see GC-11).
**Owning agents:** zig-coder + onyx-server-crypto-reviewer (proof format); solidjs-coder + onyx-crypto.
**Complexity:** L · **Target:** 0.7 P1
**Dependencies:** GS-12 (WAL durability), GC-11 (Trust Center host surface).
**Wire/protocol:** new IRCX `LEDGER` verb (`LEDGER PROOF <seq>` → proof numeric). Ledger roots
replicate as CRDT **value** writes keyed by node shortId. Deploy client-first. **Fail-closed:**
an unverifiable proof renders as "unverified," never as verified.

### GB-04 — Programmable Rooms
**Pitch:** Room-scoped WASM apps — polls, queues, standups, triage boards — running sandboxed in the daemon.
**Scope:** `Both`
**Why game-changing:** Instead of bots that must be hosted, authenticated, and trusted elsewhere, a
room owner installs a fuel-metered WASM module that the daemon runs with an explicit permission
grant. Self-hosters get an app ecosystem without inviting third-party infrastructure into the mesh.
**Novelty:** category-defining. **Overlaps F-26** (WASM extension sandbox for policy hooks) — F-26
targets *policy hooks*, this targets *room-scoped user-facing apps*. They share one host and one
permission model: build the host once, serve both.
**Implementation home:** server `src/wasm/host/` — **already exists** (`abi.zig`, `interp.zig`,
`plugin.zig`, `bridge.zig`, `orowasm-abi-v1.wit`), already reachable from config
(`src/daemon/config_format.zig:38-39,69`); needs a room-scoped permission model + lifecycle.
Client: a render contract in new `src/lib/roomapps/`.
**Owning agents:** zig-coder (host + permissions), onyx-server-hardener (fuel/abuse), solidjs-coder (render).
**Complexity:** XL · **Target:** post-0.7
**Dependencies:** GC-02 (client sandbox mirrors the same permission vocabulary), GS-01.
**Wire/protocol:** app→client UI ships as **typed tokens**, never HTML — it must route the client's
existing parse→typed-token→JSX path, never `innerHTML`. New `onyx/roomapps` CAP.

### GB-05 — Time-Travel Rooms
**Pitch:** Scrub a channel to any past moment and see the room exactly as it was — membership, topic, modes.
**Scope:** `Both`
**Why game-changing:** Incident review and onboarding both need "what did this room look like at
14:20?" Today that requires reading a log and imagining state. The Event Spine already carries the
causal ordering needed to reconstruct it.
**Novelty:** differentiated.
**Implementation home:** server `src/substrate/lotus.zig` — **a causal-DAG event store already in
tree** (`Cid`, `Event{parents, payload}`, `MissingParents`; 0 external consumers) — plus
`src/daemon/event_spine.zig` (767 lines) and `src/substrate/wal.zig` (unexposed), new
`src/daemon/timetravel.zig`; client `src/shell/MessageView.tsx` + new `src/lib/timetravel/`.
**Owning agents:** onyx-server-ircx + zig-coder; solidjs-coder + onyx-store.
**Complexity:** L · **Target:** post-0.7
**Dependencies:** GS-12 (WAL), GS-17 (durable monotonic IDs), GB-01 (shares DAG replay).
**Wire/protocol:** new `REPLAY` verb returning a bounded snapshot + delta stream.
**Guard rail:** replay-driven roster frames must **APPEND** unless the client initiated the burst —
a replace-on-every-353 path is exactly what collapsed `#root` to 2 members in production
(`onyx/src/lib/irc/client.ts:1355-1357`, the `no-implicit-names` seam).

### GB-06 — Raid Shield
**Pitch:** Mesh-coordinated raid detection that clamps admission network-wide in seconds, with an honest client banner.
**Scope:** `Both`
**Why game-changing:** A 200-account join flood is the #1 fear of anyone running a public room.
Today each node defends alone. Raid Shield puts heavy-hitter detection on one node, gossips the
verdict, and every node tightens admission together — while members see "shield active, new joins
delayed" instead of a mysteriously broken room.
**Novelty:** differentiated. **Overlaps F-18** (raid-shape detector) — F-18 is the single-node
detector; this entry adds the **mesh-wide coordination of the verdict** and the client banner.
Build F-18's detector first, then this on top.
**Implementation home:** server `src/substrate/admission.zig`, `src/substrate/count_min_sketch.zig`,
`src/substrate/topk.zig`, `src/substrate/gcra.zig` (**all unexposed**), new
`src/daemon/raid_shield.zig`; client `src/shell/` banner + `src/lib/moderation/`.
**Owning agents:** onyx-server-warden + onyx-server-hardener; solidjs-coder.
**Complexity:** L · **Target:** **0.7 P0**
**Dependencies:** GS-03 (admission fabric) is a hard prerequisite; GS-02 for the metrics.
**Wire/protocol:** shield state gossips as a CRDT **value** write (`{origin_shortId, HLC, level}`);
client learns it via an Event-Spine event. **Guard rail:** the detector's periodic sweep MUST gate on
a single owning reactor — `onTimerTick` fires on **every** reactor thread
(`src/daemon/server.zig:5163`, `:5259` show the `rx() != &self.reactors[0]` pattern to copy). A sibling
reactor silently winning that guard is precisely the class that reaped mesh peers after the 90s TTL.

### GB-07 — Searchable Call Memory
**Pitch:** Everything said in a voice room becomes durable, searchable, permission-checked history.

> **Replaces the original GB-07 ("Live Captions last mile"), which was retracted:** live captions
> already ship on *both* sides — `src/daemon/transcript.zig` server-side, and
> `onyx/src/shell/voice/overlays/CaptionsOverlay.tsx` (268 lines, with passing `role="log"`
> live-region tests) client-side. This entry is the genuine gap that the two shipped systems leave.

**Scope:** `Both`
**Why game-changing:** Captions are transient today. The daemon captures them, the client renders
them, and then they evaporate: the store keeps only `MAX_MEDIA_TRANSCRIPT_ENTRIES = 200` in memory
(`onyx/src/lib/store/store.ts:2430-2431`), nothing reaches the vault, and the search index has
**zero** knowledge of transcripts. So "what did we decide on the standup?" is unanswerable in a
product that already heard the answer. Wiring the transcript log into the existing search index
turns voice from an ephemeral channel into first-class, greppable room memory — a thing text chat
has always had and voice never has.
**Novelty:** differentiated. Adjacent to **F-37** (captions + translation hooks), which this
completes rather than repeats — F-37's capture is done; its *retention and retrieval* are not.
**Implementation home:** server — `src/daemon/transcript.zig` (`TranscriptLog` at `:57`, wired into
the server struct at `src/daemon/server.zig:4151`, constructed at `:4761`) feeding
`src/daemon/search_index.zig` (**559 lines, exists; contains no transcript/caption reference**),
with retention config; client — persist into `src/lib/vault/` and surface via the existing
`src/lib/vault/searchVaultHybrid.ts` + `src/shell/voice/overlays/CaptionsOverlay.tsx` export path.
**Owning agents:** onyx-server-store + onyx-server-media (indexing, retention); onyx-vault + onyx-media (client).
**Complexity:** L · **Target:** 0.7 P1
**Dependencies:** GB-10 (shares the index and its authz gate), GC-09 (transcripts are sensitive at rest).
**Wire/protocol:** no new verb — results ride the **existing registered `SEARCH`** command
(`src/daemon/modules/messaging.zig:68`) with a transcript hit kind. **Authz gate:** a transcript
segment inherits its channel's visibility and must be filtered at the query boundary, fail-closed.
**Consent gate:** retention is opt-in per channel and must be *visibly* indicated while recording —
a room must never silently become a permanent record.

### GB-08 — Zero-Trust Device Attestation
**Pitch:** Every device gets a signed identity the whole mesh can verify; a lost laptop is revoked once, everywhere.
**Scope:** `Both`
**Why game-changing:** E2EE is only as strong as device enrollment. Today the client can sign
(`src/lib/e2ee/deviceSign.ts`, `groupDeviceIdentity.ts`, `keyPinning.ts` all exist) but the daemon
holds no authoritative, mesh-replicated device registry. Attestation makes "which devices can read
my DMs?" answerable and revocable.
**Novelty:** differentiated. **Adjacent to F-61** (key transparency) — F-61 proves *key history*,
this makes the *device set* authoritative and mesh-revocable. Complementary, not duplicate.
**Implementation home:** server new `src/daemon/device_registry.zig` + Undertow replication
(`src/substrate/undertow/`); client `src/lib/e2ee/groupDeviceDirectory.ts`,
`trustedGroupSignerStore.ts` (both exist) + GC-11 surface.
**Owning agents:** onyx-server-crypto-reviewer + zig-coder; onyx-crypto + solidjs-coder.
**Complexity:** L · **Target:** 0.7 P1
**Dependencies:** GB-03 (revocations belong in the ledger), GC-11.
**Wire/protocol:** device records are CRDT **value** writes keyed by shortId + device pubkey.
**Fail-closed:** an unattested device cannot be added to a group seal; a failed seal is an **error**,
never a silent plaintext downgrade. Revocation must survive a mid-USR2 peer (capsule-versioned).

### GB-09 — Rateless History Reconciliation
**Pitch:** Cold-start sync that transfers only what's actually missing, using rateless set reconciliation.
**Scope:** `Both`
**Why game-changing:** A returning client today refetches windows it mostly already has. RIBLT-style
reconciliation makes the transfer proportional to the **symmetric difference**, not the window —
a two-week-old client on a slow link syncs in one round trip instead of dozens.
**Novelty:** category-defining for a chat client's history layer.
**Implementation home:** server `src/substrate/rateless.zig` (**unexposed**, RIBLT) +
`src/substrate/sketch.zig`, new `src/daemon/history_sync.zig`; client `src/lib/vault/vaultSync.ts`
(exists) + `src/lib/vault/historyVault.ts`.
**Owning agents:** zig-coder + onyx-server-store; onyx-vault + solidjs-coder.
**Complexity:** L · **Target:** post-0.7
**Dependencies:** GS-17 (stable IDs are the set elements), GS-12.
**Wire/protocol:** new `SYNC SKETCH` exchange. Old clients keep the existing window fetch — the new
path is strictly opt-in behind a CAP and **byte-identical when off**.

### GB-10 — Semantic Mesh Search
**Pitch:** Search that spans the whole mesh with near-duplicate awareness, fused with local vault results.
**Scope:** `Both`
**Why game-changing:** The client already does hybrid lexical+semantic ranking locally
(`src/lib/vault/searchVaultHybrid.ts`, `searchVaultSemantic.ts`, `embeddingIndex.ts`), but it can
only see what that device stored. A MinHash/LSH shingle index on each node lets the mesh answer
"where was this discussed?" across rooms and nodes, then RRF-fuse with local hits.
**Novelty:** differentiated.
**Implementation home:** server `src/substrate/minhash.zig` (**unexposed**) +
`src/substrate/adaptive_radix_tree.zig`, new `src/daemon/search_index.zig`; client
`src/lib/vault/searchVaultHybrid.ts`, `src/lib/search/rankingBoost.ts`.
**Owning agents:** onyx-server-store + zig-coder; onyx-vault + solidjs-coder.
**Complexity:** L · **Target:** post-0.7
**Dependencies:** GS-02 (index health metrics), GB-09 shares the ID space.
**Wire/protocol:** new `SEARCH` verb with a bounded result envelope. **Authz gate:** the index must
never return a line from a channel the requester cannot see — validation lives at the query
boundary, fail-closed on any ambiguity.

### GB-11 — Adaptive Transport Negotiation
**Pitch:** The client negotiates the best available path — wss, WebTransport, or the native Cadence leg — and switches live.
**Scope:** `Both`
**Why game-changing:** A member on hotel Wi-Fi and a member on fiber should not share one transport
compromise. Live switching means a degrading path is escaped without a reconnect, so the room never
sees a join/part storm from one person's bad network.
**Novelty:** differentiated.
**Implementation home:** server `src/substrate/adaptive_transport.zig`,
`src/substrate/transport_stack.zig`, `src/substrate/multipath.zig`; client `src/lib/net/`.
**Owning agents:** onyx-server-reactor + zig-coder; onyx-irc + solidjs-coder.
**Complexity:** L · **Target:** 0.7 P1
**Dependencies:** GS-15 (congestion control), GS-09 (ICE/PMTUD for the native leg).
**Wire/protocol:** capability advertisement in `005`/CAP; the wire **framing contract is unchanged**
(one message per frame, LF-tolerant) on every transport — that invariant is what makes the switch safe.

### GB-12 — Continuity
**Pitch:** Pick up on another device mid-sentence — scroll position, composer draft, and live call move with you.
**Scope:** `Both`
**Why game-changing:** Phone-to-desktop is the most common real transition in a chat product and
today it's a full cold start. Continuity makes the session a portable object.
**Novelty:** differentiated.
**Implementation home:** server new `src/daemon/continuity.zig` (short-lived, per-account capsule);
client `src/lib/vault/vaultResumeMemory.ts`, `src/lib/catchup/resumePoints.ts` (both exist),
`src/lib/callMediaSession.ts`.
**Owning agents:** zig-coder + onyx-server-helix-reviewer (capsule discipline); solidjs-coder + onyx-store.
**Complexity:** M · **Target:** 0.7 P1
**Dependencies:** GB-08 (only attested devices may claim a session), GC-01.
**Wire/protocol:** new capsule kind with an explicit version range — anything Helix carries needs
capsule-version discipline, and a mid-USR2 peer must tolerate an unknown version by **ignoring it**,
not by erroring the link. Drafts are E2EE-sealed; a failed seal drops the draft rather than sending it.

### GB-13 — Mesh Presence Heatmap
**Pitch:** See where the network is actually alive right now — without exposing anyone's member list.
**Scope:** `Both`
**Why game-changing:** Discovery on a small self-hosted network is hard: rooms look dead because you
can't tell 0 people from 40 idle people. HyperLogLog gives per-channel activity cardinality across
nodes with no per-member disclosure — privacy-preserving discovery.
**Novelty:** differentiated.
**Implementation home:** server `src/substrate/hyperloglog.zig` (**unexposed**), new sketch fields on
the channel record + Undertow replication; client `src/lib/stats/networkIndex.ts`,
`src/shell/ChannelBrowser.tsx` (both exist).
**Owning agents:** onyx-server-mesh + zig-coder; solidjs-coder.
**Complexity:** M · **Target:** 0.7 P1
**Dependencies:** GS-02.
**Wire/protocol:** sketch merge is a CRDT union (idempotent, commutative — no HLC needed for the
merge itself). **Guard rail:** the periodic sketch roll-up is a new periodic task → it must name a
single owning reactor, per the `reactors[0]` pattern at `src/daemon/server.zig:5163`.

### GB-14 — Consent-Gated Unfurl Proxy
**Pitch:** Link previews fetched by the server under an explicit per-user consent, never by the browser.
**Scope:** `Both`
**Why game-changing:** Client-side unfurling leaks the reader's IP to every link they scroll past;
naive server-side unfurling is an SSRF cannon into the operator's private network. The consented
proxy fixes both at once and makes the tradeoff visible to the user.
**Novelty:** incremental in concept, differentiated in that it is consent-gated and SSRF-hardened by design.
**Implementation home:** server new `src/daemon/unfurl.zig` with an `ip_cidr`-based deny list
(`src/substrate/ip_cidr.zig`, unexposed); client `src/lib/preview/unfurlPrivacy.ts`,
`src/lib/preview/linkPreview.ts` (**both exist**).
**Owning agents:** onyx-server-hardener + zig-coder; solidjs-coder + onyx-render.
**Complexity:** M · **Target:** **0.7 P0**
**Dependencies:** GS-03 (shares the policy plane), GS-13 (fetch rate governor).
**Wire/protocol:** new `UNFURL` verb. **Fail-closed:** an unresolvable, private-range, or redirect-looping
target returns *no preview* — never a partial or attacker-controlled one. Preview text renders through
the typed-token path. Default **off**; with consent absent the feature is a no-op.

### GB-15 — Deterministic Replay Bug Reports
**Pitch:** A client bug report the maintainer can *replay* — a redacted event trace fed straight into the DST harness.
**Scope:** `Both`
**Why game-changing:** "It desynced once under load" is the hardest class of bug in this stack and
the least reproducible. Onyx already owns a deterministic simulator; wiring a redacted client trace
into it converts an unreproducible report into a seeded, replayable test case.
**Novelty:** category-defining as a *product* feature (DST as a support channel).
**Implementation home:** server `src/substrate/sim.zig`, `src/substrate/fault_loom.zig`,
`src/substrate/sim_net.zig` (sim/fault_loom **unexposed** outside substrate), new
`tools/replay_report.zig`; client new `src/lib/diagnostics/traceCapture.ts`.
**Owning agents:** onyx-server-dst + zig-coder; solidjs-coder.
**Complexity:** L · **Target:** post-0.7
**Dependencies:** GS-16 (trace format), GS-02.
**Wire/protocol:** none on the live wire — the trace is an out-of-band artifact.
**Privacy invariant:** redaction happens **client-side before export**; message bodies and key
material never enter the trace. This must be reviewed by onyx-crypto before shipping.

---

# Part II — `Server` (20): daemon-only value

### GS-01 — server.zig Strangler
**Pitch:** Decompose the 102,158-line `server.zig` into cohesive modules behind the existing SerpentRegistry shape.
**Scope:** `Server`
**Why game-changing:** Every server feature in this catalog pays a tax to this file: reviews are
slow, blast radius is unknowable, and merge conflicts are constant. Strangling it — moving cohesive
regions into `src/daemon/modules/*.zig` alongside the 13 modules that already live there — is the
highest-leverage server work available.
**Novelty:** incremental (but the top-ranked item, because leverage ≠ novelty).
**Implementation home:** `src/daemon/server.zig` (102,158 lines) → `src/daemon/modules/`
(currently `accounts`, `channel_ops`, `feature_misc`, `introspect`, `ircx`, `manifest`, `messaging`,
`oper_security`, `query_info`, `services_ext`, `upgrade`, `user_query`, `webhook`),
dispatch via `src/daemon/registry.zig` (1,385 lines).
**Owning agents:** zig-coder (lead), onyx-server-ircx + onyx-server-reactor (region reviews).
**Complexity:** XL · **Target:** **0.7 P0** (phased; each phase lands independently)
**Dependencies:** none — it is the dependency.
**Wire/protocol:** **none.** Strict behavior-preserving refactor; any observable wire change is a bug.

### GS-02 — Sketch Telemetry Plane
**Pitch:** Real percentile telemetry — p50/p99/p999 latency, per-command histograms — from modules already in-tree.
**Scope:** `Server`
**Why game-changing:** An operator today cannot answer "is my node slow, and where?" `ddsketch`,
`hdr_histogram`, `tdigest`, `count_min_sketch`, and `metrics` are all built and idle. Exposing them
turns tuning from guesswork into measurement, and unblocks GS-08, GS-15, GS-20.
**Novelty:** incremental. **Overlaps F-39** (deep metrics: histograms, not just counters) — this
entry is F-39's implementation plan, adding the substrate wiring and the multi-reactor merge-owner
design F-39 leaves open.
**Implementation home:** `src/substrate/ddsketch.zig`, `hdr_histogram.zig`, `tdigest.zig`,
`count_min_sketch.zig`, `metrics.zig` (**all 0 external consumers**), new `src/daemon/telemetry.zig`.
**Owning agents:** onyx-server-perf + zig-coder.
**Complexity:** M · **Target:** **0.7 P0**
**Dependencies:** GS-01 (a clean home).
**Guard rail:** the metrics flush is a periodic task → **single owning reactor** (`reactors[0]`
pattern, `src/daemon/server.zig:5163`), or per-reactor sketches merged by one owner. Per-reactor
accumulate + single-owner merge is the recommended shape.

### GS-03 — Class-based Admission Fabric
**Pitch:** One auditable admission policy plane — connection class, CIDR, geo, reputation — replacing scattered checks.
**Scope:** `Server`
**Why game-changing:** Connection **classes already exist as configuration**
(`etc/onyx-server.reference.toml:473-485`, with a global accept-time gate at `:436`) — what's missing
is a single *enforcement and audit* plane behind them. Today an operator cannot answer "why was this
specific connection refused, under which class, by which rule?" The fabric unifies enforcement and
makes every refusal attributable, which is what turns an admission policy into something support can
reason about.
**Novelty:** incremental — this is **re-scoped** from "invent classes" to "unify enforcement +
auditability" after verifying classes ship today. See § Relationship to F-01…F-68.
**Implementation home:** `src/substrate/admission.zig`, `src/substrate/ip_cidr.zig`,
`src/substrate/geoip.zig` (admission + ip_cidr **unexposed**), new `src/daemon/admission_fabric.zig`,
config in `src/daemon/config_format.zig`.
**Owning agents:** onyx-server-warden + onyx-server-config.
**Complexity:** L · **Target:** **0.7 P0**
**Dependencies:** GS-01; prerequisite for GB-06 and GB-14.
**Wire/protocol:** refusal reasons surface as standard-replies (`FAIL`) so the client can explain
them. **Fail-closed:** an unparseable policy refuses to load at boot rather than silently admitting all.

### GS-04 — Roaring Unread Index
**Pitch:** Per-account unread/mention state as compressed bitmaps instead of per-channel scans.
**Scope:** `Server`
**Why game-changing:** Unread computation is O(channels × members) today. Roaring bitmaps make
"what's unread for this account across 400 channels" a bitmap operation — the difference between a
snappy reconnect and a two-second stall on a busy node.
**Novelty:** incremental.
**Implementation home:** `src/substrate/roaring.zig` (**unexposed**), `src/substrate/fenwick.zig`,
consumed by `src/daemon/modules/messaging.zig`.
**Owning agents:** onyx-server-store + onyx-server-perf.
**Complexity:** M · **Target:** 0.7 P1
**Dependencies:** GS-17 (monotonic IDs as bitmap keys).
**Wire/protocol:** none — internal representation only; existing read-marker semantics preserved.

### GS-05 — Scheduled Automation
**Pitch:** Native cron inside the daemon — scheduled topics, recurring announcements, timed unbans, retention jobs.
**Scope:** `Server`
**Why game-changing:** Every operator currently bolts on an external scheduler and a bot account.
`cron.zig` is already built; exposing it means the daemon owns its own maintenance and rooms get
recurring rituals (standups, office hours) without external infrastructure.
**Novelty:** differentiated (in-process, no pseudo-client — consistent with services-as-commands).
**Overlaps F-03** (scheduled operator actions) and **F-52** (scheduled & deferred delivery); F-52
already records that `cron.zig` parses expressions with nothing consuming it. This entry is the
scheduler both need, plus the reactor-ownership and USR2-idempotence contract neither specifies.
**Implementation home:** `src/substrate/cron.zig`, `src/substrate/timer_wheel.zig`,
`src/substrate/timing_wheel.zig`, `src/substrate/scheduler.zig` (**all unexposed**), new
`src/daemon/modules/schedule.zig`.
**Owning agents:** zig-coder + onyx-server-config.
**Complexity:** M · **Target:** 0.7 P1
**Dependencies:** GS-01, GS-12 (schedules must survive restart).
**Guard rail:** **CRITICAL** — a scheduler is the canonical multi-reactor hazard. Exactly one reactor
owns tick dispatch (`rx() == &self.reactors[0]`, per `src/daemon/server.zig:5163`, `:5259`), or every
job fires N times. Jobs must also be idempotent across a USR2 upgrade.

### GS-06 — Rendezvous Channel Homing
**Pitch:** Deterministic, minimal-disruption channel-to-node assignment across the mesh.
**Scope:** `Server`
**Why game-changing:** When a node joins or leaves, naive hashing reshuffles far more channels than
necessary. Rendezvous (HRW) hashing moves only the affected fraction, so mesh topology changes stop
being disruptive events.
**Novelty:** incremental. **Overlaps F-13** (geographic routing hints) and **F-66** (adaptive
shard rebalancing) — this is the hashing mechanism both of them need. Build once, consume twice.
**Implementation home:** `src/substrate/rendezvous_hash.zig`, `src/substrate/consistent_hash.zig`
(**both unexposed**), consumed by `src/substrate/undertow/`.
**Owning agents:** onyx-server-mesh + zig-coder.
**Complexity:** M · **Target:** 0.7 P1
**Dependencies:** GS-11 (breaker informs liveness input).
**Guard rail:** homing input must be **link liveness**, and liveness refresh must **never** be gated
on a newer HLC — HLC governs CRDT *value* convergence only. Conflating them prunes a live peer with
a stale clock.

### GS-07 — S2S Delta Compression
**Pitch:** Range-coded delta compression on mesh links — same convergence, a fraction of the bytes.
**Scope:** `Server`
**Why game-changing:** Gossip is chatty by design. Range coding plus varint framing cuts inter-node
bandwidth substantially, which is what makes a geographically spread self-hosted mesh affordable.
**Novelty:** incremental.
**Implementation home:** `src/substrate/range_coder.zig`, `src/substrate/vlq.zig`,
`src/substrate/undertow/delta_codec` path (range_coder + vlq **unexposed**).
**Owning agents:** onyx-server-mesh + onyx-server-perf.
**Complexity:** M · **Target:** 0.7 P1
**Dependencies:** GS-14 (shares the anti-entropy path).
**Wire/protocol:** S2S-only, negotiated per link. A peer that doesn't advertise it gets uncompressed
frames — **must** interoperate with a mid-USR2 peer running the old codec.

### GS-08 — Adaptive Media FEC
**Pitch:** Loss-adaptive forward error correction that spends redundancy only when the link needs it.
**Scope:** `Server`
**Why game-changing:** Fixed FEC either wastes bandwidth on good links or under-protects bad ones.
Four FEC implementations are already in-tree; driving them from live loss telemetry makes voice
usable on a lossy mobile link without penalizing everyone else.
**Novelty:** differentiated.
**Implementation home:** `src/substrate/raptorq.zig`, `reed_solomon.zig`, `red_fec.zig`,
`fec_window.zig`, `gf256.zig`, driven by `loss_monitor.zig`/`loss_recovery.zig` (raptorq,
reed_solomon, fec_window, gf256, loss_monitor **unexposed**).
**Owning agents:** onyx-server-media + onyx-server-perf.
**Complexity:** L · **Target:** 0.7 P1
**Dependencies:** GS-02 (loss telemetry), GS-15.
**Wire/protocol:** FEC is negotiated on the media plane; redundancy level changes mid-session must
not require renegotiation.

### GS-09 — ICE + PMTUD for the native leg
**Pitch:** Real NAT traversal and path-MTU discovery so the native Cadence transport works behind carrier NAT.
**Scope:** `Server`
**Why game-changing:** Without ICE the native media leg only works on friendly networks; without
PMTUD it silently blackholes on tunnels. Both modules are built and idle — this is what makes the
native leg deployable rather than demo-only.
**Novelty:** incremental (table stakes for the native transport, currently missing).
**Implementation home:** `src/substrate/ice_agent.zig`, `src/substrate/pmtud.zig`,
`src/substrate/turn.zig` (ice_agent + pmtud **unexposed**), consumed by `native_media_plane.zig`.
**Owning agents:** onyx-server-media + zig-coder.
**Complexity:** L · **Target:** 0.7 P1
**Dependencies:** GB-11 (transport negotiation consumes the result).
**Wire/protocol:** candidate exchange over the media EVENT plane; a client without ICE support falls
back to the existing path.

### GS-10 — Media Epoch Keys
**Pitch:** Forward-secret media rekeying on an epoch schedule and on every membership change.
**Scope:** `Server`
**Why game-changing:** A long-running ambient room (GB-02) with one static key means a compromised
key exposes the whole session. Epoch rekeying bounds exposure to one epoch and makes leave events
cryptographically meaningful.
**Novelty:** differentiated.
**Implementation home:** `src/substrate/media_epoch_key.zig` (**unexposed**),
`src/substrate/media_session.zig`, reviewed against `src/crypto/`.
**Owning agents:** onyx-server-crypto-reviewer + onyx-server-media.
**Complexity:** M · **Target:** 0.7 P1
**Dependencies:** GB-02 (its primary consumer), GB-08.
**Wire/protocol:** epoch transitions signal on the media plane. **Fail-closed:** a participant who
misses a rekey is **removed from the session**, never downgraded to the previous epoch. Constant-time
comparison and secure-zero on retired keys are mandatory.

### GS-11 — Link Supervision
**Pitch:** Circuit breakers, EWMA health, and jittered backoff on every S2S link.
**Scope:** `Server`
**Why game-changing:** A sick peer today can be retried aggressively enough to amplify its own
failure into a mesh-wide event. Breakers convert a cascading outage into one isolated degraded node —
the difference between "one server is down" and "the network is down."
**Novelty:** incremental in mechanism, high in operational value.
**Implementation home:** `src/substrate/circuit_breaker.zig`, `src/substrate/backoff.zig`,
`src/substrate/ewma.zig` (**all unexposed**), consumed by `src/substrate/undertow/s2s_peer.zig`.
**Owning agents:** onyx-server-mesh + onyx-server-reactor.
**Complexity:** M · **Target:** **0.7 P0**
**Dependencies:** GS-02 (health signal).
**Guard rail:** breaker state must not be confused with **membership** — an open breaker means "stop
dialing," **not** "prune this peer." Reaping a peer because its breaker opened is the same
false-death class that produced empty NAMES. Also: `require_signed_frames` must remain **fail-closed**
on a keyless node (`src/substrate/undertow/s2s_peer.zig:391`, `:1281`) — no breaker-driven bypass.

### GS-12 — WAL-backed Durable Store
**Pitch:** Write-ahead logging so a crash or a hard kill costs zero committed state.
**Scope:** `Server`
**Why game-changing:** Durability is the floor for GB-03 (ledger), GB-05 (time travel), GB-09
(reconciliation), and GS-05 (schedules). `wal.zig` is built and unused — this is the foundation
those features stand on.
**Novelty:** incremental.
**Implementation home:** `src/substrate/wal.zig` (**unexposed**), `src/substrate/crc32c.zig`,
integrated with the OroStore path.
**Owning agents:** onyx-server-store + zig-coder.
**Complexity:** L · **Target:** 0.7 P1
**Dependencies:** GS-17.
**Guard rail:** WAL replay must be **idempotent** and must interact correctly with Helix USR2 —
state carried across an upgrade needs capsule-version discipline, and a mid-upgrade peer must not
double-apply. Requires DST coverage (onyx-server-dst).

### GS-13 — GCRA Rate Governor
**Pitch:** One principled rate-limiting engine (GCRA leaky bucket) replacing per-site ad-hoc counters.
**Scope:** `Server`
**Why game-changing:** Ad-hoc limits are individually reasonable and collectively unpredictable.
A single governor gives smooth pacing instead of bursty cliffs, and one place to tune and audit.
**Novelty:** incremental.
**Implementation home:** `src/substrate/gcra.zig`, `src/substrate/ratelimit.zig`,
`src/substrate/pacing.zig` (gcra + ratelimit **unexposed**), new `src/daemon/rate_governor.zig`.
**Owning agents:** onyx-server-warden + onyx-server-config.
**Complexity:** M · **Target:** 0.7 P1
**Dependencies:** GS-03; consumed by GB-06 and GB-14.
**Wire/protocol:** limit hits report as standard-replies with retry hints — the client can back off
politely instead of hammering.

### GS-14 — Sparse-Merkle Anti-Entropy
**Pitch:** O(log n) mesh divergence detection instead of proportional-to-dataset comparison.
**Scope:** `Server`
**Why game-changing:** Anti-entropy cost today grows with the dataset, so it gets scheduled
conservatively, so divergence lingers. A sparse Merkle trie makes "are we in sync?" cheap enough to
ask often — divergence gets caught in seconds.
**Novelty:** differentiated.
**Implementation home:** `src/substrate/sparse_merkle.zig`, `src/substrate/merkle_mountain_range.zig`
(sparse_merkle **unexposed**), consumed by `src/substrate/undertow/` anti-entropy.
**Owning agents:** onyx-server-mesh + onyx-server-dst (convergence proofs).
**Complexity:** L · **Target:** 0.7 P1
**Dependencies:** GS-07 (shares the path), GB-03 (shares the tree code).
**Guard rail:** **CRITICAL** — anti-entropy resync is the exact task that must gate on a single
owning reactor. A sibling reactor with no peer links winning the guard is what let stale members
survive past TTL and produced empty NAMES. Copy the `rx() != &self.reactors[0]` guard at
`src/daemon/server.zig:5259`. Requires seeded DST partition-and-heal coverage.

### GS-15 — Modern Congestion Control
**Pitch:** BBR and L4S on the native transport — high throughput without bufferbloat latency.
**Scope:** `Server`
**Why game-changing:** Loss-based congestion control trades latency for throughput, which is exactly
backwards for voice. BBR plus L4S ECN gives a shared link that stays responsive under load.
**Novelty:** differentiated.
**Implementation home:** `src/substrate/bbr.zig`, `src/substrate/l4s.zig`, `src/substrate/cc_cubic.zig`,
`src/substrate/twcc.zig`, `src/substrate/flow.zig` (cc_cubic **unexposed**).
**Owning agents:** onyx-server-media + onyx-server-perf.
**Complexity:** L · **Target:** post-0.7
**Dependencies:** GS-02, GS-09.
**Wire/protocol:** native transport only; wss path unaffected.

### GS-16 — qlog Observability Export
**Pitch:** Structured, standard-shaped transport and event traces an operator can actually analyze.
**Scope:** `Server`
**Why game-changing:** Debugging a media or mesh problem today means reading prose logs. qlog gives
machine-readable traces that tooling can diff, and it is the substrate GB-15 replays.
**Novelty:** incremental. **Overlaps F-42** (OpenTelemetry trace export) and **F-40** (flight-recorder
export on fault) — same plumbing, different exporters. Pick one: qlog suits the transport/media path,
OTel suits the command path. Do not build both exporters before one is proven.
**Implementation home:** `src/substrate/qlog.zig`, `src/substrate/trace.zig`,
`src/substrate/tracing.zig` (trace/tracing **unexposed**), new `src/daemon/observability.zig`.
**Owning agents:** onyx-server-perf + zig-coder.
**Complexity:** M · **Target:** 0.7 P1
**Dependencies:** GS-02.
**Privacy invariant:** traces must be **redaction-aware by construction** — no message bodies, no key
material, no unhashed identifiers. Off by default.

### GS-17 — Durable Monotonic IDs
**Pitch:** Snowflake/ULID message identity that is stable, sortable, and mesh-unique.
**Scope:** `Server`
**Why game-changing:** Stable sortable IDs are the shared prerequisite for unread bitmaps (GS-04),
history reconciliation (GB-09), time travel (GB-05), and the ledger (GB-03). Cheap to build, and
four features are waiting on it.
**Novelty:** incremental.
**Implementation home:** `src/substrate/snowflake.zig`, `src/substrate/ulid.zig`,
`src/substrate/uuid.zig` (snowflake + ulid **unexposed**).
**Owning agents:** zig-coder + onyx-server-store.
**Complexity:** S · **Target:** **0.7 P0**
**Dependencies:** none.
**Wire/protocol:** IDs surface as a message tag. **Guard rail:** the node component must derive from
the mesh **shortId** — never a nick or UID — matching the standing mesh-identity rule.

### GS-18 — Mesh ACL Filters
**Pitch:** Each node publishes a compact probabilistic filter of its ban/ACL set, so any node can ask "might this mask be banned elsewhere?" without shipping ban lists.
**Scope:** `Server`
**Why game-changing:** Cross-node ban awareness today means either replicating full ban lists (bytes
and privacy cost that grows with the network) or not knowing. An xor/cuckoo filter is a few KB for
tens of thousands of entries, so every node can pre-screen a connecting mask against the *whole
mesh* in constant space and fetch the authoritative record only on a filter hit. A ban evader
hopping nodes gets caught at the door instead of after the damage.
**Novelty:** differentiated. **No F-item equivalent** — F-20 is operator-initiated ban *import with
attribution*; this is an automatic, space-efficient mesh-wide pre-screen.
**Implementation home:** `src/substrate/xor_filter.zig`, `src/substrate/cuckoo_filter.zig`,
`src/substrate/bloom.zig` (**all 0 external consumers — verified**), new
`src/daemon/mesh_acl_filter.zig`, replicated over `src/substrate/undertow/`.
**Owning agents:** onyx-server-warden + onyx-server-mesh.
**Complexity:** M · **Target:** 0.7 P1
**Dependencies:** GS-07 (filters ride the S2S delta path); complements F-20 rather than replacing it.
**Guard rail:** a filter is **probabilistic** — a hit is a *hint*, never a verdict. The
authoritative record must always be fetched before any enforcement action, or a false positive
becomes a wrongful ban. Filters must not leak the ban *set*: publish the filter, never the preimages.
**Fail-closed caveat:** if the authoritative fetch fails, the correct behavior is to **admit and log**
(fail-open on the *hint*), because the filter alone cannot justify a refusal — this is the one place
in the catalog where fail-closed would be wrong, and it is deliberate.

### GS-19 — Lock-free Hot Maps
**Pitch:** EBR/RCU-protected concurrent maps for the hottest lookup paths.
**Scope:** `Server`
**Why game-changing:** As reactor count grows, shared-map contention becomes the scaling ceiling.
Epoch-based reclamation gives readers a lock-free path — the change between scaling to 4 reactors and
scaling to 16.
**Novelty:** differentiated.
**Implementation home:** `src/substrate/ebr.zig`, `src/substrate/rcu_map.zig`,
`src/substrate/robin_hood.zig`, `src/substrate/string_intern.zig` (rcu_map, robin_hood,
string_intern **unexposed**).
**Owning agents:** onyx-server-reactor + onyx-server-perf.
**Complexity:** L · **Target:** post-0.7
**Dependencies:** GS-01, GS-02 (measure before and after).
**Guard rail:** ABA and memory-ordering are the failure classes here — every claim needs a
happens-before argument, and reclamation must be proven safe under DST, not asserted.

### GS-20 — Playout Discipline
**Pitch:** Adaptive jitter buffering, packet-loss concealment, and simulcast layer selection that actually adapt.
**Scope:** `Server`
**Why game-changing:** The difference between "voice works" and "voice feels good" is almost entirely
playout: a jitter buffer that tracks the network, PLC that hides a lost frame, and layer selection
that drops video before it drops audio. All three modules exist and are idle.
**Novelty:** incremental.
**Implementation home:** `src/substrate/jitter_buffer.zig`, `src/substrate/plc.zig`,
`src/substrate/playout_clock.zig`, `src/substrate/simulcast_select.zig`, `src/substrate/audio_mix.zig`
(jitter_buffer, plc, playout_clock, audio_mix **unexposed**).
**Owning agents:** onyx-server-media + onyx-server-perf.
**Complexity:** L · **Target:** 0.7 P1
**Dependencies:** GS-02, GS-08.
**Wire/protocol:** none new — feedback rides existing RTCP/TWCC paths.

---

# Part III — `Client` (15): SPA-only value

The onyx client is already mature — PWA (`src/pwa/`), message and member windowing
(`src/shell/MessageView.tsx`, `src/shell/memberWindow.ts`), a deep E2EE group stack
(24 files under `src/lib/e2ee/`), hybrid vault search, and a WASM media codec worker all exist.
These 15 are therefore either **structural** (the store monolith, the missing sandbox) or
**surfaces over capability the client already has but doesn't expose**.

### GC-01 — store.ts Strangler
**Pitch:** Break the 18,389-line store into domain facades without changing a single reactive read.
**Scope:** `Client`
**Why game-changing:** `src/lib/store/store.ts` is 18,389 lines — the client's velocity ceiling.
Domain facades (rooms, messages, presence, media, prefs) make every other client entry cheaper and
make a slice independently testable.
**Novelty:** incremental (ranked #4 for leverage).
**Implementation home:** `src/lib/store/store.ts` → `src/lib/store/domains/*.ts` behind the existing
`useStore` bridge.
**Owning agents:** onyx-store (lead) + solidjs-coder.
**Complexity:** XL · **Target:** **0.7 P0** (phased, one domain per phase)
**Dependencies:** none — it is the dependency for GB-01, GB-12, GC-04, GC-12, GC-13.
**Guard rail:** the reactivity contract is the whole risk. Reads stay through `useStore`; writes stay
immutable `set()`; `getState()` remains a **non-reactive snapshot**; **never destructure props**.
A facade that leaks a live object or turns a reactive read into a snapshot is a silent regression —
each phase needs component tests proving re-render behavior is unchanged.

### GC-02 — Extension Sandbox Host
**Pitch:** Run third-party client extensions in a real isolation boundary — worker/iframe, explicit permissions, no DOM reach.
**Scope:** `Client`
**Why game-changing:** `src/lib/extensions/` ships `manifest.ts` and `clientActions.ts` but there is
**no isolation host** (verified: no sandbox/iframe usage under `src/lib/extensions/`). Shipping
extensions without a sandbox means any extension is same-origin code with full store and DOM access.
The sandbox must land **before** the ecosystem, not after.
**Novelty:** differentiated.
**Implementation home:** `src/lib/extensions/manifest.ts`, `clientActions.ts` (exist) + new
`src/lib/extensions/sandboxHost.ts`, `permissions.ts`.
**Owning agents:** onyx-render (the sink) + solidjs-coder + onyx-crypto (permission review).
**Complexity:** L · **Target:** **0.7 P0**
**Dependencies:** GB-04 shares the permission vocabulary.
**Guard rail:** **CRITICAL** — this is an XSS/privilege boundary. Extension-provided content routes
parse → typed tokens → JSX text nodes; **never** `innerHTML`/`dangerouslySetInnerHTML`. Permissions
are deny-by-default, per-capability, and revocable. No `postMessage` handler accepts unvalidated shapes.

### GC-03 — Vault Worker Offload
**Pitch:** Move embedding, indexing, and hybrid search off the main thread so search never janks the UI.
**Scope:** `Client`
**Why game-changing:** The vault stack (`embeddingIndex.ts`, `searchVaultSemantic.ts`,
`searchVaultHybrid.ts`) is compute-heavy and today competes with rendering — the client only uses
workers for media (`OpcodecWasm.ts`, `MediaEngine.ts`). Offloading makes search-while-scrolling
smooth on a mid-range laptop.
**Novelty:** incremental.
**Implementation home:** `src/lib/vault/embeddingIndex.ts`, `searchVaultSemantic.ts`,
`searchVaultHybrid.ts` + new `src/lib/vault/vaultWorker.ts`.
**Owning agents:** onyx-vault + onyx-perf.
**Complexity:** M · **Target:** 0.7 P1
**Dependencies:** GC-01 (clean store boundary for results).
**Guard rail:** worker results must be immutable snapshots folded back via `set()` — no shared
mutable structure across the boundary. Measure before/after; no regression in first-result latency.

### GC-04 — Composer Command Surface
**Pitch:** A composable command and macro layer — chain actions, save them, bind them to keys.
**Scope:** `Client`
**Why game-changing:** Power users currently repeat multi-step moderation and navigation by hand.
A macro layer over the existing command palette turns a five-step ban-and-document ritual into one
keystroke, which is the difference between a moderator burning out and not.
**Novelty:** differentiated.
**Implementation home:** `src/lib/commands/`, `src/lib/composer/`, `src/lib/keyboard/` (all exist) +
new `src/lib/commands/macros.ts`.
**Owning agents:** onyx-cmdk + solidjs-coder.
**Complexity:** M · **Target:** 0.7 P1
**Dependencies:** GC-01.
**Guard rail:** a macro is **user-authored input** — it must not become an injection vector into the
IRC wire. Each expanded step re-validates at the send boundary; CR/LF in an expansion is rejected,
never forwarded.

### GC-05 — Offline-First Outbox
**Pitch:** Compose, react, and moderate offline; everything reconciles with visible conflict resolution on reconnect.
**Scope:** `Client`
**Why game-changing:** The pieces exist (`outboxStatus.ts`, `outboxFlushDecision.ts`,
`persistentStorage.ts`, and a real service worker under `src/pwa/`) but there is no end-to-end
offline story. On a train or in a basement, Onyx should feel like a local app that syncs, not a dead tab.
**Novelty:** differentiated.
**Implementation home:** `src/lib/vault/outboxStatus.ts`, `outboxFlushDecision.ts`,
`src/pwa/serviceWorkerRuntime.ts` (all exist) + new `src/lib/vault/outboxReconcile.ts`.
**Owning agents:** onyx-vault + solidjs-coder + onyx-store.
**Complexity:** L · **Target:** 0.7 P1
**Dependencies:** GC-01; pairs with GB-09.
**Guard rail:** **E2EE fails closed** — a queued DM whose seal fails on flush is surfaced as an
error, never sent in plaintext. Replayed sends must be idempotent (needs GS-17's stable IDs to
dedupe server-side).

### GC-06 — Render Budget Governor
**Pitch:** A frame-budget scheduler that keeps the UI at 60fps by deferring non-critical work under load.
**Scope:** `Client`
**Why game-changing:** During a raid or a busy channel, message churn, presence updates, and unfurls
all compete for the same frame. A governor prioritizes the visible message list and defers the rest,
so the worst moment on the network is not also the worst moment in the UI.
**Novelty:** differentiated.
**Implementation home:** `src/shell/MessageView.tsx`, `src/shell/memberWindow.ts` (windowing exists) +
new `src/lib/perf/renderBudget.ts`.
**Owning agents:** onyx-perf + solidjs-coder.
**Complexity:** M · **Target:** 0.7 P1
**Dependencies:** GC-01.
**Guard rail:** deferral must never drop a **correctness** update (membership, E2EE state) — only
cosmetic ones. Animation stays on compositor-friendly properties (transform/opacity). Baseline
against `docs/ui-performance-baseline.json`.

### GC-07 — Formation Mode
**Pitch:** Full keyboard-modal navigation — reach any room, member, or action without a pointer.
**Scope:** `Client`
**Why game-changing:** `src/lib/formation/` exists (`formationLoop.ts`, `formationMemory.ts`) but
isn't a complete modal system. Finishing it serves both power users and anyone who cannot use a mouse
— the same work, two audiences.
**Novelty:** differentiated.
**Implementation home:** `src/lib/formation/`, `src/lib/keyboard/` + `src/shell/` overlays.
**Owning agents:** onyx-cmdk + onyx-a11y + solidjs-coder.
**Complexity:** M · **Target:** 0.7 P1
**Dependencies:** GC-04 (shares the action registry).
**Guard rail:** focus management is the correctness surface — every overlay traps focus, restores it
on close, and honors `Escape`. Modal mode must be discoverable and escapable, never a trap.

### GC-08 — Accessibility Conformance
**Pitch:** A real WCAG 2.2 AA pass — live regions, forced-colors, reduced-motion, focus visibility — verified not asserted.
**Scope:** `Client`
**Why game-changing:** `src/lib/a11y/` and `src/shell/AccessibilityStatement.tsx` exist, so the
intent is there; conformance is what turns intent into a product a screen-reader user can actually
run all day. It is also the credibility floor for GB-07's captions.
**Novelty:** incremental (and non-negotiable).
**Implementation home:** `src/lib/a11y/`, `src/shell/*.tsx`, `src/shell/AccessibilityStatement.tsx`.
**Owning agents:** onyx-a11y (lead) + solidjs-coder.
**Complexity:** M · **Target:** **0.7 P0**
**Dependencies:** GB-07, GC-07.
**Guard rail:** the message log is an `aria-live` region — history replay, windowing, and time travel
(GB-05) must **not** re-announce the transcript. Live-region scoping is the specific bug class to test.

### GC-09 — Theme Studio
**Pitch:** User-authored themes on the OKLCH palette factory, with automatic AA contrast enforcement.
**Scope:** `Client`
**Why game-changing:** The OKLCH factory can already generate perceptually uniform palettes; exposing
it lets users theme the client without producing an unreadable result, because the studio refuses to
ship a palette that fails contrast. Personalization without an accessibility regression.
**Novelty:** differentiated.
**Implementation home:** `src/lib/theme/`, `src/lib/color/`, `src/shell/AppearancePanel.tsx` (exists)
+ new `src/shell/ThemeStudio.tsx`.
**Owning agents:** onyx-theme + onyx-a11y (the AA gate) + solidjs-coder.
**Complexity:** M · **Target:** 0.7 P1
**Dependencies:** GC-08.
**Guard rail:** every generated pair is machine-verified for AA before it can be applied; forced-colors
mode must still override cleanly. Custom CSS (`src/lib/customCssRemoval.ts` exists) stays sandboxed.

### GC-10 — Provenance-Labeled Translation
**Pitch:** On-device translation with honest provenance — always clear what was machine-translated and by what.
**Scope:** `Client`
**Why game-changing:** `src/lib/intelligence/` already has `translateMessage.ts`, `localLanguage.ts`,
and `provenance.ts` — the ethics infrastructure is there ahead of the surface. Shipping it with
visible provenance makes a multilingual room workable without pretending a machine translation is the
speaker's words.
**Novelty:** differentiated (the provenance labeling, not the translation).
**Implementation home:** `src/lib/intelligence/translateMessage.ts`, `provenance.ts`,
`localLanguage.ts`, `src/shell/AiPolicyBadge.tsx` (all exist).
**Owning agents:** solidjs-coder + onyx-render + onyx-a11y.
**Complexity:** M · **Target:** 0.7 P1
**Dependencies:** GC-03 (worker offload — translation must not jank).
**Guard rail:** translated text is **new renderable content** → typed-token path only. On-device by
default; any network path must be explicit user consent, never silent.

### GC-11 — Trust Center
**Pitch:** One panel answering "who can read this, on which devices, verified how?" — with real verification actions.
**Scope:** `Client`
**Why game-changing:** The client has a serious E2EE stack (24 files: `groupTrustStore.ts`,
`keyPinning.ts`, `trustedGroupSigner.ts`, `groupDeviceDirectory.ts`, …) whose state is largely
invisible. Trust Center turns cryptography into something a user can inspect and act on — and it is
the host surface for GB-03's proofs and GB-08's device list.
**Novelty:** differentiated.
**Implementation home:** `src/lib/e2ee/groupTrustStore.ts`, `keyPinning.ts`, `trustedGroupSigner.ts`,
`groupDeviceDirectory.ts`, `dmPrivacyChrome.ts` (all exist) + new `src/shell/TrustCenter.tsx`.
**Owning agents:** onyx-crypto (lead) + solidjs-coder + onyx-a11y.
**Complexity:** M · **Target:** 0.7 P1
**Dependencies:** GB-03, GB-08 both surface here.
**Guard rail:** never render "verified" for an unverified state — unknown renders as **unknown**.
Pin mismatch is a loud, blocking warning, not a toast. Fail-closed in the UI as in the cipher.

### GC-12 — Multi-Network Workspace
**Pitch:** Several networks and identities side by side, with correctly isolated state and one unified inbox.
**Scope:** `Client`
**Why game-changing:** Self-hosting means people belong to *several* small networks — a work mesh, a
friends' mesh, a public one. Today that's several tabs and several logins. A workspace switcher makes
the federated reality first-class.
**Novelty:** differentiated.
**Implementation home:** `src/lib/store/` (needs GC-01's domains), `src/lib/identity/`,
`src/lib/credentials.ts`, `src/lib/net/` (all exist) + new `src/lib/workspace/`.
**Owning agents:** onyx-store (lead) + solidjs-coder + onyx-irc.
**Complexity:** L · **Target:** post-0.7
**Dependencies:** **GC-01 is a hard prerequisite** — multi-network on an 18k-line singleton store is
not tractable.
**Guard rail:** **CRITICAL** — cross-network state leakage is a privacy incident. Vault namespaces,
E2EE keyrings, and credentials must be strictly partitioned per network with no shared mutable
singleton. Also: **PREFIX is learned per-network from `005`** — the server advertises the exotic
`PREFIX=(YQqov)*!.@+` (`src/lib/irc/parser.ts:290,293`), so prefix tables must be per-connection,
never global.

### GC-13 — Catch-Up Digest v2
**Pitch:** One ranked cross-room "what you missed" briefing instead of forty unread badges.
**Scope:** `Client`
**Why game-changing:** `src/lib/catchup/` already has `summary.ts`, `homeInbox.ts`, `resumePoints.ts`,
`markCaughtUp.ts`. v2 makes it a genuinely ranked digest — mentions, threads you spoke in, rooms you
care about, deduped — which is what makes returning after a week feel possible instead of hopeless.
**Novelty:** differentiated.
**Implementation home:** `src/lib/catchup/summary.ts`, `homeInbox.ts`, `resumePoints.ts`,
`src/shell/CatchUpSummary.tsx` (all exist).
**Owning agents:** solidjs-coder + onyx-store.
**Complexity:** M · **Target:** 0.7 P1
**Dependencies:** GC-01; benefits from GS-04 (server-side unread bitmaps).
**Guard rail:** ranking reads must be reactive-correct — a digest computed from a `getState()`
snapshot goes stale silently. Digest content renders through the typed-token path.

### GC-14 — Media Room UX
**Pitch:** A spatial, legible call surface — position peers on a pad, always know who's speaking, captions in place.
**Scope:** `Client`
**Why game-changing:** `spatialAudio.ts`, `activeSpeaker.ts`, and `connectionQualityAction.ts` all
exist under `src/lib/cadence-media/` but the surface doesn't fully express them. Spatial positioning
makes a 10-person call intelligible in a way a grid of tiles never does.
**Novelty:** differentiated. **Client half of F-34** (spatial audio rooms) — F-34 is the server
capability, this is the surface that makes it legible.
**Implementation home:** `src/lib/cadence-media/spatialAudio.ts`, `activeSpeaker.ts`,
`connectionQualityAction.ts`, `src/shell/CallsHub.tsx` (all exist).
**Owning agents:** onyx-media + onyx-ui + onyx-a11y.
**Complexity:** M · **Target:** 0.7 P1
**Dependencies:** GB-07 (captions land here), GB-02 (ambient presence renders here).
**Guard rail:** spatial audio must degrade to plain stereo under reduced-motion / assistive settings;
every spatial action needs a keyboard equivalent (GC-07).

### GC-15 — Portability Suite
**Pitch:** A guided migration wizard — bring your history in, take everything out, verify the round trip.
**Scope:** `Client`
**Why game-changing:** The credibility of self-hosting is exit rights. `src/lib/import/`,
`src/lib/export/`, `portableTransfer.ts`, `portableCompression.ts`, `portableShare.ts`,
`parseVaultExport` all exist — a wizard that proves the round trip converts "your data is yours" from
a claim into a demonstrable operation.
**Novelty:** differentiated.
**Implementation home:** `src/lib/import/`, `src/lib/export/`, `src/lib/vault/portableTransfer.ts`,
`portableCompression.ts`, `portableImportLock.ts`, `portableFileSave.ts` (all exist) + a wizard shell.
**Owning agents:** onyx-vault + solidjs-coder.
**Complexity:** M · **Target:** 0.7 P1
**Dependencies:** GC-01, GC-12 (per-network export scoping).
**Guard rail:** **an export is a plaintext extraction of E2EE content** — it must be explicitly
consented, clearly labeled, and offered encrypted-at-rest by default. Import is an **untrusted-input
parser**: bounded, fail-closed, never trusted to be well-formed
(`src/lib/vault/parseVaultExport.pure.test.ts` is the existing seam).

---

## Deploy order (the cross-repo rule)

Any wire-affecting entry deploys **client-first** — onyx is the live consumer, so the client must
tolerate a server that doesn't yet speak the new thing before the server starts speaking it.

```
Phase A  server-internal only, zero wire change
         GS-01  GS-02  GS-04  GS-11  GS-12  GS-14  GS-19  GS-16
Phase B  client-internal only, zero wire change
         GC-01  GC-02  GC-03  GC-04  GC-06  GC-07  GC-08  GC-09  GC-13  GC-15
Phase C  client learns the new CAP/verb but does not require it   ← CLIENT SHIPS FIRST
         GB-07  GB-14  GB-06  GB-03  GB-13  GB-12
Phase D  server begins emitting; feature is byte-identical when the CAP is absent
         (same IDs as Phase C, server half)
Phase E  post-0.7 heavy lifts
         GB-01  GB-04  GB-05  GB-09  GB-10  GB-15  GC-12  GS-15  GS-19
```

## Build order (dependency-respecting)

1. **Foundations first:** GS-01 + GC-01 (the two monoliths) and GS-17 (stable IDs — S-sized and four
   features wait on it). Nothing else is efficient before these.
2. **Observability + safety:** GS-02, GS-03, GS-11, GS-13. You cannot tune or defend blind.
3. **0.7 P0 product wins:** GB-07 (captions — nearly free), GB-14 (unfurl privacy), GB-06 (raid
   shield), GC-02 (sandbox), GC-08 (a11y).
4. **Durability, then the features that need it:** GS-12 → GB-03, GS-05, GB-05, GB-09.
5. **Media depth:** GS-20, GS-08, GS-09, GS-10 → GB-02, GC-14.
6. **Post-0.7 category bets:** GB-01 (Loom), GB-04 (Programmable Rooms), GB-09, GB-10, GB-15, GC-12.

## Risks (severity-tagged)

| Sev | Risk | Concrete failure | Owning entries |
|---|---|---|---|
| **CRITICAL** | Multi-reactor timer fan-out | A new periodic task (scheduler, anti-entropy, raid sweep, sketch roll-up) doesn't gate on one owning reactor; a sibling with no peer links wins the guard and does nothing → stale peers reaped after TTL → empty NAMES, missing remote oper prefix, 401 on cross-node PRIVMSG | GS-05, GS-14, GB-06, GB-13, GS-02 |
| **CRITICAL** | Client XSS sink | Extension, room-app, caption, translation, or digest content reaches `innerHTML` instead of the typed-token → JSX path → stored XSS with full same-origin access | GC-02, GB-04, GB-07, GC-10, GC-13 |
| **CRITICAL** | Cross-network state leak | Multi-network on a shared singleton store leaks vault entries, keyrings, or credentials between networks → privacy incident | GC-12 |
| **CRITICAL** | E2EE silent downgrade | An offline-queued or continuity-carried DM whose seal fails is sent in plaintext instead of erroring | GC-05, GB-12, GB-08 |
| **HIGH** | Roster replace-vs-append | Replay- or time-travel-driven `353` frames REPLACE the roster instead of APPENDing → the production `#root`-collapsed-to-2-members class | GB-05, GB-13 |
| **HIGH** | HLC liveness/value conflation | A liveness refresh gated on a newer HLC prunes a live peer with a stale clock | GS-06, GS-11, GB-13 |
| **HIGH** | Reactivity regression in the strangler | A store facade returns a `getState()` snapshot where a reactive read was expected → silently stale UI, no error | GC-01 |
| **HIGH** | Mid-USR2 / old-peer incompatibility | A new capsule kind or S2S codec has no version range → a mid-upgrade peer errors the link instead of ignoring the unknown | GB-12, GS-07, GS-12 |
| **HIGH** | Fail-open security branch | Any new path that limps on unsigned/keyless instead of refusing (`require_signed_frames` is fail-closed at `src/substrate/undertow/s2s_peer.zig:391`, `:1281` — keep it that way) | GS-11, GS-03, GB-08 |
| **MEDIUM** | Algorithmic-complexity DoS | Unbounded index or filter compiles from operator/peer-supplied data become a CPU or memory exhaustion vector | GB-10, GS-18 |
| **MEDIUM** | Probabilistic filter mistaken for a verdict | A mesh ACL filter hit is treated as proof and enforced without fetching the authoritative record → wrongful ban from a false positive | GS-18 |
| **MEDIUM** | Telemetry privacy | qlog / replay traces carry message bodies or unhashed identifiers | GS-16, GB-15 |
| **MEDIUM** | Strangler churn | GS-01/GC-01 conflict with every concurrent feature branch; needs strict phase serialization | GS-01, GC-01 |
| **LOW** | Substrate drift | Long-idle modules may need API updates for current Zig before wiring | most GS entries |

**Rollback posture:** every `Both` entry is CAP- or config-gated and **byte-identical when off**, so
rollback is disabling the gate, not reverting code. The two stranglers are the exception — they are
behavior-preserving refactors whose rollback is per-phase revert, which is why they must land in
small independently-gated phases rather than one merge.

## Design verdict

**GO for the 0.7 P0 set** (GS-01, GS-02, GS-03, GS-11, GS-17, GB-06, GB-07, GB-14, GC-01, GC-02,
GC-08) — no unresolved CRITICAL, and every CRITICAL row above has a named owning entry and a cited
guard to copy.

**REVISE / design-before-code** for GB-01, GB-04, GB-05, GB-09, GC-12 — each carries an open HIGH or
CRITICAL that must be closed in a dedicated blueprint first (CRDT authority model, WASM permission
model, replay roster semantics, reconciliation ID space, network partitioning).

**Confidence:**

- **CONFIRMED** — the "already exists / 0-external-consumers" claims. Verified by consumer count and
  `file:line` at HEAD, not from memory.
- **CONFIRMED** — the F-01…F-68 overlap table. Every declared overlap was read in
  `INVENTED-FEATURES-CATALOG.md`, and three of this document's original premises were **falsified
  and corrected** during that pass (content matching, admission classes, server-side captions). One
  entry (GS-18) was replaced outright because its premise was false.
- **PLAUSIBLE** — complexity ratings and release targets. These are architectural judgment, not
  measurement. Every XL entry (GS-01, GC-01, GB-01, GB-04) deserves its own blueprint before a
  coder starts; do not treat an XL row here as a spec.
- **NOT CHECKED** — whether each long-idle substrate module still compiles against current Zig. The
  modules exist and are tested in-tree, but API drift after a long period without callers is a real
  possibility and is the first thing to verify when wiring one up.

---

*Companion copy: `/home/kain/onyx/docs/features/GAME-CHANGERS-50.md` (client-focused intro, same catalog).*
