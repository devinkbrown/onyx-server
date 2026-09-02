# Onyx Server roadmap — Q4 2026 → 0.7

**Audience: contributor and maintainer.** The engineering roadmap for the daemon,
organized as a **feature spine in four waves** plus three **release tracks**
(performance, hardening, polish) that cut across every wave. Ambitious about
where the stack goes; honest about what is in the tree today.

Current daemon version: **0.5.8** (`build.zig.zon:18`). The target of this
document is **0.7.0**.

## What 0.7 is

0.5.x has been a *capability* series: TLS 1.3 + ECH + PQ verify, the Undertow
mesh, Helix USR2, OCG2 staging, group E2EE authority, a media plane with live
DTLS terminators. The tree is **842 Zig files / ~590k lines**, and almost every
subsystem listed in Waves 1–4 below already has a substantial kernel in it.

0.7 is deliberately **not** another capability series. It is the release where
the daemon stops growing outward and gets *measured, proven, and finished*:


| Track           | Prefix | Question it answers              | Why it is 0.7                                                                                                   |
| --------------- | ------ | -------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| **Feature**     | `S-xx` | What can the daemon do?          | Close the half-activated subsystems (OCG2, group E2EE, DST) rather than open new ones.                          |
| **Performance** | `P-xx` | What does it cost?               | There is **no** `bench` **step in** `build.zig` — every performance claim in this repo is currently unmeasured. |
| **Hardening**   | `H-xx` | What breaks it?                  | The adversarial corpus is 45 tests; coverage-guided fuzzing is blocked upstream; DST has no build step.         |
| **Polish**      | `L-xx` | Can a human use and maintain it? | `src/daemon/server.zig` is **102,152 lines**; `HELP` covers **6 topics** against **159 registered commands**.   |


The four tracks are ordered by how much they gate a release, not by how
interesting they are. **A 0.7 that ships new features without the P/H/L tracks
is a 0.6.** [§ 0.7 exit criteria](#07-exit-criteria) at the end of this file is
the actual ship gate.

Companion: **[onyx](../../onyx/docs/ROADMAP-2026-Q4.md)** `docs/ROADMAP-2026-Q4.md` — the
client half. Items whose wire contract spans both repos are listed once in each
file and reconciled in [§ Cross-cutting](#cross-cutting-server--client-wire-contracts).
The unified per-release view across both repos is
`[releases/0.7-ROADMAP.md](releases/0.7-ROADMAP.md)`.

This roadmap does **not** supersede the existing planning documents; it sits
above them and points into them:

- `[dev/tls-roadmap.md](dev/tls-roadmap.md)` — the phase-by-phase Armor TLS gap analysis with DONE/TODO status. Still the authority for TLS item detail.
- `[design/e2ee-everywhere-blueprint.md](design/e2ee-everywhere-blueprint.md)` — group/channel E2EE design.
- `[research/exploit-suite-blueprint.md](research/exploit-suite-blueprint.md)` — the intended shape of the adversarial corpus.
- `[audit/CODEBASE_AUDIT_2026-07-18.md](audit/CODEBASE_AUDIT_2026-07-18.md)` — the last full codebase audit.

Those are **design intent and gap analysis**. Where they disagree with
`[reference/](reference/)` or with the source, the source wins.

## How to read an item

- **Priority** — `P0` ship-blocking · `P1` this wave · `P2` scheduled · `P3` opportunistic.
- **Subsystem** — the owning source area. One item, one owner.
- **Client** — `none` (daemon-internal), `gated` (a client can already consume
it), or `contract` (needs a coordinated wire change — see § Cross-cutting).
- **Accept** — the observable condition that closes the item, expressed as a test
or a runtime proof.

Items in the P/H/L release tracks carry three additional fields, because those
tracks are scheduled rather than aspirational:

- **Owner** — the agent that does the work. One item, one owner agent. The
daemon's implementer of record is `zig-coder`; crypto/TLS substrate work is
`armor-tls` (implement) and `onyx-server-crypto-reviewer` (review-only); mesh
is `onyx-server-mesh` / `onyx-server-mesh-reviewer`; the reactor and hot path
are `onyx-server-reactor` (correctness) and `onyx-server-perf` (cost);
adversarial corpus work is `onyx-server-hardener`; seeded simulation is
`onyx-server-dst`; Helix capsules are `onyx-server-helix-reviewer`; config is
`onyx-server-config`; the command surface is `onyx-server-ircx`; the media
plane is `onyx-server-media`; anti-abuse engines are `onyx-server-warden`;
documentation is `doc-writer`. See `~/.claude/agents/ROSTER.md`.
- **Complexity** — `S` (≤ 1 focused change) · `M` (a subsystem, multi-file) ·
`L` (cross-subsystem, needs a design pass) · `XL` (multi-release; the item
here is the 0.7 slice only).
- **Gate** — the exact command that proves the item, from `build.zig`. "Passes
`zig build test`" is not a gate; the focused lane plus a named new test is.

Waves are ordered by dependency. Nothing in **Next** should start before its
**Now** prerequisites land. The P/H/L tracks are **not** waves — they run
alongside, and several of them (P-01, H-01, L-01) are prerequisites for
*measuring* whether a wave item actually landed.

## Index

**Feature spine** — what the daemon can do.


| Wave                          | Theme                                                     | Items       |
| ----------------------------- | --------------------------------------------------------- | ----------- |
| [Now](#wave-1--now)           | Assurance you can trust, OCG2 past observe, mesh liveness | S-01 … S-09 |
| [Next](#wave-2--next)         | E2EE authority, TLS finishing work, media selection       | S-10 … S-18 |
| [Later](#wave-3--later)       | Multi-node scale, storage, continuity                     | S-19 … S-25 |
| [Moonshot](#wave-4--moonshot) | PQ signing, standards interop, autonomous operation       | S-26 … S-30 |


**Release tracks** — what 0.7 adds on top of the spine.


| Track                                | Theme                                                                           | Items       |
| ------------------------------------ | ------------------------------------------------------------------------------- | ----------- |
| [Performance](#track-p--performance) | Measurement first, then the reactor, ConnState, fan-out, and crypto hot paths   | P-01 … P-12 |
| [Hardening](#track-h--hardening)     | Corpus, fuzzing, simulation, and the fail-closed invariants                     | H-01 … H-10 |
| [Polish](#track-l--polish)           | `server.zig` decomposition, `HELP`, command metadata, operator ergonomics, docs | L-01 … L-12 |


---



## Wave 1 — Now

The theme is **make the assurance story real, and finish the subsystems that are
deliberately parked in a half-activated state.** Three items below are about
proof rather than features, and they are first on purpose: this is a
from-scratch TLS stack, a from-scratch CRDT mesh, and a from-scratch hot-upgrade
path, and each one's blast radius is the whole daemon.

### S-01 — Consolidate the adversarial exploit corpus

**P0** · `src/`, `build.zig` · **client: none**

`zig build test-exploit` (alias `test-attack`) exists and runs a filter on
`"exploit:"` (`build.zig:302-311`). It currently selects **45** tests spread
across at least ten modules — `substrate/undertow/s2s_peer.zig`, `route_table.zig`,
`burst.zig`, `daemon/flood_guard.zig`, `daemon/server.zig`, `proto/names_reply.zig`,
`proto/sasl_mechrouter.zig`, `proto/irc_line.zig`, `proto/membership_event.zig`,
`proto/color_strip.zig`.

`[research/exploit-suite-blueprint.md](research/exploit-suite-blueprint.md)`
specifies a dedicated `src/security/exploit/` tree with a harness. **That
directory does not exist.** The corpus is real but structurally scattered, which
means nobody can answer "what attack classes are covered?" without grepping.

**Accept:** a corpus index — either the blueprint's tree or an equivalent
manifest — that names each attack class, its coverage, and its gaps. The
`test-exploit` count is reported per class, not as one number. Adding an
unclassified exploit test fails the gate.

### S-02 — Multi-reactor timer-guard audit

**P0** · `src/daemon/server.zig` · **client: none**

`onTimerTick` (`src/daemon/server.zig:6170`) runs on **every** reactor thread.
Shared-state maintenance must gate on reactor zero. Two spellings of the guard
are in use, and both are load-bearing:

- **Early return** — `if (self.rx() != &self.reactors[0]) return;` at
`src/daemon/server.zig:5163`, `:5259`, and `:6144`.
- **Inline conjunction** — `if (self.rx() == &self.reactors[0] and …)` guarding
a single statement, used at least fourteen times inside `onTimerTick` itself:
the upgrade signal (`:6187`), ACME reload (`:6190`), OCSP staple swap
(`:6191`), nick-delay sweep (`:6202`), access prune (`:6226`), mesh peer RTT
probe (`:6233`), and peer-count publication (`:6238`), among others.

`rx()` resolves the current reactor at `src/daemon/server.zig:4253`, falling
back to `&self.reactors[0]` when the thread-local is unset (`:4254`) — which is
why the single-reactor fast path is correct by construction and the multi-reactor
path is not.

The inline-conjunction spelling is the risk. An early return is visible at the
top of a function; a fourteenth `and self.rx() == &self.reactors[0]` buried
mid-tick is easy to omit when adding a fifteenth maintenance call.

A missing guard here is not theoretical: it caused a live roster decay where
peers were reaped past their staleness TTL, producing empty `NAMES`, a missing
remote-oper prefix, and `401` on cross-node `PRIVMSG`. The most recent commits
on this branch (`d86e1f0 fix(mesh): recover stale links and exact gauges`,
`744360e docs(ops): record stale mesh liveness release`) are the recovery from
exactly this class.

**Accept:** every timer-driven mutation of shared or mesh state is either
reactor-0-gated or provably reactor-local, enumerated in a single audit table.
A new unguarded shared-state timer fails review with a named check, not vibes.
Pairs with **[L-03](#l-03--reactor-affinity-as-a-type-not-a-convention)**, which
proposes making the guard structural rather than a convention.

### S-03 — Event Spine v2

**P1** · `src/daemon/event_spine.zig`, `src/daemon/event_history.zig` · **client: contract**

The spine is a typed oper event bus with an `EventCategory` mask, owning no
allocation and no global state — callers provide subscriber storage, publish
sinks, and render buffers (`src/daemon/event_spine.zig:5-8`). Replay, collapse
(`event_collapse.zig`), and a replay guard (`event_spine_replay_guard.zig`) all
ship, and the client consumes it via its `OperEventConsole`.

`[design/event-spine-mesh-v2.md](design/event-spine-mesh-v2.md)` describes the
mesh-wide successor. The gap is that today's spine is node-local: an operator on
node A does not see node B's flood verdicts without a separate session.

**Accept:** an oper session subscribed on one node receives categorized events
originating on any mesh node, with origin attribution and no duplicate delivery
after a partition heals. Replay across a node boundary is ordered and bounded.

### S-04 — Warden and flood introspection surface

**P1** · `src/daemon/warden.zig`, `src/daemon/flood_guard.zig` · **client: contract**

`warden.zig` ships a full `Registry` of `Ward` entries with `Match`, `Scope`,
`Action`, `Facets`, and a wire codec (`encodeWire`/`decodeWire`,
`max_wire_len` at `src/daemon/warden.zig:327`). `flood_guard.zig`,
`clone_detect.zig`, `clone_limit.zig`, `shun.zig`, `spamtrap.zig`,
`ip_reputation.zig`, and `dnsbl.zig` all exist. What is missing is a queryable
surface: an operator cannot ask the daemon "which ward matched this connection,
and why."

**Accept:** a command surface returns the active ward set, the matching ward for
a given connection, and the current flood-guard verdict with its counters. The
answer is derived from live state, not reconstructed from logs. Pairs with
client item C-03.

### S-05 — OCG2 past observe mode

**P1** · `src/daemon/ocg2_authority_issuer.zig`, `src/daemon/ocg2_projection_runtime.zig` · **client: none**

Durable operator authority is deliberately staged, and only the first stage is
live. Per `[ops/ocg2-runtime-activation.md](ops/ocg2-runtime-activation.md)`:
`enabled = false` is `disabled`; `enabled = true` is `observe` (restore the
durable image, establish its security clock, validate bounded reconciliation,
**no live privilege changes**); `projection_enabled = true` is `project` and
**this build fails boot**; `minting_enabled = true` is `mint` and **this build
also fails boot**.

The issuer itself is described in source as an "inactive sealed OCG2 authority
issuer" whose only production entry point revalidates the permit under the
issuer mutex before any authority match, clock observation, revision allocation,
or store mutation (`src/daemon/ocg2_authority_issuer.zig:4-13`).

Activating projection is the next stage. It is P1 rather than P0 because the
existing configured-local operator path works and the staging is intentional —
but the daemon should not carry a permanently boot-failing config mode.

**Accept:** `project` mode boots and applies durable authority to live sessions
with a documented rollback. The `mint` stage remains explicitly gated to the
configured authority node. Every state transition is in the audit trail, and a
DST harness covers projection across a node restart.

### S-06 — Server-side history search

**P1** · `src/daemon/search_index.zig` · **client: contract**

`search_index.zig` exists. The client's search
(`onyx/src/lib/vault/searchVaultHybrid.ts`) is device-local by construction, so
anything older than a device's vault is invisible to the user.

**Accept:** a capability-advertised search command returns ranked results for
channels the requester can access, with pagination and a hard result bound.
E2EE content is never searchable server-side — the index must not accept
ciphertext bodies as if they were text. Pairs with client item C-05.

**Fail-closed guard:** access control is evaluated per hit, not per query. A
result the requester cannot read is not returned with a redacted body; it is
not returned.

### S-07 — Mesh anti-entropy repair under partition

**P1** · `src/substrate/undertow/anti_entropy.zig`, `anti_entropy_repair.zig`, `partition_detector.zig` · **client: none**

The mesh ships a deep reconciliation toolkit — `merkle.zig`, `prolly.zig`,
`riblt.zig` (rateless invertible Bloom lookup tables), `delta_codec.zig`,
`delta_journal.zig`, `convergence.zig`, `conflict_resolver.zig` — plus
`partition_detector.zig` and Ripple witnessed failure detection
(`ripple.zig`, `ripple_dst.zig`).

The recent stale-link recovery work (`d86e1f0`) shows the liveness path is still
being hardened. The item is to prove convergence, not to add mechanism.

**Accept:** a seeded deterministic simulation partitions a mesh, mutates state on
both sides, heals, and asserts convergence — with the seed printed on failure so
any red run replays. Liveness refresh stays orthogonal to value LWW: a
"still here" last-seen update is never gated on a newer HLC.

### S-08 — Cross-node presence convergence

**P2** · `src/substrate/undertow/membership_view.zig`, `member_compact.zig` · **client: contract**

Presence is per-connection today. On a mesh, a user present on another node must
not read as offline.

**Accept:** presence converges across nodes under the existing CRDT rules, and a
node handover does not produce a visible offline flap. Mesh identity on an S2S
link is the `shortId` — any presence keying that uses the nick or UID instead is
a bug. Pairs with client item C-15.

### S-09 — Link health and mesh observability

**P2** · `src/daemon/link_health.zig`, `src/daemon/metrics_http.zig` · **client: gated**

`[architecture/observability-stats.md](architecture/observability-stats.md)`
documents the channel-statistics engine and the public `status.json` mesh-health
feed. `link_health.zig` and `metrics_http.zig` exist.

**Accept:** per-link health (RTT, backlog, last successful anti-entropy round,
partition suspicion) is exposed on one surface, and an operator can distinguish
"peer is down" from "we are partitioned from it." Pairs with client item C-18.

---



## Wave 2 — Next

The theme is **finish the deliberately-deferred halves.** Several subsystems are
90% complete with a documented follow-up list; this wave closes those lists.

### S-10 — ECH: the deferred half

**P1** · `src/crypto/ech_seal.zig`, `src/proto/ech_config.zig`, `src/crypto/tls_server.zig` · **client: none**

Encrypted Client Hello is genuinely done on both roles, including
`retry_configs` (draft-ietf-tls-esni §7.1), with daemon plumbing via
`[[tls.ech_keys]]`. Per `[dev/tls-roadmap.md](dev/tls-roadmap.md)` item 5.1, the
deferred follow-ups are explicit:

- DNS HTTPS-RR fetch (configs are supplied by file today, mirroring CRL/SCT).
- `ech_outer_extensions` decompression — the server stands down to the outer if a
client compresses.
- ECH+HRR and ECH-over-PSK/0-RTT — **both a deliberate fail-closed refusal**, not
a silent downgrade. The client refuses rather than emit a subtly
non-compliant ClientHello2.
- Non-X25519 HPKE suites (`ech_seal.zig:15-19` supports exactly
DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305).
- AAD header-inclusion confirmation against a third-party reference ECH server
before live interop.

**Accept:** ECH+HRR is implemented to the draft's confirmation transcript or the
refusal is documented as permanent with a rationale. A third-party reference
server completes an ECH handshake against this daemon. Default-off stays
byte-identical.

### S-11 — mTLS and delegated-credential tooling

**P1** · `src/crypto/tls_server.zig`, `src/daemon/certfp_bind.zig`, `src/daemon/delegated_credential_cli.zig` · **client: gated**

Mutual TLS works, including raw-public-key client certificates
(RFC 7250) — the server parses the client's `client_certificate_type` offer,
selects RawPublicKey in CertificateRequest, accepts a bare client SPKI, and
verifies CertificateVerify against it before exposing it as the CertFP identity
(`[dev/tls-roadmap.md](dev/tls-roadmap.md)` item 5.3, `[tls] raw_public_key`
composing with `[tls] request_client_cert`).

Delegated credentials (RFC 9345) also work on both roles, with
`onyx delegated-credential inspect|validate` tooling. The named gaps are **DC
mint/rotation tooling** — nothing in-tree mints or rotates a DC — and **client
DCs for mTLS**.

**Accept:** an operator can mint and rotate a delegated credential with a
documented key-handling policy. A rotation happens without a handshake failure
window. Client-side DCs for mTLS either work or are cut with a rationale.

### S-12 — E2EE group authority activation

**P0** · `src/daemon/e2ee_group_mesh_authority.zig`, `e2ee_group_outbox.zig`, `e2ee_group_replay_guard.zig`, `src/substrate/undertow/e2ee_group_relay.zig` · **client: contract**

The daemon side of group E2EE is substantial: mesh authority, outbox, replay
guard, a DST harness (`e2ee_group_dst.zig`), and the relay path. The design is
in `[design/e2ee-everywhere-blueprint.md](design/e2ee-everywhere-blueprint.md)`
and the activation staging in
`[ops/e2ee-group-authority-v2-activation.md](ops/e2ee-group-authority-v2-activation.md)`.
The client has thirteen `groupControl*` modules waiting on it.

**Accept:** group control frames replicate across the mesh with exactly-once
semantics and a replay guard that survives a USR2 upgrade. A member removal
forward-secures the next message. The daemon never sees group plaintext. Pairs
with client item C-10 — **server-first**.

### S-13 — Device directory as replicated metadata

**P1** · `src/daemon/key_transparency.zig`, `key_transparency_store.zig` · **client: contract**

Multi-device DM fan-out already works client-side with TOFU pinning of the full
device set. The daemon holds `key_transparency.zig` and its store, and the
client exposes `KEYTRANS`/`E2EEKEY` surfaces.

**Accept:** device directory entries replicate across the mesh as CRDT-portable
records with origin and HLC, and a device revocation converges. Key transparency
produces an auditable log a client can verify.

### S-14 — Helix: capsule versioning discipline

**P1** · `src/daemon/helix/` · **client: none**

The Helix tree is large — roughly 55 modules covering capsules for accounts,
away, bans, bouncer buffers, CHATHISTORY cursors, connections, memos, metadata,
monitors, read markers, rate limits, silence, sessions, tickets, TLS, WebSocket,
whowas, and the World — plus migration FSM, journal, metrics, policy, relay,
token, and six DST harnesses (`upgrade_dst.zig`, `session_migration_dst.zig`,
`world_migration_dst.zig`, `s2s_adopt_dst.zig`, `session_adopt_dst.zig`,
`multishard_upgrade_dst.zig`).

The risk is not missing capsules; it is version drift. A serialized-length change
without a capsule version bump and a legacy decode arm produces a netsplit on
upgrade — a NEW-to-NEW round-trip test passes while the real
old-binary-to-new-binary path breaks.

**Accept:** a mechanical check that every capsule with a changed serialized
layout has a bumped version range and a cross-version decode test. `zig build test-helix` reports cross-version coverage, not just round-trip coverage.

### S-15 — Deterministic simulation as a first-class lane

**P1** · `src/substrate/sim.zig`, `src/substrate/fault_loom.zig` · **client: none**

The infrastructure exists but is barely used. `src/substrate/sim.zig` is
referenced only from `src/substrate/root.zig`; `fault_loom.zig` has exactly three
consumers, all Helix DST harnesses (`session_adopt_dst.zig`,
`multishard_upgrade_dst.zig`, `s2s_adopt_dst.zig`). There is **no** `zig build dst`
**step** — DST cases run inside the ordinary test suite, so there is no way to run
a campaign or vary a seed from the build.

For a daemon whose hardest bugs are mesh convergence, USR2-under-fault, and
cross-shard ordering, this is the highest-leverage assurance gap in the tree.

**Accept:** a `dst` build step runs seeded campaigns with a configurable seed
range and prints the failing seed. Mesh convergence, USR2 upgrade under fault
injection, and cross-shard delivery ordering each have at least one campaign.
A red campaign replays deterministically from its seed.

### S-16 — Media: simulcast selection in the SFU

**P1** · `src/daemon/media_plane.zig`, `src/substrate/simulcast_select.zig` · **client: contract**

The substrate ships `simulcast_select.zig`, `twcc.zig`, `bbr.zig`, `cc_cubic.zig`,
`l4s.zig`, `loss_monitor.zig`, `loss_recovery.zig`, `raptorq.zig`,
`reed_solomon.zig`, and `red_fec.zig`. The media plane ties the SFU endpoint
registry to a live UDP socket with a background pump thread and a coarse mutex
shared with the main thread (`src/daemon/media_plane.zig:6-12`).

**Accept:** the SFU selects a per-receiver spatial layer from a multi-layer
publisher, driven by real congestion signals rather than a static rung. A
constrained receiver degrades without affecting other receivers of the same
publisher. Pairs with client item C-12 — **server-first**.

### S-17 — Media plane concurrency review

**P2** · `src/daemon/media_plane.zig` · **client: none**

The pump thread and the main thread share the endpoint registry through a single
coarse mutex, justified in source because media STUN traffic is low-rate. That
justification holds for connectivity checks; it needs re-verifying as the plane
takes on simulcast selection and per-receiver state (S-16).

**Accept:** a documented lock-ordering contract for the media plane, and either
evidence the coarse mutex still suffices under the S-16 workload or a finer
scheme with the same fail-closed properties.

### S-18 — BoGo interop: the out-of-repo half

**P2** · `tools/bogo_shim.zig` · **client: none**

The shim is implemented and self-driven (`zig build bogo-shim`,
`zig build bogo-shim-test`), touching no production code. Per
`[dev/tls-roadmap.md](dev/tls-roadmap.md)` item 0.3, the remaining work is
out-of-repo: pin BoringSSL, write the `tools/bogo.sh` driver with a
`-shim-config` encoding the modern-only posture, and add a CI job.

The roadmap is explicit that the current reproducible evidence is the exact
24-pass/3-skip required baseline, and the exploratory full corpus still has
failures. That honesty should survive this item.

**Accept:** a pinned BoringSSL runner produces a reproducible pass/skip/fail
count in CI. The `DisabledTests` list names a reason per entry. No claim of a
corpus-wide pass without the artifact.

---



## Wave 3 — Later



### S-19 — Session continuity across nodes

**P2** · `src/daemon/helix/session_migrate.zig`, `session_replica.zig` · **client: contract**

`[design/session-resume-anywhere-blueprint.md](design/session-resume-anywhere-blueprint.md)`
is the design. Session replicas and migration exist within Helix.

**Accept:** a session resumes on a different mesh node with read markers, away
state, and monitor lists intact, without the receiving node ever holding
decryptable E2EE state. Pairs with client item C-29.

### S-20 — Storage: OroStore at scale

**P2** · `src/daemon/store.zig`, `src/substrate/wal.zig` · **client: none**

`[guide/persistence.md](guide/persistence.md)` documents the key/value store.

**Accept:** a documented growth model with measured compaction behavior and a
bounded recovery time from a WAL of a stated size.

### S-21 — Exact-once message relay v2

**P2** · `src/substrate/undertow/message_relay_v2.zig`, `src/daemon/relay_v2_*.zig` · **client: none**

`[design/message-v2-exact-once.md](design/message-v2-exact-once.md)` is the
design; `relay_v2_activation.zig`, `relay_v2_event_log.zig`,
`relay_v2_outbox.zig`, and `relay_v2_replay_guard.zig` are the staging.

**Accept:** exactly-once delivery survives a partition, a node restart, and a
USR2 upgrade, proven by a DST campaign from S-15.

### S-22 — Connection classes and admission at scale

**P3** · `src/daemon/conn_class.zig`, `src/substrate/admission.zig` · **client: none**

`[class.*]` connection classes already provide registration-time
resource/admission/flood policy with bounded growable SendQ and RecvQ
(`[README.md](README.md)`).

**Accept:** admission decisions under synthetic load are bounded and fair, with
a measured worst-case rather than an assumed one.

### S-23 — CRL and OCSP: the fetch half

**P3** · `src/crypto/crl.zig`, `src/daemon/ocsp_staple.zig` · **client: none**

CRL checking is wired fail-open with caller-supplied DER; the named follow-up is
an in-daemon CDP fetch and cache. OCSP stapling is complete with a background
producer; its follow-ups are a TLS 1.2 client round-trip test, delegated
responder support, and exponential backoff on fetch failure
(`[dev/tls-roadmap.md](dev/tls-roadmap.md)` items 4.2 and 2.1).

**Accept:** CDP fetch with a cache and a bounded failure mode. Delegated OCSP
responders are accepted only with an exact `id-kp-OCSPSigning` EKU — `anyEKU`
does not count — issuer-signed and in-window.

### S-24 — Multi-certificate daemon plumbing

**P3** · `src/daemon/tls_sni_load.zig`, `src/daemon/config_format.zig` · **client: none**

SNI-based certificate selection is complete **as a library** — the engine picks
per-ClientHello from `Config.sni_certs` with case-insensitive exact and
single-label wildcard matching. The daemon-side multi-cert `[tls]` configuration
and load path is called out as a separate follow-up, and it is the ECH
prerequisite (`[dev/tls-roadmap.md](dev/tls-roadmap.md)` item 2.4).

**Accept:** an operator configures multiple certificates in TOML, and a REHASH
swaps them atomically without dropping a handshake.

### S-25 — kTLS beyond TLS 1.3

**P3** · `src/daemon/ktls.zig` · **client: none**

kTLS TX and RX are both complete for TLS 1.3 and survive USR2 (kernel socket
state survives `execve`), gated by `[tls] ktls=tx|txrx`. TLS 1.2 explicit-nonce
derivation is the documented deferral.

**Accept:** either TLS 1.2 kTLS lands with a kernel round-trip proof, or it is
cut on the modern-only posture with a note in the skip list.

---



## Wave 4 — Moonshot



### S-26 — Post-quantum signing

**P3** · `src/crypto/ml_dsa.zig`, `src/crypto/slh_dsa.zig` · **client: none**

Verification is remarkably complete: ML-DSA-44/65/87 and **all twelve**
standardized SLH-DSA parameter sets, each pinned by independent NIST ACVP
`sigVer` vectors and wired into X.509 dispatch. What is explicitly not done is
**signing**, hybrid/composite certificates, and live interop — no PQ CA issues
certificates yet (`[dev/tls-roadmap.md](dev/tls-roadmap.md)` item 5.4).

**Accept:** signing lands with ACVP `sigGen` vectors, or the verify-only posture
is documented as permanent. Any hybrid certificate scheme follows a ratified
profile, not a local invention.

### S-27 — Standards WebRTC interop

**P3** · `src/proto/dtls12_server.zig`, `dtls13_server.zig`, `src/daemon/media_bridge.zig` · **client: contract**

DTLS 1.2 and 1.3 terminators are live in the media plane —
`media_plane.zig:111-116` carries `dtls_enabled`, a per-peer
`dtls_server.Terminator`, and its backing session table — and
`media_bridge.zig` already rewraps between the native Cadence leg and an
RTP/SRTP leg.

**Accept:** an unmodified standards WebRTC client joins a call. Whether the
native Cadence transport remains the preferred path is a separate product
decision.

### S-28 — Autonomous mesh operation

**P3** · `src/substrate/undertow/` · **client: none**

Self-healing topology: automatic peer discovery, link re-weighting under
sustained loss, and partition recovery without operator action.

**Accept:** a mesh recovers from a multi-node partition without manual
intervention, proven by an S-15 campaign — and never by silently accepting a
frame it should reject.

### S-29 — Sealed operator authority end to end

**P3** · `src/daemon/ocg2_*.zig`, `src/daemon/durable_oper_authority.zig` · **client: none**

The full OCG2 arc past S-05: `mint` mode on the configured authority node, with
cross-mesh grant sharing and revocation that converges.

**Accept:** an operator grant issued on the authority node is honored mesh-wide
and revoked mesh-wide, with every transition auditable and no node able to
forge a grant.

### S-30 — Formal verification of the convergence core

**P3** · `src/substrate/undertow/convergence.zig`, `conflict_resolver.zig` · **client: none**

Property-based testing already exists (`state_props.zig`, `merkle_props.zig`,
`ripple_props.zig`, `concord_props.zig`, `x509_props.zig`, `tls_props.zig`).
The moonshot is a machine-checked proof of the CRDT merge laws —
commutativity, associativity, idempotence — for the core state types.

**Accept:** the merge laws hold under a checked model, and the model is kept in
sync with the implementation by a gate rather than by discipline.

---

## Invented features — P0 shortlist

The items below do not exist in the daemon today. They are tracked in full in
[`docs/features/INVENTED-FEATURES-CATALOG.md`](features/INVENTED-FEATURES-CATALOG.md).
None are required for 0.7; they are flagged here so wave-planner can slot them
into 0.8+ without re-discovering them.

| ID | Feature | Complexity | Client |
| --- | --- | --- | --- |
| [F-39](features/INVENTED-FEATURES-CATALOG.md#f-39--deep-metrics-histograms-not-just-counters) | Deep metrics — histograms, not just counters | M | none |
| [F-15](features/INVENTED-FEATURES-CATALOG.md#f-15--account-trust-ledger) | Account trust ledger | M | gated |
| [F-52](features/INVENTED-FEATURES-CATALOG.md#f-52--scheduled--deferred-delivery) | Scheduled & deferred delivery (`cron.zig` already parses; nothing fires it) | M | contract |
| [F-08](features/INVENTED-FEATURES-CATALOG.md#f-08--proofmark-federation-portable-moderation-receipts) | Proofmark federation — portable moderation receipts | L | gated |
| [F-24](features/INVENTED-FEATURES-CATALOG.md#f-24--outbound-event-webhooks) | Outbound event webhooks | M | none |

---



# Track P — Performance

**The premise of this track is that we do not currently know how fast the daemon
is.** `build.zig` defines thirty-odd steps — `test-`* lanes, `check`, `wasm`,
`fuzz`, `ct-check`, `bogo-shim`, `release`, `package` — and **not one of them is
a benchmark.** Every performance claim in this repository is therefore an
assertion, including the ones in this file.

So P-01 is not merely first by convention; nothing else in this track can be
accepted without it. An item here that says "reduce X" and cannot show a
before/after from a committed benchmark is not done.

Two findings below are load-bearing enough to state up front, because they
reframe what "optimize the daemon" even means in 0.7:

1. **The io_uring fast path is compiled but unreachable.** The daemon runs
  plain accept/recv/send.
2. **Fixed-size buffers dominate per-connection and per-delivery memory.** A
  40-byte `PRIVMSG` crossing a shard boundary occupies a 4 KiB pooled slot.



### P-01 — A benchmark lane that exists

**P0** · `build.zig`, new `bench/` · **client: none**
**Owner:** `onyx-server-perf` · **Complexity:** M · **Gate:** `zig build bench` (new)

There is no `bench` step in `build.zig`. Grepping the file for `bench` or `perf`
returns exactly one hit, and it is the word "perform" inside a comment on line 6.
The daemon has `hdr_histogram.zig` and `ddsketch.zig` in `src/substrate/`, so
the measurement primitives are already in-tree and unused for this purpose.

The lane must be **reproducible and committed**, not a script someone ran once:
a fixed workload, a fixed seed, a machine-readable result, and a checked-in
baseline so a regression is a diff rather than a memory.

Minimum workloads, chosen because they are the paths every other P item touches:


| Workload             | Measures                                    | Why                                                |
| -------------------- | ------------------------------------------- | -------------------------------------------------- |
| Line parse           | ns/line, allocations/line                   | `src/proto/irc_line.zig` is on every inbound byte. |
| Channel fan-out      | ns/recipient, bytes/recipient               | The `PRIVMSG` → N members path; see P-04.          |
| Cross-shard delivery | ns/message, pool slots/message              | The `DeliverBuf` path; see P-05.                   |
| Connection lifecycle | bytes/connection, accept→registered latency | `ConnState` footprint; see P-03.                   |
| TLS handshake        | handshakes/s, allocations/handshake         | Armor; see P-08.                                   |
| Mesh frame apply     | ns/frame at N peers                         | Undertow ingest; see P-09.                         |


**Accept:** `zig build bench` runs every workload above, emits a machine-readable
artifact, and compares against a committed baseline. A regression beyond a
declared threshold fails the step. The baseline records the machine it was taken
on — a number without a machine is not a baseline.

**Explicit non-goal:** cross-machine absolute numbers. The gate is
regression-vs-baseline on the same host, not a leaderboard.

### P-02 — Turn on the io_uring fast path

**P0** · `src/daemon/server.zig`, `src/daemon/config_format.zig` · **client: none**
**Owner:** `onyx-server-reactor` (correctness) + `onyx-server-perf` (measurement) · **Complexity:** L · **Gate:** `zig build test-server` + `zig build bench`

This is the single largest known performance gap in the tree, and it is a
wiring gap rather than a missing implementation.

`server.zig:860` defines a local `ringlane` namespace whose `RingFeatures`
struct (`:866-872`) carries seven fast-path toggles: `multishot_accept`,
`multishot_recv`, `buf_ring`, `send_zc`, `fixed_files`, `defer_taskrun`, and
`sqpoll`. `setupFlags` (`:877`) maps `sqpoll` to `IORING_SETUP_SQPOLL` and
`defer_taskrun` to `IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_SINGLE_ISSUER`.

Every one of those seven fields defaults to `false`. `baseline` is `.{}`
(`server.zig:875`) — all-false — and the server's config field is
`features: RingFeatureSet = RingFeatureSet.baseline` (`server.zig:1972`), passed
straight into `RingCore.init(config.ring_entries, config.features)`
(`server.zig:4359`).

**Nothing sets it to anything else.** The `[io]` config section exposes exactly
one key — `cqe_batch`, range 16..4096, default 256 (`config_format.zig:1335`,
`etc/onyx-server.reference.toml:462-464`). There is no config key, no CLI flag,
and no runtime probe that turns on a single fast-path feature.

The daemon therefore runs **plain one-shot accept, one-shot recv into a
per-connection buffer, and copy send** — the conservative profile that
`src/substrate/io/ring.zig:57-59` describes as "works on the widest range of
kernels and inside restricted sandboxes."

This is a defensible default and a poor ceiling. Each feature is a distinct
change with a distinct risk:


| Feature                       | Kernel | Wins                                                                  | Risk                                                              |
| ----------------------------- | ------ | --------------------------------------------------------------------- | ----------------------------------------------------------------- |
| `multishot_accept`            | ≥ 5.19 | One SQE per listener instead of per connection                        | Re-arm on `IORING_CQE_F_MORE` clear                               |
| `buf_ring` + `multishot_recv` | ≥ 5.19 | Kernel-selected buffers; removes the per-connection `recv_buf` (P-03) | Buffer exhaustion becomes a new failure mode                      |
| `send_zc`                     | ≥ 6.0  | Bulk fan-out without a copy                                           | Two-CQE completion (result + `F_NOTIF`); buffer must outlive both |
| `fixed_files`                 | —      | Skips fd lookup per op                                                | Registration table must survive USR2                              |
| `defer_taskrun`               | ≥ 6.1  | Less completion-path overhead                                         | Implies `SINGLE_ISSUER` — one submitter thread only               |
| `sqpoll`                      | —      | Submission without a syscall                                          | Burns a core; interacts with shard count                          |


**Accept:** each feature is independently switchable, **runtime-probed with a
fail-closed narrowing** (advertise nothing the kernel did not confirm — the
model is `RingFeatures.probe` at `src/substrate/io/ring.zig:99-108`), and
measured through P-01 before it becomes a default. A feature that cannot be
probed stays off. The USR2 handoff (`guide/upgrade.md`) survives every enabled
combination — `fixed_files` and `buf_ring` both hold kernel-side state that an
`execve` must either carry or rebuild, and a zero-drop upgrade that silently
drops the registration table is worse than not having it.

**Dependency:** P-01 (cannot accept without measurement), H-06 (USR2-under-fault
campaign must cover the enabled feature set).

**Flagged for review, not assumed:** whether `defer_taskrun`'s `SINGLE_ISSUER`
requirement is compatible with the current multi-reactor model is a design
question for `onyx-server-reactor`, not a doc claim. This roadmap does not
assert it is.

### P-03 — `ConnState` memory footprint

**P1** · `src/daemon/server.zig:2447` · **client: none**
**Owner:** `onyx-server-perf` · **Complexity:** M · **Gate:** `zig build bench` (connection-lifecycle workload)

`ConnState` (`server.zig:2447`) embeds its buffers **inline, by value**:

- `recv_buf: [default_recv_bytes]u8` (`:2462`) where `default_recv_bytes = 4096`
(`:1264`).
- `line_buf: [default_line_bytes]u8` (`:2464`) where
`default_line_bytes = irc_line.MAX_LINE_BODY + 2` (`:1269`).
- `recv_overflow: std.ArrayListUnmanaged(u8)` (`:2470`), heap, bounded by
`recvq_cap` (`default_recvq_cap = default_line_bytes`, `:1274`), and
explicitly documented as empty on the fast path.

Inline buffers are a deliberate and correct choice for the fast path: no
allocation, no pointer chase, and the address is stable enough to hand to the
kernel. The cost is that **every accepted connection pays the full ~4.6 KiB
before it has sent a byte**, including one that connects and idles, and
including one that is mid-TLS-handshake and has no IRC state at all.

At 10k connections that is ~46 MiB of mostly-cold buffer; at 100k it is ~460 MiB.
That may be entirely acceptable — the point of this item is that **nobody has
measured it**, and the tradeoff should be a decision rather than an inheritance.

Two candidate directions, neither pre-judged here:

1. **Let** `buf_ring` **own the recv buffer.** If P-02 lands `buf_ring` +
  `multishot_recv`, the kernel selects a buffer from a shared ring and
   `recv_buf` becomes dead weight for those connections. This is the direction
   the substrate skeleton anticipates (`src/substrate/io/ring.zig:374-378`).
2. **Split hot from cold.** `ConnState` mixes per-byte fields (`fd`, `token`,
  `line_len`) with fields touched once per session. A hot/cold split, or a
   `MultiArrayList` over the hot aggregate, improves cache density on the recv
   path independently of total footprint.

**Accept:** a measured `sizeof(ConnState)` and a measured bytes-per-connection at
a stated connection count, before and after. A reduction is only claimed with
both numbers. The `recv_overflow` fast-path-empty invariant (`:2466-2469`) is
preserved — spilling must remain the exception, and the bound must remain
`recvq_cap`.

### P-04 — Channel fan-out cost

**P1** · `src/daemon/server.zig` · **client: none**
**Owner:** `onyx-server-perf` · **Complexity:** M · **Gate:** `zig build bench` (fan-out workload)

A `PRIVMSG` to an N-member channel is the daemon's defining hot path, and it is
the workload where an accidental O(n²) hides best — the per-recipient cost is
small enough that it only shows up on a large channel, which is exactly where it
matters.

The questions this item answers, none of which currently have a committed
number: is the outbound line formatted once and shared, or re-rendered per
recipient? Is there per-recipient allocation? How does cost scale when the
membership is split across shards (P-05)? What happens when one recipient's
SendQ is full — does the fan-out degrade for everyone?

**Accept:** measured ns/recipient and allocations/recipient at 10, 100, 1k, and
10k members, on one shard and split across shards. Scaling is linear in
recipients within a declared tolerance. A slow or full recipient does not
degrade delivery to the others — back-pressure is per-connection, and it is
**counted**, never silent.

### P-05 — `DeliverBuf`: right-size the cross-shard path

**P1** · `src/daemon/deliver_handle.zig`, `src/daemon/reactor_fabric.zig` · **client: none**
**Owner:** `onyx-server-reactor` · **Complexity:** M · **Gate:** `zig build test-server` + `zig build bench`

Cross-shard delivery copies bytes into a pooled buffer because the sending
reactor may not touch the target reactor's send queue
(`deliver_handle.zig:5-10`). The design is right; the sizing is coarse.

`DeliverBuf.data` is `[max_bytes]u8` with `max_bytes = 4096`
(`deliver_handle.zig:17,21`). The buffer is fixed-size, so **a 40-byte**
`PRIVMSG` **and a 4000-byte one consume the same slot.** `reactor_fabric.zig:28-30`
states the consequence plainly: each pool is ~1 MiB, one pool per shard, heap
allocated once at `init`.

The per-shard pool decision itself is well-reasoned and should not be undone —
`reactor_fabric.zig:17-24` records *why* it exists: with one shared pool, "a
broadcast to a channel whose cross-shard recipients out-number the pool silently
exhausted it," and per-shard pools "collapse pool exhaustion into the single,
COUNTED inbox-full back-pressure signal (`dropped`)." That counted-not-silent
property is the invariant this item must preserve.

What is open is whether one 4 KiB size class is the right shape. A size-class
pool (say 256 B / 1 KiB / 4 KiB) would let a typical `PRIVMSG` occupy ~1/16 the
slot, raising effective pool depth at the same memory — at the cost of a second
exhaustion mode per class, which is exactly the complexity the current design
deliberately avoided.

**Accept:** a measured distribution of actual `DeliverBuf` occupancy under the
P-04 fan-out workload, and a decision recorded either way. If size classes land,
exhaustion in **every** class remains counted and surfaces as the same
back-pressure signal — never a silent drop. If they do not, the 4 KiB choice is
documented as measured rather than assumed.

### P-06 — One ring implementation, not two

**P1** · `src/substrate/io/ring.zig`, `src/daemon/server.zig:860` · **client: none**
**Owner:** `onyx-server-reactor` · **Complexity:** L · **Gate:** `zig build check` + `zig build test-server`

There are two io_uring implementations in the tree.

`src/substrate/io/ring.zig` is 741 lines, documents itself as the "Ringlane
io_uring reactor (**skeleton**)" (`:4`), and says the `Reactor` seam "will
eventually dispatch to [it] on Linux" (`:8-10`). Its only importers are
`src/substrate/io/root.zig` and the config path.

`src/daemon/server.zig:860` defines a **second, private** `ringlane` namespace
with its own `RingFeatures`, its own `setupFlags`, its own batch constants, and
the live `handleAccept` / `handleRecv` / `handleSend` handlers (`:7989`, `:9501`,
`:9590`). This one is the daemon's actual I/O path.

The substrate copy is the better-factored of the two — it has the generational
`FdToken`, the pure `user_data` pack/unpack, and the fail-closed `probe`
narrowing that P-02 needs. It is also the one that is not running.

Meanwhile `src/substrate/reactor.zig` — the DST seam that is supposed to let the
daemon run against the deterministic simulator — is 176 lines covering **only
monotonic and wall-clock time**, with `submit/poll/accept/recv/send` explicitly
deferred ("land in M1 when Ringlane (io_uring) is implemented", `reactor.zig:9-10`).
That is why H-05's simulation coverage cannot reach the I/O path today: the seam
it would need does not exist yet.

**Accept:** one implementation. The daemon's I/O path goes through the substrate
`Reactor` seam, the duplicate `ringlane` namespace in `server.zig` is deleted,
and the DST backend can drive accept/recv/send. Behavior is byte-identical
before and after, proven by `zig build test-server` and the P-01 baseline.

**Dependency:** blocks H-05 (I/O-level deterministic simulation). Pairs with
P-02 — doing them in the wrong order means implementing feature probing twice.

### P-07 — Shard-count and affinity policy

**P2** · `src/daemon/reactor_pool.zig`, `src/daemon/reactor_fabric.zig` · **client: none**
**Owner:** `onyx-server-reactor` · **Complexity:** M · **Gate:** `zig build bench`

The daemon "decides its shard count at boot from the host's core count"
(`reactor_fabric.zig:8-10`), and the fabric's memory scales with it —
`num_shards * pool_slots`, ~1 MiB per pool (`:26-30`). Client-to-shard pinning
determines how much traffic takes the cross-shard path at all: a channel whose
members all land on one shard never pays P-05's copy.

**Accept:** measured throughput and cross-shard message ratio at 1, 2, 4, 8, and
`nproc` shards on the P-04 workload. The default is chosen from that data and
documented in `[reference/config.md](reference/config.md)`. Whether pinning
policy should consider channel membership is answered with numbers, not
intuition.

### P-08 — TLS handshake and record-path cost

**P2** · `src/crypto/tls_server.zig`, `src/crypto/tls_record.zig` · **client: none**
**Owner:** `armor-tls` · **Complexity:** M · **Gate:** `zig build test-tls` + `zig build bench`

`tls_server.zig` is 7,832 lines and `tls_client.zig` is 6,468. Armor is a
from-scratch stack, so it has neither the benefit nor the burden of OpenSSL's
assembly fast paths, and handshake cost is a connection-rate ceiling.

**Accept:** measured handshakes/second and allocations/handshake for the
supported suites, including the PQ-hybrid X25519MLKEM768 path, with a committed
baseline. **Constant-time properties are not traded for throughput** — any
change to a secret-dependent path re-runs `zig build ct-check`, and a regression
there blocks the optimization regardless of its speed win.

### P-09 — Mesh ingest cost at peer scale

**P2** · `src/substrate/undertow/s2s_peer.zig`, `route_table.zig` · **client: none**
**Owner:** `onyx-server-mesh` · **Complexity:** M · **Gate:** `zig build test-mesh` + `zig build bench`

`s2s_peer.zig` is 9,198 lines and `route_table.zig` is 4,030 — the two largest
files in the mesh. Frame apply and route lookup are per-message costs that scale
with peer count, and anti-entropy rounds add a periodic burst on top.

**Accept:** measured ns/frame and route-lookup cost at 2, 4, and 8 peers, plus
the cost of one anti-entropy round at a stated state size. Anti-entropy does not
starve foreground delivery — measured, not assumed.

### P-10 — kTLS coverage and the TLS 1.2 decision

**P2** · `src/daemon/ktls.zig` · **client: none**
**Owner:** `armor-tls` · **Complexity:** S · **Gate:** `zig build test-tls` + `zig build bench`

kTLS TX and RX are complete for TLS 1.3 and survive USR2 (kernel socket state
survives `execve`), gated by `[tls] ktls=tx|txrx`. `ktls.zig` is 710 lines and
documents the deferred piece precisely: "the TLS 1.2 explicit-nonce derivation,
the `TCP_ULP` attach + `setsockopt`" (`ktls.zig:22`).

This overlaps S-25, which frames the same gap as a feature question. Here it is
a measurement question: **what does kTLS actually buy on the fan-out path?**
If the answer is large, TLS 1.2 kTLS is worth finishing; if it is small, the
modern-only posture is the cheaper correct answer and S-25 closes as "cut."

**Accept:** measured throughput and CPU with `ktls=off`, `tx`, and `txrx` on the
P-04 fan-out workload. The TLS 1.2 decision in S-25 is made from that number.

### P-11 — Allocation discipline on the hot path

**P2** · `src/daemon/`, `src/proto/` · **client: none**
**Owner:** `onyx-server-perf` · **Complexity:** M · **Gate:** `zig build bench`

Zig's explicit allocators make this auditable in a way most languages do not:
a hot path that takes an `Allocator` is making a claim about its cost. The goal
is a **counted** allocations-per-message figure on the inbound parse, the fan-out,
and the mesh apply paths — and then a budget that a benchmark enforces.

**Accept:** allocations per inbound line, per fan-out recipient, and per mesh
frame are counted and bounded by a benchmark assertion. A change that adds an
allocation to a budgeted path fails `zig build bench`, not review.

### P-12 — Build and test wall-clock

**P3** · `build.zig`, `src/daemon/server.zig` · **client: none**
**Owner:** `zig-coder` · **Complexity:** M · **Gate:** `zig build check`

Developer iteration speed is a performance surface too. `server.zig` at 102,152
lines is a single compilation unit that nearly every focused test lane pulls in,
and the full suite is ~6,280 tests (`build.zig:718`).

**Accept:** measured `zig build check` and `zig build test` wall-clock before and
after L-01's decomposition, on a stated machine. This item is mostly a
*consequence* of L-01 rather than independent work — it is listed so the win is
measured rather than assumed.

---



# Track H — Hardening

**The premise of this track is that the daemon's assurance story is real but
narrow.** There is a genuine adversarial corpus, a genuine constant-time
harness, genuine property tests, and genuine fault injection. Each one covers
less than its existence implies, and the gaps are specific and knowable.

This track is where the fail-closed invariants in
`[RUNBOOK.md](RUNBOOK.md)` and `[architecture/mesh-security.md](architecture/mesh-security.md)`
stop being conventions and become things a gate enforces.

### H-01 — Classify the exploit corpus

**P0** · `src/`, `build.zig:302-311` · **client: none**
**Owner:** `onyx-server-hardener` · **Complexity:** M · **Gate:** `zig build test-exploit`

This is S-01 restated as a hardening item, with the current numbers verified.
`zig build test-exploit` (alias `test-attack`) filters on `"exploit:"`
(`build.zig:302-311`) and selects **45** tests. Their distribution:


| Module                                   | Tests |
| ---------------------------------------- | ----- |
| `src/daemon/server.zig`                  | 22    |
| `src/proto/sasl_mechrouter.zig`          | 4     |
| `src/proto/irc_line.zig`                 | 4     |
| `src/substrate/undertow/s2s_peer.zig`    | 3     |
| `src/substrate/undertow/route_table.zig` | 3     |
| `src/proto/names_reply.zig`              | 2     |
| `src/proto/membership_event.zig`         | 2     |
| `src/proto/color_strip.zig`              | 2     |
| `src/daemon/flood_guard.zig`             | 2     |
| `src/substrate/undertow/burst.zig`       | 1     |


Read as a coverage map this is revealing. Nearly half the corpus lives in one
file. There is **no exploit test at all** in `src/crypto/` (the TLS stack has
its own KAT and fuzz lanes, but no adversarial-scenario tests), none in the
Helix upgrade path, none in the media plane, and none in the OCG2 authority
path — three subsystems whose failure modes are precisely "an attacker makes the
daemon do the wrong thing across a trust boundary."

**Accept:** every test is tagged with an attack class; `test-exploit` reports
per-class counts; each class names its uncovered surface. An unclassified
exploit test fails the gate. The classes must at minimum cover: hostile line
parse, SASL/auth bypass, mesh frame forgery and replay, resource exhaustion,
algorithmic complexity, capsule/version confusion, and media-plane abuse.

### H-02 — Close the named coverage gaps

**P0** · `src/crypto/`, `src/daemon/helix/`, `src/daemon/media_plane.zig`, `src/daemon/ocg2_*.zig` · **client: none**
**Owner:** `onyx-server-hardener` · **Complexity:** L · **Gate:** `zig build test-exploit`

Once H-01 makes the gaps visible, this fills the four that matter most:

- **Helix capsule confusion.** A hostile or corrupt capsule from a
differently-versioned peer must be rejected, not partially applied. This is
the same failure surface as S-14, approached adversarially.
- **Media plane.** Malformed DTLS, oversized RTP, and forged native-media MACs
must fail closed. The MAC is documented in
`[reference/native-media-mac.md](reference/native-media-mac.md)`.
- **OCG2 authority.** A forged or replayed authority grant must be rejected at
every stage — and this must be tested *before* S-05 moves the daemon past
observe mode, not after.
- **Mesh admission.** `require_signed_frames` **fails closed on a keyless
node**: a node without keys rejects rather than silently accepting. There must
be a test that would fail if someone made it permissive.

**Accept:** each of the four has at least one `test "exploit:` case asserting a
**rejection**, and each rejection is counted where the daemon counts things.
"Did not crash" is not a passing condition; "rejected, counted, and the
connection state is unchanged" is.

### H-03 — Unblock coverage-guided fuzzing

**P1** · `src/crypto/tls_fuzz.zig`, `build.zig:700-728` · **client: none**
**Owner:** `armor-tls` · **Complexity:** M · **Gate:** `zig build fuzz`

The fuzz targets exist and are honest about their state. `build.zig:708-716`
records it exactly: bounded corpus-replay mode "compiles and passes," while
coverage-guided `--fuzz` "BUILDS, LINKS, and starts fuzzing … but the compiler's
own fuzzer runtime then crashes deterministically (`panic: start index 1 is larger than end index 0`, a slice-bounds bug in `lib/zig/fuzzer.zig` —
reproducible with a trivial zero-onyx target)."

That is an **upstream toolchain bug, not an Onyx bug**, and the write-up
correctly proves it with a zero-dependency reproducer. It still means the
daemon has no working coverage-guided fuzzing.

The six targets are all TLS-facing: X.509, TLS record, OCSP, ClientHello and
handshake, cert-compression inflate, and SNI (`build.zig:702-703`). The IRC line
parser, the IRCX `PROP` parser, the mesh frame codec, and the config parser —
all attacker- or operator-facing — have none.

**Accept:** either the upstream bug is fixed on the pinned toolchain and
coverage-guided mode runs in CI, or a second fuzzing path is used and the
in-tree note is updated with the resolution. Targets are extended past TLS to
the IRC line parser, the mesh frame codec, and the TOML config parser. Each
target keeps a committed seed corpus and every crash becomes a regression test.

### H-04 — Constant-time verification with teeth

**P1** · `build.zig:694-696`, `src/crypto/` · **client: none**
**Owner:** `armor-tls` + `onyx-server-crypto-reviewer` · **Complexity:** M · **Gate:** `zig build ct-check`

`zig build ct-check` runs a "dudect-style constant-time verification harness"
(`build.zig:695`) built at `ReleaseFast`. It is opt-in and not part of
`all-checks` (`build.zig:814-819`), which means a change that introduces a
secret-dependent branch does not fail any default gate.

**Accept:** the harness covers every secret-dependent comparison the stack
relies on — MAC and tag verification, `MeshPass` admission, SCRAM, PSK binder,
signature verification — and it runs in the pre-push gate. A regression fails
the build. Because dudect is statistical, the gate declares its confidence
threshold and its sample count rather than reporting a bare pass.

### H-05 — Deterministic simulation as a build step

**P0** · `src/substrate/sim.zig`, `src/substrate/fault_loom.zig`, `build.zig` · **client: none**
**Owner:** `onyx-server-dst` · **Complexity:** L · **Gate:** `zig build dst` (new)

S-15 in the feature spine covers this; it is repeated here because it is a
**hardening prerequisite**, not just a feature. `fault_loom.zig` has three
consumers, all Helix DST harnesses, and there is no `dst` step in `build.zig` —
so DST cases run inside the ordinary suite with no way to vary a seed or run a
campaign.

For a daemon whose hardest failures are mesh convergence, USR2-under-fault, and
cross-shard ordering, seeded replay is the difference between "we fixed it" and
"we saw it once."

**Accept:** `zig build dst` runs seeded campaigns over a configurable seed range
and **prints the failing seed**. A red campaign replays deterministically from
that seed alone.

### H-06 — USR2 under fault injection

**P0** · `src/daemon/helix/`, `src/substrate/fault_loom.zig` · **client: none**
**Owner:** `onyx-server-dst` + `onyx-server-helix-reviewer` · **Complexity:** L · **Gate:** `zig build dst` + `zig build test-helix`

The zero-drop hot upgrade is the daemon's most operationally dangerous path: it
runs on a live production node, carries every connection's state across an
`execve`, and its failure mode is a netsplit rather than a crash.

Helix already has six DST harnesses (`upgrade_dst.zig`, `session_migration_dst.zig`,
`world_migration_dst.zig`, `s2s_adopt_dst.zig`, `session_adopt_dst.zig`,
`multishard_upgrade_dst.zig`), which is more than any other subsystem. What is
missing is **fault injection during** the upgrade: allocation failure mid-capsule
decode, a partial write on the handoff socket, a peer that reconnects during the
adoption window, a capsule from a version the new binary does not expect.

**Accept:** a campaign injects faults at each upgrade stage and asserts either
zero-drop success or a clean abort with the old binary still serving. **A panic
is never an acceptable outcome.** Every enabled P-02 io_uring feature is covered,
since `fixed_files` and `buf_ring` add kernel state the handoff must account for.

### H-07 — Capsule version-drift gate

**P1** · `src/daemon/helix/` · **client: none**
**Owner:** `onyx-server-helix-reviewer` · **Complexity:** M · **Gate:** `zig build test-helix`

The mechanical half of S-14. The failure is specific and has bitten before: a
serialized-length change without a version bump passes a NEW-to-NEW round-trip
test while the real old-binary-to-new-binary path breaks — and it breaks in
production, during an upgrade, as a netsplit.

**Accept:** a check that fails when a capsule's serialized layout changes without
a version-range bump and a legacy decode arm. `zig build test-helix` reports
**cross-version** decode coverage, not just round-trip coverage.

### H-08 — Resource exhaustion and admission bounds

**P1** · `src/daemon/conn_class.zig`, `src/substrate/admission.zig`, `src/daemon/flood_guard.zig` · **client: none**
**Owner:** `onyx-server-warden` + `onyx-server-hardener` · **Complexity:** M · **Gate:** `zig build test-exploit`

The anti-abuse engines are numerous — `flood_guard.zig`, `clone_detect.zig`,
`clone_limit.zig`, `shun.zig`, `spamtrap.zig`, `ip_reputation.zig`, `dnsbl.zig`,
`conn_class.zig`, `admission.zig` — and `[class.*]` provides registration-time
resource policy with bounded SendQ and RecvQ.

What is not proven is behavior at the **boundary**: what happens at exactly the
connection limit, at exactly `recvq_cap`, when a pooled resource is exhausted
(P-05), and when several limits bind at once.

**Accept:** each bound has a test at limit, at limit+1, and under concurrent
pressure. Exhaustion is **counted and observable**, never silent — this is the
same invariant `reactor_fabric.zig:17-24` already establishes for the delivery
pool, applied to every bounded resource. Memory does not grow without bound
under sustained abuse, measured through P-01.

### H-09 — Hostile-input corpus for the operator surface

**P2** · `src/daemon/config_format.zig`, `src/daemon/modules/` · **client: none**
**Owner:** `onyx-server-hardener` + `onyx-server-config` · **Complexity:** M · **Gate:** `zig build test-config` + `zig build test-exploit`

Operator input is semi-trusted, not trusted. A malformed TOML file, an
out-of-range value, or a hostile `env:`/`@file:` indirection
(`config_format.zig:486`) must fail with a diagnostic — and it must fail
**before** the daemon commits to an identity.

This matters more than a config parser usually would because of a documented
boot hazard: a `ParseError` at boot silently starts the **default** identity and
needs a full restart to recover, which is exactly why `--check-config` runs
first in `[RUNBOOK.md](RUNBOOK.md)`.

**Accept:** a hostile-config corpus covering truncation, type confusion,
out-of-range integers (`config_format.zig:542`), zero durations
(`:556` rejects a zero `ms/s/m/h`), missing required keys (`:478`), and
`env:`/`@file:` indirection failures. Every case produces a diagnostic and a
non-zero exit from `--check-config`, never a partial boot.

### H-10 — Third-party TLS interop evidence

**P2** · `tools/bogo_shim.zig`, `tools/bogo.sh` (new) · **client: none**
**Owner:** `armor-tls` · **Complexity:** M · **Gate:** `zig build bogo-shim-test` + the BoGo runner

S-18 with the emphasis on **evidence**. The current honest position is a
reproducible 24-pass/3-skip required baseline, with the exploratory full corpus
still failing. That honesty is the asset; the item is to widen the evidence
without weakening the claim.

**Accept:** a pinned BoringSSL runner produces a reproducible pass/skip/fail
count in CI, every `DisabledTests` entry names a reason, and the delta from the
previous run is visible. **No corpus-wide pass is claimed without the artifact.**

---



# Track L — Polish

**The premise of this track is that a daemon a human cannot navigate, and a
command surface a user cannot discover, are both defects.** The two headline
numbers are `src/daemon/server.zig` at **102,152 lines** and `HELP` at **6
topics** against **159 registered commands**.

Neither is a bug in the sense that anything computes the wrong answer. Both are
the kind of debt that makes every *other* item in this file more expensive, which
is why they belong in a release rather than in a someday list.

### L-01 — Decompose `server.zig`

**P0** · `src/daemon/server.zig` · **client: none**
**Owner:** `zig-coder` · **Complexity:** XL (0.7 takes the first slice) · **Gate:** `zig build check` + `zig build test`

`src/daemon/server.zig` is **102,152 lines** — roughly **17%** of the entire
590,831-line Zig tree in one file, and more than ten times the next largest
(`src/daemon/services.zig`, 9,765).

It contains, verified: the `ConnState` struct (`:2447`), a private io_uring
`ringlane` namespace (`:860`), the reactor loop and every completion handler
(`:7989`, `:9501`, `:9590`), `onTimerTick` with its ~20 reactor-0 guards
(`:6170`), and — because tests are co-located in Zig — a large share of the
suite, including 22 of the 45 exploit tests.

The costs are concrete, not aesthetic:

- **Review.** A reviewer cannot hold the file's invariants in working memory,
which is precisely how S-02's missing reactor-0 guard shipped.
- **Compile.** Nearly every focused test lane pulls the whole unit in (P-12).
- **Ownership.** The agent roster assigns owners by subsystem, but one file
spanning ten subsystems has no single owner.
- **Merge.** Concurrent work on unrelated subsystems collides in one file.

0.7 does not finish this. It takes the first slice and, more importantly,
**establishes the seam pattern** so subsequent slices are mechanical:


| Slice | Extract                                      | Why first                                                                                                           |
| ----- | -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| 1     | The `ringlane` namespace (`:860`+)           | P-06 deletes it outright in favor of the substrate implementation — the extraction and the dedup are the same work. |
| 2     | `ConnState` and its buffer policy (`:2447`+) | P-03 needs to reason about it in isolation; it has a clean boundary.                                                |
| 3     | Timer maintenance (`onTimerTick`, `:6170`)   | L-03 makes reactor affinity structural, which is far easier in a dedicated module.                                  |


**Accept:** each slice moves to its own module with **no behavior change**,
proven by `zig build test` and a P-01 baseline that does not move. `server.zig`
shrinks by the extracted line count. The extraction order is recorded so the
remaining slices are queued rather than improvised.

**Non-goal:** a full rewrite. Three clean slices with a stated pattern beats a
big-bang refactor of a file this load-bearing.

### L-02 — `HELP` that covers the command surface

**P0** · `src/proto/help_db.zig`, `src/daemon/modules/` · **client: gated**
**Owner:** `onyx-server-ircx` · **Complexity:** M · **Gate:** `zig build test-ircx`

`src/proto/help_db.zig` is 347 lines and defines **6** `HelpTopic` entries. The
daemon registers **159** commands across twelve modules
(`src/daemon/modules/manifest.zig:27-39`):


| Module              | Commands |
| ------------------- | -------- |
| `oper_security.zig` | 35       |
| `accounts.zig`      | 31       |
| `user_query.zig`    | 17       |
| `services_ext.zig`  | 13       |
| `ircx.zig`          | 13       |
| `messaging.zig`     | 12       |
| `query_info.zig`    | 11       |
| `channel_ops.zig`   | 11       |
| `feature_misc.zig`  | 10       |
| `introspect.zig`    | 4        |
| `webhook.zig`       | 1        |
| `upgrade.zig`       | 1        |


**About 4% of the command surface is documented in** `HELP`**.** The numerics are
right (`RPL_HELPSTART` 704, `RPL_HELPTXT` 705, `RPL_ENDOFHELP` 706,
`ERR_HELPNOTFOUND`, `help_db.zig:8-11`) and the topic format is sound — there
is simply almost no content. For the 35 oper commands in particular, `HELP` is
the *only* discovery mechanism a connected operator has.

The registry already rejects duplicate commands at **compile time**
(`manifest.zig:6-9` — `registry.Registry` `@compileError`s on duplicates,
missing dependencies, and conflicts). That same comptime reflection can require
a help topic.

**Accept:** every registered command resolves a `HELP` topic with a syntax line,
a one-line description, and its required access level. A command registered
without a topic **fails the build**, the way a duplicate command already does.
Coverage is reported as a number, and it is 100%.

**Dependency:** L-04 (access metadata) supplies the access level; do L-04 first
or the topics need a second pass.

### L-03 — Reactor affinity as a type, not a convention

**P1** · `src/daemon/server.zig` · **client: none**
**Owner:** `onyx-server-reactor` · **Complexity:** L · **Gate:** `zig build test-server` + `zig build dst`

S-02 audits the reactor-0 guards; H-06 tests them; this item tries to make the
class *unrepresentable*.

The guard is currently a convention repeated by hand at ~20 call sites in two
different spellings (see S-02). Conventions that must be remembered at twenty
sites are conventions that will be forgotten at the twenty-first — and the cost
of forgetting, established once already in production, is a roster decay with
empty `NAMES` and `401` on cross-node `PRIVMSG`.

Directions worth evaluating, none pre-judged: a `Reactor0Only` wrapper that
cannot be called from a non-zero reactor; splitting `onTimerTick` into
`onTimerTickShared` (reactor 0) and `onTimerTickLocal` (every reactor) so
placement is a choice the author must make; or a debug-mode assertion that a
shared-state mutation is on reactor 0.

**Accept:** adding a shared-state timer without the guard fails to compile, fails
a test, or trips a debug assertion — pick one and make it real. The existing ~20
guarded sites migrate to the chosen mechanism with no behavior change.

### L-04 — Command metadata as a queryable surface

**P1** · `src/daemon/registry.zig`, `src/daemon/modules/` · **client: contract**
**Owner:** `onyx-server-ircx` · **Complexity:** M · **Gate:** `zig build test-ircx`

`registry.zig` already models what a client needs: `CommandInvocation` (`:36`)
and an `Access` enum with `any` / `registered` / `oper` (`:43-49`), enforced
**centrally by the dispatcher** so "handlers no longer hand-roll auth checks"
(`:41-42`). That is the hard part, and it is done.

What is missing is exposure. A client cannot ask the daemon what commands exist,
what each requires, or which module provides it — so every client hardcodes a
command list and drifts from the server it is talking to.

**Accept:** a machine-readable command surface — name, module, access level,
parameter arity, and help topic — derived from the registry at comptime rather
than hand-maintained. It feeds `HELP` (L-02), the client's slash-command
registry, and the `onyx-client-contract.v2.json` check. Adding a command updates
all three with no separate edit.

**Cross-repo:** pairs with client item **C-33**; ships **server-first** (see
[§ Cross-cutting](#cross-cutting-server--client-wire-contracts), row X-11).

### L-05 — `WHOIS` completeness and consistency

**P1** · `src/daemon/whois.zig` · **client: gated**
**Owner:** `onyx-server-ircx` · **Complexity:** S · **Gate:** `zig build test-ircx`

`whois.zig` is 1,281 lines and the daemon has substantial identity material to
report: IRCX `PROP` metadata (`src/proto/ircx_prop_store.zig`, 3,811 lines),
account attribution, host cloaking
(`[reference/host-cloaking.md](reference/host-cloaking.md)`), and `whowas`.

The client half (C-01) is merging two divergent identity surfaces. This is the
server half: one authoritative answer, with cloaking honesty preserved —
**a cloaked host is reported as cloaked, and the real host is never leaked to a
requester not entitled to it.**

**Accept:** `WHOIS` reports account, cloaked host, channels visible to the
requester, idle and signon, oper status with the correct cross-mesh identity,
and available `PROP` metadata — in a documented numeric order. A remote user on
another mesh node returns the same shape as a local one. Reference:
`[reference/commands/](reference/commands/)`.

### L-06 — Operator ergonomics

**P1** · `src/daemon/modules/oper_security.zig` · **client: gated**
**Owner:** `onyx-server-ircx` · **Complexity:** M · **Gate:** `zig build test-ircx` + `zig build test-server`

`oper_security.zig` registers **35 commands** — the largest single module — and
they are the commands used under time pressure, during an incident, by a human
typing into a raw IRC session.

That population deserves specific affordances: consistent confirmation for
destructive actions, a dry-run where a mistake is expensive, output that is
readable in a client that does not parse the numeric, and every action landing
in `audit_trail.zig`.

**Accept:** every destructive oper command has a documented confirmation or
dry-run path and an audit-trail entry. Error messages name the failing
precondition rather than returning a bare numeric. Pairs with client item C-03.

### L-07 — Diagnostics an operator can act on

**P2** · `src/daemon/`, `src/daemon/metrics_http.zig` · **client: none**
**Owner:** `zig-coder` · **Complexity:** M · **Gate:** `zig build test-server`

An error that names its cause and its remedy is the difference between a
five-minute incident and an hour. This is the log/diagnostic counterpart to
L-06's command-level messages: startup failures, TLS handshake rejections,
mesh admission refusals, and capsule decode failures should each say what was
expected, what arrived, and what to do.

**Accept:** every fail-closed rejection path logs the reason at a level an
operator sees, with enough context to act and **without leaking secret material**
— no key bytes, no plaintext, no full certificate contents in a rejection log.

### L-08 — Config reference and sweep currency

**P2** · `docs/reference/config.md`, `docs/config-sweep/` · **client: none**
**Owner:** `doc-writer` + `onyx-server-config` · **Complexity:** S · **Gate:** `zig build test-config`

`[reference/config.md](reference/config.md)` is the repo's citation exemplar and
`docs/config-sweep/` is the per-key accuracy audit. Config keys are added far
more often than the sweep is re-run.

The `[io]` section is a live example: it currently documents exactly one key,
`cqe_batch` (`etc/onyx-server.reference.toml:462-464`,
`config_format.zig:1335`). If P-02 adds feature toggles, the reference, the
sweep, and the annotated TOML all move together or they lie.

**Accept:** every key in `config_format.zig` appears in
`[reference/config.md](reference/config.md)` with its range and default cited to
`file:line`, and in `etc/onyx-server.reference.toml`. A key present in one and
absent from another fails `zig build test-config`.

### L-09 — Documentation hub completeness

**P2** · `docs/README.md` · **client: none**
**Owner:** `doc-writer` · **Complexity:** S · **Gate:** manual review

`[README.md](README.md)` does not link `docs/audit/` or `docs/ops/`, both of
which hold current operational material — `docs/ops/` alone contains 24 release
and deployment runbooks, including the most recent
`[ops/release-v0.5.8-stale-mesh-liveness.md](ops/release-v0.5.8-stale-mesh-liveness.md)`.
Material an operator needs mid-incident should not require knowing it exists.

**Accept:** the hub links every current documentation directory. Historical trees
(`docs/planning/`, `docs/research/`) are linked **and** banner-marked as design
intent, so nobody mistakes a plan for behavior.

### L-10 — Codename glossary discipline

**P3** · `docs/reference/glossary.md` · **client: none**
**Owner:** `doc-writer` · **Complexity:** S · **Gate:** manual review

The mythos vocabulary — Undertow, Mooring, Ripple, Helix, Armor, Ringlane,
Koshi, Memo, MeshPass — is a real cognitive cost for a new contributor, and
`[reference/glossary.md](reference/glossary.md)` already maps each to source.

**Accept:** every codename's first use in a document links to the glossary, and
the glossary resolves each to a current `src/` path. A codename with no source
mapping is either removed or explained.

### L-11 — Numerics, modes, and ISUPPORT currency

**P2** · `docs/reference/protocol/` · **client: gated**
**Owner:** `doc-writer` + `onyx-server-ircx` · **Complexity:** M · **Gate:** `zig build test-ircx`

`[reference/protocol/numerics.md](reference/protocol/numerics.md)`,
`[modes.md](reference/protocol/modes.md)`,
`[isupport.md](reference/protocol/isupport.md)`, and
`[caps.md](reference/protocol/caps.md)` describe the client-visible wire surface
— the documents a third-party client implementer actually reads. A drifted
numeric here is a client bug that looks like a server bug.

The `help_db.zig` numerics are a good sign of what "current" looks like: 704,
705, 706 are defined in source at `:8-10` and can be checked mechanically.

**Accept:** the numeric, mode, and ISUPPORT tables are generated from or verified
against source, and drift fails a test rather than waiting for a reader to
notice. Pairs with L-04, which supplies the command half of the same surface.

### L-12 — Release runbook for 0.7

**P1** · `docs/ops/`, `docs/RUNBOOK.md` · **client: none**
**Owner:** `doc-writer` + `onyx-server-deploy` · **Complexity:** S · **Gate:** manual review

`docs/ops/` holds a per-release runbook for every recent deploy. 0.7 changes
more surface at once than any of them — potentially io_uring features (P-02),
a decomposed `server.zig` (L-01), and OCG2 projection (S-05).

**Accept:** a 0.7 runbook exists before the first deploy attempt, covering
`--check-config` **first**, the USR2 hot-upgrade path, a rollback for each
newly-enabled feature, and the verification steps that prove the mesh reconverged.
Deploy remains **human-gated**; this document authorizes nothing.

---



## Cross-cutting: server ↔ client wire contracts

These items cannot ship from one repo alone. The **order** column is the safety
rule: a client that sends a token the daemon does not understand is a broken
session, while a daemon that advertises a capability no client uses is inert.
So **capability and token additions ship server-first**; **client-driven
semantics that reinterpret existing wire data ship client-first**.


| #    | Contract                    | Server item | Client item | Order            | Why                                                                                                                                        |
| ---- | --------------------------- | ----------- | ----------- | ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| X-1  | Group E2EE control plane    | S-12        | C-10        | **server-first** | Authority, outbox, and replay guard must be live and advertised before the client emits group-control frames a node would reject.          |
| X-2  | Server-history search       | S-06        | C-05        | **server-first** | A search command the daemon does not implement returns an error to the user.                                                               |
| X-3  | Simulcast layer selection   | S-16        | C-12        | **server-first** | The SFU must select a layer before publishers send more than one, or the extra layer is waste.                                             |
| X-4  | Operator introspection      | S-04, S-09  | C-03, C-18  | **server-first** | Ward, flood, and mesh state must be queryable before a UI renders it.                                                                      |
| X-5  | Mesh-wide presence          | S-08        | C-15        | **server-first** | Cross-node presence is a daemon CRDT question; the client renders what converges.                                                          |
| X-6  | Stable thread keys          | S-03        | C-22        | **server-first** | A thread identity that does not survive a node change is worse than no threading.                                                          |
| X-7  | Device directory            | S-13        | C-11        | **server-first** | Directory entries are replicated metadata the daemon must accept and converge.                                                             |
| X-9  | NAMES burst semantics       | S-02        | C-02        | **client-first** | Append-vs-replace is a client interpretation of existing `353` traffic; the client must be correct before the daemon changes burst timing. |
| X-10 | Cross-device continuity     | S-19        | C-29        | **server-first** | Requires a daemon-side handoff token the client then consumes.                                                                             |
| X-11 | Command metadata surface    | L-04        | C-33        | **server-first** | The client cannot query a registry the daemon does not expose. Until it does, every client hardcodes a command list and drifts.            |
| X-12 | `WHOIS` identity shape      | L-05        | C-01        | **server-first** | The client's merged identity surface renders whatever `WHOIS` returns; the numeric order and cloaking honesty must be settled first.       |
| X-13 | Operator command ergonomics | L-06        | C-03        | **server-first** | Confirmation, dry-run, and audit-trail semantics are daemon-side; the oper desk surfaces them.                                             |


(X-8 in the client roadmap is client-only and has no server item.)

**0.7 deploy order.** Ten of the thirteen rows are **server-first**, which sets
the release sequence: the daemon ships 0.7 with the new capabilities advertised
but inert, the client ships against them, and only then does a capability count
as delivered. The two **client-first** rows (X-9) are interpretations of existing
wire data and carry no daemon dependency — they can land at any point.

A capability the daemon advertises and no client consumes is inert and harmless.
A token the client sends and the daemon rejects is a broken session. That
asymmetry, not convenience, is what fixes the order.

**Contract verification.** The machine-readable contract lives in this repo at
`docs/reference/protocol/onyx-client-contract.v1.json` and
`onyx-client-contract.v2.json`, and the client checks against it with
`pnpm check:server-contract` / `pnpm check:server-contract-v2`. Every row above
must land in the v2 contract before its client item is marked done.

## Gates

Per-subsystem focused lanes that exist today, all from `build.zig`:

```bash
zig build check              # type-check, no binary
zig build test-tls           # Armor TLS, mTLS, ECH, RPK, DC, record size
zig build test-mesh          # Undertow, S2S, repair, secured links
zig build test-helix         # upgrade, migration, resume, capsules, handoff
zig build test-media         # media, DTLS-SRTP, SFU, WebTransport, RTP/RTCP
zig build test-ircx          # IRCX, PROP, ACCESS, DATA, LISTX, MODEX, SACCESS
zig build test-event-spine   # event spine, EVENT, observe, playback
zig build test-exploit       # the adversarial fail-closed corpus (alias: test-attack)
zig build test-config        # TOML parsing, boot projection, reference config
zig build test-server        # daemon/server integration and auth
zig build test-services      # services, account, SASL, TOTP, WebAuthn, session, MEMO
zig build test-session       # reusable-session, migration, replica, World restore
zig build test-cli           # the armor CLI toolkit
zig build test-smoke         # fast semantic + TLS/server/config smoke
zig build test               # full suite (~6,280 tests)
zig build fuzz               # bounded corpus replay; --fuzz for coverage-guided
zig build ct-check           # opt-in dudect-style constant-time harness
zig build bogo-shim-test     # BoGo shim loopback self-tests
zig build all-checks         # check + wasm + full tests + bounded fuzz + BoGo self-tests
```

**Two lanes this roadmap proposes and that do not exist yet.** Both are
themselves roadmap items, not assumed infrastructure:

```bash
zig build bench              # P-01 — reproducible workloads vs a committed baseline
zig build dst                # H-05 — seeded simulation campaigns, prints failing seed
```

Deployment is a separate, human-gated decision. `--check-config` runs **first** —
a `ParseError` at boot silently starts the default identity and needs a full
restart to recover. Prefer the `USR2` zero-drop hot-upgrade over a hard restart;
see `[RUNBOOK.md](RUNBOOK.md)` and `[guide/upgrade.md](guide/upgrade.md)`. Nothing
in this roadmap authorizes a deploy or a push.

## 0.7 exit criteria

The ship gate. Every line is a **verifiable artifact**, not a judgement call —
if it cannot be pointed at, it is not met.

**Measurement (Track P)**

1. `zig build bench` exists, runs the six P-01 workloads, and compares against a
  committed baseline that records its machine.
2. Every P-track item claiming an improvement cites a before/after from that
  baseline. No unmeasured perf claim ships in a release note.
3. The io_uring feature posture is **stated**: each of the seven `RingFeatures`
  toggles is documented as on-by-default, opt-in, or deliberately off, with the
   measurement behind the choice (P-02).

**Assurance (Track H)**

1. `zig build dst` exists, runs seeded campaigns, and prints the failing seed
  (H-05).
2. A USR2-under-fault campaign passes, covering every enabled io_uring feature
  (H-06).
3. `zig build test-exploit` reports **per-class** counts, and each of the four
  named gap subsystems — crypto, Helix, media, OCG2 — has at least one
   rejection test (H-01, H-02).
4. `zig build ct-check` runs in the pre-push gate rather than opt-in (H-04).
5. The capsule version-drift check fails a layout change without a version bump
  (H-07).

**Usability and maintainability (Track L)**

1. `HELP` covers **100%** of registered commands, and a command without a topic
  fails the build (L-02).
2. Three `server.zig` slices are extracted with no behavior change and no
  baseline movement, and the remaining extraction order is recorded (L-01).
3. The reactor-0 guard is structural — compile error, test, or debug assertion
  (L-03).
4. A 0.7 deploy runbook exists in `docs/ops/` before the first deploy attempt
  (L-12).

**Correctness, unconditionally**

1. `zig build all-checks` is green.
2. Every fail-closed invariant this roadmap names still holds and has a test
  that would fail if it were made permissive: `require_signed_frames` rejects
    on a keyless node, resource exhaustion is counted rather than silent, an
    unknown CLI argument is not treated as a config path, and liveness refresh
    stays orthogonal to CRDT value LWW.

**Explicitly not required for 0.7:** every Wave 3/4 item, PQ signing (S-26),
standards WebRTC interop (S-27), and the full `server.zig` decomposition. 0.7 is
finish-and-prove, not finish-everything.

## Known documentation drift

Found while grounding this roadmap, recorded here rather than silently fixed.
Each carries a severity and the agent that owns the fix; **this document does not
change code.**

**MEDIUM — stale claim in a design doc.**
`[dev/tls-roadmap.md](dev/tls-roadmap.md)` Phase 4 item 4.3 describes DTLS as
"full DTLS 1.2/1.3 + DTLS-SRTP lib, **no live listener**." That is stale:
`src/daemon/media_plane.zig:22-23` imports `dtls12_server` and `dtls13_server`,
and `media_plane.zig:111-116` carries a live `dtls_enabled` flag, a per-peer
`dtls_server.Terminator`, and its session table. The library is wired into the
media plane. *Owner:* `doc-writer`*.*

**MEDIUM — blueprint describes a tree that does not exist.**
`[research/exploit-suite-blueprint.md](research/exploit-suite-blueprint.md)`
specifies a `src/security/exploit/` tree. That directory does not exist; the
corpus is 45 `test "exploit:` cases distributed across production modules and
selected by the `build.zig:304` filter. See S-01 and H-01. *Owner:*
`onyx-server-hardener` *(decide tree-or-manifest), then* `doc-writer`*.*

**LOW — hub omissions.** `[README.md](README.md)` does not link `docs/audit/` or
`docs/ops/`, both of which contain current operational material — `docs/ops/`
alone holds 24 release runbooks. See L-09. *Owner:* `doc-writer`*.*

**HIGH — dead performance surface.** Every `RingFeatures` fast path in
`src/daemon/server.zig:866-872` is unreachable at runtime. `baseline` is
all-false (`:875`), the server config field defaults to it (`:1972`), it is
passed unchanged into `RingCore.init` (`:4359`), and the `[io]` config section
exposes only `cqe_batch` (`config_format.zig:1335`,
`etc/onyx-server.reference.toml:462-464`). **Expected:** a runtime-probed
feature set on a modern kernel. **Actual:** plain accept/recv/send on every
deployment. **Trigger:** any deployment — this is the default and only path.
This is a *capability* gap rather than a correctness bug, and no document in
`docs/` currently claims otherwise, so it is not a doc correction — it is P-02.
*Owner:* `onyx-server-reactor`*.*

**MEDIUM — duplicated subsystem.** Two io_uring implementations coexist:
`src/substrate/io/ring.zig` (741 lines, self-described "skeleton" at `:4`, not
on the daemon's path) and the private `ringlane` namespace at
`src/daemon/server.zig:860` (live). The better-factored one — with the pure
`user_data` codec and the fail-closed `probe` narrowing — is the one not
running. See P-06. *Owner:* `onyx-server-reactor`*.*

**MEDIUM — DST seam incomplete.** `src/substrate/reactor.zig` covers only
monotonic and wall-clock time; `submit/poll/accept/recv/send` are deferred to
"M1 when Ringlane (io_uring) is implemented" (`reactor.zig:9-10`). Any
documentation implying the daemon can currently run its **I/O** against the
deterministic simulator would be wrong — time is abstracted, I/O is not. See
H-05, P-06. *Owner:* `onyx-server-dst`*.*

**LOW — upstream toolchain defect, correctly documented in-tree.**
Coverage-guided `zig build fuzz --fuzz` builds and starts, then crashes in
Zig's own fuzzer runtime (`panic: start index 1 is larger than end index 0` in
`lib/zig/fuzzer.zig`), reproducible with a trivial zero-Onyx target
(`build.zig:708-716`). Recorded here only so the roadmap's fuzzing claims are
read against it. See H-03. *Owner:* `armor-tls` *to re-verify on toolchain bumps.*

## Related docs

- [`docs/features/INVENTED-FEATURES-CATALOG.md`](features/INVENTED-FEATURES-CATALOG.md) — F-01 … F-68: speculative features the daemon does not have today, grounded against HEAD; the Top-20 game-changer shortlist is at the top of that file.
- [`docs/features/GAME-CHANGERS-50.md`](features/GAME-CHANGERS-50.md) — GB/GS/GC-01 … 50: a **cross-repo** catalog of 50 game-changing features spanning this daemon and the Onyx client (15 `Both` · 20 `Server` · 15 `Client`), with a Top-10 must-ship-for-0.7 shortlist. Its thesis is that much of `src/substrate/` is mature with **zero external consumers**, so many wins are product surfaces over algorithms already in tree. Carries a declared-overlap table against F-01 … F-68 above. Client-side companion: [`onyx/docs/features/GAME-CHANGERS-50.md`](../../onyx/docs/features/GAME-CHANGERS-50.md).
