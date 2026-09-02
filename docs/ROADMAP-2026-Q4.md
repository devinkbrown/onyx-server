# Onyx Server roadmap — Q4 2026

*Subsystem-level feature roadmap for the daemon, in four waves. Ambitious about
where the stack goes; honest about what is in the tree today.*

Current daemon version: **0.5.8** (`build.zig.zon:18`).

Companion: **[onyx `docs/ROADMAP-2026-Q4.md`](../../onyx/docs/ROADMAP-2026-Q4.md)** — the
client half. Items whose wire contract spans both repos are listed once in each
file and reconciled in [§ Cross-cutting](#cross-cutting-server--client-wire-contracts).

This roadmap does **not** supersede the existing planning documents; it sits
above them and points into them:

- [`dev/tls-roadmap.md`](dev/tls-roadmap.md) — the phase-by-phase Armor TLS gap analysis with DONE/TODO status. Still the authority for TLS item detail.
- [`design/e2ee-everywhere-blueprint.md`](design/e2ee-everywhere-blueprint.md) — group/channel E2EE design.
- [`research/exploit-suite-blueprint.md`](research/exploit-suite-blueprint.md) — the intended shape of the adversarial corpus.
- [`audit/CODEBASE_AUDIT_2026-07-18.md`](audit/CODEBASE_AUDIT_2026-07-18.md) — the last full codebase audit.

Those are **design intent and gap analysis**. Where they disagree with
[`reference/`](reference/) or with the source, the source wins.

## How to read an item

- **Priority** — `P0` ship-blocking · `P1` this wave · `P2` scheduled · `P3` opportunistic.
- **Subsystem** — the owning source area. One item, one owner.
- **Client** — `none` (daemon-internal), `gated` (a client can already consume
  it), or `contract` (needs a coordinated wire change — see § Cross-cutting).
- **Accept** — the observable condition that closes the item, expressed as a test
  or a runtime proof.

Waves are ordered by dependency. Nothing in **Next** should start before its
**Now** prerequisites land.

## Wave index

| Wave | Theme | Items |
| --- | --- | --- |
| [Now](#wave-1--now) | Assurance you can trust, OCG2 past observe, mesh liveness | S-01 … S-09 |
| [Next](#wave-2--next) | E2EE authority, TLS finishing work, media selection | S-10 … S-18 |
| [Later](#wave-3--later) | Multi-node scale, storage, continuity | S-19 … S-25 |
| [Moonshot](#wave-4--moonshot) | PQ signing, standards interop, autonomous operation | S-26 … S-30 |

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

[`research/exploit-suite-blueprint.md`](research/exploit-suite-blueprint.md)
specifies a dedicated `src/security/exploit/` tree with a harness. **That
directory does not exist.** The corpus is real but structurally scattered, which
means nobody can answer "what attack classes are covered?" without grepping.

**Accept:** a corpus index — either the blueprint's tree or an equivalent
manifest — that names each attack class, its coverage, and its gaps. The
`test-exploit` count is reported per class, not as one number. Adding an
unclassified exploit test fails the gate.

### S-02 — Multi-reactor timer-guard audit

**P0** · `src/daemon/server.zig` · **client: none**

`onTimerTick` runs on **every** reactor thread. Shared-state maintenance must
gate on reactor zero — the pattern is `if (self.rx() != &self.reactors[0]) return;`
at `src/daemon/server.zig:5163` and `src/daemon/server.zig:5259`, with
`rx()` resolving the current reactor at `src/daemon/server.zig:4254`.

A missing guard here is not theoretical: it caused a live roster decay where
peers were reaped past their staleness TTL, producing empty `NAMES`, a missing
remote-oper prefix, and `401` on cross-node `PRIVMSG`. The most recent commits
on this branch (`d86e1f0 fix(mesh): recover stale links and exact gauges`,
`744360e docs(ops): record stale mesh liveness release`) are the recovery from
exactly this class.

**Accept:** every timer-driven mutation of shared or mesh state is either
reactor-0-gated or provably reactor-local, enumerated in a single audit table.
A new unguarded shared-state timer fails review with a named check, not vibes.

### S-03 — Event Spine v2

**P1** · `src/daemon/event_spine.zig`, `src/daemon/event_history.zig` · **client: contract**

The spine is a typed oper event bus with an `EventCategory` mask, owning no
allocation and no global state — callers provide subscriber storage, publish
sinks, and render buffers (`src/daemon/event_spine.zig:5-8`). Replay, collapse
(`event_collapse.zig`), and a replay guard (`event_spine_replay_guard.zig`) all
ship, and the client consumes it via its `OperEventConsole`.

[`design/event-spine-mesh-v2.md`](design/event-spine-mesh-v2.md) describes the
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
live. Per [`ops/ocg2-runtime-activation.md`](ops/ocg2-runtime-activation.md):
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

[`architecture/observability-stats.md`](architecture/observability-stats.md)
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
`[[tls.ech_keys]]`. Per [`dev/tls-roadmap.md`](dev/tls-roadmap.md) item 5.1, the
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
([`dev/tls-roadmap.md`](dev/tls-roadmap.md) item 5.3, `[tls] raw_public_key`
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
in [`design/e2ee-everywhere-blueprint.md`](design/e2ee-everywhere-blueprint.md)
and the activation staging in
[`ops/e2ee-group-authority-v2-activation.md`](ops/e2ee-group-authority-v2-activation.md).
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
layout has a bumped version range and a cross-version decode test. `zig build
test-helix` reports cross-version coverage, not just round-trip coverage.

### S-15 — Deterministic simulation as a first-class lane

**P1** · `src/substrate/sim.zig`, `src/substrate/fault_loom.zig` · **client: none**

The infrastructure exists but is barely used. `src/substrate/sim.zig` is
referenced only from `src/substrate/root.zig`; `fault_loom.zig` has exactly three
consumers, all Helix DST harnesses (`session_adopt_dst.zig`,
`multishard_upgrade_dst.zig`, `s2s_adopt_dst.zig`). There is **no `zig build dst`
step** — DST cases run inside the ordinary test suite, so there is no way to run
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
[`dev/tls-roadmap.md`](dev/tls-roadmap.md) item 0.3, the remaining work is
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

[`design/session-resume-anywhere-blueprint.md`](design/session-resume-anywhere-blueprint.md)
is the design. Session replicas and migration exist within Helix.

**Accept:** a session resumes on a different mesh node with read markers, away
state, and monitor lists intact, without the receiving node ever holding
decryptable E2EE state. Pairs with client item C-29.

### S-20 — Storage: OroStore at scale

**P2** · `src/daemon/store.zig`, `src/substrate/wal.zig` · **client: none**

[`guide/persistence.md`](guide/persistence.md) documents the key/value store.

**Accept:** a documented growth model with measured compaction behavior and a
bounded recovery time from a WAL of a stated size.

### S-21 — Exact-once message relay v2

**P2** · `src/substrate/undertow/message_relay_v2.zig`, `src/daemon/relay_v2_*.zig` · **client: none**

[`design/message-v2-exact-once.md`](design/message-v2-exact-once.md) is the
design; `relay_v2_activation.zig`, `relay_v2_event_log.zig`,
`relay_v2_outbox.zig`, and `relay_v2_replay_guard.zig` are the staging.

**Accept:** exactly-once delivery survives a partition, a node restart, and a
USR2 upgrade, proven by a DST campaign from S-15.

### S-22 — Connection classes and admission at scale

**P3** · `src/daemon/conn_class.zig`, `src/substrate/admission.zig` · **client: none**

`[class.*]` connection classes already provide registration-time
resource/admission/flood policy with bounded growable SendQ and RecvQ
([`README.md`](README.md)).

**Accept:** admission decisions under synthetic load are bounded and fair, with
a measured worst-case rather than an assumed one.

### S-23 — CRL and OCSP: the fetch half

**P3** · `src/crypto/crl.zig`, `src/daemon/ocsp_staple.zig` · **client: none**

CRL checking is wired fail-open with caller-supplied DER; the named follow-up is
an in-daemon CDP fetch and cache. OCSP stapling is complete with a background
producer; its follow-ups are a TLS 1.2 client round-trip test, delegated
responder support, and exponential backoff on fetch failure
([`dev/tls-roadmap.md`](dev/tls-roadmap.md) items 4.2 and 2.1).

**Accept:** CDP fetch with a cache and a bounded failure mode. Delegated OCSP
responders are accepted only with an exact `id-kp-OCSPSigning` EKU — `anyEKU`
does not count — issuer-signed and in-window.

### S-24 — Multi-certificate daemon plumbing

**P3** · `src/daemon/tls_sni_load.zig`, `src/daemon/config_format.zig` · **client: none**

SNI-based certificate selection is complete **as a library** — the engine picks
per-ClientHello from `Config.sni_certs` with case-insensitive exact and
single-label wildcard matching. The daemon-side multi-cert `[tls]` configuration
and load path is called out as a separate follow-up, and it is the ECH
prerequisite ([`dev/tls-roadmap.md`](dev/tls-roadmap.md) item 2.4).

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
certificates yet ([`dev/tls-roadmap.md`](dev/tls-roadmap.md) item 5.4).

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

## Cross-cutting: server ↔ client wire contracts

These items cannot ship from one repo alone. The **order** column is the safety
rule: a client that sends a token the daemon does not understand is a broken
session, while a daemon that advertises a capability no client uses is inert.
So **capability and token additions ship server-first**; **client-driven
semantics that reinterpret existing wire data ship client-first**.

| # | Contract | Server item | Client item | Order | Why |
| --- | --- | --- | --- | --- | --- |
| X-1 | Group E2EE control plane | S-12 | C-10 | **server-first** | Authority, outbox, and replay guard must be live and advertised before the client emits group-control frames a node would reject. |
| X-2 | Server-history search | S-06 | C-05 | **server-first** | A search command the daemon does not implement returns an error to the user. |
| X-3 | Simulcast layer selection | S-16 | C-12 | **server-first** | The SFU must select a layer before publishers send more than one, or the extra layer is waste. |
| X-4 | Operator introspection | S-04, S-09 | C-03, C-18 | **server-first** | Ward, flood, and mesh state must be queryable before a UI renders it. |
| X-5 | Mesh-wide presence | S-08 | C-15 | **server-first** | Cross-node presence is a daemon CRDT question; the client renders what converges. |
| X-6 | Stable thread keys | S-03 | C-22 | **server-first** | A thread identity that does not survive a node change is worse than no threading. |
| X-7 | Device directory | S-13 | C-11 | **server-first** | Directory entries are replicated metadata the daemon must accept and converge. |
| X-9 | NAMES burst semantics | S-02 | C-02 | **client-first** | Append-vs-replace is a client interpretation of existing `353` traffic; the client must be correct before the daemon changes burst timing. |
| X-10 | Cross-device continuity | S-19 | C-29 | **server-first** | Requires a daemon-side handoff token the client then consumes. |

(X-8 in the client roadmap is client-only and has no server item.)

**Contract verification.** The machine-readable contract lives in this repo at
`docs/reference/protocol/onyx-client-contract.v1.json` and
`onyx-client-contract.v2.json`, and the client checks against it with
`pnpm check:server-contract` / `pnpm check:server-contract-v2`. Every row above
must land in the v2 contract before its client item is marked done.

## Gates

Per-subsystem focused lanes, all from `build.zig`:

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
zig build test               # full suite
zig build all-checks         # check + wasm + full tests + bounded fuzz + BoGo self-tests
```

Deployment is a separate, human-gated decision. `--check-config` runs **first** —
a `ParseError` at boot silently starts the default identity and needs a full
restart to recover. Prefer the `USR2` zero-drop hot-upgrade over a hard restart;
see [`RUNBOOK.md`](RUNBOOK.md) and [`guide/upgrade.md`](guide/upgrade.md). Nothing
in this roadmap authorizes a deploy or a push.

## Known documentation drift

Found while grounding this roadmap, recorded here rather than silently fixed:

- [`dev/tls-roadmap.md`](dev/tls-roadmap.md) Phase 4 item 4.3 describes DTLS as
  "full DTLS 1.2/1.3 + DTLS-SRTP lib, **no live listener**." That is stale:
  `src/daemon/media_plane.zig:22-23` imports `dtls12_server` and `dtls13_server`,
  and `media_plane.zig:111-116` carries a live `dtls_enabled` flag, a per-peer
  `dtls_server.Terminator`, and its session table. The library is wired into the
  media plane.
- [`research/exploit-suite-blueprint.md`](research/exploit-suite-blueprint.md)
  specifies a `src/security/exploit/` tree. That directory does not exist; the
  corpus is 45 `test "exploit:` cases distributed across production modules and
  selected by the `build.zig:304` filter. See S-01.
- [`README.md`](README.md) does not link `docs/audit/` or `docs/ops/`, both of
  which contain current operational material.
