<!-- SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com> -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Onyx 0.7 — Unified Feature Roadmap (cross-repo)

**Audience: contributor and maintainer.** This is the single-page planning index
for the Onyx 0.7 release across both the daemon and the SolidJS client. It
carries the authoritative P0/P1/P2 priority tables with owner agents and build
gates; the per-item detail lives in the documents linked below, not duplicated
here.

**0.7 is an extremely major release** (same version number). Portable
performance, per-OS kernel features, Armor TLS/CLI, IRCX expansion, client
IRCX adaptation, and the harden pass live in
[`releases/0.7-MAJOR-ROADMAP.md`](releases/0.7-MAJOR-ROADMAP.md). This index
still lists the original tag blockers; the major tracks are additional 0.7
work, not a later version.

**Current versions:** daemon `0.7.0` (`build.zig.zon`) · client `0.1.3`
(`onyx/package.json`).

---

## Document index

| Document | Repo | What it covers |
| --- | --- | --- |
| [`docs/releases/0.7-MAJOR-ROADMAP.md`](releases/0.7-MAJOR-ROADMAP.md) | both | **0.7 major expansion:** PX portable I/O, KX kernel unique features (Linux/BSD/Windows), AX Armor TLS+CLI, IX daemon IRCX, CX client IRCX, HX harden/correctness |
| [`onyx/docs/ROADMAP-0.7-IRCX.md`](../../onyx/docs/ROADMAP-0.7-IRCX.md) | onyx | Client IRCX adaptation slice (CX-1…CX-10) |
| [`docs/ROADMAP-2026-Q4.md`](ROADMAP-2026-Q4.md) | onyx-server | Full daemon feature spine (S-01…S-30) + three release tracks (P-xx, H-xx, L-xx); exit criteria; cross-cutting wire contracts |
| [`docs/releases/0.7-RELEASE-PLAN.md`](releases/0.7-RELEASE-PLAN.md) | onyx-server | Original 0.7 thesis, version audit, gap analysis (D-1…D-8), P0/P1/P2 backlog, Wave 1 dispatch; now a subset of the major plan |
| [`onyx/docs/ROADMAP-2026-Q4.md`](../../onyx/docs/ROADMAP-2026-Q4.md) | onyx | Full client feature spine (C-01…C-33) + two release tracks (CP-xx, CL-xx); in-flight work; cross-cutting wire contracts |
| [`onyx/docs/FEATURE-ROADMAP.md`](../../onyx/docs/FEATURE-ROADMAP.md) | onyx | Client-half unified view; priority tables for C-xx items |
| [`docs/features/INVENTED-FEATURES-CATALOG.md`](features/INVENTED-FEATURES-CATALOG.md) | onyx-server | F-01…F-68 speculative features grounded at HEAD; Top-20 game-changer shortlist for 0.8+ |
| [`docs/features/GAME-CHANGERS-50.md`](features/GAME-CHANGERS-50.md) | both | GB/GS/GC-01…50: cross-repo 50 game-changers (15 `Both` · 20 `Server` · 15 `Client`); Top-10 must-ship-for-0.7 shortlist; declared overlap table against F-01…F-68 — see § Relationship to F-01…F-68 in that file |
| [`onyx/docs/era3-40-game-changers.md`](../../onyx/docs/era3-40-game-changers.md) | onyx | Era-3 client game-changer acceptance ledger (40 items) |
| [`onyx/docs/PRODUCT_OVERHAUL_ROADMAP.md`](../../onyx/docs/PRODUCT_OVERHAUL_ROADMAP.md) | onyx | Product phases P0–P6, positioning, and visual direction |
| [`onyx/docs/PUBLIC_LAUNCH_ROADMAP.md`](../../onyx/docs/PUBLIC_LAUNCH_ROADMAP.md) | onyx | Desktop/packaging/signing claim ledger |

---

## P0 — tag blockers

Items that must land before the 0.7.0 tag. Every accept condition is a
verifiable artifact; see the linked detail documents for the full description.

### Daemon P0

| # | Item | Owner | Owned slice | Gate |
| --- | --- | --- | --- | --- |
| **P0-1** | Benchmark harness — `zig build bench`. Reproducible accept/fan-out/RSS baselines; no perf claim ships without it. | `onyx-server-perf` | `build.zig`, `src/substrate/bench.zig` (new), `tools/bench.sh` (new), `docs/audit/bench-baseline-0.5.8.md` (new) | `zig build bench && zig build check` |
| **P0-2** | Ringlane unification + modern feature adoption. Retire the inline `server.zig:860` shadow; wire the substrate `ring.zig` capability probe; add `[io]` config keys for multishot accept/recv and buf_ring, **default-off**. Preserves exact-cancel-by-`user_data` and Helix USR2. | `onyx-server-reactor` (lead) · `onyx-server-perf` (measurement) | `src/substrate/io/ring.zig`, `src/daemon/server.zig` (ring seam only), `src/daemon/config_format.zig`, `src/daemon/config_boot.zig` | `zig build test && zig build test-helix && zig build bench` |
| **P0-3** | Multi-reactor timer-guard audit. Every timer-driven shared/mesh-state mutation is reactor-0-gated or reactor-local, enumerated in one table. **Gates P0-2.** | `onyx-server-mesh` (audit) · `zig-coder` (fixes) | `docs/audit/timer-guard-0.7.md` (new); fixes in `src/daemon/server.zig` if found | `zig build test-mesh` |
| **P0-4** | DST as a first-class lane — `zig build dst`. Seeded campaigns; failing seed printed. Covers mesh convergence after partition, USR2 under fault injection, and cross-shard delivery ordering. | `onyx-server-dst` | `build.zig` (dst step), `src/substrate/sim.zig`, `src/substrate/fault_loom.zig`, campaign entry points | `zig build dst` |
| **P0-5** | Exploit corpus classification gate. Per-class counts in `test-exploit`; an unclassified `test "exploit:"` fails the build. Closes [S-01](ROADMAP-2026-Q4.md#s-01--consolidate-the-adversarial-exploit-corpus) and [H-01](ROADMAP-2026-Q4.md#h-01--classify-the-exploit-corpus). | `onyx-server-hardener` | `docs/reference/exploit-corpus.md` (new), `tools/exploit_index.sh` (new), `build.zig` (gate hook) | `zig build test-exploit` |
| **P0-6** | Land in-flight uncommitted work: `tls_server.zig` (+91), `tls_client.zig` (+17); `server.zig` (+130) — WHOIS unterminated-reply fix, `RPL_YOUREOPER` text, oper-prefix replay on resume. | `armor-tls` (TLS) · `zig-coder` (server) — review: `onyx-server-crypto-reviewer` | `src/crypto/tls_server.zig`, `src/crypto/tls_client.zig`, `src/daemon/server.zig` | `zig build test-tls && zig build test-server && zig build test-exploit` |
| **P0-7** | Version and release-notes drift. `NEWS.md` entries for 0.5.7 and 0.5.8 reconstructed from git log; `README.md` (v0.5.7) and `packaging/README.md` (v0.5.6) repointed to current. | `doc-writer` | `NEWS.md`, `README.md`, `packaging/README.md` | (documentation — no build gate) |
| **H-02** | Close named exploit-coverage gaps: Helix capsule confusion, media-plane malformed inputs, OCG2 authority forgery, mesh `require_signed_frames` fail-closed test. Each needs a rejection test before S-05 advances OCG2 past observe. Detail: [H-02](ROADMAP-2026-Q4.md#h-02--close-the-named-coverage-gaps). | `onyx-server-hardener` | `src/crypto/`, `src/daemon/helix/`, `src/daemon/media_plane.zig`, `src/daemon/ocg2_*.zig` | `zig build test-exploit` |
| **H-06** | USR2 under fault injection. A campaign injects allocation failure, partial write, and a capsule version mismatch during each upgrade stage; outcome is zero-drop success or clean abort — never a panic. Covers all enabled P0-2 io_uring features. Detail: [H-06](ROADMAP-2026-Q4.md#h-06--usr2-under-fault-injection). | `onyx-server-dst` · `onyx-server-helix-reviewer` | `src/daemon/helix/`, `src/substrate/fault_loom.zig` | `zig build dst && zig build test-helix` |

### Client P0

| # | Item | Owner | Gate |
| --- | --- | --- | --- |
| **C-01** | Full identity surface (WHOIS → profile). One component, one data path; account, cloaked host, E2EE key, local note, presence. In-flight work exists: `WhoisSheet.tsx` (+43), `PeopleProfileCard.tsx` (+14). Detail: [C-01](../../onyx/docs/ROADMAP-2026-Q4.md#c-01--full-identity-surface-whois--profile). | `onyx-ui` (`onyx-irc` for the WHOIS data path) | `pnpm typecheck && pnpm test` |
| **C-02** | Store strangler — first three domains (connection, roster, messages). Extract behind facades; `store.ts` shrinks; no behavior change; NAMES append guard and `useStore` reactivity contract preserved. Detail: [C-02](../../onyx/docs/ROADMAP-2026-Q4.md#c-02--store-strangler-first-three-domains). | `onyx-store` | `pnpm typecheck && pnpm test` |
| **C-10** | Group E2EE product path. Room owner enables encryption, sees exact member+device set, re-key on member removal, fail-closed on seal failure. **Server dependency cleared: S-12 is DONE (see [§ Drift reconciled](#drift-reconciled)).** Detail: [C-10](../../onyx/docs/ROADMAP-2026-Q4.md#c-10--group-e2ee-product-path). | `onyx-crypto` | `pnpm typecheck && pnpm test && pnpm check:server-contract-v2` |

**Original P0 count: 11 daemon + 3 client.** The major-release tracks below
are additional 0.7 work (same tag).

---

## 0.7 major expansion (same version)

Full accept conditions: [`releases/0.7-MAJOR-ROADMAP.md`](releases/0.7-MAJOR-ROADMAP.md).

| Track | IDs | What 0.7 adds |
| --- | --- | --- |
| **PX** portable performance | PX-0…PX-6 | `IoBackend` trait; Linux ownership-safe io flags; Windows IOCP; BSD/macOS kqueue; portable Helix fail-closed; per-OS benches |
| **KX** kernel unique features | KX-L1…L12, KX-B0…B5, KX-O1…O4, KX-W1…W5, KX-X1…X3 | Linux FASTOPEN/Landlock/seccomp/MSG_RING/kTLS rekey/`openat2`/pidfd; FreeBSD `SO_REUSEPORT_LB`/Capsicum/KTLS; OpenBSD pledge/unveil; Windows IOCP/RIO/Job objects; boot capability matrix |
| **AX** Armor TLS + CLI | AX-0…AX-8 | AX-0/AX-1 **done** (`armor ocsp`/`crl` verify fail-closed). Remain: `s_client`/`s_server`; CLI sandbox; CT/`http_fetch` (AX-5 landed in source); BoGo CI; `enc` stays stubbed |
| **IX** expanded IRCX (daemon) | IX-1…IX-10 | Draft matrix; MODEX/LISTX/WHISPER/DATA/ACCESS/SACCESS/auditorium/PROP/EVENT/AUTH/HELP completeness + hostile tests |
| **CX** client IRCX | CX-1…CX-10 | LISTX browser, MODEX UI, WHISPER compose, PROP settings, EVENT for people, ACCESS finish, auditorium roster, DATA lines, identity+PROP, slash verbs |
| **HX** harden / correctness | HX-1…HX-19 | Outbound CRLF, per-command IRCX exploits, mesh/Helix/media/auth hunt, client XSS/store poison, timer-guard real gates, full-suite count |

**Still not 0.7:** multishot recv, provided-buffer rings, PQ signing, full DTLS listener, mechanical `server.zig` split.

---

## P1 — targeted for 0.7

Items targeted for this release; may slip with a named decision. Full
descriptions in the linked roadmaps.

### Daemon P1

| # | Item | Owner | Gate |
| --- | --- | --- | --- |
| [P1-1 / S-04](ROADMAP-2026-Q4.md#s-04--warden-and-flood-introspection-surface) | Warden + flood introspection surface | `onyx-server-warden` · `onyx-server-ircx` | `zig build test-ircx` |
| [P1-2 / S-09](ROADMAP-2026-Q4.md#s-09--link-health-and-mesh-observability) | Link health + mesh observability | `onyx-server-mesh` | `zig build test-mesh` |
| [P1-3](releases/0.7-RELEASE-PLAN.md#p1--targeted-for-07) | Concurrency ceiling Phase C: written decision from P0-1 numbers | `onyx-server-reactor` · `stack-architect` | `docs/design/multireactor-phase-c.md` (new) |
| [P1-4 / S-14](ROADMAP-2026-Q4.md#s-14--helix-capsule-versioning-discipline) | Helix capsule-version discipline check | `onyx-server-helix-reviewer` · `zig-coder` | `zig build test-helix` |
| [P1-5](releases/0.7-RELEASE-PLAN.md#p1--targeted-for-07) | `[io]` and `[limits]` config surface for new knobs | `onyx-server-config` | `zig build test-config` |
| [P1-6](releases/0.7-RELEASE-PLAN.md#p1--targeted-for-07) | Documentation drift repair (D-4 stale comment, tls-roadmap DTLS claim) | `doc-writer` | (manual) |
| [L-05](ROADMAP-2026-Q4.md#l-05--whois-completeness-and-consistency) | `WHOIS` completeness and consistency | `onyx-server-ircx` | `zig build test-ircx` |
| [L-06](ROADMAP-2026-Q4.md#l-06--operator-ergonomics) | Operator ergonomics (35 oper commands with dry-run + audit trail) | `onyx-server-ircx` | `zig build test-ircx` |
| [L-12](ROADMAP-2026-Q4.md#l-12--release-runbook-for-07) | Release runbook for 0.7 | `doc-writer` · `onyx-server-deploy` | `docs/ops/release-v0.7.0.md` (new) |

### Client P1

| # | Item | Owner | Gate |
| --- | --- | --- | --- |
| [C-03](../../onyx/docs/ROADMAP-2026-Q4.md#c-03--operator-desk) | Operator desk (ward list, flood verdicts, mesh health, audit trail; in-flight at `src/lib/oper/`) | `onyx-ui` (`onyx-irc`) | `pnpm typecheck && pnpm test` |
| [C-04](../../onyx/docs/ROADMAP-2026-Q4.md#c-04--call-surface-completion) | Call surface: quality indicators, active-speaker ordering, codec-failure state | `onyx-media` | `pnpm typecheck && pnpm test` |
| [C-05](../../onyx/docs/ROADMAP-2026-Q4.md#c-05--search-that-scales-past-the-vault) | Search: server-history path via S-06 (server-first) | `onyx-vault` | `pnpm typecheck && pnpm test && pnpm check:server-contract-v2` |
| [C-06](../../onyx/docs/ROADMAP-2026-Q4.md#c-06--notification-decision-surface) | "Why was I (not) notified" trace surface | `onyx-notify` | `pnpm typecheck && pnpm test` |
| [C-07](../../onyx/docs/ROADMAP-2026-Q4.md#c-07--accessibility-from-css-coverage-to-a-tested-contract) | A11y: focus-trap + live-region primitives replacing conventions | `onyx-a11y` | `pnpm typecheck && pnpm test` |
| [C-09](../../onyx/docs/ROADMAP-2026-Q4.md#c-09--public-roadmap-honesty-pass) | Roadmap cross-link honesty pass | `doc-writer` | (manual) |
| [CL-01…CL-06](../../onyx/docs/ROADMAP-2026-Q4.md#release-track--polish-cl-xx) | Polish track: command discoverability, a11y enforcement, dead surfaces | `solidjs-coder` · `onyx-a11y` | `pnpm typecheck && pnpm lint && pnpm test` |
| [CP-01…CP-06](../../onyx/docs/ROADMAP-2026-Q4.md#release-track--performance-cp-xx) | Performance track: render budget, bundle budget, store cost | `onyx-perf` | `pnpm typecheck && pnpm test && pnpm build` |

---

## P2 — opportunistic

Full descriptions in the linked roadmaps.

**Daemon P2:** [P2-1](releases/0.7-RELEASE-PLAN.md#p2--opportunistic) bounded `server.zig` extraction (ring/reactor seam only, forced by P0-2) · [S-03](ROADMAP-2026-Q4.md#s-03--event-spine-v2) Event Spine v2 mesh-wide · [S-05](ROADMAP-2026-Q4.md#s-05--ocg2-past-observe-mode) OCG2 past observe · [P-07](ROADMAP-2026-Q4.md#p-07--shard-count-and-affinity-policy) shard-count + affinity · [H-03](ROADMAP-2026-Q4.md#h-03--unblock-coverage-guided-fuzzing) unblock fuzzing · [H-09](ROADMAP-2026-Q4.md#h-09--hostile-input-corpus-for-the-operator-surface) hostile-config corpus · [L-07…L-11](ROADMAP-2026-Q4.md#l-07--diagnostics-an-operator-can-act-on) diagnostics, config reference, hub completeness, glossary discipline, protocol docs.

**Client P2:** [C-08](../../onyx/docs/ROADMAP-2026-Q4.md#c-08--render-budget-under-windowing) render budget · [C-11](../../onyx/docs/ROADMAP-2026-Q4.md#c-11--multi-device-dm-parity) multi-device DM parity · [C-13](../../onyx/docs/ROADMAP-2026-Q4.md#c-13--vault-retention-and-storage-pressure-ux) vault retention UX · [C-15](../../onyx/docs/ROADMAP-2026-Q4.md#c-15--presence-and-typing-at-mesh-scale) presence at mesh scale · [C-16](../../onyx/docs/ROADMAP-2026-Q4.md#c-16--composer-rich-input-parity) composer rich input · [C-18](../../onyx/docs/ROADMAP-2026-Q4.md#c-18--oper-desk-mesh-operations) oper desk mesh operations · [C-19](../../onyx/docs/ROADMAP-2026-Q4.md#c-19--pwa-update-and-offline-correctness) PWA offline correctness.

**0.7 major tracks** (same tag, not 0.8): [PX / IX / CX / HX](releases/0.7-MAJOR-ROADMAP.md) — Windows/BSD I/O, expanded IRCX, client LISTX/MODEX/WHISPER/PROP, exploit hunt.

**Wave 3/4 and moonshot items** (post-0.7): [S-19…S-30](ROADMAP-2026-Q4.md#wave-3--later), [C-20…C-31](../../onyx/docs/ROADMAP-2026-Q4.md#wave-3--later). Invented F-52+ (schedule/threads/canvas) stay post-0.7 unless an IX/CX sliver requires them. Multishot recv / buf_ring stay deferred.

---

## Invented features and game-changers (0.8+)

None of these are required for 0.7. They are tracked so wave-planner can slot
them into 0.8+ without re-discovery.

- **Daemon F-01…F-68:** [`docs/features/INVENTED-FEATURES-CATALOG.md`](features/INVENTED-FEATURES-CATALOG.md) — full catalog grounded at HEAD. The **Top-20 game-changer shortlist** (ranked by operator value × novelty / cost) is at the top of that file. Highlights: F-39 deep metrics histograms, F-15 account trust ledger, F-52 scheduled delivery, F-08 proofmark federation.
- **Cross-repo 50 game-changers:** [`docs/features/GAME-CHANGERS-50.md`](features/GAME-CHANGERS-50.md) — GB/GS/GC-01…50 spanning daemon and client; carries a **declared overlap table against F-01…F-68** (§ Relationship to F-01…F-68 in that file). Client companion: [`onyx/docs/features/GAME-CHANGERS-50.md`](../../onyx/docs/features/GAME-CHANGERS-50.md).
- **Client Era-3 game-changers:** [`onyx/docs/era3-40-game-changers.md`](../../onyx/docs/era3-40-game-changers.md) — the 40-item acceptance ledger for client-side game-changers.
- **Shortlist integration point:** [`docs/ROADMAP-2026-Q4.md` § Invented features](ROADMAP-2026-Q4.md#invented-features--p0-shortlist) lists five high-priority daemon invented features (F-39, F-15, F-52, F-08, F-24) ready to slot into 0.8 wave planning without design work.

---

## Cross-cutting wire contracts (server ↔ client)

Thirteen contracts span both repos. The safety rule is:
**capability and token additions ship server-first**; client-driven
reinterpretations of existing wire data ship client-first.

Full tables with order rationale are in:
- [`docs/ROADMAP-2026-Q4.md` § Cross-cutting](ROADMAP-2026-Q4.md#cross-cutting-server--client-wire-contracts) — server perspective
- [`onyx/docs/ROADMAP-2026-Q4.md` § Cross-cutting](../../onyx/docs/ROADMAP-2026-Q4.md#cross-cutting-client--server-wire-contracts) — client perspective

Key 0.7 contracts: X-1 group E2EE (server DONE → client C-10 now unblocked), X-4 operator introspection (server P1-1/P1-2 → client C-03/C-18), X-9 NAMES burst semantics (client-first → client C-02), X-11 command metadata surface (server L-04 → client C-33).

Contract verification: `pnpm check:server-contract` and
`pnpm check:server-contract-v2` check against
`docs/reference/protocol/onyx-client-contract.v{1,2}.json` in this repo.

---

## 0.7 exit criteria

The full gate checklist is in [`docs/releases/0.7-RELEASE-PLAN.md` § Gate checklist](releases/0.7-RELEASE-PLAN.md#10-gate-checklist-before-the-070-tag). Every line must be green on a clean tree at the tagging commit.

**Summary of non-mechanical gates:**

- R-2 cleared: a cross-version 0.5.8 → 0.7.0 Helix adoption test passes before the first `-rc` bump.
- R-1 cleared: a USR2-under-fault DST campaign covers `buf_ring` enabled before that flag is documented as production-ready.
- `--check-config` accepts the reference config and every new `[io]` key.
- `NEWS.md` carries 0.5.7, 0.5.8, and 0.7.0 entries; every performance number traces to a P0-1 artifact.
- No document contradicts HEAD (P1-6 closed).
- `docs/RUNBOOK.md` records the 0.5.x ↔ 0.7.x hot-upgrade compatibility boundary.

**Explicitly not required for 0.7:** Wave 3/4 items, PQ signing (S-26), standards WebRTC interop (S-27), full `server.zig` decomposition, `zig build bench` as a hard CI gate (baseline first), BoGo full-corpus pass claim.

---

## Drift reconciled

Findings from [`docs/releases/0.7-RELEASE-PLAN.md` § Gap analysis](releases/0.7-RELEASE-PLAN.md#4-gap-analysis--roadmap-versus-head) that affect this document.

### D-6 — S-12 reclassified from P0 to DONE

[`docs/ROADMAP-2026-Q4.md` S-12](ROADMAP-2026-Q4.md#s-12--e2ee-group-authority-activation) marked E2EE group authority activation as **P0**. The release-plan audit found it **already shipped**: `docs/reference/protocol/onyx-client-contract.v2.json` declares `"group_control": "production_active"` with mesh hop custody and exact-once replay metadata, and `docs/ops/e2ee-group-authority-v2-activation.md` records a completed coordinated deployment. S-12 is **DONE**; client item C-10 (the product journey) is now unblocked.

*Spot-check required before final sign-off: `onyx-server-mesh-reviewer` should verify against HEAD that no sub-path remains incomplete before S-12 is permanently removed from the P0 column.*

### D-4 — Stale shard-count comment

`src/daemon/server.zig:1897-1901` states that shards > 1 are "currently clamped to 1 at `runThreaded`." That is no longer true: `clampShards` clamps to `[1, shard_mod.max_shards]` (ceiling 4096) and the config accepts up to `max_shards` (`config_format.zig:1304`). The comment misleads performance work. Fix: P0-6 / W1-3 (zig-coder already owns `server.zig` in Wave 1).

### D-1/D-2/D-3 — Dead io_uring fast path

`src/substrate/io/ring.zig` is the well-factored modern backend with a runtime capability probe. Nothing outside its directory imports it; the daemon runs the thinner inline `ringlane` at `server.zig:860` with every feature flag false. This is the capability gap P0-2 closes. It is not a documentation error — no document currently claims the fast path is on.

### D-5 — Coarse concurrency ceiling

`onCompletion` (`server.zig:4257-4266`) takes `world.lockWrite` around the whole completion, so reactors parallelize I/O but serialize command processing. P1-3 owns the written decision on whether 0.7 raises this or explicitly defers it.
