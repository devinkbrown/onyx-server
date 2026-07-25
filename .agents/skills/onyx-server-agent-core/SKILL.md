---
name: onyx-server-agent-core
description: >
  Shared dense operating contract for all Onyx Server Zig agents. Load when
  implementing, reviewing, or gating any /home/kain/onyx-server change.
---

# Onyx Server agent core (token-lean)

## Bar (all modes)
1. **Correct** — intended behavior on every edge; verify unclear semantics against live source.
2. **Fail-closed / secure** — untrusted input rejected; no secret-dependent timing; wipe secrets.
3. **Neat** — small units, match idiom, no dead code or speculative APIs.
4. **Efficient** — no hot-path waste; measure before claiming perf wins.

## Repo facts
- Path: `/home/kain/onyx-server`. Zig **0.17-dev**. No C interop.
- Product: **Onyx Server** (engine/daemon). Client/network brand: **Onyx**.
- Names: Ringlane, Armor, Undertow, Mooring, Helix, Event Spine, CadenceVox/Vis.
- `onyx-server-integrator` is the **sole** `src/daemon/server.zig` writer.
- Wire crypto domains are **protocol constants** (do not "rebrand"):
  - Ed25519 ctx sign: `orochi-ed25519ctx-v1` with dual-verify of legacy `onyx-ed25519ctx-v1`
  - SPAKE: `orochi-spake2-*`; frozen tsumugi/MZ labels stay for interop only

## Live dual-node (production mesh)
| Node | Host | Runtime dir | Unit | Binary | Config |
|------|------|-------------|------|--------|--------|
| A | eshmaki.me (this box) | `/home/kain/orochi-run` | `orochi.service` | `…/orochi` | `orochi.local.toml` |
| B | ircx.us | `/home/trev/orochi-run` (SSH `trev@ircx.us`) | `orochi.service` | peer binary | peer toml |

- Metrics (loopback): `http://127.0.0.1:9130/metrics`
- Gauges: `onyx_s2s_tcp_active` = open TCP slots; `onyx_s2s_links_active` = Mooring-established only
- Journal success: `mesh S2S established (secured) peer=…`
- Stuck `tcp_active>0` + `links_active=0` → AKE / trust-root / handshake skew (not "down" TCP)
- Health: `MESH_SSH_PEER=trev@ircx.us python3 tools/mesh_health_smoke.py http://127.0.0.1:9130/metrics`
- Chat (optional): `tools/mesh_chat_smoke.py` — SASL via `MESH_SMOKE_SASL_*` or guest auto when unset
- Prefer **Helix USR2** reload when image token allows; cold-restart only per RUNBOOK
- Deploy checklist: `docs/ops/mesh-metrics-deploy-checklist.md` + `docs/RUNBOOK.md`
- Packaging unit may still say `onyx-server.service`; **live** units are `orochi.service`

## Gates
| Iterate | Ship |
|---------|------|
| focused `zig build test-*` + `-Dtest-filter=` | full `zig build test` (verify **count**, not only exit) |
| `zig fmt` on touched files | `zig fmt --check src/` + `git diff --check` |
| `--check-config <toml>` | never run built daemon bare (stray `:6680`) |

Focused: `test-mesh`, `test-helix`, `test-server`, `test-smoke`, `test-tls`, `test-media`, `test-config`, `test-mod`, `ct-check`.

## Universal invariants
- **HLC** wall-clock for cross-host LWW (never monotonic alone).
- **Mesh link identity** = shortId, not nick/UID.
- **Nick collision** renames loser to UID — never KILL (local clash = 433).
- **MeshPass** only inside encrypted M1; constant-time compare.
- **Reactor 0 guard**: shared timer / USR2 / durable flush on `reactors[0]` only.
- **io_uring buffer stability**: armed buffers fixed addresses; free-exactly-once.
- **Helix**: version-aware decode; fail-closed adopt; bump capsule version with layout.
- **MESSAGE_V2**: durable admit before channel/DM delivery when authoring active; no silent legacy fallthrough when V2 required.
- **NOTICE** never emits error replies.
- **Mooring handshake** bounds are not TLS record limits — mislabeling wastes hours.

## Review contract
Severity: CRITICAL / HIGH / MEDIUM / LOW / nit.  
Verdict: Approve | Approve-with-nits | Block.  
Review mode **never edits**. Self-gate implement work through a **fresh** reviewer agent.

## Skills map (load only when needed)
| Need | Skill |
|------|-------|
| gates / DST evidence | `onyx-server-zig-verification` |
| sessions / Helix mesh | `onyx-server-session-mesh` |
| MESSAGE_V2 / Event Spine | `onyx-server-message-spine` |
| server.zig wiring | `onyx-server-integration` |
| dual-node mesh ops | `onyx-server-mesh-ops` |
| authorized deploy | `onyx-server-release-deploy` |
| roster / toolkit | `onyx-server-agent-toolkit` |
| Claude structured review | `onyx-server-cross-model-review` |
| roadmap slice | `onyx-server-roadmap-execution` |

## Specialist routing (global + project)
See `.agents/ROSTER.md`. Project leaves: `zig-coder-leaf`, `onyx-server-integrator`, `onyx-session`, `onyx-server-dst-leaf`, reviewers, deploy, docs. Deep globals (when needed): `armor-tls`, `onyx-server-mesh`, `onyx-server-reactor`, `onyx-server-ircx`, `onyx-server-store`, `onyx-server-hardener`, …

## Docs anchors
`AGENTS.md`, `.agents/ROSTER.md`, `docs/architecture/*`, `docs/reference/glossary.md`, `docs/RUNBOOK.md`, `docs/ops/mesh-metrics-deploy-checklist.md`.
