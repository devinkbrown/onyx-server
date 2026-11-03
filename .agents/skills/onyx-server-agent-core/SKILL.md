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
- Path: `/home/kain/onyx-server`. Zig **0.17.0**. No C interop.
- Product: **Onyx Server** (engine/daemon). Client/network brand: **Onyx**.
- Names: Ringlane, Armor, Undertow, Mooring, Helix, Event Spine, CadenceVox/Vis.
- `onyx-server-integrator` is the **sole** `src/daemon/server.zig` writer.
- Wire crypto domains are **protocol constants** (do not "rebrand"):
  - Ed25519 ctx sign: `orochi-ed25519ctx-v1` with dual-verify of legacy `onyx-ed25519ctx-v1`
  - SPAKE: `orochi-spake2-*`; frozen tsumugi/MZ labels stay for interop only

## Live dual-node

Operational source of truth: [production paths](../../../docs/ops/onyx-server-paths.md)
and [deployment checklist](../../../docs/ops/mesh-metrics-deploy-checklist.md).
Read their dated artifact receipt before acting; source HEAD and the deployed
artifact revision may differ after documentation or test-only commits.

| Node | Runtime | Service manager |
|------|---------|-----------------|
| eshmaki.me (local) | `/home/kain/onyx-server-run` | OpenRC `/etc/init.d/onyx-server` |
| `trev@ircx.us` | `/home/trev/onyx-server-run` | systemd `onyx-server.service` |

- Metrics (loopback): `http://127.0.0.1:9130/metrics`.
- `onyx_s2s_tcp_active` counts TCP slots; `onyx_s2s_links_active` counts established Mooring links.
- `tcp_active>0` with `links_active=0` requires handshake/trust diagnosis.
- Health: `MESH_SSH_PEER=trev@ircx.us python3 tools/mesh_health_smoke.py http://127.0.0.1:9130/metrics`.
- Prefer Helix USR2 only when the image capabilities and runtime state permit it.
  Otherwise follow the RUNBOOK cold-restart boundary, one node at a time.
- Confirm actual service configuration, user, working directory and limits before changes.
  Historical unit names and old artifact receipts are evidence, not deployment targets.

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

## Resume guard
Before the first write after a follow-up, read `.zig-cache/CURRENT.json` when
present and confirm the active assignment, source manifest, owner and phase.
The latest assignment supersedes stale unfinished work. Do not finish an older
assignment first when its contract is already accepted. Frozen evidence contexts
remain read-only; create a new context only for the current assigned change.
Report an ownership or checkpoint conflict to the coordinator before editing.
When available, run `python3 -B tools/roadmap_checkpoint_audit.py` to detect
stale job statuses, ledger-count drift and narrow full-suite attribution conflicts.
Resolve contradictions in the checkpoint; inspect unknown evidence without
restarting its job. This read-only audit never grants gate or release acceptance.

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
