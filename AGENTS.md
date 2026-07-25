# Onyx Server agent operating contract

## Product naming

- **Engine / product:** **Onyx Server** (pure-Zig IRC/IRCX mesh daemon). Binary/package names: `onyx-server`. Live process may still be named `orochi`.
- **Network / client brand:** **Onyx** (consumer-facing). IRCXNet is retired public identity only.
- **English subsystem codenames** (docs/comments): **Undertow**, **Ripple**, **Concord**, **Mooring**, **Armor**, **Helix**, **Ringlane**, **CadenceVox** / **CadenceVis**. Map: `docs/reference/glossary.md`.
- **Keep as-is (not product renames):** `onyx-*` agent/skill IDs; wire/config literals (`onyx/*` caps/tags, crypto domain labels, `ONYX_*` env); frozen dual-verify domains (`orochi-ed25519ctx-v1` + legacy `onyx-ed25519ctx-v1`).
- **Repository path:** `/home/kain/onyx-server` only.

## Roster

Full routing map: [`.agents/ROSTER.md`](.agents/ROSTER.md).  
Shared bar/gates/live dual-node facts: skill `onyx-server-agent-core`.  
Mesh ops: skill `onyx-server-mesh-ops`.

## Scope and source of truth

- Work only in this repository unless the task explicitly names a deployment host.
- Current source and tests are authoritative; roadmaps may lag.
- Pure Zig — no C interop; native Undertow mesh (not a tree protocol).
- Production contract: mesh-wide reusable sessions — every attached client stays connected and observes the same accepted events after migration or Helix on any node.

## Parallel work

- Explicit non-overlapping file sets. **`onyx-server-integrator` is always the sole `src/daemon/server.zig` writer.**
- Parallel agents for bounded modules, read-only audits, tests, and logs.
- Return concise evidence: files, invariants, commands, pass counts, unresolved risks.

## Helix and session invariants

- Current Helix state is strict and fail-closed. Missing/malformed mandatory state aborts adopt transactionally.
- Legacy decode only on explicit cold-migration paths.
- Preserve every live attachment by physical connection identity.
- Stable local session tokens across sequential upgrades; mesh migration tokens may rotate under envelope rules.
- Mesh relays: stable origin identity, exact-once accept, deterministic replay/equivocation, byte-identical signed-origin forward.
- Checkpoint adopt is allocation-failure atomic.

## Verification

- `zig fmt` on touched files.
- Project harness commands; narrow tests while iterating; full `zig build test` for ship (check **count**).
- Release: full gates, Debug + ReleaseSafe for critical modules, multi-node acceptance.
- Fresh reviewer must try to refute release-critical changes.

## Claude review routing

- Prefer `tools/claude-review.sh` for release evidence (snapshot-isolated Read).
- Lenses: `fast` mechanical, `integration` seams, `security` Helix/mesh/replay/token.
- Writer agents do not grade their own work.

## Codex / Claude specialist routing

- Project leaves: `zig-coder` / `zig-coder-leaf`, `onyx-session`, `onyx-server-integrator`, `onyx-server-dst`, reviewers, release-gate, deploy, docs.
- Deep globals when needed: `armor-tls`, `onyx-server-mesh`, `onyx-server-reactor`, `onyx-server-ircx`, `onyx-server-store`, `onyx-server-hardener`, …
- `onyx-agent-architect` only for roster evolution (reduce overlap).

## Skills and tooling

Canonical skills: `.agents/skills/` (also under `.claude/skills/`).  
After toolkit changes:  
`python3 .agents/skills/onyx-server-agent-toolkit/scripts/validate_toolkit.py`

## Live dual-node (short)

| Node | Runtime | Unit |
|------|---------|------|
| eshmaki.me | `/home/kain/orochi-run` | `orochi.service` |
| ircx.us (`trev@ircx.us`) | peer `orochi-run` | `orochi.service` |

Metrics: `:9130/metrics` — `links_active` = established Mooring; `tcp_active` = TCP only.  
Health: `MESH_SSH_PEER=trev@ircx.us python3 tools/mesh_health_smoke.py http://127.0.0.1:9130/metrics`  
Details: `docs/ops/mesh-metrics-deploy-checklist.md`, skill `onyx-server-mesh-ops`.

## Git and deployment safety

- Preserve unrelated user work; no destructive reset.
- Deploy only with explicit user authorization and skill `onyx-server-release-deploy`.
- Prefer Helix when allowed; hard-restart one node at a time otherwise.
- GitHub push **last**, only after green mesh acceptance.

## Context preservation

When compacting/handing off: active owners, modified files, exact commands, deploy state, unresolved invariants.
