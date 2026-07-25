---
name: onyx-server-release-deploy
description: >
  Execute Onyx Server's authorized two-node release in mandatory order. Use only
  when release or deployment is explicitly requested: verify commit, update both
  artifacts/configs, restart systemd (or Helix when allowed), mesh accept, docs,
  GitHub last.
disable-model-invocation: true
---

# Release and deploy Onyx Server

**Do not enter until the user explicitly authorizes deployment.**

Read: `AGENTS.md`, `docs/RUNBOOK.md`, `docs/ops/mesh-metrics-deploy-checklist.md`,
`packaging/release.sh` / `verify-release.sh` if used, this skill, `onyx-server-mesh-ops`.

## Live topology (authoritative 2026-07)
| Role | SSH / host | Runtime | Unit | Start |
|------|------------|---------|------|-------|
| Local | eshmaki.me | `/home/kain/orochi-run` | `orochi.service` | `…/orochi …/orochi.local.toml` |
| Peer | `trev@ircx.us` | `/home/trev/orochi-run` (confirm on host) | `orochi.service` | peer paths |

Packaging may still document `onyx-server.service` / `onyx-server-run` — **prefer live paths above**. Confirm with `systemctl cat orochi.service` before acting.

## Mandatory order (do not reorder)
1. **One verified release commit** — clean worktree/build provenance; full gates + critical ReleaseSafe as required; artifact revision matches commit.
2. **Rollback capture** — pre-deploy binary hashes, unit status, git rev on both nodes.
3. **Update artifacts + configs** on **both** nodes. Never print private keys.
4. **`--check-config`** on each live toml with the **new** binary before restart. Config `ParseError` must not silently default identity.
5. **Restart strategy**
   - Prefer **Helix USR2** when the release notes / image token allow seamless reload.
   - Otherwise hard-restart `orochi.service` **one node at a time**.
6. **Mesh verify** — both units active; expected binary;  
   `MESH_SSH_PEER=trev@ircx.us python3 tools/mesh_health_smoke.py http://127.0.0.1:9130/metrics`  
   Expect `links_active>=1`, `partitioned=0`. Journal: `mesh S2S established`.
7. **Live acceptance** — multi-client when authorized: session token, cross-node participation, exact event delivery, resume after reconnect. Hard restart implies TCP drop — prove token recovery.
8. **Docs** from deployed truth.
9. **GitHub push last** — never push a failed deploy state.

## Stop / roll back on
Artifact mismatch, config validation fail, service fail, mesh divergence (`links_active=0` after settle), lost client without token recovery, duplicate/missing events.

## Non-goals
- Source edits (deploy agent is not a coder)
- Unilateral Helix when cold-restart required
- Printing secrets
