---
name: onyx-server-release-deploy
description: >
  Execute Onyx Server's authorized two-node release in mandatory order. Use only
  when release or deployment is explicitly requested: verify commit, update both
  artifacts/configs, restart the service (or Helix when allowed), mesh accept, docs,
  GitHub last.
disable-model-invocation: true
---

# Release and deploy Onyx Server

**Do not enter until the user explicitly authorizes deployment.**

Read: `AGENTS.md`, `docs/RUNBOOK.md`, `docs/ops/mesh-metrics-deploy-checklist.md`,
`packaging/release.sh` / `verify-release.sh` if used, this skill, `onyx-server-mesh-ops`.

## Live topology

| Role | SSH / host | Runtime | Service manager |
|------|------------|---------|-----------------|
| Local | eshmaki.me | `/home/kain/onyx-server-run` | OpenRC `/etc/init.d/onyx-server` |
| Peer | `trev@ircx.us` | `/home/trev/onyx-server-run` | systemd `onyx-server.service` |

Read `docs/ops/onyx-server-paths.md` for the dated image receipt, actual working
directories, runtime overrides and rollback boundary. Inspect local OpenRC
configuration and peer `systemctl cat onyx-server.service` before acting. The
packaged defaults need host-specific paths, user, limits and file-sharing modes;
validate the effective sandbox with TLS loading as well as `--check-config`.
Historical unit names and source versions do not identify the running image.

## Mandatory order (do not reorder)
1. **One verified release commit** — clean worktree/build provenance; full gates + critical ReleaseSafe as required; artifact revision matches commit.
2. **Rollback capture** — pre-deploy binary hashes, unit status, git rev on both nodes.
3. **Update artifacts + configs** on **both** nodes. Never print private keys.
4. **`--check-config`** on each live toml with the **new** binary before restart. Config `ParseError` must not silently default identity.
5. **Restart strategy**
   - Prefer **Helix USR2** when the release notes / image token allow seamless reload.
   - Otherwise cold-restart through the node's actual service manager **one node at a time**.
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
