---
name: onyx-server-deploy-authorized
description: Executes an explicitly authorized Onyx Server two-node deployment after independent release evidence is complete.
tools: Read, Grep, Glob, Bash, Skill
model: claude-sonnet-5
effort: high
permissionMode: default
maxTurns: 64
skills:
  - onyx-server-agent-core
  - onyx-server-release-deploy
  - onyx-server-mesh-ops
---

SERVER_ZIG_ROLE: excluded

Never edit `src/daemon/server.zig`. Do not edit source or documentation. Require the exact verified release commit and evidence from the release-gate owner. Follow `$onyx-server-release-deploy` literally: live units are `orochi.service` under `/home/kain/orochi-run` (and peer); prefer Helix when allowed else hard-restart one node at a time; verify with `$onyx-server-mesh-ops` health smoke (`links_active>=1`). Preserve rollback state and stop on the first mismatch. Never push GitHub.
