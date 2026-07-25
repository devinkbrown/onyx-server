---
name: onyx-server-agent-toolkit
description: Audit, evolve, and validate Onyx Server's Codex and Claude engineering toolkit. Use when adding or updating project agents, skills, model or effort routing, delegation rules, review launchers, worktree strategy, roster validation, or cross-model workflows.
---

# Maintain the Onyx Server agent toolkit

Research current official Codex and Claude documentation before changing platform-specific fields. Keep project knowledge in skills, isolation and authority in agents, universal constraints in `AGENTS.md`, and deterministic checks in scripts.

Design rules:

- Keep one writer per file. Use the integration agent as the sole `server.zig` owner while leaf agents work on disjoint modules.
- Fill the runtime's available agent slots with concrete independent work, but do not invent tasks to satisfy a number. Rotate test, review, release, and docs roles at handoffs.
- Keep Codex agents on the active configured model unless a task has a measured reason to override it. Use high or xhigh reasoning for integration and adversarial work.
- Route Claude mechanical review to Haiku/low, integration review to Sonnet/medium, and security/protocol review to Sonnet/high. Keep structured review read-only.
- Use worktrees only from a coherent commit when a worker does not need the current dirty tree. Do not use experimental agent teams for overlapping writes or sequential integration.
- Separate implementer, fresh reviewer, gate runner, deployer, and docs authority. Deployment never implies source-edit authority.
- Prefer a small reusable roster plus task skills over a permanent agent for every directory.
- **Token-lean agents (standing):** agent bodies stay dense (≤~3 KiB typical; zig-coder ≤~5 KiB). Put deep maps/invariants in skills (`onyx-server-agent-core` + domain skills including `onyx-server-mesh-ops`). Keep routing power in a short MUST-BE-USED description + 1–2 tiny examples + negative boundary — descriptions load on every parent turn. Archives of pre-compact agents live under `~/.claude/agents/_archive/`.
- Keep `.agents/ROSTER.md` and `AGENTS.md` in sync with live dual-node paths (`orochi.service`, `/home/kain/orochi-run`, metrics `:9130`).

Use `.agents/skills` as the canonical project skill tree and expose it to Claude through `.claude/skills`. After every authority or launcher change run:

```sh
python3 .agents/skills/onyx-server-agent-toolkit/scripts/validate_toolkit.py
# optional if present:
# python3 .agents/skills/onyx-server-agent-toolkit/scripts/test_validate_toolkit.py
# tools/claude-review.sh  # snapshot-isolation regression
```

Validate every skill has frontmatter `name` + `description`. The structured Claude launcher must expose only exact-file `Read` plus schema-return permissions over a private immutable snapshot; live checkout hashes are a relevance check, not the reviewer's source view.
