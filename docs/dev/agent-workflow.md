# Onyx Server agent workflow

Onyx Server uses agents for context and authority isolation, skills for reusable
procedures, and scripts for deterministic validation. `AGENTS.md` remains the
mandatory contract; this document is the routing map. Start with the
[development guide](../development.md), follow the [testing guide](../guide/testing.md)
for current commands and evidence rules, and use the
[maintenance guide](../MAINTENANCE.md) for documentation upkeep.

## Roles

| Role | Writes | Trigger | Required handoff |
|---|---|---|---|
| parent/orchestrator | integration decisions and Git | every task | assigns exact file owners and validates evidence |
| `zig-coder` | assigned Zig leaf files | bounded implementation outside `server.zig` | focused tests and API seam to integrator |
| `onyx-session` | session, migration, replica, and Helix leaf files | reusable-session work | exact live-call-site requirements to integrator |
| `onyx-server-integrator` | assigned live daemon files; sole `server.zig` owner | leaf APIs are ready | live-path tests and unresolved leaf defects |
| `onyx-server-dst` | tests and test-local scaffolding | fault or topology proof | reproducible seed/counterexample; no production fix |
| `onyx-reviewer` | nothing | fresh adversarial gate | file:line finding or pass |
| `onyx-release-gate` | build caches/artifacts only | writers stop | commands, exit codes, counts, hashes, and failures |
| `onyx-server-deploy` | authorized runtime/config state only | verified release commit | both-node deployment and live evidence |
| `onyx-docs` | documentation only | live acceptance passes | source/deployed truth for every changed claim |
| `onyx-agent-architect` | nothing | toolkit audit only | evidence-backed roster change proposal |

The `onyx-server-integrator` restriction is permanent role authority, not a
rotating lock. Every other role must hand required `server.zig` edits and tests
to that integrator.

The runtime concurrency cap, not the number of definitions, controls active
parallelism. Fill available slots with concrete independent work. For a
session/message change, a useful four-slot lineup is parent,
session/leaf owner, server integrator, and DST or fresh reviewer. Rotate the last
slot into release-gate, deploy, and docs at those handoffs.

Operational topology and dated release receipts live in
[production paths](../ops/onyx-server-paths.md): local OpenRC and peer systemd.
Do not infer deployed versions from source HEAD or historical design notes.

## Skills

| Skill | Use |
|---|---|
| `onyx-server-roadmap-execution` | recover context, audit source, and select a coherent roadmap slice |
| `onyx-server-session-mesh` | tokens, resume, migration, multi-attachment, replica, and Helix session state |
| `onyx-server-message-spine` | Event Spine and MESSAGE_V2 authorship, exact-once relay, retention, and replay |
| `onyx-server-integration` | transactional live-daemon wiring and lifecycle coverage |
| `onyx-server-zig-verification` | focused gates, ReleaseSafe, OOM sweeps, topology, and release evidence |
| `onyx-server-cross-model-review` | grounded, bounded, read-only Claude review |
| `onyx-server-release-deploy` | ordered clean release, compatible Helix or sequential cold restart, acceptance, docs, and push |
| `onyx-server-agent-toolkit` | agent/skill/model/tooling evolution |

Skills are canonical under `.agents/skills`. `.claude/skills` exposes the same
tree, so a procedure is not copied into two model-specific prompts.

## Model routing

Codex agents inherit the currently selected Codex model. Use high reasoning for
bounded leaf work, deterministic release evidence, and post-acceptance
documentation; use xhigh for session, integration, DST, review, deployment, and
toolkit architecture.

Claude source implementation agents use Sonnet/high. Deterministic release
evidence (`onyx-release-gate`) and post-acceptance documentation
(`onyx-docs`) use Sonnet/medium. The structured review launcher overrides
review routing by lane:

- `fast`: Haiku/low for small mechanical or codec consistency checks;
- `integration`: Sonnet/medium for ownership and lifecycle seams;
- `security`: Sonnet/high for Helix, tokens, replay, mesh, crypto, and hostile paths.

Claude structured review stays read-only. Writer agents are rejected by the
launcher even if a caller supplies their name.

## Deterministic commands

Validate the whole toolkit after any definition or skill change:

```sh
.agents/skills/onyx-server-agent-toolkit/scripts/validate_toolkit.py
PYTHONDONTWRITEBYTECODE=1 python3 \
  .agents/skills/onyx-server-agent-toolkit/scripts/test_validate_toolkit.py
PYTHONDONTWRITEBYTECODE=1 python3 \
  .agents/skills/onyx-server-agent-toolkit/scripts/test_claude_review_stub.py
.agents/skills/onyx-server-agent-toolkit/scripts/test_claude_review.sh
bash -n tools/claude-review.sh
git diff --check
```

Select conservative gates for changed paths, including untracked files:

```sh
.agents/skills/onyx-server-zig-verification/scripts/select-gates.py
.agents/skills/onyx-server-zig-verification/scripts/select-gates.py --release
PYTHONDONTWRITEBYTECODE=1 python3 \
  .agents/skills/onyx-server-zig-verification/scripts/test_select_gates.py
```

Run a bounded external review only after the scope stops changing:

```sh
tools/claude-review.sh integration \
  --file src/daemon/server.zig \
  --file src/daemon/helix/session_replica.zig -- \
  'Try to falsify retained replay across reconnect and sequential upgrade.'
```

The launcher copies the exact scope into a private read-only snapshot, exposes
only exact-path `Read` permissions in `dontAsk` mode, records a nonce and hashes,
and validates JSON shape and source anchors against that snapshot. It rejects a
result if the live paths no longer match the reviewed bytes. The symlink-swap
regression proves a transient live-path replacement cannot change Claude's
source view.

## Handoff record

Every agent returns:

1. exact files changed or reviewed;
2. invariants proved and the production paths that exercise them;
3. exact commands, exit codes, pass/skip/fail/leak counts, and relevant hashes;
4. confirmed unresolved blockers with file:line evidence;
5. the next owner and the precise seam being handed off.

Do not use a worktree for a task that needs the current uncommitted rewrite: a
new worktree starts from a commit and cannot see that dirty state. Use worktrees
after a coherent commit for truly isolated writers. Do not use experimental
agent teams for overlapping writes or sequential `server.zig` integration.

## Platform references

Keep this toolkit aligned with the current official documentation rather than
copying stale CLI assumptions into prompts:

- [Codex custom agents](https://learn.chatgpt.com/docs/agent-configuration/subagents)
- [Codex skills](https://learn.chatgpt.com/docs/build-skills)
- [Claude Code subagents](https://code.claude.com/docs/en/sub-agents)
- [Claude Code skills](https://code.claude.com/docs/en/slash-commands)
- [Claude Code permissions](https://code.claude.com/docs/en/permissions)
