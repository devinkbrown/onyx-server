# Onyx Server agent roster

Token-lean project agents live under `.claude/agents/` (Claude) and `.codex/agents/` (Codex).  
Deep maps live in `.agents/skills/`. Global deep specialists: `~/.claude/agents/`.

## Authority
| Role | Authority |
|------|-----------|
| `onyx-server-integrator` | **Sole** writer of `src/daemon/server.zig` |
| `zig-coder` / `zig-coder-leaf` | Leaf Zig modules **outside** `server.zig` |
| `onyx-session` | Session / migration / Helix leaf state |
| `onyx-server-dst` / `*-dst-leaf` | Deterministic fault / DST campaigns |
| `onyx-reviewer` + domain reviewers | Read-only adversarial gate (never edit) |
| `onyx-release-gate` | Release evidence judgment |
| `onyx-server-deploy` / `*-deploy-authorized` | Deploy only after explicit user go + gate evidence |
| `onyx-docs` | Docs only |
| `onyx-agent-architect` | Roster evolution (read-only; reduce overlap) |

## Claude project agents (`.claude/agents/`)
| Agent | Mode |
|-------|------|
| `zig-coder-leaf` | Implement leaf Zig |
| `onyx-server-integrator` | server.zig + lifecycle |
| `onyx-session` | Session/Helix leaf |
| `onyx-server-dst-leaf` | DST implement |
| `onyx-reviewer` | Fresh adversarial (domain lens in prompt) |
| `onyx-fast-auditor` | Mechanical / Haiku-lean |
| `onyx-integration-reviewer` | Integration seams |
| `onyx-security-reviewer` | Security / protocol |
| `onyx-release-gate` | Release readiness |
| `onyx-server-deploy-authorized` | Two-node deploy |
| `onyx-docs` | Documentation |
| `onyx-agent-architect` | Toolkit audit |

## Codex project agents (`.codex/agents/`)
`zig-coder`, `onyx-session`, `onyx-server-integrator`, `onyx-server-dst`, `onyx-reviewer`, `onyx-release-gate`, `onyx-server-deploy`, `onyx-docs`, `onyx-agent-architect`.

## Global deep specialists (route when needed)
| Domain | Agent |
|--------|-------|
| General Zig implement + review gate | `zig-coder` |
| TLS / Armor crypto | `armor-tls` + `onyx-server-crypto-reviewer` |
| Mesh CRDT / Mooring S2S | `onyx-server-mesh` + `onyx-server-mesh-reviewer` |
| io_uring / reactor | `onyx-server-reactor` |
| IRCX / Event Spine commands | `onyx-server-ircx` |
| WAL / OroStore | `onyx-server-store` |
| Helix USR2 capsules | `onyx-server-helix-reviewer` |
| Anti-abuse engines | `onyx-server-warden` |
| Media plane daemon | `onyx-server-media` |
| Hostile-input harness | `onyx-server-hardener` |
| Config / REHASH | `onyx-server-config` |
| Perf | `onyx-server-perf` |

## Skills (canonical `.agents/skills/`)
`onyx-server-agent-core`, `onyx-server-zig-verification`, `onyx-server-integration`, `onyx-server-session-mesh`, `onyx-server-message-spine`, `onyx-server-mesh-ops`, `onyx-server-release-deploy`, `onyx-server-roadmap-execution`, `onyx-server-cross-model-review`, `onyx-server-agent-toolkit`.

## Parallel rules
- One writer per file. Parent assigns disjoint sets.
- Never hand `server.zig` to a leaf "temporarily".
- Fill free agent slots with real independent work — do not invent tasks.
- Validate toolkit after roster changes:  
  `python3 .agents/skills/onyx-server-agent-toolkit/scripts/validate_toolkit.py`
