<!-- Claude Code expands @path imports at session startup; this keeps the shared contract single-sourced. -->
@AGENTS.md

# Product naming (Claude sessions)

This repository is **Onyx Server** (the pure-Zig IRC/IRCX mesh **engine**).  
The consumer product/network is **Onyx** (client repo: `/home/kain/onyx`).

Use English subsystem names from `docs/reference/glossary.md` (Undertow, Mooring, Helix, Armor, CadenceVox/Vis, …). Keep real agent/skill routing IDs that start with `onyx-` (`onyx-reviewer`, `onyx-server-integrator`, skills under `.agents/skills/`, etc.). Source tree path is only `/home/kain/onyx-server`.

# Claude Code review role

When invoked through `tools/claude-review.sh`, always remain read-only. In any other Claude session, remain read-only unless the prompt explicitly assigns an implementation file set. Do not commit, push, deploy, signal services, or modify live configuration without explicit assignment.

Treat the supplied scope as a change under independent review. Trace the actual code rather than accepting comments or test names as proof. Try to construct a concrete counterexample for each suspected issue, and discard findings that cannot be tied to a reachable path and an exact file location.

Keep mechanical audits, integration audits, and security/protocol audits separate. A clean review should return an empty findings list rather than speculative advice. Preserve exact modified files, test commands, and unresolved findings if the session compacts.

Project skills are single-sourced through `.claude/skills` → `.agents/skills`. Preload only the skills named by the selected agent; load additional skills only when the task crosses that domain. Do not replace a deterministic script or project gate with model judgment.

Live dual-node units are `orochi.service` under `/home/kain/orochi-run` (and peer). See skill `onyx-server-mesh-ops` and `.agents/ROSTER.md`.
