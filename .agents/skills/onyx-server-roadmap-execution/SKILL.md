---
name: onyx-server-roadmap-execution
description: Audit and execute Onyx Server roadmap work from current source truth. Use when continuing the Onyx Server roadmap, resuming an interrupted Onyx Server implementation, selecting the next server-side slice, or coordinating parallel agents without losing existing work.
---

# Execute the Onyx Server roadmap

1. Read `AGENTS.md`, inspect `git status`, and identify active file owners before changing anything.
2. Read `/home/kain/ONYX_ONYX_MASTER_ROADMAP.md` when it exists, but treat current source and tests as authoritative. Audit the relevant implementation read-only before selecting a slice.
3. Recover unfinished work instead of restarting it. Preserve current changes, pass/fail evidence, unresolved invariants, and deployment state.
4. Prefer server, protocol, mesh, Helix, persistence, and daemon acceptance work unless a server contract forces a client-facing change.
5. Fill available agent slots only with concrete, independent tasks. Give every writer an explicit non-overlapping file set; assign integration files such as `src/daemon/server.zig` to one owner.
6. Choose the smallest coherent slice that closes a user-visible contract end to end. Do not mark roadmap prose complete from a codec or helper test alone.
7. Use `$onyx-server-zig-verification` for evidence and a fresh reviewer for release-critical work. Commit a coherent green slice locally; do not publish or deploy unless the release workflow is explicitly active.

For Codex delegation, `send_message` queues information but does not restart a
completed agent. Use `followup_task` to assign new work to a completed agent,
then verify its live status before recording it as authoring or reviewing.
A queued message, an intended assignment, or an old checkpoint is not liveness
evidence. Preserve and poll existing gate handles instead of launching copies.

Before repeating a completed gate, consult the read-only decision tool recorded in
`.zig-cache/CURRENT.json` (`execution_policy.gate_decision`). Reuse requires
checking counts and the terminal supervisor; unchanged failure requires causal
diagnosis or independent review before another attempt. Changed context alone
does not justify a retry without a relevant correction. The decision tool never
grants acceptance or replaces required gates. Preserve active handles and never
restart a job because an observation expired.

For reusable sessions or mesh migration, load `$onyx-server-session-mesh`. For Event Spine or message relay, load `$onyx-server-message-spine`. For `server.zig` wiring, load `$onyx-server-integration`.

Keep the execution checkpoint current when a gate or review finishes: remove
terminal jobs from the active list, preserve their receipts, and advance the
next unfinished contract. A closed contract is not a candidate for new work
unless a specific changed dependency or contradictory observation is recorded.
Use the exact target and options from the last verified command for that
contract; do not invent target names. Bound each active lane by its concrete
remaining implementation, review findings and acceptance checks. Do not reopen
planning or repeat an inventory audit when an actionable implementation is
already assigned.
