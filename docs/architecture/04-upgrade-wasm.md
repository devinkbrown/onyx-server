# Upgrade and OroWasm

Helix carries live daemon state between compatible images. OroWasm runs bounded
control-plane plugins. These are separate mechanisms: loading a plugin does not
replace the daemon, and requesting an upgrade does not bypass state validation.

## Helix entry points and platform scope

`UPGRADE` is registered by [the upgrade module](../../src/daemon/modules/upgrade.zig).
`LinuxServer.handleUpgradeCommand` checks the `server_restart` operator privilege;
Linux SIGUSR2 reaches the same upgrade machinery from reactor 0. The production
fleet uses Linux, with OpenRC locally and systemd on the peer. Current commands,
rollback requirements and accepted image are recorded in the [runbook](../RUNBOOK.md)
and [production paths](../ops/onyx-server-paths.md).

Linux prepares a sealed memfd arena, preserves authoritative listener/state fds,
probes the already-open successor executable, and executes that pinned image with
`--supervisor`. Windows has a separate native successor/custody driver; consult the
[Windows guide](../guide/windows.md#guarded-windows-helix-upgrade). Linux acceptance
does not certify Windows behavior. Source: [server.zig](../../src/daemon/server.zig)
(`performUpgrade`, `performUpgradeAfterCompatibleTarget`, `adoptInheritedSessions`),
[live.zig](../../src/daemon/helix/live.zig),
[handoff.zig](../../src/daemon/helix/handoff.zig), and
[native_windows_runtime.zig](../../src/daemon/helix/native_windows_runtime.zig).

## Compatibility and complete-state validation

There is no universal backwards-compatible Helix ABI. Capsule kinds have explicit
schema/version ranges in [capsule.zig](../../src/daemon/helix/capsule.zig), while
[handoff_relations.zig](../../src/daemon/helix/handoff_relations.zig) applies the
stricter current-image completeness and cross-family relations. Generic legacy
codec support does not grant permission to adopt old or incomplete live state.

Current descriptors include `.clients` v8, `.s2s_link` v6, `.ws_session` v3 and
`.handoff_manifest` v5. The textual target capability token is a distinct protocol:
for example its `clients-v5` label is not the current `.clients` schema number.
Read `upgrade_capability_token` in `helix/live.zig`; do not infer compatibility
from a version banner or from one overlapping capsule range.

Before publication, the successor validates the complete manifest, physical
connection identities, mandatory authority families, fd ownership, TLS/WS joins,
replay state and session relations. Missing, duplicate, malformed, downgraded or
inconsistent mandatory state rejects adoption. Allocation failures must leave
staged state unpublished; serving a partial adopted client population is forbidden.

| Carried authority | Source and validation boundary |
|---|---|
| Physical connections and client state | `helix/session_snapshot.zig`, `helix/physical_connection_relation.zig`; identity is physical, including several attachments sharing one logical token. |
| World and reusable sessions | `helix/world_capsule.zig`, `helix/session_capsule.zig`, `sessions.zig`; includes membership, attachment and retained restore authority. |
| TLS and WebSocket engines | `helix/tls_snapshot.zig`, `helix/ws_snapshot.zig`; secured clients require exactly matching engine state and bounded pending bytes. |
| Established secured S2S links | `helix/s2s_snapshot.zig`; Mooring keys/counters, partial framing, inner custody and remote roster must remain consistent. |
| Mesh, policy and identity checkpoints | `helix/handoff_relations.zig` plus the magic-discriminated `.mesh_checkpoint` families; current required pieces cannot silently default empty. |
| MESSAGE_V2 and Event Spine replay | `relay_v2_replay_guard.zig`, `relay_v2_event_log.zig`, `relay_v2_outbox.zig`, `attachment_delivery_spool.zig`, `event_spine_replay_guard.zig`. |

Paths in this table are relative to `src/daemon/`. Reusable credential scopes and
current redirect behavior are detailed in [credential domains](../reference/credential-domains.md)
and [the session contract](../design/session-resume-anywhere-blueprint.md).

## Refusal, stop and rollback boundaries

`upgradeContinuityBlockerLocked` in `server.zig` refuses states that cannot be
carried exactly. Examples include deferred unadmitted MESSAGE_V2 wire, retained
remote presentation/output transactions, uncheckpointed media state, and active
or retired recording writers awaiting journal/manifest completion. A configured
WebTransport listener needs its exact platform owner and custody support; its
presence alone does not prove that a particular upgrade is permitted.

Linux TERM/INT are blocked before daemon workers start and observed without
consuming their kernel-pending state. Stop checks fence deferred, frozen and exec
upgrade boundaries, and `pending-stop-v1` prevents handing blocked stop signals to
an incompatible successor. Offline CLI paths retain ordinary signal behavior.
Source: [main.zig](../../src/main.zig), `server.zig` and `helix/live.zig`.

A refusal before exec keeps the predecessor serving. Once Linux exec replaces the
image, there is no separate old process to resume: a fatal successor failure
requires the documented recovery procedure. RESTART/listener-only execution is
not a silent fallback for a failed UPGRADE. A cold restart drops TCP attachments
and in-memory session/custody state. Durable account `SESSION-TOKEN` login recovery
is separate from preserving an exact live attachment or unacknowledged message tail.
See [MESSAGE_V2 durability](../design/message-v2-exact-once.md#cold-restart-durability-contract).

## OroWasm host and dispatch

[The host](../../src/wasm/host/) is pure Zig. Registered commands pass through the
SerpentRegistry runtime first; only a registry miss can reach a loaded plugin that
owns the command. Plugins receive bounded host capabilities and fuel/memory limits,
with reply, logging and clock callbacks. The host does not grant direct daemon
memory ownership or arbitrary network access merely because a plugin is loaded.

Authoritative interfaces: `src/wasm/host/abi.zig`, `bridge.zig`, `interp.zig`, and
`LinuxServer.dispatchRegistered`. `OROWASM STATUS|ABI|WIT|PLUGINS` reports effective
budgets, allowed capabilities/intents, registry pins and loaded plugin grants.
Follow the host ABI source and plugin examples under `src/wasm/host/` and the `[wasm]` section of the
[configuration reference](../reference/config.md). Declared host features and pure
codec helpers must be distinguished from a configured, loaded runtime plugin.

## Verification

Use the [testing guide](../guide/testing.md) for the pinned compiler and focused
`test-helix`, `test-server`, `test-mesh` and module gates. A focused codec result
cannot establish live connection continuity. Release acceptance requires the full
gates and explicit multi-client evidence for the deployed upgrade strategy;
see the [2026-11-03 release record](../audit/release-and-test-speed-2026-11-03.md).
