# Helix upgrade

Helix preserves live state only when the complete source/target compatibility
and continuity checks pass. A successful signal or service reload is a request,
not completion. The accepted production topology and its current cold-restart
requirement are recorded in [production paths](../ops/onyx-server-paths.md).

Helix is Onyx Server's in-place upgrade workflow. The operator-facing command is
`UPGRADE`. Linux uses hot re-exec; OpenBSD uses a native guarded successor handoff; Windows launches a native successor and
transfers live state after an authenticated capability check. The `UPGRADE`
command requires the `server_restart` operator privilege.

## Preconditions

| Requirement | Detail | Source |
|---|---|---|
| Platform | Linux re-exec, guarded OpenBSD handoff, or native 64-bit Windows successor transfer. Windows does not use `SIGUSR2`. | `LinuxServer.performUpgrade`, native platform drivers |
| Operator privilege | The command requires `server_restart` before proceeding. | `LinuxServer.handleUpgradeCommand` |
| Linux re-exec path | The daemon probes and retains the exact configured on-disk launch image, falling back to `/proc/self/exe`. | `LinuxServer.openCompatibleUpgradeTarget`, `LinuxServer.performUpgrade` |
| Windows source and target | The config needs explicit `[node].secret_key` and `[cloak].secret`. With no argument, `UPGRADE` uses the running executable path; an explicit target must be a fully qualified `onyx-server*.exe` path beside that image. | `LinuxServer.handleUpgradeCommand`, `LinuxServer.performUpgrade` |

## Windows workflow and checks

Run `onyx-server.exe --check-config <config.toml>` before starting or upgrading a
node. If a config file changed, use
`onyx-server.exe --check-config <config.toml> --against <boot-copy.toml>` to check
the listener set against an unchanged copy of the running node's boot config.
An operator can then send `UPGRADE` to select the running image, or
`UPGRADE :C:\path\beside-current\onyx-server-next.exe` to select a staged image.
The target must pass the native capability challenge; a rejected candidate leaves
the current worker serving. Windows Service Control Manager installations keep
the service host running across a successful worker swap. See the
[native Windows guide](windows.md#guarded-windows-helix-upgrade) for the source
proof, custody rules, and live checks. The sequential IRC and secured mesh
smokes are `tools/windows_helix_smoke.py` and
`tools/windows_helix_mesh_smoke.py`; media and WebTransport have separate live
smokes in that guide.

## Linux workflow

1. The old process publishes an operator event and selects every live client,
   including the requesting oper connection. The requester is retained only as
   the destination for progress notices; it is not excluded from carry-over.
2. On a multi-reactor node, it parks every sibling reactor between loop turns before reading foreign-shard connection state. A shard that does not park within the bounded wait refuses the upgrade instead of being dropped (`LinuxServer.quiesceSiblingReactors`).
3. It snapshots connection state and channel memberships across every shard (`LinuxServer.sealShardClients`).
4. It serializes the snapshots into Helix state pieces and seals them into a memfd arena (`helix_live.prepare`).
5. It clears close-on-exec for every per-shard listener, the carried client sockets, and the arena fd; then it builds an exec plan for the configured on-disk binary with `--supervisor` and commits the exec (`LinuxServer.performUpgrade`, `helix_live.buildArenaListenerExecPlan`).
6. The successor initializes in `--supervisor` mode, adopts the inherited listener fd for each shard, keeps every `SO_REUSEPORT` accept queue represented, and stores the inherited arena fd for session adoption (`src/main.zig`, `Server.init`).
7. Before the successor starts serving, it verifies the whole manifest and cross-capsule relations, then stages and publishes the mandatory client, TLS, WebSocket, session-registry, mesh-clock, replay/outbox/event-log, attachment-spool, and secured-mesh authorities. Invalid or incomplete mandatory state refuses startup rather than publishing a partial handoff. Carried clients are deterministically re-pinned across the live shard set and I/O is armed on the first reactor turn.

Session-registry carry preserves every attachment row, including multiple live or
detached rows sharing one reusable logical-session token. The successor therefore
does not collapse a multi-client session into a single owner. It also carries the
portable bit, detached snapshots, and staged signed replicas. Once preserved secured
links are adopted, the successor re-offers portable state to rebuild the
process-local token-to-authenticated-peer authorization bindings.

Helix carry also includes the **converged mesh view**, so an upgrade no longer
replays remote membership to local clients. Each secured link's converged
remote-member roster rides the `.s2s_link` capsule's v4 roster block; the
successor primes it before the post-upgrade RESYNC re-burst, which then dedups
instead of re-announcing every surviving remote member as a spurious `JOIN`
(`src/daemon/helix/s2s_snapshot.zig`, `src/daemon/secured_s2s_link.zig`).
The server-wide cross-mesh oper-grant registry (magic `OGNT`) rides the
`.mesh_checkpoint` capsule family and is primed at the adoption commit edge, so a
peer's post-RESYNC grant re-mint sees the converged `had_oper_override` state and
never re-broadcasts a false `MODE #chan +Y <nick>`; the resume log reports
`primed N carried oper grant(s)` (`src/daemon/helix/oper_grant_snapshot.zig`,
`src/daemon/server.zig`). Topic re-bursts are diffed against the carried
World topic, and an unchanged re-affirmation is neither applied nor emitted, so an
upgrade also stops surfacing a spurious `TOPIC` line
(`src/daemon/server.zig`). Legacy codec helpers can recognize some older snapshots, but this does not
authorize a live downgrade or a partial current handoff. The live capability
and relational guards require every mandatory authority. Missing state refuses
transactionally rather than being replaced with defaults.

The Helix live path passes inherited fds through environment variables. A single-shard or legacy handoff uses `ONYX_HELIX_LISTEN_FD`; a multi-shard predecessor additionally passes the full shard-ordered set in `ONYX_HELIX_LISTEN_FDS`. The sealed arena uses `ONYX_HELIX_ARENA_FD` (`src/daemon/helix/live.zig`, `src/daemon/helix/live.zig`, `src/daemon/helix/live.zig`).

Current handoff also requires exactly one MHLC v3 mesh-clock capsule. Besides
the mesh HLC and migration-offer floor, v3 carries the configured MESSAGE_V2
authoring mode, activation epoch, and canonical roster digest. The relational
preflight rejects missing/duplicate/old/malformed MHLC state and validates the
predecessor-to-successor activation transition before any inherited state is
published. The live upgrade capability token includes `mesh-clock-v3`, so a
target image without this exact authority is refused before exec.

Because this is an exact capability boundary, the first deployment from an
image whose token predates `mesh-clock-v3` requires a planned cold restart.
After activation, a successor must keep the exact active epoch/digest and mode;
hot downgrade and plan replacement are rejected. Cold boot cannot recover the
previous active tuple from Helix, so the deployment system must preserve it.

## Stop, recording and transport boundaries

The current exact capability token also contains `pending-stop-v1`. On native
Linux, TERM/INT is blocked before daemon workers start, polled without consuming
the kernel-pending authority, and retained across same-PID exec. A requested stop
prevents a new upgrade cut. Older targets without that contract are refused;
do not hot-downgrade around the guard. Offline CLI commands keep their normal
signal behavior.

Continuity guards inspect process-owned state before sealing. Active recording
journals and retired writers awaiting their final manifest are not carried and
therefore block Helix even after their room has disappeared. Unfinished oversized
input, pending identity/membership delivery and other uncheckpointed authorities
can also defer or refuse the request. WebTransport/media/ACME continuity depends
on the actual platform, retained owner and source/target implementation; a named
feature or capability token alone does not prove that the running deployment can
upgrade it. Consult the source guard and release acceptance for the exact image.

Both Linux supervisor kits validate the staged candidate before sending USR2.
Use [service management](service-management.md) for validated reload, foreground
supervision and the systemd certificate-loader sandbox requirement.

## Custody-plane durability

The carried roster/oper-grant registries above and the durable MESSAGE_V2 custody
authorities — the accepted-event log (`RVL2`), per-hop outbox (`RVO2`), replay
guard (`RVG2`), and rendered-record spool (`ADS1`) — are **in-memory checkpoints
sealed only into the Helix upgrade capsule at re-exec**. They survive a `SIGUSR2`
hot-upgrade (`systemctl reload onyx-server`), but there is no disk write-ahead log
behind this plane: a power loss or **cold** restart under either supervisor
drops any in-flight custody obligation together with the carried roster and grant
registries. Follow the [cold-restart custody contract](../RUNBOOK.md#cold-restart).
An ordered acknowledged prefix and a quiet interval do not prove globally empty
custody or prevent a future producer from submitting another event. Record the
actual operational boundary, accepted client impact and recovery checks. See the [MESSAGE_V2 exact-once
design](../design/message-v2-exact-once.md) for the full durability contract.

## Fail-closed boundary

Current UPGRADE requires a complete state set, sealed arena, exact target
capability token, whole-handoff manifest, fd relation, and mandatory authority
validation. Failure before exec leaves the predecessor serving; invalid
successor state is rejected instead of being intentionally reduced to a
listener-only or partial-session handoff. The listener-only helper belongs to
the explicit RESTART path, not UPGRADE.

## Rollback boundary

Hot rollback is safe only when the target exposes the exact full Helix capability
token required by the running predecessor; listener compatibility alone is not
enough. In particular, do **not** hot-roll back a multi-shard Onyx Server 0.5.2+
process to a pre-0.5.2 binary. Before MESSAGE_V2 activation, use a cold restart
across that boundary. After activation, hot or cold rollback is allowed only to
an image that implements the activation boundary and preserves the exact active
mode, epoch, and roster digest. See the [runbook rollback
procedure](../RUNBOOK.md#rollback).
