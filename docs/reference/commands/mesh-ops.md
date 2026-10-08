# Mesh operations commands

*Undertow mesh introspection, routing, health, and Helix in-place upgrade.*

The `oper.security` module registers the mesh oper commands `MESH`, `NETSTAT`, `ROUTE`, and `NETHEALTH` (`src/daemon/modules/oper_security.zig:132`). The `query.info` module registers `LINKS` and `MAP` as server-information commands (`src/daemon/modules/query_info.zig:68`). The upgrade module registers `UPGRADE`, which checks oper status inside its handler (`src/daemon/modules/upgrade.zig:21`, `src/daemon/server.zig:6076`).

## MESH

- Syntax: `MESH [LOG|GRANTS|ADMISSION]`
- Description: Without a subcommand, renders live mesh peer/link health and then a partition/quorum summary (`mesh intact`, `PARTITIONED (quorum held)`, or `PARTITIONED (NO QUORUM ...)`). `MESH LOG` prints recent mesh audit events. `MESH GRANTS` lists recognized cross-mesh operator grants. `MESH ADMISSION` reports MeshPass admission posture (`open`, shared-secret fallback, or signed roots) without exposing shared secret or token bytes, plus the local MESSAGE_V2 implementation marker (`relay_v2_bridge_implemented`), authoring mode/eligibility, activation epoch, roster count, and roster digest (`relay_v2_roster_digest`). The implementation marker is not peer or full-mesh readiness proof.
- Privileges: Oper (`.access = .oper`).
- Parameters: Optional `LOG`, `GRANTS`, or `ADMISSION`.
- Replies: Server notices containing report lines.
- Errors: `ERR_NOPRIVILEGES 481`.
- Example: `MESH ADMISSION`
- Sources: `src/daemon/modules/oper_security.zig:132`, `src/daemon/server.zig:10308`, `src/daemon/server.zig:10412`

## NETSTAT

- Syntax: `NETSTAT [LOG|GRANTS|ADMISSION]`
- Description: Alias of `MESH`; dispatches to the same handler and supports the same subcommands.
- Privileges: Oper (`.access = .oper`).
- Parameters: Same as `MESH`.
- Replies: Same as `MESH`.
- Errors: `ERR_NOPRIVILEGES 481`.
- Example: `NETSTAT`
- Sources: `src/daemon/modules/oper_security.zig:133`, `src/daemon/server.zig:10308`

## ROUTE

- Syntax: `ROUTE`
- Description: Renders this node plus one-hop routes to every established peer. Multi-hop routes are reserved for a later route-table substrate.
- Privileges: Oper (`.access = .oper`).
- Parameters: None.
- Replies: Server notices containing route report lines.
- Errors: `ERR_NOPRIVILEGES 481`.
- Example: `ROUTE`
- Sources: `src/daemon/modules/oper_security.zig:134`, `src/daemon/server.zig:10455`

## NETHEALTH

- Syntax: `NETHEALTH`
- Description: Lists this node and each established peer as alive with RTT and idle time; this is not a witness-quorum death decision. A pair loses the link on ping timeout.
- Privileges: Oper (`.access = .oper`).
- Parameters: None.
- Replies: Server notices containing health report lines.
- Errors: `ERR_NOPRIVILEGES 481`.
- Example: `NETHEALTH`
- Sources: `src/daemon/modules/oper_security.zig:135`, `src/daemon/server.zig:10477`

## LINKS

- Syntax: `LINKS`
- Description: Lists Undertow mesh peers, not a TS6 spanning tree.
- Privileges: Registered client.
- Parameters: None.
- Replies: `RPL_LINKS 364`, `RPL_ENDOFLINKS 365`.
- Errors: None specific.
- Example: `LINKS`
- Sources: `src/daemon/modules/query_info.zig:68`, `src/daemon/server.zig:10143`, `src/proto/numeric.zig:121`

## MAP

- Syntax: `MAP`
- Description: Renders the Undertow mesh topology map.
- Privileges: Registered client.
- Parameters: None.
- Replies: `RPL_MAP 15`, `RPL_MAPEND 17`.
- Errors: None specific.
- Example: `MAP`
- Sources: `src/daemon/modules/query_info.zig:69`, `src/daemon/server.zig:10171`, `src/proto/numeric.zig:15`

## UPGRADE

- Syntax: `UPGRADE` or, on Windows, `UPGRADE :<absolute-path-to-onyx-server.exe>`
- Description: Helix hot in-place upgrade preserves listeners, clients, and the converged mesh view (including each link's remote-member roster and the cross-mesh oper-grant registry). Mandatory state and candidate capability must validate before adoption; incomplete state or a failed candidate leaves the serving process active. On Linux, the handler seals a memfd arena, probes the configured executable path's exact capability token (falling back to `/proc/self/exe` only when no path was recorded), and re-execs the pinned image with `--supervisor`. On Windows, it launches a native successor from the current executable path or an explicitly staged image, passes authenticated state and socket custody, and commits only after candidate validation. The Windows path requires a config file with explicit `[node].secret_key` and `[cloak].secret`; a staged image must be an absolute local `onyx-server*.exe` path beside the running image. See the [Windows guide](../../guide/windows.md#guarded-windows-helix-upgrade) for the handoff rules and smoke coverage.
- Privileges: Registered command with a `server_restart` oper privilege check inside the handler; other clients receive `ERR_NOPRIVILEGES 481`.
- Parameters: None by default; on Windows, one optional staged executable path.
- Replies: Server notices such as sealed-session count or fail-closed refusal messages.
- Errors: `ERR_NOPRIVILEGES 481`; notices for state, capability, config, seal, plan, or process-launch failures.
- Example: `UPGRADE` or `UPGRADE :C:\onyx\onyx-server-next.exe` on Windows.
- Sources: `src/daemon/modules/upgrade.zig` (`upgrade`), `src/daemon/server.zig` (`handleUpgradeCommand`, `performUpgrade`, `performUpgradeAfterCompatibleTarget`), and `src/daemon/helix/native_windows_runtime.zig` (`Driver.begin`, `Driver.transferAndCommit`).
