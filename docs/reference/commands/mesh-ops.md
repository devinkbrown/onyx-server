# Mesh operations commands

*Suimyaku mesh introspection, routing, health, and Helix in-place upgrade.*

The `oper.security` module registers the mesh oper commands `MESH`, `NETSTAT`, `ROUTE`, and `NETHEALTH` (`src/daemon/modules/oper_security.zig:132`). The `query.info` module registers `LINKS` and `MAP` as server-information commands (`src/daemon/modules/query_info.zig:68`). The upgrade module registers `UPGRADE`, which checks oper status inside its handler (`src/daemon/modules/upgrade.zig:21`, `src/daemon/server.zig:6076`).

## MESH

- Syntax: `MESH [LOG|GRANTS|ADMISSION]`
- Description: Without a subcommand, renders live mesh peer/link health and then a partition/quorum summary (`mesh intact`, `PARTITIONED (quorum held)`, or `PARTITIONED (NO QUORUM ...)`). `MESH LOG` prints recent mesh audit events. `MESH GRANTS` lists recognized cross-mesh operator grants. `MESH ADMISSION` reports MeshPass admission posture (`open`, shared-secret fallback, or signed roots) without exposing shared secret or token bytes.
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
- Description: Renders Sazanami-style liveness for this node and each established peer, including link RTT and idle time when known.
- Privileges: Oper (`.access = .oper`).
- Parameters: None.
- Replies: Server notices containing health report lines.
- Errors: `ERR_NOPRIVILEGES 481`.
- Example: `NETHEALTH`
- Sources: `src/daemon/modules/oper_security.zig:135`, `src/daemon/server.zig:10477`

## LINKS

- Syntax: `LINKS`
- Description: Lists Suimyaku mesh peers, not a TS6 spanning tree.
- Privileges: Registered client.
- Parameters: None.
- Replies: `RPL_LINKS 364`, `RPL_ENDOFLINKS 365`.
- Errors: None specific.
- Example: `LINKS`
- Sources: `src/daemon/modules/query_info.zig:68`, `src/daemon/server.zig:10143`, `src/proto/numeric.zig:121`

## MAP

- Syntax: `MAP`
- Description: Renders the Suimyaku mesh topology map.
- Privileges: Registered client.
- Parameters: None.
- Replies: `RPL_MAP 15`, `RPL_MAPEND 17`.
- Errors: None specific.
- Example: `MAP`
- Sources: `src/daemon/modules/query_info.zig:69`, `src/daemon/server.zig:10171`, `src/proto/numeric.zig:15`

## UPGRADE

- Syntax: `UPGRADE`
- Description: Helix hot in-place upgrade. The handler serializes registered sessions into a sealed memfd arena and re-execs `/proc/self/exe --supervisor` preserving the listener and arena. On some failures it falls back to listener-only upgrade. It is Linux-only.
- Privileges: Registered command with oper check inside handler; non-opers receive `ERR_NOPRIVILEGES 481`.
- Parameters: None.
- Replies: Server notices such as sealed-session count or fallback/failure messages.
- Errors: `ERR_NOPRIVILEGES 481`; notices for Linux-only, seal, plan, or exec failures.
- Example: `UPGRADE`
- Sources: `src/daemon/modules/upgrade.zig:22`, `src/daemon/server.zig:6076`
