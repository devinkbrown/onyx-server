# World, dispatch, and modules

_Local `World` state, the two-layer client command dispatch model, SerpentRegistry modules, typed hooks, and registry introspection._

This document covers local world state and the client command dispatch model. Mesh/S2S state projection is out of scope; see [mesh-s2s.md](mesh-s2s.md).

## World model

`src/daemon/world.zig` models local daemon state: nick ownership, channel membership, and channel topics. Its header explicitly says it has no S2S/CRDT responsibilities. Evidence: `src/daemon/world.zig:4`, `src/daemon/world.zig:6`, `src/daemon/world.zig:7`.

| Structure | Role | Evidence |
| --- | --- | --- |
| `ClientId` | Packed client handle with `shard`, `slot`, and `gen`, matching the sharded reactor model. | `src/daemon/world.zig:97`, `src/daemon/world.zig:99`, `src/daemon/world.zig:100`, `src/daemon/world.zig:101` |
| `Channel` | Per-channel members, topic, modes, key, limit, list modes, invites, forward target, private/hidden flags, IRCX ext flags, OID, and creation time. | `src/daemon/world.zig:172`, `src/daemon/world.zig:174`, `src/daemon/world.zig:175`, `src/daemon/world.zig:178`, `src/daemon/world.zig:180`, `src/daemon/world.zig:183`, `src/daemon/world.zig:185`, `src/daemon/world.zig:204`, `src/daemon/world.zig:206`, `src/daemon/world.zig:209`, `src/daemon/world.zig:212`, `src/daemon/world.zig:217`, `src/daemon/world.zig:220` |
| `World` | Owns allocator, channels map, nick maps, object-id source, clock, RCU mirrors, and lock. | `src/daemon/world.zig:299`, `src/daemon/world.zig:301`, `src/daemon/world.zig:304`, `src/daemon/world.zig:305`, `src/daemon/world.zig:306`, `src/daemon/world.zig:309`, `src/daemon/world.zig:313`, `src/daemon/world.zig:319`, `src/daemon/world.zig:325`, `src/daemon/world.zig:336` |
| RCU nick mirror | Activated lazily and used by `findNick` after activation for case-insensitive nick lookup. | `src/daemon/world.zig:13`, `src/daemon/world.zig:17`, `src/daemon/world.zig:19`, `src/daemon/world.zig:412`, `src/daemon/world.zig:421`, `src/daemon/world.zig:605`, `src/daemon/world.zig:606`, `src/daemon/world.zig:608` |
| RCU channel mirror | Tracks channel existence and per-channel membership for lock-free reads after activation. | `src/daemon/world.zig:31`, `src/daemon/world.zig:43`, `src/daemon/world.zig:48`, `src/daemon/world.zig:321`, `src/daemon/world.zig:325`, `src/daemon/world.zig:1303`, `src/daemon/world.zig:1304`, `src/daemon/world.zig:1320`, `src/daemon/world.zig:1323` |

## World mutations and reads

| Operation | Behavior | Evidence |
| --- | --- | --- |
| Nick registration | Activates RCU nicks, rejects case-insensitive collisions, updates RCU and fallback maps. | `src/daemon/world.zig:535`, `src/daemon/world.zig:537`, `src/daemon/world.zig:540`, `src/daemon/world.zig:548`, `src/daemon/world.zig:560`, `src/daemon/world.zig:567`, `src/daemon/world.zig:570` |
| Nick lookup | Uses RCU when active; otherwise falls back to the map. | `src/daemon/world.zig:600`, `src/daemon/world.zig:605`, `src/daemon/world.zig:606`, `src/daemon/world.zig:608`, `src/daemon/world.zig:611` |
| Join | Creates channel if needed, grants founder mode to the first unregistered channel member, inserts membership, mirrors into RCU. | `src/daemon/world.zig:624`, `src/daemon/world.zig:626`, `src/daemon/world.zig:630`, `src/daemon/world.zig:631`, `src/daemon/world.zig:634`, `src/daemon/world.zig:638`, `src/daemon/world.zig:640` |
| Part | Removes membership, mirrors removal into RCU, and prunes empty unregistered channels. | `src/daemon/world.zig:1281`, `src/daemon/world.zig:1283`, `src/daemon/world.zig:1286`, `src/daemon/world.zig:1288`, `src/daemon/world.zig:1295`, `src/daemon/world.zig:1296` |
| Target resolution | Distinguishes channel targets from nick targets. | `src/daemon/world.zig:1444`, `src/daemon/world.zig:1445`, `src/daemon/world.zig:1447`, `src/daemon/world.zig:1450`, `src/daemon/world.zig:1451` |
| Disconnect cleanup | Removes nick and all channel memberships, mirrors removals, and prunes empty unregistered channels. | `src/daemon/world.zig:1456`, `src/daemon/world.zig:1458`, `src/daemon/world.zig:1464`, `src/daemon/world.zig:1467`, `src/daemon/world.zig:1476`, `src/daemon/world.zig:1484` |

## Two-layer dispatch

There are two dispatch layers in current source:

| Layer | Source | Command surface | Evidence |
| --- | --- | --- | --- |
| Pre-registration core | `src/daemon/dispatch.zig` | PASS, NICK, USER, CAP, AUTHENTICATE, PING, PONG, QUIT | `src/daemon/dispatch.zig:1709`, `src/daemon/dispatch.zig:1710`, `src/daemon/dispatch.zig:1714`, `src/daemon/dispatch.zig:1718`, `src/daemon/dispatch.zig:1719`, `src/daemon/dispatch.zig:1720` |
| Post-registration registry | `src/daemon/registry.zig` + `src/daemon/modules/*.zig` | Comptime module commands declared in `modules/manifest.zig` and dispatched via `module_manifest.Live.dispatchGated` | `src/daemon/modules/manifest.zig:26`, `src/daemon/modules/manifest.zig:27`, `src/daemon/modules/manifest.zig:42`, `src/daemon/modules/manifest.zig:47`, `src/daemon/server.zig:8412` |

The server-level route is:

| Stage | Behavior | Evidence |
| --- | --- | --- |
| Parse | `processLine` parses one complete IRC line and adapts it into `dispatch.LineView`. | `src/daemon/server.zig:2353`, `src/daemon/server.zig:2355`, `src/daemon/server.zig:2356`, `src/daemon/server.zig:2371`, `src/daemon/server.zig:2379` |
| Prereg dispatch | `dispatch.dispatchLine` handles labels, validates table lookup/arity/prereg state, runs a handler, syncs registration, and maybe emits the welcome burst. | `src/daemon/dispatch.zig:1587`, `src/daemon/dispatch.zig:1592`, `src/daemon/dispatch.zig:1600`, `src/daemon/dispatch.zig:1616`, `src/daemon/dispatch.zig:1622`, `src/daemon/dispatch.zig:1627`, `src/daemon/dispatch.zig:1633`, `src/daemon/dispatch.zig:1639`, `src/daemon/dispatch.zig:1642` |
| Registered dispatch entry | Registered lines enter `dispatchRegistered`; it also has the multiline pre-route. | `src/daemon/server.zig:8310`, `src/daemon/server.zig:8321`, `src/daemon/server.zig:8333`, `src/daemon/server.zig:8338` |
| Registry first | `dispatchRegistered` calls `dispatchModules`, which creates `module_core.Core`, computes caps, and calls `module_manifest.Live.dispatchGated`. | `src/daemon/server.zig:8355`, `src/daemon/server.zig:8367`, `src/daemon/server.zig:8398`, `src/daemon/server.zig:8406`, `src/daemon/server.zig:8412` |
| Registry miss | If no registry command matches, OroWasm plugins may own the command. | `src/daemon/server.zig:8430`, `src/daemon/server.zig:8434`, `src/daemon/server.zig:8436`, `src/daemon/server.zig:8451` |
| Lower fallback | The remaining direct path is `processLine` for the registration-handshake command table; this keeps PASS/NICK/USER/CAP/AUTHENTICATE/PING/PONG/QUIT usable after registration where applicable. | `src/daemon/server.zig:8371`, `src/daemon/server.zig:8373`, `src/daemon/server.zig:8377`, `src/daemon/dispatch.zig:1709`, `src/daemon/dispatch.zig:1720` |

This diverges from older planning and request wording: `dispatchRegistered` no longer holds a large post-registration daemon-owned if/else command chain. The source comment states, "Everything daemon-owned is a SerpentRegistry command." Evidence: `src/daemon/server.zig:8371`.

### Control-byte firewall (CWE-93)

Every wire-facing path funnels through one predicate, `dispatch.hasControlByte`, which is true for any C0 control (`< 0x20`, including CR/LF/NUL/TAB) or DEL (`0x7f`). Evidence: `src/daemon/dispatch.zig:2281`.

- **Inbound**, the `ReplyCtx` line builders and prereg field setters reject fields carrying a control byte with `error.ControlByte` before a line is serialized. Evidence: `src/daemon/dispatch.zig:2288`, `src/daemon/dispatch.zig:1504`, `src/daemon/dispatch.zig:197`.
- **Outbound reply sinks** reuse the same predicate as a fail-closed guard so no reflected/interpolated value (a nick, a fantasy `!weather` body, a `FAIL`/`NOTICE` reason) can smuggle a raw CR/LF that starts a forged IRC line. `noticeTo`, `fantasyReply`, and `failReply` each drop the reply rather than emit it when a control byte is present. Evidence: `src/daemon/server.zig:17597`, `src/daemon/server.zig:19419`, `src/daemon/server.zig:27661`.

This is a single choke point on both directions: the builders validate what clients send, and the reply sinks validate what the daemon reflects back, so CRLF-injection has no reachable emission path.

## SerpentRegistry

`registry.zig` statically assembles module metadata, command tables, and hook tables at comptime. Its header says module metadata is validated at comptime, command/hook tables are generated once, and dispatch scans immutable declarations. Evidence: `src/daemon/registry.zig:4`, `src/daemon/registry.zig:8`, `src/daemon/registry.zig:9`.

| Registry concept | Behavior | Evidence |
| --- | --- | --- |
| `CommandSpec` | Declares command name, min params, access, optional feature gate, summary, handler. | `src/daemon/registry.zig:244`, `src/daemon/registry.zig:246`, `src/daemon/registry.zig:247`, `src/daemon/registry.zig:250`, `src/daemon/registry.zig:254`, `src/daemon/registry.zig:256`, `src/daemon/registry.zig:257` |
| `Module` | Declares id, version, category, priority, dependencies/conflicts, commands, hooks, caps, modes, numerics, ISUPPORT, lifecycle callbacks. | `src/daemon/registry.zig:349`, `src/daemon/registry.zig:352`, `src/daemon/registry.zig:353`, `src/daemon/registry.zig:354`, `src/daemon/registry.zig:355`, `src/daemon/registry.zig:357`, `src/daemon/registry.zig:359`, `src/daemon/registry.zig:362`, `src/daemon/registry.zig:368`, `src/daemon/registry.zig:371` |
| Validation | Detects duplicate modules, missing deps, conflicts, cycles, and duplicate commands/caps/modes/numerics. | `src/daemon/registry.zig:414`, `src/daemon/registry.zig:417`, `src/daemon/registry.zig:428`, `src/daemon/registry.zig:438`, `src/daemon/registry.zig:449`, `src/daemon/registry.zig:455`, `src/daemon/registry.zig:466`, `src/daemon/registry.zig:477`, `src/daemon/registry.zig:488`, `src/daemon/registry.zig:499` |
| Built tables | `Registry` builds command, hook, cap, mode, numeric, and ISUPPORT tables at comptime. | `src/daemon/registry.zig:513`, `src/daemon/registry.zig:521`, `src/daemon/registry.zig:522`, `src/daemon/registry.zig:523`, `src/daemon/registry.zig:527` |
| Command lookup | A comptime `StaticStringMapWithEql` indexes command names case-insensitively. | `src/daemon/registry.zig:529`, `src/daemon/registry.zig:533`, `src/daemon/registry.zig:537`, `src/daemon/registry.zig:550`, `src/daemon/registry.zig:551` |
| Gated dispatch | Enforces feature gates, IRCX gates, access, and arity before calling the handler. | `src/daemon/registry.zig:556`, `src/daemon/registry.zig:560`, `src/daemon/registry.zig:566`, `src/daemon/registry.zig:569`, `src/daemon/registry.zig:570`, `src/daemon/registry.zig:573`, `src/daemon/registry.zig:576`, `src/daemon/registry.zig:579` |

## Typed hooks

Hooks are typed by `HookId`, and `HookPayload(id)` maps each hook id to a concrete payload pointer type. Veto-capable payloads include `approved: bool`. Evidence: `src/daemon/registry.zig:114`, `src/daemon/registry.zig:133`, `src/daemon/registry.zig:143`, `src/daemon/registry.zig:163`, `src/daemon/registry.zig:184`, `src/daemon/registry.zig:225`.

`callHook` takes a comptime `HookId`, type-erases the typed payload at the registry boundary, runs matching bindings, and stops when a hook returns `.stop`. Evidence: `src/daemon/registry.zig:596`, `src/daemon/registry.zig:600`, `src/daemon/registry.zig:603`, `src/daemon/registry.zig:605`, `src/daemon/registry.zig:606`, `src/daemon/registry.zig:609`.

The server currently fires the `client_registered` hook after the registration welcome path. Evidence: `src/daemon/server.zig:8284`, `src/daemon/server.zig:8285`, `src/daemon/server.zig:8503`, `src/daemon/server.zig:8511`.

## Connection classes and nick-delay integration

Connection classes are not a module but a foundational daemon subsystem. Each connection is matched to a class at registration based on source IP (CIDR), TLS, SASL auth, oper status, and ident/host globs. The first matching class wins; built-in fallback classes (`user` and `server`) exist for all connections. Evidence: `src/daemon/conn_class.zig:4`, `src/daemon/conn_class.zig:9`, `src/daemon/conn_class.zig:13`, `src/daemon/conn_class.zig:132`, `src/daemon/conn_class.zig:142`, `src/daemon/conn_class.zig:199`, `src/daemon/conn_class.zig:204`, `src/daemon/conn_class.zig:239`.

Per-class enforcement hooks into the registration flow and the per-connection admission check. The class policy enforces SendQ/RecvQ ceilings, flood lines, max_clients/per_ip/channels, require_tls/sasl, and nick_delay exemption. Evidence: `src/daemon/server.zig:8264`, `src/daemon/server.zig:8267`, `src/daemon/server.zig:8268`, `src/daemon/server.zig:9771`, `src/daemon/server.zig:9775`, `src/daemon/server.zig:9776`, `src/daemon/server.zig:9781`, `src/daemon/server.zig:9813`, `src/daemon/server.zig:9815`, `src/daemon/server.zig:9817`, `src/daemon/server.zig:11535`.

Nick delay is a daemon-global but per-account and per-nick-class feature. When a nick is released (via QUIT, NICK change, or recovery), it is held for a configured window to prevent nick camping. During the hold, only the owning account can reclaim it (oper bypass always applies, and `nick_delay_exempt` classes bypass). Evidence: `src/daemon/nick_delay.zig:4`, `src/daemon/nick_delay.zig:8`, `src/daemon/nick_delay.zig:11`, `src/daemon/server.zig:8606`, `src/daemon/server.zig:8614`, `src/daemon/server.zig:8615`, `src/daemon/server.zig:8619`, `src/daemon/server.zig:8631`, `src/daemon/server.zig:22100`, `src/daemon/server.zig:24537`.

STATS reporting includes per-class policy and live member count (numeric 218 RPL_STATSYLINE) and per-S2S-peer sendq_cap, queued bytes, and uptime (numeric 211 RPL_STATSLLINE). Nick-delay status is reported by INFO. Evidence: `src/daemon/server.zig:1136`, `src/daemon/server.zig:1137`, `src/daemon/server.zig:14090`, `src/daemon/server.zig:14110`, `src/daemon/server.zig:14114`, `src/daemon/server.zig:14131`, `src/daemon/server.zig:14132`, `src/daemon/server.zig:28356`.

## Live module manifest and command families

`modules/manifest.zig` is the single enabled-module list. `Live` is the comptime-assembled and validated registry. Evidence: `src/daemon/modules/manifest.zig:4`, `src/daemon/modules/manifest.zig:26`, `src/daemon/modules/manifest.zig:27`, `src/daemon/modules/manifest.zig:42`, `src/daemon/modules/manifest.zig:47`.

| Module id | Command family in current source | Evidence |
| --- | --- | --- |
| `query.info` | VERSION, TIME, ADMIN, INFO, DIRECTORY, MOTD, LUSERS, USERS, LINKS, MAP | `src/daemon/modules/query_info.zig:66`, `src/daemon/modules/query_info.zig:68`, `src/daemon/modules/query_info.zig:69`, `src/daemon/modules/query_info.zig:78` |
| `channel.ops` | JOIN, PART, NAMES, MODE, KICK, INVITE, TOPIC, KNOCK, CREATE, RENAME, CHANBADWORDS | `src/daemon/modules/channel_ops.zig:56`, `src/daemon/modules/channel_ops.zig:58`, `src/daemon/modules/channel_ops.zig:59`, `src/daemon/modules/channel_ops.zig:69` |
| `messaging` | PRIVMSG, NOTICE, TAGMSG, REDACT, EDIT, CHATHISTORY, SEARCH, MARKREAD, PINS, METADATA, MONITOR, SILENCE | `src/daemon/modules/messaging.zig:59`, `src/daemon/modules/messaging.zig:61`, `src/daemon/modules/messaging.zig:62`, `src/daemon/modules/messaging.zig:73` |
| `accounts` | REGISTER, VERIFY, IDENTIFY, TOTP, LOGOUT, DROP, SETPASS, RESETPASS, SUCCESSOR, ACCOUNTINFO, ACCOUNT, SASLINFO, ACCOUNTSET, GHOST, RECOVER, RELEASE, CHANNEL/CS, SESSION, SESSIONTOKEN, CERTADD, CERTLIST, CERTDEL, WEBAUTHN, KEYTRANS, E2EEKEY, IDENTITY, RECOGNIZE, LISTCHANS | `src/daemon/modules/accounts.zig:125`, `src/daemon/modules/accounts.zig:153`, `src/daemon/modules/accounts.zig:155`, `src/daemon/modules/accounts.zig:157`, `src/daemon/modules/accounts.zig:187` |
| `ircx` | IRCX, ISIRCX, DATA, REQUEST, REPLY, WHISPER, PROP, ACCESS, SACCESS, AUTH, EVENT, MODEX, LISTX | `src/daemon/modules/ircx.zig:56`, `src/daemon/modules/ircx.zig:58`, `src/daemon/modules/ircx.zig:59`, `src/daemon/modules/ircx.zig:71` |
| `oper.security` | OPER, REHASH, GRANT, REVOKE, GRANTS, KILL, CLOSE, DRAIN, UNREJECT, WARD, SPAMTRAP, KLINE, DLINE, XLINE, SHUN, UNSHUN, GLOBAL, OPERMOTD, DIE, RESTART, CONNECT, SQUIT, TRACE, ETRACE, STATS, TESTLINE, TESTMASK, USERIP, DEBUG, AUDIT, SESSIONS, MESH/NETSTAT, ROUTE, NETHEALTH | `src/daemon/modules/oper_security.zig:143`, `src/daemon/modules/oper_security.zig:145`, `src/daemon/modules/oper_security.zig:149`, `src/daemon/modules/oper_security.zig:183` |
| `user.query` | ISON, USERHOST, WHOIS, LIST, WHO, WHOX, WHOWAS, AWAY, SETNAME, NICK, QUIT, ACCEPT, HELP, HELPOP, AUTOJOIN, GROUP, WELCOME | `src/daemon/modules/user_query.zig:72`, `src/daemon/modules/user_query.zig:74`, `src/daemon/modules/user_query.zig:75`, `src/daemon/modules/user_query.zig:91` |
| `feature.misc` | VHOST, PRIVS, FILTER, MEDIA, MEMO, WEBPUSH, ACTIVITY, GEOIP, SUMMON, PONG | `src/daemon/modules/feature_misc.zig:54`, `src/daemon/modules/feature_misc.zig:56`, `src/daemon/modules/feature_misc.zig:57`, `src/daemon/modules/feature_misc.zig:61`, `src/daemon/modules/feature_misc.zig:66` |
| `diag.introspect` | MODULES, MODLIST, COMMANDS, OROWASM | `src/daemon/modules/introspect.zig:210`, `src/daemon/modules/introspect.zig:213`, `src/daemon/modules/introspect.zig:214`, `src/daemon/modules/introspect.zig:217` |
| `ops.upgrade` | UPGRADE | `src/daemon/modules/upgrade.zig:21`, `src/daemon/modules/upgrade.zig:25` |
| `services.ext` | RESV, UNRESV, JUPE, UNJUPE, FORCEOP, FORCEDEOP, FORCEJOIN, FORCEPART, FORCETOPIC, CLEAR, TEMPMODE, CLONES, SEEN | `src/daemon/modules/services_ext.zig:44`, `src/daemon/modules/services_ext.zig:47`, `src/daemon/modules/services_ext.zig:53`, `src/daemon/modules/services_ext.zig:66` |
| `webhook` | WEBHOOK | `src/daemon/modules/webhook.zig:23`, `src/daemon/modules/webhook.zig:31`, `src/daemon/modules/webhook.zig:34` |

The `MEDIA` command is feature-gated by the registry feature tag `"media"`; disabled feature tags come from `Config.disabled_features`. Evidence: `src/daemon/modules/feature_misc.zig:60`, `src/daemon/registry.zig:270`, `src/daemon/registry.zig:271`, `src/daemon/server.zig:1512`, `src/daemon/server.zig:8410`.

## MODULES and COMMANDS introspection

The `diag.introspect` module exposes registry-driven introspection:

| Command | Behavior | Evidence |
| --- | --- | --- |
| MODULES / MODLIST | Oper-gated list of loaded modules with per-module command/cap/hook counts and totals. | `src/daemon/modules/introspect.zig:4`, `src/daemon/modules/introspect.zig:19`, `src/daemon/modules/introspect.zig:21`, `src/daemon/modules/introspect.zig:28`, `src/daemon/modules/introspect.zig:37`, `src/daemon/modules/introspect.zig:214`, `src/daemon/modules/introspect.zig:215` |
| COMMANDS | Access-aware command discovery; with an argument it shows one command's module, access, feature, params, availability, and summary. | `src/daemon/modules/introspect.zig:44`, `src/daemon/modules/introspect.zig:49`, `src/daemon/modules/introspect.zig:56`, `src/daemon/modules/introspect.zig:60`, `src/daemon/modules/introspect.zig:62`, `src/daemon/modules/introspect.zig:84`, `src/daemon/modules/introspect.zig:85`, `src/daemon/modules/introspect.zig:216` |
| OROWASM | Oper-gated runtime view of OroWasm status, ABI/WIT, budgets, and plugins. | `src/daemon/modules/introspect.zig:100`, `src/daemon/modules/introspect.zig:113`, `src/daemon/modules/introspect.zig:139`, `src/daemon/modules/introspect.zig:170`, `src/daemon/modules/introspect.zig:182`, `src/daemon/modules/introspect.zig:217` |

## ISUPPORT source

ISUPPORT comes from `src/proto/protocol_inventory.zig` and runtime overrides built in `src/daemon/server.zig`, not from live module declarations. The inventory file is explicitly the canonical protocol inventory for static RPL_ISUPPORT tokens, network name, and CHANMODES. Evidence: `src/proto/protocol_inventory.zig:4`, `src/proto/protocol_inventory.zig:5`, `src/daemon/server.zig:1270`, `src/daemon/server.zig:1311`, `src/daemon/dispatch.zig:2115`.

| Token/source | Evidence |
| --- | --- |
| Default network name `Onyx` | `src/proto/protocol_inventory.zig:17`, `src/proto/protocol_inventory.zig:19` |
| `CHANMODES=beIZ,k,lfj,imntsCTNgSMWOAphuadErzxwVUFDcBK` | `src/proto/protocol_inventory.zig:69`, `src/proto/protocol_inventory.zig:71` |
| Static token array | `src/proto/protocol_inventory.zig:61`, `src/proto/protocol_inventory.zig:63`, `src/proto/protocol_inventory.zig:99` |
| Runtime ISUPPORT override | `src/proto/protocol_inventory.zig:101`, `src/proto/protocol_inventory.zig:109`, `src/proto/protocol_inventory.zig:114`, `src/daemon/server.zig:1270` |
| Welcome burst emits current ISUPPORT | `src/daemon/dispatch.zig:2115` |

## Planning notes and divergences

The comptime module system is implemented across `module_core.zig`, `modules/manifest.zig`, and `introspect.zig`. Evidence: `src/daemon/module_core.zig:4`, `src/daemon/module_core.zig:7`, `src/daemon/modules/manifest.zig:4`, `src/daemon/modules/manifest.zig:42`, `src/daemon/modules/introspect.zig:6`, `src/daemon/modules/introspect.zig:8`.

The current source has moved daemon-owned post-registration commands into SerpentRegistry. Treat any planning or older request language that describes a live registered if/else command chain as historical, unless it points to the small non-command branches in `dispatchRegistered` for multiline, registry, OroWasm, and preregistration fallback. Evidence: `src/daemon/server.zig:8333`, `src/daemon/server.zig:8355`, `src/daemon/server.zig:8434`, `src/daemon/server.zig:8371`.
