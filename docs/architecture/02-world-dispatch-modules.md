# World, dispatch, and modules

_Local `World` state, the two-layer client command dispatch model, SerpentRegistry modules, typed hooks, and registry introspection._

This document covers local world state and the client command dispatch model. Mesh/S2S state projection is out of scope; see [mesh-s2s.md](mesh-s2s.md).

## World model

`src/daemon/world.zig` models local daemon state: nick ownership, channel membership, and channel topics. Its header explicitly says it has no S2S/CRDT responsibilities. Evidence: `src/daemon/world.zig`.

| Structure | Role | Evidence |
| --- | --- | --- |
| `ClientId` | Packed client handle with `shard`, `slot`, and `gen`, matching the sharded reactor model. | `src/daemon/world.zig` |
| `Channel` | Per-channel members, topic, modes, key, limit, list modes, invites, forward target, private/hidden flags, IRCX ext flags, OID, and creation time. | `src/daemon/world.zig` |
| `World` | Owns allocator, channels map, nick maps, object-id source, clock, RCU mirrors, and lock. | `src/daemon/world.zig` |
| RCU nick mirror | Activated lazily and used by `findNick` after activation for case-insensitive nick lookup. | `src/daemon/world.zig` |
| RCU channel mirror | Tracks channel existence and per-channel membership for lock-free reads after activation. | `src/daemon/world.zig` |

## World mutations and reads

| Operation | Behavior | Evidence |
| --- | --- | --- |
| Nick registration | Activates RCU nicks, rejects case-insensitive collisions, updates RCU and fallback maps. | `src/daemon/world.zig` |
| Nick lookup | Uses RCU when active; otherwise falls back to the map. | `src/daemon/world.zig` |
| Join | Creates channel if needed, grants founder mode to the first unregistered channel member, inserts membership, mirrors into RCU. | `src/daemon/world.zig` |
| Part | Removes membership, mirrors removal into RCU, and prunes empty unregistered channels. | `src/daemon/world.zig` |
| Target resolution | Distinguishes channel targets from nick targets. | `src/daemon/world.zig` |
| Disconnect cleanup | Removes nick and all channel memberships, mirrors removals, and prunes empty unregistered channels. | `src/daemon/world.zig` |

## Two-layer dispatch

There are two dispatch layers in current source:

| Layer | Source | Command surface | Evidence |
| --- | --- | --- | --- |
| Pre-registration core | `src/daemon/dispatch.zig` | PASS, NICK, USER, CAP, AUTHENTICATE, PING, PONG, QUIT | `src/daemon/dispatch.zig` |
| Post-registration registry | `src/daemon/registry.zig` + `src/daemon/modules/*.zig` | Comptime module commands declared in `modules/manifest.zig` and dispatched through per-server `module_runtime.dispatch` | `src/daemon/modules/manifest.zig`, `src/daemon/server.zig` |

The server-level route is:

| Stage | Behavior | Evidence |
| --- | --- | --- |
| Parse | `processLine` parses one complete IRC line and adapts it into `dispatch.LineView`. | `src/daemon/server.zig` |
| Prereg dispatch | `dispatch.dispatchLine` handles labels, validates table lookup/arity/prereg state, runs a handler, syncs registration, and maybe emits the welcome burst. | `src/daemon/dispatch.zig` |
| Registered dispatch entry | Registered lines enter `dispatchRegistered`; it also has the multiline pre-route. | `src/daemon/server.zig` |
| Registry first | `dispatchRegistered` calls `dispatchModules`, which creates `module_core.Core`, computes caps, and calls `module_runtime.dispatch` with current lifecycle availability. | `src/daemon/server.zig` |
| Registry miss | If no registry command matches, OroWasm plugins may own the command. | `src/daemon/server.zig` |
| Lower fallback | The remaining direct path is `processLine` for the registration-handshake command table; this keeps PASS/NICK/USER/CAP/AUTHENTICATE/PING/PONG/QUIT usable after registration where applicable. | `src/daemon/server.zig`, `src/daemon/dispatch.zig` |

This diverges from older planning and request wording: `dispatchRegistered` no longer holds a large post-registration daemon-owned if/else command chain. The source comment states, "Everything daemon-owned is a SerpentRegistry command." Evidence: `src/daemon/server.zig`.

### Control-byte firewall (CWE-93)

Reply/field builders use `dispatch.hasControlByte`, which is true for any C0 control (`< 0x20`, including CR/LF/NUL/TAB) or DEL (`0x7f`). Evidence: `src/daemon/dispatch.zig`.

- **Inbound**, the `ReplyCtx` line builders and prereg field setters reject fields carrying a control byte with `error.ControlByte` before a line is serialized. Evidence: `src/daemon/dispatch.zig`.
- **Outbound reply sinks** reuse the same predicate as a fail-closed guard so no reflected/interpolated value (a nick, a fantasy `!weather` body, a `FAIL`/`NOTICE` reason) can smuggle a raw CR/LF that starts a forged IRC line. `noticeTo`, `fantasyReply`, and `failReply` each drop the reply rather than emit it when a control byte is present. Evidence: `src/daemon/server.zig`.

These checks protect the builders and sinks that invoke them. New raw-line or
interpolation paths still need their own bounded validation and regression tests;
the existence of this helper is not a proof about every future emitter.

## SerpentRegistry

`registry.zig` statically assembles module metadata, command tables, and hook tables at comptime. Its header says module metadata is validated at comptime, command/hook tables are generated once, and dispatch scans immutable declarations. Evidence: `src/daemon/registry.zig`.

| Registry concept | Behavior | Evidence |
| --- | --- | --- |
| `CommandSpec` | Declares command name, min params, access, optional feature gate, summary, handler. | `src/daemon/registry.zig` |
| `Module` | Declares id, version, category, priority, dependencies/conflicts, commands, hooks, caps, modes, numerics, ISUPPORT, lifecycle callbacks. | `src/daemon/registry.zig` |
| Validation | Detects duplicate modules, missing deps, conflicts, cycles, and duplicate commands/caps/modes/numerics. | `src/daemon/registry.zig` |
| Built tables | `Registry` builds command, hook, cap, mode, numeric, and ISUPPORT tables at comptime. | `src/daemon/registry.zig` |
| Command lookup | A comptime `StaticStringMapWithEql` indexes command names case-insensitively. | `src/daemon/registry.zig` |
| Gated dispatch | Enforces feature gates, IRCX gates, access, and arity before calling the handler. | `src/daemon/registry.zig` |

## Typed hooks

Hooks are typed by `HookId`, and `HookPayload(id)` maps each hook id to a concrete payload pointer type. Veto-capable payloads include `approved: bool`. Evidence: `src/daemon/registry.zig`.

The current live server uses per-instance `module_runtime.emit` for
informational hooks and `module_runtime.approve` for veto-capable message
approval. `approve` fails closed on handler error and stops on the first denial.
The lower `Registry.callHook` helper is not the current live message-veto path.
See [the module system](MODULE-SYSTEM.md).

The server currently fires the `client_registered` hook after the registration welcome path. Evidence: `src/daemon/server.zig`.

## Connection classes and nick-delay integration

Connection classes are not a module but a foundational daemon subsystem. Each connection is matched to a class at registration based on source IP (CIDR), TLS, SASL auth, oper status, and ident/host globs. The first matching class wins; built-in fallback classes (`user` and `server`) exist for all connections. Evidence: `src/daemon/conn_class.zig`.

Per-class enforcement hooks into the registration flow and the per-connection admission check. The class policy enforces SendQ/RecvQ ceilings, flood lines, max_clients/per_ip/channels, require_tls/sasl, and nick_delay exemption. Evidence: `src/daemon/server.zig`.

Nick delay is a daemon-global but per-account and per-nick-class feature. When a nick is released (via QUIT, NICK change, or recovery), it is held for a configured window to prevent nick camping. During the hold, only the owning account can reclaim it (oper bypass always applies, and `nick_delay_exempt` classes bypass). Evidence: `src/daemon/nick_delay.zig`, `src/daemon/server.zig`.

STATS reporting includes per-class policy and live member count (numeric 218 RPL_STATSYLINE) and per-S2S-peer sendq_cap, queued bytes, and uptime (numeric 211 RPL_STATSLLINE). Nick-delay status is reported by INFO. Evidence: `src/daemon/server.zig`.

## Live module manifest and command families

`modules/manifest.zig` is the single enabled-module list. `Live` is the comptime-assembled and validated registry. Evidence: `src/daemon/modules/manifest.zig`.

| Module id | Command family in current source | Evidence |
| --- | --- | --- |
| `query.info` | VERSION, TIME, ADMIN, INFO, DIRECTORY, MOTD, LUSERS, USERS, LINKS, MAP | `src/daemon/modules/query_info.zig` |
| `channel.ops` | JOIN, PART, NAMES, MODE, KICK, INVITE, TOPIC, KNOCK, CREATE, RENAME, CHANBADWORDS | `src/daemon/modules/channel_ops.zig` |
| `messaging` | PRIVMSG, NOTICE, TAGMSG, REDACT, EDIT, CHATHISTORY, SEARCH, MARKREAD, PINS, METADATA, MONITOR, SILENCE | `src/daemon/modules/messaging.zig` |
| `accounts` | REGISTER, VERIFY, IDENTIFY, TOTP, LOGOUT, DROP, SETPASS, RESETPASS, SUCCESSOR, ACCOUNTINFO, ACCOUNT, SASLINFO, ACCOUNTSET, GHOST, RECOVER, RELEASE, CHANNEL/CS, SESSION, SESSIONTOKEN, CERTADD, CERTLIST, CERTDEL, WEBAUTHN, KEYTRANS, E2EEKEY, IDENTITY, RECOGNIZE, LISTCHANS | `src/daemon/modules/accounts.zig` |
| `ircx` | IRCX, ISIRCX, DATA, REQUEST, REPLY, WHISPER, PROP, ACCESS, SACCESS, AUTH, EVENT, MODEX, LISTX | `src/daemon/modules/ircx.zig` |
| `oper.security` | OPER, REHASH, GRANT, REVOKE, GRANTS, KILL, CLOSE, DRAIN, UNREJECT, WARD, SPAMTRAP, KLINE, DLINE, XLINE, SHUN, UNSHUN, GLOBAL, OPERMOTD, DIE, RESTART, CONNECT, SQUIT, TRACE, ETRACE, STATS, TESTLINE, TESTMASK, USERIP, DEBUG, AUDIT, SESSIONS, MESH/NETSTAT, ROUTE, NETHEALTH | `src/daemon/modules/oper_security.zig` |
| `user.query` | ISON, USERHOST, WHOIS, LIST, WHO, WHOX, WHOWAS, AWAY, SETNAME, NICK, QUIT, ACCEPT, HELP, HELPOP, AUTOJOIN, GROUP, WELCOME | `src/daemon/modules/user_query.zig` |
| `feature.misc` | VHOST, PRIVS, FILTER, MEDIA, MEMO, WEBPUSH, ACTIVITY, GEOIP, SUMMON, PONG | `src/daemon/modules/feature_misc.zig` |
| `diag.introspect` | MODULES, MODLIST, COMMANDS, OROWASM | `src/daemon/modules/introspect.zig` |
| `ops.upgrade` | UPGRADE | `src/daemon/modules/upgrade.zig` |
| `services.ext` | RESV, UNRESV, JUPE, UNJUPE, FORCEOP, FORCEDEOP, FORCEJOIN, FORCEPART, FORCETOPIC, CLEAR, TEMPMODE, CLONES, SEEN | `src/daemon/modules/services_ext.zig` |
| `webhook` | WEBHOOK | `src/daemon/modules/webhook.zig` |

The `MEDIA` command is feature-gated by the registry feature tag `"media"`; disabled feature tags come from `Config.disabled_features`. Evidence: `src/daemon/modules/feature_misc.zig`, `src/daemon/registry.zig`, `src/daemon/server.zig`.

## MODULES and COMMANDS introspection

The `diag.introspect` module exposes registry-driven introspection:

| Command | Behavior | Evidence |
| --- | --- | --- |
| MODULES / MODLIST | Oper-gated list of loaded modules with per-module command/cap/hook counts and totals. | `src/daemon/modules/introspect.zig` |
| COMMANDS | Access-aware command discovery; with an argument it shows one command's module, access, feature, params, availability, and summary. | `src/daemon/modules/introspect.zig` |
| OROWASM | Oper-gated runtime view of OroWasm status, ABI/WIT, budgets, and plugins. | `src/daemon/modules/introspect.zig` |

## ISUPPORT source

ISUPPORT comes from `src/proto/protocol_inventory.zig` and runtime overrides built in `src/daemon/server.zig`, not from live module declarations. The inventory file is explicitly the canonical protocol inventory for static RPL_ISUPPORT tokens, network name, and CHANMODES. Evidence: `src/proto/protocol_inventory.zig`, `src/daemon/server.zig`, `src/daemon/dispatch.zig`.

| Token/source | Evidence |
| --- | --- |
| Default network name `Onyx` | `src/proto/protocol_inventory.zig` |
| `CHANMODES=beIZ,k,lfj,imntsCTNgSMWOAphuadErzxwVUFDcBK` | `src/proto/protocol_inventory.zig` |
| Static token array | `src/proto/protocol_inventory.zig` |
| Runtime ISUPPORT override | `src/proto/protocol_inventory.zig`, `src/daemon/server.zig` |
| Welcome burst emits current ISUPPORT | `src/daemon/dispatch.zig` |

## Planning notes and divergences

The comptime module system is implemented across `module_core.zig`, `modules/manifest.zig`, and `introspect.zig`. Evidence: `src/daemon/module_core.zig`, `src/daemon/modules/manifest.zig`, `src/daemon/modules/introspect.zig`.

The current source has moved daemon-owned post-registration commands into SerpentRegistry. Treat any planning or older request language that describes a live registered if/else command chain as historical, unless it points to the small non-command branches in `dispatchRegistered` for multiline, registry, OroWasm, and preregistration fallback. Evidence: `src/daemon/server.zig`.
