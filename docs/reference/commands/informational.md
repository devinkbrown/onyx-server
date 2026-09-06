# Informational commands

*Stateless server-information queries, help, statistics, and registry introspection.*

The `query.info` module registers the stateless server-information commands (`src/daemon/modules/query_info.zig:66`). The `user.query` module registers HELP/HELPOP (`src/daemon/modules/user_query.zig:72`). The `oper.security` module registers STATS/TRACE/ETRACE (`src/daemon/modules/oper_security.zig:143`). The `diag.introspect` module provides registry introspection (`src/daemon/modules/introspect.zig:210`). Command specs without an explicit `.access` use the registry default `.registered` (`src/daemon/registry.zig:249`).

## VERSION

- Syntax: `VERSION`
- Description: Returns the current daemon version text. The version token carries the release version plus git revision, and the build token embeds the compile target and git revision the binary was built from (for example, `x86_64-linux-<shorthash>`, suffixed `-dirty` for an unclean tree), captured at build time via `build.zig` `gitCommit` -> `@import("build_info")`.
- Privileges: Registered client.
- Parameters: None.
- Replies: `RPL_VERSION 351`, followed by `RPL_ISUPPORT 005`.
- Errors: None specific.
- Example: `VERSION`
- Sources: `src/daemon/modules/query_info.zig:69`, `src/daemon/server.zig:468`, `src/daemon/server.zig:21985`, `src/daemon/server.zig:22000`, `build.zig:79`, `build.zig:790`

## TIME

- Syntax: `TIME`
- Description: Returns the server wall-clock time formatted by the daemon as UTC.
- Privileges: Registered client.
- Parameters: None.
- Replies: `RPL_TIME 391`.
- Errors: None specific.
- Example: `TIME`
- Sources: `src/daemon/modules/query_info.zig:70`, `src/daemon/server.zig:341`, `src/daemon/server.zig:21963`, `src/proto/serverinfo.zig:140`

## ADMIN

- Syntax: `ADMIN`
- Description: Returns configured admin location/email details.
- Privileges: Registered client.
- Parameters: None.
- Replies: `RPL_ADMINME 256` always; `RPL_ADMINLOC1 257` and `RPL_ADMINEMAIL 259` when configured. The shared ADMIN builder supports `RPL_ADMINLOC2 258` when `location2` is supplied, but the live handler currently passes only `location1` and `email`.
- Errors: None specific.
- Example: `ADMIN`
- Sources: `src/daemon/modules/query_info.zig:71`, `src/daemon/server.zig:1394`, `src/daemon/server.zig:21972`, `src/daemon/server.zig:21977`, `src/proto/serverinfo.zig:177`, `src/proto/serverinfo.zig:213`

## INFO

- Syntax: `INFO`
- Description: Returns implementation information lines, then runtime `RPL_INFO` lines covering advertised limits, the active connection-class count, the nick-delay window and held-nick count when nick delay is enabled, the established mesh-peer count, and a subsystem inventory, followed by an end marker.
- Privileges: Registered client.
- Parameters: None.
- Replies: `RPL_INFOSTART 373`, `RPL_INFO 371`, `RPL_ENDOFINFO 374`.
- Errors: None specific.
- Example: `INFO`
- Sources: `src/daemon/modules/query_info.zig:72`, `src/daemon/server.zig:28308`, `src/daemon/server.zig:28337`, `src/daemon/server.zig:28341`

## DIRECTORY

- Syntax: `DIRECTORY`
- Description: Returns this node's public discovery-directory summary: opt-in listing flag, network/node/description, rank inputs, public activity counters, last-active heatline state, mesh-peer health counts, and a private-node note when discovery is disabled.
- Privileges: Registered client.
- Parameters: None.
- Replies: `RPL_INFOSTART 373`, `RPL_INFO 371`, `RPL_ENDOFINFO 374`.
- Errors: None specific.
- Example: `DIRECTORY`
- Sources: `src/daemon/modules/query_info.zig:73`, `src/daemon/server.zig:28374`, `src/daemon/server.zig:28388`, `src/daemon/server.zig:28415`

## CHANSTATS

- Syntax: `CHANSTATS <TOPUSERS|WORDS|ACTIVITY|RECORD|HELP> [#channel]`
- Description: Reads the native channel-statistics aggregate. `TOPUSERS` ranks speakers, `WORDS` ranks words of length four or more, `ACTIVITY` reports non-zero UTC hourly totals, and `RECORD` reports aggregate/busiest-day/peak-hour/member records. `HELP` prints the live syntax.
- Privileges: Registered client. The command is unavailable when `[stats].channel_dir` is empty; callers need not be on the channel, but only existing channels with data return records.
- Replies: Server notices; no-data and disabled states are explicit.
- Errors: Usage is returned as a notice; unregistered callers receive `ERR_NOTREGISTERED 451` when statistics are enabled.
- Example: `CHANSTATS TOPUSERS #zig`
- Sources: `src/daemon/modules/query_info.zig:84`, `src/daemon/server.zig:48799` (`handleChanstats`), `src/daemon/chanstats.zig`

## MOTD

- Syntax: `MOTD`
- Description: Returns the Message of the Day from the configured `[motd] text` template or the built-in default. The MOTD is expanded per connection: time-of-day greeting, nick/account/host, live network figures, oper/login/TLS conditionals, and, when enabled, localized `{weather}` and `{news}` placeholders.
- Privileges: Registered client.
- Parameters: None.
- Replies: `RPL_MOTDSTART 375`, `RPL_MOTD 372`, `RPL_ENDOFMOTD 376`.
- Errors: None specific in the live handler. The shared MOTD builder can emit `ERR_NOMOTD 422` for an empty MOTD slice, but `handleMotd` supplies configured or built-in template lines.
- Example: `MOTD`
- Sources: `src/daemon/modules/query_info.zig:74`, `src/daemon/server.zig:21790`, `src/daemon/server.zig:21895`, `src/daemon/server.zig:21922`, `src/daemon/server.zig:21956`, `src/proto/motd.zig:85`, `src/proto/motd_template.zig:4`, `src/proto/motd_template.zig:78`

## LUSERS

- Syntax: `LUSERS`
- Description: Returns current local/global user, server, channel, peak connection, and accepted connection counts.
- Privileges: Registered client.
- Parameters: None.
- Replies: `RPL_LUSERCLIENT 251`, `RPL_LUSEROP 252`, `RPL_LUSERUNKNOWN 253`, `RPL_LUSERCHANNELS 254`, `RPL_LUSERME 255`, `RPL_STATSCONN 250`, `RPL_LOCALUSERS 265`, `RPL_GLOBALUSERS 266`.
- Errors: None specific.
- Example: `LUSERS`
- Sources: `src/daemon/modules/query_info.zig:75`, `src/daemon/server.zig:21703`, `src/daemon/server.zig:21735`, `src/proto/lusers.zig:61`, `src/proto/lusers.zig:85`

## USERS

- Syntax: `USERS`
- Description: Lists registered local users or reports no users.
- Privileges: Registered client.
- Parameters: None.
- Replies: `RPL_USERSSTART 392`, `RPL_USERS 393`, `RPL_ENDOFUSERS 394`, or `RPL_NOUSERS 395`.
- Errors: None specific.
- Example: `USERS`
- Sources: `src/daemon/modules/query_info.zig:76`, `src/daemon/server.zig:28418`, `src/daemon/server.zig:28420`

## LINKS

- Syntax: `LINKS`
- Description: Lists this server and each distinct established Undertow S2S peer as a one-hop neighbour, using each peer's handshake-gossiped description when available.
- Privileges: Registered client.
- Parameters: None.
- Replies: `RPL_LINKS 364`, `RPL_ENDOFLINKS 365`.
- Errors: None specific.
- Example: `LINKS`
- Sources: `src/daemon/modules/query_info.zig:77`, `src/daemon/server.zig:28438`, `src/daemon/server.zig:28446`, `src/daemon/server.zig:28469`

## MAP

- Syntax: `MAP`
- Description: Returns a compact Undertow mesh topology: this server with its local user count and each published established peer as a child row.
- Privileges: Registered client.
- Parameters: None.
- Replies: `RPL_MAP 015`, `RPL_MAPEND 017`.
- Errors: None specific.
- Example: `MAP`
- Sources: `src/daemon/modules/query_info.zig:78`, `src/daemon/server.zig:28606`, `src/daemon/server.zig:28614`, `src/daemon/server.zig:28625`

## HELP

- Syntax: `HELP [topic]`
- Description: Returns the static help topic for `topic`, or the HELP index when no topic is supplied.
- Privileges: Registered client.
- Parameters: Optional topic name.
- Replies: `RPL_HELPSTART 704`, `RPL_HELPTXT 705`, `RPL_ENDOFHELP 706`.
- Errors: `ERR_HELPNOTFOUND 524` for unknown topics.
- Example: `HELP JOIN`
- Sources: `src/daemon/modules/user_query.zig:87`, `src/daemon/server.zig:21682`, `src/proto/help_db.zig:24`, `src/proto/help_db.zig:103`, `src/proto/help_db.zig:171`

## HELPOP

- Syntax: `HELPOP [topic]`
- Description: Alias path for HELP topic lookup using the same static topic database and reply numerics.
- Privileges: Registered client.
- Parameters: Optional topic name.
- Replies: Same as `HELP`.
- Errors: Same as `HELP`.
- Example: `HELPOP OPER`
- Sources: `src/daemon/modules/user_query.zig:88`, `src/daemon/server.zig:21682`, `src/proto/help_db.zig:103`

## STATS

- Syntax: `STATS <letter>`
- Description: Returns selected server stats by letter. Implemented letters are `u` uptime, `o` configured oper bindings, `k/K` Warden mask wards, `d/D` Warden address wards, `y/Y` connection classes, `l/L` established S2S peer links, `z/Z` runtime debug counters, `p/P` online operators, `c/C` configured mesh connect blocks, `i/I` connection-class allow blocks, and `m/M` command usage counters. Unknown letters currently emit only the end marker.
- Privileges: Registered client. `STATS p` is available to registered non-opers; every other implemented letter requires oper inside the handler.
- Parameters: One stats letter.
- Replies: `RPL_STATSUPTIME 242`, `RPL_STATSOLINE 243`, `RPL_STATSKLINE 216`, `RPL_STATSDLINE 225`, `RPL_STATSYLINE 218`, `RPL_STATSLLINE 211`, `RPL_STATSDEBUG 249`, `RPL_STATSCLINE 213`, `RPL_STATSILINE 215`, `RPL_STATSCOMMANDS 212`, terminated by `RPL_ENDOFSTATS 219`.
- Notes: `STATS Y` emits one `RPL_STATSYLINE 218` row per connection class as `Y <class>`, with trailing text containing `sendq`, `recvq`, `max_clients`, `max_per_ip`, `max_per_account`, `max_per_host`, `max_chan`, `max_targets`, `monitor`, `silence`, `ping`, `ping_timeout`, `reg_timeout`, `flood`, `require_tls`, `require_sasl`, `flood_exempt`, `nick_delay_exempt`, match summary fields `cidrs`, `tls_only`, `account_only`, `oper_only`, and `live` member count. `STATS l` emits one `RPL_STATSLLINE 211` row per established S2S peer link with `sendq_cap`, queued bytes, and `uptime` seconds.
- Errors: `ERR_NEEDMOREPARAMS 461`; `ERR_NOPRIVILEGES 481` when a non-oper requests any letter except `p`.
- Example: `STATS u`
- Sources: `src/daemon/modules/oper_security.zig:173`, `src/daemon/server.zig:14052`, `src/daemon/server.zig:14063`, `src/daemon/server.zig:14069`, `src/daemon/server.zig:14206`

## TRACE

- Syntax: `TRACE`
- Description: Oper-only trace of registered local clients, one user row per client and an end row.
- Privileges: Oper (`.access = .oper`).
- Parameters: None.
- Replies: `RPL_TRACEUSER 205`, `RPL_ENDOFTRACE 262`.
- Errors: `ERR_NOPRIVILEGES 481`.
- Example: `TRACE`
- Sources: `src/daemon/modules/oper_security.zig:171`, `src/daemon/server.zig:17063`, `src/daemon/server.zig:17075`

## ETRACE

- Syntax: `ETRACE`
- Description: Oper-only extended trace, emitting local users with class, nick, user, visible host, real host, account, and realname.
- Privileges: Oper (`.access = .oper`).
- Parameters: None.
- Replies: Numeric `709` rows, then `RPL_ENDOFTRACE 262`.
- Errors: `ERR_NOPRIVILEGES 481`.
- Example: `ETRACE`
- Sources: `src/daemon/modules/oper_security.zig:172`, `src/daemon/server.zig:17130`, `src/daemon/server.zig:17154`

## MODULES

- Syntax: `MODULES`
- Description: Lists loaded registry modules with command/cap/hook counts and total command count.
- Privileges: Oper enforced inside handler.
- Parameters: None.
- Replies: `RPL_INFOSTART 373`, `RPL_INFO 371`, `RPL_ENDOFINFO 374`.
- Errors: `ERR_NOPRIVILEGES 481`.
- Example: `MODULES`
- Sources: `src/daemon/modules/introspect.zig:19`, `src/daemon/modules/introspect.zig:26`, `src/daemon/modules/introspect.zig:214`

## MODLIST

- Syntax: `MODLIST`
- Description: Alias of `MODULES`.
- Privileges: Oper enforced inside handler.
- Parameters: None.
- Replies: Same as `MODULES`.
- Errors: `ERR_NOPRIVILEGES 481`.
- Example: `MODLIST`
- Sources: `src/daemon/modules/introspect.zig:19`, `src/daemon/modules/introspect.zig:26`, `src/daemon/modules/introspect.zig:215`

## COMMANDS

- Syntax: `COMMANDS [name]`
- Description: With no argument, lists command names available to the caller after access and feature gates. With a name, shows module id, access, feature gate, minimum params, availability, and summary.
- Privileges: Any client (`.access = .any`).
- Parameters: Optional command name.
- Replies: `RPL_INFOSTART 373`, `RPL_INFO 371`, `RPL_ENDOFINFO 374`.
- Errors: None specific; unknown detail query ends with `No such command`.
- Example: `COMMANDS MESH`
- Sources: `src/daemon/modules/introspect.zig:44`, `src/daemon/modules/introspect.zig:55`, `src/daemon/modules/introspect.zig:80`, `src/daemon/modules/introspect.zig:216`

## OROWASM

- Syntax: `OROWASM [STATUS|ABI|WIT|PLUGINS]`
- Description: Oper-only runtime introspection for the OroWasm app-platform host. `STATUS` reports loaded plugin counts, command/hook registrations, allowed host capabilities, allowed privileged intents, configured registry pins, signed registry pins, revoked plugin hashes, disabled-plugin kill-switch entries, blocked load attempts, plugin directory, and resource budgets. `ABI` reports the manifest schema, hostcall table, intent table, and minimum registry trust tier for each hostcall/intent. `WIT` streams the canonical OroWasm ABI v1 WIT descriptor embedded from `src/wasm/host/orowasm-abi-v1.wit` through `src/wasm/host/abi.zig`, so opers can verify the live daemon's guest contract without reading local files. `PLUGINS` lists each loaded plugin handle with trust tier, whether its registry pin was publisher-signed, command/hook counts, granted capabilities, and granted intents.
- Privileges: Oper (`.access = .oper`).
- Parameters: Optional view name; defaults to `STATUS`.
- Replies: `RPL_INFOSTART 373`, `RPL_INFO 371`, `RPL_ENDOFINFO 374`.
- Errors: `ERR_NOPRIVILEGES 481` for non-opers.
- Example: `OROWASM WIT`
- Sources: `src/daemon/modules/introspect.zig:100`, `src/daemon/modules/introspect.zig:113`, `src/daemon/modules/introspect.zig:139`, `src/daemon/modules/introspect.zig:170`, `src/daemon/modules/introspect.zig:182`, `src/daemon/modules/introspect.zig:217`, `src/wasm/host/abi.zig:27`, `src/wasm/host/bridge.zig:36`
