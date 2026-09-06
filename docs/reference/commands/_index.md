# Command reference

*The complete client command surface of the Onyx Server daemon, sourced from the live dispatch path.*

Onyx Server is a pure-Zig 0.17-dev clean-room IRC daemon, built from first principles — not a clone of any prior daemon. This reference documents only the current registered-client source surface: the `dispatchRegistered` path (`src/daemon/server.zig:14267`), the lower connection command table it falls back to (`src/daemon/dispatch.zig:1795`), and the enabled `SerpentRegistry` modules (`src/daemon/modules/manifest.zig:23`).

Registry commands default to registered-client access unless the command table sets `.access = .any` or `.access = .oper` (`src/daemon/registry.zig:51`, `src/daemon/registry.zig:830`). Registry dispatch maps too few parameters to `ERR_NEEDMOREPARAMS 461`, denied oper commands to `ERR_NOPRIVILEGES 481`, denied registered commands to `ERR_NOTREGISTERED 451`, and disabled feature-gated commands to `ERR_UNKNOWNCOMMAND 421` (`src/daemon/server.zig:14389`). Numeric names and codes are verified against `src/proto/numeric.zig` and the server-local enum (`src/daemon/server.zig:1403`).

Last reconciled **2026-09-06** against the enabled module manifest and command registry. Compatibility aliases are listed individually below even when they share one handler or reference page.

| Command | Summary | Reference |
|---|---|---|
| `PASS` | Pre-registration password marker; after registration returns reregister error. | [connection.md](connection.md#pass) |
| `NICK` | Set registration nick or change registered nick. | [connection.md](connection.md#nick) |
| `USER` | Pre-registration username and realname. | [connection.md](connection.md#user) |
| `CAP` | IRCv3 capability negotiation. | [connection.md](connection.md#cap) |
| `AUTHENTICATE` | SASL PLAIN, EXTERNAL, or SCRAM-SHA-256 exchange. | [connection.md](connection.md#authenticate) |
| `PING` | Server heartbeat request; replies with `PONG`. | [connection.md](connection.md#ping) |
| `PONG` | No-op heartbeat acknowledgement. | [connection.md](connection.md#pong) |
| `QUIT` | Close the registered or pre-registered session. | [connection.md](connection.md#quit) |
| `PRIVMSG` | Send text to a nick or channel. | [messaging.md](messaging.md#privmsg) |
| `NOTICE` | Send no-error text to a nick or channel. | [messaging.md](messaging.md#notice) |
| `TAGMSG` | Send IRCv3 tag-only messages. | [messaging.md](messaging.md#tagmsg) |
| `REDACT` | Redact a known message id. | [messaging.md](messaging.md#redact) |
| `CHATHISTORY` | Query channel history batches. | [messaging.md](messaging.md#chathistory) |
| `MARKREAD` | Set bouncer read markers. | [messaging.md](messaging.md#markread) |
| `PINS` | List or edit pinned message ids through the channel PROP spine. | [messaging.md](messaging.md#pins) |
| `METADATA` | IRCv3 metadata get/list/set/delete. | [messaging.md](messaging.md#metadata) |
| `MONITOR` | Track online/offline nicks. | [messaging.md](messaging.md#monitor) |
| `SILENCE` | Manage caller-side sender masks. | [messaging.md](messaging.md#silence) |
| `ACCEPT` | Manage caller-id allow list. | [messaging.md](messaging.md#accept) |
| `JOIN` | Join one or more channels. | [channels.md](channels.md#join) |
| `PART` | Leave one or more channels. | [channels.md](channels.md#part) |
| `NAMES` | List channel members. | [channels.md](channels.md#names) |
| `MODE` | Query/set user or channel modes. | [channels.md](channels.md#mode) |
| `KICK` | Remove a channel member. | [channels.md](channels.md#kick) |
| `INVITE` | Invite a nick to a channel. | [channels.md](channels.md#invite) |
| `TOPIC` | Query or set channel topic. | [channels.md](channels.md#topic) |
| `KNOCK` | Request entry to a channel. | [channels.md](channels.md#knock) |
| `CREATE` | IRCX create-or-join channel. | [channels.md](channels.md#create) |
| `RENAME` | Rename a channel. | [channels.md](channels.md#rename) |
| `CHANNEL AKICK` | Registered-channel auto-kick list (services-managed). | [channels.md](channels.md#akick) |
| `CLEAR` | Mass-kick below a keep rank. | [channels.md](channels.md#clear) |
| `TEMPMODE` | Schedule or cancel temporary channel modes. | [channels.md](channels.md#tempmode) |
| `SEEN` | Show an account's last-seen/login history. | [accounts-services.md](accounts-services.md#seen) |
| `ISON` | Return online subset of nick list. | [queries.md](queries.md#ison) |
| `USERHOST` | Return user/host tuples for nicks. | [queries.md](queries.md#userhost) |
| `WHOIS` | Return local WHOIS sequence. | [queries.md](queries.md#whois) |
| `LIST` | List visible channels. | [queries.md](queries.md#list) |
| `WHO` | Return WHO or WHOX rows. | [queries.md](queries.md#who) |
| `WHOX` | Alias for WHOX-style field-selected WHO rows. | [queries.md](queries.md#who) |
| `WHOWAS` | Query WHOWAS history. | [queries.md](queries.md#whowas) |
| `AWAY` | Set or clear away state. | [queries.md](queries.md#away) |
| `SETNAME` | Change realname and notify capable peers. | [queries.md](queries.md#setname) |
| `HELP` | Return built-in help text. | [queries.md](queries.md#help) |
| `HELPOP` | Alias of `HELP`. | [queries.md](queries.md#helpop) |
| `AUTOJOIN` | Manage account autojoin list. | [queries.md](queries.md#autojoin) |
| `GROUP` | Account grouping query/management handler. | [queries.md](queries.md#group) |
| `WELCOME` | Replay welcome text. | [queries.md](queries.md#welcome) |
| `SUMMON` | Oper force-join for a target user and channel. | [queries.md](queries.md#summon) |
| `VERSION` | Show server version. | [informational.md](informational.md#version) |
| `TIME` | Show server time. | [informational.md](informational.md#time) |
| `ADMIN` | Show configured admin contact. | [informational.md](informational.md#admin) |
| `INFO` | Show implementation and runtime info. | [informational.md](informational.md#info) |
| `MOTD` | Show configured MOTD. | [informational.md](informational.md#motd) |
| `LUSERS` | Show local/global user summary. | [informational.md](informational.md#lusers) |
| `USERS` | Show registered users. | [informational.md](informational.md#users) |
| `STATS` | Show uptime, class, S2S, ban, oper, or debug stats; `z` is oper-only inside handler. | [informational.md](informational.md#stats) |
| `TRACE` | Oper trace of local users. | [informational.md](informational.md#trace) |
| `ETRACE` | Oper extended trace rows. | [informational.md](informational.md#etrace) |
| `MODULES` | Oper registry module inventory. | [informational.md](informational.md#modules) |
| `MODLIST` | Alias of `MODULES`. | [informational.md](informational.md#modlist) |
| `COMMANDS` | Discover command registry entries. | [informational.md](informational.md#commands) |
| `OROWASM` | Inspect OroWasm ABI, budgets, and loaded plugins. | [informational.md](informational.md#orowasm) |
| `OPER` | Disabled password OPER; use SASL account elevation. | [oper-moderation.md](oper-moderation.md#oper) |
| `REHASH` | Reload configuration. | [oper-moderation.md](oper-moderation.md#rehash) |
| `GRANT` | Grant a registered account operator authority network-wide. | [oper-moderation.md](oper-moderation.md#grant) |
| `REVOKE` | Revoke a runtime operator grant network-wide. | [oper-moderation.md](oper-moderation.md#revoke) |
| `GRANTS` | List live runtime operator grants. | [oper-moderation.md](oper-moderation.md#grants) |
| `AUDIT` | Inspect privileged-action audit records and ProofMark evidence. | [oper-moderation.md](oper-moderation.md#audit) |
| `KILL` | Disconnect a user. | [oper-moderation.md](oper-moderation.md#kill) |
| `CLOSE` | Close unknown/unregistered clients. | [oper-moderation.md](oper-moderation.md#close) |
| `DRAIN` | Toggle listener drain state. | [oper-moderation.md](oper-moderation.md#drain) |
| `UNREJECT` | Clear an IP reject throttle. | [oper-moderation.md](oper-moderation.md#unreject) |
| `WARD` | Unified Warden ban registry. | [oper-moderation.md](oper-moderation.md#ward) |
| `SHUN` | Mark a user as gagged. | [oper-moderation.md](oper-moderation.md#shun) |
| `UNSHUN` | Clear a user gag. | [oper-moderation.md](oper-moderation.md#unshun) |
| `GLOBAL` | Send global notice. | [oper-moderation.md](oper-moderation.md#global) |
| `OPERMOTD` | Show or set operator MOTD. | [oper-moderation.md](oper-moderation.md#opermotd) |
| `DIE` | Stop the server. | [oper-moderation.md](oper-moderation.md#die) |
| `RESTART` | Stop through restart privilege path. | [oper-moderation.md](oper-moderation.md#restart) |
| `CONNECT` | Open outbound S2S link. | [oper-moderation.md](oper-moderation.md#connect) |
| `SQUIT` | Tear down S2S link. | [oper-moderation.md](oper-moderation.md#squit) |
| `TESTLINE` | Probe Warden match. | [oper-moderation.md](oper-moderation.md#testline) |
| `TESTMASK` | Count clients matching hostmask. | [oper-moderation.md](oper-moderation.md#testmask) |
| `USERIP` | Show nick IP-style data. | [oper-moderation.md](oper-moderation.md#userip) |
| `DEBUG` | Dump flight recorder. | [oper-moderation.md](oper-moderation.md#debug) |
| `GEOIP` | Oper MaxMind lookup. | [oper-moderation.md](oper-moderation.md#geoip) |
| `CLONES` | Oper clone cluster report. | [oper-moderation.md](oper-moderation.md#clones) |
| `RESV` | Reserve channel-name glob. | [oper-moderation.md](oper-moderation.md#resv) |
| `UNRESV` | Remove channel reservation. | [oper-moderation.md](oper-moderation.md#unresv) |
| `FORCEOP` | Force channel op. | [oper-moderation.md](oper-moderation.md#forceop) |
| `FORCEDEOP` | Force channel deop. | [oper-moderation.md](oper-moderation.md#forcedeop) |
| `FORCEJOIN` | Force a user to join. | [oper-moderation.md](oper-moderation.md#forcejoin) |
| `FORCEPART` | Force a user to part. | [oper-moderation.md](oper-moderation.md#forcepart) |
| `FORCETOPIC` | Force channel topic. | [oper-moderation.md](oper-moderation.md#forcetopic) |
| `MESH` | Mesh peer report, log, grants, quorum summary. | [mesh-ops.md](mesh-ops.md#mesh) |
| `NETSTAT` | Alias of `MESH`. | [mesh-ops.md](mesh-ops.md#netstat) |
| `ROUTE` | Mesh route report. | [mesh-ops.md](mesh-ops.md#route) |
| `NETHEALTH` | Mesh liveness report. | [mesh-ops.md](mesh-ops.md#nethealth) |
| `LINKS` | Mesh peer links. | [mesh-ops.md](mesh-ops.md#links) |
| `MAP` | Mesh topology map. | [mesh-ops.md](mesh-ops.md#map) |
| `UPGRADE` | Helix hot in-place upgrade. | [mesh-ops.md](mesh-ops.md#upgrade) |
| `REGISTER` | Register an account and log in. | [accounts-services.md](accounts-services.md#register) |
| `VERIFY` | Verify account email token. | [accounts-services.md](accounts-services.md#verify) |
| `IDENTIFY` | Log in to account. | [accounts-services.md](accounts-services.md#identify) |
| `LOGOUT` | Log out account and revoke derived oper. | [accounts-services.md](accounts-services.md#logout) |
| `DROP` | Delete account by password. | [accounts-services.md](accounts-services.md#drop) |
| `ACCOUNTINFO` | Show account flags. | [accounts-services.md](accounts-services.md#accountinfo) |
| `SASLINFO` | Show SASL mechanisms and current auth state. | [accounts-services.md](accounts-services.md#saslinfo) |
| `ACCOUNTSET` | Set account email or flags. | [accounts-services.md](accounts-services.md#accountset) |
| `GHOST` | Disconnect stale nick after account password check. | [accounts-services.md](accounts-services.md#ghost) |
| `CHANNEL` | Real server channel services command. | [accounts-services.md](accounts-services.md#channel) |
| `CS` | Alias of `CHANNEL`. | [accounts-services.md](accounts-services.md#cs) |
| `SESSION` | List, token, or resume account sessions. | [accounts-services.md](accounts-services.md#session) |
| `CERTADD` | Bind TLS client certificate fingerprint. | [accounts-services.md](accounts-services.md#certadd) |
| `CERTLIST` | List bound TLS client certificate fingerprints. | [accounts-services.md](accounts-services.md#certlist) |
| `CERTDEL` | Remove a bound TLS client certificate fingerprint. | [accounts-services.md](accounts-services.md#certdel) |
| `KEYTRANS` | Inspect account credential transparency roots and proofs. | [accounts-services.md](accounts-services.md#keytrans) |
| `E2EEKEY` | Manage public account E2EE device-key advertisements. | [accounts-services.md](accounts-services.md#e2eekey) |
| `IDENTITY` | Manage portable self-signed account identity keys. | [accounts-services.md](accounts-services.md#identity) |
| `MEMO` | Offline account messages. | [accounts-services.md](accounts-services.md#memo) |
| `VHOST` | Vhost wardrobe, requests, offers, and oper set. | [accounts-services.md](accounts-services.md#vhost) |
| `PRIVS` | Show oper class and privileges. | [accounts-services.md](accounts-services.md#privs) |
| `FILTER` | Oper content filter list/add/delete. | [accounts-services.md](accounts-services.md#filter) |
| `IRCX` | Enable/report IRCX mode. | [ircx.md](ircx.md#ircx) |
| `ISIRCX` | Report IRCX support. | [ircx.md](ircx.md#isircx) |
| `DATA` | IRCX typed directed message. | [ircx.md](ircx.md#data) |
| `REQUEST` | Alias family of `DATA`. | [ircx.md](ircx.md#request) |
| `REPLY` | Alias family of `DATA`. | [ircx.md](ircx.md#reply) |
| `WHISPER` | IRCX channel-scoped private message. | [ircx.md](ircx.md#whisper) |
| `PROP` | IRCX property get/list/set/delete. | [ircx.md](ircx.md#prop) |
| `ACCESS` | IRCX channel access list. | [ircx.md](ircx.md#access) |
| `EVENT` | Event Spine subscriptions and broadcast. | [ircx.md](ircx.md#event) |
| `MODEX` | IRCX named-mode front-end. | [ircx.md](ircx.md#modex) |
| `LISTX` | IRCX extended channel list. | [ircx.md](ircx.md#listx) |
| `MEDIA` | Media control plane. | [media.md](media.md#media) |
| `ACTIVITY` | Activity/presence updates. | [media.md](media.md#activity) |

### Commands added or split out in the 0.7 registry reconciliation

| Command | Summary | Reference |
|---|---|---|
| `ACCOUNT` | Operator account lifecycle flags (`SUSPEND`, `UNSUSPEND`, `FORBID`, `UNFORBID`, `NOEXPIRE`, `INFO`). | [accounts-services.md](accounts-services.md#account) |
| `AUTH` | IRCX SASL-backed package exchange. | [ircx.md](ircx.md#auth) |
| `CHANBADWORDS` | Durable per-channel substring filter. | [channels.md](channels.md#chanbadwords) |
| `CHANSTATS` | Channel `TOPUSERS`, `WORDS`, `ACTIVITY`, and `RECORD` views. | [informational.md](informational.md#chanstats) |
| `DIRECTORY` | Public discovery-directory summary. | [informational.md](informational.md#directory) |
| `DLINE` | Warden address-ban compatibility alias. | [oper-moderation.md](oper-moderation.md#kline--dline--xline) |
| `E2EEGROUP` | Bounded opaque group-E2EE control relay. | [accounts-services.md](accounts-services.md#e2eegroup) |
| `EDIT` | Message edit operation (already documented in messaging). | [messaging.md](messaging.md#edit) |
| `JUPE` | Mesh server-name quarantine. | [oper-moderation.md](oper-moderation.md#jupe) |
| `KLINE` | Warden hostmask-ban compatibility alias. | [oper-moderation.md](oper-moderation.md#kline--dline--xline) |
| `LISTCHANS` | Registered channels where the caller has access. | [accounts-services.md](accounts-services.md#listchans) |
| `RECOGNIZE` | Account host-recognition list (`ADD`, `DEL`, `LIST`). | [accounts-services.md](accounts-services.md#recognize) |
| `RECOVER` | Reclaim a protected registered nick. | [accounts-services.md](accounts-services.md#recover) |
| `RECOVERYCODES` | Single-use offline account recovery codes. | [accounts-services.md](accounts-services.md#recoverycodes) |
| `RELEASE` | Release a held registered nick. | [accounts-services.md](accounts-services.md#release) |
| `RESETPASS` | Email-code password reset. | [accounts-services.md](accounts-services.md#resetpass) |
| `SEARCH` | Search retained message history (already documented in messaging). | [messaging.md](messaging.md#search) |
| `SESSIONS` | Oper filtered connection inventory. | [oper-moderation.md](oper-moderation.md#sessions) |
| `SACCESS` | Operator server-access deny/gag/grant/hold rules. | [oper-moderation.md](oper-moderation.md#saccess) |
| `SESSIONTOKEN` | TLS account-authentication token issuance. | [accounts-services.md](accounts-services.md#sessiontoken) |
| `SETPASS` | Change or certificate-recover an account password. | [accounts-services.md](accounts-services.md#setpass) |
| `SPAMTRAP` | Operator spam-trap registry. | [oper-moderation.md](oper-moderation.md#spamtrap) |
| `SUCCESSOR` | Registered-channel founder successor. | [accounts-services.md](accounts-services.md#successor) |
| `TOTP` | Account two-factor enrollment and status. | [accounts-services.md](accounts-services.md#totp) |
| `UNJUPE` | Remove a mesh server-name quarantine. | [oper-moderation.md](oper-moderation.md#unjupe) |
| `WEBHOOK` | Discord-compatible incoming webhook bindings. | [accounts-services.md](accounts-services.md#webhook) |
| `WEBAUTHN` | Passkey registration, authentication, and management. | [accounts-services.md](accounts-services.md#webauthn) |
| `WEBPUSH` | Browser push subscription lifecycle. | [accounts-services.md](accounts-services.md#webpush) |
| `XLINE` | Warden realname-ban compatibility alias. | [oper-moderation.md](oper-moderation.md#kline--dline--xline) |

## In-channel fantasy commands

These are not registry commands. A channel `PRIVMSG` beginning with `!` can invoke the server's weather and news bot (`!weather`/`!w`/`!wx`, `!news`/`!n`, `!localnews`), which answers as a server `NOTICE`. See [fantasy-bot.md](fantasy-bot.md). The `!news` and `!localnews` commands require the channel mode `+W` (news-wire).
