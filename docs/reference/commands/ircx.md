# IRCX commands

*IRCX discovery, typed messaging, properties, access lists, events, named modes, and extended listing.*

The IRCX module registers the discovery, typed-messaging, property, access, event, mode, and list commands (`src/daemon/modules/ircx.zig:56`). `CREATE` lives in [channels.md](channels.md#create).

## IRCX

- Syntax: `IRCX`
- Description: Enables IRCX mode on the session and reports IRCX support. It also works before registration, through the pre-registration path.
- Privileges: Registered client or pre-registration client.
- Parameters: None.
- Replies: `RPL_IRCX 800` with state, version, live SASL package list (`PLAIN,SCRAM-SHA-256,EXTERNAL`), max message size, and option list.
- Errors: None specific.
- Example: `IRCX`
- Sources: `src/daemon/server.zig:3331`, `src/daemon/modules/ircx.zig:48`, `src/daemon/server.zig:7698`

## ISIRCX

- Syntax: `ISIRCX`
- Description: Queries IRCX support without changing the session's IRCX enabled state. It also works before registration.
- Privileges: Registered client or pre-registration client.
- Parameters: None.
- Replies: `RPL_IRCX 800`.
- Errors: None specific.
- Example: `ISIRCX`
- Sources: `src/daemon/server.zig:3335`, `src/daemon/modules/ircx.zig:49`, `src/daemon/server.zig:7698`

## AUTH

- Syntax: `AUTH <package> [mechanism/payload]` (repeat with the package-specific SASL exchange)
- Description: IRCX's SASL-backed authentication transport. The package name selects the same configured mechanisms exposed by IRCv3 SASL (`PLAIN`, `SCRAM-SHA-256`, and `EXTERNAL` in the IRCX discovery list); payloads are handled by the shared SASL router and account success gate. Use IRCv3 `AUTHENTICATE` when the client does not need IRCX framing. ANON, GateKeeper, and GateKeeperPassport answer with numeric 912 and stay outside the SASL mechanism list.
- Privileges: IRCX-enabled client; registration/account effects follow the selected SASL mechanism.
- Replies: `RPL_IRCXAUTH` challenge/success/failure lines and the normal account numerics on completion.
- Errors: Package parsing, SASL, TLS, and account lockout errors from the shared router; malformed exchanges fail closed.
- Example: `AUTH PLAIN AGFsaWNlAGNvcnJlY3QtaG9yc2U=`
- Sources: `src/daemon/modules/ircx.zig:68`, `src/daemon/server.zig:33452` (`handleIrcxAuth`), `src/proto/ircx.zig`, `src/proto/sasl_mechrouter.zig`

## DATA

- Syntax: `DATA <target> <tag> :<message>`
- Description: Sends an IRCX typed message to a nick or channel. Tags must match `[A-Za-z][A-Za-z0-9.]{0,14}`. `SYS`/`ADM` prefixes require oper; `OWN`/`HST` require channel operator/host authority or oper. A remote SYS or ADM tag stays closed for every sender, including an operator account.
- Privileges: Registered client, with reserved tag restrictions.
- Parameters: Target nick/channel, tag, message.
- Replies: Relayed `DATA` line to target(s).
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_BADTAG 904`, `ERR_NOACCESS 913`, `ERR_NOTONCHANNEL 442`, `ERR_NOSUCHNICK 401`.
- Example: `DATA #zig app.status :green`
- Sources: `src/daemon/modules/ircx.zig:50`, `src/daemon/server.zig:7716`

## REQUEST

- Syntax: `REQUEST <target> <tag> :<message>`
- Description: Same handler and validation as `DATA`, but preserves the command verb in the relayed line.
- Privileges: Same as `DATA`.
- Parameters: Same as `DATA`.
- Replies: Relayed `REQUEST` line.
- Errors: Same as `DATA`.
- Example: `REQUEST alice app.ping :hello`
- Sources: `src/daemon/modules/ircx.zig:51`, `src/daemon/server.zig:7721`

## REPLY

- Syntax: `REPLY <target> <tag> :<message>`
- Description: Same handler and validation as `DATA`, but preserves the command verb in the relayed line.
- Privileges: Same as `DATA`.
- Parameters: Same as `DATA`.
- Replies: Relayed `REPLY` line.
- Errors: Same as `DATA`.
- Example: `REPLY alice app.ping :pong`
- Sources: `src/daemon/modules/ircx.zig:52`, `src/daemon/server.zig:7721`

## WHISPER

- Syntax: `WHISPER <#channel> <nick[,nick...]> :<text>`
- Description: Sends a channel-scoped private message to listed recipients only if sender and recipients are on the channel. Channel `+w` nowhisper blocks it.
- Privileges: Registered channel member.
- Parameters: Channel, recipient list, text.
- Replies: `WHISPER` lines to valid recipients.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOSUCHCHANNEL 403`, `ERR_NOTONCHANNEL 442`, `ERR_NOWHISPER 923`, `ERR_NOSUCHNICK 401`, `ERR_USERNOTINCHANNEL 441`.
- Example: `WHISPER #zig alice,bob :private aside`
- Sources: `src/daemon/modules/ircx.zig:53`, `src/daemon/server.zig:7772`

## PROP

- Syntax: `PROP <entity> [<key[,key...]> [:<value>]]`
- Description: IRCX property list/get/set/delete. One parameter lists all; two gets keys; three sets a value, and an empty trailing value deletes. Built-in channel properties such as `NAME`, `OID`, `CREATION`, `MEMBERCOUNT`, `MEMBERLIMIT`, and write-through `MEMBERKEY`/`MEMBERLIMIT` reflect live channel state. Policy properties including `history-policy`, AI consent flags (`no-ai`, `local-only`, `server-ai-ok`), and `encryption-policy` persist through the ordinary signed PROP store; `encryption-policy=required` rejects plaintext channel messages unless they carry the negotiated `+onyx/e2ee` client tag.
- Privileges: Registered client; writes require channel operator/owner, user self-ownership, or oper.
- Parameters: Entity, optional key list, optional value.
- Replies: `RPL_PROPLIST 818`, `RPL_PROPEND 819`; mode broadcasts for linked built-ins.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOACCESS 913`, `ERR_BADVALUE 906`.
- Example: `PROP #zig MEMBERCOUNT`
- Sources: `src/daemon/modules/ircx.zig:54`, `src/daemon/server.zig:7610`

## ACCESS

- Syntax: `ACCESS <#channel> <ADD|DELETE|LIST|CLEAR> [level [mask [timeout] [:reason]]]`
- Description: IRCX per-channel access list for `FOUNDER`, `OWNER`, `HOST`, `VOICE`, `DENY`, and `GRANT` levels. `ADD` accepts an optional numeric timeout before the optional reason; the timeout is stored and rendered in list entries. Management requires channel authority or oper. Successful add/delete/clear mutations are recorded in the ProofMark audit ring and published on the operator Event Spine with `proof=<id>` when the daemon has a signing identity.
- Privileges: Registered client with channel management access, or oper.
- Parameters: Channel, subcommand, optional level/mask selector, optional timeout, optional reason.
- Replies: `RPL_ACCESSADD 801`, `RPL_ACCESSDELETE 802`, `RPL_ACCESSSTART 803`, `RPL_ACCESSENTRY 804`, `RPL_ACCESSEND 805`.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_CHANOPRIVSNEEDED 482`, `ERR_NOPRIVILEGES 481`.
- Example: `ACCESS #zig ADD HOST *!*@trusted.example 0 :trusted`
- Sources: `src/daemon/modules/ircx.zig:66`, `src/proto/ircx_access_store.zig:79`, `src/proto/ircx_access_store.zig:119`, `src/proto/ircx_access_store.zig:419`, `src/daemon/server.zig:19492`

## EVENT

- Syntax: `EVENT <ADD|DEL|LIST|BROADCAST|OBSERVE|SEVERITY|REPLAY|STATS> ...`
- Description: Event Spine control. `ADD`/`DEL` manage the caller's oper event
  category mask, `LIST` renders subscriptions, `BROADCAST` sends an oper
  announcement, `OBSERVE` manages standing operator observation filters, and
  `SEVERITY`/`REPLAY`/`STATS` tune or inspect the operator feed. A standing
  `OBSERVE` mask matches lifecycle records (connect, quit, nick, oper-up)
  network-wide: an event raised on any mesh node fans out to every node,
  rendered with the originating server name, so an operator sees matching
  subjects regardless of which node they are on. `EVENT REPLAY JSON` streams
  structured history records and `EVENT STATS JSON` returns a stable counters
  object plus an `operator_surfaces` capability map for operator UIs. WALLOPS
  functionality rides `EVENT BROADCAST`; it is not a `+w` user-mode path.
- Privileges: Oper checked inside handler.
- Parameters: Subcommand; categories or observe arguments as needed.
- Replies: Raw `EVENT LIST` lines, raw Event Spine observe/broadcast `EVENT` lines, and server notices.
- Errors: `ERR_NOPRIVILEGES 481`, `ERR_NEEDMOREPARAMS 461`.
- Example: `EVENT BROADCAST :network maintenance`
- Sources: `src/daemon/modules/ircx.zig:56`, `src/daemon/server.zig:6543`, `src/daemon/server.zig:6645`

## MODEX

- Syntax: `MODEX <#channel> [named-mode changes...]`
- Description: IRCX named-mode front-end. With no changes, lists active named modes. With changes, translates names to mode letters and delegates to the normal `MODE` engine.
- Privileges: Registered client; actual mutations inherit `MODE` gates.
- Parameters: Channel and optional named mode changes.
- Replies: `RPL_MODEXLIST 806`, `RPL_MODEXEND 807`, or normal `MODE` replies/broadcasts.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOSUCHCHANNEL 403`, plus delegated `MODE` errors.
- Example: `MODEX #zig +AUTHONLY`
- Sources: `src/daemon/modules/ircx.zig:57`, `src/daemon/server.zig:6470`

## LISTX

- Syntax: `LISTX [filter]`
- Description: IRCX extended channel list. Secret and hidden channels are skipped. Filters use live channel metadata including creation time, topic time, subject/language properties, member count, and registered state; member-count filters and `C`/`T` age filters accept strict `>`/`<` and inclusive `>=`/`<=`. The handler lists the mesh-wide union of local and remote-only channels, caps oversized result sets with `RPL_LISTXTRUNC 816`, and emits `RPL_LISTXPICS 813` after an entry when the channel has a non-empty `PICS` property. A remote-only channel's 812 entry carries the topic the peer published.
- Privileges: Registered client.
- Parameters: Optional LISTX filter.
- Replies: IRCX list start/entry/PICS/truncation/end numerics `811`, `812`, `813`, `816`, `817`.
- Errors: `ERR_NEEDMOREPARAMS 461` for invalid filters.
- Example: `LISTX >=10,C<=3600000`
- Sources: `src/daemon/modules/ircx.zig:71`, `src/proto/listx.zig:73`, `src/proto/listx.zig:236`, `src/proto/listx.zig:242`, `src/proto/listx.zig:251`, `src/proto/listx.zig:420`, `src/daemon/server.zig:12920`
