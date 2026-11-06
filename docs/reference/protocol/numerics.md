# Onyx Server numeric replies

*The numeric reply codes Onyx Server emits, where each originates, and the message text clients receive.*

This reference documents current source only. The daemon-local live-handler enum is
`src/daemon/server.zig`; pre-registration dispatch uses its own enum at
`src/daemon/dispatch.zig`; shared protocol builders draw from
`src/proto/numeric.zig`, with duplicate-code checking at
`src/proto/numeric.zig`. Current enum sizes are 133 daemon-local codes, 20
pre-registration dispatch codes, and 226 shared protocol catalog codes.

## Source inventories

| Source | Scope | Evidence |
| --- | --- | --- |
| `src/daemon/server.zig` | Live daemon command handlers, daemon-local extension numerics, and the generic `queueNumeric` formatter. | `Numeric` enum at `src/daemon/server.zig`; `formatNumericCode` at `src/daemon/server.zig`; `queueNumeric` at `src/daemon/server.zig`; live 005 emitter at `src/daemon/server.zig`. |
| `src/daemon/dispatch.zig` | Pre-registration command dispatch, welcome burst, CAP/SASL registration numerics, and PING/PONG pre-registration errors. | `Numeric` enum at `src/daemon/dispatch.zig`; SASL success at `src/daemon/dispatch.zig`; welcome burst at `src/daemon/dispatch.zig`; generic errors at `src/daemon/dispatch.zig`. |
| `src/proto/numeric.zig` | Shared protocol numeric catalog used by helper builders such as WHOIS, WHO, LIST, LUSERS, MOTD, TIME, VERSION, and ADMIN. | `Numeric` enum at `src/proto/numeric.zig`; derived table at `src/proto/numeric.zig`; duplicate check at `src/proto/numeric.zig`. |

## Connection registration and SASL

| Value | Name | When emitted | Message text | Evidence |
| ---: | --- | --- | --- | --- |
| 001 | `RPL_WELCOME` | Registration completes. | Dynamic welcome naming the network, nick, and mask. | `src/daemon/dispatch.zig`, `src/proto/numeric.zig` |
| 002 | `RPL_YOURHOST` | Registration welcome burst. | Dynamic host/node/version text. | `src/daemon/dispatch.zig`, `src/proto/numeric.zig` |
| 003 | `RPL_CREATED` | Registration welcome burst. | `This node has been weaving the mesh since ...` | `src/daemon/dispatch.zig`, `src/proto/numeric.zig` |
| 004 | `RPL_MYINFO` | Registration welcome burst. | Server/version/user-mode/channel-mode parameters. | `src/daemon/dispatch.zig`, `src/proto/numeric.zig` |
| 005 | `RPL_ISUPPORT` | Registration burst and `VERSION` support refresh. | `are supported by this server` | `src/daemon/dispatch.zig`, `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 409 | `ERR_NOORIGIN` | Bare pre-registration `PING` or `PONG`. | `No origin specified` | `src/daemon/dispatch.zig`, `src/proto/numeric.zig` |
| 410 | `ERR_INVALIDCAPCMD` | Invalid CAP subcommand before registration. | `Invalid CAP command` | `src/daemon/dispatch.zig`, `src/proto/numeric.zig` |
| 421 | `ERR_UNKNOWNCOMMAND` | Unknown or disabled command. | `Unknown command`, `Command disabled by configuration`, or handler-specific text. | `src/daemon/dispatch.zig`, `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 432 | `ERR_ERRONEUSNICKNAME` | Invalid, reserved, blocked, or too-long nick. | `Erroneous nickname` or dynamic reservation/SACCESS reason. | `src/daemon/dispatch.zig`, `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 451 | `ERR_NOTREGISTERED` | Command requires completed registration. | `You have not registered` | `src/daemon/dispatch.zig`, `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 461 | `ERR_NEEDMOREPARAMS` | Generic arity/usage failure across handlers. | Usually `Not enough parameters`; handlers also emit command-specific usage strings. | `src/daemon/dispatch.zig`, `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 462 | `ERR_ALREADYREGISTRED` | PASS/USER/AUTHENTICATE after registration or duplicate registration attempt. | `You may not reregister` | `src/daemon/dispatch.zig`, `src/proto/numeric.zig` |
| 900 | `RPL_LOGGEDIN` | SASL exchange succeeds. | `You are now logged in` | `src/daemon/dispatch.zig`, `src/proto/numeric.zig` |
| 901 | `RPL_LOGGEDOUT` | SASL abort of an authenticated re-auth, or live `LOGOUT` of an authenticated session. | `You are now logged out` | `src/daemon/dispatch.zig`, `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 903 | `RPL_SASLSUCCESS` | SASL exchange succeeds after `RPL_LOGGEDIN`. | `SASL authentication successful` | `src/daemon/dispatch.zig`, `src/proto/numeric.zig` |
| 904 | `ERR_SASLFAIL` | SASL not negotiated, unsupported mechanism, verifier failure, or router failure. | `SASL authentication failed`; `Unsupported SASL mechanism` | `src/daemon/dispatch.zig`, `src/proto/numeric.zig` |
| 905 | `ERR_SASLTOOLONG` | SASL payload exceeds the configured decode limit. | `SASL message too long` | `src/daemon/dispatch.zig`, `src/proto/numeric.zig` |
| 906 | `ERR_SASLABORTED` | Client sends `AUTHENTICATE *` or the SASL router reports abort. | `SASL authentication aborted` | `src/daemon/dispatch.zig`, `src/proto/numeric.zig` |
| 907 | `ERR_SASLALREADY` | AUTHENTICATE is attempted while already registered/authenticated. | `You have already authenticated using SASL` | `src/daemon/dispatch.zig`, `src/proto/numeric.zig` |
| 908 | `RPL_SASLMECHS` | Unsupported SASL mechanism, before final 904 failure. | `are available SASL mechanisms` | `src/daemon/dispatch.zig`, `src/proto/numeric.zig` |

Note: the daemon-local IRCX enum also names 900, 903, 904, 905, 906, 907,
and 908 for IRCX-era meanings (`src/daemon/server.zig` through
`src/daemon/server.zig`). The dispatcher entries above are the SASL
meanings emitted during registration.

## Operator, server, mesh, and information queries

| Value | Name | When emitted | Message text | Evidence |
| ---: | --- | --- | --- | --- |
| 015 | `RPL_MAP` | `/MAP` renders local node and peer topology. | Dynamic map detail. | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 017 | `RPL_MAPEND` | Terminates `/MAP`. | `End of /MAP` | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 204 | `RPL_TRACEOPERATOR` | `SESSIONS` row for an operator. | Dynamic TRACE operator row. | `src/daemon/svc_sessionview.zig`, `src/proto/numeric.zig` |
| 205 | `RPL_TRACEUSER` | `TRACE` or `SESSIONS` row for a user. | Dynamic TRACE user row. | `src/daemon/server.zig`, `src/daemon/svc_sessionview.zig`, `src/proto/numeric.zig` |
| 211 | `RPL_STATSLLINE` | `/STATS l` established S2S peer links. | Dynamic peer-link detail. | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 212 | `RPL_STATSCOMMANDS` | `/STATS m` command usage counters. | Command and count params. | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 213 | `RPL_STATSCLINE` | `/STATS c` configured mesh connect blocks. | Connect-block params. | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 215 | `RPL_STATSILINE` | `/STATS i` allow/connection-class blocks. | Allow-block params and criteria. | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 216 | `RPL_STATSKLINE` | `/STATS k` Warden mask wards. | Ward match/action/reason. | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 218 | `RPL_STATSYLINE` | `/STATS Y` connection-class rows. | Dynamic class policy and live member count. | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 219 | `RPL_ENDOFSTATS` | Terminates `/STATS`. | `End of /STATS report` | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 225 | `RPL_STATSDLINE` | `/STATS d` Warden address wards. | Ward match/action/reason. | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 242 | `RPL_STATSUPTIME` | `/STATS u`. | Dynamic uptime text. | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 243 | `RPL_STATSOLINE` | `/STATS o` configured oper bindings. | Empty trailing; params carry binding. | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 249 | `RPL_STATSDEBUG` | `/STATS z` runtime counters or `/STATS p` online operators. | Dynamic counter/operator line. | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 250 | `RPL_STATSCONN` | `LUSERS` tail reports peak and total connection counts. | `Highest connection count: ...` | `src/proto/lusers.zig` |
| 251 | `RPL_LUSERCLIENT` | `LUSERS` network user/server counts. | `There are ... users and ... invisible on ... servers` | `src/daemon/server.zig`, `src/proto/lusers.zig` |
| 252 | `RPL_LUSEROP` | `LUSERS` operator count. | `IRC Operators online` | `src/proto/lusers.zig` |
| 253 | `RPL_LUSERUNKNOWN` | `LUSERS` unknown connection count. | `unknown connection(s)` | `src/proto/lusers.zig` |
| 254 | `RPL_LUSERCHANNELS` | `LUSERS` channel count. | `channels formed` | `src/proto/lusers.zig` |
| 255 | `RPL_LUSERME` | `LUSERS` local client/server count. | `I have ... clients and ... servers` | `src/proto/lusers.zig` |
| 256 | `RPL_ADMINME` | `ADMIN` mandatory first line. | Admin reply server line. | `src/daemon/server.zig`, `src/proto/serverinfo.zig`, `src/proto/numeric.zig` |
| 257 | `RPL_ADMINLOC1` | `ADMIN` configured location line. | Configured location text. | `src/daemon/server.zig`, `src/proto/serverinfo.zig`, `src/proto/numeric.zig` |
| 259 | `RPL_ADMINEMAIL` | `ADMIN` configured email/contact line. | Configured contact text. | `src/daemon/server.zig`, `src/proto/serverinfo.zig`, `src/proto/numeric.zig` |
| 262 | `RPL_ENDOFTRACE` | Terminates `TRACE` and `SESSIONS`. | `End of TRACE` | `src/daemon/server.zig`, `src/proto/trace.zig`, `src/proto/numeric.zig` |
| 265 | `RPL_LOCALUSERS` | `LUSERS` local user totals. | `Current local users ..., max ...` | `src/proto/lusers.zig`, `src/proto/numeric.zig` |
| 266 | `RPL_GLOBALUSERS` | `LUSERS` mesh-wide user totals. | `Current global users ..., max ...` | `src/proto/lusers.zig`, `src/proto/numeric.zig` |
| 270 | `RPL_PRIVS` | Oper privilege/class query. | Dynamic privilege list. | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 351 | `RPL_VERSION` | `VERSION`. | Version/build/branding, reply server, and description. | `src/daemon/server.zig`, `src/proto/serverinfo.zig`, `src/proto/numeric.zig` |
| 364 | `RPL_LINKS` | `/LINKS` lists local server and one-hop mesh neighbours. | Dynamic link detail. | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 365 | `RPL_ENDOFLINKS` | Terminates `/LINKS`. | `End of /LINKS list` | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 371 | `RPL_INFO` | `INFO` and `DIRECTORY` body lines. | Static and dynamic server/directory text. | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 373 | `RPL_INFOSTART` | Starts `INFO` or `DIRECTORY`. | Server name or directory label. | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 374 | `RPL_ENDOFINFO` | Terminates `INFO`, `DIRECTORY`, and OROWASM introspection replies. | `End of /INFO list`, `End of /DIRECTORY`, or command-specific terminator. | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 375 | `RPL_MOTDSTART` | Starts `MOTD`. | `- <server> Message of the Day -` | `src/daemon/server.zig`, `src/proto/motd.zig`, `src/proto/numeric.zig` |
| 372 | `RPL_MOTD` | `MOTD` body line. | One unfolded MOTD line. | `src/daemon/server.zig`, `src/proto/motd.zig`, `src/proto/numeric.zig` |
| 376 | `RPL_ENDOFMOTD` | Terminates `MOTD`. | `End of /MOTD command.` | `src/daemon/server.zig`, `src/proto/motd.zig`, `src/proto/numeric.zig` |
| 381 | `RPL_YOUREOPER` | Oper status granted through operator auth/binding. | `You are now an IRC operator` | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 382 | `RPL_REHASHING` | `/REHASH` status and reload outcome. | `No config file; nothing to reload`; `No I/O available; cannot reload`; dynamic reload note. | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 391 | `RPL_TIME` | `TIME`. | Current wall-clock server time. | `src/daemon/server.zig`, `src/proto/serverinfo.zig`, `src/proto/numeric.zig` |
| 392 | `RPL_USERSSTART` | Starts `USERS`. | `UserID   Terminal  Host` | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 393 | `RPL_USERS` | `USERS` row. | Dynamic local user row. | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 394 | `RPL_ENDOFUSERS` | Terminates `USERS`. | `End of users` | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 395 | `RPL_NOUSERS` | `USERS` has no rows. | `Nobody logged in` | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 481 | `ERR_NOPRIVILEGES` | Operator-only command or plugin capability failure. | `Permission Denied- You're not an IRC operator`; other handler-specific privilege text. | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 491 | `ERR_NOOPERHOST` | Legacy `OPER` command is disabled. | `OPER is disabled; authenticate via SASL (operator status is granted on login)` | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 704 | `RPL_HELPSTART` | Starts a `HELP`/`HELPOP` topic. | First help topic line. | `src/daemon/server.zig`, `src/proto/help_db.zig` |
| 705 | `RPL_HELPTXT` | Middle `HELP`/`HELPOP` topic lines. | Help topic body line. | `src/proto/help_db.zig` |
| 706 | `RPL_ENDOFHELP` | Terminates a `HELP`/`HELPOP` topic. | `End of /HELP.` | `src/proto/help_db.zig` |
| 709 | `RPL_ETRACE` | `ETRACE` row. | Extended local user trace row. | `src/daemon/server.zig`, `src/proto/trace.zig` |

## User lookup, WHO, WHOIS, and visibility

| Value | Name | When emitted | Message text | Evidence |
| ---: | --- | --- | --- | --- |
| 276 | `RPL_WHOISCERTFP` | WHOIS target authenticated with a TLS client certificate; local, or remote when propagated over a secured oper-info link and requester may see it. | `has client certificate fingerprint ...` | `src/daemon/whois.zig`, `src/proto/numeric.zig` |
| 301 | `RPL_AWAY` | PRIVMSG to an away user and WHOIS target away state. | Target away message. | `src/daemon/server.zig`, `src/daemon/whois.zig`, `src/proto/numeric.zig` |
| 302 | `RPL_USERHOST` | `USERHOST <nick>...`. | Userhost target list. | `src/daemon/server.zig`, `src/proto/ison_userhost.zig`, `src/proto/numeric.zig` |
| 303 | `RPL_ISON` | `ISON <nick>...`. | Online nick subset. | `src/daemon/server.zig`, `src/proto/ison_userhost.zig`, `src/proto/numeric.zig` |
| 311 | `RPL_WHOISUSER` | WHOIS subject identity. | Nick, user, host, and realname. | `src/daemon/whois.zig`, `src/proto/numeric.zig` |
| 312 | `RPL_WHOISSERVER` | WHOIS subject server. | Server and server description. | `src/daemon/whois.zig`, `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 313 | `RPL_WHOISOPERATOR` | WHOIS target is an operator/admin and not hidden from the requester. | Operator/admin/title text. | `src/daemon/whois.zig`, `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 315 | `RPL_ENDOFWHO` | Terminates WHO/WHOX, including hidden-channel fail-closed responses. | `End of /WHO list` | `src/daemon/server.zig`, `src/proto/who.zig`, `src/proto/numeric.zig` |
| 317 | `RPL_WHOISIDLE` | WHOIS target idle/signon for local users. | Idle seconds and signon time. | `src/daemon/whois.zig`, `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 318 | `RPL_ENDOFWHOIS` | Terminates WHOIS, including failed lookups after 401. | `End of /WHOIS list` | `src/daemon/whois.zig`, `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 319 | `RPL_WHOISCHANNELS` | WHOIS visible channel memberships. | Channel list, folded as needed. | `src/daemon/whois.zig`, `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 320 | `RPL_WHOISSPECIAL` | WHOIS GeoIP/ASN/rDNS special text and public message-restriction hints for target `+R` or `+g`. | Geo/rDNS text, `is only accepting private messages from registered users`, or `is only accepting private messages from users on its accept list`. | `src/daemon/whois.zig`, `src/daemon/server.zig` |
| 330 | `RPL_WHOISLOGGEDIN` | WHOIS target account is known. | Logged-in account line. | `src/daemon/whois.zig`, `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 335 | `RPL_WHOISBOT` | WHOIS target has bot mode. | Bot marker line. | `src/daemon/whois.zig`, `src/proto/numeric.zig` |
| 338 | `RPL_WHOISACTUALLY` | WHOIS target real host/IP is visible to requester. | Actual host/IP. | `src/daemon/whois.zig`, `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 352 | `RPL_WHOREPLY` | Plain WHO matching row. | Channel/nick/user/host/server/flags/realname row. | `src/daemon/server.zig`, `src/proto/who.zig`, `src/proto/numeric.zig` |
| 354 | `RPL_WHOSPCRPL` | WHOX matching row. | Requested WHOX fields. | `src/daemon/server.zig`, `src/proto/whox.zig`, `src/proto/numeric.zig` |
| 671 | `RPL_WHOISSECURE` | WHOIS target is connected over TLS. | Secure-connection text, with cipher when known and `[kTLS: TX]`, `[kTLS: RX]`, or `[kTLS: TX+RX]` when those kernel directions are actually attached. | `src/daemon/whois.zig`, `src/daemon/server.zig`, `src/proto/numeric.zig` |

Hidden secret/private channels now fail closed in both roster paths: a non-member
receives a bare `RPL_ENDOFNAMES` 366 for `NAMES #chan` and no 353 rows
(`src/daemon/server.zig`; regression test
`src/daemon/server.zig`), and a bare `RPL_ENDOFWHO` 315 for `WHO`/WHOX with
no 352/354 rows (`src/daemon/server.zig`;
regression test `src/daemon/server.zig`).

WHOIS `RPL_WHOISSPECIAL` 320 is repeatable. Geo/rDNS 320s are oper/self-gated
(`src/daemon/server.zig`); public `+R` and
`+g` message-restriction hints are emitted for every requester, as are the `+G`
(common-channel), `+Z` (TLS-only private messages), and `+V` (no-invite)
restriction hints when they apply (`src/daemon/whois.zig`). The same numeric
also carries the modes line, connection-class line, oper/self `ban cloak`, and
the via-WebSocket line. Tests cover `+R`,
`+g`, ordering, and coexistence with GeoIP 320s at `src/daemon/whois.zig`, and
`src/daemon/whois.zig`.

## Channel membership, MODE, lists, and messaging

| Value | Name | When emitted | Message text | Evidence |
| ---: | --- | --- | --- | --- |
| 221 | `RPL_UMODEIS` | `MODE <own-nick>` query. | Current user mode string. | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 305 | `RPL_UNAWAY` | Bare AWAY clears away state. | `You are no longer marked as being away` | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 306 | `RPL_NOWAWAY` | AWAY with message sets away state. | `You have been marked as being away` | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 321 | `RPL_LISTSTART` | Starts `LIST`. | `Channel :Users Name` | `src/daemon/server.zig`, `src/proto/list.zig`, `src/proto/numeric.zig` |
| 322 | `RPL_LIST` | One visible `LIST` channel row. | Channel, user count, and topic. | `src/proto/list.zig`, `src/proto/numeric.zig` |
| 323 | `RPL_LISTEND` | Terminates `LIST`. | `End of LIST` | `src/proto/list.zig`, `src/proto/numeric.zig` |
| 324 | `RPL_CHANNELMODEIS` | `MODE #channel` query. | Empty trailing; params contain active modes and visible params. | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 329 | `RPL_CREATIONTIME` | `MODE #channel` query when creation time is known. | Empty trailing; params carry channel and timestamp. | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 331 | `RPL_NOTOPIC` | `TOPIC #channel` when no topic exists. | `No topic is set` | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 332 | `RPL_TOPIC` | `TOPIC #channel` query when a topic exists. | Current topic text. | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 333 | `RPL_TOPICWHOTIME` | `TOPIC #channel` query when topic setter/time are known. | Empty trailing; params carry setter and timestamp. | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 341 | `RPL_INVITING` | Successful `INVITE`. | Inviter numeric naming target nick and channel. | `src/daemon/server.zig`, `src/proto/invite.zig`, `src/proto/numeric.zig` |
| 342 | `RPL_SUMMONING` | `SUMMON` force-joins a target user. | `Summoned user to channel` | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 346 | `RPL_INVITELIST` | `MODE #channel I` list query. | Invite-exception mask row. | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 347 | `RPL_ENDOFINVITELIST` | Terminates `+I` list. | `End of channel invite exception list` | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 348 | `RPL_EXCEPTLIST` | `MODE #channel e` list query. | Ban-exception mask row. | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 349 | `RPL_ENDOFEXCEPTLIST` | Terminates `+e` list. | `End of channel exception list` | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 353 | `RPL_NAMREPLY` | NAMES/JOIN names burst. | Channel member list. | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 366 | `RPL_ENDOFNAMES` | Terminates NAMES/JOIN names burst, including bare hidden-channel terminators. | `End of /NAMES list` | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 367 | `RPL_BANLIST` | `MODE #channel b` list query. | Ban mask row. | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 368 | `RPL_ENDOFBANLIST` | Terminates `+b` list. | `End of channel ban list` | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 401 | `ERR_NOSUCHNICK` | Missing nick target across WHOIS/INVITE/KILL/WHISPER/message paths. | `No such nick`; WHOIS builder uses `No such nick/channel`. | `src/daemon/server.zig`, `src/daemon/whois.zig`, `src/proto/numeric.zig` |
| 402 | `ERR_NOSUCHSERVER` | Missing SQUIT/CONNECT target server. | `No such server` | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 403 | `ERR_NOSUCHCHANNEL` | Missing channel target across JOIN/PART/MODE/TOPIC/etc. | `No such channel` | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 404 | `ERR_CANNOTSENDTOCHAN` | Message blocked by `+n`, `+m`, `+M`, `+Z`, `+b`, or `+C`. | Handler-specific `Cannot send to channel (...)` text. | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 405 | `ERR_TOOMANYCHANNELS` | JOIN would exceed configured channel limit. | `You have joined too many channels` | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 407 | `ERR_TOOMANYTARGETS` | PRIVMSG/NOTICE exceeds `MAXTARGETS`. | `Too many recipients` | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 411 | `ERR_NORECIPIENT` | Empty/invalid PRIVMSG or NOTICE target list. | Handler-specific missing-recipient reason. | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 412 | `ERR_NOTEXTTOSEND` | PRIVMSG without text. | `No text to send` | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 425 | `ERR_NOOPERMOTD` | `OPERMOTD` requested while no operator MOTD is set. | `OPERMOTD is empty` | `src/daemon/server.zig`, `src/proto/oper_motd.zig` |
| 431 | `ERR_NONICKNAMEGIVEN` | NICK command without nickname. | `No nickname given` | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 433 | `ERR_NICKNAMEINUSE` | NICK collision. | `Nickname is already in use` | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 437 | `ERR_UNAVAILRESOURCE` | Reserved channel/nick resource blocks JOIN or requested nick is held by nick delay. | Dynamic reservation reason, or `Nick is held (nick delay); try again shortly`. | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 441 | `ERR_USERNOTINCHANNEL` | Target user is not on channel for MODE/KICK/WHISPER/etc. | `They aren't on that channel` | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 442 | `ERR_NOTONCHANNEL` | Acting client is not on the channel. | `You're not on that channel` | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 443 | `ERR_USERONCHANNEL` | INVITE target already joined. | `is already on channel` | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 445 | `ERR_SUMMONDISABLED` | Cataloged in daemon-local enum for disabled summon handling; no live server.zig emission currently found. | Disabled-summon text when wired. | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 464 | `ERR_PASSWDMISMATCH` | Account/service password failure or lockout. | `Invalid account or password` or dynamic lockout message. | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 470 | `ERR_LINKCHANNEL` | JOIN is redirected by a usable one-hop channel forward target. | `Forwarding to another channel` | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 471 | `ERR_CHANNELISFULL` | JOIN blocked by `+l`. | `Cannot join channel (+l)` | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 472 | `ERR_UNKNOWNMODE` | Unsupported mode letter or invalid TEMPMODE mode. | `is unknown mode char to me` or TEMPMODE-specific text. | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 473 | `ERR_INVITEONLYCHAN` | JOIN blocked by `+i`. | `Cannot join channel (+i)` | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 474 | `ERR_BANNEDFROMCHAN` | JOIN blocked by quarantine, AKICK, access deny, or `+b`. | `Cannot join channel (+b)` or dynamic reason. | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 475 | `ERR_BADCHANNELKEY` | JOIN blocked by `+k`. | `Cannot join channel (+k)` | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 476 | `ERR_BADCHANMASK` | Invalid channel/mask syntax in list/service paths. | `Invalid channel mask` or command-specific bad-channel text. | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 477 | `ERR_NEEDREGGEDNICK` | JOIN blocked by `+a`, or PM blocked by user `+R`. | `Cannot join channel (+a) - you must be authenticated`; `Cannot message this user (+R: identify to a registered account)` | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 478 | `ERR_BANLISTFULL` | Adding `+b`, `+e`, `+I`, or `+Z` exceeds `max_list_entries`. | `Channel list is full` | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 480 | `ERR_THROTTLE` | JOIN blocked by `+j` join throttle. | `Cannot join channel (+j) - join rate exceeded, try again shortly` | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 482 | `ERR_CHANOPRIVSNEEDED` | Operator-tier channel privilege required. | `You're not channel operator` plus handler-specific privilege text. | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 489 | `ERR_SECUREONLYCHAN` | JOIN blocked by channel `+S` over non-TLS session. | `Cannot join channel (+S) - TLS required` | `src/daemon/server.zig` |
| 502 | `ERR_USERSDONTMATCH` | User MODE target is not the caller. | `Cannot change mode for other users` | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 520 | `ERR_OPERONLYCHAN` | JOIN blocked by channel `+O` or `+A`. | `Cannot join channel (+O) - IRC operator required`; `Cannot join channel (+A) - server administrator required` | `src/daemon/server.zig` |
| 524 | `ERR_HELPNOTFOUND` | Unknown `HELP`/`HELPOP` topic. | `Help not found` | `src/proto/help_db.zig`, `src/proto/numeric.zig` |
| 531 | `ERR_NOCOMICDATA` | IRCX DATA blocked by channel `+V` comic-chat policy. | `Channel does not allow comic-chat DATA (+V)` | `src/daemon/server.zig`, `src/proto/numeric.zig` |

## Lists, monitor, silence, knock, metadata, and IRCX extensions

| Value | Name | When emitted | Message text | Evidence |
| ---: | --- | --- | --- | --- |
| 271 | `RPL_SILELIST` | `SILENCE` query row. | Mask row. | `src/daemon/server.zig` |
| 272 | `RPL_ENDOFSILELIST` | Terminates `SILENCE` query. | `End of SILENCE list` | `src/daemon/server.zig` |
| 281 | `RPL_ACCEPTLIST` | `ACCEPT` query row. | Accepted nick row. | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 282 | `RPL_ENDOFACCEPT` | Terminates `ACCEPT` query. | `End of /ACCEPT list` | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 710 | `RPL_KNOCK` | Delivered to channel operators when a KNOCK arrives. | Knock reason. | `src/daemon/server.zig` |
| 711 | `RPL_KNOCKDLVR` | Sent to the knocker after delivery. | `Your KNOCK has been delivered` | `src/daemon/server.zig` |
| 713 | `ERR_CHANOPEN` | KNOCK refused because channel is open. | `Channel is open` | `src/daemon/server.zig` |
| 714 | `ERR_KNOCKONCHAN` | KNOCK refused because caller is already joined. | `You are already on that channel` | `src/daemon/server.zig` |
| 716 | `ERR_CANTSENDTOUSER` | DM blocked by recipient usermode `+g`. | `is in +g mode (must be accepted)` | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 717 | `RPL_TARGNOTIFY` | Sender notification after `+g` DM block. | `has been informed that you messaged them` | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 718 | `RPL_UMODEGMSG` | One-shot notice to a `+g` recipient. | `is messaging you, and you have umode +g set. Use ACCEPT to allow` | `src/daemon/server.zig`, `src/proto/numeric.zig` |
| 720 | `RPL_OMOTDSTART` | Starts `OPERMOTD` when set. | Operator MOTD start text. | `src/daemon/server.zig`, `src/proto/oper_motd.zig` |
| 721 | `RPL_OMOTD` | `OPERMOTD` body line. | Operator MOTD text. | `src/daemon/server.zig`, `src/proto/oper_motd.zig` |
| 722 | `RPL_ENDOFOMOTD` | Terminates `OPERMOTD` when set. | `End of OPERMOTD` | `src/daemon/server.zig`, `src/proto/oper_motd.zig` |
| 725 | `RPL_TESTLINE` | `TESTLINE` matches a Warden ban/ward. | Dynamic ward result. | `src/daemon/server.zig` |
| 726 | `RPL_NOTESTLINE` | `TESTLINE` finds no matching ban. | `No matching ban found` | `src/daemon/server.zig` |
| 727 | `RPL_TESTMASK` | `TESTMASK` reports matching clients. | `clients match` | `src/daemon/server.zig` |
| 728 | `RPL_QUIETLIST` | `MODE #channel Z` quiet-list query row. | Quiet mask row. | `src/daemon/server.zig` |
| 729 | `RPL_ENDOFQUIETLIST` | Terminates quiet-list query. | `End of channel quiet list` | `src/daemon/server.zig` |
| 730 | `RPL_MONONLINE` | MONITOR online notification. | Monitor target list. | `src/daemon/server.zig` |
| 731 | `RPL_MONOFFLINE` | MONITOR offline notification. | Monitor target list. | `src/daemon/server.zig` |
| 732 | `RPL_MONLIST` | MONITOR list query. | Monitor target list. | `src/daemon/server.zig` |
| 733 | `RPL_ENDOFMONLIST` | Terminates MONITOR list query. | End marker. | `src/daemon/server.zig` |
| 734 | `ERR_MONLISTFULL` | MONITOR add exceeds limit. | Monitor limit failure. | `src/daemon/server.zig` |
| 761 | `RPL_KEYVALUE` | METADATA GET/LIST/SET/CLEAR value rows. | Metadata value or empty string. | `src/daemon/server.zig` |
| 762 | `RPL_METADATAEND` | Terminates METADATA command. | `end of metadata` | `src/daemon/server.zig` |
| 766 | `ERR_KEYNOTSET` | METADATA GET for absent key. | `key not set` | `src/daemon/server.zig` |
| 767 | `ERR_KEYINVALID` | METADATA key validation failure. | `invalid key` or `invalid visibility` | `src/daemon/server.zig` |
| 769 | `ERR_KEYNOPERMISSION` | METADATA SET/CLEAR without permission. | `permission denied` | `src/daemon/server.zig` |
| 800 | `RPL_IRCX` | `MODE ISIRCX` / IRCX discovery. | Trailing `*`; params include state, version, package list, and max message size. | `src/daemon/server.zig` |
| 811 | `RPL_LISTXSTART` | Starts IRCX `LISTX`. | `Channel Members CreatedMs TopicMs :Topic` | `src/daemon/server.zig`, `src/proto/listx.zig` |
| 812 | `RPL_LISTXENTRY` | One IRCX `LISTX` channel row. | Channel, members, creation time, topic time, and topic. | `src/daemon/server.zig`, `src/proto/listx.zig` |
| 813 | `RPL_LISTXPICS` | Optional IRCX `LISTX` PICS row after an entry. | Channel and PICS value. | `src/daemon/server.zig`, `src/proto/listx.zig` |
| 816 | `RPL_LISTXTRUNC` | IRCX `LISTX` result cap was hit. | `LISTX results truncated` | `src/daemon/server.zig`, `src/proto/listx.zig` |
| 817 | `RPL_LISTXEND` | Terminates IRCX `LISTX`. | `End of LISTX` | `src/daemon/server.zig`, `src/proto/listx.zig` |
| 818 | `RPL_PROPLIST` | IRCX `PROP` list/get row. | Property key/value row. | `src/daemon/server.zig`, `src/proto/ircx.zig`, `src/proto/ircx_prop_cmd.zig` |
| 819 | `RPL_PROPEND` | Terminates IRCX `PROP` list/get. | PROP terminator. | `src/daemon/server.zig`, `src/proto/ircx.zig`, `src/proto/ircx_prop_cmd.zig` |
| 821 | `ERR_EVENTDUP` | IRCX EVENT add duplicate. | `Event already subscribed` | `src/daemon/server.zig` |
| 822 | `ERR_EVENTMIS` | IRCX EVENT change/delete without subscription. | `Not subscribed to event` | `src/daemon/server.zig` |
| 823 | `ERR_NOSUCHEVENT` | IRCX EVENT unknown event/category. | `No such event` or `No such event category` | `src/daemon/server.zig` |
| 825 | `RPL_EVENTCHANGE` | IRCX EVENT subscription changed. | `Event updated` | `src/daemon/server.zig` |
| 826 | `RPL_MODEXLIST` | IRCX MODEX query row. | Target and named mode list. | `src/daemon/server.zig`, `src/proto/ircx_modex.zig` |
| 827 | `RPL_MODEXEND` | Terminates IRCX MODEX query. | `End of modes` | `src/daemon/server.zig`, `src/proto/ircx_modex.zig` |
| 904 | `ERR_BADTAG` | IRCX DATA invalid tag. | `Invalid DATA tag` | `src/daemon/server.zig` |
| 906 | `ERR_BADVALUE` | IRCX PROP/PINS invalid property value. | `Invalid property value` | `src/daemon/server.zig` |
| 913 | `ERR_NOACCESS` | IRCX PROP/DATA access denied. | `Insufficient access to set property`; `Cannot set that property`; DATA reserved-tag denials. | `src/daemon/server.zig` |
| 916 | `ERR_TOOMANYACCESSES` | SACCESS add exceeds capacity. | `Cannot add SACCESS entry` | `src/daemon/server.zig` |
| 923 | `ERR_NOWHISPER` | WHISPER blocked by IRCX NOWHISPER (`+w`). | `Channel does not allow whispers (+w)` | `src/daemon/server.zig` |
| 926 | `ERR_CHANNELEXIST` | IRCX CREATE target already exists. | `Channel already exists` | `src/daemon/server.zig` |

IRCX EVENT replies use `RPL_EVENTADD` 806, `RPL_EVENTDELETE` 807,
`RPL_EVENTSTART` 808, `RPL_EVENTLIST` 809, and `RPL_EVENTEND` 810 in the
daemon-local enum (`src/daemon/server.zig` through
`src/daemon/server.zig`) and live EVENT handler
(`src/daemon/server.zig`). The shared protocol catalog still carries an
older EVENTADD/EVENTDELETE numbering (`src/proto/numeric.zig` through
`src/proto/numeric.zig`); live server behavior follows `src/daemon/server.zig`.

## Cataloged but not currently emitted by `server.zig`

The daemon-local enum includes residual IRCX 9xx numerics that stay inert until a
handler emits them: `ERR_BADCOMMAND` 900, `ERR_BADLEVEL` 903,
`ERR_BADPROPERTY` 905, `ERR_RESOURCE` 907, `ERR_SECURITY` 908,
`ERR_UNKNOWNPACKAGE` 912, `ERR_DUPACCESS` 914, `ERR_MISACCESS` 915,
`ERR_NOSUCHOBJECT` 924, `ERR_NOTSUPPORTED` 925, and
`ERR_ALREADYONCHANNEL` 927 (`src/daemon/server.zig`).

The shared protocol enum is broader than the live daemon emission set. It
catalogs additional 0xx, 2xx, 3xx, 4xx, 5xx, 6xx, and SASL/account numerics
including TRACE variants, WHOWAS variants, `RPL_WHOISHELPOP`,
`RPL_WHOISCOUNTRY`, `RPL_WHOISHOST`, `ERR_UMODEUNKNOWNFLAG`, `ERR_DISABLED`,
`ERR_INVALIDKEY`, and `ERR_NICKLOCKED` (`src/proto/numeric.zig`). Do not treat a
catalog entry as live behavior unless a handler citation above or a future
handler emission exists.

## Standard replies: FAIL, WARN

Standard replies are not numeric replies. They are line types carrying a
severity token, a command token, a reply-code token, optional context params, and
a trailing description.

| Token | Builder / emitter | Shape | Current uses | Evidence |
| --- | --- | --- | --- | --- |
| `FAIL` | `standard_replies.fail`, `standard_replies_emit.fail`, and `LinuxServer.failReply`. | `FAIL <command> <code> [context...] :<description>` | CHATHISTORY parse failures, invalid UTF-8, content filter, multiline failures, media/service failures. | `src/proto/standard_replies.zig`, `src/proto/standard_replies_emit.zig`, `src/daemon/server.zig` |
| `WARN` | `standard_replies.warn` / `standard_replies_emit.warn`. | `WARN <command> <code> [context...] :<description>` | Cataloged builder support; no live `server.zig` emission found in current source. | `src/proto/standard_replies.zig`, `src/proto/standard_replies_emit.zig` |

The shared standard-replies catalog currently contains these code tokens:
`ACCOUNT_ALREADY_EXISTS`, `ACCOUNT_REQUIRED`, `ALREADY_AUTHENTICATED`,
`ALREADY_REGISTERED`, `AUTHENTICATION_FAILED`, `BAD_ACCOUNT_NAME`,
`BAD_CHANNEL_NAME`, `BAD_PASSWORD`, `BAD_TARGET`, `BANNED_FROM_CHANNEL`,
`CANNOT_SEND_TO_CHANNEL`, `CHANNEL_DISABLED`, `CHANNEL_DOES_NOT_EXIST`,
`CHANNEL_FULL`, `CHANNEL_RENAMED`, `CHANNEL_REQUIRED`, `COMMAND_DISABLED`,
`COMMAND_RATE_LIMITED`, `EXPIRED_TOKEN`, `HOST_REQUIRED`,
`INVALID_ACCOUNT_NAME`, `INVALID_CREDENTIALS`, `INVALID_KEY`, `INVALID_MODE`,
`INVALID_PARAMS`, `INVALID_PROPERTY`, `INVALID_TARGET`, `INVALID_TOKEN`,
`LIST_EMPTY`, `MESSAGE_RATE_LIMITED`, `MESSAGE_TOO_LONG`,
`METADATA_LIMIT_REACHED`, `MONITOR_LIMIT_REACHED`, `NEED_MORE_PARAMS`,
`NETWORK_ERROR`, `NICK_LOCKED`, `NO_MATCHING_KEY`, `NOT_AUTHENTICATED`,
`NOT_CHANNEL_OPERATOR`, `NOT_ON_CHANNEL`, `NOT_REGISTERED`,
`PERMISSION_DENIED`, `PRIVILEGES_REQUIRED`, `PROPERTY_REQUIRED`,
`REGISTRATION_IS_DISABLED`, `SILENTLY_DROPPED`, `TARGET_REQUIRED`,
`TOKEN_REQUIRED`, `TOO_MANY_CHANNELS`, `TOO_MANY_MATCHES`,
`TOO_MANY_MONITOR_TARGETS`, `UNKNOWN_COMMAND`, `UNKNOWN_ERROR`,
`UNKNOWN_PROPERTY`, and `UNSUPPORTED_MEDIA_TYPE`
(`src/proto/standard_replies.zig`).
