# Onyx Server numeric replies

*The numeric reply codes Onyx Server emits, where each originates, and the message text clients receive.*

This reference documents current source only. The daemon-local live-handler enum is
`src/daemon/server.zig:1057`; pre-registration dispatch uses its own enum at
`src/daemon/dispatch.zig:156`; shared protocol builders draw from
`src/proto/numeric.zig:12`, with duplicate-code checking at
`src/proto/numeric.zig:257`. Current enum sizes are 133 daemon-local codes, 20
pre-registration dispatch codes, and 226 shared protocol catalog codes.

## Source inventories

| Source | Scope | Evidence |
| --- | --- | --- |
| `src/daemon/server.zig` | Live daemon command handlers, daemon-local extension numerics, and the generic `queueNumeric` formatter. | `Numeric` enum at `src/daemon/server.zig:1057`; `formatNumericCode` at `src/daemon/server.zig:1201`; `queueNumeric` at `src/daemon/server.zig:30906`; live 005 emitter at `src/daemon/server.zig:21972`. |
| `src/daemon/dispatch.zig` | Pre-registration command dispatch, welcome burst, CAP/SASL registration numerics, and PING/PONG pre-registration errors. | `Numeric` enum at `src/daemon/dispatch.zig:156`; SASL success at `src/daemon/dispatch.zig:1940`; welcome burst at `src/daemon/dispatch.zig:2076`; generic errors at `src/daemon/dispatch.zig:2200`. |
| `src/proto/numeric.zig` | Shared protocol numeric catalog used by helper builders such as WHOIS, WHO, LIST, LUSERS, MOTD, TIME, VERSION, and ADMIN. | `Numeric` enum at `src/proto/numeric.zig:12`; derived table at `src/proto/numeric.zig:254`; duplicate check at `src/proto/numeric.zig:257`. |

## Connection registration and SASL

| Value | Name | When emitted | Message text | Evidence |
| ---: | --- | --- | --- | --- |
| 001 | `RPL_WELCOME` | Registration completes. | Dynamic welcome naming the network, nick, and mask. | `src/daemon/dispatch.zig:157`, `src/daemon/dispatch.zig:2076`, `src/proto/numeric.zig:13` |
| 002 | `RPL_YOURHOST` | Registration welcome burst. | Dynamic host/node/version text. | `src/daemon/dispatch.zig:158`, `src/daemon/dispatch.zig:2083`, `src/proto/numeric.zig:14` |
| 003 | `RPL_CREATED` | Registration welcome burst. | `This node has been weaving the mesh since ...` | `src/daemon/dispatch.zig:159`, `src/daemon/dispatch.zig:2091`, `src/proto/numeric.zig:15` |
| 004 | `RPL_MYINFO` | Registration welcome burst. | Server/version/user-mode/channel-mode parameters. | `src/daemon/dispatch.zig:160`, `src/daemon/dispatch.zig:2093`, `src/proto/numeric.zig:16` |
| 005 | `RPL_ISUPPORT` | Registration burst and `VERSION` support refresh. | `are supported by this server` | `src/daemon/dispatch.zig:161`, `src/daemon/dispatch.zig:2099`, `src/daemon/server.zig:1058`, `src/daemon/server.zig:21972`, `src/proto/numeric.zig:17` |
| 409 | `ERR_NOORIGIN` | Bare pre-registration `PING` or `PONG`. | `No origin specified` | `src/daemon/dispatch.zig:162`, `src/daemon/dispatch.zig:2032`, `src/daemon/dispatch.zig:2043`, `src/proto/numeric.zig:158` |
| 410 | `ERR_INVALIDCAPCMD` | Invalid CAP subcommand before registration. | `Invalid CAP command` | `src/daemon/dispatch.zig:163`, `src/daemon/dispatch.zig:1786`, `src/proto/numeric.zig:159` |
| 421 | `ERR_UNKNOWNCOMMAND` | Unknown or disabled command. | `Unknown command`, `Command disabled by configuration`, or handler-specific text. | `src/daemon/dispatch.zig:164`, `src/daemon/dispatch.zig:2200`, `src/daemon/server.zig:1170`, `src/daemon/server.zig:8423`, `src/proto/numeric.zig:166` |
| 432 | `ERR_ERRONEUSNICKNAME` | Invalid, reserved, blocked, or too-long nick. | `Erroneous nickname` or dynamic reservation/SACCESS reason. | `src/daemon/dispatch.zig:165`, `src/daemon/dispatch.zig:1738`, `src/daemon/server.zig:1172`, `src/daemon/server.zig:8527`, `src/proto/numeric.zig:171` |
| 451 | `ERR_NOTREGISTERED` | Command requires completed registration. | `You have not registered` | `src/daemon/dispatch.zig:166`, `src/daemon/dispatch.zig:1621`, `src/daemon/server.zig:1169`, `src/daemon/server.zig:8417`, `src/proto/numeric.zig:184` |
| 461 | `ERR_NEEDMOREPARAMS` | Generic arity/usage failure across handlers. | Usually `Not enough parameters`; handlers also emit command-specific usage strings. | `src/daemon/dispatch.zig:167`, `src/daemon/dispatch.zig:2208`, `src/daemon/server.zig:1177`, `src/daemon/server.zig:8411`, `src/proto/numeric.zig:188` |
| 462 | `ERR_ALREADYREGISTRED` | PASS/USER/AUTHENTICATE after registration or duplicate registration attempt. | `You may not reregister` | `src/daemon/dispatch.zig:168`, `src/daemon/dispatch.zig:1725`, `src/daemon/dispatch.zig:1757`, `src/proto/numeric.zig:189` |
| 900 | `RPL_LOGGEDIN` | SASL exchange succeeds. | `You are now logged in` | `src/daemon/dispatch.zig:169`, `src/daemon/dispatch.zig:1940`, `src/proto/numeric.zig:243` |
| 901 | `RPL_LOGGEDOUT` | SASL abort of an authenticated re-auth, or live `LOGOUT` of an authenticated session. | `You are now logged out` | `src/daemon/dispatch.zig:170`, `src/daemon/dispatch.zig:2010`, `src/daemon/server.zig:23112`, `src/daemon/server.zig:23122`, `src/proto/numeric.zig:244` |
| 903 | `RPL_SASLSUCCESS` | SASL exchange succeeds after `RPL_LOGGEDIN`. | `SASL authentication successful` | `src/daemon/dispatch.zig:171`, `src/daemon/dispatch.zig:1941`, `src/proto/numeric.zig:246` |
| 904 | `ERR_SASLFAIL` | SASL not negotiated, unsupported mechanism, verifier failure, or router failure. | `SASL authentication failed`; `Unsupported SASL mechanism` | `src/daemon/dispatch.zig:172`, `src/daemon/dispatch.zig:1809`, `src/daemon/dispatch.zig:1973`, `src/proto/numeric.zig:247` |
| 905 | `ERR_SASLTOOLONG` | SASL payload exceeds the configured decode limit. | `SASL message too long` | `src/daemon/dispatch.zig:173`, `src/daemon/dispatch.zig:1985`, `src/proto/numeric.zig:248` |
| 906 | `ERR_SASLABORTED` | Client sends `AUTHENTICATE *` or the SASL router reports abort. | `SASL authentication aborted` | `src/daemon/dispatch.zig:174`, `src/daemon/dispatch.zig:1823`, `src/daemon/dispatch.zig:2012`, `src/proto/numeric.zig:249` |
| 907 | `ERR_SASLALREADY` | AUTHENTICATE is attempted while already registered/authenticated. | `You have already authenticated using SASL` | `src/daemon/dispatch.zig:175`, `src/daemon/dispatch.zig:2015`, `src/proto/numeric.zig:250` |
| 908 | `RPL_SASLMECHS` | Unsupported SASL mechanism, before final 904 failure. | `are available SASL mechanisms` | `src/daemon/dispatch.zig:176`, `src/daemon/dispatch.zig:2019`, `src/daemon/dispatch.zig:2024`, `src/proto/numeric.zig:251` |

Note: the daemon-local IRCX enum also names 900, 903, 904, 905, 906, 907,
and 908 for IRCX-era meanings (`src/daemon/server.zig:1186` through
`src/daemon/server.zig:1190`). The dispatcher entries above are the SASL
meanings emitted during registration.

## Operator, server, mesh, and information queries

| Value | Name | When emitted | Message text | Evidence |
| ---: | --- | --- | --- | --- |
| 015 | `RPL_MAP` | `/MAP` renders local node and peer topology. | Dynamic map detail. | `src/daemon/server.zig:1059`, `src/daemon/server.zig:28576`, `src/daemon/server.zig:28583`, `src/proto/numeric.zig:21` |
| 017 | `RPL_MAPEND` | Terminates `/MAP`. | `End of /MAP` | `src/daemon/server.zig:1060`, `src/daemon/server.zig:28594`, `src/proto/numeric.zig:23` |
| 204 | `RPL_TRACEOPERATOR` | `SESSIONS` row for an operator. | Dynamic TRACE operator row. | `src/daemon/svc_sessionview.zig:31`, `src/daemon/svc_sessionview.zig:213`, `src/proto/numeric.zig:30` |
| 205 | `RPL_TRACEUSER` | `TRACE` or `SESSIONS` row for a user. | Dynamic TRACE user row. | `src/daemon/server.zig:17047`, `src/daemon/server.zig:17056`, `src/daemon/svc_sessionview.zig:32`, `src/proto/numeric.zig:31` |
| 211 | `RPL_STATSLLINE` | `/STATS l` established S2S peer links. | Dynamic peer-link detail. | `src/daemon/server.zig:1137`, `src/daemon/server.zig:14128`, `src/proto/numeric.zig:50` |
| 212 | `RPL_STATSCOMMANDS` | `/STATS m` command usage counters. | Command and count params. | `src/daemon/server.zig:1140`, `src/daemon/server.zig:14188`, `src/daemon/server.zig:14196`, `src/proto/numeric.zig:36` |
| 213 | `RPL_STATSCLINE` | `/STATS c` configured mesh connect blocks. | Connect-block params. | `src/daemon/server.zig:1138`, `src/daemon/server.zig:14158`, `src/daemon/server.zig:14165`, `src/proto/numeric.zig:37` |
| 215 | `RPL_STATSILINE` | `/STATS i` allow/connection-class blocks. | Allow-block params and criteria. | `src/daemon/server.zig:1139`, `src/daemon/server.zig:14173`, `src/daemon/server.zig:14183`, `src/proto/numeric.zig:39` |
| 216 | `RPL_STATSKLINE` | `/STATS k` Warden mask wards. | Ward match/action/reason. | `src/daemon/server.zig:1134`, `src/daemon/server.zig:14084`, `src/daemon/server.zig:21663`, `src/proto/numeric.zig:40` |
| 218 | `RPL_STATSYLINE` | `/STATS Y` connection-class rows. | Dynamic class policy and live member count. | `src/daemon/server.zig:1136`, `src/daemon/server.zig:14106`, `src/proto/numeric.zig:42` |
| 219 | `RPL_ENDOFSTATS` | Terminates `/STATS`. | `End of /STATS report` | `src/daemon/server.zig:1141`, `src/daemon/server.zig:14202`, `src/proto/numeric.zig:43` |
| 225 | `RPL_STATSDLINE` | `/STATS d` Warden address wards. | Ward match/action/reason. | `src/daemon/server.zig:1135`, `src/daemon/server.zig:14085`, `src/daemon/server.zig:21663`, `src/proto/numeric.zig:47` |
| 242 | `RPL_STATSUPTIME` | `/STATS u`. | Dynamic uptime text. | `src/daemon/server.zig:1132`, `src/daemon/server.zig:14074`, `src/proto/numeric.zig:51` |
| 243 | `RPL_STATSOLINE` | `/STATS o` configured oper bindings. | Empty trailing; params carry binding. | `src/daemon/server.zig:1133`, `src/daemon/server.zig:14077`, `src/daemon/server.zig:14080`, `src/proto/numeric.zig:52` |
| 249 | `RPL_STATSDEBUG` | `/STATS z` runtime counters or `/STATS p` online operators. | Dynamic counter/operator line. | `src/daemon/server.zig:1131`, `src/daemon/server.zig:14133`, `src/daemon/server.zig:14153`, `src/proto/numeric.zig:57` |
| 250 | `RPL_STATSCONN` | `LUSERS` tail reports peak and total connection counts. | `Highest connection count: ...` | `src/proto/lusers.zig:51`, `src/proto/lusers.zig:80`, `src/proto/lusers.zig:211` |
| 251 | `RPL_LUSERCLIENT` | `LUSERS` network user/server counts. | `There are ... users and ... invisible on ... servers` | `src/daemon/server.zig:21704`, `src/proto/lusers.zig:80`, `src/proto/lusers.zig:90` |
| 252 | `RPL_LUSEROP` | `LUSERS` operator count. | `IRC Operators online` | `src/proto/lusers.zig:81`, `src/proto/lusers.zig:117` |
| 253 | `RPL_LUSERUNKNOWN` | `LUSERS` unknown connection count. | `unknown connection(s)` | `src/proto/lusers.zig:82`, `src/proto/lusers.zig:140` |
| 254 | `RPL_LUSERCHANNELS` | `LUSERS` channel count. | `channels formed` | `src/proto/lusers.zig:83`, `src/proto/lusers.zig:163` |
| 255 | `RPL_LUSERME` | `LUSERS` local client/server count. | `I have ... clients and ... servers` | `src/proto/lusers.zig:84`, `src/proto/lusers.zig:186` |
| 256 | `RPL_ADMINME` | `ADMIN` mandatory first line. | Admin reply server line. | `src/daemon/server.zig:21941`, `src/proto/serverinfo.zig:177`, `src/proto/serverinfo.zig:220`, `src/proto/numeric.zig:64` |
| 257 | `RPL_ADMINLOC1` | `ADMIN` configured location line. | Configured location text. | `src/daemon/server.zig:21946`, `src/proto/serverinfo.zig:179`, `src/proto/serverinfo.zig:215`, `src/proto/numeric.zig:65` |
| 259 | `RPL_ADMINEMAIL` | `ADMIN` configured email/contact line. | Configured contact text. | `src/daemon/server.zig:21946`, `src/proto/serverinfo.zig:179`, `src/proto/serverinfo.zig:217`, `src/proto/numeric.zig:67` |
| 262 | `RPL_ENDOFTRACE` | Terminates `TRACE` and `SESSIONS`. | `End of TRACE` | `src/daemon/server.zig:17059`, `src/daemon/server.zig:17110`, `src/proto/trace.zig:208`, `src/proto/numeric.zig:69` |
| 265 | `RPL_LOCALUSERS` | `LUSERS` local user totals. | `Current local users ..., max ...` | `src/proto/lusers.zig:86`, `src/proto/lusers.zig:243`, `src/proto/numeric.zig:71` |
| 266 | `RPL_GLOBALUSERS` | `LUSERS` mesh-wide user totals. | `Current global users ..., max ...` | `src/proto/lusers.zig:87`, `src/proto/lusers.zig:271`, `src/proto/numeric.zig:72` |
| 270 | `RPL_PRIVS` | Oper privilege/class query. | Dynamic privilege list. | `src/daemon/server.zig:1061`, `src/daemon/server.zig:26948`, `src/daemon/server.zig:26984`, `src/proto/numeric.zig:73` |
| 351 | `RPL_VERSION` | `VERSION`. | Version/build/branding, reply server, and description. | `src/daemon/server.zig:21954`, `src/daemon/server.zig:21966`, `src/proto/serverinfo.zig:97`, `src/proto/numeric.zig:116` |
| 364 | `RPL_LINKS` | `/LINKS` lists local server and one-hop mesh neighbours. | Dynamic link detail. | `src/daemon/server.zig:1064`, `src/daemon/server.zig:28408`, `src/daemon/server.zig:28415`, `src/proto/numeric.zig:126` |
| 365 | `RPL_ENDOFLINKS` | Terminates `/LINKS`. | `End of /LINKS list` | `src/daemon/server.zig:1065`, `src/daemon/server.zig:28440`, `src/proto/numeric.zig:127` |
| 371 | `RPL_INFO` | `INFO` and `DIRECTORY` body lines. | Static and dynamic server/directory text. | `src/daemon/server.zig:1068`, `src/daemon/server.zig:28277`, `src/daemon/server.zig:28304`, `src/proto/numeric.zig:132` |
| 373 | `RPL_INFOSTART` | Starts `INFO` or `DIRECTORY`. | Server name or directory label. | `src/daemon/server.zig:1070`, `src/daemon/server.zig:28297`, `src/daemon/server.zig:28357`, `src/proto/numeric.zig:134` |
| 374 | `RPL_ENDOFINFO` | Terminates `INFO`, `DIRECTORY`, and OROWASM introspection replies. | `End of /INFO list`, `End of /DIRECTORY`, or command-specific terminator. | `src/daemon/server.zig:1069`, `src/daemon/server.zig:28307`, `src/daemon/server.zig:28384`, `src/proto/numeric.zig:135` |
| 375 | `RPL_MOTDSTART` | Starts `MOTD`. | `- <server> Message of the Day -` | `src/daemon/server.zig:21925`, `src/proto/motd.zig:115`, `src/proto/motd.zig:135`, `src/proto/numeric.zig:136` |
| 372 | `RPL_MOTD` | `MOTD` body line. | One unfolded MOTD line. | `src/daemon/server.zig:21925`, `src/proto/motd.zig:142`, `src/proto/motd.zig:299`, `src/proto/numeric.zig:133` |
| 376 | `RPL_ENDOFMOTD` | Terminates `MOTD`. | `End of /MOTD command.` | `src/daemon/server.zig:21925`, `src/proto/motd.zig:171`, `src/proto/numeric.zig:137` |
| 381 | `RPL_YOUREOPER` | Oper status granted through operator auth/binding. | `You are now an IRC operator` | `src/daemon/server.zig:1066`, `src/daemon/server.zig:22249`, `src/daemon/server.zig:22536`, `src/proto/numeric.zig:139` |
| 382 | `RPL_REHASHING` | `/REHASH` status and reload outcome. | `No config file; nothing to reload`; `No I/O available; cannot reload`; dynamic reload note. | `src/daemon/server.zig:1067`, `src/daemon/server.zig:27931`, `src/daemon/server.zig:28000`, `src/proto/numeric.zig:140` |
| 391 | `RPL_TIME` | `TIME`. | Current wall-clock server time. | `src/daemon/server.zig:21932`, `src/daemon/server.zig:21937`, `src/proto/serverinfo.zig:140`, `src/proto/numeric.zig:144` |
| 392 | `RPL_USERSSTART` | Starts `USERS`. | `UserID   Terminal  Host` | `src/daemon/server.zig:1071`, `src/daemon/server.zig:28387`, `src/daemon/server.zig:28389`, `src/proto/numeric.zig:145` |
| 393 | `RPL_USERS` | `USERS` row. | Dynamic local user row. | `src/daemon/server.zig:1072`, `src/daemon/server.zig:28401`, `src/proto/numeric.zig:146` |
| 394 | `RPL_ENDOFUSERS` | Terminates `USERS`. | `End of users` | `src/daemon/server.zig:1073`, `src/daemon/server.zig:28404`, `src/proto/numeric.zig:147` |
| 395 | `RPL_NOUSERS` | `USERS` has no rows. | `Nobody logged in` | `src/daemon/server.zig:1074`, `src/daemon/server.zig:28403`, `src/proto/numeric.zig:148` |
| 481 | `ERR_NOPRIVILEGES` | Operator-only command or plugin capability failure. | `Permission Denied- You're not an IRC operator`; other handler-specific privilege text. | `src/daemon/server.zig:1181`, `src/daemon/server.zig:8416`, `src/daemon/server.zig:26965`, `src/proto/numeric.zig:207` |
| 491 | `ERR_NOOPERHOST` | Legacy `OPER` command is disabled. | `OPER is disabled; authenticate via SASL (operator status is granted on login)` | `src/daemon/server.zig:1183`, `src/daemon/server.zig:22225`, `src/proto/numeric.zig:214` |
| 704 | `RPL_HELPSTART` | Starts a `HELP`/`HELPOP` topic. | First help topic line. | `src/daemon/server.zig:21651`, `src/proto/help_db.zig:8`, `src/proto/help_db.zig:124`, `src/proto/help_db.zig:133` |
| 705 | `RPL_HELPTXT` | Middle `HELP`/`HELPOP` topic lines. | Help topic body line. | `src/proto/help_db.zig:9`, `src/proto/help_db.zig:125`, `src/proto/help_db.zig:143` |
| 706 | `RPL_ENDOFHELP` | Terminates a `HELP`/`HELPOP` topic. | `End of /HELP.` | `src/proto/help_db.zig:10`, `src/proto/help_db.zig:128`, `src/proto/help_db.zig:153` |
| 709 | `RPL_ETRACE` | `ETRACE` row. | Extended local user trace row. | `src/daemon/server.zig:17114`, `src/daemon/server.zig:17126`, `src/proto/trace.zig:219` |

## User lookup, WHO, WHOIS, and visibility

| Value | Name | When emitted | Message text | Evidence |
| ---: | --- | --- | --- | --- |
| 276 | `RPL_WHOISCERTFP` | WHOIS target authenticated with a TLS client certificate; local, or remote when propagated over a secured oper-info link and requester may see it. | `has client certificate fingerprint ...` | `src/daemon/whois.zig:31`, `src/daemon/whois.zig:227`, `src/daemon/whois.zig:640`, `src/proto/numeric.zig:74` |
| 301 | `RPL_AWAY` | PRIVMSG to an away user and WHOIS target away state. | Target away message. | `src/daemon/server.zig:1075`, `src/daemon/server.zig:29917`, `src/daemon/server.zig:29923`, `src/daemon/whois.zig:35`, `src/proto/numeric.zig:79` |
| 302 | `RPL_USERHOST` | `USERHOST <nick>...`. | Userhost target list. | `src/daemon/server.zig:12648`, `src/daemon/server.zig:12665`, `src/proto/ison_userhost.zig:22`, `src/proto/ison_userhost.zig:186`, `src/proto/numeric.zig:80` |
| 303 | `RPL_ISON` | `ISON <nick>...`. | Online nick subset. | `src/daemon/server.zig:12628`, `src/daemon/server.zig:12644`, `src/proto/ison_userhost.zig:21`, `src/proto/ison_userhost.zig:93`, `src/proto/numeric.zig:81` |
| 311 | `RPL_WHOISUSER` | WHOIS subject identity. | Nick, user, host, and realname. | `src/daemon/whois.zig:24`, `src/daemon/whois.zig:203`, `src/proto/numeric.zig:86` |
| 312 | `RPL_WHOISSERVER` | WHOIS subject server. | Server and server description. | `src/daemon/whois.zig:25`, `src/daemon/whois.zig:204`, `src/daemon/server.zig:13212`, `src/proto/numeric.zig:87` |
| 313 | `RPL_WHOISOPERATOR` | WHOIS target is an operator/admin and not hidden from the requester. | Operator/admin/title text. | `src/daemon/whois.zig:30`, `src/daemon/whois.zig:224`, `src/daemon/server.zig:13216`, `src/proto/numeric.zig:88` |
| 315 | `RPL_ENDOFWHO` | Terminates WHO/WHOX, including hidden-channel fail-closed responses. | `End of /WHO list` | `src/daemon/server.zig:12669`, `src/daemon/server.zig:12678`, `src/daemon/server.zig:12837`, `src/daemon/server.zig:12893`, `src/proto/who.zig:221`, `src/proto/numeric.zig:90` |
| 317 | `RPL_WHOISIDLE` | WHOIS target idle/signon for local users. | Idle seconds and signon time. | `src/daemon/whois.zig:26`, `src/daemon/whois.zig:214`, `src/daemon/server.zig:13194`, `src/proto/numeric.zig:92` |
| 318 | `RPL_ENDOFWHOIS` | Terminates WHOIS, including failed lookups after 401. | `End of /WHOIS list` | `src/daemon/whois.zig:36`, `src/daemon/whois.zig:249`, `src/daemon/whois.zig:283`, `src/daemon/server.zig:13105`, `src/proto/numeric.zig:93` |
| 319 | `RPL_WHOISCHANNELS` | WHOIS visible channel memberships. | Channel list, folded as needed. | `src/daemon/whois.zig:27`, `src/daemon/whois.zig:217`, `src/daemon/server.zig:13113`, `src/daemon/server.zig:13331`, `src/proto/numeric.zig:94` |
| 320 | `RPL_WHOISSPECIAL` | WHOIS GeoIP/ASN/rDNS special text and public message-restriction hints for target `+R` or `+g`. | Geo/rDNS text, `is only accepting private messages from registered users`, or `is only accepting private messages from users on its accept list`. | `src/daemon/whois.zig:34`, `src/daemon/whois.zig:236`, `src/daemon/whois.zig:240`, `src/daemon/whois.zig:243`, `src/daemon/server.zig:13205`, `src/daemon/server.zig:13210` |
| 330 | `RPL_WHOISLOGGEDIN` | WHOIS target account is known. | Logged-in account line. | `src/daemon/whois.zig:28`, `src/daemon/whois.zig:218`, `src/daemon/server.zig:13390`, `src/proto/numeric.zig:103` |
| 335 | `RPL_WHOISBOT` | WHOIS target has bot mode. | Bot marker line. | `src/daemon/whois.zig:29`, `src/daemon/whois.zig:221`, `src/proto/numeric.zig:107` |
| 338 | `RPL_WHOISACTUALLY` | WHOIS target real host/IP is visible to requester. | Actual host/IP. | `src/daemon/whois.zig:33`, `src/daemon/whois.zig:209`, `src/daemon/server.zig:13233`, `src/daemon/server.zig:13400`, `src/proto/numeric.zig:108` |
| 352 | `RPL_WHOREPLY` | Plain WHO matching row. | Channel/nick/user/host/server/flags/realname row. | `src/daemon/server.zig:12669`, `src/daemon/server.zig:12864`, `src/proto/who.zig:159`, `src/proto/numeric.zig:117` |
| 354 | `RPL_WHOSPCRPL` | WHOX matching row. | Requested WHOX fields. | `src/daemon/server.zig:12670`, `src/daemon/server.zig:12740`, `src/daemon/server.zig:12816`, `src/proto/whox.zig:14`, `src/proto/numeric.zig:119` |
| 671 | `RPL_WHOISSECURE` | WHOIS target is connected over TLS. | Secure-connection text, with cipher when known and `[kTLS: TX]`, `[kTLS: RX]`, or `[kTLS: TX+RX]` when those kernel directions are actually attached. | `src/daemon/whois.zig:32`, `src/daemon/whois.zig:230`, `src/daemon/server.zig:13228`, `src/proto/numeric.zig:75` |

Hidden secret/private channels now fail closed in both roster paths: a non-member
receives a bare `RPL_ENDOFNAMES` 366 for `NAMES #chan` and no 353 rows
(`src/daemon/server.zig:11874`, `src/daemon/server.zig:11885`; regression test
`src/daemon/server.zig:37160`), and a bare `RPL_ENDOFWHO` 315 for `WHO`/WHOX with
no 352/354 rows (`src/daemon/server.zig:12675`, `src/daemon/server.zig:12828`;
regression test `src/daemon/server.zig:37210`).

WHOIS `RPL_WHOISSPECIAL` 320 is repeatable. Geo/rDNS 320s are oper/self-gated
(`src/daemon/server.zig:13145`, `src/daemon/server.zig:13166`); public `+R` and
`+g` message-restriction hints are emitted for every requester, as are the `+G`
(common-channel), `+Z` (TLS-only private messages), and `+V` (no-invite)
restriction hints when they apply (`src/daemon/whois.zig`). The same numeric
also carries the modes line, connection-class line, oper/self `ban cloak`, and
the via-WebSocket line. Tests cover `+R`,
`+g`, ordering, and coexistence with GeoIP 320s at `src/daemon/whois.zig:1067`,
`src/daemon/whois.zig:1093`, `src/daemon/whois.zig:1115`, and
`src/daemon/whois.zig:1150`.

## Channel membership, MODE, lists, and messaging

| Value | Name | When emitted | Message text | Evidence |
| ---: | --- | --- | --- | --- |
| 221 | `RPL_UMODEIS` | `MODE <own-nick>` query. | Current user mode string. | `src/daemon/server.zig:1084`, `src/daemon/server.zig:12464`, `src/daemon/server.zig:12478`, `src/proto/numeric.zig:45` |
| 305 | `RPL_UNAWAY` | Bare AWAY clears away state. | `You are no longer marked as being away` | `src/daemon/server.zig:1076`, `src/daemon/server.zig:22166`, `src/daemon/server.zig:22182`, `src/proto/numeric.zig:83` |
| 306 | `RPL_NOWAWAY` | AWAY with message sets away state. | `You have been marked as being away` | `src/daemon/server.zig:1077`, `src/daemon/server.zig:22166`, `src/daemon/server.zig:22179`, `src/proto/numeric.zig:84` |
| 321 | `RPL_LISTSTART` | Starts `LIST`. | `Channel :Users Name` | `src/daemon/server.zig:12897`, `src/daemon/server.zig:12972`, `src/proto/list.zig:163`, `src/proto/numeric.zig:96` |
| 322 | `RPL_LIST` | One visible `LIST` channel row. | Channel, user count, and topic. | `src/proto/list.zig:173`, `src/proto/list.zig:212`, `src/proto/numeric.zig:97` |
| 323 | `RPL_LISTEND` | Terminates `LIST`. | `End of LIST` | `src/proto/list.zig:189`, `src/proto/list.zig:215`, `src/proto/numeric.zig:98` |
| 324 | `RPL_CHANNELMODEIS` | `MODE #channel` query. | Empty trailing; params contain active modes and visible params. | `src/daemon/server.zig:1082`, `src/daemon/server.zig:12001`, `src/daemon/server.zig:12039`, `src/proto/numeric.zig:99` |
| 329 | `RPL_CREATIONTIME` | `MODE #channel` query when creation time is known. | Empty trailing; params carry channel and timestamp. | `src/daemon/server.zig:1083`, `src/daemon/server.zig:12043`, `src/proto/numeric.zig:102` |
| 331 | `RPL_NOTOPIC` | `TOPIC #channel` when no topic exists. | `No topic is set` | `src/daemon/server.zig:1078`, `src/daemon/server.zig:30055`, `src/proto/numeric.zig:104` |
| 332 | `RPL_TOPIC` | `TOPIC #channel` query when a topic exists. | Current topic text. | `src/daemon/server.zig:1079`, `src/daemon/server.zig:30050`, `src/proto/numeric.zig:105` |
| 333 | `RPL_TOPICWHOTIME` | `TOPIC #channel` query when topic setter/time are known. | Empty trailing; params carry setter and timestamp. | `src/daemon/server.zig:1080`, `src/daemon/server.zig:30053`, `src/proto/numeric.zig:106` |
| 341 | `RPL_INVITING` | Successful `INVITE`. | Inviter numeric naming target nick and channel. | `src/daemon/server.zig:13465`, `src/daemon/server.zig:13503`, `src/proto/invite.zig:152`, `src/proto/numeric.zig:109` |
| 342 | `RPL_SUMMONING` | `SUMMON` force-joins a target user. | `Summoned user to channel` | `src/daemon/server.zig:1081`, `src/daemon/server.zig:22232`, `src/daemon/server.zig:22245`, `src/proto/numeric.zig:110` |
| 346 | `RPL_INVITELIST` | `MODE #channel I` list query. | Invite-exception mask row. | `src/daemon/server.zig:1094`, `src/daemon/server.zig:12314`, `src/daemon/server.zig:12316`, `src/proto/numeric.zig:112` |
| 347 | `RPL_ENDOFINVITELIST` | Terminates `+I` list. | `End of channel invite exception list` | `src/daemon/server.zig:1095`, `src/daemon/server.zig:12316`, `src/proto/numeric.zig:113` |
| 348 | `RPL_EXCEPTLIST` | `MODE #channel e` list query. | Ban-exception mask row. | `src/daemon/server.zig:1096`, `src/daemon/server.zig:12294`, `src/daemon/server.zig:12296`, `src/proto/numeric.zig:114` |
| 349 | `RPL_ENDOFEXCEPTLIST` | Terminates `+e` list. | `End of channel exception list` | `src/daemon/server.zig:1097`, `src/daemon/server.zig:12296`, `src/proto/numeric.zig:115` |
| 353 | `RPL_NAMREPLY` | NAMES/JOIN names burst. | Channel member list. | `src/daemon/server.zig:1085`, `src/daemon/server.zig:30184`, `src/daemon/server.zig:30189`, `src/proto/numeric.zig:118` |
| 366 | `RPL_ENDOFNAMES` | Terminates NAMES/JOIN names burst, including bare hidden-channel terminators. | `End of /NAMES list` | `src/daemon/server.zig:1086`, `src/daemon/server.zig:11868`, `src/daemon/server.zig:11885`, `src/daemon/server.zig:30191`, `src/proto/numeric.zig:128` |
| 367 | `RPL_BANLIST` | `MODE #channel b` list query. | Ban mask row. | `src/daemon/server.zig:1087`, `src/daemon/server.zig:30060`, `src/daemon/server.zig:30062`, `src/proto/numeric.zig:129` |
| 368 | `RPL_ENDOFBANLIST` | Terminates `+b` list. | `End of channel ban list` | `src/daemon/server.zig:1091`, `src/daemon/server.zig:30062`, `src/proto/numeric.zig:130` |
| 401 | `ERR_NOSUCHNICK` | Missing nick target across WHOIS/INVITE/KILL/WHISPER/message paths. | `No such nick`; WHOIS builder uses `No such nick/channel`. | `src/daemon/server.zig:1153`, `src/daemon/server.zig:13473`, `src/daemon/whois.zig:252`, `src/proto/numeric.zig:151` |
| 402 | `ERR_NOSUCHSERVER` | Missing SQUIT/CONNECT target server. | `No such server` | `src/daemon/server.zig:1154`, `src/daemon/server.zig:17334`, `src/proto/numeric.zig:152` |
| 403 | `ERR_NOSUCHCHANNEL` | Missing channel target across JOIN/PART/MODE/TOPIC/etc. | `No such channel` | `src/daemon/server.zig:1155`, `src/daemon/server.zig:11516`, `src/daemon/server.zig:11997`, `src/proto/numeric.zig:153` |
| 404 | `ERR_CANNOTSENDTOCHAN` | Message blocked by `+n`, `+m`, `+M`, `+Z`, `+b`, or `+C`. | Handler-specific `Cannot send to channel (...)` text. | `src/daemon/server.zig:1156`, `src/daemon/server.zig:29094`, `src/daemon/server.zig:29142`, `src/proto/numeric.zig:154` |
| 405 | `ERR_TOOMANYCHANNELS` | JOIN would exceed configured channel limit. | `You have joined too many channels` | `src/daemon/server.zig:1089`, `src/daemon/server.zig:11535`, `src/proto/numeric.zig:155` |
| 407 | `ERR_TOOMANYTARGETS` | PRIVMSG/NOTICE exceeds `MAXTARGETS`. | `Too many recipients` | `src/daemon/server.zig:1090`, `src/daemon/server.zig:29421`, `src/proto/numeric.zig:157` |
| 411 | `ERR_NORECIPIENT` | Empty/invalid PRIVMSG or NOTICE target list. | Handler-specific missing-recipient reason. | `src/daemon/server.zig:1157`, `src/daemon/server.zig:29383`, `src/proto/numeric.zig:160` |
| 412 | `ERR_NOTEXTTOSEND` | PRIVMSG without text. | `No text to send` | `src/daemon/server.zig:1158`, `src/daemon/server.zig:29388`, `src/proto/numeric.zig:161` |
| 425 | `ERR_NOOPERMOTD` | `OPERMOTD` requested while no operator MOTD is set. | `OPERMOTD is empty` | `src/daemon/server.zig:15301`, `src/daemon/server.zig:15317`, `src/proto/oper_motd.zig:12`, `src/proto/oper_motd.zig:273` |
| 431 | `ERR_NONICKNAMEGIVEN` | NICK command without nickname. | `No nickname given` | `src/daemon/server.zig:1171`, `src/daemon/server.zig:22026`, `src/proto/numeric.zig:170` |
| 433 | `ERR_NICKNAMEINUSE` | NICK collision. | `Nickname is already in use` | `src/daemon/server.zig:1173`, `src/daemon/server.zig:8558`, `src/daemon/server.zig:22094`, `src/proto/numeric.zig:172` |
| 437 | `ERR_UNAVAILRESOURCE` | Reserved channel/nick resource blocks JOIN or requested nick is held by nick delay. | Dynamic reservation reason, or `Nick is held (nick delay); try again shortly`. | `src/daemon/server.zig:1167`, `src/daemon/server.zig:8537`, `src/daemon/server.zig:11520`, `src/proto/numeric.zig:175` |
| 441 | `ERR_USERNOTINCHANNEL` | Target user is not on channel for MODE/KICK/WHISPER/etc. | `They aren't on that channel` | `src/daemon/server.zig:1174`, `src/daemon/server.zig:12130`, `src/daemon/server.zig:21099`, `src/proto/numeric.zig:178` |
| 442 | `ERR_NOTONCHANNEL` | Acting client is not on the channel. | `You're not on that channel` | `src/daemon/server.zig:1176`, `src/daemon/server.zig:11793`, `src/daemon/server.zig:12051`, `src/proto/numeric.zig:179` |
| 443 | `ERR_USERONCHANNEL` | INVITE target already joined. | `is already on channel` | `src/daemon/server.zig:1175`, `src/daemon/server.zig:13491`, `src/proto/numeric.zig:180` |
| 445 | `ERR_SUMMONDISABLED` | Cataloged in daemon-local enum for disabled summon handling; no live server.zig emission currently found. | Disabled-summon text when wired. | `src/daemon/server.zig:1179`, `src/proto/numeric.zig:182` |
| 464 | `ERR_PASSWDMISMATCH` | Account/service password failure or lockout. | `Invalid account or password` or dynamic lockout message. | `src/daemon/server.zig:1178`, `src/daemon/server.zig:23031`, `src/daemon/server.zig:23053`, `src/proto/numeric.zig:191` |
| 470 | `ERR_LINKCHANNEL` | JOIN is redirected by a usable one-hop channel forward target. | `Forwarding to another channel` | `src/daemon/server.zig:11488`, `src/daemon/server.zig:11507`, `src/proto/numeric.zig:196` |
| 471 | `ERR_CHANNELISFULL` | JOIN blocked by `+l`. | `Cannot join channel (+l)` | `src/daemon/server.zig:1159`, `src/daemon/server.zig:11584`, `src/daemon/server.zig:11592`, `src/proto/numeric.zig:197` |
| 472 | `ERR_UNKNOWNMODE` | Unsupported mode letter or invalid TEMPMODE mode. | `is unknown mode char to me` or TEMPMODE-specific text. | `src/daemon/server.zig:1168`, `src/daemon/server.zig:12423`, `src/daemon/server.zig:18917`, `src/proto/numeric.zig:198` |
| 473 | `ERR_INVITEONLYCHAN` | JOIN blocked by `+i`. | `Cannot join channel (+i)` | `src/daemon/server.zig:1160`, `src/daemon/server.zig:11391`, `src/proto/numeric.zig:199` |
| 474 | `ERR_BANNEDFROMCHAN` | JOIN blocked by quarantine, AKICK, access deny, or `+b`. | `Cannot join channel (+b)` or dynamic reason. | `src/daemon/server.zig:1161`, `src/daemon/server.zig:11247`, `src/daemon/server.zig:11382`, `src/proto/numeric.zig:200` |
| 475 | `ERR_BADCHANNELKEY` | JOIN blocked by `+k`. | `Cannot join channel (+k)` | `src/daemon/server.zig:1162`, `src/daemon/server.zig:11400`, `src/proto/numeric.zig:201` |
| 476 | `ERR_BADCHANMASK` | Invalid channel/mask syntax in list/service paths. | `Invalid channel mask` or command-specific bad-channel text. | `src/daemon/server.zig:1163`, `src/daemon/server.zig:11957`, `src/proto/numeric.zig:202` |
| 477 | `ERR_NEEDREGGEDNICK` | JOIN blocked by `+a`, or PM blocked by user `+R`. | `Cannot join channel (+a) - you must be authenticated`; `Cannot message this user (+R: identify to a registered account)` | `src/daemon/server.zig:1166`, `src/daemon/server.zig:11334`, `src/daemon/server.zig:29838`, `src/proto/numeric.zig:203` |
| 478 | `ERR_BANLISTFULL` | Adding `+b`, `+e`, `+I`, or `+Z` exceeds `max_list_entries`. | `Channel list is full` | `src/daemon/server.zig:1088`, `src/daemon/server.zig:11955`, `src/proto/numeric.zig:204` |
| 480 | `ERR_THROTTLE` | JOIN blocked by `+j` join throttle. | `Cannot join channel (+j) - join rate exceeded, try again shortly` | `src/daemon/server.zig:1063`, `src/daemon/server.zig:11566`, `src/proto/numeric.zig:206` |
| 482 | `ERR_CHANOPRIVSNEEDED` | Operator-tier channel privilege required. | `You're not channel operator` plus handler-specific privilege text. | `src/daemon/server.zig:1182`, `src/daemon/server.zig:12056`, `src/daemon/server.zig:12599`, `src/proto/numeric.zig:208` |
| 489 | `ERR_SECUREONLYCHAN` | JOIN blocked by channel `+S` over non-TLS session. | `Cannot join channel (+S) - TLS required` | `src/daemon/server.zig:1062`, `src/daemon/server.zig:11309` |
| 502 | `ERR_USERSDONTMATCH` | User MODE target is not the caller. | `Cannot change mode for other users` | `src/daemon/server.zig:1180`, `src/daemon/server.zig:12472`, `src/proto/numeric.zig:218` |
| 520 | `ERR_OPERONLYCHAN` | JOIN blocked by channel `+O` or `+A`. | `Cannot join channel (+O) - IRC operator required`; `Cannot join channel (+A) - server administrator required` | `src/daemon/server.zig:1164`, `src/daemon/server.zig:11316`, `src/daemon/server.zig:11323` |
| 524 | `ERR_HELPNOTFOUND` | Unknown `HELP`/`HELPOP` topic. | `Help not found` | `src/proto/help_db.zig:11`, `src/proto/help_db.zig:112`, `src/proto/help_db.zig:162`, `src/proto/numeric.zig:223` |
| 531 | `ERR_NOCOMICDATA` | IRCX DATA blocked by channel `+V` comic-chat policy. | `Channel does not allow comic-chat DATA (+V)` | `src/daemon/server.zig:1165`, `src/daemon/server.zig:20933`, `src/daemon/server.zig:20939`, `src/proto/numeric.zig:225` |

## Lists, monitor, silence, knock, metadata, and IRCX extensions

| Value | Name | When emitted | Message text | Evidence |
| ---: | --- | --- | --- | --- |
| 271 | `RPL_SILELIST` | `SILENCE` query row. | Mask row. | `src/daemon/server.zig:1098`, `src/daemon/server.zig:14429`, `src/daemon/server.zig:14436` |
| 272 | `RPL_ENDOFSILELIST` | Terminates `SILENCE` query. | `End of SILENCE list` | `src/daemon/server.zig:1099`, `src/daemon/server.zig:14437` |
| 281 | `RPL_ACCEPTLIST` | `ACCEPT` query row. | Accepted nick row. | `src/daemon/server.zig:1115`, `src/daemon/server.zig:16057`, `src/daemon/server.zig:16080`, `src/proto/numeric.zig:76` |
| 282 | `RPL_ENDOFACCEPT` | Terminates `ACCEPT` query. | `End of /ACCEPT list` | `src/daemon/server.zig:1116`, `src/daemon/server.zig:16081`, `src/proto/numeric.zig:77` |
| 710 | `RPL_KNOCK` | Delivered to channel operators when a KNOCK arrives. | Knock reason. | `src/daemon/server.zig:1122`, `src/daemon/server.zig:13815`, `src/daemon/server.zig:13851` |
| 711 | `RPL_KNOCKDLVR` | Sent to the knocker after delivery. | `Your KNOCK has been delivered` | `src/daemon/server.zig:1123`, `src/daemon/server.zig:13853` |
| 713 | `ERR_CHANOPEN` | KNOCK refused because channel is open. | `Channel is open` | `src/daemon/server.zig:1124`, `src/daemon/server.zig:13839` |
| 714 | `ERR_KNOCKONCHAN` | KNOCK refused because caller is already joined. | `You are already on that channel` | `src/daemon/server.zig:1125`, `src/daemon/server.zig:13830` |
| 716 | `ERR_CANTSENDTOUSER` | DM blocked by recipient usermode `+g`. | `is in +g mode (must be accepted)` | `src/daemon/server.zig:1119`, `src/daemon/server.zig:29851`, `src/daemon/server.zig:29869`, `src/proto/numeric.zig:230` |
| 717 | `RPL_TARGNOTIFY` | Sender notification after `+g` DM block. | `has been informed that you messaged them` | `src/daemon/server.zig:1120`, `src/daemon/server.zig:29870`, `src/proto/numeric.zig:231` |
| 718 | `RPL_UMODEGMSG` | One-shot notice to a `+g` recipient. | `is messaging you, and you have umode +g set. Use ACCEPT to allow` | `src/daemon/server.zig:1121`, `src/daemon/server.zig:29878`, `src/proto/numeric.zig:232` |
| 720 | `RPL_OMOTDSTART` | Starts `OPERMOTD` when set. | Operator MOTD start text. | `src/daemon/server.zig:15301`, `src/daemon/server.zig:15322`, `src/proto/oper_motd.zig:9`, `src/proto/oper_motd.zig:194` |
| 721 | `RPL_OMOTD` | `OPERMOTD` body line. | Operator MOTD text. | `src/daemon/server.zig:15323`, `src/proto/oper_motd.zig:10`, `src/proto/oper_motd.zig:223` |
| 722 | `RPL_ENDOFOMOTD` | Terminates `OPERMOTD` when set. | `End of OPERMOTD` | `src/daemon/server.zig:15327`, `src/proto/oper_motd.zig:11`, `src/proto/oper_motd.zig:249` |
| 725 | `RPL_TESTLINE` | `TESTLINE` matches a Warden ban/ward. | Dynamic ward result. | `src/daemon/server.zig:1112`, `src/daemon/server.zig:17387`, `src/daemon/server.zig:17399` |
| 726 | `RPL_NOTESTLINE` | `TESTLINE` finds no matching ban. | `No matching ban found` | `src/daemon/server.zig:1113`, `src/daemon/server.zig:17402` |
| 727 | `RPL_TESTMASK` | `TESTMASK` reports matching clients. | `clients match` | `src/daemon/server.zig:1114`, `src/daemon/server.zig:17406`, `src/daemon/server.zig:17425` |
| 728 | `RPL_QUIETLIST` | `MODE #channel Z` quiet-list query row. | Quiet mask row. | `src/daemon/server.zig:1092`, `src/daemon/server.zig:12335`, `src/daemon/server.zig:12337` |
| 729 | `RPL_ENDOFQUIETLIST` | Terminates quiet-list query. | `End of channel quiet list` | `src/daemon/server.zig:1093`, `src/daemon/server.zig:12337` |
| 730 | `RPL_MONONLINE` | MONITOR online notification. | Monitor target list. | `src/daemon/server.zig:1126`, `src/daemon/server.zig:13968`, `src/daemon/server.zig:30415` |
| 731 | `RPL_MONOFFLINE` | MONITOR offline notification. | Monitor target list. | `src/daemon/server.zig:1127`, `src/daemon/server.zig:13968`, `src/daemon/server.zig:30416` |
| 732 | `RPL_MONLIST` | MONITOR list query. | Monitor target list. | `src/daemon/server.zig:1128`, `src/daemon/server.zig:13973`, `src/daemon/server.zig:30417` |
| 733 | `RPL_ENDOFMONLIST` | Terminates MONITOR list query. | End marker. | `src/daemon/server.zig:1129`, `src/daemon/server.zig:13977`, `src/daemon/server.zig:30418` |
| 734 | `ERR_MONLISTFULL` | MONITOR add exceeds limit. | Monitor limit failure. | `src/daemon/server.zig:1130`, `src/daemon/server.zig:13968`, `src/daemon/server.zig:30419` |
| 761 | `RPL_KEYVALUE` | METADATA GET/LIST/SET/CLEAR value rows. | Metadata value or empty string. | `src/daemon/server.zig:1100`, `src/daemon/server.zig:21369`, `src/daemon/server.zig:21395` |
| 762 | `RPL_METADATAEND` | Terminates METADATA command. | `end of metadata` | `src/daemon/server.zig:1101`, `src/daemon/server.zig:21416`, `src/daemon/server.zig:21466` |
| 766 | `ERR_KEYNOTSET` | METADATA GET for absent key. | `key not set` | `src/daemon/server.zig:1102`, `src/daemon/server.zig:21397` |
| 767 | `ERR_KEYINVALID` | METADATA key validation failure. | `invalid key` or `invalid visibility` | `src/daemon/server.zig:1103`, `src/daemon/server.zig:21425`, `src/daemon/server.zig:21432` |
| 769 | `ERR_KEYNOPERMISSION` | METADATA SET/CLEAR without permission. | `permission denied` | `src/daemon/server.zig:1104`, `src/daemon/server.zig:21392`, `src/daemon/server.zig:21448` |
| 800 | `RPL_IRCX` | `MODE ISIRCX` / IRCX discovery. | Trailing `*`; params include state, version, package list, and max message size. | `src/daemon/server.zig:1111`, `src/daemon/server.zig:11967`, `src/daemon/server.zig:20787`, `src/daemon/server.zig:20796` |
| 811 | `RPL_LISTXSTART` | Starts IRCX `LISTX`. | `Channel Members CreatedMs TopicMs :Topic` | `src/daemon/server.zig:12994`, `src/daemon/server.zig:13013`, `src/proto/listx.zig:14`, `src/proto/listx.zig:369` |
| 812 | `RPL_LISTXENTRY` | One IRCX `LISTX` channel row. | Channel, members, creation time, topic time, and topic. | `src/daemon/server.zig:12979`, `src/daemon/server.zig:12984`, `src/proto/listx.zig:15`, `src/proto/listx.zig:389` |
| 813 | `RPL_LISTXPICS` | Optional IRCX `LISTX` PICS row after an entry. | Channel and PICS value. | `src/daemon/server.zig:12985`, `src/daemon/server.zig:12989`, `src/proto/listx.zig:16`, `src/proto/listx.zig:420` |
| 816 | `RPL_LISTXTRUNC` | IRCX `LISTX` result cap was hit. | `LISTX results truncated` | `src/daemon/server.zig:12975`, `src/daemon/server.zig:13076`, `src/proto/listx.zig:17`, `src/proto/listx.zig:446` |
| 817 | `RPL_LISTXEND` | Terminates IRCX `LISTX`. | `End of LISTX` | `src/daemon/server.zig:13079`, `src/proto/listx.zig:18`, `src/proto/listx.zig:463` |
| 818 | `RPL_PROPLIST` | IRCX `PROP` list/get row. | Property key/value row. | `src/daemon/server.zig:20421`, `src/daemon/server.zig:20423`, `src/proto/ircx.zig:434`, `src/proto/ircx_prop_cmd.zig:112` |
| 819 | `RPL_PROPEND` | Terminates IRCX `PROP` list/get. | PROP terminator. | `src/daemon/server.zig:20423`, `src/proto/ircx.zig:435`, `src/proto/ircx_prop_cmd.zig:112` |
| 821 | `ERR_EVENTDUP` | IRCX EVENT add duplicate. | `Event already subscribed` | `src/daemon/server.zig:1149`, `src/daemon/server.zig:17643` |
| 822 | `ERR_EVENTMIS` | IRCX EVENT change/delete without subscription. | `Not subscribed to event` | `src/daemon/server.zig:1150`, `src/daemon/server.zig:17674`, `src/daemon/server.zig:17697` |
| 823 | `ERR_NOSUCHEVENT` | IRCX EVENT unknown event/category. | `No such event` or `No such event category` | `src/daemon/server.zig:1151`, `src/daemon/server.zig:17596`, `src/daemon/server.zig:17754` |
| 825 | `RPL_EVENTCHANGE` | IRCX EVENT subscription changed. | `Event updated` | `src/daemon/server.zig:1152`, `src/daemon/server.zig:17682` |
| 826 | `RPL_MODEXLIST` | IRCX MODEX query row. | Target and named mode list. | `src/daemon/server.zig:17428`, `src/daemon/server.zig:17443`, `src/proto/ircx_modex.zig:17`, `src/proto/ircx_modex.zig:335` |
| 827 | `RPL_MODEXEND` | Terminates IRCX MODEX query. | `End of modes` | `src/daemon/server.zig:17431`, `src/proto/ircx_modex.zig:18`, `src/proto/ircx_modex.zig:371` |
| 904 | `ERR_BADTAG` | IRCX DATA invalid tag. | `Invalid DATA tag` | `src/daemon/server.zig:1110`, `src/daemon/server.zig:20888` |
| 906 | `ERR_BADVALUE` | IRCX PROP/PINS invalid property value. | `Invalid property value` | `src/daemon/server.zig:1109`, `src/daemon/server.zig:14335`, `src/daemon/server.zig:20504` |
| 913 | `ERR_NOACCESS` | IRCX PROP/DATA access denied. | `Insufficient access to set property`; `Cannot set that property`; DATA reserved-tag denials. | `src/daemon/server.zig:1107`, `src/daemon/server.zig:20485`, `src/daemon/server.zig:20906` |
| 916 | `ERR_TOOMANYACCESSES` | SACCESS add exceeds capacity. | `Cannot add SACCESS entry` | `src/daemon/server.zig:1194`, `src/daemon/server.zig:19518` |
| 923 | `ERR_NOWHISPER` | WHISPER blocked by IRCX NOWHISPER (`+w`). | `Channel does not allow whispers (+w)` | `src/daemon/server.zig:1108`, `src/daemon/server.zig:21079` |
| 926 | `ERR_CHANNELEXIST` | IRCX CREATE target already exists. | `Channel already exists` | `src/daemon/server.zig:1197`, `src/daemon/server.zig:21205`, `src/daemon/server.zig:21222` |

IRCX EVENT replies use `RPL_EVENTADD` 806, `RPL_EVENTDELETE` 807,
`RPL_EVENTSTART` 808, `RPL_EVENTLIST` 809, and `RPL_EVENTEND` 810 in the
daemon-local enum (`src/daemon/server.zig:1144` through
`src/daemon/server.zig:1148`) and live EVENT handler
(`src/daemon/server.zig:17601`, `src/daemon/server.zig:17654`,
`src/daemon/server.zig:17700`). The shared protocol catalog still carries an
older EVENTADD/EVENTDELETE numbering (`src/proto/numeric.zig:234` through
`src/proto/numeric.zig:241`); live server behavior follows `src/daemon/server.zig`.

## Cataloged but not currently emitted by `server.zig`

The daemon-local enum includes residual IRCX 9xx numerics that stay inert until a
handler emits them: `ERR_BADCOMMAND` 900, `ERR_BADLEVEL` 903,
`ERR_BADPROPERTY` 905, `ERR_RESOURCE` 907, `ERR_SECURITY` 908,
`ERR_UNKNOWNPACKAGE` 912, `ERR_DUPACCESS` 914, `ERR_MISACCESS` 915,
`ERR_NOSUCHOBJECT` 924, `ERR_NOTSUPPORTED` 925, and
`ERR_ALREADYONCHANNEL` 927 (`src/daemon/server.zig:1184`).

The shared protocol enum is broader than the live daemon emission set. It
catalogs additional 0xx, 2xx, 3xx, 4xx, 5xx, 6xx, and SASL/account numerics
including TRACE variants, WHOWAS variants, `RPL_WHOISHELPOP`,
`RPL_WHOISCOUNTRY`, `RPL_WHOISHOST`, `ERR_UMODEUNKNOWNFLAG`, `ERR_DISABLED`,
`ERR_INVALIDKEY`, and `ERR_NICKLOCKED` (`src/proto/numeric.zig:26`,
`src/proto/numeric.zig:85`, `src/proto/numeric.zig:111`,
`src/proto/numeric.zig:138`, `src/proto/numeric.zig:217`,
`src/proto/numeric.zig:222`, `src/proto/numeric.zig:245`). Do not treat a
catalog entry as live behavior unless a handler citation above or a future
handler emission exists.

## Standard replies: FAIL, WARN

Standard replies are not numeric replies. They are line types carrying a
severity token, a command token, a reply-code token, optional context params, and
a trailing description.

| Token | Builder / emitter | Shape | Current uses | Evidence |
| --- | --- | --- | --- | --- |
| `FAIL` | `standard_replies.fail`, `standard_replies_emit.fail`, and `LinuxServer.failReply`. | `FAIL <command> <code> [context...] :<description>` | CHATHISTORY parse failures, invalid UTF-8, Koshi content filter, multiline failures, media/service failures. | `src/proto/standard_replies.zig:15`, `src/proto/standard_replies.zig:200`, `src/proto/standard_replies_emit.zig:121`, `src/daemon/server.zig:10001`, `src/daemon/server.zig:5491`, `src/daemon/server.zig:10803` |
| `WARN` | `standard_replies.warn` / `standard_replies_emit.warn`. | `WARN <command> <code> [context...] :<description>` | Cataloged builder support; no live `server.zig` emission found in current source. | `src/proto/standard_replies.zig:205`, `src/proto/standard_replies_emit.zig:131` |

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
(`src/proto/standard_replies.zig:33`).
