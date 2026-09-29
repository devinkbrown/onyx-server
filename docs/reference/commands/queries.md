# User query commands

*Presence, identity, and channel lookups, plus away state, realname changes, and built-in help.*

Most of these commands are registered by `user.query` (`src/daemon/modules/user_query.zig:72`); `LUSERS` is registered by `query.info` (`src/daemon/modules/query_info.zig:46`, `src/daemon/modules/query_info.zig:75`) and `LISTX` by `ircx` (`src/daemon/modules/ircx.zig:51`, `src/daemon/modules/ircx.zig:71`).

## ISON

- Syntax: `ISON <nick>...`
- Description: Returns the subset of requested nicks that are online.
- Privileges: Registered client.
- Parameters: One or more nick tokens; the handler accepts an empty list and returns an empty result.
- Replies: `RPL_ISON 303`.
- Errors: Registry `ERR_NEEDMOREPARAMS 461` is not configured for this command; handler has no command-specific errors.
- Example: `ISON alice bob carol`
- Sources: `src/daemon/modules/user_query.zig:75`, `src/daemon/server.zig:12632`

## USERHOST

- Syntax: `USERHOST <nick>...`
- Description: Returns up to five live userhost entries, including target oper and away state.
- Privileges: Registered client.
- Parameters: Nick list.
- Replies: `RPL_USERHOST 302`.
- Errors: None specific in handler.
- Example: `USERHOST alice bob`
- Sources: `src/daemon/modules/user_query.zig:76`, `src/daemon/server.zig:12652`

## LUSERS

- Syntax: `LUSERS`
- Description: Returns network and local population counters. Registered local users come from the shared world nick registry, while global user totals include established Undertow peer route-table users.
- Privileges: Registered client.
- Parameters: None.
- Replies: `RPL_LUSERCLIENT 251`, `RPL_LUSEROP 252`, `RPL_LUSERUNKNOWN 253`, `RPL_LUSERCHANNELS 254`, `RPL_LUSERME 255`, `RPL_STATSCONN 250`, `RPL_LOCALUSERS 265`, `RPL_GLOBALUSERS 266`.
- Errors: None specific in handler.
- Example: `LUSERS`
- Sources: `src/daemon/modules/query_info.zig:46`, `src/daemon/modules/query_info.zig:75`, `src/daemon/server.zig:21735`, `src/proto/lusers.zig:60`, `src/proto/lusers.zig:80`

## WHOIS

- Syntax: `WHOIS [server] <nick>`
- Description: Emits a WHOIS sequence covering account, away state, visible channels, oper and admin visibility, bot mode, certificate fingerprint, TLS status, actual host (for opers and self), and optional GeoIP/rDNS text (for opers and self). `RPL_WHOISSPECIAL 320` also carries public +R/+g private-message restriction hints for every requester. A remote mesh WHOIS copies the roster identity and leaves idle, away, and TLS-secure on the user's home node.
- Privileges: Registered client.
- Parameters: Target nick is the last parameter.
- Replies: `RPL_WHOISUSER 311`, `RPL_WHOISSERVER 312`, `RPL_WHOISOPERATOR 313`, `RPL_WHOISIDLE 317`, `RPL_ENDOFWHOIS 318`, `RPL_WHOISCHANNELS 319`, `RPL_WHOISSPECIAL 320`, `RPL_WHOISLOGGEDIN 330`, `RPL_WHOISBOT 335`, `RPL_WHOISCERTFP 276`, `RPL_WHOISSECURE 671`, `RPL_WHOISACTUALLY 338`, and `RPL_AWAY 301` when applicable.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOSUCHNICK 401`.
- Example: `WHOIS alice`
- Sources: `src/daemon/modules/user_query.zig:77`, `src/daemon/server.zig:13086`, `src/daemon/server.zig:13149`, `src/daemon/server.zig:13209`, `src/daemon/whois.zig:203`, `src/daemon/whois.zig:236`

## LIST

- Syntax: `LIST [filter[,filter...]]`
- Description: Lists visible channels from the mesh-wide union of local and remote-only channels. Secret and hidden channels are skipped. ELIST-style filters support member-count thresholds, creation-age `C` filters, topic-age `T` filters, include masks, and `!` exclude masks; malformed filters fail closed instead of falling back to a broad listing. A remote-only channel's 322 topic is the topic the peer published.
- Privileges: Registered client.
- Parameters: Zero or one comma-separated filter parameter.
- Replies: `RPL_LISTSTART 321`, `RPL_LIST 322`, `RPL_LISTEND 323`.
- Errors: `ERR_NEEDMOREPARAMS 461` for invalid LIST filters.
- Example: `LIST >10`
- Sources: `src/daemon/modules/user_query.zig:78`, `src/daemon/server.zig:12901`, `src/daemon/server.zig:12908`, `src/proto/list.zig:132`, `src/proto/elist.zig:92`, `src/proto/list.zig:163`

## LISTX

- Syntax: `LISTX [filter[,filter...]]`
- Description: Lists visible channels using IRCX extended channel-list numerics. Filters support strict and inclusive member-count thresholds (`>N`, `<N`, `>=N`, `<=N`), creation-age `C` thresholds, topic-age `T` thresholds, `TOPICONLY`, channel/name/topic/subject/language masks, and `R=0`/`R=1` registration state. Results are capped; truncated replies emit `RPL_LISTXTRUNC 816`. A remote-only channel's 812 entry carries the topic the peer published.
- Privileges: Registered client.
- Parameters: Zero or one comma-separated filter parameter.
- Replies: `RPL_LISTXSTART 811`, `RPL_LISTXENTRY 812`, optional `RPL_LISTXPICS 813`, optional `RPL_LISTXTRUNC 816`, `RPL_LISTXEND 817`.
- Errors: `ERR_NEEDMOREPARAMS 461` for invalid LISTX filters.
- Example: `LISTX >=10,C<=3600,S=project*`
- Sources: `src/daemon/modules/ircx.zig:51`, `src/daemon/modules/ircx.zig:71`, `src/daemon/server.zig:12998`, `src/daemon/server.zig:13007`, `src/proto/listx.zig:73`, `src/proto/listx.zig:170`, `src/proto/listx.zig:236`, `src/proto/listx.zig:369`

## WHO

- Syntax: `WHO <channel|nick> [%fields[,token]]`; `WHOX <channel|nick> %fields[,token]`
- Description: Plain WHO emits channel or nick rows. When the second parameter starts with `%` and parses as WHOX, the handler emits WHOX rows instead. `WHOX` is a command-name alias for clients that send the extended form directly. For secret (`+s`) or private (`+p`) channel rosters, non-member non-opers receive only a bare `RPL_ENDOFWHO 315`.
- Privileges: Registered client.
- Parameters: Target; optional WHOX selector.
- Replies: Plain `RPL_WHOREPLY 352` and `RPL_ENDOFWHO 315`; WHOX `RPL_WHOSPCRPL 354` and `RPL_ENDOFWHO 315`.
- Errors: `ERR_NEEDMOREPARAMS 461`.
- Example: `WHOX #zig %tcuhsnfar`
- Sources: `src/daemon/modules/user_query.zig:79`, `src/daemon/modules/user_query.zig:80`, `src/daemon/server.zig:12673`, `src/daemon/server.zig:12676`, `src/daemon/server.zig:12820`, `src/daemon/server.zig:12828`, `src/proto/who.zig:159`, `src/proto/who.zig:221`

## WHOWAS

- Syntax: `WHOWAS <nick> [count]`
- Description: Looks up recorded WHOWAS snapshots for a nick, most recent first. The optional count is parsed as a decimal value and capped to 16 records; malformed counts fall back to 16. The 314 host is the connection's real host, and a logged-in account is reported with 330.
- Privileges: Registered client.
- Parameters: Nick and optional count.
- Replies: `RPL_WHOWASUSER 314` plus `RPL_WHOISSERVER 312` signoff lines when data exists, `ERR_WASNOSUCHNICK 406` when no data exists, and `RPL_ENDOFWHOWAS 369`.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_WASNOSUCHNICK 406`.
- Example: `WHOWAS alice`
- Sources: `src/daemon/modules/user_query.zig:81`, `src/daemon/server.zig:13783`, `src/daemon/server.zig:13791`, `src/proto/whowas_reply.zig:83`, `src/proto/whowas_reply.zig:113`, `src/proto/whowas_reply.zig:164`

## AWAY

- Syntax: `AWAY [:message]`
- Description: Sets or clears the caller's away message. It is accepted before registration only when the `pre-away` capability is present.
- Privileges: Registered client, or pre-registration client with `pre-away`.
- Parameters: Optional away message; no parameter clears away.
- Replies: `RPL_NOWAWAY 306`, `RPL_UNAWAY 305`; away-notify fanout to capable peers.
- Errors: None specific in handler.
- Example: `AWAY :lunch`
- Sources: `src/daemon/server.zig:3349`, `src/daemon/modules/user_query.zig:78`, `src/daemon/server.zig:8249`

## SETNAME

- Syntax: `SETNAME :<realname>`
- Description: Changes the caller's realname and notifies common-channel peers with the relevant capability.
- Privileges: Registered client.
- Parameters: New realname.
- Replies: SETNAME/chghost-style notification to capable peers; no numeric success reply.
- Errors: Handler validation errors only.
- Example: `SETNAME :Kain`
- Sources: `src/daemon/modules/user_query.zig:79`, `src/daemon/server.zig:8278`

## HELP

- Syntax: `HELP [topic]`
- Description: Returns built-in help for a topic, or general help if no topic is supplied.
- Privileges: Registered client.
- Parameters: Optional topic.
- Replies: Server `NOTICE` help lines.
- Errors: `ERR_HELPNOTFOUND 524` when no topic exists.
- Example: `HELP WARD`
- Sources: `src/daemon/modules/user_query.zig:83`, `src/daemon/server.zig:7961`

## HELPOP

- Syntax: `HELPOP [topic]`
- Description: Alias of `HELP`; registered separately but dispatched to the same handler.
- Privileges: Registered client.
- Parameters: Optional topic.
- Replies: Same as `HELP`.
- Errors: Same as `HELP`.
- Example: `HELPOP OPER`
- Sources: `src/daemon/modules/user_query.zig:84`, `src/daemon/server.zig:7961`

## AUTOJOIN

- Syntax: `AUTOJOIN <LIST|ADD|DEL|CLEAR> [#channel]`
- Description: Manages the logged-in account's autojoin list, which the daemon applies after account login.
- Privileges: Registered client; account login required inside handler.
- Parameters: Subcommand and optional channel.
- Replies: Server `NOTICE` responses.
- Errors: Account-required and parser failures as notices or failure replies.
- Example: `AUTOJOIN ADD #zig`
- Sources: `src/daemon/modules/user_query.zig:85`, `src/daemon/server.zig:5627`, `src/daemon/server.zig:8513`

## GROUP

- Syntax: `GROUP ...`
- Description: Account-grouping command surface. The handler delegates to the group implementation and emits its responses.
- Privileges: Registered client.
- Parameters: Parsed by handler.
- Replies: Server `NOTICE` or failure replies from handler.
- Errors: Handler-specific validation failures.
- Example: `GROUP LIST`
- Sources: `src/daemon/modules/user_query.zig:86`, `src/daemon/server.zig:5668`

## WELCOME

- Syntax: `WELCOME [topic]`
- Description: Sends welcome/onboarding text to the caller.
- Privileges: Registered client.
- Parameters: Optional handler-specific selector.
- Replies: Server notices/welcome text.
- Errors: Handler-specific validation failures.
- Example: `WELCOME`
- Sources: `src/daemon/modules/user_query.zig:87`, `src/daemon/server.zig:5738`

## SUMMON

- Syntax: `SUMMON <nick> <#channel>`
- Description: Oper-only force-join. Onyx Server repurposes the obsolete host-paging
  command as a direct operator command that resolves the target user, runs the
  same join path as `FORCEJOIN`, and returns `RPL_SUMMONING 342`.
- Privileges: Operator.
- Parameters: Target nick and channel name.
- Replies: `RPL_SUMMONING 342`.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOSUCHNICK 401`, join validation errors.
- Example: `SUMMON alice #ops`
- Sources: `src/daemon/modules/feature_misc.zig:36`, `src/daemon/server.zig` `handleSummon`
