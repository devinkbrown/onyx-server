# Messaging commands

*Text delivery, tag-only messages, redaction, editing, search, history playback, metadata, and caller-side filtering.*

The messaging module registers `PRIVMSG`, `NOTICE`, `TAGMSG`, `REDACT`, `EDIT`, `CHATHISTORY`, `SEARCH`, `MARKREAD`, `PINS`, `METADATA`, `MONITOR`, and `SILENCE` (`src/daemon/modules/messaging.zig:59`, `src/daemon/modules/messaging.zig:62`). `WHISPER` is registered by the IRCX module (`src/daemon/modules/ircx.zig:56`, `src/daemon/modules/ircx.zig:64`). `ACCEPT` is registered by the user query module (`src/daemon/modules/user_query.zig:72`, `src/daemon/modules/user_query.zig:86`).

## IRCv3 message layer

- Capabilities: `message-tags`, `echo-message`, `draft/chathistory`, `draft/search`, `draft/message-redaction`, `draft/message-editing`, `draft/read-marker`, `draft/typing`, `draft/react`, `draft/reply`, `batch`, `standard-replies`, `labeled-response`, and `draft/multiline` are advertised from the live CAP table.
- Message tags: Recipients with `message-tags` receive server tags such as `time`, `account`, `msgid`, and `bot`; client-only tags are relayed only when allowed by the recipient's negotiated capability. The server tag prefix leaves the oper tag off.
- Typing, reactions, and replies: `TAGMSG` relays general client-only tags to `message-tags` recipients, and relays `+typing`, `+draft/react`, `+draft/unreact`, and `+draft/reply` to recipients that negotiated their specific draft capability. Channel typing/reaction tags also feed the activity stream. A subscriber who joins that stream late can read the stored tally with `ACTIVITY TALLY`.
- Labeled response: When a client negotiated `labeled-response` and sends `@label=<value>`, replies from a command are reframed as a labeled single line, a `labeled-response` batch, or a bare labeled ACK for commands with no output.
- Standard replies: The server advertises `standard-replies`. Messaging errors that call `failReply` emit `FAIL <command> <code> :<reason>` for clients with the cap and fall back to a server `NOTICE` text for clients without it. The messaging handlers verified here use `FAIL`; no live messaging `WARN` or `NOTE` emitter was found in `server.zig`.
- Multiline: Clients with `draft/multiline` may send `BATCH +<ref> draft/multiline <target>` containing `@batch=<ref>` `PRIVMSG` or `NOTICE` chunks. The assembler enforces configured byte/line/ref/target limits, supports `draft/multiline-concat`, and delivers the reassembled value through the normal message engine. An inbound batch reassembles into one value, and a long server reply stays a single IRC line.
- Sources: `src/daemon/dispatch.zig:316`, `src/daemon/dispatch.zig:366`, `src/daemon/dispatch.zig:406`, `src/daemon/dispatch.zig:411`, `src/daemon/dispatch.zig:425`, `src/daemon/server.zig:7047`, `src/daemon/server.zig:29187`, `src/daemon/server.zig:29253`, `src/daemon/server.zig:30355`, `src/daemon/server.zig:8333`, `src/daemon/server.zig:27305`

## PRIVMSG

- Syntax: `PRIVMSG <target>[,<target>...] :<text>`
- Description: Sends text to a nick, a channel, or a status-prefixed channel target. The handler applies sender silence gates, UTF-8 and content gates, channel mode gates, direct-message gates, `SILENCE`, echo-message, history recording, away and CTCP auto-replies, mesh relay, and the caller's `MAXTARGETS` fan-out cap. A connection class can tighten that cap with `max_targets`.
- Privileges: Registered client.
- Parameters: One or more comma-separated targets and non-empty text.
- Replies: Delivery line to recipients; `RPL_AWAY 301` when messaging an away user; CTCP `VERSION`, `PING`, `TIME`, `CLIENTINFO`, and `SOURCE` requests can produce a CTCP `NOTICE` reply.
- Errors: `ERR_NORECIPIENT 411`, `ERR_NOTEXTTOSEND 412`, `ERR_NOSUCHNICK 401`, `ERR_NOSUCHCHANNEL 403`, `ERR_CANNOTSENDTOCHAN 404`, `ERR_TOOMANYTARGETS 407`, `ERR_CHANOPRIVSNEEDED 482`, `ERR_NEEDREGGEDNICK 477`, caller-id `ERR_CANTSENDTOUSER 716` / `RPL_TARGNOTIFY 717`, IRCv3 `FAIL` for invalid UTF-8, content-filter blocks, encrypted-message policy, and CTCP blocks. With active durable mesh (`MESSAGE_V2`) authoring, channel messages and token-addressed direct messages are delivered only after durable admission succeeds. Admission error or authority rejection fails `PRIVMSG` with `TEMPORARILY_UNAVAILABLE`; `NOTICE` stays silent, and neither command falls through to local or legacy delivery. ADS1 attachment-spool pressure is distinct: after the MESSAGE_V2 authorities have admitted the event, a missing attachment batch may use ordinary SendQ delivery without weakening the admission boundary.
- Example: `PRIVMSG #ops :status?`
- Sources: `src/daemon/modules/messaging.zig:10`, `src/daemon/server.zig:29398`, `src/daemon/server.zig:29410`, `src/daemon/server.zig:29418`, `src/daemon/server.zig:29451`, `src/daemon/server.zig:29730`, `src/daemon/server.zig:29822`, `src/daemon/server.zig:29868`, `src/daemon/server.zig:29898`, `src/daemon/server.zig:29948`

## NOTICE

- Syntax: `NOTICE <target>[,<target>...] :<text>`
- Description: Uses the same delivery engine as `PRIVMSG`, including channel and direct-message gates, echo-message, message tags, mesh relay, and the caller's fan-out cap. `NOTICE` does not reset idle time, does not record direct-message history, does not emit away or CTCP auto-replies, and suppresses parameter, content, channel, and target delivery errors to avoid automatic reply loops.
- Privileges: Registered client.
- Parameters: One or more comma-separated targets and text; missing target or missing text is silently dropped.
- Replies: Delivery line to recipients.
- Errors: The handler suppresses missing-recipient/text, invalid UTF-8, content-filter, channel, and no-such-nick errors for `NOTICE`. Current source still emits `ERR_TOOMANYTARGETS 407` from the shared pre-target fan-out cap when the comma-separated target list exceeds the cap; this is the only verified `NOTICE` error path in this handler.
- Example: `NOTICE suzu :heads up`
- Sources: `src/daemon/modules/messaging.zig:14`, `src/daemon/server.zig:29407`, `src/daemon/server.zig:29418`, `src/daemon/server.zig:29451`, `src/daemon/server.zig:29511`, `src/daemon/server.zig:29524`, `src/daemon/server.zig:29696`, `src/daemon/server.zig:29730`, `src/daemon/server.zig:29822`, `src/daemon/server.zig:29948`

## CTCP and DCC

- CTCP payloads are parsed from `PRIVMSG` and `NOTICE` bodies. Direct `PRIVMSG` CTCP requests for `VERSION`, `PING`, `TIME`, `CLIENTINFO`, and `SOURCE` receive CTCP `NOTICE` replies; `ACTION` is delivered as ordinary message content.
- User mode `+C` and channel mode `+C` block CTCP requests except `ACTION`, returning `FAIL PRIVMSG CTCP_BLOCKED` for direct messages or `ERR_CANNOTSENDTOCHAN 404` for channels.
- DCC is parser-only in Onyx Server: CTCP can classify DCC frames, but the server provides no DCC proxy, filehost, or relay behavior.
- Sources: `src/proto/ctcp.zig:4`, `src/proto/ctcp.zig:45`, `src/daemon/server.zig:29960`, `src/daemon/server.zig:38541`, `src/daemon/server.zig:38576`, `src/daemon/server.zig:38663`

## TAGMSG

- Syntax: `TAGMSG <target>`
- Description: Sends an IRCv3 tag-only message to a nick or channel. The handler requires a usable tag capability, strips forged server tags and disallowed/duplicate client tags, mints a `msgid`, records eligible typing/reaction TAGMSG history, and uses normal channel speech checks.
- Privileges: Registered client with `message-tags` or a specific draft tag capability such as `draft/typing`, `draft/react`, or `draft/reply`.
- Parameters: `target` is required; no text body is accepted.
- Replies: Raw `TAGMSG` to recipients whose negotiated caps allow at least one relayed tag.
- Errors: `ERR_UNKNOWNCOMMAND 421` when the client has no usable TAGMSG capability, `ERR_NOSUCHCHANNEL 403`, `ERR_CANNOTSENDTOCHAN 404`; missing target or missing relayed tags are silently dropped.
- Example: `@+typing=active TAGMSG #chat`
- Sources: `src/daemon/modules/messaging.zig:18`, `src/daemon/server.zig:29187`, `src/daemon/server.zig:29191`, `src/daemon/server.zig:29195`, `src/daemon/server.zig:29205`, `src/daemon/server.zig:29225`, `src/daemon/server.zig:29253`, `src/daemon/server.zig:30355`, `src/daemon/server.zig:37997`, `src/daemon/server.zig:38039`

## REDACT

- Syntax: `REDACT <channel> <msgid> [:reason]`
- Description: Tombstones a known channel message id in the CHATHISTORY ring, removes it from the search index, publishes an oper audit event, and broadcasts `REDACT` to recipients with `draft/message-redaction`. When the daemon records a proof id, the successful redaction reason carries `proof=<id>`.
- Privileges: Registered client that negotiated `draft/message-redaction` and is a channel operator.
- Parameters: Channel, message id, optional reason.
- Replies: `REDACT <channel> <msgid> [:reason]` to the channel scope for capable recipients.
- Errors: `FAIL REDACT NEED_REGISTRATION`, `ERR_NEEDMOREPARAMS 461`, `ERR_NOSUCHCHANNEL 403`, `ERR_NOTONCHANNEL 442`, `ERR_CHANOPRIVSNEEDED 482`, `FAIL REDACT UNKNOWN_MSGID`.
- Example: `REDACT #chat abc123 :cleanup`
- Sources: `src/daemon/modules/messaging.zig:22`, `src/daemon/server.zig:21546`, `src/daemon/server.zig:21550`, `src/daemon/server.zig:21554`, `src/daemon/server.zig:21561`, `src/daemon/server.zig:21565`, `src/daemon/server.zig:21573`, `src/daemon/server.zig:21604`

## EDIT

- Syntax: `EDIT <target> <msgid> :<text>`
- Description: Updates a message in the history ring and replays the edited body as a tagged `PRIVMSG` carrying `+draft/edit=<msgid>` and `+draft/revision=1`. Only the original sender may edit; channel operators cannot edit other users' messages.
- Privileges: Registered client that negotiated `draft/message-editing`.
- Parameters: Target, message id, and non-empty replacement text.
- Replies: Edited `PRIVMSG` to recipients with `draft/message-editing`; the sender is echoed for direct-message edits.
- Errors: `FAIL EDIT NEED_REGISTRATION`, `FAIL EDIT INVALID_PARAMS`, `ERR_NOSUCHCHANNEL 403`, `ERR_NOTONCHANNEL 442`, `ERR_NOSUCHNICK 401`, `FAIL EDIT UNKNOWN_MSGID`, `FAIL EDIT PERMISSION_DENIED`, `FAIL EDIT EDIT_FAILED`.
- Example: `EDIT #chat abc123 :corrected text`
- Sources: `src/daemon/modules/messaging.zig:26`, `src/daemon/server.zig:21608`, `src/daemon/server.zig:21612`, `src/daemon/server.zig:21616`, `src/daemon/server.zig:21627`, `src/daemon/server.zig:21641`, `src/daemon/server.zig:21647`, `src/daemon/server.zig:21652`, `src/daemon/server.zig:21660`, `src/daemon/server.zig:21671`

## CHATHISTORY

- Syntax: `CHATHISTORY <subcommand> <target> ...`
- Description: Parses the IRCv3 CHATHISTORY request, checks visibility, reads the live Lotus history ring, applies optional `+onyx/topic=<label>` filtering, and renders history lines using standard batch framing when appropriate. Retained messages carry message ids and server-time tags; edits update the stored body and redactions tombstone future replay.
- Privileges: Registered client that negotiated `draft/chathistory`.
- Parameters: Parsed by the chathistory subsystem from the raw line.
- Replies: History lines, usually in a `chathistory` `BATCH` when the client has `batch`.
- Errors: `FAIL CHATHISTORY NEED_REGISTRATION`, `FAIL CHATHISTORY <code>` for malformed requests, `FAIL CHATHISTORY REPLAY_TOO_LARGE`, and visibility failures such as `FAIL CHATHISTORY ACCESS_DENIED`.
- Example: `CHATHISTORY LATEST #chat * 20`
- Sources: `src/daemon/modules/messaging.zig:30`, `src/daemon/server.zig:15016`, `src/daemon/server.zig:15026`, `src/daemon/server.zig:15038`, `src/daemon/server.zig:15042`, `src/daemon/server.zig:15140`, `src/daemon/server.zig:45294`

## SEARCH

- Syntax: `SEARCH <target> :<query>`
- Description: Searches the bounded CHATHISTORY inverted index. Query words are AND-matched, results are re-scoped to the requested target's visible history, capped newest-first, and replayed through the CHATHISTORY renderer. Channel targets require membership; non-channel targets search the requester's direct-message history with that peer.
- Privileges: Registered client that negotiated `draft/search`.
- Parameters: Target and non-empty query text.
- Replies: Matching history lines in a `chathistory` batch when the client has `batch`, or plain history lines otherwise.
- Errors: `FAIL SEARCH NEED_REGISTRATION`, `FAIL SEARCH INVALID_PARAMS`, `FAIL SEARCH RATE_LIMITED`, `FAIL SEARCH INVALID_TARGET`.
- Example: `SEARCH #chat :release checklist`
- Sources: `src/daemon/modules/messaging.zig:34`, `src/daemon/server.zig:15176`, `src/daemon/server.zig:15190`, `src/daemon/server.zig:15209`, `src/daemon/server.zig:15214`, `src/daemon/server.zig:15221`, `src/daemon/server.zig:15235`, `src/daemon/server.zig:45042`, `src/daemon/server.zig:45125`

## MARKREAD

- Syntax: `MARKREAD <target> [timestamp=<timestamp>|*]`
- Description: Implements IRCv3 read-marker for the caller's account when logged in, otherwise the caller's nick. The one-parameter form returns the stored marker, the timestamp form advances it monotonically, and joins can push the stored marker to clients with `draft/read-marker`.
- Privileges: Registered client that negotiated `draft/read-marker`.
- Parameters: Parsed marker arguments from the read-marker store.
- Replies: Read-marker response line built by the read-marker subsystem.
- Errors: `FAIL MARKREAD NEED_REGISTRATION`, `ERR_NEEDMOREPARAMS 461` for invalid parameters.
- Example: `MARKREAD #chat timestamp=2026-06-10T12:00:00Z`
- Sources: `src/daemon/modules/messaging.zig:38`, `src/daemon/server.zig:14285`, `src/daemon/server.zig:14288`, `src/daemon/server.zig:14294`, `src/daemon/server.zig:14316`, `src/daemon/server.zig:14423`, `src/proto/read_marker_store.zig:170`, `src/proto/read_marker_store.zig:212`

## WHISPER

- Syntax: `WHISPER <channel> <nick[,nick...]> :<text>`
- Description: Sends an IRCX channel-scoped private message. The sender must be on the channel, `+w` NOWHISPER must be absent, and every local recipient must also be on the same channel. Remote recipients are relayed only when the mesh roster shows the nick as a co-member of the channel; unknown remote recipients fail closed instead of flooding peers.
- Privileges: Registered client using the IRCX command surface.
- Parameters: Channel, one or more comma-separated nicks, and non-empty text.
- Replies: `:sender WHISPER <channel> <nick> :<text>` to each valid recipient.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOSUCHCHANNEL 403`, `ERR_NOTONCHANNEL 442`, `ERR_NOWHISPER 923`, `ERR_NOSUCHNICK 401`, `ERR_USERNOTINCHANNEL 441`.
- Example: `WHISPER #chat suzu :psst`
- Sources: `src/daemon/modules/ircx.zig:23`, `src/daemon/server.zig:21090`, `src/daemon/server.zig:21096`, `src/daemon/server.zig:21100`, `src/daemon/server.zig:21104`, `src/daemon/server.zig:21108`, `src/daemon/server.zig:21118`, `src/daemon/server.zig:21168`, `src/proto/whisper.zig:4`

## PINS

- Syntax: `PINS <#channel> [LIST|ADD <msgid>|DEL <msgid>|CLEAR]`
- Description: Lists or edits the channel's pinned message ids through the live `PINS` channel PROP. The command uses the same validation, signed channel-prop storage, local IRCX PROP notification, and mesh propagation path as `PROP <#channel> PINS :...`.
- Privileges: Channel member or operator may list; channel operator or network operator may add, delete, or clear.
- Parameters: Channel; optional subcommand and message id.
- Replies: `:<server> PINS <#channel> :<comma-separated-msgids>` with an empty trailing value when no pins remain.
- Errors: `ERR_NOSUCHCHANNEL 403`, `ERR_NOTONCHANNEL 442`, `ERR_CHANOPRIVSNEEDED 482`, `ERR_BADVALUE 906`, `ERR_NEEDMOREPARAMS 461`, IRCv3 `FAIL PINS INVALID_SUBCOMMAND`.
- Example: `PINS #chat ADD 01HMSGID`
- Sources: `src/daemon/modules/messaging.zig:42`, `src/daemon/server.zig:14364`, `src/daemon/server.zig:14367`

## METADATA

- Syntax: `METADATA <target> <GET|LIST|SET|CLEAR> [key] [visibility] [value]`
- Description: Implements IRCv3 metadata-2 operations over the live metadata store. `*` aliases the requesting client for storage while replies echo the literal target.
- Privileges: Registered client that negotiated `draft/metadata-2`; mutations require write permission on the target.
- Parameters: Target, subcommand, and optional key/visibility/value as parsed by the handler.
- Replies: `RPL_KEYVALUE 761`, `RPL_METADATAEND 762` when listing/querying.
- Errors: `ERR_UNKNOWNCOMMAND 421` without the cap, `ERR_KEYNOTSET 766`, `ERR_KEYINVALID 767`, `ERR_KEYNOPERMISSION 769`, `ERR_NEEDMOREPARAMS 461`.
- Example: `METADATA * LIST`
- Sources: `src/daemon/modules/messaging.zig:46`, `src/daemon/server.zig:21399`, `src/daemon/server.zig:21401`

## MONITOR

- Syntax: `MONITOR <+|-|C|L|S> [nick[,nick]...]`
- Description: Manages the caller's monitor set and emits online/offline/list numerics. A connection class can tighten the monitor add cap.
- Privileges: Registered client.
- Parameters: Parsed monitor operation and optional nick list.
- Replies: `RPL_MONONLINE 730`, `RPL_MONOFFLINE 731`, `RPL_MONLIST 732`, `RPL_ENDOFMONLIST 733`.
- Errors: `ERR_MONLISTFULL 734`, `ERR_NEEDMOREPARAMS 461`.
- Example: `MONITOR + alice,bob`
- Sources: `src/daemon/modules/messaging.zig:50`, `src/daemon/server.zig:13946`, `src/daemon/server.zig:13948`

## SILENCE

- Syntax: `SILENCE [<mask>|+<mask>|-<mask>]`
- Description: Lists, adds, or removes sender masks in the caller's silence list. Incoming private messages from matching masks are silently dropped.
- Privileges: Registered client.
- Parameters: Bare command lists; `+mask` adds; `-mask` removes.
- Replies: `RPL_SILELIST 271`, `RPL_ENDOFSILELIST 272`.
- Errors: `ERR_NEEDMOREPARAMS 461` for invalid masks.
- Example: `SILENCE +*!*@bad.example`
- Sources: `src/daemon/modules/messaging.zig:54`, `src/daemon/server.zig:14432`, `src/daemon/server.zig:14435`, `src/daemon/server.zig:29918`

## ACCEPT

- Syntax: `ACCEPT [+nick|-nick|*|...]`
- Description: Manages the caller-id allow list keyed by the caller's nick. Bare command or `*` lists entries.
- Privileges: Registered client.
- Parameters: One or more add/remove/list tokens.
- Replies: `RPL_ACCEPTLIST 281`, `RPL_ENDOFACCEPT 282`.
- Errors: `ERR_NEEDMOREPARAMS 461` for invalid input.
- Example: `ACCEPT +alice -mallory`
- Sources: `src/daemon/modules/user_query.zig:51`, `src/daemon/server.zig:16072`, `src/daemon/server.zig:16074`, `src/daemon/server.zig:16093`
