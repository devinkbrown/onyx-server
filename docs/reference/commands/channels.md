# Channel commands

*Membership, moderation, topic and mode control, plus extended channel-administration services.*

The channel command module registers the base membership and moderation commands (`src/daemon/modules/channel_ops.zig:56`, `src/daemon/modules/channel_ops.zig:59`). IRCX channel-administration commands are split between `channel.ops` for `CREATE` and the `ircx` module for `PROP`, `ACCESS`, and `MODEX` (`src/daemon/modules/channel_ops.zig:67`, `src/daemon/modules/ircx.zig:56`, `src/daemon/modules/ircx.zig:65`). Extended service commands such as `CLEAR` and `TEMPMODE` are registered in `services.ext` (`src/daemon/modules/services_ext.zig:44`, `src/daemon/modules/services_ext.zig:63`).

## JOIN

- Syntax: `JOIN <#chan[,#chan...]> [key[,key...]]` or `JOIN 0`
- Description: Joins channels from positional comma lists. `joinOne` enforces channel-name length, `CHANLIMIT`, Warden quarantine, TLS/account/invite/key/ban gates, join throttle, limit forwarding, IRCX tier keys, automatic topic and NAMES, bouncer rewind, and mesh membership propagation.
- Privileges: Registered client.
- Parameters: Channel list; optional key list. The special target `0` parts every current channel.
- Replies: `JOIN` broadcast, `RPL_TOPIC 332` or `RPL_NOTOPIC 331`, `RPL_NAMREPLY 353`, `RPL_ENDOFNAMES 366`; may emit `ERR_LINKCHANNEL 470` for forward.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOSUCHCHANNEL 403`, `ERR_TOOMANYCHANNELS 405`, `ERR_BANNEDFROMCHAN 474`, `ERR_SECUREONLYCHAN 489`, `ERR_NEEDREGGEDNICK 477`, `ERR_INVITEONLYCHAN 473`, `ERR_BADCHANNELKEY 475`, `ERR_THROTTLE 480`, `ERR_CHANNELISFULL 471`, `ERR_UNAVAILRESOURCE 437`.
- Example: `JOIN #zig,#ops hunter2,`
- Sources: `src/daemon/modules/channel_ops.zig:59`, `src/daemon/server.zig:11441`, `src/daemon/server.zig:11446`, `src/daemon/server.zig:11516`, `src/daemon/server.zig:11665`, `src/daemon/server.zig:11745`

## PART

- Syntax: `PART <#chan[,#chan...]> [:reason]`
- Description: Parts comma-separated channels with a shared optional reason, broadcasts `PART`, removes membership, and announces membership removal to mesh peers.
- Privileges: Registered client.
- Parameters: Channel list; optional reason.
- Replies: `PART` broadcast.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOSUCHCHANNEL 403`, `ERR_NOTONCHANNEL 442`.
- Example: `PART #zig :later`
- Sources: `src/daemon/modules/channel_ops.zig:60`, `src/daemon/server.zig:11777`, `src/daemon/server.zig:11791`, `src/daemon/server.zig:11839`

## NAMES

- Syntax: `NAMES [#channel]`
- Description: Emits channel names. Bare `NAMES` sends a NAMES burst for each channel visible to the requester and skips secret (`+s`), hidden (`+h`), and private (`+p`) channels unless the requester is an oper or member. `NAMES #channel` returns a bare `RPL_ENDOFNAMES 366` for an unknown but syntactically valid channel. For an existing secret (`+s`) or private (`+p`) channel, a non-member non-oper also receives only `366` and never the member list. IRCv3 `multi-prefix` and
  IRCX/NAMEX sessions receive every visible status prefix; network operators
  carrying `oper_override` render with the derived leading `*` prefix.
- Privileges: Registered client.
- Parameters: Optional channel name.
- Replies: `RPL_NAMREPLY 353`, `RPL_ENDOFNAMES 366`.
- Errors: `ERR_NOSUCHCHANNEL 403` only for an explicit invalid channel name.
- Example: `NAMES #zig`
- Sources: `src/daemon/modules/channel_ops.zig:61`, `src/daemon/server.zig:11846`, `src/daemon/server.zig:11848`, `src/daemon/server.zig:11869`, `src/daemon/server.zig:11878`, `src/daemon/server.zig:11889`, `src/daemon/server.zig:12676`, `src/daemon/server.zig:12828`

## MODE

- Syntax: `MODE <#channel|nick|ISIRCX> [modes [args...]]`
- Description: Handles channel mode query and set, own user-mode query and set, IRCX `MODE ISIRCX` discovery, and oper-only user `+z` gag control. A channel mode query returns mode letters and hides `+k` and `+l` values from non-members. Channel setting supports member tiers, list modes, boolean flags, key and limit, throttle, forward, private/hidden flags, and IRCX extension flags.
- Privileges: Registered client; channel mutations require channel privilege; some extension flags and user `+z` require oper.
- Parameters: Target plus optional mode string and arguments.
- Replies: `RPL_CHANNELMODEIS 324`, `RPL_CREATIONTIME 329`, `RPL_UMODEIS 221`, list numerics (`367/368`, `346/347`, `348/349`, `728/729`), `RPL_IRCX 800`, or `MODE` broadcasts.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOSUCHCHANNEL 403`, `ERR_NOTONCHANNEL 442`, `ERR_CHANOPRIVSNEEDED 482`, `ERR_NOSUCHNICK 401`, `ERR_USERNOTINCHANNEL 441`, `ERR_USERSDONTMATCH 502`, `ERR_BANLISTFULL 478`, `ERR_NOPRIVILEGES 481`.
- Example: `MODE #zig +nt`
- Sources: `src/daemon/modules/channel_ops.zig:62`, `src/daemon/server.zig:11965`, `src/daemon/server.zig:11971`, `src/daemon/server.zig:12005`, `src/daemon/server.zig:12111`, `src/daemon/server.zig:12199`, `src/daemon/server.zig:12232`, `src/daemon/server.zig:12412`

### Channel mode inventory

- ISUPPORT `CHANMODES`: `beIZ,k,lfj,imnstCTNMSgWOAVUFD`.
- ISUPPORT `PREFIX`: `(YQqov)*!.@+`. `Y`/`*` is derived from the `oper_override` privilege, not grantable channel state; grantable member modes are founder `Q`/`!`, owner `q`/`.`, operator `o`/`@`, and voice `v`/`+`.
- List modes: `b` ban, `e` exempt, `I` invite-exception, `Z` quiet.
- Parameter modes: `k` key on set/unset, `l` limit on set, `f` forward target on set, `j` join throttle on set.
- Core flag modes: `i`, `m`, `n`, `t`, `s`, `C`, `T`, `N`, `g`, `S`, `M`, `W`, `O`, `A`.
- IRCX extension flags are defined by `chanmode_ext`: `p`, `h`, `s`, `m`, `t`, `i`, `n`, `u`, `a`, `f`, `d`, `E`, `r`, `z`, `x`, `w`, `V`, `U`, `F`, `D`. Direct `MODE` handles `p`/`h` separately, treats `f` as the core forward mode, and falls through to `chanmode_ext` for non-core extension letters; `MODEX NOFORMAT` is the named path for the extension `f`.
- Sources: `src/proto/protocol_inventory.zig:58`, `src/proto/protocol_inventory.zig:59`, `src/daemon/dispatch.zig:55`, `src/daemon/dispatch.zig:2789`, `src/daemon/dispatch.zig:2817`, `src/daemon/chanmode.zig:399`, `src/proto/chanmode_ext.zig:51`, `src/daemon/server.zig:12232`, `src/daemon/server.zig:12412`, `src/daemon/server.zig:30968`

## KICK

- Syntax: `KICK <#channel> <nick> [:reason]`
- Description: Removes a channel member. Kicker must be operator-or-higher and cannot kick a higher-ranked member unless server-oper.
- Privileges: Registered channel member with operator rank or server oper.
- Parameters: Channel, target nick, optional reason truncated to configured `KICKLEN`.
- Replies: `KICK` broadcast before removal.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOSUCHCHANNEL 403`, `ERR_NOTONCHANNEL 442`, `ERR_CHANOPRIVSNEEDED 482`, `ERR_USERNOTINCHANNEL 441`.
- Example: `KICK #zig badnick :rules`
- Sources: `src/daemon/modules/channel_ops.zig:63`, `src/daemon/server.zig:12568`, `src/daemon/server.zig:12577`, `src/daemon/server.zig:12597`, `src/daemon/server.zig:12613`

## INVITE

- Syntax: `INVITE <nick> <#channel>`
- Description: Invites a nick. Existing `+i` channels require channel operator unless `+g` free-invite is set or the caller has operator override.
- Privileges: Registered channel member; channel operator for invite-only channels unless `+g` is set; operator override may bypass channel membership and operator gates.
- Parameters: Nick and channel.
- Replies: `RPL_INVITING 341` to inviter and `INVITE` line to target.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOSUCHCHANNEL 403`, `ERR_NOTONCHANNEL 442`, `ERR_USERONCHANNEL 443`, `ERR_CHANOPRIVSNEEDED 482`, `ERR_NOSUCHNICK 401`.
- Example: `INVITE alice #zig`
- Sources: `src/daemon/modules/channel_ops.zig:64`, `src/daemon/server.zig:13471`, `src/daemon/server.zig:13484`, `src/daemon/server.zig:13488`, `src/daemon/server.zig:13500`

## TOPIC

- Syntax: `TOPIC <#channel> [:topic]`
- Description: With one parameter, returns current topic or no-topic. With topic text, sets and broadcasts it; `+t` or services topic lock requires operator status unless the caller has operator override. Text is UTF-8 boundary truncated to configured `TOPICLEN`.
- Privileges: Registered client; setter must be on channel and satisfy `+t` gate.
- Parameters: Channel; optional topic.
- Replies: `RPL_TOPIC 332`, `RPL_NOTOPIC 331`, or `TOPIC` broadcast.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOSUCHCHANNEL 403`, `ERR_NOTONCHANNEL 442`, `ERR_CHANOPRIVSNEEDED 482`.
- Example: `TOPIC #zig :Onyx Server development`
- Sources: `src/daemon/modules/channel_ops.zig:65`, `src/daemon/server.zig:29987`, `src/daemon/server.zig:29999`, `src/daemon/server.zig:30008`, `src/daemon/server.zig:30024`, `src/daemon/server.zig:30036`

## KNOCK

- Syntax: `KNOCK <#channel> [:reason]`
- Description: Sends a knock request to channel operators. Refused if the channel does not exist, caller is already on it, or the channel is open.
- Privileges: Registered client.
- Parameters: Channel and optional reason.
- Replies: `RPL_KNOCK 710` to operators and `RPL_KNOCKDLVR 711` to caller.
- `711` is sent only when a local operator was notified.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOSUCHCHANNEL 403`, `ERR_KNOCKONCHAN 714`, `ERR_CHANOPEN 713`.
- Example: `KNOCK #private :please`
- Sources: `src/daemon/modules/channel_ops.zig:66`, `src/daemon/server.zig:13821`

## CREATE

- Syntax: `CREATE <#channel> [modes] [clone-source]`
- Description: IRCX channel creation. The target must not already exist. With a clone source, the source channel's channel-level modes and portable room metadata are copied before requested initial modes are applied on top. Creation delegates through the normal JOIN path after parsing, so the creator receives founder status through the channel creation path.
- Privileges: Registered client.
- Parameters: Channel; optional initial mode string; optional clone-source channel.
- Replies: Same join/topic/NAMES surface as `JOIN`, plus inherited or requested `MODE` broadcasts when modes are applied.
- Errors: `ERR_NEEDMOREPARAMS 461` for invalid create syntax, `ERR_CHANNELEXIST 926` when the target already exists, `ERR_NOSUCHCHANNEL 403` for a missing clone source; join and mode errors from delegated paths.
- Example: `CREATE #new`
- Sources: `src/daemon/modules/channel_ops.zig:67`, `src/proto/ircx_create.zig:63`, `src/proto/ircx_create.zig:111`, `src/daemon/server.zig:21225`, `src/daemon/server.zig:21235`, `src/daemon/server.zig:21239`, `src/daemon/server.zig:21262`, `src/daemon/server.zig:21275`

## PROP

- Syntax: `PROP <entity> [<key[,key...]> [:<value>]]`
- Description: IRCX property list/get/set/delete. One parameter lists properties for an entity, two parameters get one or more comma-separated keys, and three parameters set a value; an empty trailing value deletes. Channel built-ins such as `MEMBERKEY`/`MEMBERLIMIT` write through to live channel state before generic PROP storage.
- Privileges: Registered client; writes require operator status for channel/member entities, self-ownership for user entities, or server operator status.
- Parameters: Entity id (`#channel`, nick, or channel-member entity), optional key list, optional value.
- Replies: `RPL_PROPLIST 818`, `RPL_PROPEND 819`; successful built-in writes may also broadcast equivalent `MODE`.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOACCESS 913`, `ERR_BADVALUE 906`.
- IRCX key ladder: secret channel keys are read-gated per tier: `FOUNDERKEY` requires founder, `OWNERKEY` owner, `HOSTKEY` operator, `VOICEKEY` voice, and `MEMBERKEY` any member; server operators can read all. On keyed JOIN, the current handler reads `FOUNDERKEY`, `OWNERKEY`, and `HOSTKEY` as raw secret props and grants founder, owner, or operator status respectively when the presented key matches.
- Example: `PROP #zig SUBJECT :Onyx Server development`
- Sources: `src/daemon/modules/ircx.zig:65`, `src/daemon/server.zig:11665`, `src/daemon/server.zig:11678`, `src/daemon/server.zig:11683`, `src/daemon/server.zig:19694`, `src/daemon/server.zig:19738`, `src/daemon/server.zig:19759`, `src/daemon/server.zig:20437`, `src/daemon/server.zig:20449`, `src/daemon/server.zig:20464`, `src/daemon/server.zig:20499`, `src/daemon/server.zig:20509`, `src/proto/ircx_prop_store.zig:111`, `src/proto/ircx_prop_store.zig:187`

## ACCESS

- Syntax: `ACCESS <#channel> <ADD|DELETE|LIST|CLEAR> [level] [mask] [duration] [:reason]`
- Description: IRCX per-channel access masks. `ADD` stores a level/mask with optional duration and reason, `DELETE` removes one level/mask, `LIST` returns matching entries, and `CLEAR` removes matching entries. Matching `DENY` entries block JOIN; matching grant entries can auto-apply member status on JOIN.
- Privileges: Registered client; server operators can manage any channel. `FOUNDER` entries require founder, `OWNER` entries require owner or founder, and `HOST`/`VOICE`/`GRANT`/`DENY` entries require channel operator or higher.
- Parameters: Channel, subcommand, optional level (`FOUNDER`, `OWNER`, `HOST`, `VOICE`, `GRANT`, `DENY`), optional hostmask, optional duration seconds, optional reason.
- Replies: `RPL_ACCESSADD 801`, `RPL_ACCESSDELETE 802`, `RPL_ACCESSSTART 803`, `RPL_ACCESSENTRY 804`, `RPL_ACCESSEND 805`.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_CHANOPRIVSNEEDED 482`, `ERR_NOPRIVILEGES 481`.
- Example: `ACCESS #zig ADD VOICE *!*@trusted.example 3600 :temporary voice`
- Sources: `src/daemon/modules/ircx.zig:66`, `src/daemon/server.zig:11691`, `src/daemon/server.zig:18363`, `src/daemon/server.zig:19582`, `src/daemon/server.zig:19600`, `src/proto/ircx_access_store.zig:12`, `src/proto/ircx_access_store.zig:79`, `src/proto/ircx_access_store.zig:380`, `src/proto/ircx_access_store.zig:465`

## MODEX

- Syntax: `MODEX <#channel[,nick]> [+|-<named-mode> ...]`
- Description: IRCX named-mode front-end. Bare `MODEX #channel` queries active base and IRCX extension modes as names. Set forms translate named channel/member modes to regular mode letters and delegate to the normal MODE engine, except named extension flags without core-mode storage are applied directly and broadcast as `MODE`.
- Privileges: Registered client; queries require the target channel to exist; mutations use the normal channel-mode privilege gates, with server-operator-only gates for `CLONE`, `REGISTERED`, and `SERVICE`.
- Parameters: Channel target, or `#channel,nick` for member status names; optional signed named mode tokens.
- Replies: `RPL_MODEXLIST 826`, `RPL_MODEXEND 827`, or normal `MODE` broadcasts.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOSUCHCHANNEL 403`, `ERR_NOTONCHANNEL 442`, `ERR_CHANOPRIVSNEEDED 482`, `ERR_NOPRIVILEGES 481`.
- Example: `MODEX #zig +AUTHONLY +FREETARGET`
- Sources: `src/daemon/modules/ircx.zig:70`, `src/proto/ircx_modex.zig:103`, `src/proto/ircx_modex.zig:219`, `src/proto/ircx_modex.zig:248`, `src/proto/ircx_modex.zig:271`, `src/proto/ircx_modex.zig:300`, `src/daemon/server.zig:17444`, `src/daemon/server.zig:17459`, `src/daemon/server.zig:17489`, `src/daemon/server.zig:17531`, `src/daemon/server.zig:30968`

## RENAME

- Syntax: `RENAME <old-channel> <new-channel> [:reason]`
- Description: Renames a channel when the caller is on it and has operator authority.
- Privileges: Registered channel operator.
- Parameters: Old channel, new channel, optional reason.
- Replies: Rename notification/broadcast from handler.
- Errors: `ERR_NOSUCHCHANNEL 403`, `ERR_NOTONCHANNEL 442`, `ERR_CHANOPRIVSNEEDED 482`, parser errors as `ERR_NEEDMOREPARAMS 461`.
- Example: `RENAME #old #new :new name`
- Sources: `src/daemon/modules/channel_ops.zig:68`, `src/daemon/server.zig:13869`

## CHANBADWORDS

- Syntax: `CHANBADWORDS <#channel> <ADD|DEL|LIST> [pattern]`
- Description: Maintains a durable, case-insensitive substring filter for one channel. Matching messages from non-operators/non-opers are blocked; the list survives restart through account services.
- Privileges: Channel operator or network oper; the caller must be on the channel for ordinary channel-op checks.
- Replies: Notices for each listed pattern and add/delete outcome, followed by an end marker for `LIST`.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOSUCHCHANNEL 403`, `ERR_NOTONCHANNEL 442`, `ERR_CHANOPRIVSNEEDED 482`, or temporary service errors.
- Example: `CHANBADWORDS #zig ADD slur`
- Sources: `src/daemon/modules/channel_ops.zig:69`, `src/daemon/server.zig:22100` (`handleChanbadwords`), `src/daemon/svc_chanbadwords.zig`

## AKICK

- Syntax: `CHANNEL AKICK <#channel> <ADD|DEL|LIST> [mask] [reason...]`
- Description: Manages the registered-channel auto-kick list through the services `CHANNEL` command. Entries are persisted to the services store and mirrored into the in-memory join gate; a matching mask (or `account:<name>` mask) is denied entry at JOIN, even when re-creating an empty registered channel. There is no separate top-level `AKICK` command: the earlier in-memory-only variant was removed to avoid a divergent second store.
- Privileges: Logged-in services account with AKICK-management access (founder/admin) on the registered channel.
- Parameters: Channel, subcommand, optional mask/reason.
- Replies: Server `NOTICE` list/add/delete responses.
- Errors: `FAIL CHANNEL` standard replies (`ACCOUNT_REQUIRED`, `NEED_MORE_PARAMS`, services access/lookup failures).
- Example: `CHANNEL AKICK #zig ADD *!*@bad.example spam`
- Sources: `src/daemon/server.zig` (`handleChannel` AKICK arm), join gate `akickDenied` in `joinOne`/`joinDenied`

## CLEAR

- Syntax: `CLEAR <#channel> USERS [KEEP <rank>] [ALLOW <acct[,acct]>] [:reason]`
- Description: Mass-kicks members below a keep rank, except allowed accounts. Requires founder rank or server oper.
- Privileges: Registered client; channel founder or oper.
- Parameters: Parsed by the mass-kick parser from reassembled command text.
- Replies: `KICK` broadcasts plus final server `NOTICE` count.
- Errors: `ERR_NOSUCHCHANNEL 403`, `ERR_NOTONCHANNEL 442`, `ERR_CHANOPRIVSNEEDED 482`; parser errors are sent as server notices.
- Example: `CLEAR #zig USERS KEEP op :reset`
- Sources: `src/daemon/modules/services_ext.zig:63`, `src/daemon/server.zig:18832`

## TEMPMODE

- Syntax: `TEMPMODE ADD <#chan> <flag> [param] <duration> | TEMPMODE CANCEL <#chan> <flag> [param] | TEMPMODE SWEEP`
- Description: Adds a boolean channel mode now and schedules an automatic revert, cancels scheduled reverts, or lets an oper sweep due reverts.
- Privileges: Registered client; channel operator or oper for add/cancel; oper for `SWEEP`.
- Parameters: Subcommand-specific channel, mode flag, optional parameter, duration.
- Replies: `MODE` broadcast for adds; server `NOTICE` for cancel/sweep.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOSUCHCHANNEL 403`, `ERR_CHANOPRIVSNEEDED 482`, `ERR_UNKNOWNMODE 472`, `ERR_NOPRIVILEGES 481`.
- Example: `TEMPMODE ADD #zig m 60000`
- Sources: `src/daemon/modules/services_ext.zig:64`, `src/daemon/server.zig:18917`
