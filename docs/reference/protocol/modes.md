# Onyx Server modes

*Current user, member-status, and channel modes Onyx Server recognizes, drawn from live source.*

This page documents current source only. The advertised channel-mode token is derived by `deriveChanmodes` and is `CHANMODES=beIZ,k,lfj,imntsCTNgSMWOAphuadErzxwVUFDcBK` (`src/proto/protocol_inventory.zig:69`, `src/proto/protocol_inventory.zig:71`). Class D is every extended channel letter except `f`. `f` stays the ordinary MODE forward parameter in class C; MODEX still names that letter NOFORMAT. ISUPPORT also advertises `CALLERID=g` and `DEAF=D` (`src/proto/protocol_inventory.zig:155`, `src/proto/protocol_inventory.zig:156`). The vendor cap `onyx/privacy` has value `umode=DGIZTVW,cmode=cBK` (`src/daemon/dispatch.zig:451`). The server does not send CAP NEW for these modes. `PREFIX` is appended by the daemon from `chanmode.MemberModes.isupport_prefix`, whose current value is `PREFIX=(YQqov)*!.@+` (`src/daemon/server.zig:1309`, `src/daemon/server.zig:1311`, `src/daemon/chanmode.zig:399`, `src/daemon/chanmode.zig:405`). The advertised `CHANMODES` token is guarded by an honesty test that checks every advertised letter against the live mode handlers (`src/daemon/dispatch.zig:3301`).

## User modes

`MODE <nick> [modes]` lets a client view or change only its own client-writable modes. Normal cross-user changes return `ERR_USERSDONTMATCH`; opers have two special cross-user paths: IRCX `+z` GAG and the server-managed media modes `+M`/`+P` (`src/daemon/server.zig:11983`, `src/daemon/server.zig:11997`, `src/daemon/server.zig:12467`, `src/daemon/server.zig:12526`). The self-user handler applies catalog entries whose policy is `client_writable`, ignores server-managed and unknown letters, and gates `+j` on `oper_override` (`src/daemon/server.zig:12496`, `src/daemon/server.zig:12502`, `src/daemon/server.zig:12503`, `src/daemon/server.zig:12507`).

| Letter | Name | Policy | Who Sets It | Meaning / Current Behavior | Evidence |
| --- | --- | --- | --- | --- | --- |
| `o` | operator | derived | Server on OPER/SASL elevation. | Rendered from `is_oper`; not client-settable and not part of the catalog bitset. | `src/proto/usermode.zig:166`, `src/daemon/dispatch.zig:1160`, `src/daemon/server.zig:22576` |
| `i` | invisible | client-writable | User via `MODE <ownnick> +/-i`. | Hidden from WHO/ISON unless requester is self, oper, or shares a channel. | `src/proto/usermode.zig:148`, `src/daemon/server.zig:12500`, `src/daemon/server.zig:12732` |
| `B` | bot | client-writable | User via `MODE <ownnick> +/-B`. | IRCv3 bot mode; advertised through ISUPPORT `BOT=B`. | `src/proto/usermode.zig:149`, `src/proto/protocol_inventory.zig:95` |
| `r` | registered | server-managed | Server-side catalog only; no client write path. | Read-only to clients; marks registered identity when set by server code. | `src/proto/usermode.zig:150`, `src/proto/usermode.zig:226` |
| `z` | secure-tls / GAG letter | server-managed; special IRCX GAG letter in oper cross-user path. | Server-side catalog for secure TLS state; opers may use user-target MODE `+z` as GAG on another user. | Clients cannot set the catalog bit; cross-user `+z` records an IP-backed GAG and marks matching sessions gagged. | `src/proto/usermode.zig:151`, `src/daemon/server.zig:11896`, `src/daemon/server.zig:11929`, `src/daemon/server.zig:11984` |
| `D` | deaf | client-writable | User. | Drops channel PRIVMSG, NOTICE, and TAGMSG for this member. JOIN, PART, MODE, QUIT, DATA, KICK, and WHISPER still arrive. Direct messages still arrive. The sender's echo-message copy is not dropped. Not shown in WHOIS. Advertised as ISUPPORT `DEAF=D`. | `src/proto/usermode.zig:19`, `src/daemon/server.zig:13782`, `src/daemon/server.zig:22269` |
| `g` | callerid | client-writable | User. | Direct messages require ACCEPT, same-account, self, or oper bypass. | `src/proto/usermode.zig:153`, `src/daemon/server.zig:29882`, `src/daemon/server.zig:29897` |
| `C` | no-ctcp | client-writable | User. | Blocks direct CTCP PRIVMSG to this user. Channel `+C` separately blocks channel CTCP from non-ops. | `src/proto/usermode.zig:154`, `src/daemon/server.zig:29874`, `src/daemon/server.zig:29877` |
| `x` | cloaked | server-managed | Server-side catalog only; no client write path. | Read-only catalog flag for cloaked host state. | `src/proto/usermode.zig:155`, `src/proto/usermode.zig:226` |
| `R` | regonly-pm | client-writable | User. | Rejects direct PRIVMSG/NOTICE from unauthenticated non-oper senders. | `src/proto/usermode.zig:156`, `src/daemon/server.zig:29864`, `src/daemon/server.zig:29869` |
| `p` | hide-chans | client-writable | User. | Suppresses own channel list in WHOIS for non-opers. | `src/proto/usermode.zig:157`, `src/daemon/server.zig:13242` |
| `Q` | no-forward | client-writable | User. | User opt-out of channel forward behavior. | `src/proto/usermode.zig:158`, `src/daemon/server.zig:11498`, `src/daemon/server.zig:11500` |
| `H` | hide-oper | client-writable | User. | Hides operator status from WHOIS/WHO for non-opers. | `src/proto/usermode.zig:159`, `src/daemon/server.zig:12715`, `src/daemon/server.zig:12719` |
| `M` | media-tx-deny | server-managed | Server/oper cross-user mode path. | Blocks media offer/join/unmute/speaking and WebSocket media datagrams. | `src/proto/usermode.zig:160`, `src/daemon/server.zig:12546`, `src/daemon/server.zig:25972`, `src/daemon/server.zig:26282` |
| `P` | media-presence-private | client-writable; oper cross-user path also accepts it. | User or oper media-mode path. | Suppresses automatic media presence broadcasts. | `src/proto/usermode.zig:161`, `src/daemon/server.zig:12546`, `src/daemon/server.zig:26349`, `src/daemon/server.zig:26352` |
| `a` | admin | server-managed | Server on operator elevation with `server_admin`. | Tracks network-administrator privilege; cleared when oper status is cleared. | `src/proto/usermode.zig:162`, `src/daemon/dispatch.zig:980`, `src/daemon/dispatch.zig:1001`, `src/daemon/dispatch.zig:1022` |
| `j` | override | client-writable, privilege-gated | Operator holding `oper_override`; optional auto-enable at elevation. | Enables audited channel override behavior. | `src/proto/usermode.zig:163`, `src/daemon/server.zig:12503`, `src/daemon/server.zig:22606`, `src/daemon/server.zig:27318` |
| `G` | common-chan | client-writable | User. | A direct PRIVMSG requires a shared channel, an ACCEPT entry, the same account, an oper, or self. Otherwise numeric 716 `is in +G mode (share a channel or ACCEPT)`. NOTICE is dropped with no numeric and no 718. Checked after `+Z`, so a cleartext sender who also fails `+G` gets the TLS numeric. WHOIS 320 says the user only accepts private messages from users who share a channel. | `src/proto/usermode.zig:33`, `src/proto/usermode.zig:171`, `src/daemon/server.zig:59948`, `src/daemon/whois.zig:252` |
| `Z` | tls-only-pm | client-writable | User. | A local direct PRIVMSG requires a TLS sender, self, an oper, or the same account. ACCEPT does not bypass it. A relay frame has no authenticated TLS bit, so a remote sender fails closed unless the sender is this nick or the same account. PRIVMSG is 716 `is in +Z mode (TLS required)`. NOTICE is silent. WHOIS 320 says the user only accepts private messages over TLS. | `src/proto/usermode.zig:34`, `src/proto/usermode.zig:172`, `src/daemon/server.zig:59941`, `src/daemon/server.zig:14208`, `src/daemon/whois.zig:255` |
| `I` | hide-idle | client-writable | User. | WHOIS omits RPL_WHOISIDLE (317) unless the requester is the target or a server operator. | `src/proto/usermode.zig:35`, `src/proto/usermode.zig:173`, `src/daemon/server.zig:24762` |
| `V` | no-invite | client-writable | User. | After INVITE preconditions allow, a local target in `+V` is not invited unless the inviter is a server operator or the same account. The INVITE is not delivered and no invite is recorded. Numeric 716 `is in +V mode (not accepting invites)`. WHOIS 320 says the user is not accepting invites. | `src/proto/usermode.zig:36`, `src/proto/usermode.zig:174`, `src/daemon/server.zig:25050`, `src/daemon/whois.zig:258` |
| `W` | whois-notify | client-writable | User. | After the WHOIS reply is queued, the target receives `NOTICE` `{requester} is doing a /whois on you` from the server name. A self-WHOIS and an oper WHOIS do not notify. | `src/proto/usermode.zig:37`, `src/proto/usermode.zig:175`, `src/daemon/server.zig:24799` |
| `T` | no-chan-notice | client-writable | User. | Drops channel NOTICE for this member. Channel PRIVMSG still arrives. This is a user mode. Channel `+T` is a separate channel flag. Not shown in WHOIS. | `src/proto/usermode.zig:38`, `src/proto/usermode.zig:176`, `src/daemon/server.zig:13789` |

Onyx Server divergence: legacy wallops and snomask do not use user `+w`. Operator notifications ride the Event Spine as raw `EVENT` lines, replacing legacy snote/wallops broadcast channels (`src/daemon/dispatch.zig:910`).

## Member status modes and prefixes

The visible prefix ladder is network operator `+Y` (`*`) > founder `+Q` (`!`) > owner `+q` (`.`) > op `+o` (`@`) > voice `+v` (`+`) (`src/daemon/chanmode.zig:399`, `src/daemon/chanmode.zig:405`). `+Y` is derived from operator privilege and is never stored as a member status mode (`src/daemon/chanmode.zig:327`, `src/daemon/chanmode.zig:332`). Host access/key grants map to `+o`, not to a separate wire prefix (`src/daemon/server.zig:2691`, `src/daemon/server.zig:2695`, `src/daemon/server.zig:11683`, `src/daemon/server.zig:11686`).

| Mode | Prefix | Rank | Param | Who Sets It | Notes | Evidence |
| --- | --- | ---: | --- | --- | --- | --- |
| `Y` | `*` | derived above 4 | none | Server render layer for opers with `oper_override`. | Not grantable through channel MODE; shown in NAMES/WHO and announced as synthetic `+Y`. | `src/daemon/chanmode.zig:327`, `src/daemon/server.zig:11188`, `src/daemon/server.zig:30125`, `src/daemon/server.zig:30177` |
| `Q` | `!` | 4 | target nick | First joiner at channel creation; services/CREATE paths may restore founder. | Cannot be added by ordinary channel MODE; highest stored rank. | `src/daemon/world.zig:625`, `src/daemon/world.zig:627`, `src/daemon/world.zig:634`, `src/daemon/server.zig:12122`, `src/daemon/server.zig:12126` |
| `q` | `.` | 3 | target nick | Founder/owner-level actor with sufficient rank. | Owner tier; admin/service access aliases to stored op where applicable, not a distinct wire mode. | `src/daemon/chanmode.zig:423`, `src/daemon/chanmode.zig:427`, `src/daemon/server.zig:12116`, `src/daemon/server.zig:12174` |
| `o` | `@` | 2 | target nick | Op or higher. | Grants channel operator authority; host grants map here. | `src/daemon/chanmode.zig:423`, `src/daemon/chanmode.zig:428`, `src/daemon/server.zig:12118`, `src/daemon/server.zig:11686` |
| `v` | `+` | 1 | target nick | Op or higher. | May speak in `+m` moderated channels. | `src/daemon/chanmode.zig:418`, `src/daemon/chanmode.zig:420`, `src/daemon/server.zig:12119` |

Rank gating: a member may set or clear only a tier whose required rank is at or below their own rank, and may not change a higher-ranked member unless an active server override applies (`src/daemon/server.zig:12149`, `src/daemon/server.zig:12155`, `src/daemon/server.zig:12159`, `src/daemon/server.zig:12167`).

**Modes combined per line** are advertised through the `MODES` ISUPPORT token, sourced from `[limits] modes_per_line` (default `4`, range `1..20`) and appended by `buildIsupportTokens` (`src/daemon/server.zig:1313`, `src/daemon/server.zig:1316`). The token tunes how many changes a client should batch; the server itself parses a full multi-mode `MODE` line.

**Cross-node MODE attribution:** when a member-prefix MODE is applied to a user homed on another mesh node, the remote node renders the change under the setter's nick, not the origin server. The setter is carried by the membership announcement (`src/daemon/server.zig:12187`, `src/daemon/server.zig:12196`).

## Advertised channel mode classes

| Class | Advertised Letters | Param Rules | Source |
| --- | --- | --- | --- |
| A list modes | `b`, `e`, `I`, `Z` | Take a mask parameter for add/remove; no parameter queries the list. | `src/proto/protocol_inventory.zig:59`, `src/daemon/server.zig:12276`, `src/daemon/server.zig:12357` |
| B parameter modes | `k` | Takes a key on set; unset echo uses `*`. | `src/proto/protocol_inventory.zig:59`, `src/daemon/chanmode.zig:102`, `src/daemon/server.zig:12243` |
| C parameter-on-set modes | `l`, `f`, `j` | `+l` takes numeric limit; `+f` takes forward channel; `+j` takes `joins:seconds`; unset is bare. | `src/proto/protocol_inventory.zig:59`, `src/daemon/server.zig:12261`, `src/daemon/server.zig:12358`, `src/daemon/server.zig:12378` |
| D flags | `imntsCTNgSMWOAphuadErzxwVUFDcBK` | No parameter. Source order from the base catalog, then each extended letter except `f`. `c`, `B`, and `K` are NOCOLOR, NOBOT, and FOUNDERKICK. | `src/proto/protocol_inventory.zig:77`, `src/daemon/dispatch.zig:3317`, `src/proto/chanmode_ext.zig:75` |

## Channel list modes

| Letter | Name | Param | Who Sets It | Meaning | Evidence |
| --- | --- | --- | --- | --- | --- |
| `b` | ban | mask | Channel op or higher. | Blocks matching JOIN unless exempted by `+e`; supports extended-ban context in world checks. | `src/daemon/chanmode.zig:99`, `src/daemon/server.zig:11380`, `src/daemon/server.zig:12276`, `src/daemon/world.zig:1201` |
| `e` | exempt | mask | Channel op or higher. | Ban/quiet exception list; overrides `+b` and `+Z` checks. | `src/daemon/chanmode.zig:100`, `src/daemon/server.zig:12297`, `src/daemon/world.zig:1201`, `src/daemon/world.zig:1208` |
| `I` | invite-exception | mask | Channel op or higher. | Lets matching users bypass `+i`. | `src/daemon/chanmode.zig:101`, `src/daemon/server.zig:11391`, `src/daemon/server.zig:12317`, `src/daemon/world.zig:1216` |
| `Z` | quiet / mute | mask | Channel op or higher. | Suppresses speech for matching masks without blocking JOIN; `+e` exempts and `+U` can route held messages to ops. | `src/daemon/server.zig:12337`, `src/daemon/server.zig:29160`, `src/daemon/server.zig:29161`, `src/daemon/world.zig:1208` |

List modes are capped by `World.max_list_entries`; exceeding the cap returns `ERR_BANLISTFULL` (`src/daemon/world.zig:123`, `src/daemon/world.zig:303`, `src/daemon/world.zig:992`, `src/daemon/server.zig:11959`).

## Channel parameter modes

| Letter | Name | Param | Who Sets It | Meaning | Evidence |
| --- | --- | --- | --- | --- | --- |
| `k` | key | key on set; unset echo uses `*` | Channel op or higher. | Requires matching JOIN key. | `src/daemon/chanmode.zig:102`, `src/daemon/server.zig:11400`, `src/daemon/server.zig:12243`, `src/daemon/world.zig:774` |
| `l` | limit | integer on set; no param on unset | Channel op or higher. | Maximum member count; blocked JOIN returns `ERR_CHANNELISFULL`, with `+f` forward considered first. | `src/daemon/chanmode.zig:103`, `src/daemon/server.zig:11583`, `src/daemon/server.zig:11588`, `src/daemon/server.zig:12261` |
| `j` | join throttle | `joins:seconds` on set; no param on unset | Channel op or higher. | At most N joins per window; blocked JOIN returns `ERR_THROTTLE`. | `src/daemon/server.zig:11561`, `src/daemon/server.zig:11575`, `src/daemon/server.zig:12358`, `src/daemon/world.zig:1133` |
| `f` | forward | target channel on set; no param on unset | Channel op or higher, with target-side permission unless oper. | Redirects refused JOINs to another channel; target must be valid and, unless `+F`, controlled by setter. | `src/daemon/server.zig:11496`, `src/daemon/server.zig:11504`, `src/daemon/server.zig:12378`, `src/daemon/server.zig:12394` |

## Channel flag modes

| Letter | Name | Param | Who Sets It | Meaning | Evidence |
| --- | --- | --- | --- | --- | --- |
| `i` | invite-only | none | Channel op or higher. | JOIN requires invite or `+I` exception. | `src/daemon/chanmode.zig:104`, `src/daemon/server.zig:11391` |
| `m` | moderated | none | Channel op or higher. | Only voiced or operator-tier members may speak. | `src/daemon/chanmode.zig:105`, `src/daemon/chanmode.zig:418`, `src/daemon/server.zig:29132` |
| `n` | no-external | none | Channel op or higher. | Non-members cannot message the channel. | `src/daemon/chanmode.zig:106`, `src/daemon/server.zig:29124` |
| `t` | topic-ops | none | Channel op or higher. | Only channel operators may change topic. | `src/daemon/chanmode.zig:107`, `src/daemon/server.zig:10781`, `src/daemon/server.zig:10788`, `src/daemon/server.zig:30017` |
| `s` | secret | none | Channel op or higher. | Hidden from LIST and gates NAMES/WHO/WHOIS roster visibility. | `src/daemon/chanmode.zig:108`, `src/daemon/server.zig:11878`, `src/daemon/server.zig:12901`, `src/daemon/server.zig:12937` |
| `C` | no-ctcp | none | Channel op or higher. | Blocks channel CTCP except ACTION from non-ops. | `src/daemon/chanmode.zig:109`, `src/daemon/server.zig:29115`, `src/daemon/server.zig:29172` |
| `T` | no-notice | none | Channel op or higher. | Drops channel NOTICE from non-ops. | `src/daemon/chanmode.zig:110`, `src/daemon/server.zig:29116`, `src/daemon/server.zig:29176` |
| `N` | no-nick | none | Channel op or higher. | Blocks nick changes by non-ops while joined. | `src/daemon/chanmode.zig:111`, `src/daemon/server.zig:22083`, `src/daemon/server.zig:22091` |
| `M` | moderate-unregistered | none | Channel op or higher. | Unauthenticated members need voice/operator tier to speak. | `src/daemon/chanmode.zig:114`, `src/daemon/server.zig:29103`, `src/daemon/server.zig:29141` |
| `S` | tls-only | none | Channel op or higher. | JOIN only over TLS unless server oper. | `src/daemon/chanmode.zig:113`, `src/daemon/server.zig:11310`, `src/daemon/server.zig:11312` |
| `g` | free-invite | none | Channel op or higher. | Any member may INVITE while `+i`. | `src/daemon/chanmode.zig:112`, `src/daemon/server.zig:13489`, `src/proto/invite.zig:143`, `src/proto/invite.zig:145` |
| `W` | news-wire | none | Channel op or higher. | Enables in-channel `!news` and `!localnews`. `!weather` and `!forecast` do not need `+W`. | `src/daemon/chanmode.zig:115`, `src/daemon/server.zig:19134`, `src/daemon/server.zig:19246`, `src/daemon/server.zig:19252` |
| `O` | oper-only | none | Server oper only. | JOIN requires server operator status. | `src/daemon/chanmode.zig:116`, `src/daemon/server.zig:11317`, `src/daemon/server.zig:11319`, `src/daemon/server.zig:12217` |
| `A` | admin-only | none | Server oper only. | JOIN requires server administrator privileges. | `src/daemon/chanmode.zig:117`, `src/daemon/server.zig:11323`, `src/daemon/server.zig:11327`, `src/daemon/server.zig:12217` |
| `V` | NOCOMICDATA | none | Channel op or higher. | Refuses IRCX DATA from members below channel-op unless they are server opers. | `src/proto/chanmode_ext.zig:68`, `src/daemon/server.zig:12415`, `src/daemon/server.zig:20963`, `src/daemon/server.zig:20970` |
| `U` | OPMODERATE | none | Channel op or higher. | Routes messages blocked by moderation gates (`+m`, `+M`, `+Z`) to ops instead of rejecting them. | `src/proto/chanmode_ext.zig:69`, `src/daemon/server.zig:29129`, `src/daemon/server.zig:29161`, `src/daemon/server.zig:29767` |
| `F` | FREETARGET | none | Channel op or higher. | Allows channels to be forward targets without target-side op check. | `src/proto/chanmode_ext.zig:70`, `src/daemon/server.zig:12385`, `src/daemon/server.zig:12394` |
| `D` | DISFORWARD | none | Channel op or higher. | Refuses use as a forward target. | `src/proto/chanmode_ext.zig:71`, `src/daemon/server.zig:11504`, `src/daemon/server.zig:11506` |

The compact `chanmode.zig` catalog covers `b e I k l i m n t s C T N g S M W O A` (`src/daemon/chanmode.zig:98`). The live channel-MODE handler additionally enforces `Z`, `j`, `f`, `p`, `h`, and the IRCX extended flags through `server.zig`, `world.zig`, and `chanmode_ext.zig` (`src/daemon/server.zig:12199`, `src/daemon/server.zig:12232`, `src/daemon/server.zig:12412`, `src/proto/chanmode_ext.zig:51`).

## IRCX extended channel flags

The live MODE handler recognizes extended channel flags through `chanmode_ext.letterToFlag`; oper-only extended flags require server operator status (`src/daemon/server.zig:12415`, `src/daemon/server.zig:12416`, `src/proto/chanmode_ext.zig:237`, `src/proto/chanmode_ext.zig:255`). Every extended letter except `f` is advertised in CHANMODES class D. The packed flag word keeps the first twenty flags in bits 0–19. `c`, `B`, and `K` occupy bits 20, 21, and 22. The checkpoint and mode-state masks are `(1 << 23) - 1` (`0x007fffff`). The base channel-mode mask stays `0x3fff`. The world checkpoint version stays 2. A peer that does not know the new bits rejects a frame that sets them.

| Letter | IRCX Name | Oper Only | Meaning / Current Storage | Evidence |
| --- | --- | --- | --- | --- |
| `p` | PRIVATE | No | Private channel flag stored separately in `World.Channel`; gates NAMES/WHO rosters for non-members and non-opers. | `src/proto/chanmode_ext.zig:52`, `src/daemon/world.zig:926`, `src/daemon/server.zig:12232`, `src/daemon/server.zig:11878`, `src/daemon/server.zig:12829` |
| `h` | HIDDEN | No | Hidden channel flag stored separately in `World.Channel`; omitted from LIST and bare NAMES enumeration. | `src/proto/chanmode_ext.zig:53`, `src/daemon/world.zig:938`, `src/daemon/server.zig:12232`, `src/daemon/server.zig:11848`, `src/daemon/server.zig:12937` |
| `u` | KNOCK | No | Enables KNOCK behavior. | `src/proto/chanmode_ext.zig:59`, `src/daemon/server.zig:13840` |
| `a` | AUTHONLY | No | Requires authenticated user to JOIN. | `src/proto/chanmode_ext.zig:60`, `src/daemon/server.zig:10149`, `src/daemon/server.zig:11334` |
| `f` | NOFORMAT | No | Strips IRC formatting before channel delivery. | `src/proto/chanmode_ext.zig:61`, `src/daemon/server.zig:7595`, `src/daemon/server.zig:29756` |
| `d` | CLONEABLE | No | Channel clone/template flag. | `src/proto/chanmode_ext.zig:62`, `src/daemon/world.zig:823`, `src/daemon/server.zig:11586` |
| `E` | CLONE | Yes | Marks cloned channel. | `src/proto/chanmode_ext.zig:63`, `src/daemon/world.zig:869`, `src/daemon/world.zig:870` |
| `r` | REGISTERED | Yes | Persistent registered channel flag. | `src/proto/chanmode_ext.zig:64`, `src/daemon/world.zig:728`, `src/daemon/world.zig:736` |
| `z` | SERVICE | Yes | Service channel flag. | `src/proto/chanmode_ext.zig:65`, `src/proto/chanmode_ext.zig:255` |
| `x` | AUDITORIUM | No | Auditorium visibility: regular members are hidden from each other in NAMES. | `src/proto/chanmode_ext.zig:66`, `src/daemon/server.zig:30157`, `src/daemon/server.zig:30159` |
| `w` | NOWHISPER | No | Blocks channel WHISPER with `ERR_NOWHISPER`. | `src/proto/chanmode_ext.zig:67`, `src/daemon/server.zig:7678`, `src/daemon/server.zig:21109` |
| `V` | NOCOMICDATA | No | Advertised flag; disables IRCX DATA to the channel for non-op members. | `src/proto/chanmode_ext.zig:68`, `src/daemon/server.zig:20963`, `src/daemon/server.zig:20970` |
| `U` | OPMODERATE | No | Advertised flag; moderation-denied messages are held to ops instead of rejected. | `src/proto/chanmode_ext.zig:69`, `src/daemon/server.zig:29129`, `src/daemon/server.zig:29184` |
| `F` | FREETARGET | No | Advertised flag; allows a channel to be used as a forward target without target-side op check. | `src/proto/chanmode_ext.zig:70`, `src/daemon/server.zig:12385`, `src/daemon/server.zig:12394` |
| `D` | DISFORWARD | No | Advertised flag; refuses use as a forward target. | `src/proto/chanmode_ext.zig:71`, `src/daemon/server.zig:11504`, `src/daemon/server.zig:11506` |
| `c` | NOCOLOR | No | Rejects channel PRIVMSG that contains IRC formatting from a member who is not a channel operator and not a server operator. The founder counts as an operator. NOTICE with those bytes is dropped and produces no numeric. The rejected bytes are 0x02, 0x03, 0x04, 0x0f, 0x11, 0x16, 0x1d, 0x1e, and 0x1f. Numeric 404 `Cannot send to channel (+c: no color or formatting)`. This rejects. `+f` NOFORMAT strips, and its stripper does not treat 0x04 as formatting. Bit 20. | `src/proto/chanmode_ext.zig:75`, `src/proto/chanmode_ext.zig:151`, `src/daemon/server.zig:58630`, `src/daemon/server.zig:72318` |
| `B` | NOBOT | No | An existing channel refuses JOIN from a user in user mode `+B`, including a user who holds an invite. A server operator can join. Creating a channel does not consult this gate, and a member already inside is not removed when the flag is set. Numeric 474 `Cannot join channel (+B) - bots are not allowed`. User `+B` and channel `+B` are different namespaces. Bit 21. | `src/proto/chanmode_ext.zig:76`, `src/proto/chanmode_ext.zig:152`, `src/daemon/server.zig:22479` |
| `K` | FOUNDERKICK | No | After the rank check, a kick requires the kicker to be the founder or a server operator. An ordinary channel op kicking a regular member gets 482 `Cannot kick (+K: founder only)`. An op kicking the founder still fails the higher-rank check first. Bit 22. | `src/proto/chanmode_ext.zig:77`, `src/proto/chanmode_ext.zig:153`, `src/daemon/server.zig:24079` |

Some IRCX names duplicate base flags (`PRIVATE`, `HIDDEN`, `SECRET`, `MODERATED`, `TOPICOP`, `INVITEONLY`, `NOEXTERN`). The live handler special-cases `p` and `h`, routes base letters through the base channel-mode path, and sends remaining recognized letters through `chanmode_ext` (`src/daemon/server.zig:12199`, `src/daemon/server.zig:12232`, `src/daemon/server.zig:12412`, `src/daemon/server.zig:12420`).
