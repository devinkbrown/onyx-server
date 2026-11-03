# Onyx Server modes

*Current user, member-status, and channel modes Onyx Server recognizes, drawn from live source.*

This page documents current source only. The advertised channel-mode token is derived by `deriveChanmodes` and is `CHANMODES=beIZ,k,lfj,imntsCTNgSMWOAphuadErzxwVUFDcBK` (`src/proto/protocol_inventory.zig`). Class D is every extended channel letter except `f`. `f` stays the ordinary MODE forward parameter in class C; MODEX still names that letter NOFORMAT. ISUPPORT also advertises `CALLERID=g` and `DEAF=D` (`src/proto/protocol_inventory.zig`). The vendor cap `onyx/privacy` has value `umode=DGIZTVW,cmode=cBK` (`src/daemon/dispatch.zig`). The server does not send CAP NEW for these modes. `PREFIX` is appended by the daemon from `chanmode.MemberModes.isupport_prefix`, whose current value is `PREFIX=(YQqov)*!.@+` (`src/daemon/server.zig`, `src/daemon/chanmode.zig`). The advertised `CHANMODES` token is guarded by an honesty test that checks every advertised letter against the live mode handlers (`src/daemon/dispatch.zig`).

## User modes

`MODE <nick> [modes]` lets a client view or change only its own client-writable modes. Normal cross-user changes return `ERR_USERSDONTMATCH`; opers have two special cross-user paths: IRCX `+z` GAG and the server-managed media modes `+M`/`+P` (`src/daemon/server.zig`). The self-user handler applies catalog entries whose policy is `client_writable`, ignores server-managed and unknown letters, and gates `+j` on `oper_override` (`src/daemon/server.zig`).

| Letter | Name | Policy | Who Sets It | Meaning / Current Behavior | Evidence |
| --- | --- | --- | --- | --- | --- |
| `o` | operator | derived | Server on OPER/SASL elevation. | Rendered from `is_oper`; not client-settable and not part of the catalog bitset. | `src/proto/usermode.zig`, `src/daemon/dispatch.zig`, `src/daemon/server.zig` |
| `i` | invisible | client-writable | User via `MODE <ownnick> +/-i`. | Hidden from WHO/ISON unless requester is self, oper, or shares a channel. | `src/proto/usermode.zig`, `src/daemon/server.zig` |
| `B` | bot | client-writable | User via `MODE <ownnick> +/-B`. | IRCv3 bot mode; advertised through ISUPPORT `BOT=B`. | `src/proto/usermode.zig`, `src/proto/protocol_inventory.zig` |
| `r` | registered | server-managed | Server-side catalog only; no client write path. | Read-only to clients; marks registered identity when set by server code. | `src/proto/usermode.zig` |
| `z` | secure-tls / GAG letter | server-managed; special IRCX GAG letter in oper cross-user path. | Server-side catalog for secure TLS state; opers may use user-target MODE `+z` as GAG on another user. | Clients cannot set the catalog bit; cross-user `+z` records an IP-backed GAG and marks matching sessions gagged. | `src/proto/usermode.zig`, `src/daemon/server.zig` |
| `D` | deaf | client-writable | User. | Drops channel PRIVMSG, NOTICE, and TAGMSG for this member. JOIN, PART, MODE, QUIT, DATA, KICK, and WHISPER still arrive. Direct messages still arrive. The sender's echo-message copy is not dropped. Not shown in WHOIS. Advertised as ISUPPORT `DEAF=D`. | `src/proto/usermode.zig`, `src/daemon/server.zig` |
| `g` | callerid | client-writable | User. | Direct messages require ACCEPT, same-account, self, or oper bypass. | `src/proto/usermode.zig`, `src/daemon/server.zig` |
| `C` | no-ctcp | client-writable | User. | Blocks direct CTCP PRIVMSG to this user. Channel `+C` separately blocks channel CTCP from non-ops. | `src/proto/usermode.zig`, `src/daemon/server.zig` |
| `x` | cloaked | server-managed | Server-side catalog only; no client write path. | Read-only catalog flag for cloaked host state. | `src/proto/usermode.zig` |
| `R` | regonly-pm | client-writable | User. | Rejects direct PRIVMSG/NOTICE from unauthenticated non-oper senders. | `src/proto/usermode.zig`, `src/daemon/server.zig` |
| `p` | hide-chans | client-writable | User. | Suppresses own channel list in WHOIS for non-opers. | `src/proto/usermode.zig`, `src/daemon/server.zig` |
| `Q` | no-forward | client-writable | User. | User opt-out of channel forward behavior. | `src/proto/usermode.zig`, `src/daemon/server.zig` |
| `H` | hide-oper | client-writable | User. | Hides operator status from WHOIS/WHO for non-opers. | `src/proto/usermode.zig`, `src/daemon/server.zig` |
| `M` | media-tx-deny | server-managed | Server/oper cross-user mode path. | Blocks media offer/join/unmute/speaking and WebSocket media datagrams. | `src/proto/usermode.zig`, `src/daemon/server.zig` |
| `P` | media-presence-private | client-writable; oper cross-user path also accepts it. | User or oper media-mode path. | Suppresses automatic media presence broadcasts. | `src/proto/usermode.zig`, `src/daemon/server.zig` |
| `a` | admin | server-managed | Server on operator elevation with `server_admin`. | Tracks network-administrator privilege; cleared when oper status is cleared. | `src/proto/usermode.zig`, `src/daemon/dispatch.zig` |
| `j` | override | client-writable, privilege-gated | Operator holding `oper_override`; optional auto-enable at elevation. | Enables audited channel override behavior. | `src/proto/usermode.zig`, `src/daemon/server.zig` |
| `G` | common-chan | client-writable | User. | A direct PRIVMSG requires a shared channel, an ACCEPT entry, the same account, an oper, or self. Otherwise numeric 716 `is in +G mode (share a channel or ACCEPT)`. NOTICE is dropped with no numeric and no 718. Checked after `+Z`, so a cleartext sender who also fails `+G` gets the TLS numeric. WHOIS 320 says the user only accepts private messages from users who share a channel. | `src/proto/usermode.zig`, `src/daemon/server.zig`, `src/daemon/whois.zig` |
| `Z` | tls-only-pm | client-writable | User. | A local direct PRIVMSG requires a TLS sender, self, an oper, or the same account. ACCEPT does not bypass it. A relay frame has no authenticated TLS bit, so a remote sender fails closed unless the sender is this nick or the same account. PRIVMSG is 716 `is in +Z mode (TLS required)`. NOTICE is silent. WHOIS 320 says the user only accepts private messages over TLS. | `src/proto/usermode.zig`, `src/daemon/server.zig`, `src/daemon/whois.zig` |
| `I` | hide-idle | client-writable | User. | WHOIS omits RPL_WHOISIDLE (317) unless the requester is the target or a server operator. | `src/proto/usermode.zig`, `src/daemon/server.zig` |
| `V` | no-invite | client-writable | User. | After INVITE preconditions allow, a local target in `+V` is not invited unless the inviter is a server operator or the same account. The INVITE is not delivered and no invite is recorded. Numeric 716 `is in +V mode (not accepting invites)`. WHOIS 320 says the user is not accepting invites. | `src/proto/usermode.zig`, `src/daemon/server.zig`, `src/daemon/whois.zig` |
| `W` | whois-notify | client-writable | User. | After the WHOIS reply is queued, the target receives `NOTICE` `{requester} is doing a /whois on you` from the server name. A self-WHOIS and an oper WHOIS do not notify. | `src/proto/usermode.zig`, `src/daemon/server.zig` |
| `T` | no-chan-notice | client-writable | User. | Drops channel NOTICE for this member. Channel PRIVMSG still arrives. This is a user mode. Channel `+T` is a separate channel flag. Not shown in WHOIS. | `src/proto/usermode.zig`, `src/daemon/server.zig` |

Onyx Server divergence: legacy wallops and snomask do not use user `+w`. Operator notifications ride the Event Spine as raw `EVENT` lines, replacing legacy snote/wallops broadcast channels (`src/daemon/dispatch.zig`).

## Member status modes and prefixes

The visible prefix ladder is network operator `+Y` (`*`) > founder `+Q` (`!`) > owner `+q` (`.`) > op `+o` (`@`) > voice `+v` (`+`) (`src/daemon/chanmode.zig`). `+Y` is derived from operator privilege and is never stored as a member status mode (`src/daemon/chanmode.zig`). Host access/key grants map to `+o`, not to a separate wire prefix (`src/daemon/server.zig`).

| Mode | Prefix | Rank | Param | Who Sets It | Notes | Evidence |
| --- | --- | ---: | --- | --- | --- | --- |
| `Y` | `*` | derived above 4 | none | Server render layer for opers with `oper_override`. | Not grantable through channel MODE; shown in NAMES/WHO and announced as synthetic `+Y`. | `src/daemon/chanmode.zig`, `src/daemon/server.zig` |
| `Q` | `!` | 4 | target nick | First joiner at channel creation; services/CREATE paths may restore founder. | Cannot be added by ordinary channel MODE; highest stored rank. | `src/daemon/world.zig`, `src/daemon/server.zig` |
| `q` | `.` | 3 | target nick | Founder/owner-level actor with sufficient rank. | Owner tier; admin/service access aliases to stored op where applicable, not a distinct wire mode. | `src/daemon/chanmode.zig`, `src/daemon/server.zig` |
| `o` | `@` | 2 | target nick | Op or higher. | Grants channel operator authority; host grants map here. | `src/daemon/chanmode.zig`, `src/daemon/server.zig` |
| `v` | `+` | 1 | target nick | Op or higher. | May speak in `+m` moderated channels. | `src/daemon/chanmode.zig`, `src/daemon/server.zig` |

Rank gating: a member may set or clear only a tier whose required rank is at or below their own rank, and may not change a higher-ranked member unless an active server override applies (`src/daemon/server.zig`).

**Modes combined per line** are advertised through the `MODES` ISUPPORT token, sourced from `[limits] modes_per_line` (default `4`, range `1..20`) and appended by `buildIsupportTokens` (`src/daemon/server.zig`). The token tunes how many changes a client should batch; the server itself parses a full multi-mode `MODE` line.

**Cross-node MODE attribution:** when a member-prefix MODE is applied to a user homed on another mesh node, the remote node renders the change under the setter's nick, not the origin server. The setter is carried by the membership announcement (`src/daemon/server.zig`).

## Advertised channel mode classes

| Class | Advertised Letters | Param Rules | Source |
| --- | --- | --- | --- |
| A list modes | `b`, `e`, `I`, `Z` | Take a mask parameter for add/remove; no parameter queries the list. | `src/proto/protocol_inventory.zig`, `src/daemon/server.zig` |
| B parameter modes | `k` | Takes a key on set; unset echo uses `*`. | `src/proto/protocol_inventory.zig`, `src/daemon/chanmode.zig`, `src/daemon/server.zig` |
| C parameter-on-set modes | `l`, `f`, `j` | `+l` takes numeric limit; `+f` takes forward channel; `+j` takes `joins:seconds`; unset is bare. | `src/proto/protocol_inventory.zig`, `src/daemon/server.zig` |
| D flags | `imntsCTNgSMWOAphuadErzxwVUFDcBK` | No parameter. Source order from the base catalog, then each extended letter except `f`. `c`, `B`, and `K` are NOCOLOR, NOBOT, and FOUNDERKICK. | `src/proto/protocol_inventory.zig`, `src/daemon/dispatch.zig`, `src/proto/chanmode_ext.zig` |

## Channel list modes

| Letter | Name | Param | Who Sets It | Meaning | Evidence |
| --- | --- | --- | --- | --- | --- |
| `b` | ban | mask | Channel op or higher. | Blocks matching JOIN unless exempted by `+e`; supports extended-ban context in world checks. | `src/daemon/chanmode.zig`, `src/daemon/server.zig`, `src/daemon/world.zig` |
| `e` | exempt | mask | Channel op or higher. | Ban/quiet exception list; overrides `+b` and `+Z` checks. | `src/daemon/chanmode.zig`, `src/daemon/server.zig`, `src/daemon/world.zig` |
| `I` | invite-exception | mask | Channel op or higher. | Lets matching users bypass `+i`. | `src/daemon/chanmode.zig`, `src/daemon/server.zig`, `src/daemon/world.zig` |
| `Z` | quiet / mute | mask | Channel op or higher. | Suppresses speech for matching masks without blocking JOIN; `+e` exempts and `+U` can route held messages to ops. | `src/daemon/server.zig`, `src/daemon/world.zig` |

List modes are capped by `World.max_list_entries`; exceeding the cap returns `ERR_BANLISTFULL` (`src/daemon/world.zig`, `src/daemon/server.zig`).

## Channel parameter modes

| Letter | Name | Param | Who Sets It | Meaning | Evidence |
| --- | --- | --- | --- | --- | --- |
| `k` | key | key on set; unset echo uses `*` | Channel op or higher. | Requires matching JOIN key. | `src/daemon/chanmode.zig`, `src/daemon/server.zig`, `src/daemon/world.zig` |
| `l` | limit | integer on set; no param on unset | Channel op or higher. | Maximum member count; blocked JOIN returns `ERR_CHANNELISFULL`, with `+f` forward considered first. | `src/daemon/chanmode.zig`, `src/daemon/server.zig` |
| `j` | join throttle | `joins:seconds` on set; no param on unset | Channel op or higher. | At most N joins per window; blocked JOIN returns `ERR_THROTTLE`. | `src/daemon/server.zig`, `src/daemon/world.zig` |
| `f` | forward | target channel on set; no param on unset | Channel op or higher, with target-side permission unless oper. | Redirects refused JOINs to another channel; target must be valid and, unless `+F`, controlled by setter. | `src/daemon/server.zig` |

## Channel flag modes

| Letter | Name | Param | Who Sets It | Meaning | Evidence |
| --- | --- | --- | --- | --- | --- |
| `i` | invite-only | none | Channel op or higher. | JOIN requires invite or `+I` exception. | `src/daemon/chanmode.zig`, `src/daemon/server.zig` |
| `m` | moderated | none | Channel op or higher. | Only voiced or operator-tier members may speak. | `src/daemon/chanmode.zig`, `src/daemon/server.zig` |
| `n` | no-external | none | Channel op or higher. | Non-members cannot message the channel. | `src/daemon/chanmode.zig`, `src/daemon/server.zig` |
| `t` | topic-ops | none | Channel op or higher. | Only channel operators may change topic. | `src/daemon/chanmode.zig`, `src/daemon/server.zig` |
| `s` | secret | none | Channel op or higher. | Hidden from LIST and gates NAMES/WHO/WHOIS roster visibility. | `src/daemon/chanmode.zig`, `src/daemon/server.zig` |
| `C` | no-ctcp | none | Channel op or higher. | Blocks channel CTCP except ACTION from non-ops. | `src/daemon/chanmode.zig`, `src/daemon/server.zig` |
| `T` | no-notice | none | Channel op or higher. | Drops channel NOTICE from non-ops. | `src/daemon/chanmode.zig`, `src/daemon/server.zig` |
| `N` | no-nick | none | Channel op or higher. | Blocks nick changes by non-ops while joined. | `src/daemon/chanmode.zig`, `src/daemon/server.zig` |
| `M` | moderate-unregistered | none | Channel op or higher. | Unauthenticated members need voice/operator tier to speak. | `src/daemon/chanmode.zig`, `src/daemon/server.zig` |
| `S` | tls-only | none | Channel op or higher. | JOIN only over TLS unless server oper. | `src/daemon/chanmode.zig`, `src/daemon/server.zig` |
| `g` | free-invite | none | Channel op or higher. | Any member may INVITE while `+i`. | `src/daemon/chanmode.zig`, `src/daemon/server.zig`, `src/proto/invite.zig` |
| `W` | news-wire | none | Channel op or higher. | Enables in-channel `!news` and `!localnews`. `!weather` and `!forecast` do not need `+W`. | `src/daemon/chanmode.zig`, `src/daemon/server.zig` |
| `O` | oper-only | none | Server oper only. | JOIN requires server operator status. | `src/daemon/chanmode.zig`, `src/daemon/server.zig` |
| `A` | admin-only | none | Server oper only. | JOIN requires server administrator privileges. | `src/daemon/chanmode.zig`, `src/daemon/server.zig` |
| `V` | NOCOMICDATA | none | Channel op or higher. | Refuses IRCX DATA from members below channel-op unless they are server opers. | `src/proto/chanmode_ext.zig`, `src/daemon/server.zig` |
| `U` | OPMODERATE | none | Channel op or higher. | Routes messages blocked by moderation gates (`+m`, `+M`, `+Z`) to ops instead of rejecting them. | `src/proto/chanmode_ext.zig`, `src/daemon/server.zig` |
| `F` | FREETARGET | none | Channel op or higher. | Allows channels to be forward targets without target-side op check. | `src/proto/chanmode_ext.zig`, `src/daemon/server.zig` |
| `D` | DISFORWARD | none | Channel op or higher. | Refuses use as a forward target. | `src/proto/chanmode_ext.zig`, `src/daemon/server.zig` |

The compact `chanmode.zig` catalog covers `b e I k l i m n t s C T N g S M W O A` (`src/daemon/chanmode.zig`). The live channel-MODE handler additionally enforces `Z`, `j`, `f`, `p`, `h`, and the IRCX extended flags through `server.zig`, `world.zig`, and `chanmode_ext.zig` (`src/daemon/server.zig`, `src/proto/chanmode_ext.zig`).

## IRCX extended channel flags

The live MODE handler recognizes extended channel flags through `chanmode_ext.letterToFlag`; oper-only extended flags require server operator status (`src/daemon/server.zig`, `src/proto/chanmode_ext.zig`). Every extended letter except `f` is advertised in CHANMODES class D. The packed flag word keeps the first twenty flags in bits 0–19. `c`, `B`, and `K` occupy bits 20, 21, and 22. The checkpoint and mode-state masks are `(1 << 23) - 1` (`0x007fffff`). The base channel-mode mask stays `0x3fff`. The world checkpoint version stays 2. A peer that does not know the new bits rejects a frame that sets them.

| Letter | IRCX Name | Oper Only | Meaning / Current Storage | Evidence |
| --- | --- | --- | --- | --- |
| `p` | PRIVATE | No | Private channel flag stored separately in `World.Channel`; gates NAMES/WHO rosters for non-members and non-opers. | `src/proto/chanmode_ext.zig`, `src/daemon/world.zig`, `src/daemon/server.zig` |
| `h` | HIDDEN | No | Hidden channel flag stored separately in `World.Channel`; omitted from LIST and bare NAMES enumeration. | `src/proto/chanmode_ext.zig`, `src/daemon/world.zig`, `src/daemon/server.zig` |
| `u` | KNOCK | No | Enables KNOCK behavior. | `src/proto/chanmode_ext.zig`, `src/daemon/server.zig` |
| `a` | AUTHONLY | No | Requires authenticated user to JOIN. | `src/proto/chanmode_ext.zig`, `src/daemon/server.zig` |
| `f` | NOFORMAT | No | Strips IRC formatting before channel delivery. | `src/proto/chanmode_ext.zig`, `src/daemon/server.zig` |
| `d` | CLONEABLE | No | Channel clone/template flag. | `src/proto/chanmode_ext.zig`, `src/daemon/world.zig`, `src/daemon/server.zig` |
| `E` | CLONE | Yes | Marks cloned channel. | `src/proto/chanmode_ext.zig`, `src/daemon/world.zig` |
| `r` | REGISTERED | Yes | Persistent registered channel flag. | `src/proto/chanmode_ext.zig`, `src/daemon/world.zig` |
| `z` | SERVICE | Yes | Service channel flag. | `src/proto/chanmode_ext.zig` |
| `x` | AUDITORIUM | No | Auditorium visibility: regular members are hidden from each other in NAMES. | `src/proto/chanmode_ext.zig`, `src/daemon/server.zig` |
| `w` | NOWHISPER | No | Blocks channel WHISPER with `ERR_NOWHISPER`. | `src/proto/chanmode_ext.zig`, `src/daemon/server.zig` |
| `V` | NOCOMICDATA | No | Advertised flag; disables IRCX DATA to the channel for non-op members. | `src/proto/chanmode_ext.zig`, `src/daemon/server.zig` |
| `U` | OPMODERATE | No | Advertised flag; moderation-denied messages are held to ops instead of rejected. | `src/proto/chanmode_ext.zig`, `src/daemon/server.zig` |
| `F` | FREETARGET | No | Advertised flag; allows a channel to be used as a forward target without target-side op check. | `src/proto/chanmode_ext.zig`, `src/daemon/server.zig` |
| `D` | DISFORWARD | No | Advertised flag; refuses use as a forward target. | `src/proto/chanmode_ext.zig`, `src/daemon/server.zig` |
| `c` | NOCOLOR | No | Rejects channel PRIVMSG that contains IRC formatting from a member who is not a channel operator and not a server operator. The founder counts as an operator. NOTICE with those bytes is dropped and produces no numeric. The rejected bytes are 0x02, 0x03, 0x04, 0x0f, 0x11, 0x16, 0x1d, 0x1e, and 0x1f. Numeric 404 `Cannot send to channel (+c: no color or formatting)`. This rejects. `+f` NOFORMAT strips, and its stripper does not treat 0x04 as formatting. Bit 20. | `src/proto/chanmode_ext.zig`, `src/daemon/server.zig` |
| `B` | NOBOT | No | An existing channel refuses JOIN from a user in user mode `+B`, including a user who holds an invite. A server operator can join. Creating a channel does not consult this gate, and a member already inside is not removed when the flag is set. Numeric 474 `Cannot join channel (+B) - bots are not allowed`. User `+B` and channel `+B` are different namespaces. Bit 21. | `src/proto/chanmode_ext.zig`, `src/daemon/server.zig` |
| `K` | FOUNDERKICK | No | After the rank check, a kick requires the kicker to be the founder or a server operator. An ordinary channel op kicking a regular member gets 482 `Cannot kick (+K: founder only)`. An op kicking the founder still fails the higher-rank check first. Bit 22. | `src/proto/chanmode_ext.zig`, `src/daemon/server.zig` |

Some IRCX names duplicate base flags (`PRIVATE`, `HIDDEN`, `SECRET`, `MODERATED`, `TOPICOP`, `INVITEONLY`, `NOEXTERN`). The live handler special-cases `p` and `h`, routes base letters through the base channel-mode path, and sends remaining recognized letters through `chanmode_ext` (`src/daemon/server.zig`).
