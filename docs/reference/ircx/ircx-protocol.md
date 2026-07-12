# IRCX

_Opt-in extended IRC commands, channel modes, properties, access lists, events, and media policy integration._

> Historical reference only: this page describes a legacy C IRCX implementation
> (`modules/m_ircx_*.c`). It is not the Orochi Zig implementation source of truth.
> For Orochi, verify current behavior in `src/daemon/modules/ircx.zig`,
> `src/daemon/server.zig`, and the relevant `src/proto/ircx_*.zig` files.

## Overview

In this legacy C implementation, IRCX support is implemented by `modules/m_ircx_*.c`. The base module registers the `IRCX` server capability, the `IRCX` and `ISIRCX` client commands, and the ISUPPORT tokens `IRCX`, `MAXCODEPAGE`, and `MAXLANGUAGE`.

IRCX is explicit opt-in for clients. A client enters IRCX mode by sending `IRCX` or `ISIRCX`; the server sets IRCX/NAMESX state and replies with `RPL_IRCX`. Current source does not force IRCX mode merely because a client becomes an IRC operator.

## Commands

| Command | Default | Description |
| --- | --- | --- |
| `IRCX` | Load `m_ircx_base` | Enables IRCX behavior for the client. |
| `ISIRCX` | Load `m_ircx_base` | Alias path handled like `IRCX`. |
| `AUTH <mechanism> I|S [:data]` | Load `m_ircx_auth` | SASL shorthand for non-CAP clients. `AUTH *` aborts. |
| `CREATE #channel [modes]` | Load `m_ircx_create` | Creates a channel and applies optional modes. |
| `LISTX [filters]` | Load `m_ircx_listx` | Extended list with member count, creation age, topic age, topic-only, and glob filters. |
| `MODEX <target> [modes]` | Load `m_ircx_modex` | Queries or sets named channel/member modes. |
| `PROP <target> ...` | Load `m_ircx_prop` | Gets, sets, clears, persists, and syncs properties. |
| `ACCESS <target> ...` | Load `m_ircx_access` | Manages channel access entries; `ACCESS *` delegates to server-level access when loaded. |
| `SACCESS ...` | Load `m_ircx_access_server` | Server-level DENY, GAG, GRANT, NOCHANNEL, and NONICK access control. |
| `EVENT ...` | Load `m_ircx_event` | Oper event subscriptions. |
| `REQUEST <target> <type> :text` | Load `m_ircx_request` | Sends a typed request and preauthorizes reply. |
| `REPLY <target> <type> :text` | Load `m_ircx_request` | Replies to a request. |
| `WHISPER <#channel> <nick> :text` | Load `m_ircx_whisper` | Sends a private channel-member message unless `+w` blocks it. |
| `DATA <target> <tag> :content` | Load `m_ircx_comic` | Microsoft Comic Chat data relay with tag and payload validation. |
| `GAG ...` | Load `m_ircx_oper` | Oper-only gag control. |
| `OPFORCE ...` | Load `m_ircx_oper` | Oper-only channel force actions. |
| `SVSJOIN` | Load `m_ircx_oper` | Server-service join helper. |

Server-only sync commands include `TACCESS`, `BTACCESS`, `TPROP`, `BTPROP`, `NOCHAN_*`, `NONICK_*`, `GRANT_*`, and `GAG_*`.

## AUTH syntax

```irc
AUTH PLAIN I :AGFsaWNlAHNlY3JldA==
AUTH SCRAM-SHA-256 I :<client-first>
AUTH SCRAM-SHA-256 S :<client-final>
AUTH *
```

The sequence token must be `I` for an initial step or `S` for a continuation step. Abort uses `AUTH *`.

## Channel modes

| Mode | Default | Description |
| --- | --- | --- |
| `PUBLIC` | No visibility mode | MODEX name for public visibility. |
| `+p` `PRIVATE` | Core | Listed but properties are restricted. Clears `+h`. |
| `+h` `HIDDEN` | `m_ircx_modes` | Hidden from LIST/LISTX but queryable by name. Clears `+p` and `+s`. |
| `+s` `SECRET` | Core | Hidden from non-members. Clears `+h`. |
| `+m` `MODERATED` | Core | Only privileged users may speak. |
| `+t` `TOPICOP` | Core | Only channel ops/owners may change topic. |
| `+i` `INVITEONLY` | Core | Requires invite to join. |
| `+n` `NOEXTERN` | Core | Blocks external messages. |
| `+u` `KNOCK` | `m_ircx_modes` | Enables KNOCK notifications. |
| `+a` `AUTHONLY` | `m_ircx_modes` | Only services-identified users may join. |
| `+f` `NOFORMAT` | `m_ircx_modes` | Raw text/no formatting mode. |
| `+d` `CLONEABLE` | `m_ircx_modes` | Allows numbered clones when the channel overflows. |
| `+E` `CLONE` | `m_ircx_modes` | Marks a server-created clone; oper/service-only. |
| `+r` `REGISTERED` | `m_ircx_modes` | Registered/persistent channel; oper/service-only. |
| `+z` `SERVICE` | `m_ircx_modes` | Service-monitoring channel; oper-only. |
| `+x` `AUDITORIUM` | `m_ircx_auditorium` | Hides normal JOIN/PART and limits visible members. |
| `+w` `NOWHISPER` | `m_ircx_whisper` | Blocks `WHISPER`. |
| `+Y` `NOCOMICDATA` | `m_ircx_comic` | Blocks Comic Chat-tagged `DATA`. |

Built-in non-IRCX channel modes still exist, including `+c` no color, `+C` no CTCP, `+S` TLS-only, `+O` oper-only, and `+A` admin-only.

## Member modes

| MODEX Name | Default | Description |
| --- | --- | --- |
| `OWNER` | `+q` | Channel owner. |
| `HOST` | `+o` | Channel operator. |
| `VOICE` | `+v` | Voiced member. |

```irc
MODEX #team
MODEX #team +AUTHONLY +NOFORMAT
MODEX #team,alice +OWNER
```

## Properties

`PROP` supports both legacy positional syntax and explicit verbs:

```irc
PROP #team
PROP #team TOPIC
PROP #team LADON.MEDIA.VOICE :members
PROP #team LADON.MEDIA.VOICE :
PROP #team CLEAR
PROP #team GET TOPIC
PROP #team SET CLIENT :example-web
```

| Property Family | Default | Description |
| --- | --- | --- |
| Channel built-ins | Load `m_ircx_prop_channel_builtins` | `OID`, `NAME`, `CREATION`, `TOPIC`, `MEMBERCOUNT`, `MEMBERKEY`, `MEMBERLIMIT`, `PICS`, `LAG`, and `CLIENT`. |
| Channel keys | Load `m_ircx_prop_ownerkey`, `m_ircx_prop_opkey` | `OWNERKEY`, `OPKEY`, and `HOSTKEY` alias. |
| User profile | Load `m_ircx_prop_user_profile` | `URL`, `GENDER`, `PICTURE`, `LOCATION`, `BIO`, `REALNAME`, `EMAIL`, plus readable user/GeoIP fields such as `NICK`, `COUNTRY`, `REGION`, `CITY`, `ASN`, and `ASORG`. |
| Hooks | Load `m_ircx_prop_onjoin`, `m_ircx_prop_onpart`, `m_ircx_prop_member_of` | Join/part/member property helpers. |

`MAXPROP` is advertised from `ConfigChannel.max_prop` when `m_ircx_prop` is loaded.

## Access

Channel `ACCESS` levels:

| Level | Default | Description |
| --- | --- | --- |
| `OWNER` / `ADMIN` | `+q` | Owner access. |
| `HOST` / `OP` | `+o` | Operator access. |
| `VOICE` | `+v` | Voice access. |
| `DENY` | Stored in ban list flag | Explicit deny entry. |
| `GRANT` | Stored in invite/exception flag | Explicit grant entry. |
| `QUIET` | Quiet flag | Quiet entry. |

```irc
ACCESS #team LIST
ACCESS #team ADD alice!*@* OWNER
ACCESS #team DELETE alice!*@*
ACCESS #team CLEAR
```

Server-level access supports:

```irc
ACCESS * ADD DENY bad!*@* 60 :abuse
ACCESS * ADD GAG flooder!*@*
ACCESS * ADD GRANT trusted!*@*
ACCESS * ADD NOCHANNEL #bad*
ACCESS * ADD NONICK badnick*
ACCESS * LIST
ACCESS * CLEAR GAG
```

## Events

`EVENT` is oper-oriented. Supported event types:

| Type | Default | Description |
| --- | --- | --- |
| `CHANNEL` | Available | Channel create, mode, topic, and related events. |
| `MEMBER` | Available | Join, part, kick, and member changes. |
| `USER` | Available | Connect, quit, nick/mode, GeoIP, kills, and spy command activity. |
| `SERVER` | Available | Server link events. |
| `BROADCAST` | Oper-only for subscription | Operwall, server notices, and wallops. |
| `AUTH` | Available | Account login/logout. |
| `PRIVMSG` | Requires `oper:operspy` | Channel/user message observation. |

```irc
EVENT ADD CHANNEL #team*
EVENT ADD AUTH *
EVENT LIST
EVENT DELETE CHANNEL
EVENT CLEAR
```

## LISTX filters

```irc
LISTX >5,TOPICONLY,#dev*
```

| Filter | Default | Description |
| --- | --- | --- |
| `>N`, `<N` | Optional | Member count comparison. |
| `C>N`, `C<N` | Optional | Channel age comparison. |
| `T>N`, `T<N` | Optional | Topic age comparison. |
| `TOPICONLY` | Optional | Only channels with topics. |
| `#pattern` | Optional | Glob against channel name. |

## Media integration

LADON media policy uses IRCX properties and access entries. Use properties for the current, unambiguous policy path:

```irc
PROP #team LADON.MEDIA.VOICE :members
PROP #team LADON.MEDIA.VIDEO :op
PROP #team LADON.MEDIA.SCREEN :owner
ACCESS #team ADD alice!*@* VOICE
```

See `LADON Media` for frame-level details.

## Related pages

- `LADON Overview`
- `LADON Media`
- `Tsumugi Security`
