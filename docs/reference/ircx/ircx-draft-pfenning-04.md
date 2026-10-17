# IRCX: draft-pfenning-irc-extensions-04 (canonical reference)

_Normative extraction of the canonical IRCX IETF draft — the source of truth for IRCX numerics, commands, modes, and properties._

> Source: IETF Internet-Draft "Extensions to the Internet Relay Chat Protocol
> (IRCX)", Pfenning/Abraham (Microsoft), July 1998.
> https://www.ietf.org/archive/id/draft-pfenning-irc-extensions-04.txt
> Captured 2026-06-05 as Onyx Server's authoritative IRCX reference. Legacy C
> implementation notes live in the sibling `ircx-protocol.md` and
> `m_ircx_*.md` files.

## Protocol discovery

- `MODE ISIRCX` (or `ISIRCX` / `IRCX`) returns reply `800 IRCRPL_IRCX`:
  `<state> <version> <package-list> <maxmsg> <option-list>`.
  - `state` is 0 (disabled) or 1 (enabled); `version` starts at 0; `package-list`
    is a comma-separated list of SASL mechanisms; `maxmsg` is 512 by default;
    `option-list` is `*` when empty.
- Non-IRCX servers return an error, which lets unregistered clients probe support.
- `IRCX` enables IRCX mode for the session.

## AUTH (predates CAP/SASL)

```text
AUTH <name> <seq> [:<parameter>]      ; seq = I (initial) | S (subsequent) | * (abort)
AUTH <name> S [:<parameter>]          ; server: continue
AUTH <name> * <ident> <oid>           ; server: success (ident=userid@domain)
```

When the server advertises IRCX SASL mechanisms, the client's first message must
be AUTH (when authenticating), before USER and NICK.

## ACCESS

```text
ACCESS <object> LIST
ACCESS <object> ADD|DELETE <level> <mask> [<timeout> [:<reason>]]
ACCESS <object> CLEAR [<level>]
```

- Levels: `DENY`, `GRANT`, `HOST`, `OWNER`, `VOICE`.
- Evaluation order: OWNER → HOST → VOICE → GRANT → DENY.
- Objects: channel, nickname, `$` (server), `*` (network).

## PROP (entity properties)

```text
PROP <object> <prop>[,<prop>]      ; query
PROP <object> <prop> :<data>       ; set
PROP <object> <prop> :             ; delete
```

Channel properties are read-only or string/numeric, with per-visibility read and
write rules: `OID` (R/O), `NAME` (R/O, 63), `CREATION` (R/O), `LANGUAGE` (31),
`OWNERKEY`/`HOSTKEY`/`MEMBERKEY` (31, never readable), `PICS` (255), `TOPIC` (160),
`SUBJECT` (31), `CLIENT` (255), `ONJOIN` (255; PRIVMSG from the channel name to the joiner only; a backslash followed by `n` starts another line), `ONPART` (255; NOTICE from the channel name to the parter only; same line break), `LAG` (0–2s),
`ACCOUNT` (31), `CLIENTGUID`, `SERVICEPATH`.

## EVENT

```text
EVENT [ADD|DELETE] <event> [<mask>]
EVENT LIST [<event>]
```

- Event types: `CHANNEL`, `MEMBER`, `SERVER`, `CONNECTION`, `SOCKET`, `USER`.
- Only sysops and sysop-managers may receive events.

## LISTX (extended LIST)

`LISTX [<channel list>]` or `LISTX <query list> [<query limit>]`. Query terms:
`<#`, `>#` (member count); `C<#` / `C>#` (creation age min); `L=` / `N=` / `S=` /
`T=` (language/name/subject/topic mask); `R=0` / `R=1` (unregistered/registered);
`T<#` / `T>#` (topic-change age).

## CREATE, WHISPER, DATA

- `CREATE <channel> [<modes> [<modeargs>]]` returns an OID; modes t/n/m/l/k/c/e.
- `WHISPER <channel> <nick-list> :<message>` — the sender and all recipients must
  be on the channel.
- `DATA <target> <tag> :<message>` — tag `[A-z][A-z0-9.]{0,14}`; reserved prefixes
  SYS/ADM/OWN/HST are gated by privilege.

## Channel modes

Visibility modes are mutually exclusive: PUBLIC (default), PRIVATE +p, HIDDEN +h,
SECRET +s. Other modes: MODERATED +m, NOEXTERN +n, TOPICOP +t, INVITE +i,
KNOCK +u, NOFORMAT +f, NOWHISPER +w, AUDITORIUM +x, REGISTERED +r, SERVICE +z,
AUTHONLY +a, CLONEABLE +d, CLONE +e. User modes: OWNER +q (`.` prefix), GAG +z
(sysop-only).

## Numerics

Reply numerics:

| Code(s) | Meaning |
| --- | --- |
| `800` | IRCX |
| `801–805` | ACCESS ADD/DELETE/START/LIST/END |
| `806–810` | EVENT ADD/DEL/START/LIST/END |
| `811–817` | LISTX START/LIST/PICS/…/TRUNC/END |
| `818` | PROPLIST |
| `819` | PROPEND |

Error numerics: `900` BADCOMMAND, `901` TOOMANYARGUMENTS, `902` BADFUNCTION,
`903` BADLEVEL, `904` BADTAG, `905` BADPROPERTY, `906` BADVALUE, `907` RESOURCE,
`908` SECURITY, `909` ALREADYAUTHENTICATED, `910` AUTHENTICATIONFAILED,
`911` AUTHENTICATIONSUSPENDED, `912` UNKNOWNPACKAGE, `913` NOACCESS,
`914` DUPACCESS, `915` MISACCESS, `916` TOOMANYACCESSES, `918` EVENTDUP,
`919` EVENTMIS, `920` NOSUCHEVENT, `921` TOOMANYEVENTS, `923` NOWHISPER,
`924` NOSUCHOBJECT, `925` NOTSUPPORTED, `926` CHANNELEXIST,
`927` ALREADYONCHANNEL, `999` UNKNOWNERROR.

## Object prefixes

`#` / `&` RFC1459 global/local; `%#` / `%&` UTF8 global/local; `'` UTF8 IRCX nick;
`^` UTF8-to-hex display nick; `0` internal OID (8 hex); `$` server.

## Clone takeover protection

Creating a clone channel removes any same-named channel, which prevents clone
takeover.
