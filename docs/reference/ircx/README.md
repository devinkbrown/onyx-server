# IRCX reference (Onyx Server)

_Index of Onyx Server's IRCX command family, with a cross-check of the live surface against the canonical draft._

Onyx Server implements IRCX as built-in Zig server commands registered in the SerpentRegistry module table
[`src/daemon/modules/ircx.zig`](../../../src/daemon/modules/ircx.zig) as a thin
thunk over a `LinuxServer.handle*` method in
[`src/daemon/server.zig`](../../../src/daemon/server.zig). Protocol parsing,
stores, and reply builders live under [`src/proto/`](../../../src/proto/).

Except for discovery, IRCX commands are **gated behind IRCX mode**: a session
opts in with `IRCX`, `ISIRCX`, or `MODE ISIRCX`; using an IRCX command without
opting in returns `421 ERR_UNKNOWNCOMMAND` (`IRCX command requires ISIRCX`).
Discovery itself works before registration.

## Command pages

| Page | Command(s) | Handler |
| --- | --- | --- |
| [m_ircx_prop.md](m_ircx_prop.md) | `PROP` | `handleProp` |
| [m_ircx_prop_channel_builtins.md](m_ircx_prop_channel_builtins.md) | channel properties (+ `EPHEMERAL`, `PINS`) | `channelBuiltinGet`/`Set` |
| [m_ircx_prop_entity_user.md](m_ircx_prop_entity_user.md) | user / member properties | `handleProp` + prop providers |
| [m_ircx_access.md](m_ircx_access.md) | `ACCESS` | `handleAccess` |
| [m_ircx_auth.md](m_ircx_auth.md) | `AUTH` | `handleIrcxAuth` |
| [m_ircx_event.md](m_ircx_event.md) | `EVENT` | `handleEvent` |
| [m_ircx_oper.md](m_ircx_oper.md) | `SACCESS`, `MODE +z` GAG, oper `EVENT` | `handleSaccess`/`applyGag` |
| [m_ircx_auditorium.md](m_ircx_auditorium.md) | `+x AUDITORIUM`, `+h HIDDEN` | `auditorium.zig` / channel model |

Other IRCX-family commands registered in the module: `IRCX`/`ISIRCX`
(discovery), `DATA`/`REQUEST`/`REPLY` (typed directed messaging), `WHISPER`
(channel-scoped private message, `+w NOWHISPER` / `923`), `MODEX` (named channel
modes), and `LISTX` (extended `LIST`). `CREATE` lives with the channel-ops
module.

## Authoritative material

| Document | Role |
| --- | --- |
| [`ircx-draft-pfenning-04.md`](ircx-draft-pfenning-04.md) | Historical external draft excerpt defining the IRCX standard vocabulary; current daemon behavior and deliberate extensions are documented by the live references and source. |
| [../../architecture/event-spine.md](../../architecture/event-spine.md) | Full architecture behind `EVENT`, OBSERVE, BROADCAST, categories, and severity. |

## Numeric map (live)

| Range | Replies |
| --- | --- |
| `800` | `RPL_IRCX` (discovery / AUTH package list) |
| `801–805` | `ACCESS` — ADD / DELETE / START / ENTRY / END |
| `806–810` | `EVENT` — ADD / DELETE / START / LIST / END |
| `818–819` | `PROP` — `RPL_PROPLIST` / `RPL_PROPEND` |
| `821–823`, `825` | `EVENT` — EVENTDUP / EVENTMIS / NOSUCHEVENT / EVENTCHANGE |
| `826–827` | `MODEX` — `RPL_MODEXLIST` / `RPL_MODEXEND` (an Onyx Server extension, kept clear of draft-reserved codes) |
| `906` | `ERR_BADVALUE` (invalid `PROP` value) |
| `913` | `ERR_NOACCESS` (`PROP`/property permission denial) |
| `923` | `ERR_NOWHISPER` (`+w` channel) |

## Conformance notes

- **PROP permission denials** use `913 ERR_NOACCESS` and invalid values use
  `906 ERR_BADVALUE` — no `918` squatting (918 is left free for the draft's
  `EVENTDUP` family; Onyx Server uses `821` for event-dup).
- **EVENT numerics** follow the draft `806–810` band; the IRCX event types are
  `CHANNEL/MEMBER/USER` plus the Onyx Server-specific `MEDIA` call-presence type.
  Delivery maps these onto Event-Spine categories while replies stay on the IRCX
  numeric surface — see [event-spine.md](../../architecture/event-spine.md).
- **MODEX** (`826/827`) is a deliberate Onyx Server extension and is kept clear of
  ACCESS/EVENT/PROP draft codes.
- **AUTH ordering.** Onyx Server's primary authentication is IRCv3 SASL via `CAP`;
  IRCX `AUTH` is the legacy pre-CAP path, layered over the same mechanisms.
- **WALLOPS is folded into the Event Spine** (`EVENT BROADCAST`) rather than a
  `+w` umode — an intentional divergence from the draft.
