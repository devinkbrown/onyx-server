# IRCX EVENT

_The IRCX `EVENT` command — client/operator subscription control over Onyx Server's typed event planes. Concise command reference; for the full model see [event-spine.md](../../architecture/event-spine.md)._

`EVENT` is a built-in server command registered in the SerpentRegistry module table
[`src/daemon/modules/ircx.zig`](../../../src/daemon/modules/ircx.zig) as a thin
thunk over `LinuxServer.handleEvent` in
[`src/daemon/server.zig`](../../../src/daemon/server.zig). It is an IRCX-family
command: the session must first opt in with `IRCX`/`ISIRCX`/`MODE ISIRCX`, or
the dispatch gate rejects it with `421 ERR_UNKNOWNCOMMAND` (`IRCX command
requires ISIRCX`).

## Syntax

```text
EVENT LIST [<type>]
EVENT ADD    <type> [<subject-mask>]
EVENT CHANGE <type> <subject-mask>
EVENT DELETE|DEL <type>
EVENT CLEAR  [<type>]

# operator-only sub-verbs
EVENT BROADCAST :<message>
EVENT OBSERVE <mask> [<actions>…] | OFF | LIST
EVENT SEVERITY <level>
EVENT REPLAY  [JSON] [<args>…]
EVENT STATS
```

`<type>` is an IRCX event type from
[`src/daemon/event_spine.zig`](../../../src/daemon/event_spine.zig)
(`IrcxEventType`): `CHANNEL`, `MEMBER`, `USER`, `MEDIA`. `<subject-mask>`
defaults to `*`.

## Behavior

- **Subscription plane.** `LIST/ADD/CHANGE/DELETE/CLEAR` manage the calling
  session's IRCX event subscriptions, each with a per-type subject mask. The
  IRCX plane is token-routed by type and deliberately kept separate from the
  operator Event-Spine category mask, so a `USER` subscriber receives only
  `USER` events.
- **Client vs operator scope.** Ordinary clients may subscribe only to the
  channel-scoped `MEDIA` type (the call-presence feed for channels they are in).
  `CHANNEL/MEMBER/USER`, plus `BROADCAST` and `OBSERVE`, are operator-only; the
  operator path additionally requires the `event_subscribe` privilege.
- **`EVENT BROADCAST`** sends an operator announce (the former WALLOPS, folded
  into the Event Spine) to every announce-subscribed operator as
  `:<server> EVENT <oper> <message>`.
- **`EVENT OBSERVE`** installs a standing operator observation subscription over
  a nick/host mask and pushes a live lifecycle feed (with real hosts); it emits
  an immediate snapshot of the currently-matching population on subscribe.
- **`SEVERITY` / `REPLAY` / `STATS`** tune the per-session minimum severity,
  replay recorded events, and report counters. `EVENT REPLAY JSON` and
  `EVENT STATS JSON` provide machine-readable NOTICE payloads, with
  `EVENT STATS JSON` also advertising the stable `operator_surfaces` capability
  map; see
  [event-spine.md](../../architecture/event-spine.md).

## Numerics

| Numeric | Name | Use |
| --- | --- | --- |
| `806` | `RPL_EVENTADD` | subscription added |
| `807` | `RPL_EVENTDELETE` | subscription removed |
| `808` | `RPL_EVENTSTART` | opens a `LIST` |
| `809` | `RPL_EVENTLIST` | one per subscription |
| `810` | `RPL_EVENTEND` | closes a `LIST` |
| `825` | `RPL_EVENTCHANGE` | subject mask updated |
| `821` | `ERR_EVENTDUP` | already subscribed |
| `822` | `ERR_EVENTMIS` | not subscribed |
| `823` | `ERR_NOSUCHEVENT` | unknown event type |

## Examples

```irc
IRCX
EVENT ADD MEDIA #studio
EVENT LIST
EVENT DELETE MEDIA
EVENT BROADCAST :network maintenance in 10 minutes
EVENT OBSERVE *!*@*.example.net JOIN PART
```
