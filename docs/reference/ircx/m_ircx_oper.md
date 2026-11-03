# IRCX oper surface

_The operator-gated corner of Onyx Server's IRCX family — server access lists (`SACCESS`), the `+z` GAG umode, and the operator `EVENT` plane._

IRCX operator controls are built-in server commands in
[`server.zig`](../../../src/daemon/server.zig), registered through
[`modules/ircx.zig`](../../../src/daemon/modules/ircx.zig). Access/privilege checks
apply before mutation. [The moderation reference](../commands/oper-moderation.md)
documents the other operator command families.

## SACCESS — server-level access lists

```text
SACCESS <channel|*> <ADD|DELETE|LIST|CLEAR> [<level>] [<mask>] [<timeout>] [:<reason>]
ACCESS  *           …                                # same server-access path
```

`SACCESS` is registered with `.access = .oper`, so the dispatch layer refuses it
to non-operators before the handler runs. It is the server-level counterpart to
the channel-scoped [`ACCESS`](m_ircx_access.md) command: entries match on
`nick!user@host` facets and gate connection, nick, and channel-join at the
server level (`handleSaccess` / `handleServerAccessRequest`). Live entries are
persisted to the durable services store and replayed on restart. The bare
`ACCESS *` form is routed here as well.

## GAG — `MODE <nick> +z`

An operator may silence another user with `MODE <nick> +z` (cleared with `-z`),
handled by `applyGag`. The server records the target's real IP in its gag set
and refuses messages from local connections bound to that gagged IP; `-z` lifts
it. This handler is local-node authority and does not itself prove mesh-wide
replication of the gag table. The
change is reflected back as `:<server> MODE <nick> +z`. This is the IRCX
operator "gag"; it is a cross-user umode that only operators may set.

## Operator EVENT plane

Operators drive the wider event surface through [`EVENT`](m_ircx_event.md):

- `EVENT BROADCAST :<message>` — the operator announce that replaces WALLOPS.
- `EVENT OBSERVE <mask> …` — a standing lifecycle feed with real hosts.

Both require operator status and the `event_subscribe` privilege. See
[event-spine.md](../../architecture/event-spine.md) for the full model.

## Notes

- The legacy `OPFORCE`/`SVSJOIN` commands are intentionally absent.
  Forced joins and moderation are expressed through the modern surface (SACCESS,
  channel `ACCESS`, WARD ban policy) rather than services pseudo-commands.
- All of these are IRCX-family commands except `MODE`; the IRCX ones require the
  session to have opted in via `IRCX`/`ISIRCX` first.

## Examples

```irc
IRCX
SACCESS * ADD DENY *!*@*.spamhost.example 86400 :network ban
SACCESS #ops LIST
MODE badnick +z
EVENT BROADCAST :ring 0 restart in 5m
```
