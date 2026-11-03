# IRCX ACCESS

_The IRCX `ACCESS` command — persistent channel access lists (FOUNDER/OWNER/HOST/VOICE/GRANT/DENY) applied on join._

`ACCESS` is a real server command registered in
[`src/daemon/modules/ircx.zig`](../../../src/daemon/modules/ircx.zig), handled
by `LinuxServer.handleAccess` in
[`src/daemon/server.zig`](../../../src/daemon/server.zig). Parsing, the entry
store, and the reply builders live in
[`src/proto/ircx_access_store.zig`](../../../src/proto/ircx_access_store.zig).
It is IRCX-gated: opt in with `IRCX`/`ISIRCX` first, or dispatch replies
`421 ERR_UNKNOWNCOMMAND`.

## Syntax

```text
ACCESS <channel> LIST   [<level>] [<mask>]
ACCESS <channel> ADD    <level> <mask> [<timeout-secs>] [:<reason>]
ACCESS <channel> DELETE <level> <mask>
ACCESS <channel> CLEAR  [<level>]

ACCESS * …           # server-level list — routed to the SACCESS path
```

`<level>` is one of `FOUNDER`, `OWNER`, `HOST`, `VOICE`, `GRANT`, `DENY`
(`ircx_access_store.Level`). `<mask>` is a `nick!user@host` hostmask.

## Behavior

- **Management is channel-operator-gated.** `accessCanManage` requires the
  caller to be a channel operator (or network operator) for the target channel
  and level; otherwise `482 ERR_CHANOPRIVSNEEDED`. A malformed request yields
  `461 ERR_NEEDMOREPARAMS`. Writes made under an active operator override are
  audited.
- **Join-time application.** When a user joins, a matching entry applies its
  effect: `FOUNDER/OWNER/HOST/VOICE` grant the corresponding member status;
  `DENY` blocks the join; `GRANT` bypasses a matching server-level (SACCESS)
  deny/gag. `HOST` maps to channel-operator (`+o`) status.
- **`ACCESS *`** is the server-access selector and is forwarded to the
  server-access request path (see [IRCX oper surface](m_ircx_oper.md) and
  `SACCESS`), which is operator-gated.
- Entries carry an optional expiry (`<timeout-secs>`) and free-text reason, and
  are held in the `ircx_access_store` (bounded by the config-driven limits).

## Numerics

| Numeric | Name | Use |
| --- | --- | --- |
| `801` | `RPL_ACCESSADD` | entry added |
| `802` | `RPL_ACCESSDELETE` | entry removed |
| `803` | `RPL_ACCESSSTART` | opens a `LIST` |
| `804` | `RPL_ACCESSENTRY` | one per listed entry |
| `805` | `RPL_ACCESSEND` | closes a `LIST` / `CLEAR` |

## Examples

```irc
IRCX
ACCESS #zig ADD OWNER nick!*@host.test 3600 :trusted founder
ACCESS #zig ADD DENY *!*@spam.example
ACCESS #zig LIST HOST
ACCESS #zig DELETE OWNER nick!*@host.test
ACCESS #zig CLEAR DENY
```

## Signed mesh convergence

Current channel ACCESS changes can be emitted as `ACCESS_EVENT_V1` with an
immutable origin signature and LWW/tombstone authority. The secured transport uses
the `event-spine-v2` gate; an older peer can skip the unknown tag without dropping
the link, so an established mesh alone does not prove ACCESS convergence through
that peer. Expiry/skew and account/channel authorization remain independent checks.
See [the S2S catalog](../../architecture/mesh-s2s.md#s2s-frame-codec),
`src/proto/ircx_access_event.zig` and the live ACCESS admit/apply paths in `server.zig`.
Local store persistence and a signed forwarded fact are distinct evidence.
