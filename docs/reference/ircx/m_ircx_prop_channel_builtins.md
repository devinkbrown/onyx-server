# IRCX built-in channel properties

_The channel properties Onyx Server knows by name — computed built-ins, mode-linked keys, the secret key ladder, and the server-policy properties._

Channel properties are served by `LinuxServer.handleProp` in
[`src/daemon/server.zig`](../../../src/daemon/server.zig) over the store in
[`src/proto/ircx_prop_store.zig`](../../../src/proto/ircx_prop_store.zig). The
known-key table is `ircx_prop_store.ChannelPropKey` / `channelPropInfo`;
computed reads are `channelBuiltinGet`; validated writes are
`channelBuiltinSet`. All of these are addressed through the
[`PROP`](m_ircx_prop.md) command and require IRCX mode (else `421`).

## Known channel property keys

`OID`, `NAME`, `CREATION`, `MEMBERCOUNT`, `MEMBERLIMIT`, `LANGUAGE`,
`FOUNDERKEY`, `OWNERKEY`, `HOSTKEY`, `VOICEKEY`, `MEMBERKEY`, `PICS`, `TOPIC`,
`SUBJECT`, `CLIENT`, `ONJOIN`, `ONPART`, `LAG`, `ACCOUNT`, `CLIENTGUID`,
`SERVICEPATH`, `no-ai`, `local-only`, `server-ai-ok`, `history-policy`.

`ONJOIN` is sent only to the client that just joined, as a `PRIVMSG` with the
channel name as the sender. `ONPART` is sent only to the client that just
parted, as a `NOTICE` from that same sender. The stored characters `\` and `n`
start another line. Other members do not receive either message. A stored
control byte is dropped instead of being split into a second wire command.

### Computed / linked (answered ahead of the generic store)

| Key | Source | Notes |
| --- | --- | --- |
| `NAME` | the channel name | read-only |
| `OID` | `world.channelOid` | `0` + 8 hex digits; read-only |
| `CREATION` | `world.channelCreatedUnix` | unix seconds; read-only |
| `MEMBERCOUNT` | `world.memberCount` | live; read-only |
| `MEMBERLIMIT` | channel `+l` | host-settable; write links to `MODE +l` |
| `MEMBERKEY` | channel `+k` | secret; write links to `MODE +k` |

Setting `MEMBERKEY`/`MEMBERLIMIT` writes through to live channel state and
broadcasts the equivalent `MODE` so every member's mode view stays in sync.

### Secret key ladder (per-tier read gate)

`FOUNDERKEY`, `OWNERKEY`, `HOSTKEY`, `VOICEKEY`, `MEMBERKEY` are marked
`secret`. They are visible only to members at or above their tier (founder >
owner > op/host > voice > member), or to operators. Non-authorized requesters do
not see these rows at all.

## Persisted policy properties

### `EPHEMERAL <secs>` — message TTL (commit `201e5f3`)

```text
PROP <#channel> EPHEMERAL :<seconds>     # 60 … 2592000 (30 days)
PROP <#channel> EPHEMERAL :0             # disable (non-ephemeral)
PROP <#channel> EPHEMERAL :              # delete the property
```

Sets a per-channel message time-to-live in whole seconds. `channelBuiltinSet`
validates the bound (at least `60`, at most `30 days`; `0` disables) and returns
`906 ERR_BADVALUE` for anything out of range or non-numeric. It is **not** a
mode-linked built-in: the value is persisted and mesh-propagated as an ordinary
signed channel property, and it is enforced on **read** at the single
history-replay funnel `renderHistoryReplay` — which serves CHATHISTORY, bouncer
rewind, **and** SEARCH. Every replay drops messages older than the TTL
(`channelEphemeralTtlMs` → `ephemeralFloorMs`), so expired content is simply
never re-served. The history ring still bounds memory; this makes the expiry
policy authoritative on read. Only `#`/`&` channels are ephemeral (DMs never
expire on this path).

### `PINS` — pinned messages (commit `dc2c351`)

```text
PROP <#channel> PINS :<msgid>[,<msgid>…]   # up to 50 msgids
PROP <#channel> PINS :                     # clear all pins
```

A comma-separated list of pinned message-id tokens. `channelBuiltinSet` calls
`validPinsValue`: each token must be non-empty, ≤ 64 chars, printable, and
contain no whitespace or comma; at most 50 tokens; an empty value means "no
pins". Invalid values return `906 ERR_BADVALUE`. Like `EPHEMERAL`, it is stored
and mesh-propagated as a plain signed channel property (not mode-linked), and —
like all channel-property writes — it is channel-operator gated. Clients render
a pins drawer, resolving each msgid against their own history.

### AI policy flags

```text
PROP <#channel> no-ai :1          # no AI processing for this room
PROP <#channel> local-only :1     # local/on-device inference only
PROP <#channel> server-ai-ok :1   # server-side plaintext-channel inference allowed
PROP <#channel> no-ai :0          # disable the flag
PROP <#channel> no-ai :           # delete the flag
```

These are public, channel-operator-managed policy flags for future server-side
AI/plugin paths. `channelBuiltinSet` accepts only `0` or `1`; other values return
`906 ERR_BADVALUE`. They are ordinary signed channel properties after
validation, so they persist, mesh-propagate, and survive the same PROP replay
path as `EPHEMERAL`, `PINS`, `history-policy`, and `onyx_server.topics`.

When multiple flags are present, daemon-side readers resolve precedence as:
`no-ai` > `local-only` > `server-ai-ok` > unspecified. That makes the safest
policy win if a channel temporarily has conflicting flags during edits or mesh
convergence.

Server-owned integrations must use `LinuxServer.checkChannelAiPolicy` rather
than reading the flags directly. Local/client-side inference is allowed unless
`no-ai` wins. Server-side plaintext processing is allowed only when
`server-ai-ok` wins; `unspecified` fails closed for server-side work. This is a
policy hook only; it does not imply or create a separate MCP server.

### `history-policy` — CHATHISTORY visibility

```text
PROP <#channel> history-policy :public    # default: ordinary visibility rules
PROP <#channel> history-policy :members   # only members and opers may replay
PROP <#channel> history-policy :opers     # only opers may replay
PROP <#channel> history-policy :          # delete the policy
```

This is Onyx Server's live Aegis policy hook for history reads. `channelBuiltinSet`
accepts only `public`, `members`, or `opers`; invalid values return
`906 ERR_BADVALUE`. The value is stored as an ordinary signed channel property
and enforced at the CHATHISTORY target-visibility gate after normal channel
existence/secret/private/hidden checks pass. DMs do not use this channel policy.

## Mesh note

Channel properties (built-in, `EPHEMERAL`, `PINS`, `history-policy`,
`onyx_server.topics`, and AI policy flags alike) are signed at the local origin and
replicated as last-writer-wins CRDT facts. Commit `c2eee68` fixed cross-mesh
PROP propagation so channel and entity properties now reach peers; the origin is
stamped with the node's `shortId`.

## Examples

```irc
IRCX
PROP #vault EPHEMERAL :3600        ; drop anything older than an hour on replay
PROP #vault EPHEMERAL :0           ; turn expiry off again
PROP #news PINS :01H…ABC,01H…XYZ   ; pin two messages by id
PROP #news PINS :                  ; unpin everything
PROP #private no-ai :1             ; opt the room out of AI processing
PROP #vault history-policy :members ; require membership for history replay
```
