# IRCX PROP

_The IRCX `PROP` command — get, list, set, and delete properties on channels, members, and users._

`PROP` is a real server command registered in
[`src/daemon/modules/ircx.zig`](../../../src/daemon/modules/ircx.zig), handled
by `LinuxServer.handleProp` in
[`src/daemon/server.zig`](../../../src/daemon/server.zig). The line parser,
property store, access ladder, and reply builders live in
[`src/proto/ircx_prop_store.zig`](../../../src/proto/ircx_prop_store.zig).
Computed user properties come from
[`src/proto/ircx_prop_providers.zig`](../../../src/proto/ircx_prop_providers.zig).

> `PROP` is an IRCX-family command. The session must opt in with
> `IRCX`/`ISIRCX`/`MODE ISIRCX` first; otherwise the dispatch gate replies
> `421 ERR_UNKNOWNCOMMAND` (`IRCX command requires ISIRCX`).

## Syntax

```text
PROP <entity>                       # list every property on the entity
PROP <entity> <key[,key…]>          # get one or more properties
PROP <entity> <key> :<value>        # set a property
PROP <entity> <key> :               # empty trailing value = delete
```

`<entity>` is resolved by shape (`ircx_prop_store.Entity.fromId`):

| Form | Kind |
| --- | --- |
| `#chan` / `&chan` | channel |
| `#chan:nick` | member (a user's props within a channel) |
| `nick` | user |

## Behavior

- **Access ladder** (`propAccess`): network operators act as `sysop`; channel
  and member properties require the caller to be a channel operator; user
  properties are self-only. A denied write returns `913 ERR_NOACCESS`.
- **Replies:** listed/returned properties are `818 RPL_PROPLIST`
  (`:<srv> 818 <nick> <entity> <key> :<value>`), terminated by
  `819 RPL_PROPEND`. An invalid value returns `906 ERR_BADVALUE`.
- **Computed and linked built-ins** are answered ahead of the generic store:
  channel `NAME/OID/CREATION/MEMBERCOUNT/MEMBERLIMIT/MEMBERKEY` reflect live
  state, and setting `MEMBERKEY`/`MEMBERLIMIT` writes through to the `+k`/`+l`
  channel mode and broadcasts the equivalent `MODE`. See
  [built-in channel properties](m_ircx_prop_channel_builtins.md).
- **Secret keys.** The `*KEY` family (`FOUNDERKEY/OWNERKEY/HOSTKEY/VOICEKEY/
  MEMBERKEY`) is read-gated per tier (`maySeeSecretKey`): the store hides
  secrets unconditionally, so authorized reads go through `getPropRaw`/
  `listPropsRaw` behind the daemon's own rank gate. Non-authorized requesters
  simply do not see those rows.
- **Mesh propagation.** A channel property write is signed once at the local
  origin and replicated as a last-writer-wins CRDT fact
  (`announceChannelProp` / `channel_prop_event`); member/user properties
  propagate over `ENTITY_PROP` (`propagateLocalEntityProp`) with the same
  signed multi-hop LWW guarantees. Cross-mesh PROP propagation was fixed in
  commit `c2eee68` (the origin is stamped with the node's `shortId`).

## Examples

```irc
IRCX
PROP #zig                       ; list all channel properties
PROP #zig TOPIC,SUBJECT         ; get two keys
PROP #zig TOPIC :Ziggy time     ; set TOPIC
PROP #zig SUBJECT :             ; delete SUBJECT
PROP #zig:alice ROLE :greeter   ; a member property
PROP bob BIO :hi there          ; a user property (self only)
```

## Policy and publication boundary

A property name being accepted by a generic store does not guarantee that a live
consumer enforces it. Computed built-ins, secret key reads, mode-linked writes and
policy properties use their specific provider/handler rules. Mesh propagation
must preserve the original signed fact and its revision; signing does not bypass
write authorization. See [channel policy properties](m_ircx_prop_channel_builtins.md)
and [mesh security](../../architecture/mesh-security.md).
