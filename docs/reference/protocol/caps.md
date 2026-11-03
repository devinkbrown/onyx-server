# Onyx Server IRCv3 capabilities

The immutable `CapId` and `cap_specs` definitions live in
[`live_cap_metadata.zig`](../../../src/proto/live_cap_metadata.zig).
[`dispatch.zig`](../../../src/daemon/dispatch.zig) imports that table and owns
session/runtime policy and `CapSession.handle`. `src/proto/cap.zig` is a separate
codec/helper and is not the live daemon registry. The current metadata declares
47 names over 46 IDs; the two no-implicit-names tokens share one ID.

CAP LS emits the available names; CAP LS 302 adds effective values. SASL is
omitted when no verifier is available, and STS is omitted without a runtime policy.
The [SASL and message-tag reference](../ircv3-capabilities.md) explains the dynamic
mechanism list and recipient gates. Client interoperability must be tested against
the actual client version and negotiated set; an old client matrix is not current
support evidence.

## CAP LS 302 table

| Capability | CAP LS 302 Value | Notes | Evidence |
| --- | --- | --- | --- |
| `server-time` | none | Enables server-time tags. | `src/daemon/dispatch.zig` |
| `message-tags` | none | Negotiable generic message tags. | `src/daemon/dispatch.zig` |
| `echo-message` | none | Echo sent messages to sender. | `src/daemon/dispatch.zig` |
| `sasl` | runtime enabled-mechanism list | The session advertises only configured verifiers, potentially including channel-bound SCRAM, account SESSION-TOKEN, OAuth or anonymous policy; unconfigured checkers fail closed. | `src/daemon/dispatch.zig` (`sasl`, `writeSaslCapValue`) |
| `multi-prefix` | none | Multi-prefix NAMES/WHOIS behavior. | `src/daemon/dispatch.zig` |
| `userhost-in-names` | none | Adds userhost detail to NAMES for capable clients. | `src/daemon/dispatch.zig` |
| `away-notify` | none | Away state notifications. | `src/daemon/dispatch.zig` |
| `setname` | none | SETNAME support. | `src/daemon/dispatch.zig` |
| `extended-join` | none | Extended JOIN support. | `src/daemon/dispatch.zig` |
| `invite-notify` | none | Invite notifications. | `src/daemon/dispatch.zig` |
| `account-tag` | none | Enables account tags. | `src/daemon/dispatch.zig` |
| `onyx/session-sync` | none | Onyx Server vendor cap for sibling-device direct-message mirroring. | `src/daemon/dispatch.zig` |
| `onyx/2fa` | `IDENTIFY` | Onyx Server vendor cap for two-factor identity assertion. | `src/proto/live_cap_metadata.zig` |
| `onyx/privacy` | `umode=DGIZTVW,cmode=cBK` | Onyx Server vendor cap advertising the enforced privacy user/channel modes. | `src/proto/live_cap_metadata.zig` |
| `onyx/bouncer` | none | Onyx Server vendor cap for automatic history rewind on join/rejoin. | `src/daemon/dispatch.zig` |
| `onyx/topics` | none | Onyx Server vendor cap for named conversations: clients can receive `+onyx/topic=<label>` without generic `message-tags`, and discover topic-filtered CHATHISTORY. | `src/daemon/dispatch.zig` (`onyx_topics`) |
| `onyx/e2ee` | none | Onyx Server vendor cap for the `+onyx/e2ee` client tag used by encrypted-room policy. | `src/daemon/dispatch.zig` (`onyx_e2ee`) |
| `chghost` | none | Receive CHGHOST lines for common-user host changes. | `src/daemon/dispatch.zig` |
| `no-implicit-names` | none | Suppress automatic NAMES burst on JOIN for capable clients. | `src/daemon/dispatch.zig` |
| `draft/no-implicit-names` | none | Draft spelling for the same negotiated capability as `no-implicit-names`; ACK echoes the requested token. | `src/daemon/dispatch.zig` (`no_implicit_names`) |
| `draft/chathistory` | none | CHATHISTORY command and chathistory BATCH replies. | `src/daemon/dispatch.zig` |
| `draft/search` | none | SEARCH command over the bounded CHATHISTORY inverted index. | `src/daemon/dispatch.zig` (`search`), `src/daemon/server.zig` (`handleSearch`) |
| `draft/message-redaction` | none | REDACT command. | `src/daemon/dispatch.zig` |
| `draft/message-editing` | none | EDIT command. | `src/daemon/dispatch.zig` |
| `draft/read-marker` | none | MARKREAD command. | `src/daemon/dispatch.zig` |
| `draft/typing` | none | Client-only typing tags relayed through TAGMSG. | `src/daemon/dispatch.zig` |
| `draft/react` | none | Client-only reaction tags relayed through TAGMSG. | `src/daemon/dispatch.zig` |
| `draft/reply` | none | Client-only reply tags relayed through TAGMSG. | `src/daemon/dispatch.zig` |
| `draft/event-playback` | none | CHATHISTORY/bouncer replay includes channel events (JOIN/PART/MODE/TOPIC/KICK/NICK/QUIT) rendered as `:sender CMD <body>`; clients without it get messages only. | `src/daemon/dispatch.zig` (`event_playback`) |
| `batch` | none | Server emits BATCH for features such as chathistory and netsplit. | `src/daemon/dispatch.zig` |
| `bot` | none | Bot mode/cap; user `+B` is surfaced in WHOIS. | `src/daemon/dispatch.zig` |
| `draft/channel-rename` | none | Receive RENAME for common channel renames. | `src/daemon/dispatch.zig` |
| `extended-monitor` | none | Extended MONITOR state notifications. | `src/daemon/dispatch.zig` |
| `account-notify` | none | ACCOUNT lines on common-user login/logout. | `src/daemon/dispatch.zig` |
| `draft/account-registration` | `custom-account-name` (CAP LS 302) | REGISTER/VERIFY account registration discovery; the 302 value signals that custom (non-nick) account names are accepted. | `src/daemon/dispatch.zig` (`account_registration`, `value_302`) |
| `draft/metadata-2` | none | METADATA GET/SET/LIST/CLEAR and 761/762/766 numerics. | `src/daemon/dispatch.zig` |
| `standard-replies` | none | FAIL/WARN support. | `src/daemon/dispatch.zig` |
| `cap-notify` | none | Static cap set support; CAP NEW/DEL do not fire for the static set. | `src/daemon/dispatch.zig` |
| `labeled-response` | none | Echoes `@label` on responses and frames multiline replies with labeled-response BATCH. | `src/daemon/dispatch.zig` |
| `draft/pre-away` | none | AWAY may be sent during registration. | `src/daemon/dispatch.zig` |
| `draft/channel-context` | none | Relays client-only channel-context tags. | `src/daemon/dispatch.zig` |
| `draft/multiline` | `max-bytes=<ircv3.multiline_max_bytes>,max-lines=<ircv3.multiline_max_lines>` | Accepts inbound multiline BATCH chunks and reassembles them within enforced limits. Defaults are `40000` bytes and `64` lines. | `src/daemon/dispatch.zig`, `src/daemon/server.zig` |
| `sts` | runtime policy value | Config-gated; omitted unless a live STS policy is enabled for the session. | `src/daemon/dispatch.zig` |
| `account-extban` | `a` | Discovers account extban support; the same value is advertised in ISUPPORT `ACCOUNTEXTBAN`. | `src/daemon/dispatch.zig` (`account_extban`), `src/proto/isupport.zig` |
| `utf8-only` | none | Discovers the server's strict UTF-8 enforcement and `UTF8ONLY` ISUPPORT token. | `src/daemon/dispatch.zig` (`utf8_only`), `src/proto/utf8_only.zig` |
| `draft/netsplit` | none | Discovers IRCv3 netsplit BATCH support for mesh peer drops. | `src/daemon/dispatch.zig` (`netsplit`), `src/proto/netsplit_batch.zig` |
| `draft/netjoin` | none | Discovers IRCv3 netjoin BATCH support for mesh peer roster bursts. | `src/daemon/dispatch.zig` (`netjoin`), `src/proto/netsplit_batch.zig` |

## Negotiation behavior

| Operation | Behavior | Evidence |
| --- | --- | --- |
| `CAP LS [302]` | Enters negotiating state, remembers 302 support, and emits live cap specs, chunking to `MAX_CAP_REPLY_BODY` if needed. | `src/daemon/dispatch.zig` |
| `CAP REQ` | Parses requested tokens; unknown or unavailable caps NAK the request without partial mutation. | `src/daemon/dispatch.zig` |
| `CAP LIST` | Emits currently negotiated cap names. | `src/daemon/dispatch.zig` |
| `CAP END` | Marks negotiation complete and releases registration hold. | `src/daemon/dispatch.zig` |

## Vendor caps

The live vendor namespace is `onyx/*`, defined in `src/proto/live_cap_metadata.zig` (`cap_specs`, imported by `src/daemon/dispatch.zig`): `onyx/session-sync`, `onyx/bouncer`, `onyx/topics`, `onyx/e2ee`, `onyx/2fa` (302 value `IDENTIFY`), and `onyx/privacy` (302 value `umode=DGIZTVW,cmode=cBK`). No `ocean/*` capability appears in the live registry; do not document an Ocean vendor cap unless one is added to `cap_specs`.

## Negotiation example

```irc
CAP LS 302
CAP REQ :server-time message-tags batch draft/chathistory echo-message
CAP END
```

Only request tokens actually offered on this connection. An unknown or unavailable
name/value NAKs the whole request without partially changing negotiated state.
Authentication during registration additionally requires negotiating the offered
`sasl` capability and following its mechanism-specific challenge sequence.
