# Onyx Server IRCv3 capabilities

*Live CAP registry advertised during capability negotiation, sourced from `src/daemon/dispatch.zig`.*

This reference documents the live capability registry in `src/daemon/dispatch.zig`. `src/proto/cap.zig` is not the live CAP registry. The live registry is `CapId` plus `cap_specs`. CAP LS emits those specs and appends `=<value>` for CAP LS 302 only when the spec or session supplies a value (`src/daemon/dispatch.zig:223`, `src/daemon/dispatch.zig:293`, `src/daemon/dispatch.zig:504`).

For third-party client readiness (Halloy REQ set vs this table, SASL mechs, SESSION/CHATHISTORY/WEBPUSH/IRCX gaps), see [client-interop-halloy.md](../client-interop-halloy.md).

## CAP LS 302 table

| Capability | CAP LS 302 Value | Notes | Evidence |
| --- | --- | --- | --- |
| `server-time` | none | Enables server-time tags. | `src/daemon/dispatch.zig:293` |
| `message-tags` | none | Negotiable generic message tags. | `src/daemon/dispatch.zig:294` |
| `echo-message` | none | Echo sent messages to sender. | `src/daemon/dispatch.zig:295` |
| `sasl` | `PLAIN,EXTERNAL,SCRAM-SHA-256,SCRAM-SHA-512` | Live `AUTHENTICATE` routes PLAIN, EXTERNAL, SCRAM-SHA-256, and SCRAM-SHA-512 through the mech router; unconfigured checkers fail closed. | `src/daemon/dispatch.zig` (`sasl`, `writeSaslCapValue`) |
| `multi-prefix` | none | Multi-prefix NAMES/WHOIS behavior. | `src/daemon/dispatch.zig:299` |
| `userhost-in-names` | none | Adds userhost detail to NAMES for capable clients. | `src/daemon/dispatch.zig:300` |
| `away-notify` | none | Away state notifications. | `src/daemon/dispatch.zig:301` |
| `setname` | none | SETNAME support. | `src/daemon/dispatch.zig:302` |
| `extended-join` | none | Extended JOIN support. | `src/daemon/dispatch.zig:303` |
| `invite-notify` | none | Invite notifications. | `src/daemon/dispatch.zig:304` |
| `account-tag` | none | Enables account tags. | `src/daemon/dispatch.zig:305` |
| `onyx/session-sync` | none | Onyx Server vendor cap for sibling-device direct-message mirroring. | `src/daemon/dispatch.zig:308` |
| `onyx/2fa` | `IDENTIFY` | Onyx Server vendor cap for two-factor identity assertion. | `src/proto/live_cap_metadata.zig:195` |
| `onyx/privacy` | `umode=DGIZTVW,cmode=cBK` | Onyx Server vendor cap advertising the enforced privacy user/channel modes. | `src/proto/live_cap_metadata.zig:199` |
| `onyx/bouncer` | none | Onyx Server vendor cap for automatic history rewind on join/rejoin. | `src/daemon/dispatch.zig:312` |
| `onyx/topics` | none | Onyx Server vendor cap for named conversations: clients can receive `+onyx/topic=<label>` without generic `message-tags`, and discover topic-filtered CHATHISTORY. | `src/daemon/dispatch.zig` (`onyx_topics`) |
| `onyx/e2ee` | none | Onyx Server vendor cap for the `+onyx/e2ee` client tag used by encrypted-room policy. | `src/daemon/dispatch.zig` (`onyx_e2ee`) |
| `chghost` | none | Receive CHGHOST lines for common-user host changes. | `src/daemon/dispatch.zig:316` |
| `no-implicit-names` | none | Suppress automatic NAMES burst on JOIN for capable clients. | `src/daemon/dispatch.zig:319` |
| `draft/no-implicit-names` | none | Draft spelling for the same negotiated capability as `no-implicit-names`; ACK echoes the requested token. | `src/daemon/dispatch.zig` (`no_implicit_names`) |
| `draft/chathistory` | none | CHATHISTORY command and chathistory BATCH replies. | `src/daemon/dispatch.zig:331` |
| `draft/search` | none | SEARCH command over the bounded CHATHISTORY inverted index. | `src/daemon/dispatch.zig` (`search`), `src/daemon/server.zig` (`handleSearch`) |
| `draft/message-redaction` | none | REDACT command. | `src/daemon/dispatch.zig:332` |
| `draft/message-editing` | none | EDIT command. | `src/daemon/dispatch.zig:333` |
| `draft/read-marker` | none | MARKREAD command. | `src/daemon/dispatch.zig:334` |
| `draft/typing` | none | Client-only typing tags relayed through TAGMSG. | `src/daemon/dispatch.zig:335` |
| `draft/react` | none | Client-only reaction tags relayed through TAGMSG. | `src/daemon/dispatch.zig:336` |
| `draft/reply` | none | Client-only reply tags relayed through TAGMSG. | `src/daemon/dispatch.zig:337` |
| `draft/event-playback` | none | CHATHISTORY/bouncer replay includes channel events (JOIN/PART/MODE/TOPIC/KICK/NICK/QUIT) rendered as `:sender CMD <body>`; clients without it get messages only. | `src/daemon/dispatch.zig:337` (`event_playback`) |
| `batch` | none | Server emits BATCH for features such as chathistory and netsplit. | `src/daemon/dispatch.zig:338` |
| `bot` | none | Bot mode/cap; user `+B` is surfaced in WHOIS. | `src/daemon/dispatch.zig:339` |
| `draft/channel-rename` | none | Receive RENAME for common channel renames. | `src/daemon/dispatch.zig:342` |
| `extended-monitor` | none | Extended MONITOR state notifications. | `src/daemon/dispatch.zig:345` |
| `account-notify` | none | ACCOUNT lines on common-user login/logout. | `src/daemon/dispatch.zig:349` |
| `draft/account-registration` | `custom-account-name` (CAP LS 302) | REGISTER/VERIFY account registration discovery; the 302 value signals that custom (non-nick) account names are accepted. | `src/daemon/dispatch.zig` (`account_registration`, `value_302`) |
| `draft/metadata-2` | none | METADATA GET/SET/LIST/CLEAR and 761/762/766 numerics. | `src/daemon/dispatch.zig:354` |
| `standard-replies` | none | FAIL/WARN support. | `src/daemon/dispatch.zig:356` |
| `cap-notify` | none | Static cap set support; CAP NEW/DEL do not fire for the static set. | `src/daemon/dispatch.zig:357` |
| `labeled-response` | none | Echoes `@label` on responses and frames multiline replies with labeled-response BATCH. | `src/daemon/dispatch.zig:362`, `src/daemon/dispatch.zig:1125` |
| `draft/pre-away` | none | AWAY may be sent during registration. | `src/daemon/dispatch.zig:368` |
| `draft/channel-context` | none | Relays client-only channel-context tags. | `src/daemon/dispatch.zig:371` |
| `draft/multiline` | `max-bytes=<ircv3.multiline_max_bytes>,max-lines=<ircv3.multiline_max_lines>` | Accepts inbound multiline BATCH chunks and reassembles them within enforced limits. Defaults are `40000` bytes and `64` lines. | `src/daemon/dispatch.zig`, `src/daemon/server.zig` |
| `sts` | runtime policy value | Config-gated; omitted unless a live STS policy is enabled for the session. | `src/daemon/dispatch.zig:383`, `src/daemon/dispatch.zig:504` |
| `account-extban` | `a` | Discovers account extban support; the same value is advertised in ISUPPORT `ACCOUNTEXTBAN`. | `src/daemon/dispatch.zig` (`account_extban`), `src/proto/isupport.zig` |
| `utf8-only` | none | Discovers the server's strict UTF-8 enforcement and `UTF8ONLY` ISUPPORT token. | `src/daemon/dispatch.zig` (`utf8_only`), `src/proto/utf8_only.zig` |
| `draft/netsplit` | none | Discovers IRCv3 netsplit BATCH support for mesh peer drops. | `src/daemon/dispatch.zig` (`netsplit`), `src/proto/netsplit_batch.zig` |
| `draft/netjoin` | none | Discovers IRCv3 netjoin BATCH support for mesh peer roster bursts. | `src/daemon/dispatch.zig` (`netjoin`), `src/proto/netsplit_batch.zig` |

## Negotiation behavior

| Operation | Behavior | Evidence |
| --- | --- | --- |
| `CAP LS [302]` | Enters negotiating state, remembers 302 support, and emits live cap specs, chunking to `MAX_CAP_REPLY_BODY` if needed. | `src/daemon/dispatch.zig:468`, `src/daemon/dispatch.zig:504` |
| `CAP REQ` | Parses requested tokens; unknown or unavailable caps NAK the request without partial mutation. | `src/daemon/dispatch.zig:531`, `src/daemon/dispatch.zig:577` |
| `CAP LIST` | Emits currently negotiated cap names. | `src/daemon/dispatch.zig:564` |
| `CAP END` | Marks negotiation complete and releases registration hold. | `src/daemon/dispatch.zig:552` |

## Vendor caps

The live vendor namespace is `onyx/*`, defined in `src/proto/live_cap_metadata.zig` (`cap_specs`, imported by `src/daemon/dispatch.zig`): `onyx/session-sync`, `onyx/bouncer`, `onyx/topics`, `onyx/e2ee`, `onyx/2fa` (302 value `IDENTIFY`), and `onyx/privacy` (302 value `umode=DGIZTVW,cmode=cBK`). No `ocean/*` capability appears in the live registry; do not document an Ocean vendor cap unless one is added to `cap_specs`.
