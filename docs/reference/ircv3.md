# IRCv3 spec coverage

*The full IRCv3 extension catalog mapped to Onyx Server modules and implementation status.*

Extensions are drawn from the IRCv3 specifications repository (`github.com/ircv3/ircv3-specifications`).
Always implement to the actual spec text; this table is the work map, not the spec.

Status legend:

| Status | Meaning |
|---|---|
| Implemented | A source implementation exists at the listed surface; configuration, handler and client gates still apply. This is not full external-spec conformance certification. |
| In-flight | Partially implemented or under active work. |
| TODO | Planned, not yet started. |
| Removed | Intentionally excluded (clean-room, no legacy). |

| IRCv3 extension | Onyx Server | Status |
|---|---|---|
| capability-negotiation | `proto/live_cap_metadata.zig` + `daemon/dispatch.zig` | Implemented |
| message-tags | `proto/irc_line.zig` (parse) + `proto/msgtags.zig` (emit) | Implemented |
| server-time | `proto/msgtags.zig` | Implemented |
| account-tag | `proto/msgtags.zig` | Implemented |
| message-ids | `proto/msgtags.zig` (msgid) | Implemented |
| batch / client-batch | `proto/batch.zig` | Implemented |
| labeled-response | `proto/labeled_response.zig` + `proto/batch.zig` + dispatch echo/framing | Implemented |
| standard-replies | `proto/standard_replies.zig` | Implemented |
| extended-isupport / isupport | `proto/isupport.zig` + `proto/protocol_inventory.zig` | Implemented |
| sasl-3.1 / sasl-3.2 | `proto/sasl.zig` + `proto/sasl_mechrouter.zig` (PLAIN/EXTERNAL/SCRAM-256/SCRAM-512) | Implemented |
| account-registration | `daemon/services.zig` (REGISTER) | Implemented (backend) |
| monitor | `proto/monitor.zig` | Implemented |
| extended-monitor | `proto/extended_monitor.zig` | Implemented (wired into dispatch) |
| away-notify | `proto/away.zig` | Implemented |
| pre-away | `proto/away.zig` + pre-registration dispatch | Implemented |
| chghost | `proto/chghost.zig` | Implemented |
| setname | `proto/chghost.zig` | Implemented |
| chathistory | `proto/chathistory.zig` (Lotus) | Implemented |
| read-marker | `proto/read_marker.zig` + `MARKREAD` handler | Implemented |
| multiline | `proto/multiline.zig` + inbound BATCH reassembler | Implemented |
| message-redaction | `proto/msgedit.zig` + `REDACT` handler | Implemented |
| message-editing | `proto/msgedit.zig` + `EDIT` handler | Implemented |
| search | CHATHISTORY inverted index + `SEARCH` handler | Implemented |
| event-playback | Lotus channel-event entries + `draft/event-playback` replay gate | Implemented |
| sts | `proto/sts.zig` | Implemented |
| websocket | `proto/websocket.zig` + daemon WebSocket adapter | Implemented (negotiated text/media protocols, bounded binary) |
| whox | `proto/who.zig` | Implemented |
| account-extban | `proto/extban.zig` + `ACCOUNTEXTBAN` ISUPPORT/CAP | Implemented |
| bot-mode | `proto/bot_mode.zig` (RPL_WHOISBOT 335, BOT isupport) | Implemented (wired into dispatch) |
| echo-message | `proto/echo_message.zig` | Implemented (wired into dispatch) |
| extended-join | `proto/extended_join.zig` | Implemented (wired into dispatch) |
| userhost-in-names / multi-prefix | `proto/names_reply.zig` | Implemented |
| invite-notify | `proto/invite_notify.zig` | Implemented (wired into dispatch) |
| channel-context | `proto/draft_channel_context.zig` + client-tag relay | Implemented |
| channel-rename | `proto/channel_rename.zig` + `RENAME` handler | Implemented |
| no-implicit-names | `proto/draft_no_implicit_names.zig` + JOIN NAMES gate | Implemented |
| utf8only | `proto/utf8_only.zig` (strict UTF-8 + UTF8ONLY isupport + FAIL) | Implemented (wired into dispatch) |
| netsplit / netjoin | `proto/netsplit_batch.zig` + mesh peer drop/roster bursts | Implemented |
| metadata-2 | `proto/metadata_store.zig` + `METADATA` handler | Implemented |
| oper-tag | No live CAP advertisement in `live_cap_metadata.zig` | Not advertised |
| network-icon | `[network] icon_url` -> `NETWORKICON` ISUPPORT | Implemented |
| account-notify | `proto/account_notify.zig` | Implemented (wired into dispatch) |
| webirc | — | Removed (clean-room: WebSocket only) |
| deprecated: tls (STARTTLS), sasl-dh-* | — | Removed (TLS-native / modern SASL) |

IRCv3 `METADATA` and IRCX `PROP` have separate command/store contracts; do not
assume a write through one creates every view in the other. Account-derived
operator authority is separate from advertising `oper-tag`. `labeled-response`
uses BATCH framing. The [live CAP reference](protocol/caps.md) is authoritative
for names the daemon actually advertises.

## WebSocket application protocols

WebSocket clients may offer `onyx.irc-media.v1` and `text.ircv3.net`; the
server selects the first supported token in the client's offered order. The
Onyx client offers the media protocol first and the IRCv3 text protocol as its
fallback. `text.ircv3.net` accepts exactly one CR/LF-free IRC message per text
frame and rejects binary frames. `onyx.irc-media.v1` adds bounded Cadence binary
datagrams while retaining text IRC frames. A client that offers no protocol is
accepted in the explicit legacy compatibility mode.

Inbound frame payloads and fragmented binary application messages are bounded
at 4 MiB. Malformed framing and protocol mismatches close with RFC 6455 status
1002; frame or aggregate size violations close with 1009. The selected protocol
and any in-progress bounded fragmented-binary accumulator are preserved by the
current Helix WebSocket capsule.
