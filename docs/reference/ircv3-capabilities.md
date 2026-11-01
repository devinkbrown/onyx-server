# IRCv3 Capability Reference

This file documents the current Onyx Server IRCv3 client capability surface. The
filename is historical; do not treat it as product terminology.

## Source of truth

Onyx Server advertises client capabilities from the static `cap_specs` table in
`src/daemon/dispatch.zig`. CAP negotiation is handled by `CapSession.handle`:
`LS` emits the advertised set, `REQ` atomically ACKs or NAKs the requested token
list, `LIST` reports negotiated caps, and `END` completes negotiation.

Source: `src/daemon/dispatch.zig:316-445`,
`src/daemon/dispatch.zig:548-579`, `src/daemon/dispatch.zig:598-638`,
`src/daemon/dispatch.zig:663-727`.

## Advertised capabilities

`CAP LS 302` includes values for value-bearing caps. Bare `CAP LS` suppresses
static values. The `sasl` cap is omitted unless at least one SASL mechanism is
available on the session, and `sts` is omitted unless a runtime STS policy is
configured.

| Capability | CAP LS value | Behavior | Source |
|------------|--------------|----------|--------|
| `server-time` | none | Adds `time` tags to tagged outbound messages for recipients that negotiated the cap. | `src/daemon/dispatch.zig:317`, `src/daemon/server.zig:37876-37890` |
| `message-tags` | none | Enables generic client-only tag relay, `TAGMSG`, server `msgid`/`bot` tags, and complete visibility of relayed client-only tags. | `src/daemon/dispatch.zig:318`, `src/daemon/server.zig:30355-30378`, `src/daemon/server.zig:37899-37930`, `src/daemon/server.zig:37997-38037` |
| `echo-message` | none | Echoes the sender's own `PRIVMSG`, `NOTICE`, and eligible `TAGMSG` deliveries when negotiated. | `src/daemon/dispatch.zig:319`, `src/daemon/server.zig:29692-29695`, `src/daemon/server.zig:29776-29781`, `src/proto/echo_message.zig:109-124` |
| `sasl` | runtime mechanism list | Enables `AUTHENTICATE`; value is built per session from configured mechanisms. | `src/daemon/dispatch.zig:320-330`, `src/daemon/dispatch.zig:1418-1441`, `src/daemon/dispatch.zig:1810-1857` |
| `multi-prefix` | none | Negotiates multi-prefix names/status visibility. | `src/daemon/dispatch.zig:331` |
| `userhost-in-names` | none | Negotiates userhost data in names replies. | `src/daemon/dispatch.zig:332` |
| `away-notify` | none | Sends `AWAY` changes to common-channel members that negotiated the cap. | `src/daemon/dispatch.zig:333`, `src/daemon/server.zig:22200-22224` |
| `setname` | none | Sends `SETNAME` updates to the caller and common-channel members that negotiated the cap. | `src/daemon/dispatch.zig:334`, `src/daemon/server.zig:22227-22245` |
| `extended-join` | none | Negotiates extended JOIN account/realname data. | `src/daemon/dispatch.zig:335` |
| `invite-notify` | none | Negotiates invite notifications. | `src/daemon/dispatch.zig:336` |
| `account-tag` | none | Adds `account` tags when an account is known and the recipient negotiated the cap. | `src/daemon/dispatch.zig:337`, `src/daemon/server.zig:37876-37890` |
| `onyx/session-sync` | none | Opts into sibling-device direct-message mirroring and outgoing DM self-view. | `src/daemon/dispatch.zig:338-340`, `src/daemon/server.zig:29925-29939` |
| `onyx/2fa` | `IDENTIFY` | Onyx vendor cap for two-factor identity assertion. | `src/proto/live_cap_metadata.zig:195` |
| `onyx/privacy` | `umode=DGIZTVW,cmode=cBK` | Onyx vendor cap advertising the enforced privacy user/channel modes. | `src/proto/live_cap_metadata.zig:199` |
| `onyx/bouncer` | none | Replays missed channel history after the client's read marker on join. | `src/daemon/dispatch.zig:341-344`, `src/daemon/server.zig:14928-14947` |
| `onyx/topics` | none | Allows `+onyx/topic` named-conversation tags without requiring generic `message-tags`; CHATHISTORY can filter by the topic tag. | `src/daemon/dispatch.zig:345-348`, `src/daemon/server.zig:15042-15046`, `src/daemon/server.zig:30355-30363` |
| `onyx/e2ee` | none | Allows Onyx Server E2EE control-plane tags and supports channel encryption-policy enforcement. | `src/daemon/dispatch.zig:349-352`, `src/daemon/server.zig:29730-29737`, `src/daemon/server.zig:30355-30363` |
| `chghost` | none | Negotiates host-change notifications. | `src/daemon/dispatch.zig:353-355` |
| `no-implicit-names` | none | Suppresses the automatic NAMES burst after JOIN. | `src/daemon/dispatch.zig:356-362` |
| `draft/no-implicit-names` | none | Alias for `no-implicit-names`; either token maps to the same capability id. | `src/daemon/dispatch.zig:356-362`, `src/daemon/dispatch.zig:729-733` |
| `draft/chathistory` | none | Enables `CHATHISTORY`; replay is emitted as `chathistory` BATCH output when `batch` is also negotiated, otherwise as plain replay lines. | `src/daemon/dispatch.zig:363-377`, `src/daemon/server.zig:14821-14853`, `src/daemon/server.zig:15016-15145` |
| `draft/search` | none | Enables full-text search over the CHATHISTORY store, scoped to visible target history and replayed through the same renderer. | `src/daemon/dispatch.zig:374-377`, `src/daemon/server.zig:15176-15285` |
| `draft/message-redaction` | none | Enables `REDACT`; operator-authorized redactions tombstone history and notify capable recipients. | `src/daemon/dispatch.zig:378`, `src/daemon/server.zig:21546-21606` |
| `draft/message-editing` | none | Enables `EDIT`; original senders can update stored message text and capable recipients receive edit-tagged updates. | `src/daemon/dispatch.zig:379`, `src/daemon/server.zig:21608-21679`, `src/daemon/server.zig:30355-30363` |
| `draft/read-marker` | none | Enables `MARKREAD` state and read-marker replies. | `src/daemon/dispatch.zig:380`, `src/proto/read_marker.zig:91-151` |
| `draft/event-playback` | none | Allows non-message history events to appear in replay output. | `src/daemon/dispatch.zig:381`, `src/daemon/server.zig:14807-14811`, `src/daemon/server.zig:15148-15152` |
| `draft/typing` | none | Allows `+typing`/`+draft/typing` client-only tags to reach draft-capable recipients, including through `TAGMSG`. | `src/daemon/dispatch.zig:382`, `src/daemon/server.zig:30355-30363`, `src/daemon/server.zig:38039-38076` |
| `draft/react` | none | Allows `+draft/react` and `+draft/unreact` client-only tags to reach draft-capable recipients and feed activity. | `src/daemon/dispatch.zig:383`, `src/daemon/server.zig:29241-29257`, `src/daemon/server.zig:30355-30363` |
| `draft/reply` | none | Allows `+draft/reply` client-only tags to reach draft-capable recipients. | `src/daemon/dispatch.zig:384`, `src/daemon/server.zig:30355-30363` |
| `batch` | none | Enables server BATCH framing for CHATHISTORY, SEARCH, labeled-response multi-line replies, and netsplit/netjoin outputs. | `src/daemon/dispatch.zig:385`, `src/daemon/server.zig:14837-14853`, `src/daemon/server.zig:15180-15182`, `src/daemon/dispatch.zig:1582-1657` |
| `bot` | none | Surfaces bot tags/status to `message-tags` recipients. | `src/daemon/dispatch.zig:386`, `src/daemon/server.zig:37921-37930` |
| `draft/channel-rename` | none | Negotiates channel rename notifications. | `src/daemon/dispatch.zig:387-389` |
| `extended-monitor` | none | Negotiates AWAY, SETNAME, CHGHOST, and ACCOUNT changes for monitored nicks. | `src/daemon/dispatch.zig:390-392` |
| `account-notify` | none | Sends ACCOUNT changes for users in common channels. | `src/daemon/dispatch.zig:393-396` |
| `draft/account-registration` | `custom-account-name` | Enables `REGISTER`/`VERIFY` account registration after connection completion; pre-registration registration is not advertised. | `src/daemon/dispatch.zig:397-403`, `src/daemon/server.zig:22965-23021` |
| `draft/metadata-2` | none | Enables `METADATA GET`, `LIST`, `SET`, and `CLEAR` with metadata numerics. | `src/daemon/dispatch.zig:404-405`, `src/daemon/server.zig:21400-21498` |
| `standard-replies` | none | Enables typed `FAIL`/`WARN` surfaces used by command errors and validation failures. | `src/daemon/dispatch.zig:406-407`, `src/proto/standard_replies.zig:201-206`, `src/proto/standard_replies.zig:343-354` |
| `cap-notify` | none | Advertises capability-notify support; the current cap set is static, so runtime `CAP NEW`/`DEL` is not expected. | `src/daemon/dispatch.zig:408-410` |
| `labeled-response` | none | Applies `@label` to responses, using a labeled-response BATCH for multi-line replies and bare `ACK` for no-output commands. | `src/daemon/dispatch.zig:411-415`, `src/daemon/dispatch.zig:1582-1657`, `src/daemon/server.zig:32120-32145` |
| `draft/pre-away` | none | Allows `AWAY` during registration so away state is set before welcome completion. | `src/daemon/dispatch.zig:416-420` |
| `draft/channel-context` | none | Allows `+draft/channel-context=<channel>` client-only tags on direct messages through the client tag relay. | `src/daemon/dispatch.zig:421-424`, `src/daemon/server.zig:30355-30363` |
| `draft/multiline` | `max-bytes=40000,max-lines=64`, or runtime config | Accepts inbound `BATCH +ref draft/multiline <target>` and reassembles PRIVMSG/NOTICE chunks within runtime limits. | `src/daemon/dispatch.zig:425-428`, `src/daemon/dispatch.zig:1410-1415`, `src/daemon/server.zig:29564-29655`, `src/daemon/server.zig:38951-39029` |
| `sts` | runtime policy | Advertised only when a runtime STS policy exists; default sessions omit it. | `src/daemon/dispatch.zig:429-436`, `src/daemon/dispatch.zig:598-615` |
| `account-extban` | `a` | Advertises `$a` account extban support. | `src/daemon/dispatch.zig:437-441` |
| `utf8-only` | none | Advertises global UTF-8 enforcement; malformed message bodies are rejected with `FAIL ... INVALID_UTF8` for PRIVMSG. | `src/daemon/dispatch.zig:439-442`, `src/daemon/server.zig:29511-29523` |
| `draft/netsplit` | none | Advertises netsplit BATCH framing. | `src/daemon/dispatch.zig:439-443`, `src/daemon/netsplit_batch.zig:148-172` |
| `draft/netjoin` | none | Advertises netjoin BATCH framing. | `src/daemon/dispatch.zig:439-444`, `src/daemon/netsplit_batch.zig:148-172` |

## Negotiation details

`CAP LS` output is chunked when the advertised set would exceed the configured
segment size. `CAP REQ` resolves every requested token before mutating the
negotiated set; unknown names, unavailable policy-gated names, empty values, or
unoffered values cause a `NAK` for the whole request.

Value-bearing requests are accepted when the requested value exactly matches the
offered value or one item in a comma-separated offered list. That applies to
`sasl`, `draft/multiline`, `draft/account-registration`, `account-extban`, and
runtime `sts` values.

Source: `src/daemon/dispatch.zig:598-638`,
`src/daemon/dispatch.zig:663-727`.

## Message tags

Inbound IRCv3 tags are parsed from a leading `@tags` segment. `@label` is
captured and unescaped for labeled-response handling. Other message tags remain
available as raw client tags to delivery code.

Only client-only tags (`+...`) are relayed. Generic relay requires
`message-tags`; specific tags can also be delivered to recipients with narrower
caps:

| Tag key | Narrow cap |
|---------|------------|
| `+onyx/topic` | `onyx/topics` |
| Onyx Server encrypted-message tag keys | `onyx/e2ee` |
| `+typing`, `+draft/typing` | `draft/typing` |
| `+draft/react`, `+draft/unreact` | `draft/react` |
| `+draft/reply` | `draft/reply` |
| `+draft/edit`, `+draft/revision` | `draft/message-editing` |

Server-owned tags such as `time`, `account`, `msgid`, and `bot` are generated
by the daemon and are not accepted from client input. Malformed or oversized
tag input closes only the sender connection in the threaded server tests.

Source: `src/daemon/dispatch.zig:116-136`,
`src/daemon/dispatch.zig:752-798`,
`src/daemon/server.zig:30355-30397`,
`src/proto/message_tags_relay.zig:30-72`,
`src/proto/message_tags_relay.zig:93-158`,
`src/daemon/server.zig:38166-38243`.

## SASL mechanisms

`sasl` is advertised only when `writeSaslCapValue` can build a non-empty
mechanism list for the session. The CAP value is comma-separated; numeric 908
uses the same enabled mechanisms in space-separated form.

| Mechanism | Advertisement condition |
|-----------|-------------------------|
| `PLAIN` | `sasl_plain` verifier is configured. |
| `EXTERNAL` | `sasl_external` verifier is configured. |
| `SCRAM-SHA-256` | SCRAM-SHA-256 lookup and server nonce are configured. |
| `SCRAM-SHA-512` | SCRAM-SHA-512 lookup and server nonce are configured. |
| `SCRAM-SHA-512-PLUS` | SCRAM-SHA-512 lookup, server nonce, and TLS exporter are configured. |
| `SESSION-TOKEN` | Session-token verifier is configured. |
| `OAUTHBEARER` | OAuth bearer verifier is configured. |
| `ANONYMOUS` | Anonymous SASL is enabled for the session. |

`AUTHENTICATE` is rejected unless the client negotiated `sasl`. Each mechanism
fails closed when its verifier is missing, and unsupported mechanism requests
emit numeric 908 with the current mechanism list before failing authentication.

Source: `src/daemon/dispatch.zig:1418-1441`,
`src/daemon/dispatch.zig:1810-1857`,
`src/daemon/dispatch.zig:2034-2043`.
