# IRCv3 Capability Reference

This file documents the current Onyx Server IRCv3 client capability surface. The
filename is historical; do not treat it as product terminology.

## Source of truth

Onyx Server imports the immutable `cap_specs` table from
`src/proto/live_cap_metadata.zig` into `src/daemon/dispatch.zig`. CAP negotiation is handled by `CapSession.handle`:
`LS` emits the advertised set, `REQ` atomically ACKs or NAKs the requested token
list, `LIST` reports negotiated caps, and `END` completes negotiation.

Source: `src/daemon/dispatch.zig`.

## Advertised capabilities

Use [the canonical CAP table](protocol/caps.md) for the complete 47-name inventory,
values and policy gates. This page owns the complementary SASL and message-tag
semantics rather than a second copy of that inventory.

## Negotiation details

`CAP LS` output is chunked when the advertised set would exceed the configured
segment size. `CAP REQ` resolves every requested token before mutating the
negotiated set; unknown names, unavailable policy-gated names, empty values, or
unoffered values cause a `NAK` for the whole request.

Value-bearing requests are accepted when the requested value exactly matches the
offered value or one item in a comma-separated offered list. That applies to
`sasl`, `draft/multiline`, `draft/account-registration`, `account-extban`, and
runtime `sts` values.

Source: `src/daemon/dispatch.zig`.

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

Source: `src/daemon/dispatch.zig`,
`src/daemon/server.zig`,
`src/proto/message_tags_relay.zig`,
`src/daemon/server.zig`.

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

Source: `src/daemon/dispatch.zig`.
