# Native media authentication and endpoint keys

This is the current client/server contract for native CadenceVox/CadenceVis UDP
media. It distinguishes live physical endpoint admission from retained legacy
codec helpers. Sources: [media_capability.zig](../../src/substrate/media_capability.zig),
[native_media_transport.zig](../../src/daemon/native_media_transport.zig),
[cadence_frame.zig](../../src/substrate/cadence_frame.zig),
[native_feedback.zig](../../src/substrate/native_feedback.zig), and
`PreparedMediaAdvertisements` in [server.zig](../../src/daemon/server.zig).

## Issuance and scope

A successful native `MEDIA OFFER`/`ANSWER` transaction prepares an exact physical
endpoint and caller-only protected replies before publishing transport authority.
`MEDIA NATIVE` advertises the candidate, issued nonzero stream ID, codec and
`mac=hmac-sha256-128`. `MEDIA NATIVE-MACKEY` carries `stream=<id> key=<base64>`;
the key is fresh 32-byte endpoint master material, not a public stream selector.
The protected signaling output and endpoint publication are one transaction.
A plaintext caller cannot receive these secrets through a fallback output path.

The current physical endpoint is tied to the routing Domain, call, physical
client/leg and endpoint incarnation. A matching channel/nickname or a remembered
stream ID alone cannot authorize another endpoint. A logical non-browser
`MEDIA JOIN` does not itself allocate UDP credentials. Browser `MEDIA MACKEY`
uses a separate WebSocket media contract; do not substitute that key for a native
endpoint's master. See [credential domains](credential-domains.md#media-credentials).

## Direction and purpose derivation

For each issued stream, derive four independent 32-byte keys:

```text
key = HMAC-SHA256(master, label || 0x00 || stream_id_u32_be)
```

| Purpose | Exact label |
|---|---|
| Client to server media | `onyx native endpoint capability v1 c2s frame` |
| Server to client media | `onyx native endpoint capability v1 s2c frame` |
| Client to server feedback | `onyx native endpoint capability v1 c2s feedback` |
| Server to client feedback | `onyx native endpoint capability v1 s2c feedback` |

`media_capability.derive` rejects stream zero and provides independent test vectors.
Never use the master directly as a datagram key, or reuse a key across direction
or purpose. A server-to-client packet cannot authenticate as client-to-server input.

## Cadence media frame

```text
payload_length:u32le | band_id:u8 | stream_id:u32le | sequence:u32le |
timestamp:u64le | flags:u8 | codec_tag:u8 | payload | mac_tag:16
```

The payload-length prefix excludes the appended MAC. The 16-byte tag is
`HMAC-SHA256(direction_frame_key, complete_frame_without_tag)[0..16]`.
Verification uses constant-time comparison. The live physical admission path
requires exact framing and a valid client-to-server tag before address learning,
metering or routing. It also checks the current endpoint stamp, offered codecs,
media kind and ownership of the source address. Outbound protection uses the
recipient's server-to-client key rather than forwarding the sender's tag.

## Native feedback envelope

```text
"ONFB" | version:u8=1 | sender_stream_id:u32be | payload_len:u16be |
feedback_payload | mac_tag:16
```

The tag is `HMAC-SHA256(direction_feedback_key, envelope_without_tag)[0..16]`.
The sender selector identifies the authenticating endpoint; the payload's stream
is the target of feedback. Current admission checks exact payload shapes, endpoint
and source-address ownership, and bounds NACK requests to 1..64 sequence numbers.
It rejects malformed or trailing data before publication. A MAC authenticates
bytes; it does not itself provide freshness. The codec permits repeated
well-formed authenticated feedback operations.

## Legacy helpers and configuration

`cadence_frame.deriveNativeMediaMacKey` retains the older process-root plus
channel/participant derivation. The pure `acceptNativeMediaMac` helper can accept
untagged frames when its `require_tag` input is false. Those helpers and the
`[media].native_media_require_mac` compatibility setting do not weaken the current
physical routing path's endpoint/direction verification. Source-level helper
compatibility is not proof that an untagged packet can enter a live configured
physical endpoint.

Stream IDs remain public selectors. Their width or unpredictability is not a
substitute for authentication. Keys and retained issuer output are secrets;
never log them, publish them in an operator event, or include them in a bug report.
The MAC authenticates transport bytes and provides no payload encryption. Browser
client-held media E2EE and SRTP/DTLS use separate security domains.

See [media architecture](../architecture/03-media.md), [MEDIA commands](commands/media.md),
and [the test guide](../guide/testing.md) for integration and verification.
