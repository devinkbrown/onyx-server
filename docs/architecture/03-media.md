# Media architecture

*Onyx Server's media stack: an Undertow SFU control plane, RTP/SRTP and native Cadence UDP legs, header-only Cadence-frame <-> RTP rewrap, DTLS-SRTP keying, WebTransport framing, and browser/WASM codec exports.*

This document covers the current source tree only.

## SFU control plane

`src/substrate/undertow/media.zig` is the pure media control substrate. It owns bounded roster state, SFU forwarding decisions, simulcast layer choice, ABR hints, and codec offer/answer negotiation, with hot paths using inline storage. Evidence: `src/substrate/undertow/media.zig:4`, `src/substrate/undertow/media.zig:6`, `src/substrate/undertow/media.zig:7`.

| Type | Role | Evidence |
| --- | --- | --- |
| `MediaKind` | Voice, video, and screen media kinds. | `src/substrate/undertow/media.zig:47` |
| `ParticipantId` | Bounded inline participant id with validation. | `src/substrate/undertow/media.zig:87`, `src/substrate/undertow/media.zig:93` |
| `Participant` | Tracks joined, muted, and speaking kind sets; controls publish/receive checks. | `src/substrate/undertow/media.zig:115`, `src/substrate/undertow/media.zig:121`, `src/substrate/undertow/media.zig:125` |
| `Session(max_participants)` | Inline roster, join/leave/mute/speaking operations, and `forwardSet`. | `src/substrate/undertow/media.zig:132`, `src/substrate/undertow/media.zig:140`, `src/substrate/undertow/media.zig:151`, `src/substrate/undertow/media.zig:167`, `src/substrate/undertow/media.zig:180`, `src/substrate/undertow/media.zig:205` |
| `RoutePolicy` | Optional `require_speaking` forwarding gate. | `src/substrate/undertow/media.zig:246` |

`forwardSet` verifies the source participant exists, verifies the source can publish the requested kind, optionally requires the source to be speaking, and returns receivers that can receive the kind while excluding the source. Evidence: `src/substrate/undertow/media.zig:211`, `src/substrate/undertow/media.zig:213`, `src/substrate/undertow/media.zig:214`, `src/substrate/undertow/media.zig:218`, `src/substrate/undertow/media.zig:220`, `src/substrate/undertow/media.zig:221`.

## Daemon media rooms

`src/daemon/media_room.zig` maps an IRC channel to an Undertow `Session`. This is control plane only: who is in a call, what they publish, and mute/speaking state; media bytes flow over the transport substrate. Evidence: `src/daemon/media_room.zig:4`, `src/daemon/media_room.zig:5`, `src/daemon/media_room.zig:6`, `src/daemon/media_room.zig:7`.

| Concern | Current behavior | Evidence |
| --- | --- | --- |
| Room sizing | Runtime default is 64 participants, while the inline `Room` ceiling is `media.Session(256)`. `[media].max_participants` is clamped to `1..256` and enforced at join. | `src/daemon/media_room.zig:17`, `src/daemon/media_room.zig:18`, `src/daemon/media_room.zig:19`, `src/daemon/media_room.zig:23`, `src/daemon/media_room.zig:32`, `src/daemon/media_room.zig:37`, `src/daemon/media_room.zig:339` |
| Native leg sizing | The native Cadence leg is separately bounded at 64 participants per call. | `src/daemon/native_media_transport.zig:35`, `src/daemon/native_media_transport.zig:42`, `src/daemon/native_media_transport.zig:43` |
| Runtime config | Breakout label cap and participant cap are runtime-tunable under the inline ceilings. | `src/daemon/media_room.zig:25`, `src/daemon/media_room.zig:26`, `src/daemon/media_room.zig:27`, `src/daemon/media_room.zig:39` |
| Per-channel maps | Rooms, breakouts, positions, hands, negotiated profiles, and per-participant profiles are keyed by channel/composite keys. | `src/daemon/media_room.zig:84`, `src/daemon/media_room.zig:87`, `src/daemon/media_room.zig:91`, `src/daemon/media_room.zig:94`, `src/daemon/media_room.zig:96`, `src/daemon/media_room.zig:100`, `src/daemon/media_room.zig:104` |
| Codec/FEC profile | `MEDIA OFFER` establishes a per-channel `CallProfile`; `MEDIA ANSWER` consults it. | `src/daemon/media_room.zig:70`, `src/daemon/media_room.zig:73`, `src/daemon/media_room.zig:259`, `src/daemon/server.zig:26596`, `src/daemon/server.zig:26822` |
| Room lifecycle | Join creates the room on first join; leave prunes when empty. | `src/daemon/media_room.zig:334`, `src/daemon/media_room.zig:385`, `src/daemon/media_room.zig:354`, `src/daemon/media_room.zig:396` |

## RTP/SRTP media plane

`src/daemon/media_plane.zig` ties the `MediaTransport` endpoint registry to a live UDP socket and pump thread. The pump demuxes DTLS/STUN/RTP/RTCP, answers STUN checks, and relays RTP/RTCP under a mutex. Evidence: `src/daemon/media_plane.zig:4`, `src/daemon/media_plane.zig:5`, `src/daemon/media_plane.zig:7`, `src/daemon/media_plane.zig:334`, `src/daemon/media_plane.zig:343`.

| Path | Behavior | Evidence |
| --- | --- | --- |
| Startup | Binds UDP, records local port, optionally discovers a server-reflexive candidate, sets recv timeout, and spawns the pump thread. | `src/daemon/media_plane.zig:182`, `src/daemon/media_plane.zig:186`, `src/daemon/media_plane.zig:188`, `src/daemon/media_plane.zig:191`, `src/daemon/media_plane.zig:198`, `src/daemon/media_plane.zig:214` |
| STUN | STUN datagrams call `transport.handleStunBinding` under the mutex and send a response if one is built. | `src/daemon/media_plane.zig:334`, `src/daemon/media_plane.zig:336`, `src/daemon/media_plane.zig:340` |
| RTP/RTCP filter | Non-STUN media must look like RTP/RTCP version 2 and be at least RTP header length, preventing open UDP reflection. | `src/daemon/media_plane.zig:343`, `src/daemon/media_plane.zig:345` |
| RTCP feedback | RTCP is decrypted first for DTLS peers, then Generic NACK is terminated locally from the retransmit cache; other RTCP is relayed or translated cross-leg. | `src/daemon/media_plane.zig:612`, `src/daemon/media_plane.zig:621`, `src/daemon/media_plane.zig:643`, `src/daemon/media_plane.zig:649`, `src/daemon/media_plane.zig:652` |
| RTP relay | Decodes RTP header where possible, forwards through `transport.forwardFromSource`, caches for NACK, and sends to selected targets. | `src/daemon/media_plane.zig:354`, `src/daemon/media_plane.zig:356`, `src/daemon/media_plane.zig:567`, `src/daemon/media_plane.zig:581`, `src/daemon/media_plane.zig:592` |
| Cross-leg bridge | After RTP relay, the plane can call an installed `RtpCrossSink` to reach native participants. | `src/daemon/media_plane.zig:105`, `src/daemon/media_plane.zig:177`, `src/daemon/media_plane.zig:606`, `src/daemon/media_plane.zig:608` |
| Signaling support | `allocate` returns ICE credentials; `groupKey` returns the legacy per-call SRTP group key; `remoteFor` resolves live peer address. | `src/daemon/media_plane.zig:710`, `src/daemon/media_plane.zig:715`, `src/daemon/media_plane.zig:728`, `src/daemon/media_plane.zig:735` |

### RTP/RTCP helpers

The RTP/RTCP helpers are pure protocol surfaces used by the plane and bridge. `rtp_profile.zig` owns the 12-byte RTP header, RFC 3550-style stats, and SR/RR helpers; `rtp_ext.zig` parses RFC 8285 RTP extensions; `rtp_red.zig` handles RED payload blocks; `rtcp_compound.zig`, `rtcp_translate.zig`, and `rtcp_xr.zig` parse/build RTCP compound, feedback, and XR packets. SRTP/SRTCP protection lives in `srtp.zig` and `srtcp.zig`. Evidence: `src/proto/rtp_profile.zig:4`, `src/proto/rtp_profile.zig:12`, `src/proto/rtp_ext.zig:4`, `src/proto/rtp_red.zig:12`, `src/proto/rtcp_compound.zig:4`, `src/proto/rtcp_translate.zig:4`, `src/proto/rtcp_xr.zig:4`, `src/proto/srtp.zig:4`, `src/proto/srtcp.zig:4`.

## DTLS-SRTP signaling and RFC 8122 fingerprint verification

DTLS-SRTP is opt-in (`[media].dtls_srtp`, plus `[media].dtls13` for the DTLS 1.3 engine). When enabled, RFC 7983 demux routes DTLS records to the per-peer terminator; otherwise STUN/RTP/SRTP paths remain byte-identical. The DTLS 1.2 and 1.3 engines share one certificate fingerprint for signaling. Evidence: `src/daemon/server.zig:3649`, `src/daemon/server.zig:3650`, `src/daemon/server.zig:3651`, `src/daemon/media_plane.zig:327`, `src/daemon/media_plane.zig:330`, `src/daemon/media_plane.zig:247`, `src/daemon/media_plane.zig:255`.

The signaling path parses `fingerprint=sha-256:<colon-hex>` on `MEDIA OFFER`/`MEDIA ANSWER` and fails closed on malformed fingerprints or a DTLS request while the feature is unavailable. When accepted, the peer fingerprint is stored per `(channel, participant)`, resolved to the peer's ICE-bound transport address, and bound into both DTLS terminators before handshake completion. Evidence: `src/daemon/server.zig:26554`, `src/daemon/server.zig:26557`, `src/daemon/server.zig:26609`, `src/daemon/server.zig:26621`, `src/daemon/server.zig:26629`, `src/daemon/server.zig:26834`, `src/daemon/server.zig:26875`, `src/daemon/media_plane.zig:489`, `src/daemon/media_plane.zig:527`, `src/daemon/media_plane.zig:538`, `src/daemon/media_plane.zig:551`.

| Path | Behavior | Evidence |
| --- | --- | --- |
| Server identity | In DTLS mode, `MEDIA TRANSPORT` advertises `fingerprint=<server fp>` and `setup=passive` instead of the legacy `srtp=` group key. | `src/daemon/server.zig:26684`, `src/daemon/server.zig:26692`, `src/daemon/server.zig:26702`, `src/daemon/server.zig:40671`, `src/daemon/server.zig:40682` |
| `use_srtp` | `dtls_srtp.zig` defines RFC 5764 profiles, key export, and `use_srtp` encode/parse helpers; both terminators select AES-128-CM-HMAC-SHA1-80 when offered. | `src/proto/dtls_srtp.zig:4`, `src/proto/dtls_srtp.zig:19`, `src/proto/dtls_srtp.zig:78`, `src/proto/dtls_srtp.zig:129`, `src/proto/dtls12_server.zig:754`, `src/proto/dtls13_server.zig:815` |
| Verification gate | `exportedKeys` and `srtpProfile` return null for a bound-but-unverified peer; `recordPeerCertificate` is the certificate-capture seam and uses constant-time digest compare. | `src/proto/dtls_peer_verify.zig:4`, `src/proto/dtls_peer_verify.zig:41`, `src/proto/dtls12_server.zig:235`, `src/proto/dtls12_server.zig:240`, `src/proto/dtls12_server.zig:249`, `src/proto/dtls12_server.zig:279`, `src/proto/dtls13_server.zig:245`, `src/proto/dtls13_server.zig:254`, `src/proto/dtls13_server.zig:274` |
| Per-recipient SRTP | For established DTLS peers, RTP is decrypted once to a canonical packet and re-encrypted per DTLS recipient; SRTCP follows the same canonical-then-protect model. | `src/daemon/media_plane.zig:559`, `src/daemon/media_plane.zig:575`, `src/daemon/media_plane.zig:592`, `src/daemon/media_plane.zig:600`, `src/daemon/media_plane.zig:655`, `src/daemon/media_plane.zig:665` |

## Native CadenceVox/CadenceVis transport

`src/daemon/native_media_transport.zig` is the daemon-owned native UDP leg for CadenceVox/CadenceVis framing. It forwards Cadence frame datagrams, not RTP, and never transcodes. Evidence: `src/daemon/native_media_transport.zig:4`, `src/daemon/native_media_transport.zig:5`, `src/daemon/native_media_transport.zig:6`, `src/daemon/native_media_transport.zig:17`, `src/daemon/native_media_transport.zig:18`.

| Path | Behavior | Evidence |
| --- | --- | --- |
| Channel isolation | Each call/channel has its own `NativeMediaLink`; a stream-id index maps inbound datagrams to the owning channel. | `src/daemon/native_media_transport.zig:9`, `src/daemon/native_media_transport.zig:10`, `src/daemon/native_media_transport.zig:55`, `src/daemon/native_media_transport.zig:57` |
| Startup | Binds UDP, records local port, sets recv timeout, starts pump thread. | `src/daemon/native_media_transport.zig:117`, `src/daemon/native_media_transport.zig:121`, `src/daemon/native_media_transport.zig:123`, `src/daemon/native_media_transport.zig:124`, `src/daemon/native_media_transport.zig:128` |
| Frame validation | Pump requires Cadence framing, accepts either an exact frame or frame+MAC tag, and decodes before routing. | `src/daemon/native_media_transport.zig:154`, `src/daemon/native_media_transport.zig:160`, `src/daemon/native_media_transport.zig:161`, `src/daemon/native_media_transport.zig:162` |
| Forwarding | Routes by stream id, authenticates the datagram, learns/verifies publisher address, computes SFU forward set, and resends the same bytes to each recipient. | `src/daemon/native_media_transport.zig:170`, `src/daemon/native_media_transport.zig:173`, `src/daemon/native_media_transport.zig:175`, `src/daemon/native_media_transport.zig:191`, `src/daemon/native_media_link.zig:224`, `src/daemon/native_media_link.zig:236`, `src/daemon/native_media_link.zig:242` |
| Registration | `register` records channel, participant id, media kind, stream id, and address, then indexes stream id to channel. | `src/daemon/native_media_transport.zig:325`, `src/daemon/native_media_transport.zig:329`, `src/daemon/native_media_transport.zig:344`, `src/daemon/native_media_transport.zig:349`, `src/daemon/native_media_transport.zig:350` |
| Cross-leg bridge | After native forwarding, a native frame can be handed to a cross-leg sink for RTP/SRTP participants. | `src/daemon/native_media_transport.zig:78`, `src/daemon/native_media_transport.zig:94`, `src/daemon/native_media_transport.zig:193`, `src/daemon/native_media_transport.zig:195` |

### Native security model

Native stream ids are keyed HMAC-derived capability tokens per `(channel, nick)`, delivered through authenticated IRC signaling. The optional per-datagram MAC uses a key derived from the same native stream PRF root plus `(channel, participant)`, HMAC-SHA256 truncated to 128 bits. When `[media].native_media_require_mac` is false, untagged frames are accepted for compatibility but present tags must verify; when it is true, missing or bad tags fail closed before forwarding. Evidence: `src/daemon/server.zig:26781`, `src/daemon/server.zig:26796`, `src/daemon/server.zig:26717`, `src/daemon/config_format.zig:464`, `src/daemon/config_format.zig:1193`, `src/daemon/server.zig:3628`, `src/substrate/cadence_frame.zig:68`, `src/substrate/cadence_frame.zig:248`, `src/substrate/cadence_frame.zig:300`, `src/substrate/cadence_frame.zig:320`, `src/substrate/cadence_frame.zig:327`, `src/substrate/cadence_frame.zig:329`, `src/daemon/native_media_transport.zig:246`, `src/daemon/native_media_transport.zig:249`, `src/daemon/native_media_transport.zig:252`.

Address binding is also fail-closed for native streams after the first observed source: `NativeMediaLink.inboundFrom` learns a publisher address, then rejects later datagrams for that stream from a different address; native feedback envelopes use `bindAddressForStream` for the same ownership check. Evidence: `src/daemon/native_media_link.zig:105`, `src/daemon/native_media_link.zig:108`, `src/daemon/native_media_link.zig:111`, `src/daemon/native_media_link.zig:224`, `src/daemon/native_media_link.zig:236`, `src/daemon/native_media_transport.zig:213`.

## Cadence frame container and codecs

`src/substrate/cadence_frame.zig` is a wire container, not the audio/video codec itself. It carries encoded payloads over media bands. Evidence: `src/substrate/cadence_frame.zig:4`, `src/substrate/cadence_frame.zig:6`, `src/substrate/cadence_frame.zig:7`.

| Field/behavior | Evidence |
| --- | --- |
| Media bands are `band_id >= 64`; control bands are below 64. | `src/substrate/cadence_frame.zig:10`, `src/substrate/cadence_frame.zig:61`, `src/substrate/cadence_frame.zig:136` |
| Wire format includes payload length, band id, stream id, sequence, timestamp, keyframe flag, codec tag, and payload. | `src/substrate/cadence_frame.zig:12`, `src/substrate/cadence_frame.zig:14`, `src/substrate/cadence_frame.zig:19`, `src/substrate/cadence_frame.zig:20` |
| `CodecTag` supports `raw`, `cadencevox_audio`, and `cadencevis_video`. | `src/substrate/cadence_frame.zig:78`, `src/substrate/cadence_frame.zig:80`, `src/substrate/cadence_frame.zig:81`, `src/substrate/cadence_frame.zig:82` |
| Decode rejects truncation, control band ids, trailing bytes, and unknown codec tags. | `src/substrate/cadence_frame.zig:171`, `src/substrate/cadence_frame.zig:175`, `src/substrate/cadence_frame.zig:222`, `src/substrate/cadence_frame.zig:232` |
| ReassemblyBuffer is a bounded jitter/reorder buffer with compile-time payload/window bounds and runtime window config. | `src/substrate/cadence_frame.zig:396`, `src/substrate/cadence_frame.zig:397`, `src/substrate/cadence_frame.zig:410`, `src/substrate/cadence_frame.zig:418` |
| CadenceVox is an allocation-free IMA ADPCM voice codec building block; CadenceVis is an allocation-free lossless delta/RLE video building block. | `src/substrate/cadencevox_adpcm.zig:4`, `src/substrate/cadencevox_adpcm.zig:6`, `src/substrate/cadencevox_adpcm.zig:58`, `src/substrate/cadencevox_adpcm.zig:76`, `src/substrate/cadencevis_delta.zig:4`, `src/substrate/cadencevis_delta.zig:6`, `src/substrate/cadencevis_delta.zig:60`, `src/substrate/cadencevis_delta.zig:71` |

## Cross-leg bridge

`src/daemon/media_bridge.zig` bridges participants on the native Cadence leg and the RTP/SRTP leg by header rewrap only. Payload bytes stay opaque and are shared verbatim; there is no encoding, decoding, or transcoding. Evidence: `src/daemon/media_bridge.zig:4`, `src/daemon/media_bridge.zig:6`, `src/daemon/media_bridge.zig:10`, `src/daemon/media_bridge.zig:19`.

| Direction | Behavior | Evidence |
| --- | --- | --- |
| Native to RTP | Decode Cadence frame, map to bridge frame, write RTP using the mapped SSRC, send to opposite-leg members. | `src/daemon/media_bridge.zig:254`, `src/daemon/media_bridge.zig:260`, `src/daemon/media_bridge.zig:261`, `src/daemon/media_bridge.zig:266`, `src/daemon/media_bridge.zig:268`, `src/daemon/media_bridge.zig:269` |
| RTP to native | Decode RTP header, map to native frame with the mapped stream id, encode Cadence datagram, send to native members. | `src/daemon/media_bridge.zig:272`, `src/daemon/media_bridge.zig:276`, `src/daemon/media_bridge.zig:277`, `src/daemon/media_bridge.zig:282`, `src/daemon/media_bridge.zig:283`, `src/daemon/media_bridge.zig:285`, `src/daemon/media_bridge.zig:286` |
| Target selection | Cross-leg targets are opposite-leg recipients from the per-channel session, excluding disconnected/ineligible members. | `src/daemon/media_bridge.zig:236`, `src/daemon/media_bridge.zig:237`, `src/daemon/media_bridge.zig:240`, `src/daemon/media_bridge.zig:243` |
| Transcode-free gate | Participant codec sets must converge on a shared codec; incompatible sets cause cross-leg fanout to drop rather than transcode. | `src/daemon/media_bridge.zig:191`, `src/daemon/media_bridge.zig:213`, `src/daemon/media_bridge.zig:221`, `src/daemon/media_bridge.zig:262`, `src/daemon/media_bridge.zig:278` |

The live server installs bridge callbacks around `LinuxServer.media_bridges`, `media_plane`, and `native_media`. Evidence: `src/daemon/server.zig:190`, `src/daemon/server.zig:244`, `src/daemon/server.zig:3589`, `src/daemon/server.zig:3590`, `src/daemon/server.zig:3646`, `src/daemon/server.zig:3664`, `src/daemon/server.zig:26750`.

## MEDIA command and EVENT-plane signaling

`MEDIA` is the command surface for call presence, codec negotiation, transport credential replies, native-leg registration, stats, ABR/layer hints, captions, reactions, roster, and leave cleanup. Media bytes do not flow through the command handler. Evidence: `src/daemon/server.zig:25968`, `src/daemon/server.zig:25970`, `src/daemon/server.zig:26007`, `src/daemon/server.zig:26023`, `src/daemon/server.zig:26027`, `src/daemon/server.zig:26055`, `src/daemon/server.zig:26163`, `src/daemon/server.zig:26218`, `src/daemon/server.zig:26242`.

`MEDIA OFFER` and `MEDIA ANSWER` negotiate Cadence codecs through the SDP/media-session path, publish capability/profile events, and provision both the RTP/SRTP transport and the native Cadence candidate/stream id. Evidence: `src/daemon/server.zig:26596`, `src/daemon/server.zig:26637`, `src/daemon/server.zig:26639`, `src/daemon/server.zig:26656`, `src/daemon/server.zig:26661`, `src/daemon/server.zig:26669`, `src/daemon/server.zig:26679`, `src/daemon/server.zig:26713`, `src/daemon/server.zig:26725`, `src/daemon/server.zig:26822`, `src/daemon/server.zig:26880`, `src/daemon/server.zig:26884`.

Media presence rides the IRCX EVENT plane as `MEDIA <action> <channel> <nick> [detail]`. `MEDIA` is an IRCX event type ordinary clients may subscribe to, but non-oper delivery is member-scoped: the event's channel is the subject, and `mediaEventAllowed` requires the recipient to be a member of that channel. Non-members do not see call presence, including for private/secret channels. Evidence: `src/daemon/event_spine.zig:198`, `src/daemon/event_spine.zig:202`, `src/daemon/event_spine.zig:213`, `src/daemon/server.zig:17593`, `src/daemon/server.zig:17596`, `src/daemon/server.zig:17676`, `src/daemon/server.zig:17677`, `src/daemon/server.zig:18072`, `src/daemon/server.zig:18079`, `src/daemon/server.zig:18085`, `src/daemon/server.zig:18117`, `src/daemon/server.zig:18122`, `src/daemon/server.zig:18126`.

Targeted secrets and transport material are not broadcast. `sendMediaEventReply` renders caller-only MEDIA replies, and `MACKEY` is derived per participant and sent only to the owning WebSocket session. Evidence: `src/daemon/server.zig:18088`, `src/daemon/server.zig:18104`, `src/daemon/server.zig:26351`, `src/daemon/server.zig:26355`, `src/daemon/server.zig:26365`.

## Client-held media E2EE v2

Native WebSocket media can use the v2 end-to-end encryption protocol. Media
keys are created and retained by clients; Onyx Server never receives a group
key and cannot decrypt a media payload. The daemon is the authenticated control
plane: it verifies that a physical connection is entitled to speak for an exact
`nick:attachment`, publishes signed handshake material to call members, and
rejects frames that do not match the connection's bound attachment, stream,
kind, or server MAC.

### Signed attachment handshake

The binary handshake envelope is exactly 275 bytes:

| Offset | Length | Field |
| ---: | ---: | --- |
| 0 | 1 | protocol version, `2` |
| 1 | 16 | physical attachment id |
| 17 | 65 | static P-256 public key |
| 82 | 65 | per-call ephemeral P-256 public key |
| 147 | 32 | fresh nonce |
| 179 | 32 | enrolled Ed25519 public key |
| 211 | 64 | Ed25519 signature |

The signed transcript is the first 211 envelope bytes prefixed by the ASCII
domain `onyx-media-handshake-v2\0`, followed by the raw UTF-8 channel bytes
with only ASCII `A-Z` folded to lowercase, and a final NUL. The daemon builds
the same byte sequence in `mediaE2eeHandshakeTranscript`, requires the Ed25519
key to match the authenticated account enrollment, and verifies the signature
with `mediaE2eeHandshakeSignatureValid` before it mutates call state, binds the
attachment, or publishes the handshake. A malformed, unsigned, mismatched, or
legacy envelope fails closed.

The ephemeral P-256 key is regenerated for each call. Clients derive pairwise
wrapping secrets with ECDH, use the enrolled Ed25519 identity to authenticate
the exchange, and bind trust-on-first-use identity to both the static P-256 and
Ed25519 public keys. Reusing a nick does not merge physical clients: the
authority and routing identity is always the full `nick:attachment` tuple.

### Group keys and encrypted frames

The elected client leader distributes a group epoch over the member-scoped
EVENT plane with the exact signaling shape:

```text
MEDIA GROUPKEY <channel> <sender-nick> <sender-attachment> <target-nick> <target-attachment> <epoch> <wrapped-key>
```

Only the exact target attachment can unwrap the key. Generation and epoch
checks reject stale leadership, replay, and equal-epoch collisions. A detached
observer retains room epoch and participant metadata but no media key material;
it follows the remaining deterministic leader and accepts only a later,
server-authenticated distribution. This is exercised with three-member calls,
leader departure, detach/rejoin, and a pending lower-ranked leader.

Each media frame is encrypted client-side with AES-GCM and signed by its sender
with Ed25519. The associated metadata binds the channel generation, key epoch,
sender attachment, stream, media kind, and sequence. `handleWsMediaDatagram`
also requires current physical call membership and validates the server-issued
MAC plus the bound attachment, stream, and kind before relaying the opaque
ciphertext. The daemon does not offer a plaintext fallback and does not accept
v1 handshake downgrade.

### Physical-attachment retirement

Media authority follows the socket, not merely the shared account or nick.
`retireMediaPhysicalChannel`, `retireLogicalMediaBeforeNickMutation`, and
`retireMediaBeforeAccountMutation` make retirement explicit:

| Transition | Required result |
| --- | --- |
| same attachment re-handshakes as a new attachment | publish exact `E2EE-DETACH` for the old attachment before binding the new one |
| explicit `MEDIA LEAVE` or disconnect | retire only that physical attachment; publish nick-wide leave only after the final attachment leaves |
| `PART` or `KICK` | retire affected physical media membership before channel membership is removed |
| successful nick change | retire the old nick authority and require a fresh MEDIA join and handshake |
| successful account change, registration, identify, or logout | retire the old account authority before mutation; failed or same-account authentication does not retire it |

`E2EE-DETACH` is server-authored only. Clients cannot forge it. On receiving its
own detach, a client zeroizes local group and pairwise key material and returns
the call state to idle. A retired connection cannot continue sending old
WebSocket frames even when another attachment has the same account and nick.

### Mesh boundary

Signed E2EE control events use the Event Spine and converge across the secured
Undertow mesh. Binary WebSocket media is origin-cascaded across secured mesh
peers as opaque `MEDIA_WS_DATAGRAM` frames (`0x25`): the admitting node validates
the browser Cadence MAC, fans out locally, then publishes once to established
secured peers; receivers re-wrap for local WS call participants and never
re-mesh (loop prevention is origin-only emit). Payloads are never decrypted or
re-encoded — E2EE stays end-to-end. Codec: `src/proto/media_ws_relay.zig`.

## WebTransport and WASM shims

`src/proto/webtransport.zig` is a pure framing module for QUIC varints, capsules, WebTransport datagrams, and stream signal prefixes. The daemon listener in `src/daemon/webtransport_listener.zig` turns the QUIC + HTTP/3 + WebTransport stack into a live UDP endpoint and bridges each WebTransport session to the daemon's ordinary IRC listener over a loopback TCP proxy. Evidence: `src/proto/webtransport.zig:4`, `src/proto/webtransport.zig:6`, `src/proto/webtransport.zig:24`, `src/proto/webtransport.zig:30`, `src/proto/webtransport.zig:174`, `src/proto/webtransport.zig:215`, `src/daemon/webtransport_listener.zig:4`, `src/daemon/webtransport_listener.zig:5`, `src/daemon/webtransport_listener.zig:7`.

Browser and client WASM exports are separate from the daemon plugin host.

| File | Export surface | Evidence |
| --- | --- | --- |
| `src/wasm/cadence_wasm.zig` | CadenceVox audio encode/decode and CadenceVis video intra/inter encode/decode for `wasm32-freestanding`. | `src/wasm/cadence_wasm.zig:1`, `src/wasm/cadence_wasm.zig:3`, `src/wasm/cadence_wasm.zig:17`, `src/wasm/cadence_wasm.zig:21`, `src/wasm/cadence_wasm.zig:35`, `src/wasm/cadence_wasm.zig:39`, `src/wasm/cadence_wasm.zig:49` |
| `src/wasm/browser_transport.zig` | Browser transport shim core is re-exported from the package root; the wasm32 export wrapper lives in `src/wasm/transport_shim.zig`. | `src/root.zig:18`, `src/root.zig:21`, `src/wasm/browser_transport.zig:1`, `src/wasm/transport_shim.zig:1` |

## Browser WS media vs native/WebRTC legs (E2EE boundary)

Browser clients with `[media].ws_media_relay` use a third media plane that is
**not** bridged to native Cadence UDP or WebRTC RTP:

| Plane | Framing | Crypto | Cross-leg |
| --- | --- | --- | --- |
| Native UDP | Cadence container over UDP | Optional per-stream MAC (`native_media_require_mac`) | Yes ↔ WebRTC via `media_bridge` rewrap |
| WebRTC UDP | RTP/SRTP (optional DTLS-SRTP) | SRTP group key or DTLS-exported keys | Yes ↔ native via `media_bridge` rewrap |
| Browser WS | Cadence container over binary WebSocket | Per-stream MAC + **client-held E2EE** (AES-GCM group epoch; server has no key) | **No** — server must not decrypt; opaque fan-out to other WS members only |

`handleWsMediaDatagram` validates MAC/stream/kind/attachment and relays the
opaque ciphertext to other **on-node** WS call members, then **origin-only**
cascades the same opaque bytes to secured mesh peers as S2S
`MEDIA_WS_DATAGRAM` (`src/proto/media_ws_relay.zig`, tag `0x25`). Receivers
local-fanout only and **never re-mesh** (loop prevention). It never feeds the
payload into `media_bridge` rewrap: the Cadence payload is E2EE ciphertext with
an attachment prefix, not a shared-codec native/RTP payload. A mixed WS+native
call therefore cannot hear across legs without breaking E2EE (server decrypt) or
shipping undecryptable bytes.

To avoid advertising dead paths, `provisionMediaTransports` treats WebSocket
connections specially:

- never advertise `NATIVE` (browser path is not Cadence UDP)
- advertise `TRANSPORT` only when the client explicitly requests WebRTC/DTLS
  **and** the candidate host is not loopback (`media_host` default `127.0.0.1`
  with no STUN is unroutable from a remote browser)
- do not bridge-register a pure WS participant (not on either UDP leg)

Browser primary path: `MEDIA JOIN` → `MACKEY` → binary Cadence frames. Configure
`ws_media_relay` (and prefer `ws_media_require_mac`) for browser deployments;
set a public `media_host` or STUN only for native/WebRTC UDP peers.

## Planning notes and divergences

Where older media-transport design intent has not fully landed in the source, the current code verifies these concrete pieces:

| Topic | Current status | Evidence |
| --- | --- | --- |
| Runtime media SFU sizing | SFU rooms now have a runtime participant cap defaulting to 64 and clamped to the inline 256-seat ceiling. The native Cadence call leg remains capped at 64. | `src/daemon/media_room.zig:17`, `src/daemon/media_room.zig:18`, `src/daemon/media_room.zig:37`, `src/daemon/native_media_transport.zig:42`, `src/daemon/native_media_transport.zig:43` |
| Runtime Cadence reassembly sizing | Runtime window defaults exist, but actual `ReassemblyBuffer` capacity remains comptime-bound. | `src/substrate/cadence_frame.zig:34`, `src/substrate/cadence_frame.zig:39`, `src/substrate/cadence_frame.zig:397`, `src/substrate/cadence_frame.zig:418` |
| Mixed-leg calls | The bridge exists as header rewrap only between native UDP and WebRTC RTP; it requires a shared codec payload and does not transcode. Browser WS E2EE frames are not bridged. | `src/daemon/media_bridge.zig:10`, `src/daemon/media_bridge.zig:19`, `src/daemon/media_bridge.zig:254`, `src/daemon/media_bridge.zig:272`, `src/daemon/server.zig` `handleWsMediaDatagram` / `provisionMediaTransports` |
| WS unroutable candidates | WS OFFER/ANSWER suppresses loopback TRANSPORT and always omits NATIVE; MACKEY remains the browser media plane. | `src/daemon/server.zig` `provisionMediaTransports`, `mediaHostIsLoopback` |
| Mesh WS media cascade | **Shipped:** origin node meshes opaque Cadence WS datagrams via secured `MEDIA_WS_DATAGRAM`; receivers fan out locally only (no re-mesh). | `src/proto/media_ws_relay.zig`, `src/proto/s2s_frame.zig` tag `0x25`, `s2s_peer.sendMediaWsDatagram` / `takeMediaWsDatagrams`, `relayWsMediaDatagram` / `drainMediaWsDatagrams` |
