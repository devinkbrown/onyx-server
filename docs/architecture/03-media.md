# Media architecture

*Onyx Server's media stack: an Undertow SFU control plane, RTP/SRTP and native Cadence UDP legs, header-only Cadence-frame <-> RTP rewrap, DTLS-SRTP keying, WebTransport framing, and browser/WASM codec exports.*

This document covers the current source tree only.

## SFU control plane

`src/substrate/undertow/media.zig` is the pure media control substrate. It owns bounded roster state, SFU forwarding decisions, simulcast layer choice, ABR hints, and codec offer/answer negotiation, with hot paths using inline storage. Evidence: `src/substrate/undertow/media.zig`.

| Type | Role | Evidence |
| --- | --- | --- |
| `MediaKind` | Voice, video, and screen media kinds. | `src/substrate/undertow/media.zig` |
| `ParticipantId` | Bounded inline participant id with validation. | `src/substrate/undertow/media.zig` |
| `Participant` | Tracks joined, muted, and speaking kind sets; controls publish/receive checks. | `src/substrate/undertow/media.zig` |
| `Session(max_participants)` | Inline roster, join/leave/mute/speaking operations, and `forwardSet`. | `src/substrate/undertow/media.zig` |
| `RoutePolicy` | Optional `require_speaking` forwarding gate. | `src/substrate/undertow/media.zig` |

`forwardSet` verifies the source participant exists, verifies the source can publish the requested kind, optionally requires the source to be speaking, and returns receivers that can receive the kind while excluding the source. Evidence: `src/substrate/undertow/media.zig`.

## Daemon media rooms

`src/daemon/media_room.zig` maps an IRC channel to an Undertow `Session`. This is control plane only: who is in a call, what they publish, and mute/speaking state; media bytes flow over the transport substrate. Evidence: `src/daemon/media_room.zig`.

| Concern | Current behavior | Evidence |
| --- | --- | --- |
| Room sizing | Runtime default is 64 participants, while the inline `Room` ceiling is `media.Session(256)`. `[media].max_participants` is clamped to `1..256` and enforced at join. | `src/daemon/media_room.zig` |
| Native leg sizing | The native Cadence leg is separately bounded at 64 participants per call. | `src/daemon/native_media_transport.zig` |
| Runtime config | Breakout label cap and participant cap are runtime-tunable under the inline ceilings. | `src/daemon/media_room.zig` |
| Per-channel maps | Rooms, breakouts, positions, hands, negotiated profiles, and per-participant profiles are keyed by channel/composite keys. | `src/daemon/media_room.zig` |
| Codec/FEC profile | `MEDIA OFFER` establishes a per-channel `CallProfile`; `MEDIA ANSWER` consults it. | `src/daemon/media_room.zig`, `src/daemon/server.zig` |
| Room lifecycle | Join creates the room on first join; leave prunes when empty. | `src/daemon/media_room.zig` |

## RTP/SRTP media plane

`src/daemon/media_plane.zig` ties the `MediaTransport` endpoint registry to a live UDP socket and pump thread. The pump demuxes DTLS/STUN/RTP/RTCP, answers STUN checks, and relays RTP/RTCP under a mutex. Evidence: `src/daemon/media_plane.zig`.

| Path | Behavior | Evidence |
| --- | --- | --- |
| Startup | Binds UDP, records local port, optionally discovers a server-reflexive candidate, sets recv timeout, and spawns the pump thread. | `src/daemon/media_plane.zig` |
| STUN | STUN datagrams call `transport.handleStunBinding` under the mutex and send a response if one is built. | `src/daemon/media_plane.zig` |
| RTP/RTCP filter | Non-STUN media must look like RTP/RTCP version 2 and be at least RTP header length, preventing open UDP reflection. | `src/daemon/media_plane.zig` |
| RTCP feedback | RTCP is decrypted first for DTLS peers, then Generic NACK is terminated locally from the retransmit cache; other RTCP is relayed or translated cross-leg. | `src/daemon/media_plane.zig` |
| RTP relay | Decodes RTP header where possible, forwards through `transport.forwardFromSource`, caches for NACK, and sends to selected targets. | `src/daemon/media_plane.zig` |
| Cross-leg bridge | After RTP relay, the plane can call an installed `RtpCrossSink` to reach native participants. | `src/daemon/media_plane.zig` |
| Signaling support | `allocate` returns ICE credentials; `groupKey` returns the legacy per-call SRTP group key; `remoteFor` resolves live peer address. | `src/daemon/media_plane.zig` |

### RTP/RTCP helpers

The RTP/RTCP helpers are pure protocol surfaces used by the plane and bridge. `rtp_profile.zig` owns the 12-byte RTP header, RFC 3550-style stats, and SR/RR helpers; `rtp_ext.zig` parses RFC 8285 RTP extensions; `rtp_red.zig` handles RED payload blocks; `rtcp_compound.zig`, `rtcp_translate.zig`, and `rtcp_xr.zig` parse/build RTCP compound, feedback, and XR packets. SRTP/SRTCP protection lives in `srtp.zig` and `srtcp.zig`. Evidence: `src/proto/rtp_profile.zig`, `src/proto/rtp_ext.zig`, `src/proto/rtp_red.zig`, `src/proto/rtcp_compound.zig`, `src/proto/rtcp_translate.zig`, `src/proto/rtcp_xr.zig`, `src/proto/srtp.zig`, `src/proto/srtcp.zig`.

## DTLS-SRTP signaling and RFC 8122 fingerprint verification

DTLS-SRTP is opt-in (`[media].dtls_srtp`, plus `[media].dtls13` for the DTLS 1.3 engine). When enabled, RFC 7983 demux routes DTLS records to the per-peer terminator; otherwise STUN/RTP/SRTP paths remain byte-identical. The DTLS 1.2 and 1.3 engines share one certificate fingerprint for signaling. Evidence: `src/daemon/server.zig`, `src/daemon/media_plane.zig`.

The signaling path parses `fingerprint=sha-256:<colon-hex>` on `MEDIA OFFER`/`MEDIA ANSWER` and fails closed on malformed fingerprints or a DTLS request while the feature is unavailable. When accepted, the peer fingerprint is stored per `(channel, participant)`, resolved to the peer's ICE-bound transport address, and bound into both DTLS terminators before handshake completion. Evidence: `src/daemon/server.zig`, `src/daemon/media_plane.zig`.

| Path | Behavior | Evidence |
| --- | --- | --- |
| Server identity | In DTLS mode, `MEDIA TRANSPORT` advertises `fingerprint=<server fp>` and `setup=passive` instead of the legacy `srtp=` group key. | `src/daemon/server.zig` |
| `use_srtp` | `dtls_srtp.zig` defines RFC 5764 profiles, key export, and `use_srtp` encode/parse helpers; both terminators select AES-128-CM-HMAC-SHA1-80 when offered. | `src/proto/dtls_srtp.zig`, `src/proto/dtls12_server.zig`, `src/proto/dtls13_server.zig` |
| Verification gate | `exportedKeys` and `srtpProfile` return null for a bound-but-unverified peer; `recordPeerCertificate` is the certificate-capture seam and uses constant-time digest compare. | `src/proto/dtls_peer_verify.zig`, `src/proto/dtls12_server.zig`, `src/proto/dtls13_server.zig` |
| Per-recipient SRTP | For established DTLS peers, RTP is decrypted once to a canonical packet and re-encrypted per DTLS recipient; SRTCP follows the same canonical-then-protect model. | `src/daemon/media_plane.zig` |

## Native CadenceVox/CadenceVis transport

`src/daemon/native_media_transport.zig` owns the native UDP leg and exact physical
endpoint table. The current configured routing path verifies a per-endpoint,
direction-specific client-to-server MAC, endpoint incarnation, codec/kind profile
and source-address ownership before learning or forwarding. It stages endpoint
publication with protected caller-only signaling. A stream ID is a public selector,
not a bearer credential.

Fresh 32-byte master material is issued as `MEDIA NATIVE-MACKEY`; four frame and
feedback keys are derived by direction and purpose in
`src/substrate/media_capability.zig`. Outbound native protection uses each
recipient's server-to-client key. Older channel/nick PRF helpers and optional
untagged codec admission remain for compatibility; they do not describe current
physical endpoint authority. The exact format, derivation labels and legacy
boundary are in [native-media authentication](../reference/native-media-mac.md).

The native/WebRTC bridge forwards compatible encoded payloads by header rewrap;
it never transcodes and must validate both source and destination authority under
the routing Domain. Browser client-held E2EE payloads use a separate path.

## Cadence frame container and codecs

`src/substrate/cadence_frame.zig` is a wire container, not the audio/video codec itself. It carries encoded payloads over media bands. Evidence: `src/substrate/cadence_frame.zig`.

| Field/behavior | Evidence |
| --- | --- |
| Media bands are `band_id >= 64`; control bands are below 64. | `src/substrate/cadence_frame.zig` |
| Wire format includes payload length, band id, stream id, sequence, timestamp, keyframe flag, codec tag, and payload. | `src/substrate/cadence_frame.zig` |
| `CodecTag` supports `raw`, `cadencevox_audio`, and `cadencevis_video`. | `src/substrate/cadence_frame.zig` |
| Decode rejects truncation, control band ids, trailing bytes, and unknown codec tags. | `src/substrate/cadence_frame.zig` |
| ReassemblyBuffer is a bounded jitter/reorder buffer with compile-time payload/window bounds and runtime window config. | `src/substrate/cadence_frame.zig` |
| CadenceVox is an allocation-free IMA ADPCM voice codec building block; CadenceVis is an allocation-free lossless delta/RLE video building block. | `src/substrate/cadencevox_adpcm.zig`, `src/substrate/cadencevis_delta.zig` |

## Cross-leg bridge

`src/daemon/media_bridge.zig` bridges participants on the native Cadence leg and the RTP/SRTP leg by header rewrap only. Payload bytes stay opaque and are shared verbatim; there is no encoding, decoding, or transcoding. Evidence: `src/daemon/media_bridge.zig`.

| Direction | Behavior | Evidence |
| --- | --- | --- |
| Native to RTP | Decode Cadence frame, map to bridge frame, write RTP using the mapped SSRC, send to opposite-leg members. | `src/daemon/media_bridge.zig` |
| RTP to native | Decode RTP header, map to native frame with the mapped stream id, encode Cadence datagram, send to native members. | `src/daemon/media_bridge.zig` |
| Target selection | Cross-leg targets are opposite-leg recipients from the per-channel session, excluding disconnected/ineligible members. | `src/daemon/media_bridge.zig` |
| Transcode-free gate | Participant codec sets must converge on a shared codec; incompatible sets cause cross-leg fanout to drop rather than transcode. | `src/daemon/media_bridge.zig` |

The live server installs bridge callbacks around `LinuxServer.media_bridges`, `media_plane`, and `native_media`. Evidence: `src/daemon/server.zig`.

## MEDIA command and EVENT-plane signaling

`MEDIA` is the command surface for call presence, codec negotiation, transport credential replies, native-leg registration, stats, ABR/layer hints, captions, reactions, roster, and leave cleanup. Media bytes do not flow through the command handler. Evidence: `src/daemon/server.zig`.

`MEDIA OFFER` and `MEDIA ANSWER` negotiate Cadence codecs through the SDP/media-session path, publish capability/profile events, and prepare the selected RTP/SRTP and native endpoint legs. WebSocket clients do not receive native UDP candidates; an explicit eligible WebRTC request can select that leg. Evidence: `src/daemon/server.zig`.

Media presence rides the IRCX EVENT plane as `MEDIA <action> <channel> <nick> [detail]`. `MEDIA` is an IRCX event type ordinary clients may subscribe to, but non-oper delivery is member-scoped: the event's channel is the subject, and `mediaEventAllowed` requires the recipient to be a member of that channel. Non-members do not see call presence, including for private/secret channels. Evidence: `src/daemon/event_spine.zig`, `src/daemon/server.zig`.

Targeted secrets and transport material are not broadcast. `sendMediaEventReply` renders caller-only MEDIA replies, and `MACKEY` is derived per participant and sent only to the owning WebSocket session. Evidence: `src/daemon/server.zig`.

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

`src/proto/webtransport.zig` is a pure framing module for QUIC varints, capsules, WebTransport datagrams, and stream signal prefixes. The daemon listener in `src/daemon/webtransport_listener.zig` turns the QUIC + HTTP/3 + WebTransport stack into a live UDP endpoint and bridges each WebTransport session to the daemon's ordinary IRC listener over a loopback TCP proxy. Evidence: `src/proto/webtransport.zig`, `src/daemon/webtransport_listener.zig`.

Browser and client WASM exports are separate from the daemon plugin host.

| File | Export surface | Evidence |
| --- | --- | --- |
| `src/wasm/cadence_wasm.zig` | CadenceVox audio encode/decode and CadenceVis video intra/inter encode/decode for `wasm32-freestanding`. | `src/wasm/cadence_wasm.zig` |
| `src/wasm/browser_transport.zig` | Browser transport shim core is re-exported from the package root; the wasm32 export wrapper lives in `src/wasm/transport_shim.zig`. | `src/root.zig`, `src/wasm/browser_transport.zig`, `src/wasm/transport_shim.zig` |

## Browser WS media vs native/WebRTC legs (E2EE boundary)

Browser clients with `[media].ws_media_relay` use a third media plane that is
**not** bridged to native Cadence UDP or WebRTC RTP:

| Plane | Framing | Crypto | Cross-leg |
| --- | --- | --- | --- |
| Native UDP | Cadence container over UDP | Current physical endpoint uses directional frame/feedback MAC keys | Yes ↔ WebRTC via `media_bridge` rewrap |
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

## Recording and upgrade boundaries

`MEDIA RECORD` is opt-in under `[media] recording_*`; `MEDIA CONSENT` records the
participant decision required by the room policy. The recorder writes a bounded
packet journal rather than a transcoded movie. `src/daemon/media_record.zig` owns
asynchronous journal/rotation/manifest work and bounded queues; transport taps
must not perform file I/O inside routing transactions. A participant joining
without the required consent stops an active recording.

The journal and pending retired writer/manifest state currently have no Helix
capsule. `upgradeContinuityBlockerLocked` therefore refuses an upgrade while any
such owner remains, including after the visible room is gone. Other media owners
must independently prove continuity; platform-specific native state support does
not grant a general seamless-media-upgrade promise. See
[upgrade architecture](04-upgrade-wasm.md) and [configuration](../reference/config.md).

## Verification boundary

The source contains pure codecs, routing plans, actual transport workers and
server integration tests; these establish different scopes. Use `test-media` and
focused server/native tests while iterating, then the full release gates. The
[release audit](../audit/release-and-test-speed-2026-11-03.md) records the accepted
Linux fleet checks; it is not certification of every browser or native client.
