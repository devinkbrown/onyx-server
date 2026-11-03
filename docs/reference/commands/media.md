# Media and presence commands

*Per-channel voice, video, and screen-share control plane plus presence updates.*

The `feature.misc` module registers `MEDIA`, which the `media` config flag feature-gates (`src/daemon/modules/feature_misc.zig`). The same module registers `ACTIVITY` (`src/daemon/modules/feature_misc.zig`).

## MEDIA

- Syntax: `MEDIA <subcommand> <#channel> [args...]`
- Description: Media control plane for per-channel SFU and call state. The implemented subcommands are `ROSTER`, `OFFER`, `ANSWER`, `PROFILE`, `STATS`, `LAYER`, `ABR`, `BREAKOUT`, `POS`, `CAPTION`, `TRANSCRIPT`, `HAND`, `QUEUE`, `REACT`, `LEAVE`, `JOIN`, `MUTE`, `UNMUTE`, `SPEAKING`, `CONSENT`, `RECORD`, `QUALITY`, `E2EE-HANDSHAKE`, `E2EE-GROUPKEY`; `E2EE-DETACH` is server-originated and client attempts are refused. Text IRC commands carry signaling; browser media uses binary frames on the negotiated media WebSocket, while native/WebRTC use UDP. Control replies and call-state notifications are `EVENT <target> MEDIA ...` Event Spine lines plus standard failures.
- Privileges: Registered client; caller must be a member of the target channel, except `QUALITY` also permits an operator outside the channel. The command is unavailable if the `media` feature is disabled.
- Parameters: Subcommand and existing channel. `JOIN`/`MUTE`/`UNMUTE`/`SPEAKING` accept kind `voice`, `video`, or `screen` with `voice` default. `OFFER`/`ANSWER` use codec CSV values `cadencevox`, `cadencevis`, `raw` (legacy `kaguravox`/`kaguravis` codec aliases remain accepted; CAPS/ROSTER emit English names); either command optionally accepts `transport=webrtc` or `webrtc`. `LAYER` sets the receiver's native simulcast ceiling as `<max_spatial> <max_temporal>`. `ABR` reports receiver bandwidth/loss as `<current_kbps> <available_kbps> <loss_pct> <rtt_ms> [nack_per_sec]`; the daemon applies the Undertow ABR hint to the native simulcast ceiling without transcoding. A standards WebRTC peer additionally requests **DTLS-SRTP keying** (RFC 5764/8122) by carrying its own certificate fingerprint as a single token `fingerprint=sha-256:<colon-hex>` (the alg is colon-joined to the hex so it survives IRC tokenization; optionally `setup=active`).
- DTLS-SRTP (`TRANSPORT` keying): when the `[media].dtls_srtp` server option is on **and** the `OFFER` or `ANSWER` carried a well-formed `fingerprint=`, the `TRANSPORT` reply advertises the server's DTLS certificate fingerprint and DTLS role in RFC 8122 form — `fingerprint=sha-256 <colon-hex> setup=passive` (Onyx Server is the DTLS server) — **instead of** the SDES `srtp=<base64 group key>` token. The daemon binds the peer's offered fingerprint to the exact physical transport endpoint; on DTLS handshake completion the terminator verifies the peer's presented certificate against it and **fails closed on a mismatch** (no SRTP keys are exported, so no media flows). When `[media].dtls_srtp` is off, or the peer carries no `fingerprint=`, the reply uses the legacy SDES form (`srtp=<base64 group key>`). A `fingerprint=` request while DTLS-SRTP is disabled/unavailable is rejected (`FAIL MEDIA DTLS_UNAVAILABLE`) rather than downgraded.
- Replies/events: `EVENT <target> MEDIA ...` lines including `ROSTER`, `ROSTER-END`, `OFFER-ACK`, `ANSWER-ACK`, `PROFILE`, `CAPS`, `KIND-DENIED`, `TRANSPORT`, `NATIVE`, `STATS`, `STATS-END`, `LAYER`, `ABR`, `BREAKOUT`, `POS`, `CAPTION`, `TRANSCRIPT`, `TRANSCRIPT-END`, `HAND`, `REACT`, `JOIN`, `LEAVE`, `MUTE`, `UNMUTE`, and `SPEAKING`/`SILENT`. `CAPS` publishes each participant's advertised codec/FEC set as `codecs=<csv> fec=<scheme>` after a successful `OFFER` or `ANSWER`; `KIND-DENIED` is a caller-targeted reply (`kind=<voice|video> reason=no_common_codec`) when an advertised media kind cannot join the negotiated transcode-free codec set; `ABR` is a caller-targeted reply such as `action=decrease bitrate=320 fec=2 keyframe=true spatial<=0 temporal<=0`; `ROSTER` includes capability fields for participants whose capabilities are known. `TRANSPORT` carries either `srtp=<base64>` (legacy SDES) or `fingerprint=sha-256 <colon-hex> setup=passive` (DTLS-SRTP), never both. Participant-specific transport/key replies (`TRANSPORT`, `NATIVE`, `NATIVE-MACKEY`, `MACKEY`) are targeted Event Spine replies to the requesting client, not broadcast to every subscriber.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOSUCHCHANNEL 403`, `ERR_NOTONCHANNEL 442`, `ERR_UNKNOWNCOMMAND 421` if feature-disabled by registry, IRCv3 `FAIL MEDIA` codes including `NO_OFFER`, `NOT_IN_CALL`, `BAD_LAYER`, `BAD_ABR`, `BREAKOUT_FAILED`, `INVALID_POSITION`, `POS_FAILED`, `INVALID_REACTION`, `INVALID_KIND`, `JOIN_FAILED`, `NOT_PUBLISHING`, `INVALID_SUBCOMMAND`, `NO_CODECS`, `NEGOTIATE_FAILED`, `NO_COMMON_CODEC`, `BAD_FINGERPRINT` (malformed `fingerprint=` token), `DTLS_UNAVAILABLE` (DTLS keying requested but not enabled/available).
- Example: `MEDIA JOIN #zig voice`
- Offer/answer transport: successful `OFFER` replies with `OFFER-ACK`, then provisions the selected caller legs; browser WebSocket callers omit `NATIVE` and require an explicit eligible WebRTC request for `TRANSPORT`. Successful `ANSWER` replies with `ANSWER-ACK`, then prepares the selected answerer endpoint legs against the active call profile.
- DTLS example: `MEDIA OFFER #zig cadencevox transport=webrtc fingerprint=sha-256:3C:57:42:...:BA setup=active` -> `:server EVENT nick MEDIA TRANSPORT #zig ufrag=... pwd=... candidate=203.0.113.5:38405 fingerprint=sha-256 9F:...:1D setup=passive`
- ABR example: `MEDIA ABR #zig 1200 400 10 60 25` -> `:server EVENT nick MEDIA ABR #zig action=decrease bitrate=320 fec=2 keyframe=true spatial<=0 temporal<=0`
- Sources: `src/daemon/modules/feature_misc.zig`, `src/daemon/server.zig`

## ACTIVITY

- Syntax: `ACTIVITY <target> <state> [text]`
- Description: Presence/activity update surface. The handler applies target parsing and broadcasts activity state to the relevant recipients.
- Privileges: Registered client.
- Parameters: Target, state, optional text as parsed by handler.
- Replies: Activity notification lines.
- Errors: Handler-specific target/parameter failures.
- Example: `ACTIVITY #zig coding :docs`
- Sources: `src/daemon/modules/feature_misc.zig`, `src/daemon/server.zig`

## Join and transport examples

On an authenticated protected connection, after joining the IRC channel:

```irc
MEDIA JOIN #team voice
MEDIA ROSTER #team
MEDIA OFFER #team cadencevox
MEDIA PROFILE #team
MEDIA STATS #team
```

A non-browser logical JOIN creates call membership without allocating UDP secrets.
A successful eligible native offer returns caller-only `NATIVE` plus
`NATIVE-MACKEY stream=<id> key=<base64-master>`; use the directional derivation in
[native authentication](../native-media-mac.md). A browser connection negotiated
as `onyx.irc-media.v1` uses its protected `MACKEY` and bounded binary-WS media
path. `text.ircv3.net` rejects binary frames. DTLS fingerprint requests must fail
closed if the requested engine is unavailable; the placeholder fingerprint in
examples must be replaced with the caller's actual certificate fingerprint.

## Consent and recording

```irc
MEDIA CONSENT #team on
MEDIA RECORD #team
MEDIA RECORD #team stop
MEDIA CONSENT #team off
```

The caller must already be in the call. Starting recording needs the server's
`recording_enabled`, usable storage, and consent from **every current member**.
Any call participant can request the implemented start/stop path; this command
is not restricted to channel operators. Off consent stops an active room
recording, and a new unconsented participant also stops it. Failures include
`NOT_IN_CALL`, `BAD_CONSENT`, `RECORDING_DISABLED`, `CONSENT_REQUIRED` and
`RECORDING_UNAVAILABLE`.

The output is a bounded packet journal with segment/manifest management, quotas,
retention and duration limits; it is not a playable transcoded movie. An
asynchronous writer owns accepted packet copies. Pending active/retired journal
or manifest custody blocks Helix until its owner is finished; stopping the room
is not by itself proof that pending file work is complete. See
[media configuration](../config.md#media) and `src/daemon/media_record.zig`.

## E2EE, quality and refusal boundaries

`MEDIA E2EE-HANDSHAKE <#channel> :<base64-signed-v2-envelope>` binds the enrolled
account identity key to the current physical media attachment. It requires a
current call membership and protected authenticated caller. A sibling attachment
cannot take over an already-owned attachment tuple merely by copying its public
selector. `E2EE-GROUPKEY` relays a bounded wrapped key to an exact target
attachment/epoch; the server does not receive the plaintext client group key.
Use the full [media E2EE contract](../../architecture/03-media.md#client-held-media-e2ee-v2)
for canonical envelopes and retirement rules rather than manufacturing a token.

`MEDIA QUALITY #team` is readable by a channel member or an operator and returns
current quality state. `MEDIA QUEUE #team` reads the speaking/hand queue; `MEDIA HAND #team up|down`
updates the caller's hand state. The queue is advisory: the current SPEAKING path
does not enforce that the sender is at its head. `MEDIA TURN` always fails with `TURN_CUT`; the parser's
TURN codec is not an offered relay/allocation service.

The authoritative subcommand dispatcher is
[media_cmd.zig](../../../src/daemon/media_cmd.zig), with actual transport and
publication plans in `server.zig`. Configured enablement and codec availability
must be checked independently of an example's syntax.
