# Onyx Server Web Push

*Server-sent browser push notifications for offline recipients — RFC 8291 message
encryption and RFC 8292 VAPID authorization, delivered by a background worker.*

Onyx Server can nudge a logged-out account's browser when an offline DM (memo) arrives,
so the recipient sees it "with the tab closed." The push body is encrypted
end-to-end to the browser: the server never holds a plaintext channel to the push
service, only ciphertext it forwards. The message crypto is a pure, deterministic
module (`crypto/webpush.zig`); the daemon glue — subscription store, VAPID key,
delivery worker — lives in `daemon/webpush.zig`.

Web Push is **off by default** and available on Linux, OpenBSD, and Windows. Enabling it
needs an account store (subscriptions are account-scoped) and outbound HTTPS;
delivery reuses the ACME transport and PEM trust anchors. On Windows, set
`[acme].ca_bundle_path` to a readable PEM bundle and place
`[webpush].vapid_key_path` under a private directory. Boot fails if these
requirements cannot be met. Windows smoke tests cover VAPID boot and restart,
subscription persistence, worker startup, and a trusted local HTTPS delivery;
delivery to a public push service still needs external acceptance. See the
[Windows guide](../guide/windows.md).

Source of truth: `src/crypto/webpush.zig`, `src/daemon/webpush.zig`, the launch
wiring in `src/main.zig`, and the command/trigger wiring in
`src/daemon/server.zig`.

## Message crypto (RFC 8291 / 8292)

`crypto/webpush.zig` is I/O-free and deterministic — no clock, no ambient
allocator surprises — which makes it a known-answer-test (KAT) surface:

- `encrypt()` produces an `aes128gcm` HTTP body from a caller-supplied ephemeral
  key pair and salt: 16-byte salt, 4-byte `rs`, 1-byte key-id length, 65-byte
  application-server public key, then AES-GCM over `plaintext || 0x02` plus the
  16-byte tag (`src/crypto/webpush.zig:44-45`, `src/crypto/webpush.zig:86-105`).
  It is pinned to the **RFC 8291 Appendix A** vector: the test reproduces the
  RFC's exact 65-byte application-server public key and body byte-for-byte
  (`src/crypto/webpush.zig:194-220`). `encryptRandom()` is the production entry:
  fresh ephemeral P-256 key pair plus random 16-byte salt per message, as RFC
  8291 requires (`src/crypto/webpush.zig:110-121`). A single record caps
  plaintext at `max_plaintext` (`record_size` 4096 minus the delimiter byte and
  16-byte tag; `src/crypto/webpush.zig:37-42`).
- `vapidJwt()` mints the ES256 JWT the push service demands (`{"typ":"JWT",
  "alg":"ES256"}` header; `{"aud","exp","sub"}` claims; raw `r ‖ s` signature, not
  DER; all base64url-unpadded). `vapidAuthValue()` formats the
  `Authorization: vapid t=<jwt>, k=<pubkey>` header
  (`src/crypto/webpush.zig:126-171`).

The same KAT vector pins the wire format shared with the JS client: the round-trip
test derives the CEK/nonce from the emitted body header exactly as a browser would
and decrypts it, proving salt and keys thread through correctly
(`src/crypto/webpush.zig:243-282`).

## The `WEBPUSH` command

Registered by `feature.misc` (`src/daemon/modules/feature_misc.zig:31`,
`src/daemon/modules/feature_misc.zig:64`), dispatched to `handleWebpush` in
`server.zig` (`src/daemon/server.zig:40854`). Account-scoped; a client
must be logged in. Keys are passed exactly as `PushSubscription.getKey()` gives
them (base64url-unpadded).

```text
WEBPUSH SUBSCRIBE <endpoint> <p256dh> <auth>   ; store a subscription (max 3/account)
WEBPUSH UNSUBSCRIBE <endpoint>                  ; remove one
WEBPUSH LIST                                    ; NOTICE per stored endpoint + count
```

- `<endpoint>` must be a well-formed absolute `https://` URL (`validEndpoint`:
  ≤ 512 bytes, no control/space/`0x7f` characters;
  `src/daemon/webpush.zig:140-150`).
- `<p256dh>` is the browser's uncompressed SEC1 P-256 key (65 bytes;
  `decodeKey65`); `<auth>` is the 16-byte subscription secret (`decodeAuth16`;
  `src/daemon/webpush.zig:130-138`).
- Re-subscribing an existing endpoint **refreshes its keys in place** rather than
  adding a duplicate. The per-account cap is `max_subscriptions_per_account` (3;
  `src/daemon/server.zig:25717-25744`, `src/daemon/webpush.zig:31`).
- With the worker disabled the command answers `FAIL WEBPUSH DISABLED`, so a client
  can probe safely. Other failures: `ACCOUNT_REQUIRED`, `INVALID_ENDPOINT`,
  `INVALID_KEY`, `NEED_MORE_PARAMS`, `TEMPORARILY_UNAVAILABLE`,
  `TOO_MANY_SUBSCRIPTIONS`, `NOT_SUBSCRIBED`, `INVALID_SUBCOMMAND`
  (`src/daemon/server.zig:25683-25716`, `src/daemon/server.zig:25729-25796`).

There is **no `WEBPUSH VAPID` subcommand**; unknown subcommands fail with
`INVALID_SUBCOMMAND`, and VAPID discovery is the ISUPPORT token below
(`src/daemon/server.zig:25796`).

## VAPID discovery via ISUPPORT

The server's VAPID public key is advertised as an **ISUPPORT (005) token**,
`VAPID=<base64url-pubkey>`, appended in `buildIsupportTokens` only when a key is
loaded (`src/daemon/server.zig:1270-1278`, `src/daemon/server.zig:1322-1326`).
`src/main.zig` calls `Vapid.loadOrCreate` **before** ISUPPORT is built, so the 005
burst carries the key and a client can call `pushManager.subscribe` with **zero
extra round-trips** — it reads the key once at registration
(`src/main.zig:286-305`).

This replaced an earlier reply-channel design. The design rule: service state
does not ride ad-hoc reply lines. Discovery is ISUPPORT, not a `NOTE` round-trip
or data channel (`src/main.zig:286-288`); `LIST` answers as plain server NOTICEs
(`src/daemon/server.zig:25782-25792`), and lifecycle publishes to the Event
Spine (`src/daemon/server.zig:25745-25749`, `src/daemon/server.zig:25775-25778`).

## Delivery: trigger, worker, storage

**Trigger (memo).** After `handleMemo` successfully stores an offline DM, it
calls `webpushNotify(recipient, from, text)` and
`meshBroadcastMemoPush(recipient, from, text)` — best-effort nudges; the
local memo store remains the message source of truth (`src/daemon/server.zig:40832`,
`src/daemon/server.zig:40833`).
`webpushNotify` builds a compact JSON payload
`{"type":"dm","from":…,"text":…}` (text preview truncated to 240 bytes so it always
fits one encrypted record, escaped by `writeJsonEscaped`) and enqueues one job per
stored subscription (`src/daemon/server.zig:40988`).

**Worker.** `webpush.Worker` is a background thread draining a bounded job queue
(`max_queued_jobs` 256; a full queue drops the push). Reactor threads only ever
`enqueue` — the network POST never blocks them. Per job the worker mints a VAPID JWT
for the endpoint's origin, encrypts the payload with `encryptRandom`, and POSTs it
through the shared ACME HTTPS transport (`acme_runner.httpsRequest`) with
`content-encoding: aes128gcm`, `ttl` (`push_ttl_seconds`, 12h), and `urgency: high`.
It is spawned in `src/main.zig` when `[webpush] enabled` with an account store
present, a loaded VAPID key, and CA trust anchors, and shut down on exit
(`src/daemon/webpush.zig:225-266`, `src/daemon/webpush.zig:297-339`,
`src/main.zig:824-879`).

**Dead-endpoint pruning.** A push service answering `404`/`410` marks the endpoint
gone; the worker collects these on a `dead` list that the next `webpushNotify`
drains under the server lock and prunes from the account's stored subscriptions
(`src/daemon/webpush.zig:214-216`, `src/daemon/webpush.zig:348-355`,
`src/daemon/server.zig:25823-25840`).

**Node-local storage.** Subscriptions persist in the local durable store's `.props`
family under a private `wps\x00<account>` key
(`src/daemon/services.zig:2031-2070`) — the same private-namespace rule as TOTP,
**never reachable through the METADATA command surface**. Each node also loads its
**own** VAPID key, so a browser's subscription is inherently bound to the node it
subscribed through (`src/daemon/webpush.zig:157-187`, `src/main.zig:286-295`).
Subscriptions and workers are node-local, but secured mesh peers can receive a
bounded `MEMO_PUSH` hint (frame tag `0x1C`) and run their **own** local Web Push
worker for the same account if they already hold a local subscription; the hint
carries only account/from/text preview, never subscription or VAPID material
(`src/daemon/server.zig:41032`, `src/daemon/server.zig:41048`,
`src/daemon/s2s_link.zig:825`, `src/daemon/secured_s2s_link.zig:1090`,
`src/proto/memo_push_relay.zig:4`, `src/proto/s2s_frame.zig:109`).

## Lifecycle on the Event Spine

Subscribe/unsubscribe events publish to the Event Spine `.service` category via
`publishOperEventSubject`, so opers can watch subscription lifecycle (`"WEBPUSH:
<account> subscribed a push endpoint"` / `"… removed a push endpoint"`). This is the
oper-observable surface (`src/daemon/server.zig:25745-25749`,
`src/daemon/server.zig:25775-25778`).

## Configuration

The `[webpush]` section (`src/daemon/config_format.zig:717-727`):

| Key             | Type   | Default                      | Meaning |
|-----------------|--------|------------------------------|---------|
| `enabled`       | bool   | `false`                      | Master gate. Off ⇒ command rejected, no worker, nothing advertised. |
| `subject`       | string | `mailto:ops@eshmaki.me`      | VAPID `sub` claim — an operator contact the push service may use. |
| `vapid_key_path`| string | `onyx-webpush-vapid.key`   | Where the ES256 VAPID secret persists (64 hex chars). Created once if absent; **rotating it invalidates every stored subscription**. |

The VAPID key file is load-or-create: a fresh P-256 secret is generated and written
if the path is empty, so the key survives restarts and Helix upgrades.
(`src/daemon/webpush.zig:157-180`).

**Config-default heap-dup gotcha** (cd8407e): `setStr` frees the previous value when
overlaying a non-optional string, so the `[webpush]` string defaults must be
heap-owned, not static literals — otherwise `--check-config` dies with an invalid
free the moment a config sets `webpush.subject`. The defaults are `allocator.dupe`d
at config init and freed in `Config.deinit` (the `acme_directory_url` pattern;
`src/daemon/config_format.zig:830-833`, `src/daemon/config_format.zig:950-951`,
`src/daemon/config_format.zig:1360-1362`, `src/daemon/config_format.zig:1572-1578`).
