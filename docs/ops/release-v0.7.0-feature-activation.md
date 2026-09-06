# 0.7.0 feature activation record — 2026-09-06

This is the production record for the symmetric feature-gate activation on
`eshmaki.me` and `ircx.us`. The existing verified artifact was retained; this
was a configuration-only release followed by one cold restart per node.

## Release identity

| Item | eshmaki.me | ircx.us |
| --- | --- | --- |
| Unit | `onyx-server.service` | `onyx-server.service` |
| Runtime | `/home/kain/onyx-server-run` | `/home/trev/onyx-server-run` |
| Artifact | `0.7.0+ae78d490` | `0.7.0+ae78d490` |
| Binary SHA-256 | `0f110e833bc96bd6540ad7df0a620af869526cf8b4dbc3fd4650aa8ada8ddf1c` | same |
| Final config SHA-256 | `3c7a96a54df0905d4bc7fbb8a3df36c85236273fabb3d2b0e5badff8c3fa4c60` | `270e93193cc41cf0da5c3ffe14a6f234894df3b5b1dba0ef0227f3f3d95a63a7` |
| Final MainPID | `3508600` | `3579801` |

The pre-change configurations remain recoverable at:

- `/home/kain/onyx-server-run/onyx-server.local.toml.pre-all-features-20260906T044847Z`
- `/home/trev/onyx-server-run/onyx-server.local.toml.pre-all-features-20260906T044847Z`

Those backups hash to `e573b27828b45099a5de98266a8acf878e25d244b24358aa463bf922e0941a3d`
and `7d8f1f77a50cb703ee582f697c844dbe88aa65d4511504cd2099c779cce03e63`,
respectively.

## Activated gates

Both live TOMLs now enable the following supported paths:

- `[network] discoverable = true` (public directory listing intent).
- `[listen] webtransport = 4433` (dual-stack UDP/QUIC, using the live TLS
  certificate and signing key).
- `[tls] raw_public_key = true` and `ktls = "tx"` (RPK is negotiated only by
  clients that offer it; kTLS offloads server-to-client TLS 1.3 records).
- `[sts] preload = true` with the existing secure port `6697`.
- `[weather] enabled = true` and `[news] enabled = true`; the live Geo cache
  remains the source because no fabricated sample source file is configured.
- `[media] native_media_require_mac = true`, `ws_media_require_mac = true`,
  `dtls_srtp = true`, and `dtls13 = true`. Native and browser media now require
  their authenticated tags; DTLS 1.3 peers fall back to the hardened 1.2 path
  when appropriate.
- `[io] sqpoll = true` and `defer_taskrun = false`. SQPOLL is accepted by both
  kernels and is compatible with the current four-reactor loop.
- `[webhook] enabled = true`, loopback bind `127.0.0.1:9140`, and a persistent
  node-local `webhooks.tsv` store. HTTPS exposure still requires an explicitly
  configured reverse proxy.

Already-live gates (SASL/account store, WebSocket TLS, STS, media, Web Push,
E2EEGROUP authoring, DNSBL, metrics, backups, sessions, account cloaking, and
secured/signed Mooring) were preserved and verified after restart.

## Explicit holds

The following are intentionally not enabled or not promoted by this record:

- `[acme] enabled = false` on both nodes, per the request. No ACME/Let's Encrypt
  renewal worker was started.
- `[ocsp] enabled = false`: the deployed Let's Encrypt leaves expose no OCSP
  responder URI, so enabling the worker would be a no-op rather than a staple.
- OCG2 remains disabled. Only observe mode is implemented; its authority tuple
  and durable activation prerequisites are not provisioned, while projection
  and minting fail closed by design.
- Mail remains disabled because neither node has a configured relay host and
  sender. Enabling the boolean alone would create no sender or delivery path.
- `listen.ws_plain` remains false (testing-only), `listen.proxy_protocol`
  remains false (no trusted proxy list), `sasl.allow_anonymous` remains false,
  and `mail.insecure_skip_verify` remains false.
- kTLS RX is not requested. TX-only avoids the documented inbound re-key
  reconnect behavior while retaining the safe server-write offload.
- `defer_taskrun` was tested and rolled back: with this artifact's rings created
  before the four worker threads bind, every reactor returned `InvalidThread`.
  Both kernels reject `SQPOLL | DEFER_TASKRUN | SINGLE_ISSUER` together with
  `EINVAL`; SQPOLL is therefore the active io_uring optimization.
- WebAuthn policy flags (`require_uv`, `require_attestation`) remain policy
  choices, not capability gates. No browser media or WebTransport interoperability
  claim is made beyond the listener/boot evidence below.

## Acceptance evidence

Before mutation, both nodes were healthy (`links_active=1`, `peers_up=1`,
`partitioned=0`) and the existing bidirectional mesh chat smoke passed.

For each final TOML, the deployed binary passed:

```text
onyx-server --check-config <node-config>
```

The local node required a cold restart because Helix has no exact checkpoint for
the newly-created WebTransport listener. The peer was restarted only after the
local node was healthy. Both restarts reported:

```text
ActiveState=active
SubState=running
Result=success
```

Boot logs confirmed kTLS TX, STS preload, the media and native-media UDP
transports, WebTransport UDP `:4433`, and webhook TCP `127.0.0.1:9140` on both
nodes. A TLS 1.3 handshake to the local listener negotiated
`TLS_AES_128_GCM_SHA256`.

Post-release checks:

- Six mesh-health samples on both nodes: `links_active=1`, `peers_up=1`,
  `partitioned=0`, `tcp_active=1` every time.
- `tools/mesh_chat_smoke.py`: registration, JOIN, A→B PRIVMSG, and B→A
  PRIVMSG all passed.
- `GET http://127.0.0.1:9140/` returned `404` on both nodes, proving the
  loopback listener is reachable and rejects an unknown webhook route.
- `ss` showed UDP `:4433`, loopback TCP `:9140`, and loopback metrics TCP
  `:9130` on both nodes.
- No `InvalidThread`, reactor-give-up, fatal, bind-failure, or disabled-feature
  log appeared after either final restart.
- `zig build test` exited successfully from the release checkout.

The mesh is therefore released with all activatable production gates enabled,
with the prerequisite-bound and explicitly unsafe/reserved paths above kept
fail-closed.
