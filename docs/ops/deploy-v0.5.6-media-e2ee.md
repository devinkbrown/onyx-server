# Onyx Server 0.5.6 media E2EE release record

Deployment date: 2026-07-20

This is the executed two-node release record for attachment-safe client-held
media encryption. It records observed production paths, including legacy unit
and binary names; those literals are not new product naming.

> **Historical snapshot (2026-07).** The paths and unit names below are immutable
> evidence for that release. Current production uses `onyx-server.service` and
> `/home/kain/onyx-server-run` / `/home/trev/onyx-server-run`; see
> [`onyx-server-paths.md`](onyx-server-paths.md).

## Immutable release inputs

| Item | Value |
| --- | --- |
| E2EE source commit | `60a50cf` (`Complete attachment-safe media encryption`) |
| Deployed source tree | `c78f1c3` (E2EE release plus merged Armor entropy portability fix) |
| Client commit | `4f42356` (`Complete attachment-safe media encryption`) |
| Version banner | `Onyx Server 0.5.6+c78f1c3` |
| Server artifact | `zig-out/bin/onyx-server` |
| Artifact SHA-256 | `711d4ed1c5ccf414a750a40316a41c9235f22aa7837683a7ba94d96e9d57c64e` |
| Reviewer | fresh independent high/critical security review: `PASS`, no remaining finding |

After the remote Armor portability commit was merged, the final source tree
passed `zig build all-checks --summary all`: 18/18 steps, 7,818 tests passed, 4
skipped, zero failed. The full ReleaseSafe server lane passed again, as did the
clean static x86_64 Linux artifact build and diff checks.

The Onyx client passed 399 test files and 5,189 tests, typecheck, production
build, and lint with zero errors. Seven existing Solid reactivity warnings in
`VoiceBar` remain warnings, not release failures.

## Live node inventory and rollback

| | `eshmaki.me` | `ircx.us` |
| --- | --- | --- |
| Live unit | `orochi.service` | `orochi.service` |
| Live binary | `/home/kain/orochi-run/orochi` | `/home/trev/orochi-run/orochi` |
| Config | `/home/kain/orochi-run/orochi.local.toml` | `/home/trev/orochi-run/orochi.ircxus.toml` |
| Binary rollback | `orochi.rollback-pre-c78f1c3` | `orochi.rollback-pre-c78f1c3` |
| Config backup | `orochi.local.toml.pre-c78f1c3` | `orochi.ircxus.toml.pre-c78f1c3` |
| Restart time | 2026-07-20 06:26:53 CEST | 2026-07-19 21:26:54 PDT |
| Initial PID | `1670376` | `615538` |

The same artifact SHA was verified on both nodes. Each preserved production
config passed the staged binary's `--check-config` before replacement. The
deployment introduced no configuration change. Both services were hard
restarted together and reported `0.5.6+c78f1c3`.

After activation, both metrics endpoints reported quorum 1, partitioned 0, one
connected component, and one of one mesh peers up. Startup logs had no crash,
restart, or Mooring reconnection loop.

## Certificate session and routing acceptance

The saved WeeChat profiles `ircx` and `ircx.us` use
`/home/kain/.weechat/tls/relay.pem`, TLS verification, SASL EXTERNAL, and the
account/nick `kain`. The certificate file is mode 0600, has subject
`CN=eshmaki.me`, and is valid through 2026-08-23.

After the final restart, an explicit WeeChat reconnect presented the configured
client certificate, completed SASL EXTERNAL as `kain`, ran against
`0.5.6+c78f1c3`, and reported `SESSION RESUME: certificate-authenticated
session restored`. It did not emit `MODE #root +Y kain`.

Two concurrent OpenSSL-backed certificate clients were then held open, one on
each mesh node. Each authored a channel marker and a direct-message marker. All
four events reached both transports exactly once with identical `msgid` and
`time` tags:

| Marker | `msgid` |
| --- | --- |
| channel from node A | `2KHHR8R4ZY523BW1EXZM7T0WHT` |
| channel from node B | `3RYE8GHBJB4DJY7J2P9GXE127K` |
| direct message from node A | `0AAXNRJR78KJ2YFRRQ5AA0ZTBS` |
| direct message from node B | `750PY805BP2XT3620E1TYM58MG` |

Neither attachment caused unchanged grant-mode churn.

## E2EE acceptance

The accepted release enforces the signed v2 attachment handshake, account-key
enrollment, per-call ephemeral ECDH, exact `nick:attachment` group-key targeting,
AES-GCM media frames, Ed25519 sender signatures, generation/epoch/replay fences,
and server-side MAC plus attachment/stream/kind binding. Legacy and plaintext
downgrades fail closed.

Lifecycle tests and independent review covered re-handshake, explicit leave,
disconnect, final nick-wide leave, `PART`, `KICK`, nick mutation, account
mutation, failed and same-account authentication, server-only detach, old-frame
denial, three-member leader departure, pending leadership, and detached-client
key zeroization.

## Website and automation acceptance

The Onyx site was deployed from client commit `4f42356`. Routes `/`, `/stats/`,
`/status/`, `/roadmap/`, `/invite/`, `/about/`, `/accessibility/`, `/glossary/`,
`/integrations/`, `/agents/`, `/app/`, and `/sw.js` returned HTTP 200. The live
service worker cache is `onyx-shell-20260720-052915-4f42356`.

The stats feed was populated with current `#root` data: 53 messages, 6 active
users, 6 present users, and one network day at the final acceptance snapshot.
The user `announce.service` detected and announced both release commits,
recovered after the planned local restart, and updated the topic to the current
client and server source commits.

## Known boundaries

- E2EE control events converge over the secured Undertow mesh. Binary WebSocket
  media forwarding remains node-local; cross-node encrypted frame cascading is
  not part of this release.
- Minimal Python standard-library TLS clients reproduced a TLS 1.3
  `decode_error` against both nodes while WeeChat and OpenSSL-backed clients
  authenticated and routed successfully. This is an Armor record-path
  interoperability investigation, not a reason to weaken client-certificate or
  E2EE signature enforcement.
