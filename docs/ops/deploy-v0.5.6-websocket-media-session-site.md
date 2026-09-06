# Onyx Server 0.5.6 WebSocket, session, and unified-site follow-up

Deployment date: 2026-07-20

This is the executed two-node follow-up record for negotiated WebSocket media,
certificate-backed reusable sessions, immediate Onyx rosters, video-panel
startup/layout, live stats, and registered-account DM encryption.

> **Historical snapshot (2026-07).** This record preserves the exact release-time
> paths and service names. Do not use it as a current deployment target; current
> fleet paths are maintained in [`onyx-server-paths.md`](onyx-server-paths.md).

## Immutable inputs and verification

| Item | Value |
| --- | --- |
| Server source commit | `332fd84` (`fix: send WebSocket size close codes`) |
| Client source commit | `ecdb661` (`docs: publish continuity roadmap`) |
| Landing source commit | `cfcec98` (`site: publish complete product roadmap`) |
| Server version | `Onyx Server 0.5.6+332fd84` |
| Server artifact | x86_64 Linux musl, ReleaseFast, stripped |
| Artifact SHA-256 | `5fae656cb942c6562670cd37344fc667eff0cdbcfcc00eee2e642fa931059e46` |
| Reproducibility | two isolated `/home/kain/.cache` builds were byte-identical |
| Deployed site cache | `onyx-shell-20260720-231424-ecdb661` |

The exact server commit passed `zig build all-checks --summary all`: 18/18
steps, 7,844 tests passed, 4 skipped, and zero failed. Focused WebSocket lanes
passed in Debug and ReleaseSafe, including single-frame and fragmented aggregate
limits, coalesced-buffer overflow, strict text mode, mixed recipients, and
current Helix mid-fragment restoration. Fresh review found no remaining blocker.

The client passed its 400-file, 5,213-test unit suite, typecheck, production
build, and lint with zero errors. Seven existing `VoiceBar` warnings remain
warnings. Focused roster suites passed 93 tests; shell/media startup passed 72;
and the video reflow browser lane passed 4/4, including 400 percent and compact
desktop layouts. The unified landing build and full 281-test suite passed; its
public roadmap contract adds shipped, active, and later bands without claiming
that the partial Cadence call product is complete.

## Two-node activation

| | `eshmaki.me` | `ircx.us` |
| --- | --- | --- |
| Live unit | `orochi.service` | `orochi.service` |
| Live binary | `/home/kain/orochi-run/orochi` | `/home/trev/orochi-run/orochi` |
| Config | `/home/kain/orochi-run/orochi.local.toml` | `/home/trev/orochi-run/orochi.ircxus.toml` |
| Rollback binary | `orochi.rollback-pre-332fd84` | `orochi.rollback-pre-332fd84` |
| Initial final PID | `2117098` | `650391` |

Both preserved production configs passed the staged artifact's `--check-config`.
Both nodes were hard-restarted onto the byte-identical artifact and returned
active with mesh quorum 1, partitioned 0, one component, and one of one peers
up. TLS 1.3/ECDHE is already active; this release needs neither a new CA bundle
nor a static DH parameter file.

## Live protocol and session acceptance

Both public WebSocket endpoints selected `onyx.irc-media.v1` when it was offered
before `text.ircv3.net`, selected strict text when requested alone, and accepted
the no-protocol legacy path. Strict text rejected binary, empty, and CR/LF text
messages with 1002. The custom protocol rejected a 4 MiB plus one byte binary
message with 1009 rather than an abnormal close.

The `ircx` WeeChat profile presented `/home/kain/.weechat/tls/relay.pem`, used
SASL EXTERNAL as account/nick `kain`, and reported certificate-authenticated
session restoration. Two attachments remained present. A release marker sent
through the `ircx.us` attachment arrived in all three observed `#root` buffers.
The only `+Y kain` was the genuine first grant reconstruction after the planned
cold restart; subsequent certificate session attachments emitted no mode churn.

## Live Onyx acceptance

The client requests explicit `NAMES` after JOIN when it negotiates
`draft/no-implicit-names`. A fresh public client received the complete `#root`
roster in its first 250 ms sample instead of remaining on “Loading members…”.

The first video click now keeps the connected shell mounted while lazy voice
chunks load. At 1280 by 800 the live stage measured 144 px, the message history
retained 132 px, the rectangles did not overlap, and Voice settings did not
open. `/stats/` contained at 320/320 CSS pixels under simulated 400 percent zoom.

The registered-account live E2EE gate created two accounts, joined both to
`#root`, opened the DM from the authoritative member list, and delivered the
same plaintext to both feeds. The outbound wire contained a tagged `TSUMUGI1`
envelope and did not contain the plaintext. The durable gate is
`tools/e2ee-live.mjs` in the Onyx client repository.

The composite site returned HTTP 200 for `/`, `/app/`, `/stats/`, `/status/`,
`/roadmap/`, and `/self-host/`. The live roadmap rendered 23 cards across Here
now, Building now, and Later horizon at desktop, mobile, and simulated 400
percent zoom with no document-level horizontal overflow or page errors.
Announce remained active and published the server/client commits with numeric
test inventory rather than `? tests`.
