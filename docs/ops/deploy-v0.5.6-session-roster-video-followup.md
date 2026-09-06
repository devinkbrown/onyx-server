# Onyx Server 0.5.6 session-roster and Onyx video follow-up

Deployment date: 2026-07-20

This is the executed two-node follow-up release record for immediate roster
delivery after certificate-backed session resume. It also records the paired
Onyx client deployment that makes Edge video-call startup visible immediately
and keeps the video stage docked instead of covering chat.

> **Historical snapshot (2026-07).** This record preserves the exact release-time
> paths and service names. Do not use it as a current deployment target; current
> fleet paths are maintained in [`onyx-server-paths.md`](onyx-server-paths.md).

## Immutable release inputs

| Item | Value |
| --- | --- |
| Server source commit | `ed8bad4` (`fix session resume roster bootstrap`) |
| Client source commit | `cb0cb48` (`fix video call panel startup and docking`) |
| Version banner | `Onyx Server 0.5.6+ed8bad4` |
| Server artifact | x86_64 Linux musl, ReleaseFast, stripped |
| Artifact SHA-256 | `eeed6df8072d5a31c97ebbc13d336fa99dc9f75172929332465e483310364f4d` |
| Reproducibility | two isolated `/home/kain/.cache` builds were byte-identical |
| Review | fresh independent server review: clean, no remaining blocker |

The final server tree passed `zig build all-checks --summary all`: 18/18
steps, 7,821 tests passed, 4 skipped, zero failed. The affected ReleaseSafe
session and server suites passed 1,089 tests with 4 skipped. The exact seed that
first exposed missing SEND activation, `0x59faf993`, also passed the complete
413-test server lane with 4 skips.

The Onyx client passed 399 test files and 5,192 unit tests, typecheck, production
build, and lint with zero errors. Seven existing `VoiceBar` reactivity warnings
remain warnings. The focused live-layout Playwright lane passed three Chromium
tests, including 400 percent reflow and the requirement that a docked video
stage leave the message feed visible.

## Server fix

Session restore previously generated JOIN/topic/NAMES only for a synthetic
logical join. A physical attachment already seated in World state could
therefore resume successfully without receiving its roster until the client
issued a later `NAMES` poll.

The restore transaction now prepares the claimant's complete PART/NICK/JOIN,
topic, and projected `353` through `366` stream before committing World and
SessionStore state. It reserves the exact transport bound, appends the complete
batch atomically, and immediately arms SEND. Unexpected post-commit transport
failure poisons the connection rather than exposing a partially successful
resume. Claimant and peer events reuse the same immutable server-time bytes,
and `no-implicit-names` remains respected.

The roster projection deduplicates the restored logical nick and retains its
member-mode prefix. Regression coverage parses the final IRC parameter as a
trailing field, requires `kain` exactly once, and covers both local SASL
EXTERNAL resume and live reusable-token resume.

## Onyx video and panel fix

The client now publishes provisional in-call state before awaiting Edge media
permission, capture, or WASM startup. The video panel therefore appears on the
first click and duplicate starts are suppressed; failed startup rolls the
provisional state back to idle.

The video stage is a bounded responsive tray rather than a full-height overlay.
Desktop height is capped at 42 percent of the viewport and narrow layouts at 34
dynamic viewport percent, leaving the message feed visible and scrollable while
the call is open.

The deployed site uses service-worker stamp
`onyx-shell-20260720-071321-cb0cb48`. The live `/app/` route returned HTTP 200,
and the deployed AppShell and voice stylesheet hashes matched the local build.

## Two-node deployment and rollback

| | `eshmaki.me` | `ircx.us` |
| --- | --- | --- |
| Live unit | `orochi.service` | `orochi.service` |
| Live binary | `/home/kain/orochi-run/orochi` | `/home/trev/orochi-run/orochi` |
| Config | `/home/kain/orochi-run/orochi.local.toml` | `/home/trev/orochi-run/orochi.ircxus.toml` |
| Previous SHA-256 | `711d4ed1c5ccf414a750a40316a41c9235f22aa7837683a7ba94d96e9d57c64e` | same |
| Binary rollback | `orochi.rollback-pre-ed8bad4` | `orochi.rollback-pre-ed8bad4` |
| Config backup | `orochi.local.toml.pre-ed8bad4` | `orochi.ircxus.toml.pre-ed8bad4` |
| Initial PID | `1744795` | `619284` |

Each preserved production config passed the staged artifact's `--check-config`.
Both live binaries were replaced with the identical verified artifact, and both
services were hard-restarted. Each returned `active/running` with the expected
version and hash. Both metrics endpoints reported mesh quorum 1, partitioned 0,
one connected component, and one of one peers up.

## Live certificate-session acceptance

The saved WeeChat profiles use `/home/kain/.weechat/tls/relay.pem`, TLS
verification, SASL EXTERNAL, and account/nick `kain`. The certificate is valid
through 2026-08-23.

After the mesh was stable, the `eshmaki` and `ircx` profiles were reconnected
independently. On each node the client presented the certificate, completed
SASL as `kain`, reported certificate-authenticated session restoration, joined
`#root`, and received topic plus a seven-member roster immediately. Each roster
contained one prefixed `kain`. Neither resume emitted `MODE #root +Y kain`.

One `+Y kain` appeared when the first local attachment rebuilt membership on
the newly cold-started process. That connection received a fresh token and no
session-resume notice, so it was the genuine first logical grant transition.
The subsequent local and remote certificate resumes were silent, demonstrating
that per-login mode churn is removed while first-grant semantics remain intact.

The user `announce.service` detected commit `ed8bad4` and announced it in
`#root`, confirming commit announcements remained active through the release.
