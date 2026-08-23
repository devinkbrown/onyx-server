# Atomic detached-session resume rollout

Deployed 2026-08-14 from source commit `8c0ec5d` (`0.5.8+8c0ec5d`).

## Scope

- Detached `SESSION RESUME` no longer commits the claimant token, World
  identity, channel image, or session attachment before retained delivery-spool
  transfer is known to be safe.
- Local, staged-mesh, replicated-mesh, and degraded no-snapshot reclaim paths
  use the same prepared transaction boundary.
- A spool conflict now fails closed with the claimant unchanged, the detached
  ghost still recoverable, and its queued bytes intact. A later retry can
  transfer those exact bytes and complete the resume.
- The client release paired with this rollout makes adaptive backgrounds honor
  mobile capability and consolidates mobile workspace settings into one
  keyboard-safe menu.

## Verification

- Focused atomic-resume filters: 71/71 in Debug and 71/71 in ReleaseSafe.
- Full `zig build test-session`: 723/723 in Debug and 723/723 in ReleaseSafe,
  with no failure, skip, leak, or logged error.
- ReleaseSafe executable root and both exact live TOMLs: exit 0.
- `packaging/verify-release.sh`: clean-cache byte-identical rebuild and manifest
  integrity passed.
- Independent release review found no remaining P0/P1 blocker.

## Artifact

- `dist/onyx-server-0.5.8-x86_64-linux-musl`
- SHA-256:
  `7f7674a9ac4dd3260cb713715be30d2e334aead3fe0d0ad18ba6d7bde37ea9b5`
- SBOM and SLSA-shaped provenance were emitted by `packaging/release.sh`.

## Deployed nodes

| Node | Unit | Main PID | Running and on-disk SHA-256 |
| --- | --- | ---: | --- |
| `eshmaki.me` | `onyx-server.service` active | `828697` | `7f7674a9ac4dd3260cb713715be30d2e334aead3fe0d0ad18ba6d7bde37ea9b5` |
| `ircx.us` | `onyx-server.service` active | `1245448` | `7f7674a9ac4dd3260cb713715be30d2e334aead3fe0d0ad18ba6d7bde37ea9b5` |

Both nodes used Helix reload and retained their Main PID. The peer restored
three TLS clients, four sessions across three accounts, and its mesh link. The
local node re-attached six client connections, restored six sessions, and
preserved its four listener shards and mesh link.

## Live acceptance

- `EXPECT_VER=8c0ec5d tools/era2_acceptance_smoke.sh`: pass.
- Dual-node metrics: `links_active=1`, `peers_up=1`, `partitioned=0`,
  `tcp_active=1` on both nodes.
- `tools/mesh_chat_smoke.py`: guest registration/join and unique PRIVMSG
  delivery passed in both directions.
- A disposable identity was registered in both node-local credential stores.
  Eshmaki issued an MTOKEN, the source disconnected, `ircx.us` resumed the
  detached session through the mesh credential, and `SESSION LIST` returned.
  Both disposable account records were then dropped.
- Running `/proc/<pid>/exe` and installed binary hashes match the release
  artifact on both nodes. Post-deploy inspection found no panic, fatal,
  segfault, or assertion line.

## Client

Client commit `56dda2ce` is live as release
`20260814-182527-56dda2ce` at `https://eshmaki.me/app/`. The live service worker
stamp and the exact deployed `AppShell` chunk were verified after deployment.
The client passed 6,609 unit tests, typecheck, touched-file lint, production
build, 101 deploy-controller tests, and five production-preview browser flows.

## Rollback

- Eshmaki:
  `/home/kain/onyx-server-run/onyx-server.prev-6b8612f-20260814T163457Z`
- ircx:
  `/home/trev/onyx-server-run/onyx-server.prev-6b8612f-20260814T163457Z`
- Previous artifact SHA-256:
  `b681fe6b73272b3e8494e3320710501cf51ebd2b58e32fba50b4ca5e795d45be`

Roll back one node at a time through Helix, then verify the running `/proc`
hash and mesh health before touching the second node.

## Follow-up frontier

- Remove the remaining 512-member `NAMES` projection cap so large-channel
  rosters converge without truncation.
- Tighten exact ghost retirement after prepared resume and broaden conflict
  assertions across staged-mesh and degraded no-snapshot paths.
