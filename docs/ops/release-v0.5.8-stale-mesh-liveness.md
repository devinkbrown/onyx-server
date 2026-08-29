# v0.5.8 Stale Mesh Liveness Recovery

Deployment completed 2026-08-29.

## Incident

The two-node mesh entered a persistent asymmetric partition on 2026-08-28 at
05:32 CEST. `eshmaki.me` retained a half-open S2S socket as an established peer,
while `ircx.us` reported no peer and retried every ten seconds. Each newly
authenticated replacement was then collapsed against the stale deterministic
winner. The loop produced about 6,900 transient establishments and left runtime
connection gauges far above the physical descriptor count.

Emergency containment cold-restarted one node at a time, first `eshmaki.me` and
then `ircx.us`. This cleared the inconsistent in-memory peer state and restored
simultaneous mesh health before the permanent release was built.

## Immutable inputs

- Source commit: `d86e1f098d65e2a7a5a553c3fe21d410ac82f019`
- Runtime version: `Onyx Server 0.5.8+d86e1f0`
- ReleaseFast binary SHA-256:
  `ea647accdd19d825433e938b208bde038e9af141be14a81c3183a0cfb96ade5b`
- Changed runtime source: `src/daemon/server.zig`

The release adds an application-level S2S receipt deadline, arms it at the exact
whole-record SendQ commit boundary, replaces liveness-expired collision winners,
fully scans duplicate candidates, and safely finalizes both armed and unarmed
teardown paths. Per-slot metric ownership and post-commit Helix reconstruction
keep client and S2S gauges paired with physical slots.

## Verification

- Focused module regressions, Debug: 77/77 passed.
- Focused module regressions, ReleaseSafe: 77/77 passed.
- Debug server: 420/424 passed, 4 skipped.
- Debug mesh: 489/491 passed, 2 skipped.
- Debug services: 534/534 passed.
- ReleaseSafe server: 420/424 passed, 4 skipped.
- ReleaseSafe mesh: 489/491 passed, 2 skipped.
- ReleaseSafe services: 534/534 passed.
- Full `zig build test --summary all`: 8,432/8,436 passed, 4 skipped.
- `zig build all-checks --summary all`: 18/18 steps and 96/96 tests passed.
- ReleaseFast reproducibility rebuild matched the release SHA-256 byte for byte.
- Fresh adversarial lifecycle review: PASS, no remaining findings after four
  review/fix passes.

## Rollout

Both exact production configurations passed `--check-config` with the staged
artifact. The rolling Helix deployment preserved the active MESSAGE_V2 custody
state and the established secured link:

| Node | Resume time | Restored runtime |
|---|---|---|
| `eshmaki.me` | `2026-08-29 02:51:26 CEST` | 5 clients, 1 mesh link, 4 listeners |
| `ircx.us` | `2026-08-28 17:51:42 PDT` | 3 clients, 1 mesh link, 1 listener |

Both processes retained their PIDs and adopted mandatory World, history, event,
replay, webhook, session, replica, and migration state. The installed artifact
and each live `/proc/<pid>/exe` matched the release SHA-256.

## Live acceptance

- Eight simultaneous two-node health samples over more than 80 seconds reported
  `links_active=1`, `peers_up=1`, `partitioned=0`, and `tcp_active=1` on both
  nodes, covering the new probe and timeout window.
- `tools/era2_acceptance_smoke.sh` passed against version `d86e1f0`.
- `tools/mesh_chat_smoke.py` delivered one message in each direction across the
  secured mesh.
- After the smoke clients disconnected, `connections_active` returned to 5 on
  `eshmaki.me` and 3 on `ircx.us`.
- Each node logged exactly one Helix-resume establishment and no reconnect churn.

## Rollback

Both nodes retain `onyx-server.prev-413ab96-pre-d86e1f0`, version
`Onyx Server 0.5.8+413ab96`, with SHA-256
`c3d2a02c631b6a2b4bc7d6023efd9f997b0655ce1c00b31ec93e06b01ac65528`.
Rollback remains subject to the active MESSAGE_V2 and Helix compatibility
constraints in `docs/RUNBOOK.md`.
