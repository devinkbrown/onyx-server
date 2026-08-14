# Exact session-row revoke rollout

Deployment completed on 2026-08-14 from source commit
`c9901d8d13a649516eb53464294427a9f182d1e2` (`0.5.8+c9901d8`).

## Scope

- `SESSION LIST` binds each ordinal to the exact emitted physical row and emits
  an opaque 128-bit SID when the row has a stable attachment ID.
- `SESSION DROP` compare-and-removes only that token/client/signon/attachment
  row. Reordered stores, recycled clients, token rotation, ambiguous SIDs, and
  stale LIST images fail closed.
- Same-reactor shared-token revocation prepares the World nick/channel handoff,
  performs the exact Store CAS, commits the allocation-free handoff, then closes
  the old transport. The surviving attachment retains the nick and merged modes
  without a false QUIT. Removing the final row retains the ordinary QUIT path.
- Cross-reactor attached targets and unattested cross-reactor successors return
  `TEMPORARILY_UNAVAILABLE` without mutation. The reserved two-owner transaction
  remains a future activation boundary; no incomplete foreign-owner control was
  deployed.
- LIST caches are complete and dynamically sized, securely erase successful
  DROP selectors without reindexing, clear before failed LIST allocation, and
  are not serialized through Helix.

## Verification

- Focused `SESSION DROP` tests: Debug and ReleaseSafe exit 0.
- `zig build test-session`, `test-services`, `test-server`, and `test-helix`:
  exit 0 when run serially.
- Full `zig build test`: exit 0.
- `zig build check` and `zig build release`: exit 0.
- Fresh independent review found no remaining release-safety blocker after the
  prepared handoff, final-QUIT, cache-lifecycle, foreign-sibling, and
  three-sibling successor-selection regressions landed.
- `tools/upgrade_smoke.py` passed with two listener shards, plain/TLS/WSS
  connections, eight filler clients, and the same reclaim token surviving the
  Helix re-exec.

## Artifact proof

- Artifact: `onyx-server-0.5.8-x86_64-linux-musl`
- SHA-256:
  `d2171fc28efd46419d9285d37594a775cb909002092a3b0d8a2610fb0f68ff6f`
- `packaging/verify-release.sh` rebuilt the clean commit with an independent
  cache and produced a byte-identical binary. The shipped binary, SBOM, and
  provenance all matched `SHA256SUMS`.
- The staged artifact passed `--check-config` against each exact live TOML before
  either process was reloaded.

## Deployed nodes

| Node | Unit | Main PID | Running and on-disk SHA-256 |
| --- | --- | ---: | --- |
| `eshmaki.me` | `onyx-server.service` active/running | `828697` | `d2171fc28efd46419d9285d37594a775cb909002092a3b0d8a2610fb0f68ff6f` |
| `ircx.us` | `onyx-server.service` active/running | `1245448` | `d2171fc28efd46419d9285d37594a775cb909002092a3b0d8a2610fb0f68ff6f` |

Both nodes used Helix `SIGUSR2` reload and retained their Main PID. Eshmaki
reattached six clients and its secured mesh link; ircx reattached three clients
and its secured mesh link. Mandatory World/history/event/replay state, session
rows, replicas, and staged migrations were restored on both nodes.

## Live acceptance

- `tools/era2_acceptance_smoke.sh` with `EXPECT_VER=c9901d8`: pass.
- Dual-node metrics on both nodes: `links_active=1`, `peers_up=1`,
  `partitioned=0`, `tcp_active=1`.
- `tools/mesh_chat_smoke.py`: guest clients registered and joined `#root`; one
  unique `PRIVMSG` arrived in each direction across the mesh.
- SASL EXTERNAL portable-session acceptance: created a session on eshmaki,
  obtained a sealed credential without logging it, disconnected, resumed the
  session on ircx under a fresh transport, listed the restored attachment, and
  logged the temporary acceptance session out.

## Rollback

- Eshmaki:
  `/home/kain/onyx-server-run/onyx-server.prev-31b6be1-20260814T132134Z`
- ircx:
  `/home/trev/onyx-server-run/onyx-server.prev-31b6be1-20260814T132134Z`
- Previous artifact SHA-256 on both nodes:
  `77e55d699de3e35000ee36e74073eb39cd279f4027a418782426be2682f1368c`

Validate a rollback artifact against the exact live configuration before
installing it. Roll back one node at a time through Helix, verify the running
`/proc/<MainPID>/exe` hash and mesh health, then touch the peer.
