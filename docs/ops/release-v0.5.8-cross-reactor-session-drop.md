# Cross-reactor session revoke and resume rollout

Deployed 2026-08-14 from source commit `6b8612f` (`0.5.8+6b8612f`).

## Scope

- `SESSION DROP` now reserves the exact physical row and its reusable-token
  group before a cross-reactor revoke. The Store compare-and-remove is the
  linearization point; stale client, token, signon, attachment, or reservation
  identity fails closed.
- A live exact-token sibling inherits the rendered nick and the union of channel
  modes before the target owner closes. A final row retains ordinary QUIT
  behavior.
- Close, detach, token rebind, exact attachment restore, bootstrap attach, cap
  eviction, and logout cannot mutate a token group while DROP owns a reservation.
  Close cancels precommit work and retries the allocation-free detach path.
- Transaction state is bounded, generational, secret-erased, and excluded from
  Helix snapshots. Hot upgrade refuses an active transaction rather than
  serializing a partial ownership transfer.
- Control mailboxes are independent of chat delivery pressure. Misses are
  counted, recovered by the authoritative journal sweep, and rate-limited in
  server warnings.

## Verification

- Direct transaction journal: 20/20 Debug and ReleaseSafe.
- Focused reservation, sentinel, token-index, control, close-race, all
  `SESSION DROP`, and active-upgrade-blocker filters: Debug and ReleaseSafe.
- True two-reactor acceptance used live shard-owned connections and proved SID
  removal, owner-shard close delivery and closure, journal reap, mode union,
  surviving nick ownership, and no false QUIT.
- `zig build test-session`: Debug and ReleaseSafe.
- Full `zig build test`: Debug and ReleaseSafe. The sweep covered 8,351 tests;
  the only initial failure was a stale constant lookup expectation after adding
  two O(1) reservation guards. The corrected bound passed directly and in both
  full reruns.
- `zig build check` and stripped ReleaseSafe build: exit 0.
- Independent release review found no remaining P0/P1 blocker.

## Artifact

- `dist/onyx-server-0.5.8-x86_64-linux-musl`
- SHA-256:
  `b681fe6b73272b3e8494e3320710501cf51ebd2b58e32fba50b4ca5e795d45be`
- SBOM and SLSA-shaped provenance were emitted by `packaging/release.sh` from
  the clean commit. Each exact live TOML passed `--check-config` before install.

## Deployed nodes

| Node | Unit | Main PID | Running and on-disk SHA-256 |
| --- | --- | ---: | --- |
| `eshmaki.me` | `onyx-server.service` active | `828697` | `b681fe6b73272b3e8494e3320710501cf51ebd2b58e32fba50b4ca5e795d45be` |
| `ircx.us` | `onyx-server.service` active | `1245448` | `b681fe6b73272b3e8494e3320710501cf51ebd2b58e32fba50b4ca5e795d45be` |

Both nodes used Helix reload and retained their Main PID. `ircx.us` restored
three TLS clients, three sessions, and its mesh link. `eshmaki.me` restored six
clients, six sessions, four listener shards, and its mesh link.

## Live acceptance

- `EXPECT_VER=6b8612f tools/era2_acceptance_smoke.sh`: pass.
- Dual-node metrics: `links_active=1`, `peers_up=1`, `partitioned=0`,
  `tcp_active=1` on both nodes.
- `tools/mesh_chat_smoke.py`: guest registration/join and unique PRIVMSG
  delivery passed in both directions across `#root`.
- A disposable-account acceptance obtained an MTOKEN on eshmaki, disconnected,
  resumed it on `ircx.us`, and completed `SESSION LIST`; cleanup was issued.
- Post-deploy journals contained no panic, fatal, segfault, assertion, control
  miss, or upgrade-refusal line.

## Client

The exact-SID session roster/drop parser shipped first at client commits
`976ab35c` and `4a233f1d`, release `20260814-154951-4a233f1d`, at
`https://eshmaki.me/app/`. Its deploy controller preserves the runtime-owned
`onyxOS/status.json` feed while still proving staged/live byte equality.

## Rollback

- Eshmaki:
  `/home/kain/onyx-server-run/onyx-server.prev-c9901d8-20260814T153207Z`
- ircx:
  `/home/trev/onyx-server-run/onyx-server.prev-c9901d8-20260814T153208Z`
- Previous artifact SHA-256:
  `d2171fc28efd46419d9285d37594a775cb909002092a3b0d8a2610fb0f68ff6f`

Roll back one node at a time through Helix, verify its running `/proc` hash and
mesh health, then touch the second node.
