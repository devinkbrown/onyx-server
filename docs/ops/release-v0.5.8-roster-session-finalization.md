# Roster and session finalization rollout

Deployed 2026-08-14 from source commit `793d26d` (`0.5.8+793d26d`).

## Scope

- NAMES no longer truncates channels at 512 members. The server constructs the
  complete case-insensitive local, projected-resume, and mesh roster with
  bounded dynamic storage and renders standards-sized `353` lines followed by
  exactly one `366`.
- A NAMES burst is prepared completely before live output. SendQ refusal emits
  no partial list; a post-reservation TLS/WebSocket framing failure poisons the
  connection rather than leaving it usable after partial ciphertext.
- Malformed admitted mesh roster rows fail the requesting connection locally
  without escaping the reactor completion firewall or certifying an incomplete
  roster.
- Labeled NAMES and resume bootstrap captures use the caller's checked remaining
  SendQ instead of the former fixed capture ceiling.
- Account DROP revokes stored and replicated session authority and publishes an
  exact-generation poison before closing every same-account connection across
  reactor ownership. An already-ready receive cannot execute with stale account
  or operator authority.
- Retryable SESSION RESUME preservation is attempt-scoped and bounded. Both the
  login-time and later manual paths expire cleanly, release deferred autojoin,
  restore SESSION TOKEN behavior, and cannot block UPGRADE indefinitely.

## Verification

- Final exact-tree `zig build test-session`: pass.
- Debug NAMES: 91/91; ReleaseSafe NAMES: 91/91.
- Debug retry/upgrade: 73/73; ReleaseSafe retry/upgrade: 73/73.
- Debug DROP: 81/81; ReleaseSafe DROP: 81/81.
- Production-boundary regressions cover the CQE-to-completion malformed-roster
  path and a true two-reactor DROP/receive-before-mailbox-close race.
- All reported focused gates had zero failures, skips, leaks, or logged errors.
- Independent final architecture review: SHIP, no P0/P1 in this release diff.

## Artifact

- `dist/onyx-server-0.5.8-x86_64-linux-musl`
- SHA-256:
  `db4a9c4a40a25117cdfee912dddad7e2432c0ac3200bb8cb9e2be90634aa5b53`
- Clean-cache reproducibility rebuild: byte-identical.
- SHA256SUMS integrity, SBOM JSON, and SLSA-shaped provenance JSON: pass.
- Both exact live TOMLs passed `--check-config` under `0.5.8+793d26d`.

## Deployed nodes

| Node | Unit | Main PID | Running and on-disk SHA-256 |
| --- | --- | ---: | --- |
| `eshmaki.me` | `onyx-server.service` active | `828697` | `db4a9c4a40a25117cdfee912dddad7e2432c0ac3200bb8cb9e2be90634aa5b53` |
| `ircx.us` | `onyx-server.service` active | `1245448` | `db4a9c4a40a25117cdfee912dddad7e2432c0ac3200bb8cb9e2be90634aa5b53` |

Both nodes used Helix re-exec and retained their Main PID. Eshmaki restored six
client connections and six sessions; ircx.us restored three client connections
and four sessions. Each preserved its mesh link and staged migrations.

## Live acceptance

- `EXPECT_VER=793d26d tools/era2_acceptance_smoke.sh`: pass.
- Both nodes: `links_active=1`, `peers_up=1`, `partitioned=0`, `tcp_active=1`.
- Guest mesh chat: registration/join and unique PRIVMSG delivery passed in both
  directions.
- Disposable-account MTOKEN lifecycle: issued on eshmaki, source disconnected,
  resumed on ircx.us, `SESSION LIST` returned, and both account records dropped.
- Installed and running `/proc/<pid>/exe` hashes match the verified artifact on
  both nodes; local post-upgrade logs contain no panic, fatal, segfault,
  assertion, upgrade refusal, or delivery-gap line.

## Client

- Visual/mobile release `20260814-182527-56dda2ce` introduced adaptive mobile
  backgrounds and unified workspace/context menus.
- Session-lifecycle release `20260814-190440-bc2599f4` prevents unrelated
  SESSION LIST/DROP failures from erasing bearers, separates MTOKEN expiry from
  the still-valid node-local TOKEN, and rotates token generations safely across
  account switch/logout.
- Final client gate: 513 files and 6,613 tests, plus typecheck, scoped lint, and
  production build. The live service-worker stamp and new runtime bytes were
  verified at `https://eshmaki.me/app/`.

## Rollback

- Eshmaki:
  `/home/kain/onyx-server-run/onyx-server.prev-8c0ec5d-20260814T175507Z`
- ircx:
  `/home/trev/onyx-server-run/onyx-server.prev-8c0ec5d-20260814T175507Z`
- Previous artifact SHA-256:
  `7f7674a9ac4dd3260cb713715be30d2e334aead3fe0d0ad18ba6d7bde37ea9b5`

Roll back one node at a time through Helix and verify running hash plus mesh
health before touching the second node.

## Explicit residual item

One pre-existing architectural issue was not changed by this release: a legacy
group TOKEN shared by multiple detached physical attachments does not encode an
attachment ID, so exact device/spool selection is ambiguous. The designed
follow-up uses opaque `srm2l`/`srm2m` credentials binding group token plus stable
attachment ID, legacy credentials as create-new-only, and safe mesh redirect
until signed SRM2/SRA3 spool transfer is wired. It remains unimplemented because
the user requested this final rollout and then a stop.
