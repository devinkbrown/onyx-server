# Onyx Server 0.7.0 — remote oper display

Deployment date: 2026-09-04

## Scope

Display-only remote oper projection from live signed mesh grants
(`964e0857`). WHOIS 313 / NAMES `*` / `MODE +Y` follow a grant for a
remote account. Local privilege (KICK, DATA, `isOverrideOper`) stays
configured-local.

No config changes. Units are `onyx-server.service`.

## Immutable release inputs

| Item | Value |
|---|---|
| Production commit | `964e0857c5d7eeece1e4aa5afea854c1779e2099` |
| Branch | `main` |
| Version banner | `Onyx Server 0.7.0+964e0857` |
| Artifact | `dist/onyx-server-0.7.0-x86_64-linux-musl` |
| Artifact SHA-256 | `003c3968341055bb14f6df31dfe1eb05991e265e6c8c5c01e38ac4691b40dd73` |

`packaging/release.sh` at that commit. Unsigned (no `COSIGN_KEY`).

## Live node inventory and rollback

| | `ircx.us` (first) | `eshmaki.me` (second) |
|---|---|---|
| Unit | `onyx-server.service` | `onyx-server.service` |
| Previous banner | `0.7.0+e4bb3a01` | `0.7.0+e4bb3a01` |
| Previous SHA-256 | `46d025f9d66f06655d672a4e0b92ef64dcd147badb8d430c6f9c44e0ac575d3e` | same |
| Binary rollback | `onyx-server.predeploy-964e0857` | `onyx-server.predeploy-964e0857` |
| Main PID | `3476022` (unchanged) | `3979560` (unchanged) |
| Activation | Helix `systemctl reload` | Helix `systemctl reload` |

Both live TOMLs printed `config OK` under the staged `0.7.0+964e0857`
binary before install. Running `/proc/<pid>/exe` hashes match the
artifact on both nodes after reload.

## Helix resume

- `ircx.us`: 31 capsules; primed 2 oper grants; re-attached 3 TLS
  clients and 3 sessions; 1 mesh link preserved
  (`mesh S2S established (helix-resume) peer=eshmaki.me`).
- `eshmaki.me`: 36 capsules; 4-shard seal; primed 2 oper grants;
  re-attached 5 clients (3 TLS) and 1 session; 1 mesh link preserved
  (`mesh S2S established (helix-resume) peer=ircx.us`).
- No panic, fatal, segfault, assertion, `UPGRADE failed`, or
  `HandshakeTooLarge` in the post-reload window.

## Post-deploy checks

- `EXPECT_VER=964e0857 PEER_SSH=trev@ircx.us tools/era2_acceptance_smoke.sh`: **PASS**
- Mesh: both sides `links_active=1 peers_up=1 partitioned=0 tcp_active=1`
- Guest mesh chat: register/JOIN `#root` and A↔B PRIVMSG **ALL CHECKS PASSED**
