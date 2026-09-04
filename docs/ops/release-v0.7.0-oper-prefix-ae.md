# Onyx Server 0.7.0 — oper prefix AE / grant→nick fix

Deployment date: 2026-09-04

## Scope

Follow-up to `964e0857` remote-oper display. Stops 30s synthetic
`MODE +Y` spam from anti-entropy remints, and wires signed-peer roster
accounts so remote `*` / grant→nick resolve without residence-only
blanking. Collision short-circuits stay F1-safe via `account_trusted`.

No config changes. Units are `onyx-server.service`.

## Immutable release inputs

| Item | Value |
|---|---|
| Production commit | `ae78d490bdea39484d7170b7c434b78787021876` |
| Branch | `main` |
| Version banner | `Onyx Server 0.7.0+ae78d490` |
| Artifact | `dist/onyx-server-0.7.0-x86_64-linux-musl` |
| Artifact SHA-256 | `0f110e833bc96bd6540ad7df0a620af869526cf8b4dbc3fd4650aa8ada8ddf1c` |

`packaging/release.sh` at that commit. Unsigned (no `COSIGN_KEY`).

## Live node inventory and rollback

| | `ircx.us` (first) | `eshmaki.me` (second) |
|---|---|---|
| Unit | `onyx-server.service` | `onyx-server.service` |
| Previous banner | `0.7.0+964e0857` | `0.7.0+964e0857` |
| Previous SHA-256 | `003c3968341055bb14f6df31dfe1eb05991e265e6c8c5c01e38ac4691b40dd73` | same |
| Binary rollback | `onyx-server.predeploy-ae78d490` | `onyx-server.predeploy-ae78d490` |
| Main PID | `3476022` (unchanged) | `3979560` (unchanged) |
| Activation | Helix `systemctl reload` | Helix `systemctl reload` |

Both live TOMLs printed `config OK` under the staged `0.7.0+ae78d490`
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

- `EXPECT_VER=ae78d490 PEER_SSH=trev@ircx.us tools/era2_acceptance_smoke.sh`: **PASS**
- Mesh: both sides `links_active=1 peers_up=1 partitioned=0 tcp_active=1`
- Guest mesh chat: register/JOIN `#root` and A↔B PRIVMSG **ALL CHECKS PASSED**
