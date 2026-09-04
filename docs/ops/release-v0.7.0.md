# Onyx Server 0.7.0 dual-node Helix deploy

Deployment date: 2026-09-04

## Scope

- Promote live fleet from `0.5.8+b2dfb55` to `0.7.0+e4bb3a01`.
- Helix capability bridge (frozen 0.5.8 `predecessor_v4` including `sessions-v4`).
- Ownership-safe `[io] defer_taskrun` / `sqpoll` projection; Armor TLS hardening;
  exploit-corpus classification; live bench + staged USR2 rehearsal already on
  `main`.

No config changes. No GitHub Release tag. Units are `onyx-server.service`
(not `orochi.service`).

## Immutable release inputs

| Item | Value |
|---|---|
| Production commit | `e4bb3a01bd548ce9fe2cd3e50b166363459f7748` |
| Branch | `main` |
| Version banner | `Onyx Server 0.7.0+e4bb3a01` |
| Artifact | `dist/onyx-server-0.7.0-x86_64-linux-musl` |
| Artifact SHA-256 | `46d025f9d66f06655d672a4e0b92ef64dcd147badb8d430c6f9c44e0ac575d3e` |

`packaging/release.sh` at that commit. Unsigned (no `COSIGN_KEY`).

## Live node inventory and rollback

| | `ircx.us` (first) | `eshmaki.me` (second) |
|---|---|---|
| Unit | `onyx-server.service` | `onyx-server.service` |
| SSH | `trev@ircx.us` (`~/.ssh/id_ed25519`) | local |
| Binary | `/home/trev/onyx-server-run/onyx-server` | `/home/kain/onyx-server-run/onyx-server` |
| Config | `/home/trev/onyx-server-run/onyx-server.local.toml` | `/home/kain/onyx-server-run/onyx-server.local.toml` |
| Previous banner | `0.5.8+b2dfb55` | `0.5.8+b2dfb55` |
| Previous SHA-256 | `4ff5418cb11eac0b0b489681d18835f6218203a2bd854d7012b3fc5c510e9080` | `bc290559905d3bc0e6b0bdf86567ed9807169ebbf002c666908bfa0078d86795` |
| Binary rollback | `onyx-server.predeploy-e4bb3a01` | `onyx-server.predeploy-e4bb3a01` |
| Main PID | `3366089` (unchanged) | `930587` (unchanged) |
| Activation | Helix `systemctl reload` | Helix `systemctl reload` |

Both live TOMLs printed `config OK` under the staged `0.7.0+e4bb3a01` binary
before install. Running `/proc/<pid>/exe` hashes match the artifact on both
nodes after reload.

## Helix resume

- `ircx.us`: 31 capsules; re-attached 3 TLS clients and 3 sessions; 1 mesh link
  preserved (`mesh S2S established (helix-resume) peer=eshmaki.me`).
- `eshmaki.me`: 36 capsules; 4-shard seal; re-attached 5 clients (3 TLS) and 1
  session; 1 mesh link preserved (`mesh S2S established (helix-resume) peer=ircx.us`).
- No panic, fatal, segfault, assertion, `UPGRADE failed`, or `HandshakeTooLarge`
  in the post-reload window.

## Post-deploy checks

- `EXPECT_VER=e4bb3a01 PEER_SSH=trev@ircx.us tools/era2_acceptance_smoke.sh`: **PASS**
- Mesh: `MESH_SSH_PEER=trev@ircx.us python3 tools/mesh_health_smoke.py http://127.0.0.1:9130/metrics`
  → both sides `links_active=1 peers_up=1 partitioned=0 tcp_active=1`
- Guest mesh chat: `MESH_SMOKE_B=ircx.us:6697 MESH_SMOKE_INSECURE_TLS=1 python3 tools/mesh_chat_smoke.py`
  → register/JOIN `#root` and A↔B PRIVMSG **ALL CHECKS PASSED**
