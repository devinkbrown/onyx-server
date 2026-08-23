# Onyx Server 0.5.8 EXTERNAL canonical-session deploy

Deployment date: 2026-08-20

Tokenless SASL EXTERNAL no longer disconnects with `WARN SESSION AMBIGUOUS_SESSION`
when multiple account+nick tokens exist. Selection uses a mesh-wide total order so
any number of peers converge on one logical session.

## Immutable release inputs

| Item | Value |
|---|---|
| Production commit | `9c6d5d8` (local `main` = live `330d732` + this fix) |
| GitHub merge | PR [#3](https://github.com/devinkbrown/onyx-server/pull/3) → `160380e` (cherry-pick onto public `main`) |
| Version banner | `Onyx Server 0.5.8+9c6d5d8` |
| Artifact | `onyx-server-0.5.8-x86_64-linux-musl` |
| Artifact SHA-256 | `17d8b2c4076b4802efcf63195bd52d7fb841de338a02e6a97ee3097ead8a3745` |

## Live node inventory and rollback

| | `ircx.us` (first) | `eshmaki.me` (second) |
|---|---|---|
| Unit | `onyx-server.service` | `onyx-server.service` |
| Binary | `/home/trev/onyx-server-run/onyx-server` | `/home/kain/onyx-server-run/onyx-server` |
| Config | `/home/trev/onyx-server-run/onyx-server.local.toml` | `/home/kain/onyx-server-run/onyx-server.local.toml` |
| Previous banner | `0.5.8+330d732` | `0.5.8+330d732` |
| Binary rollback | `onyx-server.prev-330d732-pre-9c6d5d8` | `onyx-server.prev-330d732-pre-9c6d5d8` |
| Activation | cold `systemctl restart` | cold `systemctl restart` |

Helix `systemctl reload` was attempted on `ircx.us` first; upgrade refused with
`SessionReplicaConverging` / incomplete client seal, so both nodes used hard restart.
Config was unchanged and passed `--check-config` on the staged `9c6d5d8` binary.

## Post-deploy checks

- Both units `active (running)` on `0.5.8+9c6d5d8`
- Mesh: `MESH_SSH_PEER=trev@ircx.us python3 tools/mesh_health_smoke.py http://127.0.0.1:9130/metrics`
  → both sides `links_active=1 peers_up=1 partitioned=0 tcp_active=1`
- Journal: secured S2S established peer-to-peer after each restart

## Client acceptance

Reconnect WeeChat EXTERNAL profiles (`ircx` / `ircx.us`) with the shared client
certificate. A second concurrent login should attach (or mint once, then join) without
`AMBIGUOUS_SESSION` or an immediate TLS tear-down.
