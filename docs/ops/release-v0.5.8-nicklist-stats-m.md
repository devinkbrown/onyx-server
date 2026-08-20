# Onyx Server 0.5.8 nicklist + STATS m deploy

Deployment date: 2026-08-20

## Scope

- JOIN auto-NAMES fail-closed on malformed mesh roster rows (empty-nicklist desync).
- `STATS m` / `212 RPL_STATSCOMMANDS` emits four discrete params:
  `<command> <count> <bytes> <remote>`.

## Immutable release inputs

| Item | Value |
|---|---|
| Production commit | `ea249b2` |
| Branch | `cursor/nicklist-desync-join-names-6bd0` |
| Version banner | `Onyx Server 0.5.8+ea249b2` |
| Artifact | `onyx-server-0.5.8-x86_64-linux-musl` |
| Artifact SHA-256 | `d8b7e5139e03cbd2d4abff98fafabfb9a9259d838b9c72d8b364c174fd6b9208` |

## Live node inventory and rollback

| | `ircx.us` (first) | `eshmaki.me` (second) |
|---|---|---|
| Unit | `onyx-server.service` | `onyx-server.service` |
| Binary | `/home/trev/onyx-server-run/onyx-server` | `/home/kain/onyx-server-run/onyx-server` |
| Config | `/home/trev/onyx-server-run/onyx-server.local.toml` | `/home/kain/onyx-server-run/onyx-server.local.toml` |
| Previous | `0.5.8+9c6d5d8` | `0.5.8+9c6d5d8` |
| Binary rollback | `onyx-server.prev-9c6d5d8-pre-ea249b2` | `onyx-server.prev-9c6d5d8-pre-ea249b2` |
| Activation | Helix `systemctl reload` (MainPID preserved) | Helix `systemctl reload` (MainPID preserved) |

Config unchanged; both nodes passed `--check-config` on the staged `ea249b2` binary.

## Post-deploy checks

- Both units `active (running)` on `0.5.8+ea249b2`
- Mesh: `MESH_SSH_PEER=trev@ircx.us python3 tools/mesh_health_smoke.py http://127.0.0.1:9130/metrics`
  → both sides `links_active=1 peers_up=1 partitioned=0 tcp_active=1`
- Guest mesh chat smoke: registration/JOIN + A↔B PRIVMSG PASS
