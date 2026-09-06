# Onyx Server production paths

**Product name: Onyx Server.** There is no production service named after legacy codenames.

This is the canonical current-topology document. It was refreshed from both
systemd units, `/proc/<pid>/exe`, executable hashes, and loopback metrics on
**2026-09-06**. Re-run the commands below after any deployment; release notes
preserve the exact historical inputs and are not substitutes for this table.

| | eshmaki.me | ircx.us |
|--|------------|---------|
| **systemd unit** | `onyx-server.service` | `onyx-server.service` |
| **Binary** | `/home/kain/onyx-server-run/onyx-server` | `/home/trev/onyx-server-run/onyx-server` |
| **Config** | `/home/kain/onyx-server-run/onyx-server.local.toml` | `/home/trev/onyx-server-run/onyx-server.local.toml` |
| **WorkingDirectory** | `/home/kain/onyx-server-run` | `/home/trev/onyx-server-run` |
| **Metrics** | `http://127.0.0.1:9130/metrics` | same (loopback) |
| **TLS IRC** | `:6697` | `:6697` |
| **WSS** | `:8080` | `:8080` |

## Verified fleet baseline (2026-09-06)

| Evidence | eshmaki.me | ircx.us |
|---|---|---|
| Service state | `active/running` (`onyx-server.service`) | `active/running` (`onyx-server.service`) |
| Running image | `0.7.0+ae78d490` | `0.7.0+ae78d490` |
| Executable SHA-256 | `0f110e833bc96bd6540ad7df0a620af869526cf8b4dbc3fd4650aa8ada8ddf1c` | same |
| `tcp_active` | `1` | `1` |
| `links_active` / `peers_up` | `1 / 1` | `1 / 1` |
| `partitioned` / `components` | `0 / 1` | `0 / 1` |

The last source-code change before this documentation reconciliation is
`ae78d490`, which is also the deployed image baseline. This checkout includes
documentation-only commits after that code. A new build from the current
checkout will identify itself with its current Git revision; that is not a claim
that the newly built image is installed on the fleet.

## Day-2 ops

```bash
# Status
systemctl status onyx-server

# Helix hot upgrade (after installing a new binary at the same path)
sudo systemctl reload onyx-server   # SIGUSR2 via ExecReload

# Config check without restart
/home/kain/onyx-server-run/onyx-server --check-config /home/kain/onyx-server-run/onyx-server.local.toml

# Peer config check (run over SSH)
ssh trev@ircx.us /home/trev/onyx-server-run/onyx-server --check-config /home/trev/onyx-server-run/onyx-server.local.toml

# Dual-node mesh
MESH_SSH_PEER=trev@ircx.us python3 tools/mesh_health_smoke.py http://127.0.0.1:9130/metrics

# Acceptance
tools/era2_acceptance_smoke.sh
```

## Timers (eshmaki)

- `onyx-server-backup.timer` — nightly vault-safe backup  
- `onyx-server-geoip.timer` — weekly GeoIP refresh  

## Client

- Live SPA root: `/home/kain/onyx/out` (nginx)  
- Deploy only via `/home/kain/onyx/deploy.sh` (builds to `dist/`, syncs to `out/`)  
