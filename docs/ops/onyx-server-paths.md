# Onyx Server production paths

**Product name: Onyx Server.** There is no production service named after legacy codenames.

| | eshmaki.me | ircx.us |
|--|------------|---------|
| **systemd unit** | `onyx-server.service` | `onyx-server.service` |
| **Binary** | `/home/kain/onyx-server-run/onyx-server` | `/home/trev/onyx-server-run/onyx-server` |
| **Config** | `/home/kain/onyx-server-run/onyx-server.local.toml` | `/home/trev/onyx-server-run/onyx-server.local.toml` |
| **WorkingDirectory** | `/home/kain/onyx-server-run` | `/home/trev/onyx-server-run` |
| **Metrics** | `http://127.0.0.1:9130/metrics` | same (loopback) |
| **TLS IRC** | `:6697` | `:6697` |
| **WSS** | `:8080` | `:8080` |

## Day-2 ops

```bash
# Status
systemctl status onyx-server

# Helix hot upgrade (after installing a new binary at the same path)
sudo systemctl reload onyx-server   # SIGUSR2 via ExecReload

# Config check without restart
/home/kain/onyx-server-run/onyx-server --check-config /home/kain/onyx-server-run/onyx-server.local.toml

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
