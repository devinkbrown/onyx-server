# Onyx Server production paths

**Product name: Onyx Server.** There is no production service named after legacy codenames.

This is the canonical current-topology document. It was refreshed from the
running processes, `/proc/<pid>/exe`, executable hashes, and loopback metrics
on **2026-10-17**. eshmaki.me is Alpine and supervises the daemon with OpenRC.
ircx.us supervises it with systemd. Re-run the commands below after any
deployment; release notes preserve the exact historical inputs and are not
substitutes for this table.

| | eshmaki.me | ircx.us |
|--|------------|---------|
| **Service** | OpenRC `/etc/init.d/onyx-server` | systemd `onyx-server.service` |
| **Binary** | `/home/kain/onyx-server-run/onyx-server` | `/home/trev/onyx-server-run/onyx-server` |
| **Config** | `/home/kain/onyx-server-run/onyx-server.local.toml` | `/home/trev/onyx-server-run/onyx-server.local.toml` |
| **WorkingDirectory** | `/home/kain/onyx-server-run` | `/home/trev/onyx-server-run` |
| **Metrics** | `http://127.0.0.1:9130/metrics` | same (loopback) |
| **TLS IRC** | `:6697` | `:6697` |
| **WSS** | `:8080` | `:8080` |

## Verified fleet baseline (2026-10-17)

| Evidence | eshmaki.me | ircx.us |
|---|---|---|
| Service state | OpenRC `started` | systemd `active` |
| Running image | `0.8.0+unknown` | `0.8.0+unknown` |
| Executable SHA-256 | `d405c2697db35a8e9a2fd1e5bf10e5af1b422cf0a2baf946351a5ee63baec944` | same |
| `tcp_active` | `1` | `1` |
| `links_active` / `peers_up` | `1 / 1` | `1 / 1` |
| `partitioned` | `0` | `0` |

`SIGUSR2` did not adopt this image on either node: both processes kept the
previous inode. The roll was a full restart, eshmaki first, then ircx.us.
Rollback binaries are `onyx-server.prev-0.7.0-ae78d490` in each run directory,
SHA-256 `0f110e833bc96bd6540ad7df0a620af869526cf8b4dbc3fd4650aa8ada8ddf1c`.
The banner says `unknown` because the qemu build runner could not run git.
The full `zig build test` suite was not re-run for this image.

## Day-2 ops

```bash
# Status
rc-service onyx-server status          # eshmaki, OpenRC
systemctl status onyx-server           # ircx.us, systemd

# Full restart. On 2026-10-17, SIGUSR2 left the old inode running.
sudo rc-service onyx-server restart    # eshmaki
sudo systemctl restart onyx-server     # ircx.us

# Config check without restart
/home/kain/onyx-server-run/onyx-server --check-config /home/kain/onyx-server-run/onyx-server.local.toml

# Restore drill. Reads latest.json, checks included and excluded families,
# reopens the account snapshot as <scratch-dir>/restored.wal, then exits.
# It does not boot, bind, or send mail. <backup-dir> is a [backup] dir.
onyx-server --restore-drill <backup-dir> --into <scratch-dir>

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
