# Onyx Server production paths

**Product name: Onyx Server.** There is no production service named after legacy codenames.

This is the canonical current-topology document. It was refreshed from the
running processes, `/proc/<pid>/exe`, executable hashes, and loopback metrics
on **2026-10-18**. eshmaki.me is Alpine and supervises the daemon with OpenRC.
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

## Verified fleet baseline (2026-10-18)

| Evidence | eshmaki.me | ircx.us |
|---|---|---|
| Service state | OpenRC `started` | systemd `active` |
| Running image | `0.8.0+2c3566e7d7f3-dirty` | `0.8.0+2c3566e7d7f3-dirty` |
| Executable SHA-256 | `b85ae4aa12e9995ba36348750fd551e8f7e391b087e726fb0de20c205342eb6d` | same |
| `tcp_active` | `1` | `1` |
| `links_active` / `peers_up` | `1 / 1` | `1 / 1` |
| `partitioned` | `0` | `0` |

The `-dirty` suffix is the uncommitted WHOIS profile work on top of `2c3566e7d7f3`.
`SIGUSR2` does not adopt a new inode. This roll was a full restart, eshmaki
first (`rc-service`), then ircx.us (`systemctl`). The previous image is
`onyx-server.prev-0.8.0-3da63872fc9f` in each run directory, SHA-256
`e05d95a4456c45e70e4f5745b98025e6e9fb511773ad468dd905681c33d82a3f`.
After both nodes were up, a guest on eshmaki.me ran `WHOIS trev` (homed on
ircx.us) and received 317, 330, 313, 671 with the cipher, and 320 modes.
Real host, certfp, and rDNS stayed off that non-operator reply. The full
`zig build test` suite was not re-run for this image.

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
