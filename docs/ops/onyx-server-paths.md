# Onyx Server production paths

**Product name: Onyx Server.** There is no production service named after legacy codenames.

This is the canonical current-topology document. It was refreshed from the
running processes, `/proc/<pid>/exe`, executable hashes, and loopback metrics
on **2026-10-23**. eshmaki.me is Alpine and supervises the daemon with OpenRC.
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

## Verified fleet baseline (2026-10-23)

| Evidence | eshmaki.me | ircx.us |
|---|---|---|
| Service state | OpenRC `started` | systemd `active` |
| Running image | `0.8.1+48891b338921` | `0.8.1+48891b338921` |
| Executable SHA-256 | `258dadd825a05b5039fffa35306b781f463d7f1c69dcbf632a249fd5bb08737f` | same |
| Process ID at acceptance | `4523` | `2144191` |
| `tcp_active` | `1` | `1` |
| `links_active` / `peers_up` | `1 / 1` | `1 / 1` |
| `partitioned` | `0` | `0` |

This roll used authorized cold restarts, local first, because S2S checkpoint
schema v5 adds mandatory authenticated partial-frame carry. The image probe
refuses pre-v5 hot handoffs before exec. Local OpenRC state was reconciled with
the existing process before starting the replacement; it now reports `started`.
ircx.us reports `active` and started at 2026-10-23 08:08:24 UTC.

Rollback binaries remain in each runtime directory:

- eshmaki: `onyx-server.prev-20261023-569a8c28`, SHA-256
  `569a8c286907c098505550ec9e739fb4e5b5ec80d782aae834a966cba38167a9`.
- ircx: `onyx-server.prev-20261023-4aad53f3`, SHA-256
  `4aad53f36ad5f816e6cf2512597509df636dec2e4c1200791b832d30dd483af0`.

Both staged binaries passed `--check-config`. Configs remain byte-identical to
their `onyx-server.local.toml.prev-48891b33` backups; relay authoring stays
active at epoch 1 with the same two-node roster digest. Both nodes report
`links_active=1`, `peers_up=1`, and `partitioned=0`. Cross-node TLS chat passed
in both directions. Persisted-account login and fresh exact-token reconnect
passed. Old exact-attachment tokens did **not** survive the cold boundary;
users need to log in again. This is not evidence of live Helix continuity.

Full Debug and ReleaseSafe each passed 10,169 tests with 322 skips and zero
failures/leaks. The release rebuilt byte-identically from a clean cache.
Details: [mesh record recovery audit](../audit/mesh-record-carry-2026-10-23.md).

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
