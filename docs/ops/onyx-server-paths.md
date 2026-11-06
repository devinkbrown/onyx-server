# Onyx Server production paths

**Product name: Onyx Server.** There is no production service named after legacy codenames.

This is the canonical current-topology document. It was refreshed from the
running processes, `/proc/<pid>/exe`, executable hashes, and loopback metrics
on **2026-11-06**. eshmaki.me is Alpine and supervises the daemon with OpenRC.
ircx.us supervises it with systemd. Re-run the commands below after any
deployment; release notes preserve the exact historical inputs and are not
substitutes for this table.

| | eshmaki.me | ircx.us |
|--|------------|---------|
| **Service** | OpenRC `/etc/init.d/onyx-server` | systemd `onyx-server.service` |
| **Binary** | `/home/kain/onyx-server-run/onyx-server` | `/home/trev/onyx-server-run/onyx-server` |
| **Config** | `/home/kain/onyx-server-run/onyx-server.local.toml` | `/home/trev/onyx-server-run/onyx-server.local.toml` |
| **WorkingDirectory** | `/home/kain/onyx-server-run/service-state` (`0700`) | `/home/trev/onyx-server-run` |
| **Metrics** | `http://127.0.0.1:9130/metrics` | same (loopback) |
| **TLS IRC** | `:6697` | `:6697` |
| **WSS** | `:8080` | `:8080` |
| **WebTransport** | UDP `:4433` | UDP `:4433` |
| **Operational log** | `/home/kain/onyx-server-run/onyx-server.log` (`0600`) | journal for `onyx-server.service` |

## Verified fleet baseline (2026-11-06)

| Evidence | eshmaki.me | ircx.us |
|---|---|---|
| Service state | OpenRC `started` | systemd `active` |
| Running image | `0.10.1+0200fe471693` | `0.10.1+0200fe471693` |
| Executable SHA-256 | `d9fb312e191da46b203337b6ab9cbd1e80b082a9172ff33198f56da27d2592fa` | same |
| Process ID at acceptance | `8616` | `2967193` |
| `tcp_active` | `1` | `1` |
| `links_active` / `peers_up` | `1 / 1` | `1 / 1` |
| `partitioned` | `0` | `0` |

0.10.1 (`0200fe47`) followed the same procedure the same day. It renames the
Koshi content filter keys to `[filter] max_patterns` / `max_pattern_len` and
refuses the retired names. Both live configs were updated with it. The same
rollout renamed the silently ignored `[mesh.sazanami]` and `[bouncer] tegami_*`
sections to `[mesh.ripple]` and `memo_*`, and enabled `[trace] file`,
`[limits] nick_delay = "60s"` and consent-gated `[media]` recording. Pre-change
configs are kept as `onyx-server.local.toml.bak-0.10.0-20261106` and
`.bak-0.10.0-koshi`, and the 0.10.0 binary as `onyx-server.0.10.0-ef223080`.
Both nodes passed `--check-config`, the mesh health smoke and the cross-node
chat smoke after their cold restarts.

The artifact is built from clean source `ef223080` (static ReleaseFast
x86_64-linux-musl) and `packaging/verify-release.sh` rebuilt it byte-for-byte.
Both nodes passed `--check-config` with the new binary before a cold restart,
one node at a time (eshmaki.me first). Each restart re-established
`mesh S2S established (secured)`, and a CA-verified cross-node chat smoke
(`tools/mesh_chat_smoke.py`, guest, `#root`) delivered PRIVMSG in both directions.
The previous `0.9.0+5bdd9dc55d99` binary is kept beside each live binary as
`onyx-server.0.9.0-5bdd9dc5` for rollback. A live client reconnected after the
restart; token resume was not exercised by a dedicated fixture for this rollout.
Helix remains blocked by WebTransport.

The 2026-11-03 `0.9.0` acceptance (durable token recovery across cold restart,
four-client exact-event checks) is in the
[release and testing audit](../audit/release-and-test-speed-2026-11-03.md).

The original `c730d9f3` rollout's first peer candidate start disabled TLS: systemd's separate
`RestrictSUIDSGID` filter rejected `openat2` with `ENOSYS`. The peer was restored
before diagnosis. An isolated A/B probe and all seven native service checks
verified the corrected unit before retry. Its remaining sandbox is retained;
see [service management](../guide/service-management.md).

## Refresh and day-2 operations

The baseline above is a dated acceptance snapshot. PIDs are observational,
not stable service identifiers. Before operating a node, resolve its current
service child identity and inspect `/proc/<pid>/exe`, process start time,
working directory, supervisor and executable SHA-256. Recheck identity before
signaling or replacing a path; a stale PID file or a matching process name
alone does not prove ownership. Confirm the on-disk candidate and running
executable separately, because atomic replacement can leave an older image
running. Keep config contents, environment values and keys private.

The commands below are operator actions; the restart examples require the
[release runbook](../RUNBOOK.md) custody, rollback and recovery preconditions.
Do not run both restarts together.

```bash
# Status
rc-service onyx-server status          # eshmaki, OpenRC
systemctl status onyx-server           # ircx.us, systemd

# Current WebTransport-enabled topology requires cold restart; TCP clients drop.
sudo rc-service onyx-server restart    # eshmaki
sudo systemctl restart onyx-server     # ircx.us

# Config check without restart; run as the daemon user (kain locally).
/home/kain/onyx-server-run/onyx-server --check-config /home/kain/onyx-server-run/onyx-server.local.toml

# Restore drill. Reads latest.json, checks included and excluded families,
# reopens the account snapshot as <scratch-dir>/restored.wal, then exits.
# It does not boot, bind, or send mail. <backup-dir> is a [backup] dir.
onyx-server --restore-drill <backup-dir> --into <scratch-dir>

# Peer config check (run over SSH)
ssh trev@ircx.us /home/trev/onyx-server-run/onyx-server --check-config /home/trev/onyx-server-run/onyx-server.local.toml

# Dual-node mesh
MESH_SSH_PEER=trev@ircx.us python3 tools/mesh_health_smoke.py http://127.0.0.1:9130/metrics

# Logs
tail -n 100 /home/kain/onyx-server-run/onyx-server.log
ssh trev@ircx.us 'sudo -n journalctl -u onyx-server.service --since "30 minutes ago" --no-pager'

# Acceptance
tools/era2_acceptance_smoke.sh
```

## Log retention (eshmaki)

OpenRC `onyx-logrotate` is started and enabled in the default runlevel. It checks
only the Onyx log every 300 seconds, rotates daily or when it reaches 32 MiB,
and keeps seven archives with compression. Its config is
`/etc/logrotate.d/onyx-server`; the loop is
`/usr/local/sbin/onyx-logrotate-loop`. `copytruncate` preserves the daemon's open
descriptor, though concurrent writes in its copy/truncate window can be lost.
Connection diagnostics are also rate-limited; this is an operational log, not
a lossless message or security audit trail.

The local OpenRC service's future startup output is routed by
`/etc/conf.d/onyx-server`. Runtime stderr uses `[logging].stderr_file`; remote
stderr continues to the persistent systemd journal.

## Client

- Live SPA root: `/home/kain/onyx/out` (nginx)  
- Deploy only via `/home/kain/onyx/deploy.sh` (builds to `dist/`, syncs to `out/`)  

Source of truth for the 2026-11-06 baseline: accepted daemon source `ef223080`,
service kit `6131c4de`, and the reproducible release manifest built from that commit.
The 2026-11-03 `0.9.0` acceptance is recorded by the [release audit](../audit/release-and-test-speed-2026-11-03.md).
Superseded deployment records are available in Git history; the table above
is the accepted fleet baseline.
