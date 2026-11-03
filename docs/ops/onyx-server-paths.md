# Onyx Server production paths

**Product name: Onyx Server.** There is no production service named after legacy codenames.

This is the canonical current-topology document. It was refreshed from the
running processes, `/proc/<pid>/exe`, executable hashes, and loopback metrics
on **2026-11-03**. (Earlier rolls are recorded separately below.) eshmaki.me is Alpine and supervises the daemon with OpenRC.
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

## Verified fleet baseline (2026-11-03)

| Evidence | eshmaki.me | ircx.us |
|---|---|---|
| Service state | OpenRC `started` | systemd `active` |
| Running image | `0.9.0+c730d9f37b01` | `0.9.0+c730d9f37b01` |
| Executable SHA-256 | `5735c08b3f537ee27b4d0c22ac7a80e96a6efc5b5122ba666f3d8e6ca3be5e61` | same |
| Process ID at acceptance | `34450` (supervisor `34449`) | `2818026` |
| `tcp_active` | `1` | `1` |
| `links_active` / `peers_up` | `1 / 1` | `1 / 1` |
| `partitioned` | `0` | `0` |

The artifact is built from clean source `c730d9f37b017a3e4c0a400c19cfa482a5198562`
and reproduces byte-for-byte. Service kits include the correction in `6131c4de`.
Local OpenRC now uses `supervise-daemon`; peer systemd uses the canonical sandbox
with an explicit host-path/account override. Both hosts preserve `UMask=0022`
for their public status/backup feeds; packaged defaults remain private.

Both cold restarts recovered durable account tokens issued before deployment.
Four TLS clients then passed channel/DM exact-event checks, matching message IDs
and timestamps, local exact attachment resume, and peer redirect followed by
origin resume. This does not establish arbitrary-node exact attachment restore
or continuity of old composite tokens across cold restart. Helix remains blocked
by WebTransport. See the [release and testing audit](../audit/release-and-test-speed-2026-11-03.md).

The peer's first candidate start disabled TLS: systemd's separate
`RestrictSUIDSGID` filter rejected `openat2` with `ENOSYS`. The peer was restored
before diagnosis. An isolated A/B probe and all seven native service checks
verified the corrected unit before retry. Its remaining sandbox is retained;
see [service management](../guide/service-management.md).

### Previous roll (2026-11-02, historical)

This roll (2026-11-02, source `a11610c2`: all 90 local branches merged into
main, full gate 11,112 pass / 312 skip / 0 fail) deployed cold restarts, local
first; Helix remains blocked by the WebTransport listener. It also added the
now-mandatory `[mesh] presence_store_path = "<runtime>/guest-presence.wal"`
to both live configs (the merged guest-authority stack fails closed without
it). Live acceptance: mesh health smoke green both ways and cross-node chat
smoke passed both directions. Note: local OpenRC reports `starting` (state
left by the first crashed start before the config fix) while the daemon,
pidfile, metrics and mesh are all healthy. Rollback for this roll:
`rollback-0.9.0-20261102T183408Z` in each node's runtime directory (previous
image `0.9.0+066d9b8356be-dirty`, SHA-256
`61d218f6682857eed5f3d4bb4007c2d99869fc723810f0df637961a417e5fe02`).

### Previous roll (2026-10-23, historical)

The accepted source was `2a7bbcb71348e2b61152bb8bfafb5ffbf425b8a6`. This roll
used authorized cold restarts, local first. The predecessor's Helix capability
probe attempted to open `/dev/null` read/write, which its inherited Landlock
policy denied. The new image uses an immediately closed stdin pipe and a bounded
probe deadline. Both staged binaries passed `--check-config` before rollout.

The local config now enables persistent stderr logging; the remote config is
unchanged and retains journald. Rollback directories contain the previous
`onyx-server` and `onyx-server.local.toml`:

- eshmaki: `/home/kain/onyx-server-run/rollback-2a7bbcb7-20261023T181147Z`.
- ircx: `/home/trev/onyx-server-run/rollback-2a7bbcb7-20261023T181147Z`.

Both previous images are `0.8.1+48891b338921`, SHA-256
`258dadd825a05b5039fffa35306b781f463d7f1c69dcbf632a249fd5bb08737f`.

Live acceptance passed protected-nickname rejection followed by fallback NICK
and account registration on the same TLS socket, persisted-account login,
fresh-token reconnect, and bidirectional cross-node TLS chat. Cold restart drops
physical attachments; these checks do not establish recovery of old exact
attachment tokens across that boundary.

**Production Helix remains blocked by the configured WebTransport listener.**
Both nodes have `[listen].webtransport = 4433`; the existing Linux continuity
guard refuses handoff of this process-owned state. Local USR2 was refused before
exec with `SessionReplicaConverging`; this generic error did not indicate a mesh
partition. The PID and original TLS sockets stayed live. Stable tokens, channel
membership, 14 reciprocal delivery rounds, and authenticated reconnect/resume
passed after refusal. The remote node was not signaled. No successful production
exec/adoption is claimed. Disabling this listener also requires a cold restart;
there is no verified zero-drop operational workaround for this topology.

The final full ReleaseSafe suite passed 10,181 tests with 322 skips and zero
failures/leaks/log errors. Affected Debug gates passed 3,253 tests with 106 skips;
the final full Debug suite is not claimed complete. The release reproduced
byte-for-byte. Isolated plain/TLS/WSS and active-kTLS Helix rehearsals passed,
without WebTransport configured. Details and remaining cleanup limitations:
[nickname, logging, and Helix audit](../audit/nickname-logging-helix-2026-10-23.md).

## Day-2 ops

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
