# Onyx Server production paths

**Product name: Onyx Server.** There is no production service named after legacy codenames.

This is the canonical current-topology document. It was refreshed from the
running processes, `/proc/<pid>/exe`, executable hashes, and loopback metrics
on **2026-11-07**. eshmaki.me is Alpine and supervises the daemon with OpenRC.
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

## Verified fleet baseline (2026-11-13, 0.11.4)

| Evidence | eshmaki.me | ircx.us |
|---|---|---|
| Running image | `0.11.4+5c6650b9d135` | `0.11.4+5c6650b9d135` |
| Executable SHA-256 | `3cdd8e1fa80859579f894860ba3ec61045e8643ff8d6988323c96fd05ce685cf` | same |
| Restart | cold (OpenRC), PID 8796, presence epoch 14 | Helix, PID 2980332 kept |
| `links_active` / `peers_up` / `partitioned` | `1 / 1 / 0` | `1 / 1 / 0` |

0.11.4 is a hotfix for `ktls = "txrx"`: a provided-buffer multishot recv armed
across the TLS 1.3 Finished boundary pre-consumed the client's first
application record before `TLS_RX` attached, so every client that wrote right
after the handshake (WeeChat, `openssl s_client`) died with EBADMSG
(`tls_record_failure`). Kernel-RX-capable TLS conns now stay on single-shot
recv until the attach. Built with `packaging/release.sh` (Zig 0.17.0,
`7c61539a…`). Acceptance: immediate-send TLS 1.3 registration 3/3 and TLS 1.2
on both nodes, mesh health smoke OK. ircx.us went first by Helix. eshmaki.me
refused Helix with `ACME renewal companion has no exact Helix checkpoint`
(in-daemon `[acme]` was enabled there on 2026-11-13 and blocks every Linux
Helix while enabled), so it was cold-restarted. Rollback binaries:
`onyx-server.0.11.3-877fe313` on both nodes.

## Previous baseline (2026-11-07, 0.11.3)

| Evidence | eshmaki.me | ircx.us |
|---|---|---|
| Service state | OpenRC `started` | systemd `active` |
| Running image | `0.11.3+44574d95513b` | `0.11.3+44574d95513b` |
| Executable SHA-256 | `877fe313b470416b27031680846ba4af70039fb796bb31503dda70251aa57e02` | same |
| Process ID at acceptance | `27078` | `2980332` |
| `links_active` / `peers_up` / `partitioned` | `1 / 1 / 0` | `1 / 1 / 0` |
| `[geo] news_insecure_tls` | `false` | `false` |

0.11.1, 0.11.2 and 0.11.3 each went live on both nodes by Helix reload alone
(ircx.us first), with held TLS 1.3 and TLS 1.2 probes surviving every swap and
both PIDs kept. Each release rebuilt byte-for-byte. 0.11.3 was deployed on the
operator's request after the focused registration tests; the full suite last
passed on `08c155a8` (12,159 passed) before the 0.11.2/0.11.3 registration
changes. Acceptance after 0.11.3: mesh health and cross-node TLS chat pass; a
second `guest` gets `433` and keeps its connection; a `guest` reconnecting
inside the nick-delay window gets `437` and is renamed to `guest-xxxx`; the
Onyx web client stays connected; `onyx_guest_presence_unpublished_no_id` and
`onyx_helix_continuity_remote_visible_blocked` read 0 on both nodes. Config
backups from the news flip: `onyx-server.local.toml.bak-pre-news-verify-20261107`
on both nodes.

## Previous baseline (2026-11-07, 0.11.0)

| Evidence | eshmaki.me | ircx.us |
|---|---|---|
| Service state | OpenRC `started` | systemd `active` |
| Running image | `0.11.0+130b02bbebe7` | `0.11.0+130b02bbebe7` |
| Executable SHA-256 | `3431379f28a7b8618a4563a03baec6eab538403e098685600e77ef2f1d6ebe0e` | same |
| Process ID at acceptance | `21843` | `2980332` |
| `tcp_active` | `1` | `1` |
| `links_active` / `peers_up` | `1 / 1` | `1 / 1` |
| `partitioned` | `0` | `0` |

0.11.0 (`130b02bb`, Armor hardening) was built from a clean worktree and
`packaging/verify-release.sh` rebuilt it byte-for-byte. Both live configs
passed `--check-config` with the new binary before the swap.

- **ircx.us:** Helix reload from 0.10.4. PID 2980332 and issuer epoch 12 were
  kept; 4 TLS clients re-attached (held TLS 1.3 and TLS 1.2 probes answered
  PING afterwards) and the mesh link resumed (`helix-resume`).
- **eshmaki.me:** the 0.10.4 predecessor refused Helix four times over about
  ten minutes with "remote visible identity and physical notification
  frontiers has live process-owned state with no exact Helix checkpoint"
  (`scanUpgradeContinuityBlockersLocked`: a local QUIT capture, pending remote
  host records/departures, or uncheckpointed attachment-delivery output that
  did not drain). Every refusal was before exec and kept all connections. It
  was then cold-restarted onto 0.11.0 through OpenRC (3 client connections
  dropped; presence authority opened cold at epoch 12). A same-image Helix
  reload on 0.11.0 afterwards kept PID 21843 and epoch 12 and re-attached
  3 TLS + 1 WSS clients, with held TLS 1.3 and TLS 1.2 probes surviving.

Mesh health and the CA-verified cross-node TLS chat smoke passed after both
swaps. The 0.10.4 binary is kept as `onyx-server.0.10.4-b9fcf90d`; for a hot
rollback follow [Helix rollback to 0.10.4](#helix-rollback-to-0104).

0.10.4 (`e202c6cf`) went live by Helix reload alone, with no cold restart.
Both nodes kept their PID (9223 and 2980332), and the issuer epochs stayed at
11 and 12. Each node held a TLS client across the reload. The mesh health and
cross-node chat smokes passed afterwards. The release rebuilt byte-for-byte.
The 0.10.3 binary is kept as `onyx-server.0.10.3-fda55aaa`.

0.10.3 (`04beb65d`) carries the durable mesh presence store across Helix.
Both nodes were cold-restarted onto it, eshmaki.me first, because 0.10.2
refuses Helix with a presence store. Then a live `reload` ran on each node with
a held TLS client:

- **eshmaki.me:** PID 9223 was kept and the issuer epoch stayed at 11.
- **ircx.us:** PID 2980332 was kept and the issuer epoch stayed at 12. The
  first attempt refused safely with "not every registered client could be
  sealed", a transient I/O-in-flight state. The retry adopted every client,
  including real users.

On both nodes the held client answered PING after the reload, and the log
showed `mesh presence authority adopted hot (…; no cold epoch advance)`. The
mesh health and CA-verified cross-node chat smokes passed afterwards. The
release rebuilt byte-for-byte with `packaging/verify-release.sh`. The 0.10.2
binary is kept as `onyx-server.0.10.2-6ad83624`.

0.10.2 (`6ad83624`) restores Linux Helix handoff and adoption and makes reload
refuse before exec while the durable mesh presence store is configured. Both
nodes were cold-restarted onto it. A live `reload` on each then refused with
`durable mesh presence store (no Helix carry yet)`, kept the same PID, and a
held TLS client answered PING afterwards. The 0.10.1 binary is kept as
`onyx-server.0.10.1-0200fe47`.

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
Helix was then blocked by the durable mesh presence store (carried since 0.10.3).

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

## Helix rollback to 0.10.4

`0.10.4` (`e202c6cf`) adopts `.tls_session` rows at schema v3 only. Later
images write v4 for any TLS 1.2 row that carries the RFC 9266 channel binding,
uses TLS 1.2 kTLS offload, or holds TLS 1.2 control state. Before this guard,
a Helix UPGRADE back to `0.10.4` passed the capability probe and executed the
old image. The old successor then rejected the handoff ("noncanonical
TLS-session capsule") and dropped every client on the node.

The predecessor now reads the target's rolling state capabilities from its
probe answer. A current image prints extra lines after the unchanged base
token. `0.10.4` prints neither line:

- `ONYX_HELIX_STATE_CAP=tls-session-v4`
- `ONYX_HELIX_STATE_CAP=quic-wide-key-update-v1`

When the target lacks them, the predecessor does this before exec:

- TLS 1.3 rows and plain TLS 1.2 rows are written as exact v3.
- A bound but not offloaded TLS 1.2 row drops only its channel binding and is
  written as v3. `0.10.4` never offers SCRAM `-PLUS` on TLS 1.2, so the
  successor loses nothing it could use. The log counts these rows.
- A kTLS-offloaded TLS 1.2 row has no v3 form. UPGRADE is refused with
  `UPGRADE refused: target binary cannot adopt N kTLS TLS 1.2 session(s)
  (tls-session-v4) ...`. Every connection stays up and nothing is executed.
- WebTransport: QUIC session-ticket keys are dropped, so the checkpoint is
  the v2 frame. Tickets issued before the swap fall back to a full handshake.
  A live `TLS_AES_256_GCM_SHA384` WebTransport connection refuses UPGRADE
  (`quic-wide-key-update-v1`) and stays connected.

Hot rollback procedure (one node at a time):

1. Set `[tls] ktls = "off"`. Then Helix UPGRADE to the **current** image.
   The successor reads the new config. Existing connections are carried, and
   offloaded rows keep their offload. New TLS 1.2 sessions are no longer
   offloaded.
   Do **not** set `enable_tls12 = false` for this step. A successor with TLS
   1.2 disabled has no TLS 1.2 config, so it cannot resume any carried TLS 1.2
   row. This build's predecessor reads the target config before exec and
   refuses such an UPGRADE ("target config sets [tls] enable_tls12 = false
   but N TLS 1.2 session(s) are attached"), keeping every connection. A
   `0.10.4` predecessor has no such check: its successor would reject the whole
   handoff and drop every client on the node. Keep `enable_tls12 = true` through every
   Helix step while TLS 1.2 clients are connected.
2. Wait until `onyx_tls_ktls12_active` on `:9130/metrics` reaches `0`. You can
   also ask the remaining TLS 1.2 clients to reconnect, or disconnect them.
3. Point the service binary at `0.10.4` and Helix UPGRADE. A refusal leaves
   the node serving. Read the NOTICE or log line, fix the cause, and retry.
4. If you cannot wait, cold-restart onto `0.10.4`. Clients reconnect.

There is no TLS-1.2-only offload switch yet. `ktls = "off"` also stops TLS 1.3
offload, but TLS 1.3 rows are rollback-safe either way.

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
