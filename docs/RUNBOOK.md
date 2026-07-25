# Onyx Server runbook

*Build, stage, validate, deploy, monitor, hot-upgrade, and roll back an Onyx Server node.*

This runbook describes the shipped tree. For full configuration details, use
[reference/config.md](reference/config.md) and `etc/onyx-server.reference.toml`.

## Operator Model

Onyx Server runs as a long-lived network daemon with:

- a config file passed as `argv[1]`;
- a systemd unit source at `etc/systemd/onyx-server.service`, packaged to
  `lib/systemd/system/onyx-server.service` and normally installed as
  `/etc/systemd/system/onyx-server.service`;
- state under `/var/lib/onyx-server` in the packaged unit;
- ReleaseFast production binaries from `zig build release` or `zig build package`;
- session-preserving reload via SIGUSR2/Helix, exposed as `systemctl reload onyx-server`.

Cold restart is the fallback path and drops sessions. Reload is the normal upgrade path.
Cold restart is also **not crash-durable for the MESSAGE_V2 custody plane** and can lose an
intermediate node's last un-repaired custody copy — see [Cold Restart](#cold-restart) and the
[cold-restart durability contract](design/message-v2-exact-once.md#cold-restart-durability-contract).

## Build And Stage

```sh
zig build check
zig build test-smoke --summary all
zig build test-roadmap --summary all
zig build test-smoke -Doptimize=ReleaseSafe --summary all
zig build package --prefix /tmp/onyx-server-stage
```

The package step stages:

| Path | Contents |
|---|---|
| `/tmp/onyx-server-stage/bin/onyx-server` | ReleaseFast stripped daemon |
| `/tmp/onyx-server-stage/etc/onyx-server/onyx-server.reference.toml` | Annotated reference config |
| `/tmp/onyx-server-stage/lib/systemd/system/onyx-server.service` | systemd service unit |

For local smoke tests against the debug binary:

```sh
zig build
python3 tools/runtime_smoke.py zig-out/bin/onyx-server
python3 tools/upgrade_smoke.py zig-out/bin/onyx-server
```

## Pre-Deploy Config Validation

Validate the exact config before staging a reload (and on every cold start):

```sh
onyx-server --check-config /etc/onyx-server/onyx-server.toml
# or from a source tree:
zig build run -- --check-config /etc/onyx-server/onyx-server.toml
```

`--check-config` is a real daemon flag (`src/main.zig`): it reads and parses the
file, resolves configured `env:` and `@file:` string indirection through the CLI
resolver, runs mesh cloak / MESSAGE_V2 identity preflight, reports `config OK`,
and exits without binding listeners or dialing mesh peers. Exit `0` on success,
`1` on any read/parse/preflight error, `2` on usage.

The packaged unit embeds this as `ExecStartPre` so a bad config **fails the start**
instead of risking a silent fall-through to the built-in DEFAULT identity. Reload
(`systemctl reload` / SIGUSR2) does **not** re-run `ExecStartPre`; always run
`--check-config` yourself before a Helix reload when the config or binary changed.

## First Install

After `zig build package --prefix /tmp/onyx-server-stage`, install the staged assets:

```sh
useradd --system --home-dir /var/lib/onyx-server --shell /usr/sbin/nologin onyx-server
install -d -o onyx-server -g onyx-server /var/lib/onyx-server /etc/onyx-server
install -m 0640 -o onyx-server -g onyx-server /tmp/onyx-server-stage/etc/onyx-server/onyx-server.reference.toml /etc/onyx-server/onyx-server.toml
install -m 0755 /tmp/onyx-server-stage/bin/onyx-server /usr/local/bin/onyx-server
install -m 0644 /tmp/onyx-server-stage/lib/systemd/system/onyx-server.service /etc/systemd/system/onyx-server.service
# unit ships ExecStartPre=… --check-config …; preflight before enable:
/usr/local/bin/onyx-server --check-config /etc/onyx-server/onyx-server.toml
systemctl daemon-reload
systemctl enable --now onyx-server
```

If all listeners use high ports, remove `AmbientCapabilities=CAP_NET_BIND_SERVICE` and
`CapabilityBoundingSet=CAP_NET_BIND_SERVICE` from the unit.

For a public HTTPS / `wss` node, follow the [Production TLS card](guide/tls.md#production-tls-card)
before opening the listeners.

## Hot Upgrade

Use Helix reload for normal production upgrades:

```sh
zig build package --prefix /tmp/onyx-server-stage
zig build run -- --check-config /etc/onyx-server/onyx-server.toml
install -m 0755 /tmp/onyx-server-stage/bin/onyx-server /usr/local/bin/onyx-server
systemctl reload onyx-server
```

`ExecReload=/bin/kill -USR2 $MAINPID` asks the live daemon to re-exec in place. The
successor inherits every per-shard `SO_REUSEPORT` listener and attempts to reattach
live client, TLS, WebSocket, session-registry, and secured-mesh state from the sealed
Helix arena. The process PID remains under systemd control; systemd does not see a
normal restart.

The session registry preserves duplicate same-token attachment rows rather than
electing a single owner. Portable flags, detached snapshots, and staged reusable mesh
replicas are carried as well; adopted secured links immediately re-offer portable
state so remote attachments remain authorized after re-exec.

Verify after reload:

```sh
systemctl status onyx-server --no-pager
journalctl -u onyx-server -n 100 --no-pager
```

Then connect an IRC client or run an out-of-band probe against the configured listener.

For a two-node Undertow mesh, roll one node at a time: reload the first node,
verify systemd, logs, `/INFO`, `/STATS l`, and that node's
`[stats].channel_dir/status.json`, then repeat on the peer. Do not cold-restart
both nodes together unless accepting session loss and a temporary mesh partition.

### Mesh health smoke (dual-node)

After any hard restart or binary replace on a meshed pair, confirm Mooring is
**established** (not merely TCP-dialed):

```sh
# On each node (or from an ops host that can reach both /metrics ports):
python3 tools/mesh_health_smoke.py \
  http://127.0.0.1:9130/metrics \
  http://peer.example:9130/metrics

# When the peer metrics port is loopback-only (Undertow eshmaki/ircx):
MESH_SSH_PEER=trev@ircx.us python3 tools/mesh_health_smoke.py \
  http://127.0.0.1:9130/metrics
```

Expect `links_active >= 1` and `peers_up >= 1` with `partitioned = 0` on both.
`onyx_s2s_tcp_active` may be higher than `links_active` during AKE; a stuck
`tcp_active > 0` with `links_active = 0` means handshake failure (check journal
for `HandshakeTooLarge` / `PrekeyRejected` / `BadSignature` — usually wire
domain or trust-root skew).

One-line deploy sequence: [`docs/ops/mesh-metrics-deploy-checklist.md`](ops/mesh-metrics-deploy-checklist.md).
Cross-node PRIVMSG (guest auto when SASL unset if the network allows unregistered
nicks; SASL when creds present — fail-closed on SASL fail):

```sh
# Guest path (no credentials; works when nodes accept NICK+USER → 001)
MESH_SMOKE_B=peer.example:6697 MESH_SMOKE_INSECURE_TLS=1 \
  python3 tools/mesh_chat_smoke.py

# SASL path (preferred for account-bound checks)
export MESH_SMOKE_SASL_USER=… MESH_SMOKE_SASL_PASS=…   # or ANNOUNCE_SASL_*
python3 tools/mesh_chat_smoke.py 127.0.0.1:6667 peer.example:6697
# B is TLS by default; channel #root; unique PRIVMSG both directions.
# MESH_SMOKE_REQUIRE_SASL=1 → exit 2 if credentials missing (no guest fallback).
```

### MESSAGE_V2 activation runbook

MESSAGE_V2 authoring has two configuration reloads after the bridge binary is
deployed. Keep these as separate, fully verified passes:

1. Deploy the exact bridge binary everywhere with `relay_v2_authoring = "compat"`
   and no plan. `--check-config` every node before reloading it. A running image
   whose exact Helix token predates `mesh-clock-v3` requires a planned cold
   restart for this first bridge deployment.
2. Select a strictly increasing, never-reused activation epoch and one complete
   public-key roster. Add the exact epoch/roster everywhere while leaving the
   mode `compat`; run the new binary's `--check-config` against that final staged
   config, then Helix-reload every node.
3. On every roster member, inspect `jq '.relay_v2' status.json` and
   `/quote MESH ADMISSION`. Require `bridge_implemented=true`, `authoring=compat`, the
   same non-zero epoch/digest/count, and healthy links. This is an inventory-wide
   operator gate; direct neighbors and the roster itself do not prove hidden
   nodes are ready.
4. For each node in sequence, change only the mode to `active`, run
   `--check-config`, Helix-reload it, and require `authoring_eligible=true` with
   the exact epoch/digest/count unchanged. Before advancing to the next node,
   negotiate message-tags/server-time on controlled clients, send channel and
   shared portable-session events from the newly active node, and confirm every
   live attachment sees one copy with one msgid/server-time identity.

The activation plan requires an explicit `[node].secret_key` or a
`[node].public_key` for persisted-keyfile deployments, secured S2S, signed
frames, 1..255 valid direct trust roots, and a 2..4096-key full roster containing
both the local key and every direct root. Direct roots and their compact u64 ids
must be unique and must not collide with the local identity. For a persisted
keyfile, derive `public_key` from the already-created `onyx-server-node.key` identity.
`--check-config` non-mutatingly reads that existing keyfile and proves the match;
runtime initialization repeats the binding against the identity it actually
loaded. A missing, corrupt, or mismatched keyfile rejects preflight. The first
compat bridge boot without a plan is the natural identity-generation step.
`bridge_implemented` is a local build marker, not proof that any peer or the full
mesh is ready.

Once any node is active, neither hot nor cold rollback may change that active
tuple, return it to `compat`, or boot an image that lacks the exact activation
and capability semantics. Current Helix handoff
enforces the boundary in memory, but cold boot has no durable previous-active
floor. Preserve the exact active configuration and binary through deployment
automation. Roster change after activation is not implemented and requires a
future protocol/release. A higher epoch can replace a staged plan only while its
predecessor remains `compat`; never reuse or rebind an existing epoch.

## Cold Restart

Before MESSAGE_V2 activation, use cold restart only when changing host-level unit
constraints, recovering from a bad state, or accepting session loss:

```sh
systemctl restart onyx-server
systemctl status onyx-server --no-pager
```

Cold restart drops live client sessions and mesh links. Mesh peers should redial through
the configured `[mesh].connect` and listener paths. After any mesh member activates,
a cold restart is allowed only with a compatible binary and the exact active tuple.

Cold restart is **not crash-durable for the MESSAGE_V2 custody plane**. The RVL2/RVO2/RVG2/ADS1
custody authorities are in-memory and survive only a connection-preserving Helix reload, whose
checkpoints ride the upgrade capsule across re-exec. A cold restart (or power loss) discards them,
so an intermediate node that has ACKed upstream but not yet repaired a message downstream can lose
that message's last custody copy. Prefer `systemctl reload onyx-server`; hard-restart only from a drained
node with no outstanding custody obligations. See the
[cold-restart durability contract](design/message-v2-exact-once.md#cold-restart-durability-contract).

## Rollback

The generic procedures below apply only before any MESSAGE_V2 member activates.
After activation, rollback is restricted to a compatible binary that preserves
the exact active tuple. Keep the previous known-good binary before replacing
`/usr/local/bin/onyx-server`:

```sh
install -m 0755 /usr/local/bin/onyx-server /usr/local/bin/onyx-server.prev
install -m 0755 /tmp/onyx-server-stage/bin/onyx-server /usr/local/bin/onyx-server
systemctl reload onyx-server
```

If the new image fails after reload and the previous binary exposes the exact
full Helix capability token required by the running image, a second reload is
allowed. Multi-shard listener compatibility is necessary but not sufficient:

```sh
install -m 0755 /usr/local/bin/onyx-server.prev /usr/local/bin/onyx-server
systemctl reload onyx-server
```

**Compatibility boundary:** never hot-roll back a multi-shard node from Onyx Server 0.5.2
or newer to a pre-0.5.2 binary. The newer predecessor passes one inherited listener
fd per shard through `ONYX_HELIX_LISTEN_FDS`; an older successor only adopts shard
0 and leaves the sibling fds open but unserved. Because those fds remain in the
`SO_REUSEPORT` group, a share of new connections is silently hashed into queues no
reactor accepts. Use a cold restart for that rollback:

```sh
install -m 0755 /usr/local/bin/onyx-server.prev /usr/local/bin/onyx-server
systemctl restart onyx-server
```

Use a cold restart as well when the process is already failed, the reload path is
broken, or listener-handoff compatibility is unknown. This drops sessions, but it
closes every inherited listener and rebuilds the complete shard set safely.

## Health Checks

| Check | Command / Surface | Expected |
|---|---|---|
| systemd state | `systemctl status onyx-server --no-pager` | active running |
| recent logs | `journalctl -u onyx-server -n 100 --no-pager` | no repeated panic/restart loop |
| config parse | `onyx-server --check-config /etc/onyx-server/onyx-server.toml` | `config OK` |
| IRC registration | connect to listener, send `NICK`/`USER` | `001` welcome |
| PING/PONG | send `PING :token` | `PONG` with token |
| INFO | `/INFO` | runtime limits, class count, mesh peer count |
| STATS Y | `/STATS Y` as oper | connection-class policy visible |
| STATS l | `/STATS l` as oper | established S2S sendq state |
| status feed | configured `[stats].channel_dir` `status.json` | current node and peer health |
| Prometheus | configured `[metrics].listen` `/metrics` | Prometheus text body |

### Certificate session-resume acceptance

For a release that changes reusable sessions, keep two controlled clients open at
the same time: one through each secured mesh node. Both must present the same
configured client certificate and complete SASL EXTERNAL as the same account and
requested nick. Do not put a session token in either registration flow.

Require all of the following before declaring the mesh healthy:

1. both clients receive SASL numerics `900` and `903`, then `001` under the same
   nick and account;
2. the server reports certificate-authenticated session restoration rather than
   creating a guest or collision nick;
3. every restored channel receives its unsolicited `353` roster followed by
   `366` immediately after the restore bootstrap, without waiting for a client
   `NAMES` poll; parse the final `353` parameter as a trailing field and require
   the requested nick exactly once, including its expected status prefix;
4. each client can author one channel message and one direct message;
5. every marker arrives exactly once on both clients, with identical `time` and
   `msgid` tags on the two transports; and
6. attaching the second client does not emit `MODE #channel +Y nick`. A cold
   process may publish one genuine first grant transition while reconstructing
   state, but later attachments and unchanged grant refreshes must stay silent.

Also test the actual saved client profile, not only an ad-hoc TLS probe. WeeChat
can contain similarly named profiles such as `ircx` and `ircx.us`; inspect each
profile that users invoke and require `tls_cert`, `sasl_mechanism=external`, the
intended account/nick, and reconnect policy to be set explicitly.

### Media E2EE release acceptance

Treat client-held media E2EE as a client/server release. Before activation:

1. run the complete client unit suite, typecheck, lint, and production build;
2. run `zig build all-checks --summary all`, the affected ReleaseSafe server
   lane, a clean static release build, and `git diff --check`;
3. require tests that reject a bad version, length, enrolled key, signature,
   channel transcript, attachment, stream, kind, MAC, epoch, and replay without
   publishing or mutating call state;
4. exercise at least three physical clients, including same-nick attachments,
   leader detach, leader disconnect, rejoin, re-handshake, `PART`, `KICK`, nick
   change, successful account mutation, failed authentication, and old-frame
   rejection after retirement; and
5. obtain a fresh security review of the handshake, lifecycle, and WebSocket
   ingress changes. Reproduce each finding against the release tree rather than
   accepting the review result uncritically.

After both nodes are restarted, require healthy mesh metrics (`quorum=1`,
`partitioned=0`, one component, and all configured peers up), repeat the
two-client certificate routing acceptance above, and confirm that E2EE control
events traverse the mesh exactly once. Smoke the deployed browser application,
service worker, status, roadmap, and stats data—not only its build output.

Cross-node binary WebSocket media rides secured `MEDIA_WS_DATAGRAM` (origin-only
cascade of opaque Cadence frames). Control-plane presence alone is not proof of
media path health — accept with real media frames on both nodes. Do not describe
a two-node control-plane-only test as cross-node media delivery.

`status.json` and channel stats are file outputs, not daemon-owned HTTP routes. Serve
the configured stats directory with nginx or another static file server if needed.

## Common Incidents

| Symptom | Likely Cause | Action |
|---|---|---|
| `--check-config` fails | Bad TOML, missing required fields, invalid range/`@file:` target, or a MESSAGE_V2 activation keyfile that is missing, corrupt, or mismatched | Fix config/identity and rerun `--check-config`; do not reload until clean. |
| systemd starts then loops | Binary crash or invalid runtime dependency | Check `journalctl -u onyx-server`; restore previous binary and restart/reload. |
| Privileged port bind fails | Unit lacks `CAP_NET_BIND_SERVICE` or port already bound | Add capability lines from unit or move listeners to high ports; inspect `ss -ltnup`. |
| Reload drops sessions | Helix exact-handoff invariant violation | Stop the rollout, preserve evidence, check logs for `SIGUSR2 UPGRADE failed` or adoption errors, and run `tools/upgrade_smoke.py` locally. Current UPGRADE does not intentionally fall back to listener-only or partial adoption. |
| Mesh peer absent after reload | Peer link not reattached or redial still pending | Inspect `/INFO`, `/STATS l`, status feed, and `[mesh].connect`; verify peer listener reachability. |
| Metrics unavailable | `[metrics].listen = 0`, bind failure, or loopback-only bind | Check config and startup logs; default bind is loopback unless widened deliberately. |
| WebSocket/WebTransport disabled | TLS cert/key material missing or listener disabled | Check `[tls]`, `[listen].ws`, `[listen].webtransport`, and boot logs. |
| Python `ssl` receives a TLS 1.3 `decode_error` while WeeChat and OpenSSL clients work | Armor record interoperability differs for that client stack; certificate presentation alone does not isolate the record-path failure | Preserve a packet/log trace, reproduce with a minimal Python client against both nodes, and inspect the Armor TLS record parser. Do not weaken certificate or signature validation as a workaround. |

## CI And Release Expectations

Before merging a release-bearing change:

```sh
zig build all-checks --summary all
zig build release -Dtarget=x86_64-linux-musl
zig build package --summary all
git diff --check
```

For long tmux or CI diagnosis, use verbose lanes:

```sh
zig build test-roadmap-verbose --summary all
zig build all-checks-verbose --summary all
```

Verbose lanes print every test name, duration, final counts, and the slowest tests.
