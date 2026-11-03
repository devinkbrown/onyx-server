# Onyx Server observability: channel stats and status feed

*The per-channel statistics engine, public status feed, and IRC-visible stats surfaces as implemented in the current source tree.*

Onyx Server ships a native, in-process chanstats engine that aggregates live channel activity into per-channel counters and emits self-describing JSON for a static dashboard, plus a separate `status.json` public health feed. Both are pure data producers: no sockets, no SQLite. The daemon feeds the aggregate from its history chokepoints and flushes on a throttled cadence into a directory nginx serves at `/stats/data/`. The engine lives in [src/daemon/chanstats.zig](../../src/daemon/chanstats.zig); the daemon wiring, IRC `STATS`/`INFO` handlers, and `status.json` feed live in [src/daemon/server.zig](../../src/daemon/server.zig).

## Per-channel statistics engine

`ChanStats` owns a name-to-`ChannelAgg` map ([src/daemon/chanstats.zig](../../src/daemon/chanstats.zig)). Three recorders drive it, all taking wall-clock unix-ms (`platform.realtimeMillis()`):

- `recordMessage` counts a channel message, bumps the hour-of-day bucket, the 7x24 weekday heatmap, and the current day, tokenizes the text into word-frequency counts, and updates the author's `UserAgg` with question/exclamation/URL/monologue/action behaviour metrics. CTCP ACTION (`\x01ACTION …\x01`) increments both messages and `actions`. Nicks in `[stats] ignore_nicks` are skipped entirely (ophion ignore list).
- `recordEvent` increments `joins`/`parts`/`quits`/`kicks`.
- `recordTopic` appends to a bounded topic history and increments `topic_changes`.
- `notePresent` / flush-time presence raises `peak_members` (ophion high-water mark).

### IRC surface: `CHANSTATS` (ophion subset)

`CHANSTATS TOPUSERS|WORDS|ACTIVITY|RECORD #channel` — registered clients, NOTICE replies from live in-memory aggregates (no SQLite). Help via `CHANSTATS HELP`.

### Ophion parity ledger (native subset)

| Ophion m_chanstats | Onyx Server status |
|---|---|
| messages / words / joins / parts / kicks / topics | **DONE** |
| hours + weekday heatmap + daily series | **DONE** |
| top users + top words | **DONE** |
| CTCP ACTION counters | **DONE** (`actions` on totals + top_users) |
| peak concurrent members | **DONE** (`peak_members`) |
| ignore nicks (bots) | **DONE** (`[stats] ignore_nicks`) |
| CHANSTATS TOPUSERS/WORDS/ACTIVITY/RECORD | **DONE** (NOTICE subset) |
| SQLite WAL + full HTML site regen | out of scope (JSON + Solid dashboard) |
| quotes / quiz / hall-of-fame / digests / milestones | later |
| mention matrix / compare pages / user profiles | later |

The engine is bounded by construction: per-channel user (4096) and word (8192) tables are capped, and when a table is full only already-tracked users update while new words are ignored, so a hostile flood cannot pin unbounded memory ([src/daemon/chanstats.zig](../../src/daemon/chanstats.zig)). Day history caps at 60 and topics at 40.

The daemon feeds the aggregate from its `recordHistory*` chokepoints: `chanstatsMessage` handles local and relayed channel `PRIVMSG`s, and `chanstatsEvent` handles `JOIN`/`PART`/`QUIT`/`KICK`/`TOPIC` ([src/daemon/server.zig](../../src/daemon/server.zig)). Both are no-ops unless `[stats] channel_dir` has populated `config.chanstats_dir` ([src/daemon/server.zig](../../src/daemon/server.zig), [src/daemon/config_format.zig](../../src/daemon/config_format.zig)), and `chanstatsMessage` skips ephemeral rooms so those messages leave no durable footprint ([src/daemon/server.zig](../../src/daemon/server.zig)). Because relayed messages feed the same path, the aggregate captures channel activity from across the mesh that reaches this node.

### Outputs

`writeJson` prunes dead channels, then writes one `index.json` plus one `<slug>.json` per channel into `chanstats_dir` ([src/daemon/chanstats.zig](../../src/daemon/chanstats.zig)). A channel is only emitted once it reaches `min_messages` (default 1), keeping fly-by one-liners out of the index ([src/daemon/chanstats.zig](../../src/daemon/chanstats.zig)). `renderChannel` is split from the file write so it can be unit-tested by parsing the output back ([src/daemon/chanstats.zig](../../src/daemon/chanstats.zig)). Channel JSON is written through a temp-file plus rename, and `status.json` uses `createFileAtomic` plus `sync`, so nginx does not serve half-written files ([src/daemon/chanstats.zig](../../src/daemon/chanstats.zig), [src/daemon/server.zig](../../src/daemon/server.zig)).

A per-channel `<slug>.json` (from `renderChannel`, top-N capped at 30 users / 40 words):

```json
{
  "channel": "#root",
  "generated_at": 1700000000,
  "first_seen": 1699990000,
  "last_active": 1700000000,
  "present": 12,
  "last_speaker": "kain",
  "totals": {"messages": 842, "words": 5120, "active_users": 37,
             "joins": 60, "parts": 22, "quits": 14, "kicks": 1, "topic_changes": 3,
             "actions": 40, "peak_members": 28},
  "hours": [0,0,1, "...24 hourly totals..."],
  "days": [{"date": "2026-06-28", "messages": 120}, "..."],
  "heatmap": [[0,0,"...24..."], "...7 weekday rows..."],
  "top_users": [{"nick": "kain", "messages": 210, "words": 1400, "last_active": 1700000000,
                 "questions": 12, "exclamations": 30, "urls": 4, "monologue": 6, "actions": 9}, "..."],
  "top_words": [{"word": "onyx", "count": 88}, "..."],
  "topics": [{"ts": 1699999000, "setter": "kain", "topic": "build channel"}, "...newest first..."],
  "records": {"busiest_day": {"date": "2026-06-30", "messages": 300}, "peak_hour": 20, "peak_members": 28}
}
```

The keys above are emitted by `renderChannel`: `present`, `last_speaker`, `totals`, `hours`, `days`, `heatmap`, top users/words, newest-first `topics`, and `records` (`busiest_day`, `peak_hour`) ([src/daemon/chanstats.zig](../../src/daemon/chanstats.zig)). `present` is the live member count injected by the daemon, while `active_users` is the all-time distinct-author count for that channel ([src/daemon/chanstats.zig](../../src/daemon/chanstats.zig)).

## Slug generation

`slugify` lowercases, strips a leading channel prefix (`#`/`&`/`+`/`!`), keeps `[a-z0-9._-]`, maps every other byte to `_`, and neutralises a leading dot ([src/daemon/chanstats.zig](../../src/daemon/chanstats.zig)). The slug is the join key between the served index and the per-channel file, so the server `slugify` and any dashboard slug logic must produce byte-identical output or a card 404s. The pinned test vectors are `#root` -> `root`, `#foo/bar` -> `foo_bar`, `#../etc/passwd` -> `_._etc_passwd`, `&.hidden` -> `_hidden`, and `#` -> null ([src/daemon/chanstats.zig](../../src/daemon/chanstats.zig)); the same neutralisation guarantees a slug can never be `.`, `..`, or contain a path separator, so a crafted channel name can never escape the data dir.

## Persistence across restart / USR2

The served JSON is top-N capped (lossy), so it cannot be the persistence source. Instead the whole aggregate is serialized to a compact versioned binary snapshot, `.chanstats.snapshot`, written atomically alongside the JSON on every flush and reloaded once at boot, so per-channel stats survive a cold restart or a USR2 hot-upgrade ([src/daemon/chanstats.zig](../../src/daemon/chanstats.zig), [src/daemon/server.zig](../../src/daemon/server.zig)). `serialize`/`deserialize` are split from the file I/O so the round-trip is unit-testable in memory ([src/daemon/chanstats.zig](../../src/daemon/chanstats.zig)), using little-endian length-prefixed framing (`putInt`/`putBytes`/`Cursor`).

The format is a 4-byte magic followed by an explicit format-version byte. The current magic is `OCS2` with version `1`; it supersedes the original `OCS1`, which was bumped to add the version byte after the magic ([src/daemon/chanstats.zig](../../src/daemon/chanstats.zig)). A reader distinguishes "wrong file" (bad magic, such as a leftover `OCS1`) from "newer format" (good magic, higher version) and starts empty in either case. Loading is best-effort: a missing/short/corrupt blob leaves the aggregate empty, and a partial parse keeps already-restored channels. Load caps every re-read table at the same live ceiling, and rejects a snapshot listing the same channel twice, so a hostile snapshot cannot exceed limits or leak memory ([src/daemon/chanstats.zig](../../src/daemon/chanstats.zig)).

## Index: spark series, network daily series, live presence

`index.json` carries a top-level `users_online` plus a `network_days` series and a per-channel card list. Each card includes a compact `spark` array: the last up-to-14 daily message counts, oldest to newest, so the index renders per-card trends with no extra fetch ([src/daemon/chanstats.zig](../../src/daemon/chanstats.zig)). `network_days` is the per-day message total merged across every tracked channel, computed into a bounded day-sorted set and emitted for the last 14 days ([src/daemon/chanstats.zig](../../src/daemon/chanstats.zig)).

```json
{
  "generated_at": 1700000000,
  "network": "Onyx",
  "node": "eshmaki.me",
  "users_online": 214,
  "network_days": [{"date": "2026-06-28", "messages": 4200}, "...last 14..."],
  "channels": [
    {"channel": "#root", "messages": 842, "active_users": 37, "present": 12,
     "last_active": 1700000000, "topic": "build channel", "spark": [120,90,110,"..."]}
  ]
}
```

The live figures are injected by the server at flush time through a `NetInfo` struct so the engine stays world-agnostic and testable ([src/daemon/chanstats.zig](../../src/daemon/chanstats.zig)). `users_online` is the mesh-wide user total from `meshUserCount`, which sums this node's local nicks plus each established peer link's `remoteNickCount` ([src/daemon/server.zig](../../src/daemon/server.zig)). The per-channel `present` is provided by a `presence_fn` bound to `globalMemberCount` (local + mesh roster). Both are read under the same `world.lockWrite` the flush already holds, so presence is consistent with the recorder feed even on a multi-reactor node ([src/daemon/server.zig](../../src/daemon/server.zig)).

## Dead-channel prune

`writeJson` calls `pruneDeadChannels` before rendering ([src/daemon/chanstats.zig](../../src/daemon/chanstats.zig)). A channel is dead when it no longer exists: unregistered and empty (zero local + mesh members). A dead channel's `<slug>.json` is deleted, its aggregate freed, and it drops from the map, so it vanishes from the index and from `network_days` too. A registered channel survives even while momentarily empty; a currently-populated one always survives.

Existence is decided by the optional `exists_fn` callback ([src/daemon/chanstats.zig](../../src/daemon/chanstats.zig)). The server binds it to a predicate that returns true when `globalMemberCount > 0` or `Services.channelIsRegistered` reports a durable `.chanregs` record ([src/daemon/server.zig](../../src/daemon/server.zig), [src/daemon/services.zig](../../src/daemon/services.zig)). When `exists_fn` is absent, nothing is pruned, preserving backward-compatible behaviour. Pruning is two-phase, collecting up to 64 dead keys and then removing them, so the map is never mutated mid-iteration; file deletion is best-effort and never blocks the flush ([src/daemon/chanstats.zig](../../src/daemon/chanstats.zig)).

## IRC command surfaces: `STATS`, `INFO`, `EVENT STATS`

`STATS` is implemented by one switch in `handleStats` and always terminates with `RPL_ENDOFSTATS` (`219`) for implemented and unknown letters alike ([src/daemon/server.zig](../../src/daemon/server.zig)). The exact supported first-letter set is `u`, `o`, `k`/`K`, `d`/`D`, `y`/`Y`, `l`/`L`, `z`/`Z`, `p`/`P`, `c`/`C`, `i`/`I`, and `m`/`M`; all are operator-only except `p`/`P`, which remains public ([src/daemon/server.zig](../../src/daemon/server.zig)).

The letters emit these numerics and values:

- `STATS u`: `242 RPL_STATSUPTIME`, text `Server Up <days> days HH:MM:SS`, computed from `nowMs() - start_ms` ([src/daemon/server.zig](../../src/daemon/server.zig)).
- `STATS o`: `243 RPL_STATSOLINE`, one row per oper binding with account and class ([src/daemon/server.zig](../../src/daemon/server.zig)).
- `STATS k`/`K`: `216 RPL_STATSKLINE`, Warden mask wards (`match token`, pattern, action, reason); `STATS d`/`D`: `225 RPL_STATSDLINE`, Warden address wards with the same row shape ([src/daemon/server.zig](../../src/daemon/server.zig)).
- `STATS y`/`Y`: `218 RPL_STATSYLINE`, one row per connection class with sendq, recvq, max_clients, max_per_ip, max_per_account, max_per_host, max_chan, max_targets, monitor, silence, ping timers, registration timeout, flood window, TLS/SASL/exemption flags, CIDR count, class predicates, and live member count ([src/daemon/server.zig](../../src/daemon/server.zig)).
- `STATS l`/`L`: `211 RPL_STATSLLINE`, established S2S peer links only, with peer name plus `sendq_cap`, queued bytes, and uptime seconds ([src/daemon/server.zig](../../src/daemon/server.zig)).
- `STATS z`/`Z`: `249 RPL_STATSDEBUG`, runtime counter lines from `server_stats`: `conns`, `conns_active`, `s2s`, `s2s_active`, `msgs_in`, `bytes_in`, `bytes_out`, `quits`, and `errors` ([src/daemon/server.zig](../../src/daemon/server.zig), [src/daemon/server_stats.zig](../../src/daemon/server_stats.zig)).
- `STATS p`/`P`: public `249 RPL_STATSDEBUG` rows for currently connected registered operators, with parameter `p` and the operator display name ([src/daemon/server.zig](../../src/daemon/server.zig)).
- `STATS c`/`C`: `213 RPL_STATSCLINE`, configured `[mesh].connect` auto-dial peers as C-lines, parsing `host:port` when possible and otherwise reporting the raw spec with `*` port ([src/daemon/server.zig](../../src/daemon/server.zig)).
- `STATS i`/`I`: `215 RPL_STATSILINE`, one allow-block row per connection class with CIDR count and class predicate flags (`tls_only`, `account_only`, `oper_only`) ([src/daemon/server.zig](../../src/daemon/server.zig)).
- `STATS m`/`M`: `212 RPL_STATSCOMMANDS`, one row per recorded command verb with `<count> <bytes> 0`; command usage records every well-formed line before registration checks, uppercases verbs, caps names at 24 bytes, and holds up to 192 verbs ([src/daemon/server.zig](../../src/daemon/server.zig), [src/daemon/command_usage.zig](../../src/daemon/command_usage.zig)).

`INFO` emits `373 RPL_INFOSTART`, one `371 RPL_INFO` per rendered line, and `374 RPL_ENDOFINFO` ([src/daemon/server.zig](../../src/daemon/server.zig)). The body combines the pure `server_about.renderInfo` output (version, Zig version, target, optimize mode, network, online-since time, uptime, and codename subsystem inventory) with runtime lines for limits, connection-class count, optional nick-delay state, established mesh peer count, and active subsystem inventory ([src/proto/server_about.zig](../../src/proto/server_about.zig), [src/daemon/server.zig](../../src/daemon/server.zig)).

`EVENT STATS [JSON]` is separate from IRC `STATS`. It is operator-only, reports Event Spine counts since boot plus the current history-ring depth, and in JSON mode emits every category token, every severity token, and fixed `operator_surfaces` booleans ([src/daemon/server.zig](../../src/daemon/server.zig)). The counters are lock-free atomics in `EventStats`, incremented both when this node publishes an Event Spine event and when it drains a peer event from the mesh ([src/daemon/event_history.zig](../../src/daemon/event_history.zig), [src/daemon/server.zig](../../src/daemon/server.zig)).

Event Spine flood-collapse is not part of IRC `STATS`, but it affects `EVENT STATS` totals: identical low-severity events past the threshold are suppressed before delivery, mesh fanout, history, and stats recording; severity `warn` and above is never collapsed ([src/daemon/event_collapse.zig](../../src/daemon/event_collapse.zig), [src/daemon/server.zig](../../src/daemon/server.zig)). Reactor 0 flushes elapsed collapse windows on the stats tick into a single `.flood`/`.warn` Event Spine summary, which bypasses collapse and is then counted like any other delivered Event Spine event ([src/daemon/server.zig](../../src/daemon/server.zig)).

## Public status feed: `status.json`

The same chanstats flush also emits `status.json` beside the channel stats ([src/daemon/server.zig](../../src/daemon/server.zig)). `buildStatusJson` is a pure, testable builder that renders into a caller buffer; `writeStatusJson` wraps it with the same atomic status-file writer used elsewhere ([src/daemon/server.zig](../../src/daemon/server.zig)). Each node writes its own file from its own perspective.

```json
{
  "generated_at": 1700000000,
  "network": "Onyx",
  "node": "eshmaki.me",
  "description": "Onyx Server flagship node",
  "icon_url": "https://example.test/onyx.png",
  "discoverable": true,
  "uptime_seconds": 86400,
  "users_online": 214,
  "activity": {
    "channels": 12,
    "messages": 2048,
    "active_channels_24h": 5,
    "last_active": 1700000000,
    "heatline": [12, 30, 41, 27, 98, 132, 119]
  },
  "directory": {
    "listed": true,
    "rank_score": 2678,
    "last_active": 1700000000,
    "entry": {"network": "Onyx", "node": "eshmaki.me",
              "description": "Onyx Server flagship node", "users_online": 214,
              "channels": 12, "messages": 2048, "active_channels_24h": 5}
  },
  "features": {
    "s2s": true,
    "websocket": true,
    "webtransport": true,
    "proxy_protocol": true,
    "media": true,
    "webpush": true,
    "webauthn": true,
    "webhook": true,
    "metrics": true,
    "sts": true,
    "raw_public_key": true,
    "ktls_tx": true,
    "ktls_rx": false,
    "orowasm": false,
    "geo": true,
    "connection_throttle": true,
    "mesh_clone_limit": true,
    "reputation_gate": true,
    "dnsbl": true
  },
  "mesh": {"quorum": true, "partitioned": false, "components": 1},
  "mesh_admission": {"mode": "open", "secured_s2s": false, "require_secured": false,
                     "require_signed_frames": true, "roots": 0,
                     "token_present": false, "min_revocation_epoch": 0},
  "accounts": {"key_transparency": {"enabled": true, "entries": 42, "root": "..."}},
  "history": {"targets": 12, "entries": 2048, "tombstones": 17, "root": "..."},
  "peers": [
    {"name": "peer-a.example", "state": "up", "up": true, "rtt_ms": 38, "since_seconds": 3600},
    {"name": "peer-b.example", "state": "down", "up": false, "rtt_ms": null, "since_seconds": 120}
  ]
}
```

Node identity is `network` plus `node` (`serverName`). `description`, `icon_url`, and `discoverable` are operator-controlled directory metadata from `[network]`; `discoverable` is explicit opt-in, so private meshes can publish local health without asking public crawlers to index them. `uptime_seconds` is derived from `boot_unix`; `users_online` is again `meshUserCount` ([src/daemon/server.zig](../../src/daemon/server.zig)).

The `activity` object is a compact liveness summary from the same bounded `ChanStats` aggregate used by `index.json`, counting only channels that meet the public index threshold and exposing last activity for directory ranking. `activity.heatline` is the same bounded 14-day sparkline shape used by the channel index, aggregated across public-indexed channels only and ordered oldest-to-newest ([src/daemon/chanstats.zig](../../src/daemon/chanstats.zig), [src/daemon/server.zig](../../src/daemon/server.zig)). The `directory` object mirrors the discoverability flag, rank score, last activity, and aggregate entry fields that the `DIRECTORY` command reports without listing channel names ([src/daemon/server.zig](../../src/daemon/server.zig)).

The `features` object is derived from live configuration gates and lets public directory crawlers classify a discoverable node without probing optional listeners or exposing secrets, thresholds, blocklist zones, trusted-proxy addresses, peer lists, keys, or operator-only values. Fronting and anti-abuse entries such as `proxy_protocol`, `connection_throttle`, `mesh_clone_limit`, `reputation_gate`, and `dnsbl` are coarse booleans only ([src/daemon/server.zig](../../src/daemon/server.zig)). The `mesh` envelope reflects the live partition detector through `partition_quorum`, `partition_split`, and `partition_components`; `mesh_admission` reports MeshPass posture without leaking admission token bytes ([src/daemon/server.zig](../../src/daemon/server.zig)).

The `accounts.key_transparency` object exposes the live account credential transparency root/size when services are attached, and `history` reports retained Lotus CHATHISTORY target, entry, and tombstone counts plus a deterministic BLAKE3 root over sorted targets and retained entries ([src/daemon/server.zig](../../src/daemon/server.zig)).

The `peers` array is built from the live `peer_health` registry. For each used slot it emits the peer name, a `state` string mapped by `peerStatusString` (`established` -> `up`, `connecting`/`handshaking` -> `connecting`, `draining`, `down`), a boolean `up`, the smoothed `rtt_ms` (the EWMA `ewma_rtt_ms`, or `null` before the first sample), and `since_seconds`, the time in the current state from `LinkHealth.since` ([src/daemon/server.zig](../../src/daemon/server.zig), [src/daemon/link_health.zig](../../src/daemon/link_health.zig)). Tests cover the feed shape, `directory`, feature booleans, `mesh_admission`, and state mapping ([src/daemon/server.zig](../../src/daemon/server.zig)).

The feed combines peer/partition observations with adopted live state after a
compatible Helix transition; current acceptance must also check its freshness. A preserved mesh link resumes already established, so the fresh-establishment hook never fires for it; `adoptInheritedS2sLink` therefore re-runs the peer-up registration so `status.json` reflects the preserved peer immediately after the upgrade instead of showing an empty peer list ([src/daemon/server.zig](../../src/daemon/server.zig)).

## Cadence and gating

`index.json`, per-channel JSON, and `status.json` write on the shared `[stats] interval` cadence (default 30s), throttled by `chanstats_last_write_ms`, and only when `chanstats_dir` and `crypto_io` are both configured ([src/daemon/server.zig](../../src/daemon/server.zig), [src/daemon/config_format.zig](../../src/daemon/config_format.zig), [src/daemon/server.zig](../../src/daemon/server.zig)). The flush runs inside the timer completion under `world.lockWrite`, so it is serialized against the recorder feed on a multi-reactor node and exactly one chanstats/status flush happens per interval ([src/daemon/server.zig](../../src/daemon/server.zig)).

## Operational example and freshness

```sh
curl --fail http://127.0.0.1:9130/metrics
MESH_SSH_PEER=trev@ircx.us python3 tools/mesh_health_smoke.py http://127.0.0.1:9130/metrics
```

Run from the repository with the authorized peer configuration. A TCP connection
alone is not Mooring establishment: inspect `links_active`, `peers_up` and
`partitioned` together on both nodes. Failed metric rendering retains the previous
valid snapshot; a successful HTTP response therefore does not by itself prove
fresh state. Inspect generation/timestamp and runtime logs as appropriate.

Private service state and public static feeds have different access needs. The
canonical kits use restrictive defaults; public nginx-served stats/backups need
an explicit deployment directory/umask policy. Verify that newly rewritten files
remain readable, not just a preexisting feed, and compare generated timestamps.
The [production paths](../ops/onyx-server-paths.md) and
[acceptance checklist](../ops/mesh-metrics-deploy-checklist.md) record the accepted
fleet policy rather than relying on package defaults.
