# Orochi configuration reference

*Complete operator-facing reference for the daemon TOML format.*

This reference is verified against `Config` and `parseToml` in `src/daemon/config_format.zig:29`, `src/daemon/config_format.zig:310`, and the live boot projection in `src/daemon/config_boot.zig:18`.

Orochi is a pure-Zig 0.17-dev clean-room IRC daemon, built from first principles — not a clone of any prior daemon. The daemon target is 64-bit only (`build.zig:20`, `build.zig:24`), uses implicit TLS rather than STARTTLS (`src/main.zig:216`, `src/main.zig:219`), and uses Zig-native OroStore persistence rather than LMDB (`src/daemon/store.zig:1`, `src/daemon/store.zig:3`).

Use `etc/orochi.reference.toml` as the runnable example and copy from it when building an instance config. Two keys are required: `[node].id >= 1` and `[listen].irc != 0`. Missing either makes `parseToml` fail (`src/daemon/config_format.zig:478`).

## Format rules

The config file is TOML v1.0 (`src/daemon/config_format.zig:3`). Missing keys keep typed defaults (`src/daemon/config_format.zig:4`, `src/daemon/config_format.zig:9`). Integer fields use the ranges in `parseToml`; out-of-range values return `ParseError` (`src/daemon/config_format.zig:542`). Durations are quoted strings using `ms`, `s`, `m`, or `h`, must be non-zero, and are converted to milliseconds (`src/daemon/config_format.zig:556`).

The parser supports string indirection for any string value: `env:NAME` and `@file:path` (`src/daemon/config_format.zig:486`). The CLI boot path wires both resolvers through `ResolverCtx`, so config strings can pull from the process environment or from files relative to the daemon working directory (`src/main.zig:8`, `src/main.zig:23`, `src/main.zig:64`).

The live mapping is conservative: only non-empty or non-zero values overlay onto `server.Config` (`src/daemon/config_boot.zig:15`). TLS and STS are projected separately because `server.Config` does not own those parser structs (`src/daemon/config_boot.zig:92`, `src/daemon/config_boot.zig:119`).

## Required keys

| Key | Requirement | Source |
|---|---:|---|
| `[node].id` | Required, integer >= 1 | `src/daemon/config_format.zig:319`, `src/daemon/config_format.zig:479` |
| `[listen].irc` | Required, port 1..65535 | `src/daemon/config_format.zig:338`, `src/daemon/config_format.zig:480` |

## `[node]`

Source: struct fields at `src/daemon/config_format.zig:50`, parsing at `src/daemon/config_format.zig:318`, S2S identity wiring at `src/main.zig:141`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `id` | integer | `0` before validation | required, `>= 1` | Sovereign node id used by the runtime config (`src/daemon/config_boot.zig:60`) and mesh identity paths. |
| `public_key` | string or null | unset | any string | Parsed and stored for node identity metadata; not directly overlaid by `mapToServerConfig`. |
| `secret_key` | string or null | unset | any string | If set, `main.zig` derives a node identity and enables PQ-secured S2S (`src/main.zig:147`). |

## `[network]`

Source: struct at `src/daemon/config_format.zig:56`, parsing at `src/daemon/config_format.zig:326`, mapping at `src/daemon/config_boot.zig:20`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `name` | string | `"Orochi"` | any string | Network name advertised in ISUPPORT `NETWORK=` and the welcome burst (`src/main.zig:129`). |
| `server_name` | string or null | `"orochi.local"` | any hostname | This node's own server name — the source prefix of all server-originated lines (welcome numerics, the `!weather`/`!news` bot replies, ERROR/PING) and the identity presented to S2S peers. MUST be unique per node in a mesh so replies/identities don't collide (`src/proto/protocol_inventory.zig` `setServerName`). |
| `description` | string or null | unset | any string | Per-node description shown in VERSION/WHOIS and gossiped to mesh peers (`src/daemon/config_format.zig:67`, `src/daemon/config_boot.zig:22`). |
| `icon_url` | string or null | unset | URL string | IRCv3 network icon: when set, advertised as the `NETWORKICON=<url>` ISUPPORT token (clients may render the logo); omitted when unset. NETWORKICON support (`src/daemon/server.zig` `buildIsupportTokens`, `src/daemon/config_boot.zig`). |
| `discoverable` | boolean | `false` | `true`/`false` | Opt-in bit for public discovery directories. `status.json` exports `"discoverable":true` only when enabled, so private meshes are not indexed by accident (`src/daemon/server.zig` `buildStatusJson`). |

## `[motd]`

Source: struct at `src/daemon/config_format.zig:62`, parsing at `src/daemon/config_format.zig:329`, mapping at `src/daemon/config_boot.zig:21`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `text` | string or null | unset | any string | MOTD body served by `MOTD`; newlines are split into MOTD lines. Supports `@file:` at parser level. |

The MOTD is a **per-connection template** expanded by `src/proto/motd_template.zig`
before being split into lines. When omitted or empty, the server serves a
personalized built-in default.

Substitutions use `{key}`; unknown keys are left verbatim, and `{{` / `}}` emit
literal braces. The available keys are `{nick}`, `{account}`, `{host}`,
`{network}`, `{server}`, `{version}`, `{time}`, `{date}`, `{users}`, `{opers}`,
and `{channels}`, plus `{greeting}` (a time-of-day greeting) and `{weather}` /
`{news}` (see `[weather]` / `[news]`).

Conditionals take the form `{if:COND}…{else}…{/if}`, where `COND` is `oper`,
`account`, `secure`, `weather`, or `news` (the last two are true when that line is
available); conditionals nest. For example:
`{if:account}Welcome back, {account}!{else}Please register.{/if}`

## `[admin]`

Source: struct at `src/daemon/config_format.zig:69`, parsing at `src/daemon/config_format.zig:332`, mapping at `src/daemon/config_boot.zig:22`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `location` | string | `"Orochi IRC network"` | any string | ADMIN command location line (`src/daemon/server.zig:916`). |
| `email` | string | `"admin@orochi.local"` | any string | ADMIN command contact email (`src/daemon/server.zig:916`). |

## `[weather]`

Localized weather for the MOTD `{weather}` placeholder. The daemon reads `source`
(a `key=value` file refreshed by an external updater) and renders it in the units
the region uses (`src/proto/weather_units.zig`; `src/daemon/server.zig` `handleMotd`).


| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `enabled` | bool | `false` | — | Enable the `{weather}` MOTD line. |
| `source` | string or null | unset | path | `key=value` file (`temp_c`, `wind_kph`, `precip_mm`, `desc`, `location`, `country`); read fresh per `MOTD`. Supports `@file:`. |
| `location` | string or null | unset | any string | Display location override (else the file's `location`). |
| `country` | string or null | unset | ISO code | Country for unit selection (else the file's `country`). |
| `units` | string or null | unset (`auto`) | `auto`/`metric`/`imperial`/`uk` | Unit override. `auto` = by country: US + territories → °F/mph; GB → °C/mph; else °C/km/h. |

## `[news]`

Headlines for the MOTD `{news}` placeholder.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `enabled` | bool | `false` | — | Enable the `{news}` MOTD line. |
| `source` | string or null | unset | path | File with one headline per line; the first `count` are joined with `" | "`. Supports `@file:`. |
| `count` | integer | `3` | `1..20` | Number of headlines to show. |

## `[geo]`

The live in-channel `!weather`/`!news` bot (see
[commands/fantasy-bot.md](commands/fantasy-bot.md)). When enabled, the daemon
fetches `wttr.in` (weather) and the bundled RSS feeds (news) on a background
thread and serves them to channel fantasy commands. All sources are key-free.

Source: struct at `src/daemon/config_format.zig` (`Geo`), mapping at `src/daemon/config_boot.zig`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `enabled` | bool | `false` | — | Enable the `!weather`/`!news` bot. |
| `news_insecure_tls` | bool | `true` | — | Skip TLS verification for the public read-only news feeds, so the best-effort clean-room TLS reaches more hosts. Weather is plain HTTP and unaffected. |
| `cmd_cooldown_ms` | integer | `3000` | `0..600000` | Minimum interval between bot replies in a single channel (anti-flood). 0 disables. |
| `default_location` | string or null | unset | any string | Fallback `!weather` location when a user has no GeoIP / `location` metadata. |
| `news_cache_dir` | string or null | unset | path | Directory of headline files written by `tools/news_update.sh` (one headline per line, `src_<key>.txt` / `cc_<cc>.txt`). When set, `!news` reads these files instead of fetching live — robust full coverage of every feed regardless of the in-daemon TLS reach. |

## `[listen]`

Source: struct at `src/daemon/config_format.zig:75`, parsing at `src/daemon/config_format.zig:336`, mapping at `src/daemon/config_boot.zig:24`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `host` | string | `"127.0.0.1"` | any string accepted by bind helpers | Bind address for runtime listeners (`src/daemon/config_boot.zig:25`). |
| `irc` | port integer | `0` before validation | required, `1..65535` | Plain IRC listener port. Current parser requires this even for TLS-first deployments. |
| `ws` | port integer | `0` | `0..65535` | Secure-WebSocket browser listener intent. `mapToServerConfig` overlays it into `ws_enabled`/`ws_port`; the listener stands up when TLS certificates are loaded, or with testing-only `ws_plain` (`src/daemon/config_format.zig:462`, `src/daemon/config_boot.zig:45`, `src/main.zig:350`, `src/daemon/server.zig:1862`). |
| `webtransport` | port integer | `0` | `0..65535` | UDP WebTransport/HTTP3 listener port. `mapToServerConfig` overlays it into `webtransport_port`, and `main.zig` starts `webtransport_listener.zig` when TLS certificate/signing material and the IRC listener are available (`src/daemon/config_boot.zig:45`, `src/main.zig:472`, `src/main.zig:494`). |
| `ws_plain` | bool | `false` | `true` or `false` | Testing-only plain WebSocket mode. Only used when `ws` is non-zero; production browser clients require TLS (`src/daemon/config_format.zig:139`, `src/daemon/config_boot.zig:54`). |
| `proxy_protocol` | bool | `false` | `true` or `false` | Enable HAProxy PROXY v1/v2 header consumption before IRC/TLS/WebSocket framing, gated by `trusted_proxies` (`src/daemon/config_format.zig:141`, `src/daemon/config_boot.zig:46`, `src/daemon/server.zig:4107`). |
| `trusted_proxies` | array of strings | `[]` | IP literals | Source IPs allowed to supply PROXY headers; empty disables trusted PROXY handling even if `proxy_protocol` is true (`src/daemon/config_format.zig:144`, `src/daemon/server.zig:3614`, `src/daemon/server.zig:3633`). |
| `s2s` | port integer | `0` | `0..65535` | Server-to-server mesh listener; `0` disables it (`src/daemon/config_boot.zig:26`, `src/daemon/server.zig:1046`). |
| `media` | port integer | `0` | `0..65535` | UDP media transport plane port; `0` means ephemeral (`src/daemon/config_boot.zig:27`, `src/daemon/server.zig:963`). |
| `native_media` | port integer | `0` | `0..65535` | Native KaguraVox/KaguraVis media UDP port; `0` means ephemeral (`src/daemon/config_boot.zig:28`, `src/daemon/server.zig:971`). |
| `media_host` | string | `"127.0.0.1"` | any string | Advertised media candidate host/IP (`src/daemon/config_boot.zig:29`, `src/daemon/server.zig:965`). |

## `[mesh]`

Source: struct at `src/daemon/config_format.zig:109`, parsing at `src/daemon/config_format.zig:346`, secured S2S wiring at `src/main.zig:141`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `realm` | string | `"local"` | any string | Realm fed into node identity derivation for secured S2S (`src/main.zig:149`). |
| `trust_roots` | array of strings | `[]` | hex/base64 Ed25519 public keys | Parsed, mapped to `server.Config.mesh_trust_roots`, decoded at server init, and used as the expected secured-S2S peer key allowlist (`src/daemon/config_format.zig:177`, `src/daemon/config_boot.zig:101`, `src/daemon/server.zig:2272`, `src/daemon/server.zig:3833`). |
| `mesh_pass` | string or null | unset | any string | Shared MeshPass fallback gate. When no signed admission roots are configured, secured-S2S responders constant-time-compare this value against the encrypted M1 bytes; plaintext mesh-session reclaim also uses it as its seal key. |
| `admission_token` | string or null | unset | hex or standard base64 MeshPass token, max 448 decoded bytes | This node's signed MeshPass capability token. When set, secured-S2S initiators send the decoded token bytes inside encrypted Tsumugi M1. |
| `admission_roots` | array of strings | `[]` | hex/base64 Ed25519 public keys | MeshPass token signer roots. When non-empty, server init requires secured S2S identity/crypto and secured-S2S responders require the peer M1 token to verify against one root, match the authenticated peer node key, have relay role, and allow control/sync/irc_app/tsumugi frame families. |
| `admission_min_revocation_epoch` | integer | `0` | `0..u64_max` | Minimum accepted MeshPass token revocation epoch for all configured `admission_roots`. |
| `connect` | array of strings | `[]` | `host:port` strings | Peers auto-dialed at boot and retried while down; IPv6 hosts must be bracketed (`src/daemon/config_format.zig:179`, `src/daemon/config_boot.zig:105`, `src/daemon/server.zig:2249`). |
| `require_secured` | bool | `false` | `true`/`false` | Refuse plaintext S2S: reject inbound plaintext peers and never dial plaintext outbound. When secured S2S is unavailable, all S2S is dropped rather than falling back to clear (`src/main.zig` mesh wiring, `src/daemon/server.zig` handleAccept / initiateS2sConnectToAddr). |
| `require_signed_frames` | bool | `true` | `true`/`false` | For secured S2S peers with a node signing key, require the remote handshake to advertise signed-frame support and reject unsigned direct-owned mesh state frames. Set false only for an explicit mixed-rollout window. |

Plaintext S2S applies when no node identity is configured and `require_secured` is false; secured S2S is enabled by `[node].secret_key` (`src/main.zig:141`, `src/main.zig:153`). Signed MeshPass admission is not available on plaintext S2S: if `admission_roots` is non-empty but the secured S2S identity path is unavailable, server initialization fails closed.

### `[mesh.routing]`

Live Suimyaku route-table and server-registry capacities. These keys are parsed into `Config.mesh.s2s`, projected to `server.Config.s2s_config`, and used for both plaintext S2S links and the secured S2S inner CRDT stream.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `max_nicks` | integer | `4096` | `64..10000000` | Max tracked nicknames in one peer route table. |
| `max_channels` | integer | `1024` | `16..1000000` | Max tracked channels in one peer route table. |
| `max_nodes_per_channel` | integer | `64` | `4..4096` | Max member nodes recorded for one remote channel. |
| `max_name_len` | integer | `64` | `16..256` | Max nick/channel name bytes accepted by the route table. |
| `max_servers` | integer | `512` | `8..65536` | Max servers tracked in the peer server registry. |
| `max_server_name_len` | integer | `63` | `16..255` | Max server-name bytes accepted by the registry. |
| `max_server_desc_len` | integer | `255` | `32..1024` | Max server-description bytes accepted by the registry. |

### `[mesh.gossip]`, `[mesh.sazanami]`, `[mesh.link]`

Live S2S peer-driver tuning. `[mesh.link]` per-link `gossip_fanout` and view-capacity overrides are applied after `[mesh.gossip]` defaults.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `mesh.gossip.round_fanout` | integer | `3` | `1..64` | Gossip round push fanout. |
| `mesh.gossip.max_member_deltas` | integer | `64` | `1..1024` | Max membership deltas packed per gossip payload. |
| `mesh.gossip.max_suspicions` | integer | `64` | `1..1024` | Max suspicion records packed per gossip payload. |
| `mesh.gossip.view_active_capacity` | integer | `8` | `2..64` | Bounded membership-view active capacity. |
| `mesh.gossip.view_passive_capacity` | integer | `64` | `active+1..4096` | Bounded membership-view passive capacity. |
| `mesh.gossip.view_shuffle_active` | integer | `2` | `0..active` | Active entries sampled per shuffle. |
| `mesh.gossip.view_shuffle_passive` | integer | `4` | `0..passive` | Passive entries sampled per shuffle. |
| `mesh.sazanami.suspicion_timeout_ms` | integer | `3000` | `0..120000` | Gossip-side suspect to dead reaping timeout. |
| `mesh.sazanami.witness_quorum` | integer | `2` | `2..16` | Witness quorum for Sazanami dead declaration. |
| `mesh.link.send_credit_bytes` | integer | `65536` | `4096..16777216` | Initial peer-link flow-control send credit. |
| `mesh.link.replay_window` | integer | `64` | `8..4096` | Anti-replay sequence window. |
| `mesh.link.handshake_timeout_ms` | integer | `10000` | `1000..120000` | Peer-link handshake completion timeout. |
| `mesh.link.heartbeat_interval_ms` | integer | `15000` | `1000..120000` | Heartbeat send interval when idle. |
| `mesh.link.idle_timeout_ms` | integer | `45000` | `5000..600000` | No-receive idle timeout before drain. |
| `mesh.link.drain_timeout_ms` | integer | `5000` | `500..60000` | Drain-to-close grace timeout. |
| `mesh.link.gossip_interval_ms` | integer | `1000` | `100..60000` | S2S session gossip-round cadence. |
| `mesh.link.repair_interval_ms` | integer | `2000` | `200..120000` | S2S anti-entropy repair cadence. |
| `mesh.link.gossip_fanout` | integer | `1` | `1..64` | Per-link gossip fanout override. |
| `mesh.link.view_active_capacity` | integer | `4` | `2..64` | Per-link active-view capacity override. |
| `mesh.link.view_passive_capacity` | integer | `8` | `active+1..4096` | Per-link passive-view capacity override. |
| `mesh.link.burst_max_bytes` | integer | `65536` | `4096..16777216` | Max bytes for a serialized full-state CRDT burst. |
| `mesh.link.burst_max_records` | integer | `512` | `16..65536` | Max records in one full-state CRDT burst. |

## `[dnsbl]`

Source: `Dnsbl` struct + parsing in `src/daemon/config_format.zig`; resolver in `src/daemon/dnsbl_resolver.zig`; construction in `src/main.zig`; enforcement in `src/daemon/server.zig` (`enforceDnsbl`).

Connect-time DNS blocklist. Each non-loopback client IP is checked against the configured zones on a background resolver thread (off the accept path), and a listed IP is enforced at registration. **Fail-open**: an IP whose lookup has not resolved by registration — or that no zone lists — is always admitted (a blocklist never refuses an IP it has not confirmed as listed). Operators and loopback are exempt. Uses the system resolver (`/etc/resolv.conf`); inert when that yields no nameservers or no zones are configured.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `enabled` | bool | `false` | `true`/`false` | Master switch; the resolver is built only when enabled with at least one zone. |
| `zones` | array of strings | `[]` | DNSBL zone hostnames | Blocklist zones queried per IP (A-record `127.0.0.x` = listed). The first zone that lists the IP wins, e.g. `["zen.spamhaus.org", "dnsbl.dronebl.org"]`. |
| `action` | string | `"refuse"` | `refuse` / `ward` | Enforcement for a listed IP: `refuse` closes the connection; `ward` additionally records a node-scope Warden ban so the block persists across the IP's reconnects. |

## `[mail]`

Source: `Mail` struct + parsing in `src/daemon/config_format.zig`; sender in `src/daemon/mail_sender.zig`; construction in `src/main.zig`; REGISTER delivery in `src/daemon/server.zig`.

Outbound SMTP submission relay. When enabled with a relay host + sender, account email-verification codes are delivered out-of-band through the relay on a background thread, so REGISTER can verify email ownership. Disabled (default) = no mail (REGISTER records emails as unverified). A submission CLIENT to an existing relay, never the daemon's own MTA.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `enabled` | bool | `false` | `true`/`false` | Master switch; the sender is built only when enabled with `relay_host` + `from`. |
| `relay_host` | string | unset | hostname | Submission relay (resolved via DNS A record). |
| `relay_port` | integer | `587` | `1..65535` | `587` = STARTTLS; `465` = implicit TLS. |
| `starttls` | bool | `true` | `true`/`false` | `false` selects port-465 implicit TLS (TLS from connect). |
| `from` | string | unset | email address | Envelope sender + `From:` header. |
| `user` / `pass` | string or null | unset | relay credentials | Optional AUTH PLAIN credentials. |
| `insecure_skip_verify` | bool | `false` | `true`/`false` | Skip TLS cert verification. **Security:** cert verification is not yet wired, so AUTH to a NON-loopback relay is REFUSED unless this is explicitly set true (a MITM could otherwise capture the submission credentials). Prefer a relay on localhost / a trusted path. |

## `[limits]`

Source: struct at `src/daemon/config_format.zig:115`, parsing at `src/daemon/config_format.zig:354`, mapping at `src/daemon/config_boot.zig:35`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `backlog` | integer | `128` | `1..32767` | Listener backlog (`src/daemon/config_boot.zig:35`). |
| `max_clients` | integer | `1024` | `1..32767` | Reserved connection table size and accept cap (`src/daemon/server.zig:983`). |
| `num_shards` | integer | `1` | `1..max_shards` | Worker reactor shards. **Opt-in: defaults to 1** (single in-line reactor); set `> 1` to run that many reactor threads. `Server.init` allocates the reactor array from the (clamped) shard count, and `runThreaded` spawns one worker per reactor plus the cross-shard delivery fabric when more than one reactor exists. Multi-reactor is correct under the coarse `world.lockWrite` taken once per completion (parallel io_uring I/O, serialized command processing). |
| `handshake_timeout` | duration string | `"30s"` | positive `ms/s/m/h` duration | Registration timeout, mapped to `registration_timeout_ms` (`src/daemon/config_boot.zig:47`). |
| `ping_interval` | duration string | `"2m"` | positive `ms/s/m/h` duration | Idle interval before server PING (`src/daemon/config_boot.zig:48`). |
| `ping_timeout` | duration string | `"1m"` | positive `ms/s/m/h` duration | Grace after PING before disconnect (`src/daemon/config_boot.zig:49`). |
| `topiclen` | integer | `390` | `1..8192` | TOPICLEN advertised and enforced (`src/daemon/server.zig:919`). |
| `awaylen` | integer | `256` | `1..256` | AWAYLEN advertised and enforced (`src/daemon/server.zig:922`). |
| `kicklen` | integer | `307` | `1..400` | KICKLEN advertised and enforced (`src/daemon/server.zig:925`). |
| `nicklen` | integer | `64` | `1..64` | NICKLEN advertised and enforced (`src/daemon/server.zig:928`). |
| `channellen` | integer | `64` | `2..200` | CHANNELLEN advertised and enforced (`src/daemon/server.zig:932`). |
| `maxlist` | integer | `100` | `1..10000` | Per-channel list mode cap for `+b/+e/+I/+Z` (`src/daemon/server.zig:935`). |
| `chanlimit` | integer | `50` | `1..10000` | Max channels per non-oper (`src/daemon/server.zig:938`). |
| `maxtargets` | integer | `4` | `1..64` | Max comma-separated PRIVMSG/NOTICE targets (`src/daemon/server.zig:941`). |
| `keylen` | integer | `64` | `1..64` | KEYLEN advertised; max channel-key (`+k`) length, enforced by the `MODE +k` handler (over-long keys are rejected, never truncated). |
| `modes_per_line` | integer | `4` | `1..20` | Channel-mode changes a client should combine per MODE command, advertised as the `MODES` ISUPPORT token. Clients that honor it (mIRC, HexChat) send one mode/target per line when set to `1` (`src/daemon/server.zig` `buildIsupportTokens`). |
| `monitorlimit` | integer | `128` | `1..100000` | MONITOR target limit (`src/daemon/server.zig:945`). |
| `silencelimit` | integer | `32` | `1..256` | SILENCE mask limit (`src/daemon/server.zig:948`). |
| `max_clones_per_ip` | integer | `0` | `0..65535` | Exact-IP clone cap; `0` disables. Refusals publish `SECURITY` Event-Spine entries visible through `EVENT ADD SECURITY` / `EVENT REPLAY` (`src/daemon/server.zig`). |
| `max_clones_per_net` | integer | `0` | `0..65535` | Network-prefix clone cap; `0` disables. Refusals publish `SECURITY` Event-Spine entries visible through `EVENT ADD SECURITY` / `EVENT REPLAY` (`src/daemon/server.zig`). |
| `nick_delay` | duration string | `"0"` (disabled) | non-negative `ms/s/m/h` duration | Hold a released nick against reuse for this window after its owner exits (anti nick-camping). The owning account may reclaim during the window; opers and `nick_delay_exempt` classes bypass. `0` disables (`src/daemon/config_format.zig`, `src/daemon/nick_delay.zig`). |
| `throttle_connects` | integer | `0` (disabled) | `0..1000000` | Connection-rate throttle: max NEW connections one source IP may open within `throttle_window`; excess is refused at accept and publishes a `SECURITY` Event-Spine entry. Loopback and `trusted_proxies` are exempt (a shared reverse proxy is never throttled as one IP), making it WebSocket-safe. `0` disables (`src/daemon/clone_detect.zig`, `src/daemon/server.zig` `refuseSilentClient`). |
| `throttle_window` | duration string | `"10s"` | positive `ms/s/m/h` duration | Sliding window for `throttle_connects`. |
| `raid_joins` | integer | `0` (disabled) | `0..65535` | Network raid guard: a default join-throttle applied to channels with no explicit `+j` mode. At most `raid_joins` joins per `raid_window` before new joins are denied (`ERR_THROTTLE`) and a one-shot `.flood` Event-Spine raid alert fires. An explicit `+j` always overrides this default; opers and invited users bypass. `0` disables (`src/daemon/world.zig` `throttleAdmit`, `src/daemon/server.zig` `raidAlert`). |
| `raid_window` | duration string | `"10s"` | positive `ms/s/m/h` duration | Window for `raid_joins`. |
| `max_clones_per_ip_net` | integer | `0` (disabled) | `0..65535` | Network-wide (mesh) concurrent connections per source IP: this node plus every peer's count for the same IP, gossiped as a salted hash (raw IPs never cross the wire; needs a shared `[mesh] pass`). Authenticated accounts get +2; `limit_exempt` opers bypass; loopback/trusted proxies exempt (`src/daemon/mesh_clones.zig`, `src/daemon/server.zig`). |
| `reputation_refuse_threshold` | integer | `0` | `0..1000000` | Refuse connects at or above decaying reputation score and publish a `SECURITY` Event-Spine entry; `0` disables (`src/daemon/server.zig`). |
| `reputation_half_life` | duration string | `"1m"` | positive `ms/s/m/h` duration | IP reputation score decay half-life (`src/daemon/config_boot.zig:53`). |
| `sweep_interval` | duration string | `"2s"` | positive `ms/s/m/h` duration | Timeout sweep timer granularity (`src/daemon/config_boot.zig:54`). |
| `sasl_decode_max_bytes` | integer | `512` | `64..512` | Maximum decoded SASL AUTHENTICATE payload bytes for registration SASL and IRCX AUTH. The upper bound is the router's compiled protocol buffer; lower it only for hardened deployments. |

## `[class.<name>]`

Source: `Policy`/`ClassDef` at `src/daemon/conn_class.zig` and `src/daemon/config_format.zig:247`, parsing at `src/daemon/config_format.zig:780`, registry built at `src/daemon/config_boot.zig`.

A **connection class** is a named bundle of per-connection resource, admission, and flood policy, assigned to a client at registration by matching its IP, TLS, account, oper status, and ident/host. The first class in file order whose `match_*` criteria are all satisfied wins; a class with no criteria is a catch-all. Two built-ins always exist as fallbacks: `user` and `server`. Per-class limits **override** the matching `[limits]` / `nick_delay` globals; a `0` value means "inherit the global". Inspect live classes and per-class member counts with `STATS Y`.

Sizes accept `K`/`M`/`G` suffixes (`"1M"` = 1048576). Durations are strings (`"30s"`).

The source-keyed clone caps (`max_per_ip` / `max_per_host` / `max_per_account`) are enforced at registration, so they see the real post-PROXY source IP, account, and host (WebSocket- and proxy-safe). Authenticated accounts receive a **+2 bonus** above the configured value on those dimensions; operators holding the `limit_exempt` privilege bypass every per-class cap.

| Key | Type | Default | What it controls |
|---|---|---:|---|
| `match` | string array | `[]` | Source IP/CIDR list to match (IPv4 + IPv6). |
| `match_tls` | bool | `false` | Match only implicit-TLS connections. |
| `match_account` | bool | `false` | Match only SASL-authenticated connections. |
| `match_oper` | bool | `false` | Match only connections that have opered up. |
| `match_ident` | string (glob) | unset | Glob on the connection's ident/username. |
| `match_host` | string (glob) | unset | Glob on the connection's hostname. |
| `sendq` | size | `1M` (`8M` server) | Outbound SendQ ceiling in bytes. |
| `recvq` | size | `0` (inherit) | Inbound line ceiling in bytes; `0` = physical line buffer. |
| `max_clients` | integer | `0` | Max members of this class; `0` = unlimited. |
| `max_per_ip` | integer | `0` | Max concurrent connections per IP in this class; `0` = unlimited. Skipped for loopback / trusted-proxy sources (WebSocket-safe). |
| `max_per_account` | integer | `0` | Max concurrent connections per account in this class; `0` = unlimited. Always proxy/WebSocket-safe (per-identity). |
| `max_per_host` | integer | `0` | Max concurrent connections per resolved host in this class; `0` = unlimited. Skipped for the loopback host. |
| `max_channels` | integer | `0` | Max channels a member may join; `0` = inherit `chanlimit`. |
| `max_targets` | integer | `0` | Max PRIVMSG/NOTICE targets; `0` = inherit `maxtargets`. |
| `monitor` | integer | `0` | Max MONITOR entries; `0` = inherit `monitorlimit`. |
| `silence` | integer | `0` | Max SILENCE masks; `0` = inherit `silencelimit`. |
| `ping_interval` | duration | `0` (inherit) | Per-class PING interval override. |
| `ping_timeout` | duration | `0` (inherit) | Per-class PING-timeout grace override. |
| `register_timeout` | duration | `0` (inherit) | Per-class registration-handshake timeout override. |
| `flood_lines` | integer | `0` | Per-class command-rate budget driving the runtime flood guard (`src/daemon/flood_guard.zig`): keep-alives are free, PRIVMSG/NOTICE/JOIN are weighted, sustained over-budget traffic accrues excess toward an Excess Flood disconnect. `0` = no flood limit. |
| `flood_window` | duration | `0` (`10s` when only `flood_lines` set) | Window for `flood_lines`. |
| `flood_excess` | integer | `0` (auto) | Excess strikes tolerated before disconnect; `0` = auto (`max(20, 2×flood_lines)`). Each over-budget command adds a strike; strikes decay ~1/s. |
| `flood_targets` | integer | `0` (auto) | Distinct PRIVMSG targets a client may spray per `flood_window` before the spread-spam throttle bites; `0` = auto (`max(8, flood_lines)`). |
| `require_tls` | bool | `false` | Refuse admission unless the connection is TLS. |
| `require_sasl` | bool | `false` | Refuse admission unless SASL-authenticated. |
| `flood_exempt` | bool | `false` | Exempt this class from flood/throttle enforcement. |
| `nick_delay_exempt` | bool | `false` | Let members take a held nick without waiting out nick delay. |

## `[io]`

Source: struct at `src/daemon/config_format.zig:153`, parsing at `src/daemon/config_format.zig:377`, mapping at `src/daemon/config_boot.zig:55`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `ring_entries` | integer | `32` | `8..4096` | io_uring SQ entries per reactor (`src/daemon/server.zig:981`). |
| `cqe_batch` | integer | `256` | `16..4096` | Maximum io_uring completion events reaped per event-loop drain. Larger values improve burst throughput; smaller values cap per-iteration work. |

## `[reputation]`

Source: struct at `src/daemon/config_format.zig:158`, parsing at `src/daemon/config_format.zig:380`, mapping at `src/daemon/config_boot.zig:56`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `registration_timeout_penalty` | float | `50.0` | `0..1000` | Reputation penalty for unfinished registration (`src/daemon/server.zig:1020`). |
| `clone_refuse_penalty` | float | `25.0` | `0..1000` | Reputation penalty for clone-limit refusal (`src/daemon/server.zig:1022`). |

## `[accounts]`

Source: struct `Accounts` in `src/daemon/config_format.zig`, parsing in `src/daemon/config_format.zig`, services construction in `src/main.zig`.

Durable account-services policy. These settings take effect when `[sasl].account_db` is configured and the daemon opens the account store.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `pbkdf2_rounds` | integer | `100000` | `10000..10000000` | PBKDF2-HMAC-SHA256 iteration count for new password hashes and password verification timing equalization. |
| `password_min_len` | integer | `8` | `1..64` | Minimum length for newly registered or changed account passwords. |
| `password_max_len` | integer | `512` | `64..4096` | Maximum length for newly registered or changed account passwords. Existing account login keeps the historical verifier bounds to avoid lockout after tightening policy. |

## `[bouncer]`

Source: struct `Bouncer` in `src/daemon/config_format.zig`, parsing in `parseToml`, mapping in `src/daemon/config_boot.zig`, live Tegami store construction in `src/daemon/server.zig`.

Per-account bouncer/offline-message retention limits. These values construct the live Tegami offline-mail store at daemon boot.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `tegami_text_max_len` | integer | `400` | `64..2048` | Max offline DM body length accepted by `TEGAMI SEND`. |
| `tegami_from_max_len` | integer | `64` | `16..128` | Max sender label length stored on an offline DM. |
| `tegami_mailbox_depth` | integer | `64` | `8..1024` | Per-account offline mailbox depth before new Tegami delivery fails closed. |
| `tegami_max_accounts` | integer | `65536` | `1024..1048576` | Max distinct accounts with live offline mailboxes. |

## `[filter]`

Source: struct `Filter` in `src/daemon/config_format.zig`, parsing in `parseToml`, mapping in `src/daemon/config_boot.zig`, live Koshi content-filter construction in `src/daemon/server.zig`.

Oper-managed Koshi moderation filter sizing. These values construct the live content-filter store at daemon boot.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `koshi_max_patterns` | integer | `256` | `16..4096` | Max oper-curated Koshi filter patterns. |
| `koshi_pattern_max_len` | integer | `256` | `16..1024` | Max length of a single Koshi pattern. |

## `[storage]`

Source: `store.Config` in `src/daemon/store.zig`, parsing in `src/daemon/config_format.zig`, account-store open in `src/main.zig`.

OroStore append-only WAL/snapshot and recent-mutation feed limits. These values are applied when `[sasl].account_db` opens the durable account store.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `max_record_bytes` | integer | `16777216` | `65536..268435456` | Max single WAL/snapshot record payload size. |
| `max_wal_bytes` | integer | `268435456` | `1048576..4294967296` | Max WAL size accepted on replay; long-lived stores compact at half this budget. |
| `changefeed_capacity` | integer | `64` | `8..4096` | Bounded recent-mutation feed capacity for service-sync consumers. |

## `[sessions]`

Source: struct at `src/daemon/config_format.zig:164`, parsing at `src/daemon/config_format.zig:384`, mapping at `src/daemon/config_boot.zig:58`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `max_accounts` | integer | `65536` | `1..4294967295` | Multi-session/bouncer account registry size (`src/daemon/server.zig:1024`). |
| `max_per_account` | integer | `64` | `1..1000000` | Max live sessions per account (`src/daemon/server.zig:1024`). |

## `[ircv3]`

Source: struct `Ircv3` in `src/daemon/config_format.zig`, parsing in `parseToml`, mapping in `src/daemon/config_boot.zig`, CAP advertisement in `src/daemon/dispatch.zig`, and live enforcement in `src/daemon/server.zig`.

Live IRCv3 protocol limits. The multiline byte/line values are advertised in CAP LS 302 as `draft/multiline=max-bytes=...,max-lines=...`; all four values are enforced by the inbound multiline reassembler.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `multiline_max_bytes` | integer | `40000` | `4096..262144` | Max reassembled draft/multiline body bytes accepted per batch. |
| `multiline_max_lines` | integer | `64` | `2..1024` | Max PRIVMSG/NOTICE chunks accepted in one multiline batch. |
| `multiline_ref_len` | integer | `64` | `1..128` | Max draft/multiline batch reference length. |
| `multiline_target_len` | integer | `128` | `8..255` | Max target length accepted in a multiline batch open/chunk. |

## `[history.search]`

Source: struct `History` in `src/daemon/config_format.zig`, parsing in `parseToml`, mapping in `src/daemon/config_boot.zig`, live `SearchIndex` construction in `src/daemon/server.zig`.

Live draft/search inverted-index sizing. These values construct the in-memory `SEARCH` index used by the daemon's CHATHISTORY-backed search path at boot.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `max_words` | integer | `8192` | `256..1048576` | Max distinct normalized words held in the live search index. |
| `max_ids_per_word` | integer | `1024` | `16..65536` | Max message ids retained per indexed word. |
| `max_token_bytes` | integer | `64` | `8..256` | Max bytes in a normalized search token accepted for indexing/search. |

## `[media]`

Source: struct at `src/daemon/config_format.zig:446`, parsing at `src/daemon/config_format.zig:1174`, mapping at `src/daemon/config_boot.zig:85`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `enabled` | bool | `false` | `true` or `false` | Enables or disables the media feature surface through `server.Config.media_enabled` and `disabled_features` (`src/daemon/config_format.zig:389`, `src/daemon/config_boot.zig:30`). |
| `max_upload_bytes` | integer | `16777216` | `0..1073741824` | Runtime upload cap applied to both media planes through `server.Config.media_max_upload_bytes` (`src/daemon/config_boot.zig:61`, `src/daemon/server.zig:2399`, `src/daemon/server.zig:2401`). |
| `max_frame_bytes` | integer | `65536` | `0..16777216` | Runtime frame cap applied to SFU/native media with each transport's protocol maximum as an upper bound (`src/daemon/config_boot.zig:62`, `src/daemon/server.zig:2397`, `src/daemon/server.zig:2400`). |
| `max_participants` | integer | `64` | `1..256` | Max participants per SFU room (`Room`), enforced at join. The inline roster ceiling is 256; the native (KaguraVox/KaguraVis) call leg caps at 64. Default 64 preserves prior behavior (`src/daemon/media_room.zig`, `src/daemon/config_boot.zig`). |
| `reorder_window_frames` | integer | `64` | `1..64` | Kagura media reorder/reassembly window in frames, clamped to the comptime `window_cap` (64). Default 64 (`src/substrate/kagura_frame.zig`, `src/daemon/server.zig` `mediaReassemblyConfig`). |
| `captions_max_text_bytes` | integer | `400` | `64..4000` | Max caption text length accepted by `MEDIA TRANSCRIPT PUSH`. |
| `captions_max_speaker_bytes` | integer | `64` | `16..256` | Max speaker label length stored in the live transcript ring. |
| `captions_ring_depth_per_channel` | integer | `128` | `16..4096` | Retained captions per channel before FIFO eviction. |
| `captions_max_channels` | integer | `4096` | `64..1048576` | Max channels with a live transcript ring. |
| `media.sfu.max_breakout_label_bytes` | integer | `32` | `8..256` | Max `MEDIA BREAKOUT` label bytes retained by `MediaRooms`; longer labels are truncated in room state. |
| `media.pins.max_per_channel` | integer | `50` | `1..1024` | Max msgids accepted in the live `PINS` channel prop. |
| `media.pins.max_msgid_bytes` | integer | `64` | `8..256` | Max bytes per msgid token accepted in the live `PINS` channel prop. |
| `media.reactions.max_token_bytes` | integer | `32` | `8..256` | Max `MEDIA REACT` token bytes; reactions are ephemeral event broadcasts. |
| `native_media_require_mac` | bool | `false` | `true` or `false` | Require an authenticated per-datagram MAC on native (KaguraVox/KaguraVis) media. `false` accepts untagged datagrams (back-compat); `true` drops untagged/bad-tag datagrams before the SFU learns the sender. HMAC-SHA256-128 keyed from the per-stream PRF capability; needs matching client support (`src/daemon/config_format.zig:462`, `src/daemon/config_boot.zig:101`, `src/substrate/kagura_frame.zig`). |
| `ws_media_relay` | bool | `false` | `true` or `false` | Relay browser media datagrams (binary WebSocket frames) between a channel's call participants (SFU). Off by default; opt-in. When on, `MEDIA JOIN` hands each participant a per-stream MAC key over the authenticated WS as `EVENT <nick> MEDIA MACKEY <#chan> <base64>`, and each datagram is lenient-verified before fan-out to same-node call members, including members homed on other reactor shards through the cross-shard fabric (`src/daemon/config_format.zig:466`, `src/daemon/config_boot.zig:102`, `src/daemon/server.zig` `handleWsMediaDatagram`, `src/substrate/kagura_frame.zig`). |
| `ws_media_require_mac` | bool | `false` | `true` or `false` | Require a valid per-stream MAC tag on every browser media datagram. `false` relays untagged datagrams (a present tag must still verify); `true` drops untagged/bad-tag datagrams. Same `native_stream_key`-derived `(channel, participant)` key as the native leg (`src/daemon/config_format.zig:470`, `src/daemon/config_boot.zig:103`). |
| `dtls_srtp` | bool | `false` | `true` or `false` | Enable DTLS-SRTP termination on the UDP media plane. Off by default; when enabled the media plane exposes a DTLS fingerprint for `MEDIA` negotiation and rejects malformed or unavailable fingerprint offers fail-closed (`src/daemon/config_format.zig:474`, `src/daemon/config_format.zig:1191`, `src/daemon/config_boot.zig:104`, `src/daemon/server.zig:26456`). |
| `dtls13` | bool | `false` | `true` or `false` | Additionally enable the DTLS 1.3 engine on the media plane. This is parsed independently, but only has an effect with `dtls_srtp` enabled (`src/daemon/config_format.zig:480`, `src/daemon/config_format.zig:1192`, `src/daemon/config_boot.zig:105`, `src/daemon/server.zig:3643`). |
| `stun_host` | string or null | unset | any string | Optional STUN host mapped to media discovery config (`src/daemon/config_format.zig:483`, `src/daemon/config_boot.zig:106`, `src/daemon/server.zig:3623`). |
| `stun_port` | port integer | `0` | `0..65535` | STUN port mapped when non-zero (`src/daemon/config_format.zig:484`, `src/daemon/config_format.zig:1219`, `src/daemon/config_boot.zig:107`). |

## `[stats]`

Source: struct at `src/daemon/config_format.zig:180`, parsing at `src/daemon/config_format.zig:394`, mapping at `src/daemon/config_boot.zig:32`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `dir` | string | `""` | any string | Directory for `stats.json` and `index.html`; empty disables (`src/daemon/server.zig:958`). |
| `channel_dir` | string | `""` | any string | Directory for channel-stats JSON plus the durable `.chanstats.snapshot`; empty disables chanstats publication. |
| `interval` | duration string | `"30s"` | positive `ms/s/m/h` duration | Minimum interval between stats writes (`src/daemon/config_format.zig:395`). |

## `[backup]`

Source: struct at `src/daemon/config_format.zig`, parsing in `parseToml`, mapping at `src/daemon/config_boot.zig`, writer at `src/daemon/server.zig`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `dir` | string | `""` | any string | Directory for timestamped local backup sets. Empty disables backup publication. |
| `interval` | duration string | `"24h"` | positive `ms/s/m/h` duration | Minimum interval between backup sets. Reactor 0 compacts the account store under the services lock, copies the account snapshot and chanstats snapshot when present, and writes `latest.json`. |

## `[metrics]`

Source: struct at `src/daemon/config_format.zig:263`, parsing at `src/daemon/config_format.zig:562`, mapping at `src/daemon/config_boot.zig:67`, live HTTP endpoint at `src/daemon/metrics_http.zig:1`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `listen` | port integer | `0` | `0..65535` | Live Prometheus `/metrics` HTTP listener port. `0` or absent disables the endpoint (`src/daemon/config_boot.zig:69`, `src/daemon/server.zig:2443`). |
| `bind` | string | `"127.0.0.1"` | IPv4 literal | Bind address for the metrics listener. Defaults to loopback; invalid/non-IPv4 values keep the secure loopback default (`src/daemon/config_boot.zig:71`, `src/daemon/config_boot.zig:112`). |

## `[geoip]`

Source: struct at `src/daemon/config_format.zig:188`, parsing at `src/daemon/config_format.zig:397`, mapping at `src/daemon/config_boot.zig:34`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `database` | string | `""` | any string | MaxMind `.mmdb` path; empty disables GeoIP (`src/daemon/server.zig:955`). |
| `asn_database` | string | `""` | any string | Optional separate ASN `.mmdb` path for WHOIS AS-number/org enrichment (`src/daemon/config_format.zig:277`, `src/daemon/config_boot.zig:74`). |

## `[sasl]`

Source: struct at `src/daemon/config_format.zig:193`, parsing at `src/daemon/config_format.zig:400`, account-store boot at `src/main.zig:160`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `enabled` | bool | `false` | `true` or `false` | Explicit `false` disables SASL even when `account_db` is configured. If omitted, older `account_db`-only configs still enable the account store (`src/daemon/config_format.zig:282`, `src/daemon/config_boot.zig:102`, `src/main.zig:255`). |
| `realm` | string or null | unset | any string | Informational SASL/account realm stored in runtime config; current wire mechanisms do not emit it in challenges (`src/daemon/config_format.zig:288`, `src/daemon/config_boot.zig:103`, `src/daemon/server.zig:1387`). |
| `account_db` | string or null | unset | path string | Opens the OroStore account backend; when opened, PLAIN, SCRAM-SHA-256, SCRAM-SHA-512, and EXTERNAL are wired. With the store open, SESSION-TOKEN (opaque reconnect tokens, issued only over TLS) is available, and SCRAM-SHA-512-PLUS is offered to TLS clients via the RFC 9266 `tls-exporter` channel binding (`src/main.zig:178`, `src/main.zig:193`). |
| `allow_anonymous` | bool | `false` | `true` or `false` | Allow SASL ANONYMOUS (RFC 4505) guest logins. Default off (spam vector). A guest binds no account, is left `+r`-unset, and receives no oper/services privileges (`src/daemon/config_format.zig:297`). |
| `oauth_hmac_key` / `oauth_jwks_file` / `oauth_pubkey` | string or null | unset | secret / path | OAUTHBEARER (RFC 7628) JWT verification key. Exactly one source enables OAUTHBEARER: an HS256 shared secret, an RS256/ES256 JWKS file, or an RS256/ES256 PEM/DER public key. Unset = OAUTHBEARER is not advertised (`src/daemon/oauth_jwt.zig`, `src/daemon/config_format.zig:306`). |
| `oauth_issuer` / `oauth_audience` / `oauth_account_claim` | string or null | unset / `"sub"` | any string | When set, `iss`/`aud` are required to match; `oauth_account_claim` selects the JWT claim mapped to the account (default `sub`). OAuth identities are federated and are never auto-elevated to oper (`src/daemon/config_format.zig:302`). |

## `[acme]`

Source: struct `Acme` at `src/daemon/config_format.zig:351`, parsing at `src/daemon/config_format.zig:625`, scheduler at `src/daemon/acme_renewal.zig`, reactor-0 hot-swap at `src/daemon/server.zig` (`maybeReloadAcmeTls`).

Automatic in-daemon TLS certificate renewal (Linux only). A background thread checks the `[tls].cert_path` leaf expiry every `check_interval`; within `renew_before_days` of `notAfter` it issues a new certificate off the reactor and signals reactor 0 to hot-swap it without a restart. This requires `[tls]` with `cert_path` and `key_path`. Changing those paths via live REHASH while `[acme]` is enabled is unsupported.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `enabled` | bool | `false` | `true` or `false` | Enable in-daemon ACME renewal. |
| `directory_url` | string | Let's Encrypt prod | any URL | ACME directory endpoint. |
| `domain` | string or null | unset | hostname | Certificate domain to renew. |
| `contact` | string or null | unset | `mailto:…` | ACME account contact. |
| `renew_before_days` | integer | `30` | `1..89` | Renew when the leaf is within N days of `notAfter`. |
| `check_interval` | duration string | `"12h"` | positive `ms/s/m/h` duration | How often to check the leaf expiry. |
| `ca_bundle_path` | string | `/etc/ssl/certs/ca-certificates.crt` | file path | PEM trust bundle used to verify the ACME API endpoint. Also used by Web Push trust-anchor loading. |
| `ca_bundle_max_bytes` | integer | `4194304` | `65536..67108864` | Maximum CA bundle file size read into memory. |
| `challenge_port` | integer | `14402` | `1..65535` | Loopback HTTP-01 listener port that nginx proxies to. |
| `max_steps` | integer | `64` | `8..1024` | ACME state-machine step limit before aborting. |
| `debug` | bool | `false` | `true` or `false` | Log every ACME HTTP exchange; error bodies are still logged when false. |
| `max_response_bytes` | integer | `262144` | `16384..4194304` | Maximum decrypted HTTP response body accepted from the ACME server. |
| `error_body_preview_bytes` | integer | `512` | `0..4096` | Maximum RFC 7807 problem-body bytes included in ACME error logs. |
| `resolv_conf_max_bytes` | integer | `65536` | `4096..1048576` | Maximum `/etc/resolv.conf` bytes read by the built-in resolver. |
| `dns_port` | integer | `53` | `1..65535` | UDP port used for ACME endpoint A-record lookups. |
| `http01_listen_backlog` | integer | `16` | `1..1024` | TCP listen backlog for the loopback HTTP-01 listener. |
| `http01_accept_poll` | duration string | `"250ms"` | `50ms..5s` | Accept-loop wake interval used to re-check shutdown. |
| `http01_conn_read_timeout` | duration string | `"5s"` | `1s..60s` | Per-challenge-connection read timeout. Whole seconds only. |

## `[ocsp]`

OCSP stapling. Source: struct `Ocsp` at `src/daemon/config_format.zig:766`, parsing at `src/daemon/config_format.zig:1384`. When enabled, a background worker keeps a fresh OCSP staple for the served leaf certificate; the responder is contacted only when the cached staple is stale or missing.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `enabled` | bool | `false` | `true` or `false` | Master switch for OCSP staple fetching/attachment. |
| `check_interval` | duration string | `"15m"` | duration | How often the worker wakes to check whether a (re)fetch is due (parsed via `durationMs`, `src/daemon/config_format.zig:1385`). |

## `[cloak]`

Source: struct `Cloak` at `src/daemon/config_format.zig:611`, parsing at `src/daemon/config_format.zig:1272`, boot wiring at `src/main.zig:468`. See [Host cloaking](host-cloaking.md) for the full model.

The cloak key is not a bare `SHA256(secret)`: `secret` (and `previous_secret`) are stretched through **argon2id** (memory-hard KDF, 64 MiB / t=2 / p=1) with a fixed domain-separation salt `orochi/cloak-key/argon2id/v1`, so a low-entropy operator passphrase is not offline-brute-forceable against the fully-enumerable IPv4 input space (`src/main.zig:491`, `src/crypto/argon2_kdf.zig:117`, `src/crypto/argon2_kdf.zig:130`). Derivation is deterministic (fixed salt), so cloaked hosts stay stable across restarts and identical mesh-wide.

**Mesh requirement:** every mesh node MUST share one `[cloak] secret`. A meshed node with no shared secret generates a per-boot random key, so cloaked hosts differ per node and change on restart — `*!*@<cloak>` and subnet WARD bans neither federate nor persist. `--check-config` **hard-errors** (`meshCloakSecretMissing`) when `[mesh] connect` OR `[listen] s2s` is set without a `[cloak] secret` (`src/daemon/config_format.zig:829`, `src/main.zig:192`).

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `secret` | string or null | unset | any string | argon2id-derived stable hostname cloak key. If absent, `main.zig` generates a per-boot random key so real IPs are never shown by default (`src/main.zig:494`, `src/main.zig:531`). |
| `previous_secret` | string or null | unset | any string | Prior cloak key kept live across a `secret` rotation (derived through the same argon2id path). New cloaks use `secret`; WARD host/mask matching additionally tests the cloak under this key, so bans written before the rotation keep matching during a grace window. Drop once old bans have aged out (`src/main.zig:508`). |
| `suffix` | string or null | unset | any string | Optional network-identifying suffix for generated cloak hosts (`src/daemon/config_format.zig:622`). |
| `mode` | string or null | `hierarchical` | `hierarchical` \| `opaque` | IP cloak granularity. `hierarchical` emits subnet-bannable prefix tokens plus `a<asn>.<cc>` geo labels; `opaque` emits a single token over the whole address (nothing leaks — not even country/ASN or subnet membership — but it cannot be subnet-banned) (`src/daemon/config_format.zig:626`, `src/main.zig:523`). |
| `account_cloak` | bool | `false` | `true` \| `false` | When true, a logged-in client's visible host becomes the friendly `<account>.users.<suffix>`, stable across IPs and devices. Explicit VHOST personas still override it (`src/daemon/config_format.zig:634`). |
| `anon_epoch_secs` | integer (seconds) | `86400` | `0..31536000` | Anonymous-client cloak rotation cadence. When non-zero, an **unauthenticated** client gets an OPAQUE cloak salted by the current wall-clock epoch `floor(now/anon_epoch_secs)`, so a static-IP anonymous user is neither linkable across epochs nor leaks subnet co-membership. Logged-in clients are unaffected (they keep the stable account/hierarchical cloak). Wall-clock based so every mesh node agrees on the epoch. `0` disables rotation (pre-2026-07 behavior). Default 86400 (24 h) (`src/daemon/config_format.zig:646`, `src/daemon/config_format.zig:1279`, `src/daemon/server.zig:5825`). |

## `[webpush]`

Source: struct at `src/daemon/config_format.zig:495`, parsing at `src/daemon/config_format.zig:866`.

Browser [Web Push](web-push.md) delivery for offline direct messages (triggered by the `tegami` away-delivery path). Off by default; enabling it needs an account store (subscriptions are account-scoped) and outbound HTTPS (it reuses the same trust anchors as ACME). The VAPID public key is advertised to clients through an ISUPPORT `VAPID=` token; lifecycle visibility is published on the Event Spine.

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Master switch. When off, the `WEBPUSH` command is not registered. |
| `subject` | string | `mailto:ops@eshmaki.me` | VAPID JWT `sub` claim (RFC 8292) — an operator contact the push service may use to reach the node. |
| `vapid_key_path` | string | `orochi-webpush-vapid.key` | Where the ES256 VAPID secret persists. **Rotating it invalidates every stored browser subscription** (the advertised public key changes). |

## `[webhook]`

Source: struct `Webhook` in `src/daemon/config_format.zig`, parsing in `parseToml`, boot projection in `src/daemon/config_boot.zig`, HTTP listener in `src/daemon/webhook_http.zig`, payload rendering in `src/daemon/webhook_render.zig`, and live channel injection in `src/daemon/server.zig` `handleWebhook` / `injectWebhookPost`.

Incoming channel webhooks are off by default. When enabled, channel operators and network operators can run `WEBHOOK CREATE <#channel> [name]` to mint a one-time URL of the form `/api/webhooks/<id>/<token>`. The token is stored only as a hash; `LIST` never reveals it again, and `DELETE <id>` removes the binding.

The listener is a single-threaded, one-connection-at-a-time HTTP/1.1 accept loop and requires a valid `Content-Length` on every POST body — a body-bearing request without one is rejected immediately with `411 Length Required` rather than being awaited. Because a stalled or dribbled request still occupies the loop for up to `conn_read_timeout_sec` (5s), a non-loopback `bind` MUST sit behind a buffering reverse proxy (nginx/Caddy) that terminates TLS and always forwards a complete, `Content-Length`-framed request. Keep the default loopback bind unless such a proxy is in front.

The listener accepts sanitized JSON payloads with `content`, `embeds`, Discord-style `components`, and Block-Kit-lite `blocks`. Supported block fallback types are `header`, `section`, `context`, and `actions`; buttons and select menus always degrade to bounded text lines such as `[button] Open <https://...>` and `[select] Promote to: staging, prod`. For clients that negotiated `message-tags`, block action metadata is also delivered as a client-only IRCv3 tag: `+orochi/block-kit=v1|b:<label>,u:<url>|s:<label>,o:<opt>~<opt>`, with tag values percent-encoded and capped inline. CR/LF/NUL/control bytes are stripped before reactor handoff, and each post is capped by `max_body_bytes`, rendered line limits, metadata tag limits, and per-binding rate limits.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `enabled` | bool | `false` | `true` or `false` | Master switch. When false the listener never binds and `WEBHOOK` is not registered. |
| `listen` | port integer | `0` | `0..65535` | Plain HTTP listener port. `0` binds an OS-ephemeral port when enabled; set a fixed loopback port behind a TLS reverse proxy in production. |
| `bind` | string or null | unset (`127.0.0.1`) | IPv4 literal | Bind address for the webhook listener. Invalid/non-IPv4 values keep the loopback default. |
| `store_path` | string or null | unset | path | TSV persistence for webhook bindings across restart and USR2. Unset keeps runtime bindings in memory only. |
| `max_body_bytes` | integer | `8192` | `1..1048576` | Maximum accepted JSON body bytes; larger requests receive 413. |
| `rate_per_min` | integer | `60` | `0..1000000` | Per-binding sustained request rate. `0` disables rate limiting. |
| `rate_burst` | integer | `10` | `1..1000000` | Per-binding token-bucket burst capacity. |
| `public_url_base` | string or null | unset | URL origin | Public reverse-proxy base used in `WEBHOOK CREATE` replies. When unset, replies derive `http://<bind>:<port>`. |

## `[tls]`

Source: struct at `src/daemon/config_format.zig:208`, parsing at `src/daemon/config_format.zig:408`, TLS boot projection at `src/daemon/config_boot.zig:97`, live listener at `src/main.zig:216`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `enabled` | bool | `false` | `true` or `false` | Enables the implicit TLS listener when certificate loading/bootstrap succeeds (`src/main.zig:222`). |
| `port` | port integer | `6697` | `0..65535` | TLS listener port; `0` binds ephemerally if TLS is enabled (`src/daemon/server.zig:1499`). |
| `cert_path` | string or null | unset | path string | Leaf certificate path; paired with `key_path` (`src/daemon/config_format.zig:411`). |
| `key_path` | string or null | unset | path string | Private key path; paired with `cert_path` (`src/daemon/config_format.zig:412`). |
| `dns_name` | string | `"localhost"` | any string | CN/SAN for self-signed bootstrap cert when files are absent (`src/main.zig:224`). |
| `request_client_cert` | bool | `false` | `true` or `false` | Requests client certs so SASL EXTERNAL can match cert fingerprints (`src/main.zig:234`, `src/daemon/sasl_bridge.zig:70`). |
| `enable_tls12` | bool | `false` | `true` or `false` | Also accept hardened TLS 1.2 ECDHE-AEAD clients through version dispatch. Off by default (`src/daemon/config_format.zig:324`, `src/daemon/config_boot.zig:174`, `src/main.zig:347`). |
| `enable_resumption` | bool | `false` | `true` or `false` | Enable TLS 1.3 PSK session tickets/resumption on the live TLS listener (`src/daemon/config_format.zig:330`, `src/daemon/config_boot.zig:175`). |
| `early_data_max_size` | integer | `0` | `0..4294967295` | Maximum TLS 1.3 0-RTT bytes advertised in issued tickets. `0` disables early data while still allowing resumption (`src/daemon/config_format.zig:334`, `src/daemon/config_boot.zig:176`). |
| `raw_public_key` | bool | `false` | `true` or `false` | Enables RFC 7250 raw-public-key negotiation. When true, a client that offers `server_certificate_type=RawPublicKey` may receive the active leaf's bare SubjectPublicKeyInfo instead of the X.509 chain. With `request_client_cert = true`, a client that offers `client_certificate_type=RawPublicKey` may present a bare SPKI for SASL EXTERNAL CertFP. Default off keeps X.509 handshakes byte-identical. |
| `ktls` | string | `"off"` | `"off"`, `"tx"`, `"txrx"` | Requests Linux kTLS offload on the implicit TLS listener. The daemon only enables offload when the running kernel advertises the TLS ULP; otherwise TLS remains userspace. |
| `[[tls.sni]]` | array of tables | empty | `server_names`, `cert_path`, `key_path` | Adds SNI-selectable certificate material. Each entry is loaded with the same cert/key loader as the default leaf, validated before the listener is wired, and handed to the TLS engine as a `tls_server.SniCert`. A bad entry disables TLS startup rather than running a half-configured listener. |
| `[[tls.ech_keys]]` | array of tables | empty | `config_path` plus 64-hex-byte `private_key` | Opt-in server ECH acceptance. `config_path` is a single-entry ECHConfigList file; `private_key` is the matching X25519 HPKE recipient key. Bad files or key/config mismatches disable TLS at boot before the listener is wired. Empty keeps ECH off and preserves existing ClientHelloOuter behavior. |

Orochi has no STARTTLS path. TLS is a separate implicit-TLS listener (`src/main.zig:216`, `src/daemon/dispatch.zig:369`).

## `[sts]`

Source: struct at `src/daemon/config_format.zig:229`, parsing at `src/daemon/config_format.zig:416`, STS boot projection at `src/daemon/config_boot.zig:68`, live advertisement at `src/main.zig:242`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `enabled` | bool | `false` | `true` or `false` | Enables IRCv3 STS advertisement only if a TLS listener is live (`src/main.zig:247`, `src/main.zig:248`). |
| `duration` | integer | `2592000` | `0..4294967295` | STS max-age in seconds (`src/main.zig:249`). |
| `port` | port integer | `6697` | `0..65535` | Secure port advertised in the STS policy (`src/main.zig:251`). |
| `preload` | bool | `false` | `true` or `false` | Adds `preload` to the STS value (`src/main.zig:252`). |

STS is omitted entirely unless a policy is present; this prevents clients from being stranded by a nonexistent TLS listener (`src/daemon/dispatch.zig:369`).

## `[webauthn]`

Passkey (WebAuthn/FIDO2) registration and passwordless login (the `WEBAUTHN` command). Source: struct `Webauthn` at `src/daemon/config_format.zig:796`, parsing at `src/daemon/config_format.zig:1120`. The command fails closed until BOTH `rp_id` and one or more `origins` are configured — a passkey ceremony must be bound to the deploy's exact domain.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `rp_id` | string or null | unset | registrable domain | Relying Party ID (e.g. `chat.example`). Passkeys are scoped to this; it must match the site the client's `navigator.credentials` call runs on. Null ⇒ WEBAUTHN unavailable. |
| `origins` | array of strings | `[]` | `https://…` origins | Allowed top-level origins. A ceremony whose clientDataJSON `origin` is not listed is rejected. Empty ⇒ WEBAUTHN unavailable. |
| `require_uv` | bool | `false` | `true` or `false` | Require the User-Verified (UV) flag (not just User-Present) in authenticatorData for both registration and login. When off, wire behaviour is byte-identical to the UP-only default. |
| `require_attestation` | bool | `false` | `true` or `false` | Require a verified attestation statement at registration (`fmt` may not be `none`). The attestation signature is verified fail-closed, but the x5c leaf is NOT anchored to a bundled FIDO metadata root — this proves tamper-evidence, not hardware provenance. When off, registration keeps trust-on-first-use. |

## `[oper]`

Operator subsystem settings, distinct from the per-operator `[[opers]]` bindings
below. Source: struct `OperSection` at `src/daemon/config_format.zig:238`, parsing at
`src/daemon/config_format.zig:1035`, mapping at `src/daemon/config_boot.zig`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `grants_path` | string or null | unset | path | File for persisting runtime `GRANT`/`REVOKE` operator grants. When set, active grants are written here on change and reloaded at boot, so runtime-granted opers survive a restart; revoked accounts are dropped. See [commands/oper-moderation.md](commands/oper-moderation.md#grant). |
| `event_history_path` | string or null | unset | path | File for persisting the Event Spine history ring so `EVENT REPLAY` survives a USR2 hot-upgrade and a cold restart. Loaded at boot and rewritten by reactor 0 on the stats cadence; unset keeps the history per-process-lifetime (`src/daemon/config_format.zig:244`, `src/daemon/config_format.zig:1036`, `src/daemon/server.zig:23138`, `src/daemon/server.zig:23151`). |
| `auto_override` | bool | `false` | — | Auto-enable the `+j` override umode on elevation for any operator holding the `oper_override` privilege, so admins get full channel authority (KICK/MODE/TOPIC/PROP/…) without a manual `/mode +j`. `false` keeps override an explicit, audited opt-in (`src/daemon/server.zig` `applyOperAutoOverride`). |

## `[wasm]`

OroWasm plugin module system. Source: struct `Wasm` at `src/daemon/config_format.zig`, mapping at `src/daemon/config_boot.zig`, loaded by `src/daemon/server.zig` `loadWasmPlugins` (boot and REHASH), dispatched via `src/wasm/host/bridge.zig`. The canonical guest ABI v1 descriptor lives at `src/wasm/host/orowasm-abi-v1.wit`, is embedded by `src/wasm/host/abi.zig`, and is visible to opers through `OROWASM WIT`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `plugin_dir` | string or null | unset (dormant) | directory path | Directory scanned at boot and on REHASH for `*.wasm` control-plane plugins. Each registers IRC commands consulted **after** the built-in registry — a plugin can extend, never shadow, a core command. Plugins run sandboxed with only their negotiated host capabilities (reply/log/time). Missing dir / malformed plugin is logged, never fatal. |
| `max_plugin_bytes` | integer | `8388608` | `1024..67108864` | Maximum bytes read for one `.wasm` plugin file before interpretation. |
| `max_memory_bytes` | integer | `65536` | `65536..16777216` | Maximum linear memory bytes available to one plugin instance. |
| `default_fuel` | integer | `16384` | `1..10000000` | Instruction fuel budget for each plugin command or hook dispatch. |
| `allowed_caps` | array of strings | `["reply","log","time"]` | `reply`, `log`, `time`, `rand`, `store`, `lookup`, `hooks`, `net:outbound` | Hostcall capability classes a plugin may receive after manifest negotiation. Registry trust tiers still cap grants: unlisted may receive `reply`/`log`/`time`/`rand`, listed may also receive `store`/`lookup`, and verified is required for `hooks` plus `net:outbound`. Omitted keeps the minimal control-plane set; `[]` denies every hostcall. |
| `allowed_intents` | array of strings | `[]` | `message-content` | Privileged data-access intents a plugin may receive after manifest negotiation. Intents are separate from hostcall capabilities and default to deny-all; `message-content` is verified-tier only and must be explicitly enabled here plus requested by the plugin's `orowasm.intent/message_content` import. |
| `registry` | array of inline tables | `[]` | `{ name, blake3, tier, publisher, signature }` | Content-addressed plugin registry pins. When non-empty, only named plugins whose BLAKE3-256 digest matches load. `tier` is `unlisted`, `listed`, or `verified` and is shown in `OROWASM PLUGINS`. Optional `publisher` and `signature` are Ed25519 hex fields over the canonical registry pin transcript; when either is set both are required and verified before load. |
| `revoked_blake3` | array of strings | `[]` | BLAKE3-256 hex digests | Emergency content kill-switch. Matching `.wasm` bytes are refused regardless of plugin file name or registry pin and counted in `OROWASM STATUS` as blocked loads. |
| `disabled_plugins` | array of strings | `[]` | plugin names or `.wasm` filenames | Local plugin kill-switch. Matching names are refused before the file is read and are counted in `OROWASM STATUS` as blocked loads. |

## `[[opers]]`

Source: struct `Oper` at `src/daemon/config_format.zig:289`, parsing at `src/daemon/config_format.zig:1399`, SASL-only runtime behavior at `src/daemon/server.zig:8300`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `account` | string | required per table | non-empty; registry validation max 128 bytes | SASL account name that becomes oper after successful SASL login (`src/daemon/config_format.zig:290`, `src/daemon/oper.zig:11`). |
| `class` | string | `""` | registry validation max 64 bytes | Operator privilege group name. It must name a non-empty configured group with effective privileges; otherwise the oper binding is skipped (`src/daemon/config_boot.zig:183`). |
| `title` | string | `""` | any string | Optional WHOIS/operator title (`src/daemon/config_format.zig:294`, `src/daemon/oper.zig:139`). |
| `presubscribe` | array of strings | `[]` | Event-Spine category names (e.g. `["ANNOUNCE","KILL"]` or `["ALL"]`) | Event-Spine categories this oper is auto-subscribed to on elevation. Empty = none (the oper opts in per-category with `EVENT ADD`). A cross-mesh grant carries no presubscribe, so a remotely granted oper defaults to none (`src/daemon/config_format.zig:298`, `src/daemon/config_format.zig:1425`, `src/daemon/server.zig:22892`). |
| `certfp` | string or array of strings | `[]` | lowercase-hex SHA-256 fingerprint(s), 64 chars each | TLS client-certificate fingerprints pre-bound to this oper's `account` at boot, so SASL EXTERNAL works without a prior runtime `CERTADD`. Accepts a single string or an array; each is seeded into the certfp bind store and coexists with runtime `CERTADD` bindings. Malformed entries are skipped with a boot warning (never fatal); case is normalized to lowercase (`src/daemon/config_format.zig:306`, `src/daemon/config_format.zig:1433`). |

There is no oper password. `OPER` is disabled and directs users to authenticate through SASL (`src/daemon/server.zig:8300`). Operator status is granted after SASL when the account matches a configured binding (`src/daemon/server.zig:8308`).

## `[[oper_groups]]`

Source: struct at `src/daemon/config_format.zig:95`, parsing at `src/daemon/config_format.zig:450`, group registry at `src/daemon/operator_groups.zig:1`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `name` | string | required per table | non-empty | Group name referenced by `[[opers]].class` (`src/daemon/config_format.zig:462`). |
| `privileges` | array of strings | `[]` | exact `oper.Privilege` enum names | Privilege flags included in the group. Unknown names are ignored by boot conversion (`src/daemon/config_boot.zig:159`). |
| `inherits` | string | `""` | group name | Optional parent group; effective privileges union parent links up to depth 32 (`src/daemon/operator_groups.zig:11`, `src/daemon/operator_groups.zig:88`). |

Valid privilege strings are the exact enum names from `src/daemon/oper.zig:36`: `server_rehash`, `server_restart`, `server_shutdown`, `client_moderate`, `channel_moderate`, `client_kill`, `mesh_admin`, `service_admin`, `server_admin`, `oper_grant`, `oper_spy`, `event_subscribe`, `audit_read`, and `oper_override`.

Note one current behavior: if an oper names a class that has no group, or that resolves to an empty effective privilege set, boot skips that oper binding (`src/daemon/config_boot.zig:250`, `src/daemon/config_boot.zig:255`). REHASH rebuilds configured operator bindings through the same group resolver and has coverage for preserving group privileges (`src/daemon/server.zig:20008`, `src/daemon/server.zig:20546`).

## Parsed but not yet wired

No top-level key in this reference is currently known to be parser-only in the
`main.zig` / `config_boot.zig` / `server.zig` path as of `c0e4a23`. When a future
key is accepted before it changes live behavior, add it here in the same change.

## Comptime-bound values not yet configurable

| Value | Bound | Source |
|---|---:|---|
| Maximum daemon shards | `4096` | `src/daemon/shard.zig:23` |
| Operator account name length | `128` bytes | `src/daemon/oper.zig:11` |
| Operator class name length | `64` bytes | `src/daemon/oper.zig:11` |
| Operator group inheritance depth | `32` links | `src/daemon/operator_groups.zig:11` |
