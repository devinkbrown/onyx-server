# Onyx Server configuration reference

*Complete operator-facing reference for the daemon TOML format.*

This reference is verified against `Config` and `parseToml` in `src/daemon/config_format.zig`, and the live boot projection in `src/daemon/config_boot.zig`.

Onyx Server is a pure-Zig 0.17.0 clean-room IRC daemon, built from first principles — not a clone of any prior daemon. The daemon target is 64-bit only (`build.zig`), uses implicit TLS rather than STARTTLS (`src/main.zig`), and uses Zig-native OroStore persistence rather than LMDB (`src/daemon/store.zig`).

Use `etc/onyx-server.reference.toml` as the runnable example and copy from it when building an instance config. Two keys are required: `[node].id >= 1` and `[listen].irc != 0`. Missing either makes `parseToml` fail (`src/daemon/config_format.zig`).

## Format rules

The config file is TOML v1.0 (`src/daemon/config_format.zig`). Missing keys keep typed defaults (`src/daemon/config_format.zig`). Integer fields use the ranges in `parseToml`; out-of-range values return `ParseError` (`src/daemon/config_format.zig`). Durations are quoted strings using `ms`, `s`, `m`, or `h`, must be non-zero, and are converted to milliseconds (`src/daemon/config_format.zig`).

String fields routed through `setStr`, `setOpt`, or an owned string-array reader
support `env:NAME` and `@file:path`. The CLI wires those resolvers through
`ResolverCtx` in `src/main.zig`. Indirection is **not universal**: enum tokens,
duration strings, class sizes/durations, registry digests/signatures and the
quoted OCG2 node ID are read directly. Keep those values literal. The ECH private
key and OCG2 authority public key explicitly resolve indirection before decoding.

`@file:` substitutes the file's contents; it does not name a data file for the
feature to open later. For example `motd.text = "@file:/etc/onyx-server/motd.txt"`
loads text, whereas `sasl.account_db = "/var/lib/onyx-server/accounts.wal"` names a
WAL. The CLI file resolver reads at most 1 MiB. It preserves bytes, including a
trailing newline, so create secret files with the exact content expected by the
consumer. Unavailable variables/files fail resolution. The complete TOML input
is limited to 2 MiB (`config_limits.zig`).

Relative config paths and ordinary data/secret paths resolve from the **process
working directory**, which the service manager controls. They do not generally
resolve from the TOML file's directory. The generated node identity file is an
explicit exception: it lives beside the config. Prefer absolute paths in service
configs; see [service management](../guide/service-management.md) for private
working directories and intentional public-feed sharing.

`config_boot.zig` maps typed parser state into the server; `main.zig` separately
constructs TLS, account, mail, Web Push and renewal services. Some optional
addresses/ports overlay only when nonempty/nonzero; other booleans and numeric
limits assign directly. Do not infer that a parsed zero or `false` is ignored.
Unknown ordinary keys and some wrong-type optional values can be ignored by
getters; a successful parse is not a strict unknown-key lint. `[oper.ocg2]`,
retired-fence records, and several security-sensitive keys have stricter checks.
Use the exact key names and types below.

### Applying configuration changes

`REHASH` performs a partial live reload, not a general process rebuild.
`configFieldClass` labels changes for `REHASH DRY` previews and treats unproven
fields as startup-only; those labels are not a universal rejection gate on an
ordinary REHASH. A successful reload can apply supported fields while leaving
other edited settings unchanged in the running process.

| Change family | Supported application |
| --- | --- |
| `limits.max_clones_per_ip`, `max_clones_per_net`, `max_clones_per_ip_net`, `nick_delay`, `throttle_connects`, `throttle_window`, `raid_joins`, `raid_window` | REHASH applies the live admission/abuse policy. |
| `[class.<name>]`, `[[opers]]` and their privilege-group resolution | REHASH rebuilds the corresponding registries. |
| `[wasm]` directory, limits, capabilities, intents, pins and kill switches | REHASH repoints policy and rescans plugins. |
| `tls.cert_path`, `tls.key_path`, `tls.dns_name` | Certificate reload for new handshakes; existing transports keep their negotiated state. ACME-enabled path changes are unsupported. |
| `[[tls.sni]]`, `[[tls.ech_keys]]` (Linux and OpenBSD) | Reloaded in the same transaction as the default certificate on REHASH. Every file is read and the complete set is checked before anything is published; one bad entry keeps the whole current set serving and the reload reports failure (the log names `[[tls.sni]]` or `[[tls.ech_keys]]`). ACME renewal reloads only the default certificate and keeps the current SNI and ECH sets, so it never reverts a REHASH change and a bad SNI file never blocks a renewal. Handshakes already in progress keep the material they started with. Native Windows binds these into its static Helix proof, so there they still need a restart. |
| Listener address/ports and `tls.enabled` | REHASH does not rebuild listeners. Other supported edits can apply successfully while the existing sockets remain unchanged. Listener compatibility is enforced separately by UPGRADE/Helix preflight and `--check-config --against`; use cold maintenance for incompatible changes. |
| `node.id`, `mesh.realm` and node-identity material | These are not ordinary live identity replacements. A retained boot policy that requires the identity capability causes REHASH to validate the prospective identity and refuse an incompatible change; a legacy/empty policy does not provide that universal refusal. Use the documented identity/cold-maintenance workflow and verify the actual active identity. |
| Other fields, including service constructors, cloak policy, reactor count, recording, WebAuthn and OCG2 mode | Startup-only unless a specific live path proves otherwise. Validate the replacement and use the compatible process-replacement strategy; a startup-only classification alone does not prove Helix compatibility. |

For example, editing `listen.irc` and `limits.max_clones_per_ip` together and
running REHASH can apply the clone limit and report success while the old IRC
listener keeps serving on its original port. Use `REHASH DRY` to inspect change
classes, then verify the relevant live state after applying supported changes.
A later UPGRADE still compares the proposed listeners against the running set
and can refuse that same file. TLS material reload is also separate: if it fails,
the previous certificates remain active even when other configuration changes
have committed. Read the command's notices as well as its success numeric.

Validate using the intended daemon user and working directory:

```sh
/path/to/onyx-server --check-config /etc/onyx-server/onyx-server.toml
/path/to/onyx-server --check-config /etc/onyx-server/proposed.toml --against /etc/onyx-server/current.toml
```

The check does not bind the daemon listeners. It can validate or create a
configured diagnostic log destination; run it with production ownership and
permissions. Keep the last accepted config and artifact available for rollback.
Follow the [RUNBOOK](../RUNBOOK.md) for mesh changes and custody boundaries.

## Required keys

| Key | Requirement | Source |
|---|---:|---|
| `[node].id` | Required, integer >= 1 | `src/daemon/config_format.zig` |
| `[listen].irc` | Required, port 1..65535 | `src/daemon/config_format.zig` |

## `[node]`

Source: struct fields at `src/daemon/config_format.zig`, parsing at `src/daemon/config_format.zig`, S2S identity wiring at `src/main.zig`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `id` | integer | `0` before validation | required, `>= 1` | Sovereign node id used by the runtime config (`src/daemon/config_boot.zig`) and mesh identity paths. |
| `public_key` | string or null | unset | 32-byte Ed25519 key in hex/base64 | Optional explicit public identity. For a MESSAGE_V2 activation plan on a persisted-keyfile deployment, `--check-config` non-mutatingly reads the existing `onyx-server-node.key` beside the config and requires this key to match it; runtime init repeats the binding against the loaded identity. If `secret_key` is also set, preflight requires the derived and configured public keys to match. |
| `secret_key` | string or null | unset | exactly 64 hexadecimal characters (32-byte Ed25519 seed) | If set, `main.zig` derives a node identity and enables PQ-secured S2S (`src/main.zig`). |

## `[network]`

Source: struct at `src/daemon/config_format.zig`, parsing at `src/daemon/config_format.zig`, mapping at `src/daemon/config_boot.zig`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `name` | string | `"Onyx"` | any string | Network name advertised in ISUPPORT `NETWORK=` and the welcome burst (`src/main.zig`). |
| `server_name` | string or null | `"onyx.local"` | any hostname | This node's own server name — the source prefix of all server-originated lines (welcome numerics, the `!weather`/`!news` bot replies, ERROR/PING) and the identity presented to S2S peers. MUST be unique per node in a mesh so replies/identities don't collide (`src/proto/protocol_inventory.zig` `setServerName`). |
| `description` | string or null | unset | any string | Per-node description shown in VERSION/WHOIS and gossiped to mesh peers (`src/daemon/config_format.zig`, `src/daemon/config_boot.zig`). |
| `icon_url` | string or null | unset | URL string | IRCv3 network icon: when set, advertised as the `NETWORKICON=<url>` ISUPPORT token (clients may render the logo); omitted when unset. NETWORKICON support (`src/daemon/server.zig` `buildIsupportTokens`, `src/daemon/config_boot.zig`). |
| `discoverable` | boolean | `false` | `true`/`false` | Opt-in bit for public discovery directories. `status.json` exports `"discoverable":true` only when enabled, so private meshes are not indexed by accident (`src/daemon/server.zig` `buildStatusJson`). |

## `[logging]`

Source: `src/daemon/config_format.zig` (`Logging`), `src/daemon/dlog.zig`, and
the startup/config-check paths in `src/main.zig`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---|---|---|
| `stderr_file` | string | unset | NUL-free path, 1..4095 bytes; Linux only | Append operational stderr to this file. Unset preserves inherited stderr, including a systemd journal sink. Relative paths use the process working directory. |

The destination must be a regular file owned by the daemon user, with mode
`0600` and one hard link. Final-component symlinks and nonregular destinations
are rejected. `--check-config` validates the destination and may create it;
run the check as the daemon user. Existing contents are retained.

The sink is opened on cold startup and each Helix successor. If replacement
fails at runtime, the daemon reports the error to inherited stderr and continues
adoption of live connections. Arrange external log rotation; the daemon appends
without truncating the file.

Connection diagnostics record UTC milliseconds, physical connection identity,
peer address, escaped nickname, transport, lifecycle events, and socket/TLS error
categories. They exclude authentication payloads, passwords, session tokens,
message contents, and arbitrary QUIT text. The process-wide budget is 128
diagnostic events per fixed one-second window; the next admitted record reports
suppressed events. This budget applies to connection diagnostics, not every
operational log line.

## `[trace]`

Source: `Config.Trace`, `config_boot.zig` and `server.zig` flight-recorder paths.

| Key | Type | Default | Valid range | What it controls |
| --- | --- | --- | --- | --- |
| `file` | string or null | unset | filesystem path | Fault-triggered replacement dump of the in-memory flight recorder. Unset/empty writes no dump. It is separate from the append-only stderr log and the oper DEBUG ring. |

Use a dedicated private destination such as
`file = "/var/lib/onyx-server/private/flight.log"`; its parent must already exist.
Linux refuses final symlinks, foreign/shared/nonregular or insecurely-mode files
before truncation, following the diagnostic-log custody rules. A failed dump is
best effort and cannot replace normal service diagnostics. Configure at startup;
protect the dump as operational data.

## `[motd]`

Source: struct at `src/daemon/config_format.zig`, parsing at `src/daemon/config_format.zig`, mapping at `src/daemon/config_boot.zig`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `text` | string or null | unset | any string | MOTD body served by `MOTD`; newlines are split into MOTD lines. Supports `@file:` at parser level. |

The MOTD is a **per-connection template** expanded by `src/proto/motd_template.zig`
before being split into lines. When omitted or empty, the server serves a
personalized built-in default.

Substitutions use `{key}`; unknown keys are left verbatim, and `{{` / `}}` emit
literal braces. `{key|fallback}` supplies text when the value is missing or
empty. `{plural:key:one:many}` picks a word from a count (`1` uses `one`).
CR, LF, and NUL inside a value become spaces.

Keys: `{nick}`, `{account}`, `{username}`, `{realname}`, `{host}`, `{away}`,
`{network}`, `{server}`, `{version}`, `{time}`, `{date}`, `{weekday}`,
`{uptime}`, `{online}`, `{users}`, `{local_users}`, `{opers}`, `{channels}`,
`{channels_here}`, `{servers}`, `{city}`, `{region}`, `{country}`, `{greeting}`,
`{weather}`, `{news}`. `{greeting}` uses solar time from the client's GeoIP
longitude when one is known, otherwise UTC. The place fields are that
connection's city, region, and country; the MOTD does not include the IP.

Conditionals are `{if:COND}…{else}…{/if}`, `{if:!COND}`, and `{if:not:COND}`.
Flags: `oper`, `account`, `secure`, `weather`, `news`, `away`, `place`, `city`,
`region`, `country`, and `channels` (this client is in at least one). Numeric
keys compare with `>`, `<`, `>=`, `<=`, `=`, `==`, and `!=`. Conditionals nest.
For example: `{if:account}Welcome back, {account}!{else}Please register.{/if}`

## `[admin]`

Source: struct at `src/daemon/config_format.zig`, parsing at `src/daemon/config_format.zig`, mapping at `src/daemon/config_boot.zig`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `location` | string | `"Onyx IRC network"` | any string | ADMIN command location line (`src/daemon/server.zig`). |
| `email` | string | `"admin@onyx.local"` | any string | ADMIN command contact email (`src/daemon/server.zig`). |

## `[weather]`

Localized weather for the MOTD `{weather}` placeholder. The daemon reads `source`
(a `key=value` file refreshed by an external updater) and renders it in the units
the region uses (`src/proto/weather_units.zig`; `src/daemon/server.zig` `handleMotd`).


| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `enabled` | bool | `false` | — | Enable the `{weather}` MOTD line. |
| `source` | string or null | unset | path | `key=value` file (`temp_c`, `wind_kph`, `precip_mm`, `desc`, `location`, `country`); read fresh per `MOTD`. The value names the source path, not its contents. |
| `location` | string or null | unset | any string | Display location override (else the file's `location`). |
| `country` | string or null | unset | ISO code | Country for unit selection (else the file's `country`). |
| `units` | string or null | unset (`auto`) | `auto`/`metric`/`imperial`/`uk` | Unit override. `auto` = by country: US + territories → °F/mph; GB → °C/mph; else °C/km/h. |

## `[news]`

Headlines for the MOTD `{news}` placeholder.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `enabled` | bool | `false` | — | Enable the `{news}` MOTD line. |
| `source` | string or null | unset | path | File with one headline per line; the first `count` are joined. The value names the source path. |
| `count` | integer | `3` | `1..20` | Number of headlines to show. |

## `[geo]`

The live in-channel `!weather`/`!forecast`/`!news` bot (see
[commands/fantasy-bot.md](commands/fantasy-bot.md)). When enabled, the daemon
fetches wttr.in `format=j1` (weather and forecast) and the bundled RSS feeds
(news) on a background thread and serves them to channel fantasy commands.
All sources are key-free.

Source: struct at `src/daemon/config_format.zig` (`Geo`), mapping at `src/daemon/config_boot.zig`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `enabled` | bool | `false` | — | Enable the `!weather`/`!forecast`/`!news` bot. |
| `news_insecure_tls` | bool | `false` | — | Operator escape hatch: skip TLS certificate verification for the live news fetch. The daemon logs a warning at boot when this is `true`. Weather is plain HTTP and unaffected. |
| `news_ca_bundle` | string or null | unset (`/etc/ssl/certs/ca-certificates.crt`) | non-empty path | PEM CA bundle (`CERTIFICATE` blocks) used as the trust anchors for the live news fetch. The fetcher thread loads it once. If the file is missing, larger than `news_ca_bundle_max_bytes`, or holds no usable certificate, the daemon logs an error and disables the live news fetch. It never falls back to `news_insecure_tls`. Not read when `news_cache_dir` is set or `news_insecure_tls = true`. Passed to the geo service at boot (`src/daemon/config_boot.zig` → `server.zig` `geo_services.Service.init`). |
| `news_ca_bundle_max_bytes` | integer | `4194304` | `65536..67108864` | Read bound for `news_ca_bundle`. A larger file is refused, not truncated. Passed to the geo service at boot. |
| `cmd_cooldown_ms` | integer | `3000` | `0..600000` | Minimum interval between bot replies in a single channel (anti-flood). 0 disables. |
| `default_location` | string or null | unset | any string | Fallback place for `!weather` and `!forecast` after the argument, nick `location`, and channel `!setweather`. Also used by the MOTD `{weather}` line after nick `location` and `[weather] location`. |
| `news_cache_dir` | string or null | unset | path | Directory of headline files written by `tools/news_update.sh` (`src_<key>.txt` / `cc_<cc>.txt`). A line is a title, or `epoch<TAB>title<TAB>deck`. When set, `!news` reads these files instead of fetching live. The daemon keeps up to five headlines per feed. |

## `[listen]`

Source: struct at `src/daemon/config_format.zig`, parsing at `src/daemon/config_format.zig`, mapping at `src/daemon/config_boot.zig`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `host` | string | `"127.0.0.1"` | IPv4 or IPv6 literal, or a wildcard bind address | Bind address for runtime listeners. On Windows, an IPv6 literal may include a numeric interface index or local interface alias after `%` (`src/daemon/config_boot.zig`, `src/daemon/windows_ipv6_scope.zig`). |
| `irc` | port integer | `0` before validation | required, `1..65535` | Plain IRC listener port. Current parser requires this even for TLS-first deployments. |
| `ws` | port integer | `0` | `0..65535` | Secure-WebSocket browser listener intent. `mapToServerConfig` overlays it into `ws_enabled`/`ws_port`; the listener stands up when TLS certificates are loaded, or with testing-only `ws_plain` (`src/daemon/config_format.zig`, `src/daemon/config_boot.zig`, `src/main.zig`, `src/daemon/server.zig`). |
| `webtransport` | port integer | `0` | `0..65535` | UDP WebTransport/HTTP3 listener port. `mapToServerConfig` overlays it into `webtransport_port`, and `main.zig` starts `webtransport_listener.zig` when TLS certificate/signing material and the IRC listener are available (`src/daemon/config_boot.zig`, `src/main.zig`). |
| `ws_plain` | bool | `false` | `true` or `false` | Testing-only plain WebSocket mode. Only used when `ws` is non-zero; production browser clients require TLS (`src/daemon/config_format.zig`, `src/daemon/config_boot.zig`). |
| `proxy_protocol` | bool | `false` | `true` or `false` | Enable HAProxy PROXY v1/v2 header consumption before IRC/TLS/WebSocket framing, gated by `trusted_proxies` (`src/daemon/config_format.zig`, `src/daemon/config_boot.zig`, `src/daemon/server.zig`). |
| `trusted_proxies` | array of strings | `[]` | IPv4/IPv6 literals | Source IPs allowed to supply PROXY headers. Every resolved entry must be an IP literal; CIDR, hostnames, empty strings, malformed addresses and mixed invalid lists fail configuration loading with a fixed `listen.trusted_proxies` diagnostic. An empty array disables trusted handling even if `proxy_protocol` is true. Environment/file indirection uses the same validation (`src/daemon/config_format.zig`, `src/daemon/server.zig` `trustedProxyMatches`). |
| `s2s` | port integer | `0` | `0..65535` | Server-to-server mesh listener; `0` disables it (`src/daemon/config_boot.zig`, `src/daemon/server.zig`). |
| `media` | port integer | `0` | `0..65535` | UDP media transport plane port; `0` means ephemeral (`src/daemon/config_boot.zig`, `src/daemon/server.zig`). |
| `native_media` | port integer | `0` | `0..65535` | Native CadenceVox/CadenceVis media UDP port; `0` means ephemeral (`src/daemon/config_boot.zig`, `src/daemon/server.zig`). |
| `media_host` | string | `"127.0.0.1"` | any string | Advertised media candidate host/IP for native Cadence UDP and WebRTC ICE. Default `127.0.0.1` is local-only; production native/WebRTC needs a public address or `[media].stun_host`/`stun_port`. Browser WS media does not use this candidate — enable `ws_media_relay` (MACKEY + binary WS). Loopback candidates are suppressed for WS clients (`src/daemon/config_boot.zig`, `src/daemon/server.zig` `provisionMediaTransports`). |

For a Windows link-local bind, set `host = "fe80::abcd%7"` or `host = "fe80::abcd%Wi-Fi 2"`, replacing the address and zone with an address assigned to the local interface. The zone identifies the local interface, not a remote host. Windows Helix adoption checks the inherited listener's address, port, and scope against this configuration (`src/daemon/server.zig` `validateNativeListenerAddress`).

## `[mesh]`

Source: struct at `src/daemon/config_format.zig`, parsing at `src/daemon/config_format.zig`, secured S2S wiring at `src/main.zig`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `realm` | string | `"local"` | any string | Realm fed into node identity derivation for secured S2S (`src/main.zig`). |
| `trust_roots` | array of strings | `[]` | hex/base64 Ed25519 public keys | Parsed, mapped to `server.Config.mesh_trust_roots`, decoded at server init, and used as the expected secured-S2S peer key allowlist (`src/daemon/config_format.zig`, `src/daemon/config_boot.zig`, `src/daemon/server.zig`). This is deliberately the **exact direct-neighbor pin set**, not a broad transitive CA list, and is distinct from `admission_roots` (MeshPass signer roots). Under a staged MESSAGE_V2 plan it also fixes this node's direct-neighbor **custody membership** — the confirmed-node set each durable RVL2 accepted-event row must collect ACKs from before it may retire its retained wire — so activation bounds it to 1..255 keys (`default_max_confirmed_nodes_per_row` minus the local node) and requires every direct root to appear in `relay_v2_roster` (`src/daemon/config_format.zig`, `src/daemon/relay_v2_event_log.zig`). |
| `presence_store_path` | string or null | unset | private local WAL path | Durable issuer, signed guest-presence, and retirement state for exact guest-incarnation routing. Required when the node has a mesh listener, auto-connect peer, or direct trust roots; startup refuses an active mesh without it. Keep this WAL separate from the account database and other stores. |
| `mesh_pass` | string or null | unset | any string | Shared MeshPass fallback gate. When no signed admission roots are configured, secured-S2S responders constant-time-compare this value against the encrypted M1 bytes; plaintext mesh-session reclaim also uses it as its seal key. |
| `admission_token` | string or null | unset | hex or standard base64 MeshPass token, max 448 decoded bytes | This node's signed MeshPass capability token. When set, secured-S2S initiators send the decoded token bytes inside encrypted Mooring M1. |
| `admission_roots` | array of strings | `[]` | hex/base64 Ed25519 public keys | MeshPass token signer roots. When non-empty, server init requires secured S2S identity/crypto and secured-S2S responders require the peer M1 token to verify against one root, match the authenticated peer node key, have relay role, and allow control/sync/irc_app/mooring frame families. |
| `admission_min_revocation_epoch` | integer | `0` | `0..u64_max` | Minimum accepted MeshPass token revocation epoch for all configured `admission_roots`. |
| `relay_v2_authoring` | string | `"compat"` | `"compat"`, `"active"` | Controls only local MESSAGE_V2 authoring. Compatibility nodes receive, ACK, retain, and forward V2 but author legacy only. Active nodes author each V2-eligible mesh event as V2 only; an admitted event never falls back to a legacy twin. Active mode requires a complete staged epoch/roster plan. |
| `relay_v2_activation_epoch` | integer | `0` | `0..i64_max` | Monotonic operator rollout generation, not a timestamp. Zero means no plan. A non-zero value requires `relay_v2_roster`; the exact value is bound into current Helix state. |
| `relay_v2_roster` | array of strings | `[]` | 2..4096 unique hex/base64 Ed25519 public keys | Complete secured-mesh node roster for the activation generation, distinct from direct-neighbor `trust_roots`. Onyx Server decodes and sorts the full keys, requires the local key and every direct-neighbor pin, and binds a domain-separated BLAKE3 digest into Helix. |
| `connect` | array of strings | `[]` | `host:port` strings | Peers auto-dialed at boot and retried while down; bracket IPv6 literals, including scoped literals (`src/daemon/config_format.zig`, `src/daemon/config_boot.zig`, `src/daemon/server.zig` `parseHostPort` / `sockaddrForHost`). |
| `require_secured` | bool | `false` | `true`/`false` | Refuse plaintext S2S: reject inbound plaintext peers and never dial plaintext outbound. When secured S2S is unavailable, all S2S is dropped rather than falling back to clear (`src/main.zig` mesh wiring, `src/daemon/server.zig` handleAccept / initiateS2sConnectToAddr). |
| `require_signed_frames` | bool | `true` | `true`/`false` | For secured S2S peers with a node signing key, require the remote handshake to advertise signed-frame support and reject unsigned direct-owned mesh state frames. Set false only for an explicit mixed-rollout window. |

On Windows, a link-local peer can use `connect = ["[fe80::abcd%7]:6900"]` or `connect = ["[fe80::abcd%Wi-Fi 2]:6900"]`. The `%` zone names the **local outbound interface** by index or Windows interface alias; replace the sample address and zone for each node. A malformed scoped literal is rejected rather than sent to DNS (`src/daemon/windows_ipv6_scope.zig`, `src/daemon/server.zig` `sockaddrForHost`).

Plaintext S2S applies when no node identity is available and `require_secured` is false. Secured S2S uses `[node].secret_key` when set; otherwise the daemon loads or creates `onyx-server-node.key` beside the config. Signed MeshPass admission is not available on plaintext S2S: if `admission_roots` is non-empty but the secured S2S identity path is unavailable, server initialization fails closed.

MESSAGE_V2 activation is deliberately multi-pass. Deploy a bridge-capable binary to the entire roster with `relay_v2_authoring = "compat"`; stage the same non-zero epoch and complete roster on every node; run the new binary's `--check-config` against that final staged config; Helix-reload every node once while still compatible; verify every live node reports the same epoch/digest/count and local bridge implementation marker; then change only `relay_v2_authoring` to `"active"` and Helix-reload sequentially. Run `--check-config` again before every activation reload. A non-zero plan requires an explicit `[node].secret_key` or `[node].public_key`, `require_secured = true`, `require_signed_frames = true`, 1..255 unique valid direct `trust_roots` keys, and 2..4096 unique roster keys. The local key and every direct root must be in the roster; no direct root may equal the local key, duplicate another root, or collide with another configured compact u64 node id. Roster order and hex/base64 representation are canonicalized and do not affect the digest.

A current Helix handoff permits compatibility-to-active only when the predecessor already carried the exact epoch and roster digest. After a plan is staged, compatibility mode cannot remove/decrease it or bind the same epoch to another roster; replacement by a strictly higher epoch is allowed only while the predecessor remains compatible. Active-to-compat and all active plan changes are rejected, as are old MHLC v1/v2 state, duplicates, and malformed activation state before publication. Roster change after activation is not implemented and requires a future protocol/release. Epochs are rollout generations, must never be reused, and are not timestamps. The daemon does not yet gather a mesh-wide signed READY certificate automatically, so the bridge-complete verification is an operator/deployment-system gate, not an inference from direct-neighbor capabilities or proof supplied by the roster itself. `bridge_implemented` is only a local build marker. Cold boot has no durable previous-active floor; deployment automation must preserve the exact active tuple and never cold-start an image that lacks the exact activation/capability semantics or changes the active tuple.

“V2-eligible” currently means authored channel `PRIVMSG`, `NOTICE`, `TAGMSG`, and typed `DATA`/`REQUEST`/`REPLY`. Direct-message variants additionally require an authenticated portable recipient-session token; other IRC events remain on their existing paths.

### `[[mesh.retired_session_group_fences]]`

An optional array of exact historical denial facts, default `[]`. These records
are not active peer roots, general signing roots or permission to accept arbitrary
facts from a retired issuer. `session_group_retired_policy.zig` bounds the list
at 4096 entries; parsing canonicalizes order and rejects duplicate triples.

| Entry key | Type | Requirement | Meaning |
| --- | --- | --- | --- |
| `group_key` | string | exactly 64 lowercase hex characters; nonzero | Exact session-group key digest. |
| `issuer_key` | string | exactly 64 lowercase hex characters; nonzero | Exact historical issuer public key. |
| `fact_digest` | string | exactly 64 lowercase hex characters; nonzero | Exact accepted denial-fact digest. |

Every entry must contain exactly these three fields; indirection is not applied
to these raw hex strings. Provision only audited historical triples through the
`session-fences` workflow, never invented example keys. Changes are refused by
REHASH and warm-handoff policy checks. Keep identical intended immutable policy
through sequential upgrades; do not add retired keys to active trust roots.

## `[guest_presence]`

| Key | Type | Default | Valid range | What it controls |
| --- | --- | --- | --- | --- |
| `issuer_path` | string or null | unset | nonempty NUL-free path | Durable local guest issuer/custody state. Distinct from `mesh.presence_store_path`; absent leaves this optional preparation pipeline disabled. |

Create a private parent directory, set the absolute path, then provision once:

```sh
onyx-server --initialize-guest-issuer /etc/onyx-server/onyx-server.toml
```

Missing or corrupt configured state fails startup; never delete the WAL to make
a retry succeed. The initializer does not boot network listeners. This local
issuer preparation alone does not turn on a new mesh presence protocol. Keep its
state and ownership intact across restarts and Helix. Source: `main.zig`
`initializeGuestIssuerOffline` and `server.zig` guest issuer construction.

### `[mesh.routing]`

Live Undertow route-table and server-registry capacities. These keys are parsed into `Config.mesh.s2s`, projected to `server.Config.s2s_config`, and used for both plaintext S2S links and the secured S2S inner CRDT stream.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `max_nicks` | integer | `4096` | `64..10000000` | Max tracked nicknames in one peer route table. |
| `max_channels` | integer | `1024` | `16..1000000` | Max tracked channels in one peer route table. |
| `max_nodes_per_channel` | integer | `64` | `4..4096` | Max member nodes recorded for one remote channel. |
| `max_name_len` | integer | `64` | `16..256` | Max nick/channel name bytes accepted by the route table. |
| `max_servers` | integer | `512` | `8..65536` | Max servers tracked in the peer server registry. |
| `max_server_name_len` | integer | `63` | `16..255` | Max server-name bytes accepted by the registry. |
| `max_server_desc_len` | integer | `255` | `32..1024` | Max server-description bytes accepted by the registry. |

### `[mesh.gossip]`, `[mesh.ripple]`, `[mesh.link]`

Live S2S peer-driver tuning. `[mesh.link]` per-link `gossip_fanout` and view-capacity overrides are applied after `[mesh.gossip]` defaults.

**Ripple keys** configure the witness-quorum library under `[mesh.ripple]`.
The active parser recognizes this table only; `mesh.sazanami` is not a supported
alias. The quorum minimum of 2 prevents one accuser from declaring a peer dead.
These parsed library settings are not proof that the live daemon timer drives
the complete witnessed-failure state machine; inspect the caller and runtime
acceptance before attributing an outage or convergence guarantee to them.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `mesh.gossip.round_fanout` | integer | `3` | `1..64` | Gossip round push fanout. |
| `mesh.gossip.max_member_deltas` | integer | `64` | `1..1024` | Max membership deltas packed per gossip payload. |
| `mesh.gossip.max_suspicions` | integer | `64` | `1..1024` | Max suspicion records packed per gossip payload. |
| `mesh.gossip.view_active_capacity` | integer | `8` | `2..64` | Bounded membership-view active capacity. |
| `mesh.gossip.view_passive_capacity` | integer | `64` | `active+1..4096` | Bounded membership-view passive capacity. |
| `mesh.gossip.view_shuffle_active` | integer | `2` | `0..active` | Active entries sampled per shuffle. |
| `mesh.gossip.view_shuffle_passive` | integer | `4` | `0..passive` | Passive entries sampled per shuffle. |
| `mesh.ripple.suspicion_timeout_ms` | integer | `3000` | `0..120000` | Gossip-side suspect to dead reaping timeout. Milliseconds. |
| `mesh.ripple.witness_quorum` | integer | `2` | `2..16` | Witness quorum for Ripple dead declaration. Minimum two witnesses. |
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
| `relay_port` | integer | `587` | `1..65535` | Submission TCP destination. Conventionally 587 with STARTTLS or 465 with implicit TLS; set `starttls` consistently because the port does not select the mode. |
| `starttls` | bool | `true` | `true`/`false` | Upgrade the SMTP connection using STARTTLS; false uses TLS from connect. The destination remains `relay_port`. |
| `from` | string | unset | email address | Envelope sender + `From:` header. |
| `user` / `pass` | string or null | unset | relay credentials | Optional AUTH PLAIN credentials. |
| `insecure_skip_verify` | bool | `false` | `true`/`false` | Explicitly bypass relay certificate verification. Remote AUTH without configured trust anchors is refused unless this unsafe bypass is selected. Keep false and supply `trust_store_path`. |
| `trust_store_path` | string or null | unset | PEM/DER trust-anchor file; CLI loads at most 1 MiB | Certificate anchors for verifying the submission relay. The loaded anchor list must be nonempty. This is independent of the ACME/Web Push trust bundle. Relative paths use process CWD. |

## `[limits]`

Source: struct at `src/daemon/config_format.zig`, parsing at `src/daemon/config_format.zig`, mapping at `src/daemon/config_boot.zig`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `backlog` | integer | `128` | `1..32767` | Listener backlog (`src/daemon/config_boot.zig`). |
| `max_clients` | integer | `1024` | `1..32767` | Reserved connection table size and accept cap (`src/daemon/server.zig`). |
| `num_shards` | integer | `1` | `1..max_shards` | Worker reactor shards. **Opt-in: defaults to 1** (single in-line reactor); set `> 1` to run that many reactor threads. `Server.init` allocates the reactor array from the (clamped) shard count, and `runThreaded` spawns one worker per reactor plus the cross-shard delivery fabric when more than one reactor exists. Multi-reactor is correct under the coarse `world.lockWrite` taken once per completion (parallel io_uring I/O, serialized command processing). |
| `handshake_timeout` | duration string | `"30s"` | positive `ms/s/m/h` duration | Registration timeout, mapped to `registration_timeout_ms` (`src/daemon/config_boot.zig`). |
| `ping_interval` | duration string | `"2m"` | positive `ms/s/m/h` duration | Idle interval before server PING (`src/daemon/config_boot.zig`). |
| `ping_timeout` | duration string | `"1m"` | positive `ms/s/m/h` duration | Grace after PING before disconnect (`src/daemon/config_boot.zig`). |
| `topiclen` | integer | `390` | `1..8192` | TOPICLEN advertised and enforced (`src/daemon/server.zig`). |
| `awaylen` | integer | `256` | `1..256` | AWAYLEN advertised and enforced (`src/daemon/server.zig`). |
| `kicklen` | integer | `307` | `1..400` | KICKLEN advertised and enforced (`src/daemon/server.zig`). |
| `nicklen` | integer | `64` | `1..64` | NICKLEN advertised and enforced (`src/daemon/server.zig`). |
| `channellen` | integer | `64` | `2..200` | CHANNELLEN advertised and enforced (`src/daemon/server.zig`). |
| `maxlist` | integer | `100` | `1..10000` | Per-channel list mode cap for `+b/+e/+I/+Z` (`src/daemon/server.zig`). |
| `chanlimit` | integer | `50` | `1..10000` | Max channels per non-oper (`src/daemon/server.zig`). |
| `maxtargets` | integer | `4` | `1..64` | Max comma-separated PRIVMSG/NOTICE targets (`src/daemon/server.zig`). |
| `keylen` | integer | `64` | `1..64` | KEYLEN advertised; max channel-key (`+k`) length, enforced by the `MODE +k` handler (over-long keys are rejected, never truncated). |
| `modes_per_line` | integer | `4` | `1..20` | Channel-mode changes a client should combine per MODE command, advertised as the `MODES` ISUPPORT token. Clients that honor it (mIRC, HexChat) send one mode/target per line when set to `1` (`src/daemon/server.zig` `buildIsupportTokens`). |
| `monitorlimit` | integer | `128` | `1..100000` | MONITOR target limit (`src/daemon/server.zig`). |
| `silencelimit` | integer | `32` | `1..256` | SILENCE mask limit (`src/daemon/server.zig`). |
| `whowas_max_entries` | integer | `20` | `1..100` | Maximum WHOWAS results for one query, additionally capped by the hard server result ceiling. It limits returned rows rather than sizing the historical nickname store. |
| `max_clones_per_ip` | integer | `0` | `0..65535` | Exact-IP clone cap; `0` disables. Refusals publish `SECURITY` Event-Spine entries visible through `EVENT ADD SECURITY` / `EVENT REPLAY` (`src/daemon/server.zig`). |
| `max_clones_per_net` | integer | `0` | `0..65535` | Network-prefix clone cap; `0` disables. Refusals publish `SECURITY` Event-Spine entries visible through `EVENT ADD SECURITY` / `EVENT REPLAY` (`src/daemon/server.zig`). |
| `nick_delay` | duration string | omitted (`0` ms, disabled) | positive `ms/s/m/h` duration when supplied | Hold a released nick against reuse for this window after its owner exits (anti nick-camping). The owning account may reclaim during the window; opers and `nick_delay_exempt` classes bypass. Omit the key to retain the disabled default; `"0"` and `"0s"` are rejected by the general duration parser (`src/daemon/config_format.zig`, `src/daemon/nick_delay.zig`). |
| `throttle_connects` | integer | `0` (disabled) | `0..1000000` | Connection-rate throttle: max NEW connections one source IP may open within `throttle_window`; excess is refused at accept and publishes a `SECURITY` Event-Spine entry. Loopback and `trusted_proxies` are exempt (a shared reverse proxy is never throttled as one IP), making it WebSocket-safe. `0` disables (`src/daemon/clone_detect.zig`, `src/daemon/server.zig` `refuseSilentClient`). |
| `throttle_window` | duration string | `"10s"` | positive `ms/s/m/h` duration | Sliding window for `throttle_connects`. |
| `raid_joins` | integer | `0` (disabled) | `0..65535` | Network raid guard: a default join-throttle applied to channels with no explicit `+j` mode. At most `raid_joins` joins per `raid_window` before new joins are denied (`ERR_THROTTLE`) and a one-shot `.flood` Event-Spine raid alert fires. An explicit `+j` always overrides this default; opers and invited users bypass. `0` disables (`src/daemon/world.zig` `throttleAdmit`, `src/daemon/server.zig` `raidAlert`). |
| `raid_window` | duration string | `"10s"` | positive `ms/s/m/h` duration | Window for `raid_joins`. |
| `max_clones_per_ip_net` | integer | `0` (disabled) | `0..65535` | Network-wide (mesh) concurrent connections per source IP: this node plus every peer's count for the same IP, gossiped as a salted hash (raw IPs never cross the wire; needs a shared `[mesh] pass`). Authenticated accounts get +2; `limit_exempt` opers bypass; loopback/trusted proxies exempt (`src/daemon/mesh_clones.zig`, `src/daemon/server.zig`). |
| `reputation_refuse_threshold` | integer | `0` | `0..1000000` | Refuse connects at or above decaying reputation score and publish a `SECURITY` Event-Spine entry; `0` disables (`src/daemon/server.zig`). |
| `reputation_half_life` | duration string | `"1m"` | positive `ms/s/m/h` duration | IP reputation score decay half-life (`src/daemon/config_boot.zig`). |
| `sweep_interval` | duration string | `"2s"` | positive `ms/s/m/h` duration | Timeout sweep timer granularity (`src/daemon/config_boot.zig`). |
| `sasl_decode_max_bytes` | integer | `512` | `64..512` | Maximum decoded SASL AUTHENTICATE payload bytes for registration SASL and IRCX AUTH. The upper bound is the router's compiled protocol buffer; lower it only for hardened deployments. |

## `[class.<name>]`

Source: `Policy`/`ClassDef` at `src/daemon/conn_class.zig` and `src/daemon/config_format.zig`, parsing at `src/daemon/config_format.zig`, registry built at `src/daemon/config_boot.zig`.

A **connection class** is a named bundle of per-connection resource, admission, and flood policy, assigned to a client at registration by matching its IP, TLS, account, oper status, and ident/host. The first matching class in the constructed registry wins; the TOML parser stores named tables in a hash map, so file order is not a reliable precedence contract. Use disjoint match criteria and inspect `STATS Y`; avoid overlapping catch-all custom classes. Two built-ins always exist as fallbacks: `user` and `server`. Per-class policy overrides matching global settings where a class override exists; zero means inheritance, automatic sizing or no limit according to the individual field below. Inspect live classes and per-class member counts with `STATS Y`.

Sizes accept `K`/`M`/`G` suffixes (`"1M"` = 1048576) or nonnegative integer bytes. Class durations accept strings (`"30s"`) or nonnegative integer milliseconds, including `0` for inheritance. Class count fields accept `0..4294967295`. These class-specific readers differ from the global positive-duration reader.

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

Source: struct at `src/daemon/config_format.zig`, parsing at `src/daemon/config_format.zig`, mapping at `src/daemon/config_boot.zig`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `ring_entries` | integer | `32` | `8..4096` | io_uring submission-queue entries per reactor. The live ring sizes the completion queue to at least 256, and to four times this value, capped at 32768. |
| `cqe_batch` | integer | `256` | `16..4096` | Maximum io_uring completion events reaped per event-loop drain. Larger values improve burst throughput; smaller values cap per-iteration work. |
| `defer_taskrun` | bool | `false` | — | Parsed and stored. The live `Ring.init` never requests `IORING_SETUP_DEFER_TASKRUN` or `IORING_SETUP_SINGLE_ISSUER`. `--check-config` still rejects this key together with `sqpoll`. Default off. |
| `sqpoll` | bool | `false` | — | `IORING_SETUP_SQPOLL` when true. The live ring keeps the flag through its setup ladder and falls back only on `error.ArgumentsInvalid`. Default off. |
| `sqpoll_idle_ms` | integer | `10` | `1..60000` | Idle spin window for an enabled SQPOLL worker. The balanced window reduces CPU between bursts; explicitly set `1000` for the former latency-oriented window. Zero and non-integers are refused. Applies when new rings are created. |

On Linux, boot also arms provided-buffer multishot receive and zero-copy send. There is no key for either one. The daemon copies each selected receive into the connection buffer and replenishes the pool slice. A zero-copy send holds the send buffer until the kernel notification. kTLS, and a ring that cannot install the buffer group, stay on the copy path. Fixed files are not registered. A kernel that refuses zero-copy drops that ring back to copy send.

## `[resources]`

Source: `src/daemon/resource_limits.zig`, parsing at `src/daemon/config_format.zig` (`parseResources`), cross-checks at `src/daemon/config_boot.zig`.

Every key defaults to unset (`0`), so a config without `[resources]` behaves exactly as before. Unknown keys, wrong types, out-of-range values and limits that contradict `[limits]` or `[mesh]` fail closed at load. `--check-config` prints one `config resources:` line for each value it enforces, and a `config WARNING:` line for each value it accepts but does not enforce.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `memory_budget_bytes` | integer | `0` (off) | `1 MiB..2^50` | Total bytes client admission may commit. Each shard admits its equal share. Mesh links and Helix-adopted clients are exempt. Refusals count in `onyx_resource_budget_refusals_total`. |
| `per_client_memory_bytes` | integer | `0` (derived) | `1024..1 GiB` | Committed bytes per client for budget admission. `0` derives it from the class SendQ/RecvQ ceilings and the fixed connection record. |
| `cpu_max_shards` | integer | `0` | `1..max_shards` | Upper bound on `[limits].num_shards`. The host CPU count is not checked. |
| `net_ingress_bytes_per_sec` | integer | `0` | `1..2^40` | Accepted but not enforced or estimated by this build; `--check-config` warns. |
| `net_egress_bytes_per_sec` | integer | `0` | `1..2^40` | Bounds capacity estimates only; this build does not rate-limit egress. |
| `net_max_s2s_peers` | integer | `0` (unlimited) | `1..65535` | Cap on the number of `[mesh].connect` peers. |
| `fd_reserve` | integer | `64` | `0..65535` | File descriptors held back from the client count for listeners, logs, stores and mesh links. |

`[resources.basis]` names the measurement a capacity estimate extrapolates from, for example a `tools/bench_live.py` run. It is all-or-nothing: `name`, `harness` and `revision` (text), plus `measured_clients` (`1..1000000`), `rss_per_client_bytes` (`1..1 GiB`) and `egress_bytes_per_sec_per_client` (`1..1 GiB`). Without a basis the daemon gives no estimate. An estimate beyond twice the measured client count is flagged as an extrapolation. Basis text is never printed.

## `[quota]`

Source: `src/daemon/workload_quota.zig`, parsing at `src/daemon/config_format.zig` (`parseQuota`), cross-checks at `src/daemon/config_boot.zig` (`workloadQuotaError`).

A per-shard admission governor with three work classes: new client admission, session recovery (RESUME and reclaim token checks), and mesh recovery (redials, inbound S2S accept and AKE). It holds back a recovery reserve, so a client reconnect storm cannot take the slots that mesh and session recovery need. Under pressure, the client admission share shrinks toward its floor and grows back when pressure clears. Values not set are derived from `[limits].max_clients`. On a very small table the governor stays off, and `--check-config` warns when that happens.

| Key | Type | Valid range | Meaning |
|---|---|---|---|
| `enabled` | bool | — | `false` turns the governor off on every shard. Setting any other key together with `false` is refused. |
| `recovery_reserve_slots` | integer | `1..2048`, below `max_clients` | Slots client admission can never use. |
| `mesh_reserve_slots` | integer | `1..2048`, below `recovery_reserve_slots` | Part of the reserve that only mesh recovery may use. |
| `admission_floor_slots` | integer | `1..2048`, at most `max_clients - recovery_reserve_slots` | Lowest client admission share under pressure. |
| `max_recovery_inflight_per_peer` | integer | `1..2048` | In-flight recovery units for one peer, so a flapping peer cannot take every unit. |
| `admission_rate_per_sec`, `admission_burst` | integer | `1..2^24`; burst at least `9` | Client admission token bucket. |
| `session_recovery_rate_per_sec`, `session_recovery_burst` | integer | `1..2^24` | Session recovery token bucket. |
| `session_recovery_peer_rate_per_sec`, `session_recovery_peer_burst` | integer | `1..2^24`, below the class value | Per-peer session recovery bucket. |
| `mesh_recovery_rate_per_sec`, `mesh_recovery_burst` | integer | `1..2^24` | Mesh recovery token bucket. |
| `mesh_recovery_peer_rate_per_sec`, `mesh_recovery_peer_burst` | integer | `1..2^24`, below the class value | Per-peer mesh recovery bucket. |

The governor never exceeds a capacity of 2048 per shard. The S2S handshake timeout (30 s) has no TOML key in this release.

## `[reputation]`

Source: struct at `src/daemon/config_format.zig`, parsing at `src/daemon/config_format.zig`, mapping at `src/daemon/config_boot.zig`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `registration_timeout_penalty` | float | `50.0` | `0..1000` | Reputation penalty for unfinished registration (`src/daemon/server.zig`). |
| `clone_refuse_penalty` | float | `25.0` | `0..1000` | Reputation penalty for clone-limit refusal (`src/daemon/server.zig`). |

## `[accounts]`

Source: struct `Accounts` in `src/daemon/config_format.zig`, parsing in `src/daemon/config_format.zig`, services construction in `src/main.zig`.

Durable account-services policy. These settings take effect when `[sasl].account_db` is configured and the daemon opens the account store.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `pbkdf2_rounds` | integer | `100000` | `10000..10000000` | PBKDF2-HMAC-SHA256 iteration count for new password hashes and password verification timing equalization. |
| `password_min_len` | integer | `8` | `1..64` | Minimum length for newly registered or changed account passwords. |
| `password_max_len` | integer | `512` | `64..4096` | Maximum length for newly registered or changed account passwords. Existing account login keeps the historical verifier bounds to avoid lockout after tightening policy. |

## `[bouncer]`

Source: struct `Bouncer` at `src/daemon/config_format.zig`, field defaults at `src/daemon/config_format.zig`, parsing at `src/daemon/config_format.zig`, mapping at `src/daemon/config_boot.zig`, live `MemoBox` construction at `src/daemon/server.zig` / `src/daemon/memo.zig`.

Per-account bouncer/offline-message retention limits. These values construct the live memo offline-mail store at daemon boot.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `memo_text_max_len` | integer | `400` | `64..2048` | Max offline DM body length accepted by `MEMO SEND` (`src/daemon/memo.zig`, `src/daemon/config_format.zig`). |
| `memo_from_max_len` | integer | `64` | `16..128` | Max sender label length stored on an offline DM (`src/daemon/memo.zig`, `src/daemon/config_format.zig`). |
| `memo_mailbox_depth` | integer | `64` | `8..1024` | Per-account offline mailbox depth before new memo delivery fails closed (`src/daemon/memo.zig`, `src/daemon/config_format.zig`). |
| `memo_max_accounts` | integer | `65536` | `1024..1048576` | Max distinct accounts with live offline mailboxes (`src/daemon/memo.zig`, `src/daemon/config_format.zig`). |

## `[filter]`

Source: struct `Filter` in `src/daemon/config_format.zig`, parsing in `parseToml`, mapping in `src/daemon/config_boot.zig`, live content-filter construction in `src/daemon/server.zig`.

Oper-managed content filter sizing. These values construct the live content-filter store at daemon boot. The retired key names `koshi_max_patterns` and `koshi_pattern_max_len` are refused with an error naming the replacement.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `max_patterns` | integer | `256` | `16..4096` | Max oper-curated content filter patterns. |
| `max_pattern_len` | integer | `256` | `16..1024` | Max length of a single content filter pattern. |

## `[storage]`

Source: `store.Config` in `src/daemon/store.zig`, parsing in `src/daemon/config_format.zig`, account-store open in `src/main.zig`.

OroStore append-only WAL/snapshot and recent-mutation feed limits. These values are applied when `[sasl].account_db` opens the durable account store.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `max_record_bytes` | integer | `16777216` | `65536..268435456` | Max single WAL/snapshot record payload size. |
| `max_wal_bytes` | integer | `268435456` | `1048576..4294967296` | Max WAL size accepted on replay; long-lived stores compact at half this budget. |
| `changefeed_capacity` | integer | `64` | `8..4096` | Bounded recent-mutation feed capacity for service-sync consumers. |

## `[sessions]`

Source: struct `Sessions` at `src/daemon/config_format.zig`, parsing at `src/daemon/config_format.zig`, mapping at `src/daemon/config_boot.zig`, consumed by the SessionStore at construction (`src/daemon/server.zig`).

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `max_accounts` | integer | `65536` | `1..4294967295` | Multi-session/bouncer account registry size (`src/daemon/sessions.zig`). |
| `max_per_account` | integer | `64` | `1..65535` | Max live bouncer/multi-device sessions per account, enforced at session attach. Complete account snapshots are allocated to the configured size for fan-out and Helix carry; the upper bound matches the session-capsule u16 count. |
| `resume_composite_issuance` | boolean | `false` | boolean | Issue attachment-bound composite `SESSION TOKEN`/MTOKEN credentials when a physical attachment identity is available. Keep false until intended clients accept the composite shape. Disabling new issuance does not disable decoding existing composite credentials. Distinct from the account-level SASL SESSION-TOKEN mechanism. |
| `migrate_on_detach` | boolean | `true` | boolean | Enable proactive portable-session replication. MTOKEN issuance immediately offers live state; last-local-attachment detach offers its retained snapshot; secured-peer establishment/reconnect re-offers live and detached portable state. Set false as a rolling-deploy kill switch; local resume is unaffected. |
| `max_pending_migrations` | integer | `4096` | `16..1000000` | Global bound for peer-staged reusable signed replicas and rolling-compatibility consumed-token tombstones. `max_per_account` is also enforced as a per-account staging bound; inserts fail closed at either limit instead of evicting another valid replica. |

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

Source: struct at `src/daemon/config_format.zig`, parsing at `src/daemon/config_format.zig`, mapping at `src/daemon/config_boot.zig`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `enabled` | bool | `false` | `true` or `false` | Enables or disables the media feature surface through `server.Config.media_enabled` and `disabled_features` (`src/daemon/config_format.zig`, `src/daemon/config_boot.zig`). |
| `max_upload_bytes` | integer | `16777216` | `0..1073741824` | Runtime upload cap applied to both media planes through `server.Config.media_max_upload_bytes` (`src/daemon/config_boot.zig`, `src/daemon/server.zig`). |
| `max_frame_bytes` | integer | `65536` | `0..16777216` | Runtime frame cap applied to SFU/native media with each transport's protocol maximum as an upper bound (`src/daemon/config_boot.zig`, `src/daemon/server.zig`). |
| `max_participants` | integer | `64` | `1..256` | Max participants per SFU room (`Room`), enforced at join. The inline roster ceiling is 256; the native (CadenceVox/CadenceVis) call leg caps at 64. Default 64 preserves prior behavior (`src/daemon/media_room.zig`, `src/daemon/config_boot.zig`). |
| `reorder_window_frames` | integer | `64` | `1..64` | Cadence media reorder/reassembly window in frames, clamped to the comptime `window_cap` (64). Default 64 (`src/substrate/cadence_frame.zig`, `src/daemon/server.zig` `mediaReassemblyConfig`). |
| `captions_max_text_bytes` | integer | `400` | `64..4000` | Max caption text length accepted by `MEDIA TRANSCRIPT PUSH`. |
| `captions_max_speaker_bytes` | integer | `64` | `16..256` | Max speaker label length stored in the live transcript ring. |
| `captions_ring_depth_per_channel` | integer | `128` | `16..4096` | Retained captions per channel before FIFO eviction. |
| `captions_max_channels` | integer | `4096` | `64..1048576` | Max channels with a live transcript ring. |
| `recording_enabled` | bool | `false` | `true` or `false` | Enables packet-journal recording after unanimous participant consent. Requires a nonempty `recording_dir`. |
| `recording_dir` | string or null | unset | path | Private journal directory, created or verified as mode `0700`; its parent must exist. Segment and manifest names contain random recording IDs rather than channel or participant names. |
| `recording_retention_days` | integer | `7` | `0..3650` | Removes expired owned journal files on the first recording start after boot. `0` disables this sweep. |
| `recording_max_total_bytes` | integer | `536870912` | `65536..68719476736` | Total byte budget for one recording across its segments; exhaustion stops that recording. |
| `recording_max_duration_secs` | integer | `14400` | `1..604800` | Maximum recording duration. All tracks use a common local monotonic recording clock. |
| `media.sfu.max_breakout_label_bytes` | integer | `32` | `8..256` | Max `MEDIA BREAKOUT` label bytes retained by `MediaRooms`; longer labels are truncated in room state. |
| `media.pins.max_per_channel` | integer | `50` | `1..1024` | Max msgids accepted in the live `PINS` channel prop. |
| `media.pins.max_msgid_bytes` | integer | `64` | `8..256` | Max bytes per msgid token accepted in the live `PINS` channel prop. |
| `media.reactions.max_token_bytes` | integer | `32` | `8..256` | Max `MEDIA REACT` token bytes; reactions are ephemeral event broadcasts. |
| `native_media_require_mac` | bool | `false` | `true` or `false` | Require an authenticated per-datagram MAC on native (CadenceVox/CadenceVis) media. `false` accepts untagged datagrams (back-compat); `true` drops untagged/bad-tag datagrams before the SFU learns the sender. HMAC-SHA256-128 keyed from the per-stream PRF capability; needs matching client support (`src/daemon/config_format.zig`, `src/daemon/config_boot.zig`, `src/substrate/cadence_frame.zig`). |
| `ws_media_relay` | bool | `false` | `true` or `false` | **Primary browser media plane.** Relay browser media datagrams (binary WebSocket Cadence frames, client-held E2EE ciphertext) between a channel's call participants. Off by default; opt-in. When on, `MEDIA JOIN` hands each WS participant a per-stream MAC key as `EVENT <nick> MEDIA MACKEY <#chan> <base64>`, and each datagram is lenient-verified before fan-out to same-node call members (including cross-shard), with authenticated opaque cascade over secured mesh peers. The daemon never decrypts E2EE payloads and never rewraps them onto native UDP or WebRTC RTP; WS OFFER suppresses unroutable NATIVE/TRANSPORT candidates (`src/daemon/config_format.zig`, `src/daemon/config_boot.zig`, `src/daemon/server.zig` `handleWsMediaDatagram` / `provisionMediaTransports`, `src/substrate/cadence_frame.zig`). |
| `ws_media_require_mac` | bool | `false` | `true` or `false` | Require a valid per-stream MAC tag on every browser media datagram. `false` relays untagged datagrams (a present tag must still verify); `true` drops untagged/bad-tag datagrams. Same `native_stream_key`-derived `(channel, participant)` key as the native leg. Prefer `true` with `ws_media_relay` in production (`src/daemon/config_format.zig`, `src/daemon/config_boot.zig`). |
| `dtls_srtp` | bool | `false` | `true` or `false` | Enable DTLS-SRTP termination on the UDP media plane. Off by default; when enabled the media plane exposes a DTLS fingerprint for `MEDIA` negotiation and rejects malformed or unavailable fingerprint offers fail-closed (`src/daemon/config_format.zig`, `src/daemon/config_boot.zig`, `src/daemon/server.zig`). |
| `dtls13` | bool | `false` | `true` or `false` | Additionally enable the DTLS 1.3 engine on the media plane. This is parsed independently, but only has an effect with `dtls_srtp` enabled (`src/daemon/config_format.zig`, `src/daemon/config_boot.zig`, `src/daemon/server.zig`). |
| `stun_host` | string or null | unset | any string | Optional STUN host mapped to media discovery config (`src/daemon/config_format.zig`, `src/daemon/config_boot.zig`, `src/daemon/server.zig`). |
| `stun_port` | port integer | `0` | `0..65535` | STUN port mapped when non-zero (`src/daemon/config_format.zig`, `src/daemon/config_boot.zig`). |

Recording producers queue owned packet data without disk I/O. Maintenance writes
strict `ONYXREC1` segments and manifests, rotates segments, and retries retained
finalization work. Helix refuses while any active or retired recording still owns
writer state; stop recording and allow finalization to complete before upgrading.

## `[stats]`

Source: struct at `src/daemon/config_format.zig`, parsing at `src/daemon/config_format.zig`, mapping at `src/daemon/config_boot.zig`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `dir` | string | `""` | any string | Directory for `stats.json` and `index.html`; empty disables (`src/daemon/server.zig`). |
| `channel_dir` | string | `""` | any string | Directory for channel-stats JSON plus the durable `.chanstats.snapshot`; empty disables chanstats publication. |
| `interval` | duration string | `"30s"` | positive `ms/s/m/h` duration | Minimum interval between stats writes (`src/daemon/config_format.zig`). |
| `ignore_nicks` | array of strings | `[]` | nickname strings | Nicknames excluded from channel-statistics tracking/publication. Passed to the chanstats runtime; this does not suppress IRC traffic or authorize clients. |

## `[backup]`

Source: struct at `src/daemon/config_format.zig`, parsing in `parseToml`, mapping at `src/daemon/config_boot.zig`, writer at `src/daemon/server.zig`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `dir` | string | `""` | any string | Directory for timestamped local backup sets. Empty disables backup publication. |
| `interval` | duration string | `"24h"` | positive `ms/s/m/h` duration | Minimum interval between backup sets. Reactor 0 compacts the account store under the services lock, copies the account snapshot and chanstats snapshot when present, and writes `latest.json`. |

Restore drill:

```
onyx-server --restore-drill <backup-dir> --into <scratch-dir>
```

The command reads `<backup-dir>/latest.json` and checks the family lists. `included` names the OroStore families in the account snapshot: `accounts`, `nicks`, `chanregs`, `bans`, `memos`, `vhosts`, `props`, and `history`. `excluded` names `search`, `webhooks`, `event_history`, and `mail`. `chanstats` is included when that snapshot file was copied, and excluded when `[stats] channel_dir` was empty. A successful drill reopens the account snapshot as `<scratch-dir>/restored.wal` and exits. It does not boot, bind, or send mail.

## `[metrics]`

Source: struct at `src/daemon/config_format.zig`, parsing at `src/daemon/config_format.zig`, mapping at `src/daemon/config_boot.zig`, live HTTP endpoint at `src/daemon/metrics_http.zig`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `listen` | port integer | `0` | `0..65535` | Live Prometheus `/metrics` HTTP listener port. `0` or absent disables the endpoint (`src/daemon/config_boot.zig`, `src/daemon/server.zig`). |
| `bind` | string | `"127.0.0.1"` | IPv4 literal | Bind address for the metrics listener. Defaults to loopback; invalid/non-IPv4 values keep the secure loopback default (`src/daemon/config_boot.zig`). |

## `[e2ee]`

Source: `src/daemon/config_format.zig`, mapped by `src/daemon/config_boot.zig`,
and enforced by the live E2EEGROUP command path in `src/daemon/server.zig`.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `group_authoring_enabled` | boolean | `true` | Startup state for accepting new locally-authored E2EEGROUP controls. Set `false` on every mesh node before the first EGRG cold activation so restarted successors remain quiesced. This does not stop inbound relay, custody retry, ACK, or ACK_CONFIRM drain work. |

## `[geoip]`

Source: struct at `src/daemon/config_format.zig`, parsing at `src/daemon/config_format.zig`, mapping at `src/daemon/config_boot.zig`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `database` | string | `""` | any string | MaxMind `.mmdb` path; empty disables GeoIP (`src/daemon/server.zig`). |
| `asn_database` | string | `""` | any string | Optional separate ASN `.mmdb` path for WHOIS AS-number/org enrichment (`src/daemon/config_format.zig`, `src/daemon/config_boot.zig`). |

## `[sasl]`

Source: struct at `src/daemon/config_format.zig`, parsing at `src/daemon/config_format.zig`, account-store boot at `src/main.zig`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `enabled` | bool | `false` | `true` or `false` | Explicit `false` disables SASL even when `account_db` is configured. If omitted, older `account_db`-only configs still enable the account store (`src/daemon/config_format.zig`, `src/daemon/config_boot.zig`, `src/main.zig`). |
| `realm` | string or null | unset | any string | Informational SASL/account realm stored in runtime config; current wire mechanisms do not emit it in challenges (`src/daemon/config_format.zig`, `src/daemon/config_boot.zig`, `src/daemon/server.zig`). |
| `account_db` | string or null | unset | path string | Opens the OroStore account backend; when opened, PLAIN, SCRAM-SHA-256, SCRAM-SHA-512, and EXTERNAL are wired. With the store open, SESSION-TOKEN (opaque reconnect tokens, issued only over TLS) is available, and SCRAM-SHA-512-PLUS is offered to TLS clients via the RFC 9266 `tls-exporter` channel binding (`src/main.zig`). |
| `allow_anonymous` | bool | `false` | `true` or `false` | Allow SASL ANONYMOUS (RFC 4505) guest logins. Default off (spam vector). A guest binds no account, is left `+r`-unset, and receives no oper/services privileges (`src/daemon/config_format.zig`). |
| `oauth_hmac_key` / `oauth_jwks_file` / `oauth_pubkey` | string or null | unset | secret / path | OAUTHBEARER (RFC 7628) JWT verification key. Exactly one source enables OAUTHBEARER: an HS256 shared secret, an RS256/ES256 JWKS file, or an RS256/ES256 PEM/DER public key. Unset = OAUTHBEARER is not advertised (`src/daemon/oauth_jwt.zig`, `src/daemon/config_format.zig`). |
| `oauth_issuer` / `oauth_audience` / `oauth_account_claim` | string or null | unset / `"sub"` | any string | When set, `iss`/`aud` are required to match; `oauth_account_claim` selects the JWT claim mapped to the account (default `sub`). OAuth identities are federated and are never auto-elevated to oper (`src/daemon/config_format.zig`). |
| `oauth_auto_provision` | bool | `false` | `true` or `false` | Default false: OAUTHBEARER refuses account names without a registered account. Setting true is the operator choosing to let a valid token bind a session for an account name that never REGISTER'd. The daemon still does not create the account and does not auto-elevate oper. |

## `[acme]`

Source: struct `Acme` at `src/daemon/config_format.zig`, parsing at `src/daemon/config_format.zig`, scheduler at `src/daemon/acme_renewal.zig`, reactor-0 hot-swap at `src/daemon/server.zig` (`maybeReloadAcmeTls`).

Automatic in-daemon TLS certificate renewal on Linux, OpenBSD, and Windows. A background thread checks the `[tls].cert_path` leaf expiry every `check_interval`; within `renew_before_days` of `notAfter` it issues a new certificate off the reactor and signals reactor 0 to hot-swap it without a restart. This requires `[tls]` with `cert_path` and `key_path`. Changing those paths via live REHASH while `[acme]` is enabled is unsupported. On Windows, set `ca_bundle_path` to a readable PEM trust bundle (the default is a Linux path) and create the key file's private parent directory with `onyx-server.exe --init-private-dir <path>`. Windows boot rejects an unreadable bundle or a broadly accessible key parent. Native loopback ACME issuance and worker startup are tested; issuance against a public CA still needs external acceptance. See the [Windows guide](../guide/windows.md).

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `enabled` | bool | `false` | `true` or `false` | Enable in-daemon ACME renewal. |
| `directory_url` | string | Let's Encrypt prod | any URL | ACME directory endpoint. |
| `domain` | string or null | unset | hostname | Certificate domain to renew. |
| `contact` | string or null | unset | `mailto:…` | ACME account contact. |
| `renew_before_days` | integer | `30` | `1..89` | Renew when the leaf is within N days of `notAfter`. |
| `check_interval` | duration string | `"12h"` | positive `ms/s/m/h` duration | How often to check the leaf expiry. |
| `ca_bundle_path` | string | `/etc/ssl/certs/ca-certificates.crt` | file path | PEM trust bundle used to verify the ACME API endpoint and load Web Push and OCSP trust anchors. Set a Windows path explicitly. |
| `ca_bundle_max_bytes` | integer | `4194304` | `65536..67108864` | Maximum CA bundle file size read into memory. |
| `challenge_port` | integer | `14402` | `1..65535` | Loopback HTTP-01 listener port to which the public HTTP endpoint forwards challenge requests. |
| `max_steps` | integer | `64` | `8..1024` | ACME state-machine step limit before aborting. |
| `debug` | bool | `false` | `true` or `false` | Log every ACME HTTP exchange; error bodies are still logged when false. |
| `max_response_bytes` | integer | `262144` | `16384..4194304` | Maximum decrypted HTTP response body accepted from the ACME server. |
| `error_body_preview_bytes` | integer | `512` | `0..4096` | Maximum RFC 7807 problem-body bytes included in ACME error logs. |
| `resolv_conf_max_bytes` | integer | `65536` | `4096..1048576` | Maximum `/etc/resolv.conf` bytes read by the Unix built-in resolver; unused by the Windows DNS Client path. |
| `dns_port` | integer | `53` | `1..65535` | UDP port used for Unix ACME endpoint A-record lookups; unused by the Windows DNS Client path. |
| `http01_listen_backlog` | integer | `16` | `1..1024` | TCP listen backlog for the loopback HTTP-01 listener. |
| `http01_accept_poll` | duration string | `"250ms"` | `50ms..5s` | Accept-loop wake interval used to re-check shutdown. |
| `http01_conn_read_timeout` | duration string | `"5s"` | `1s..60s` | Per-challenge-connection read timeout. Whole seconds only. |
| `challenge` | string | `"http-01"` | `"http-01"`, `"dns-01"`, `"tls-alpn-01"` | Which ACME challenge type to answer. Any other value is a parse error. |
| `account_key_path` | string or null | unset (`acme-account.key.pem` in the directory of `[tls].key_path`) | file path, not equal to `[tls].cert_path` or `[tls].key_path` | Persistent ACME account key (P-256, SEC1 PEM). See "Account key" below. |
| `dns_hook` | string or null | unset | absolute path | `dns-01` only (required for it): executable that publishes and removes the TXT record. See "dns-01 hook" below. |
| `dns_hook_timeout` | duration string | `"60s"` | `1s..10m` | Wall-clock limit for one hook run. When it runs out the hook is killed with SIGKILL and issuance fails. |
| `dns_propagation_delay` | duration string | `"30s"` | `1ms..1h` | How long to wait after a successful `add` before asking the CA to validate. |

### Account key

The ACME account key is separate from the certificate key. On the first renewal it is generated, written with mode `0600` (owner read/write only), and reused for every later renewal. Each renewal still gets a fresh certificate key. Startup refuses an `account_key_path` that names the certificate chain or the certificate key.

Migration: earlier releases made a throwaway account key for every issuance and never saved it. Because no old key survives, an RFC 8555 §7.3.5 key change (which the old key has to sign) is impossible. When the file is missing, the daemon writes a new key before it contacts the CA and registers a new account (RFC 8555 §7.3). Every later run sends `newAccount` with the same key, and the CA returns the existing account (RFC 8555 §7.3.1). Existing deployments therefore need no action. A key file that exists but is malformed, unreadable, or readable by group or other makes the renewal fail. The daemon never replaces that file, because replacing it would orphan the registered account. Fix the file by hand (for example `chmod 600`).

### dns-01 hook

With `challenge = "dns-01"` the daemon runs the hook directly through `execve`. No shell is involved, so nothing in the arguments is interpolated:

```text
<dns_hook> add _acme-challenge.<domain> <txt-value>
<dns_hook> del _acme-challenge.<domain> <txt-value>
```

- `<txt-value>` is `base64url(SHA-256(key authorization))` (RFC 8555 §8.4): exactly 43 characters from `A-Z a-z 0-9 - _`. It can start with `-`, so read the arguments by position and never parse them as options.
- The daemon checks the record name against strict hostname syntax before it spawns the hook.
- The hook's stdin and stdout are `/dev/null`. Its stderr goes to the daemon log.
- The hook's environment contains only `PATH`. Read DNS API credentials from a file the hook owns.
- A non-zero exit or a timeout aborts the issuance before the CA is asked to validate.
- `del` runs for every record that `add` attempted, whether the issuance succeeds or fails. A failed `del` is logged so you can remove the record by hand.
- dns-01 hooks run on Linux only.

### tls-alpn-01

With `challenge = "tls-alpn-01"` (RFC 8737) the CA connects to port 443 of the domain. It offers only the ALPN protocol `acme-tls/1`. The daemon's TLS listener must answer on that public port, either directly or through a TCP (layer-4) passthrough; a TLS-terminating proxy cannot answer this challenge. During an issuance the renewal worker publishes a self-signed P-256 challenge certificate. That certificate holds the domain as its only subjectAltName and a critical `id-pe-acmeIdentifier` extension containing `SHA-256(key authorization)`. The listener presents the certificate only to a ClientHello that carries SNI for that domain and an ALPN list of exactly `acme-tls/1`. Every other client gets the normal certificate. The challenge certificate is withdrawn when the authorization settles. The HTTP-01 loopback listener is not started for `dns-01` or `tls-alpn-01`.

## `[ocsp]`

OCSP stapling. Source: struct `Ocsp` at `src/daemon/config_format.zig`, parsing at `src/daemon/config_format.zig`. When enabled, a background worker keeps a fresh OCSP staple for the served leaf certificate; the responder is contacted only when the cached staple is stale or missing.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `enabled` | bool | `false` | `true` or `false` | Master switch for OCSP staple fetching/attachment. |
| `check_interval` | duration string | `"15m"` | duration | How often the worker wakes to check whether a (re)fetch is due (parsed via `durationMs`, `src/daemon/config_format.zig`). |

## `[cloak]`

Source: struct `Cloak` at `src/daemon/config_format.zig`, parsing at `src/daemon/config_format.zig`, boot wiring at `src/main.zig`. See [Host cloaking](host-cloaking.md) for the full model.

The cloak key is not a bare `SHA256(secret)`: `secret` (and `previous_secret`) are stretched through **argon2id** (memory-hard KDF, 64 MiB / t=2 / p=1) with a fixed domain-separation salt `onyx/cloak-key/argon2id/v1`, which raises the cost of offline guesses over the enumerable IPv4 input space; operators must still choose a high-entropy secret (`src/main.zig`, `src/crypto/argon2_kdf.zig`). Derivation is deterministic (fixed salt), so cloaked hosts stay stable across restarts and identical mesh-wide.

**Mesh requirement:** every mesh node MUST share one `[cloak] secret`. A meshed node with no shared secret generates a per-boot random key, so cloaked hosts differ per node and change on restart — `*!*@<cloak>` and subnet WARD bans neither federate nor persist. `--check-config` **hard-errors** (`meshCloakSecretMissing`) when `[mesh] connect` OR `[listen] s2s` is set without a `[cloak] secret` (`src/daemon/config_format.zig`, `src/main.zig`).

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `secret` | string or null | unset | any string | argon2id-derived stable hostname cloak key. If absent, `main.zig` generates a per-boot random key so real IPs are never shown by default (`src/main.zig`). |
| `previous_secret` | string or null | unset | any string | Prior cloak key kept live across a `secret` rotation (derived through the same argon2id path). New cloaks use `secret`; WARD host/mask matching additionally tests the cloak under this key, so bans written before the rotation keep matching during a grace window. Drop once old bans have aged out (`src/main.zig`). |
| `suffix` | string or null | unset | any string | Optional network-identifying suffix for generated cloak hosts (`src/daemon/config_format.zig`). |
| `mode` | string or null | `hierarchical` | `hierarchical` \| `opaque` | IP cloak granularity. `hierarchical` emits subnet-bannable prefix tokens plus `a<asn>.<cc>` geo labels; `opaque` emits one 128-bit token over the whole address (nothing leaks — not even country/ASN or subnet membership — but it cannot be subnet-banned) (`src/daemon/config_format.zig`, `src/main.zig`). |
| `account_cloak` | bool | `false` | `true` \| `false` | When true, a logged-in client's visible host becomes the friendly `<account>.users.<suffix>`, stable across IPs and devices. Explicit VHOST personas still override it (`src/daemon/config_format.zig`). |
| `anon_epoch_secs` | integer (seconds) | `1209600` | `0..31536000` | Anonymous cloak cadence (14 days). V4 opaque hosts bind address, epoch, cadence, and suffix; literal provenance lets policies match historical cloaks with bounded work. Connected clients receive CHGHOST at the epoch boundary. Account/persona scope stays separate; `0` disables rotation. Explicit daily settings remain daily. Legacy unlabeled masks need a migration audit; see [host cloaking](host-cloaking.md). |

## `[webpush]`

Source: struct at `src/daemon/config_format.zig`, parsing at `src/daemon/config_format.zig`.

Browser [Web Push](web-push.md) delivery for offline direct messages (triggered by the `MEMO SEND` away-delivery path). Off by default; enabling it needs an account store (subscriptions are account-scoped) and outbound HTTPS (it reuses the same trust anchors as ACME). The VAPID public key is advertised to clients through an ISUPPORT `VAPID=` token; lifecycle visibility is published on the Event Spine.

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Master switch. When off, the `WEBPUSH` command is not registered. |
| `subject` | string | `mailto:ops@eshmaki.me` | VAPID JWT `sub` claim (RFC 8292) — an operator contact the push service may use to reach the node. |
| `vapid_key_path` | string | `onyx-webpush-vapid.key` | Where the ES256 VAPID secret persists. **Rotating it invalidates every stored browser subscription** (the advertised public key changes). |

## `[webhook]`

Source: struct `Webhook` in `src/daemon/config_format.zig`, parsing in `parseToml`, boot projection in `src/daemon/config_boot.zig`, HTTP listener in `src/daemon/webhook_http.zig`, payload rendering in `src/daemon/webhook_render.zig`, and live channel injection in `src/daemon/server.zig` `handleWebhook` / `injectWebhookPost`.

Incoming channel webhooks are off by default. When enabled, channel operators and network operators can run `WEBHOOK CREATE <#channel> [name]` to mint a one-time URL of the form `/api/webhooks/<id>/<token>`. The token is stored only as a hash; `LIST` never reveals it again, and `DELETE <id>` removes the binding.

With active MESSAGE_V2 authorship, webhook messages use the reserved sender
`=<sanitized-name>!webhook@<origin-server>`. Clients cannot claim a nickname
beginning with `=`. The authenticated origin and restricted webhook shape remain
mandatory, and local delivery, mesh delivery, and history share one signed event
identity. Compatibility mode retains the ordinary sanitized sender name.
Upgrade every mesh node before enabling active webhooks: older peers reject the
reserved sender form, although the MESSAGE_V2 schema and signature transcript
are unchanged.

The listener is a single-threaded, one-connection-at-a-time HTTP/1.1 accept loop and requires a valid `Content-Length` on every POST body — a body-bearing request without one is rejected immediately with `411 Length Required` rather than being awaited. Because a stalled or dribbled request still occupies the loop for up to `conn_read_timeout_sec` (5s), a non-loopback `bind` MUST sit behind a buffering reverse proxy (nginx/Caddy) that terminates TLS and always forwards a complete, `Content-Length`-framed request. Keep the default loopback bind unless such a proxy is in front.

The listener accepts sanitized JSON payloads with `content`, `embeds`, Discord-style `components`, and Block-Kit-lite `blocks`. Supported block fallback types are `header`, `section`, `context`, and `actions`; buttons and select menus always degrade to bounded text lines such as `[button] Open <https://...>` and `[select] Promote to: staging, prod`. For clients that negotiated `message-tags`, block action metadata is also delivered as a client-only IRCv3 tag: `+onyx/block-kit=v1|b:<label>,u:<url>|s:<label>,o:<opt>~<opt>`, with tag values percent-encoded and capped inline. CR/LF/NUL/control bytes are stripped before reactor handoff, and each post is capped by `max_body_bytes`, rendered line limits, metadata tag limits, and per-binding rate limits.

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
| `allow_private_targets` | bool | `false` | boolean | Allow outbound webhook destinations on loopback/link-local networks. Default false preserves target filtering. This flag does not change the inbound HTTP bind address or replace TLS termination. |

## `[tls]`

Source: struct at `src/daemon/config_format.zig`, parsing at `src/daemon/config_format.zig`, TLS boot projection at `src/daemon/config_boot.zig`, live listener at `src/main.zig`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `enabled` | bool | `false` | `true` or `false` | Enables the implicit TLS listener when certificate loading/bootstrap succeeds (`src/main.zig`). |
| `port` | port integer | `6697` | `0..65535` | TLS listener port; `0` binds ephemerally if TLS is enabled (`src/daemon/server.zig`). |
| `cert_path` | string or null | unset | path string | Leaf certificate path; paired with `key_path` (`src/daemon/config_format.zig`). |
| `key_path` | string or null | unset | path string | Private key path; paired with `cert_path` (`src/daemon/config_format.zig`). |
| `dns_name` | string | `"localhost"` | any string | CN/SAN for self-signed bootstrap cert when certificate/key settings are omitted (`src/main.zig`). |
| `request_client_cert` | bool | `false` | `true` or `false` | Requests client certs so SASL EXTERNAL can match cert fingerprints (`src/main.zig`, `src/daemon/sasl_bridge.zig`). |
| `enable_tls12` | bool | `false` | `true` or `false` | Also accept hardened TLS 1.2 ECDHE-AEAD clients through version dispatch. Off by default (`src/daemon/config_format.zig`, `src/daemon/config_boot.zig`, `src/main.zig`). |
| `enable_resumption` | bool | `false` | `true` or `false` | Enable TLS 1.3 PSK session tickets/resumption on the live TLS listener (`src/daemon/config_format.zig`, `src/daemon/config_boot.zig`). |
| `early_data_max_size` | integer | `0` | `0..4294967295` | Maximum TLS 1.3 0-RTT bytes advertised in issued tickets. `0` disables early data while still allowing resumption (`src/daemon/config_format.zig`, `src/daemon/config_boot.zig`). |
| `raw_public_key` | bool | `false` | `true` or `false` | Enables RFC 7250 raw-public-key negotiation. When true, a client that offers `server_certificate_type=RawPublicKey` may receive the active leaf's bare SubjectPublicKeyInfo instead of the X.509 chain. With `request_client_cert = true`, a client that offers `client_certificate_type=RawPublicKey` may present a bare SPKI for SASL EXTERNAL CertFP. Default off keeps X.509 handshakes byte-identical. |
| `ktls` | string | `"off"` | `"off"`, `"tx"`, `"txrx"` | Requests Linux kTLS offload on the implicit TLS listener. `tx` offloads server-to-client encryption; `txrx` also offloads client-to-server decryption. Applies to TLS 1.3 and to hardened TLS 1.2 AEAD sessions (the 1.2 explicit nonce is installed as the record sequence, so kernel nonces continue the engine's). A TLS 1.2 client that negotiated a `record_size_limit` below 16384 stays in userspace. Under kernel RX a TLS 1.2 alert closes the connection and any handshake record (renegotiation) is fatal. Offloaded connections of both versions survive Helix on the same descriptor (`tls_session` schema v4). The daemon only enables offload when the running kernel advertises the TLS ULP; otherwise TLS remains userspace. FreeBSD offloads TLS 1.3 only. |
| `groups` | array of strings | `["X25519MLKEM768", "x25519", "secp256r1"]` | 1..8 distinct names from `X25519MLKEM768`, `x25519`, `secp256r1` (`P-256`, `P256`); case-insensitive | TLS 1.3 key-exchange group preference (RFC 8446 §4.2.7/§4.2.8), most preferred first; validated at parse time with `tls_server.validateGroups`. The QUIC/WebTransport listener uses the subset it implements (`X25519MLKEM768`, `x25519`) in the same order, so with `[listen] webtransport` set the list must name one of them. Boot-only: the slice lives for the process; a Helix successor parses its own copy. |
| `delegated_credentials` | inline table or null | unset (no DC) | `valid`: 1s..168h (default `"24h"`); `renew_before`: below `valid` (default `"12h"`); `algorithm`: `"ecdsa_p256"` (default) or `"ed25519"` | RFC 9345 delegated-credential rotation. The maintenance reactor mints a credential from the default leaf at boot, renews it once it enters the renewal window, and re-mints when the leaf changes (ACME renewal, reload). Every candidate is validated by a probe `tls_server.Server.init` before it is installed; a superseded credential is freed only once no incomplete handshake borrows it. A credential is presented only while it is unexpired and bound to the serving leaf. A leaf without the DelegationUsage extension (OID 1.3.6.1.4.1.44363.44) or without digitalSignature is logged once and rotation stays off until the leaf changes; transient failures retry after 60 s. The delegated private key lives only in process memory: `key_out_dir` is refused. |
| `alpn` | array of strings | `["irc"]` | up to 8 distinct ids, each 1..255 bytes; `[]` turns ALPN off | ALPN ids the IRC TLS listener may select, in preference order. A client that sends no ALPN, or only ids not listed, still completes the handshake: the server leaves ALPN out of its reply and sends no alert. The browser WebSocket listener selects only `http/1.1` while ALPN is on. Applies to the TLS 1.3 and TLS 1.2 legs; on the 1.2 leg a malformed ALPN extension is a decode error. |
| `cert_compression` | bool | `false` | `true` or `false` | RFC 8879 certificate compression (zlib) for clients that offer it. The compressed form is sent only when it is smaller. |
| `enforce_cert_signature_algorithms` | bool | `false` | `true` or `false` | Refuse the handshake (`handshake_failure`) when the chain's non-self-signed certificate signatures use an algorithm the client did not list in `signature_algorithms_cert` (or `signature_algorithms` when that is absent). Self-signed and trust-anchor certificates are exempt. |
| `ticket_lifetime` | integer seconds or duration string | engine default (TLS 1.3: 86400, TLS 1.2: 7200) | `1..604800` seconds; strings use `s`, `m`, `h` (`"12h"`) | Lifetime advertised in issued session tickets on both legs. Only matters with `enable_resumption = true`. RFC 8446 caps it at 7 days. |
| `mooring_max_meshpass_len` | integer | `4096` | `1..65535` | Largest Mooring mesh password accepted in the mesh handshake, in both directions. Must be at least the length of `[mesh] mesh_pass`, or the config is refused. Applied once at process start; change it with a restart or Helix. |
| `debug_log` | bool | `false` | `true` or `false` | Trace outbound TLS client handshakes (ACME, OCSP, Web Push, feeds) to stderr: states, message types, lengths and error names, never key material. Applied once at process start. |
| `[[tls.sni]]` | array of tables | empty | `server_names`, `cert_path`, `key_path` | Adds SNI-selectable certificate material. Each entry is loaded with the same cert/key loader as the default leaf, validated before the listener is wired, and handed to the TLS engine as a `tls_server.SniCert`. A bad entry disables TLS startup rather than running a half-configured listener. Reloaded with the default certificate on REHASH, not on ACME renewal (not on native Windows). |
| `[[tls.ech_keys]]` | array of tables | empty | `config_path` plus 64-hex-character `private_key` (32 decoded bytes) | Opt-in server ECH acceptance. `config_path` is a single-entry ECHConfigList file; `private_key` is the matching X25519 HPKE recipient key. Bad files or key/config mismatches disable TLS at boot before the listener is wired. Empty keeps ECH off and preserves existing ClientHelloOuter behavior. When keys are present, a client whose ECH the server cannot decrypt receives every configured ECHConfig as `retry_configs`. Reloaded with the default certificate on REHASH, not on ACME renewal (not on native Windows). |

`tls.ratchet_max_skip` and `tls.treekem_max_members` were removed. They only
ever tuned the double-ratchet and TreeKEM modules, which the daemon does not
use, so they never had an effect; a config that still sets either is refused
with a message naming the key.

Onyx Server has no STARTTLS path. TLS is a separate implicit-TLS listener (`src/main.zig`, `src/daemon/dispatch.zig`).

**SCRAM `-PLUS` channel binding.** `SCRAM-SHA-512-PLUS` uses the RFC 9266
`tls-exporter` binding. RFC 9266 §2 defines it for TLS 1.3 and for earlier
versions only when the master secret is unique, i.e. with the RFC 7627
extended master secret. The hardened TLS 1.2 engine requires EMS, so `-PLUS`
is offered on TLS 1.2 too; without EMS the exporter is refused and `-PLUS` is
not advertised. A Helix-resumed TLS 1.2 engine holds no master secret, so the
binding derived at handshake time is carried in the `tls_session` row (schema
v4). A v3 row has no binding, and that connection simply stops offering
`-PLUS`.

**0-RTT across the mesh.** TLS session-ticket keys are random per process and
are carried only across a local Helix upgrade; they are never shared between
mesh nodes. A ticket issued by one node does not decrypt on another, so a
0-RTT flight captured at one node cannot be replayed into a different node
(it falls back to a full handshake). Replay within one node is bounded by the
per-process replay guard and the ticket-age window. The QUIC listener follows
the same rule with its own per-process key (`[webtransport]`).

**ACME tls-alpn-01.** With `[acme] challenge = "tls-alpn-01"` the implicit-TLS
listener consults the renewal worker's challenge store on each connection's
first record. A ClientHello with SNI for a pending domain and an ALPN list of
exactly `acme-tls/1` is answered by an engine that holds only the challenge
certificate and its key, selects `acme-tls/1`, and issues no ticket, early
data, OCSP staple or delegated credential (RFC 8737 §3). The connection never
reaches IRC and is closed once the handshake completes. TLS 1.2 validators are
answered the same way when `enable_tls12` is on.

## `[webtransport]`

QUIC policy for the `[listen] webtransport` listener. Source: struct
`WebTransport` at `src/daemon/config_format.zig`, mapping at
`src/daemon/config_boot.zig`, applied by `WebTransportListener.applyQuicPolicy`
on cold start and on every Helix candidate.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `resumption` | bool | `false` | — | Issue NewSessionTickets and accept PSK resumption (RFC 9001 §4.5). The ticket key is random per process and per node, distinct from the TCP TLS ticket key. |
| `early_data` | bool | `false` | requires `resumption` | Accept 0-RTT (RFC 9001 §4.6). Replay is bounded by a per-process guard (with a quiet window after every listener start) and the ticket-age window; foreign-node tickets never decrypt. |
| `ticket_lifetime` | integer seconds or duration | `"24h"` | `1..604800` | Advertised ticket lifetime (RFC 8446 §4.6.1). |
| `stateless_reset_key` | string or null | unset | 64 hex characters, not all zero; `env:`/`@file:` allowed | Static stateless-reset key (RFC 9000 §10.3.2). Unset derives it from the TLS signing key, so a restarted process serving the same key emits the same tokens. |

### TLS metrics

When `[metrics] listen` is set, `/metrics` carries these series for the client
TLS listeners (`src/daemon/server_stats.zig`, `src/daemon/server.zig`). Every
label set is fixed, so unknown suites, groups and errors fold into `other`.
Counters reset when the process image changes (restart or Helix).

| Series | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `onyx_tls_handshake_failures_total` | counter | `reason`: `peer_alert`, `protocol_version`, `no_shared_group`, `no_shared_cipher`, `bad_record`, `certificate`, `bad_handshake`, `ech`, `resource`, `other` | Handshakes that ended in an error. Record faults after a completed handshake are not counted. |
| `onyx_tls_handshakes_total` | counter | `version`: `tls13`, `tls12` | Completed handshakes. |
| `onyx_tls_handshake_cipher_total` | counter | `suite`: IANA suite name or `other` | Completed handshakes by cipher suite. |
| `onyx_tls_handshake_group_total` | counter | `group`: `x25519mlkem768`, `x25519`, `secp256r1`, `other` | Full (non-resumed) TLS 1.3 handshakes by key-exchange group. |
| `onyx_tls_resumptions_total` | counter | `version` | Handshakes that resumed a session ticket. |
| `onyx_tls_early_data_total` | counter | `result`: `accepted`, `rejected` | TLS 1.3 0-RTT offers by outcome. |
| `onyx_tls_ktls_offloads_total` | counter | `direction`: `tx`, `rx` | Connections whose record crypto moved into the kernel. |
| `onyx_tls_ktls_active` | gauge | none | Open client connections with kernel TLS in either direction. |
| `onyx_tls_ktls12_active` | gauge | none | The TLS 1.2 subset of `onyx_tls_ktls_active`. |
| `onyx_tls_delegated_credential_expiry_seconds` | gauge | none | Seconds until the presented delegated credential expires; `0` when none is presented. |
| `onyx_quic_resumptions_total` | counter | none | QUIC handshakes completed with PSK resumption. |
| `onyx_quic_early_data_accepted_total` | counter | none | QUIC handshakes whose 0-RTT was accepted. |
| `onyx_quic_early_data_rejected_total` | counter | none | QUIC handshakes whose offered 0-RTT was rejected. |
| `onyx_quic_stateless_resets_sent_total` | counter | none | QUIC Stateless Reset datagrams sent. |
| `onyx_tls_ocsp_staple_status` | gauge | `status`: `none`, `good`, `expired` | Exactly one is 1. `good` means a validated staple is being served. |
| `onyx_tls_ocsp_staple_age_seconds` | gauge | none | Seconds since the staple's `thisUpdate`. Present only while a staple is held. |
| `onyx_tls_ocsp_staple_expires_in_seconds` | gauge | none | Seconds until the staple stops being served. Present only while a staple is held. |
| `onyx_tls_certificate_expiry_days` | gauge | `source`: `default`, `tls12`, `sni`; `server_name` (first `server_names` entry for SNI) | Whole days until the serving leaf's `notAfter`, negative once expired. Read from the live chains, so it works without `[acme]`. |

### `[[tls.sni]]` entry fields

| Key | Type | Default/requirement | Meaning |
| --- | --- | --- | --- |
| `server_names` | array of strings | required, nonempty array | Case-insensitive names or `*.` wildcard patterns used for certificate selection. |
| `cert_path` | string | required | Certificate/full-chain file, resolved from process CWD when relative. |
| `key_path` | string | required | Matching private-key file, resolved from process CWD when relative. |

All three fields are required per entry. Empty SNI configuration preserves the
default single-certificate path. Names and paths pass through string resolvers;
certificate loading and key matching still must succeed at boot.

```toml
[[tls.sni]]
server_names = ["irc.example.net", "*.chat.example.net"]
cert_path = "/etc/onyx-server/tls/chat.fullchain.pem"
key_path = "/etc/onyx-server/tls/chat.key"
```

### `[[tls.ech_keys]]` entry fields

| Key | Type | Default/requirement | Meaning |
| --- | --- | --- | --- |
| `config_path` | string | required | File containing a single-entry ECHConfigList; the boot loader reads at most 65536 bytes. |
| `private_key` | string | required, 64 hex characters after trimming | Matching 32-byte X25519 HPKE private key. `env:`/`@file:` indirection is explicitly supported before hex decoding. |

Publishing the ECHConfigList to clients (for example through DNS HTTPS records)
is an external operation. Merely listing a private key does not publish it.
Runtime validates the config/key pair before wiring TLS. Keep this material
private and treat rotations as a coordinated certificate/listener operation.

```toml
[[tls.ech_keys]]
config_path = "/etc/onyx-server/tls/echconfig.bin"
private_key = "@file:/etc/onyx-server/private/ech-key.hex"
```

## `[sts]`

Source: struct at `src/daemon/config_format.zig`, parsing at `src/daemon/config_format.zig`, STS boot projection at `src/daemon/config_boot.zig`, live advertisement at `src/main.zig`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `enabled` | bool | `false` | `true` or `false` | Enables IRCv3 STS advertisement only if a TLS listener is live (`src/main.zig`). |
| `duration` | integer | `2592000` | `0..4294967295` | STS max-age in seconds (`src/main.zig`). |
| `port` | port integer | `6697` | `0..65535` | Secure port advertised in the STS policy (`src/main.zig`). |
| `preload` | bool | `false` | `true` or `false` | Adds `preload` to the STS value (`src/main.zig`). |

STS is omitted entirely unless a policy is present; this prevents clients from being stranded by a nonexistent TLS listener (`src/daemon/dispatch.zig`).

## `[webauthn]`

Passkey (WebAuthn/FIDO2) registration and passwordless login (the `WEBAUTHN` command). Source: struct `Webauthn` at `src/daemon/config_format.zig`, parsing at `src/daemon/config_format.zig`. The command fails closed until BOTH `rp_id` and one or more `origins` are configured — a passkey ceremony must be bound to the deploy's exact domain.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `rp_id` | string or null | unset | registrable domain | Relying Party ID (e.g. `chat.example`). Passkeys are scoped to this; it must match the site the client's `navigator.credentials` call runs on. Null ⇒ WEBAUTHN unavailable. |
| `origins` | array of strings | `[]` | `https://…` origins | Allowed top-level origins. A ceremony whose clientDataJSON `origin` is not listed is rejected. Empty ⇒ WEBAUTHN unavailable. |
| `require_uv` | bool | `false` | `true` or `false` | Require the User-Verified (UV) flag (not just User-Present) in authenticatorData for both registration and login. When off, wire behaviour is byte-identical to the UP-only default. |
| `require_attestation` | bool | `false` | `true` or `false` | Require a verified attestation statement at registration (`fmt` may not be `none`). The attestation signature is verified fail-closed, but the x5c leaf is NOT anchored to a bundled FIDO metadata root — this proves tamper-evidence, not hardware provenance. When off, registration keeps trust-on-first-use. |

## `[oper]`

Operator subsystem settings, distinct from the per-operator `[[opers]]` bindings
below. Source: struct `OperSection` at `src/daemon/config_format.zig`, parsing at
`src/daemon/config_format.zig`, mapping at `src/daemon/config_boot.zig`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `grants_path` | string or null | unset | path | File for persisting runtime `GRANT`/`REVOKE` operator grants. When set, active grants are written here on change and reloaded at boot, so runtime-granted opers survive a restart; revoked accounts are dropped. See [commands/oper-moderation.md](commands/oper-moderation.md#grant). |
| `event_history_path` | string or null | unset | path | File for persisting the Event Spine history ring so `EVENT REPLAY` survives a USR2 hot-upgrade and a cold restart. Loaded at boot and rewritten by reactor 0 on the stats cadence; unset keeps the history per-process-lifetime (`src/daemon/config_format.zig`, `src/daemon/server.zig`). |
| `two_person_rule` | bool | `false` | boolean | Gate DIE, RESTART and mesh-scope bans on a second distinct operator identity confirming the same kind/target within 60 seconds. The first request waits; the same identity cannot approve itself. This is separate from command privilege checks. |
| `auto_override` | bool | `false` | — | Auto-enable the `+j` override umode on elevation for any operator holding the `oper_override` privilege, so admins get full channel authority (KICK/MODE/TOPIC/PROP/…) without a manual `/mode +j`. `false` keeps override an explicit, audited opt-in (`src/daemon/server.zig` `applyOperAutoOverride`). |

### `[oper.ocg2]`

Durable operator authority has three explicit stages: observation, projection
onto live operator sessions, and authority-node minting. All default off. The
active `config_boot.zig` supports project and mint; they are not reserved
parser-only flags. Shared config contains only a public authority tuple. The
private seed comes from the authority node's existing identity.

| Key | Type | Default | Requirements and behavior |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Load/validate durable OCG2 state. Alone selects observe mode with no privilege consumer. Requires an enabled account store and the complete public authority tuple. |
| `projection_enabled` | bool | `false` | Requires `enabled`; applies verified durable authority to live sessions. This changes authority behavior and is a separate rollout decision. |
| `minting_enabled` | bool | `false` | Requires enabled plus projection. Only the node matching the exact authority public key/derived short ID may mint; receivers cannot enable mint mode. |
| `authority_node_id` | integer or string | `0` before validation | Required nonzero when enabled. Positive TOML integer or exactly 16 hexadecimal characters in a quoted string; the string form supports the full unsigned 64-bit short-ID domain. Must equal the short ID derived from the authority public key. |
| `authority_public_key` | string | unset | Required when enabled; 32-byte Ed25519 public key as hex or standard base64, with explicit string indirection support. |

When disabled, specifying either authority field is rejected. Unknown fields in
this table are rejected, including private-key inventions. The account store
must be available (`sasl.account_db`, with SASL not explicitly disabled), and
storage record/WAL limits must fit the durable authority representation. Mode
and authority state are constructed at startup; REHASH is not activation.
Preserve strict verified durable state across Helix. Validate the staged plan
before enabling projection or minting on a production mesh.

A safe default is:

```toml
[oper.ocg2]
enabled = false
projection_enabled = false
minting_enabled = false
# Supply the matching public tuple before selecting an enabled mode.
```

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

### `[[wasm.registry]]` entry fields

`registry` is an array of inline tables (or equivalent TOML table records).
Only a pin's `name` passes through string indirection; the cryptographic tokens
are literal encoded values. The same interpreter trust policy still applies
after a digest matches.

| Entry key | Type | Default/requirement | Meaning |
| --- | --- | --- | --- |
| `name` | string | required | Logical plugin name used by the registry. |
| `blake3` | string | required, exactly 64 hex characters | BLAKE3-256 digest of the exact `.wasm` bytes. |
| `tier` | string | `"listed"` | `unlisted`, `listed` or `verified`; caps the allowed hostcalls and privileged intents. |
| `publisher` | string | optional; exactly 64 hex characters | Ed25519 public key for the signed registry transcript. Must accompany `signature`. |
| `signature` | string | optional; exactly 128 hex characters | Ed25519 signature over the canonical pin transcript. Must accompany `publisher`; a malformed/incomplete pair is rejected. |

Use digests/signatures computed for the exact reviewed plugin; fabricated
placeholders cannot establish trust. Policy does not let plugins shadow built-in
commands. Update through REHASH and inspect `OROWASM PLUGINS`/`OROWASM STATUS`.

## `[[opers]]`

Source: struct `Oper` at `src/daemon/config_format.zig`, parsing at `src/daemon/config_format.zig`, SASL-only runtime behavior at `src/daemon/server.zig`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `account` | string | required per table | non-empty; registry validation max 128 bytes | SASL account name that becomes oper after successful SASL login (`src/daemon/config_format.zig`, `src/daemon/oper.zig`). |
| `class` | string | `""` | registry validation max 64 bytes | Operator privilege group name. It must name a non-empty configured group with effective privileges; otherwise the oper binding is skipped (`src/daemon/config_boot.zig`). |
| `title` | string | `""` | any string | Optional WHOIS/operator title (`src/daemon/config_format.zig`, `src/daemon/oper.zig`). |
| `presubscribe` | array of strings | `[]` | Event-Spine category names (e.g. `["ANNOUNCE","KILL"]` or `["ALL"]`) | Event-Spine categories this oper is auto-subscribed to on elevation. Empty = none (the oper opts in per-category with `EVENT ADD`). A cross-mesh grant carries no presubscribe, so a remotely granted oper defaults to none (`src/daemon/config_format.zig`, `src/daemon/server.zig`). |
| `certfp` | string or array of strings | `[]` | lowercase-hex SHA-256 fingerprint(s), 64 chars each | TLS client-certificate fingerprints pre-bound to this oper's `account` at boot, so SASL EXTERNAL works without a prior runtime `CERTADD`. Accepts a single string or an array; each is seeded into the certfp bind store and coexists with runtime `CERTADD` bindings. Malformed entries are skipped with a boot warning (never fatal); case is normalized to lowercase (`src/daemon/config_format.zig`). |

There is no oper password. `OPER` is disabled and directs users to authenticate through SASL (`src/daemon/server.zig`). A matching account binding is subject to the live authentication/authority gates: a passkey-locked account does not gain oper projection from a password, recovery or session-token session; it requires the supported passkey/EXTERNAL step-up path. OCG2 projection, when enabled, is an additional durable-authority path.

## `[[oper_groups]]`

Source: struct at `src/daemon/config_format.zig`, parsing at `src/daemon/config_format.zig`, group registry at `src/daemon/operator_groups.zig`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `name` | string | required per table | non-empty | Group name referenced by `[[opers]].class` (`src/daemon/config_format.zig`). |
| `privileges` | array of strings | `[]` | exact `oper.Privilege` enum names | Privilege flags included in the group. Unknown names are ignored by boot conversion (`src/daemon/config_boot.zig`). |
| `inherits` | string | `""` | group name | Optional parent group; effective privileges union parent links up to depth 32 (`src/daemon/operator_groups.zig`). |

Valid privilege strings are the exact enum names from `src/daemon/oper.zig`: `server_rehash`, `server_restart`, `server_shutdown`, `client_moderate`, `channel_moderate`, `client_kill`, `mesh_admin`, `service_admin`, `server_admin`, `oper_grant`, `oper_spy`, `event_subscribe`, `audit_read`, `oper_override`, and `limit_exempt`.

Note one current behavior: if an oper names a class that has no group, or that resolves to an empty effective privilege set, boot skips that oper binding (`src/daemon/config_boot.zig`). REHASH rebuilds configured operator bindings through the same group resolver and has coverage for preserving group privileges (`src/daemon/server.zig`).

## Configuration examples and operational dependencies

These are **partial overlays**, not complete configs. Merge keys into existing
tables instead of repeating a TOML table. Set the required node/listen identity,
create directories under the daemon user, and validate the complete file before
applying the restart/reload policy above. Example hostnames and public keys must
be replaced; enabling a service is an explicit deployment choice.

### Local development and a public TLS listener

A minimal local instance keeps network exposure on loopback:

```toml
[node]
id = 1
[listen]
host = "127.0.0.1"
irc = 16667
```

For public TLS, add certificate material and a unique server name. An enabled
TLS listener with omitted certificate/key settings bootstraps a self-signed leaf.
Configured missing files fail certificate loading rather than trigger bootstrap.
Self-signed bootstrap is useful for controlled testing, not public enrollment.

```toml
[network]
name = "Example Network"
server_name = "irc-a.example.net"
[tls]
enabled = true
port = 6697
cert_path = "/etc/onyx-server/tls/fullchain.pem"
key_path = "/etc/onyx-server/private/server.key"
[sts]
enabled = true
port = 6697
duration = 2592000
preload = false
```

The service sandbox must permit actual cert/key reads. `--check-config` passing
outside the effective sandbox does not prove TLS will open inside it. Confirm
listener availability and a verified TLS handshake after activation. Optional
ACME requires reachable HTTP-01 forwarding and writable cert/key destinations;
OCSP needs a suitable issuer/responder and trust material. Neither option repairs
an unreadable private key or an invalid serving chain.

### Account authentication, relay trust and passkeys

```toml
[sasl]
enabled = true
account_db = "/var/lib/onyx-server/private/accounts.wal"
allow_anonymous = false
oauth_auto_provision = false
[mail]
enabled = true
relay_host = "smtp.example.net"
relay_port = 587
starttls = true
trust_store_path = "/etc/ssl/certs/ca-certificates.crt"
insecure_skip_verify = false
from = "irc@example.net"
user = "env:ONYX_SMTP_USER"
pass = "@file:/etc/onyx-server/private/smtp-password"
[webauthn]
rp_id = "chat.example.net"
origins = ["https://chat.example.net"]
require_uv = true
require_attestation = false
```

The WebAuthn origin is the browser application's origin, not necessarily the
IRC server name. Require UV only when intended authenticators support it.
`require_attestation` verifies the submitted statement; it does not supply a
FIDO hardware-vendor trust database. Mail delivery depends on relay DNS, TLS,
credentials and sender policy; enabling it does not guarantee receipt.

For OAUTHBEARER, choose **one** key source (`oauth_hmac_key`, `oauth_jwks_file`,
or `oauth_pubkey`) and restrict `oauth_issuer`/`oauth_audience` to the provider's
intended values. Use `oauth_account_claim` to select the exact account claim.
Multiple key sources fail parsing. JWT verification does not grant oper rights;
keep auto-provision false unless accepting otherwise unregistered names is
intended. Key files are process-CWD based; `@file:` on a path-valued setting
would substitute the file contents as a path, which is usually incorrect.

### Secured mesh and reusable-session rollout

Before configuring a peer, provision unique node identities, exact direct-peer
public-key pins and the shared cloak secret. Active identity meshes require a
private `mesh.presence_store_path`; retain this WAL across maintenance. See
[the mesh guide](../guide/mesh.md) and the [activation checklist](../ops/mesh-metrics-deploy-checklist.md)
for identity/roster examples rather than inventing trust roots.

```toml
[mesh]
realm = "example-private"
require_secured = true
require_signed_frames = true
presence_store_path = "/var/lib/onyx-server/private/mesh-presence.wal"
# trust_roots = ["env:EXACT_DIRECT_PEER_PUBLIC_KEY"]
# connect = ["irc-b.example.net:6900"]
[cloak]
secret = "@file:/etc/onyx-server/private/shared-cloak-secret"
[sessions]
max_per_account = 64
resume_composite_issuance = false
migrate_on_detach = true
max_pending_migrations = 4096
```

This overlay deliberately omits enabled listeners and activation keys. Turning on
MESSAGE_V2 authorship requires the complete validated epoch/full-mesh roster and
matching direct-neighbor custody membership everywhere; changing `compat` to
`active` alone is invalid. Retain the accepted activation tuple through upgrades.
Composite credential issuance is a separate client rollout gate; forwarding a
mesh credential is not proof that the contacted node can perform arbitrary exact
attachment migration. Test the supported resume/redirect behavior end to end.

### Browser media and consented packet journals

```toml
[media]
enabled = true
ws_media_relay = true
ws_media_require_mac = true
native_media_require_mac = true
dtls_srtp = false
dtls13 = false
recording_enabled = false
recording_retention_days = 7
recording_max_total_bytes = 536870912
recording_max_duration_secs = 14400
# recording_dir = "/var/lib/onyx-server/private/recordings"
```

The browser transport needs the configured WSS listener/TLS material and clients
that negotiate the media protocol and attach valid MACs. Native/DTLS legs need
reachable UDP candidates and compatible clients. `dtls13` requires DTLS-SRTP
termination and does not enable it implicitly.

Recording remains off in this example. To enable it, provision the private
recording directory and set both `recording_dir` and `recording_enabled = true`.
The feature journals accepted packet data with consent; it is not a server-side
decryption key or a ready-to-play transcoder. The byte cap is **per recording**
across its segments, not a whole-directory disk quota. Retention runs on the first
recording start after boot, so arrange independent storage monitoring. Stop and
drain active/finalizing writer state before Helix.

### Webhook ingress, browser push and publication files

```toml
[webhook]
enabled = true
bind = "127.0.0.1"
listen = 18080
store_path = "/var/lib/onyx-server/private/webhooks.tsv"
public_url_base = "https://irc.example.net"
max_body_bytes = 8192
rate_per_min = 60
rate_burst = 10
allow_private_targets = false
[webpush]
enabled = false
subject = "mailto:ops@example.net"
vapid_key_path = "/var/lib/onyx-server/private/webpush-vapid.key"
[metrics]
listen = 9130
bind = "127.0.0.1"
[stats]
dir = "/var/lib/onyx-server/public/stats"
channel_dir = "/var/lib/onyx-server/public/channels"
interval = "30s"
ignore_nicks = ["ExampleBot"]
[backup]
dir = "/var/lib/onyx-server/private/backups"
interval = "24h"
```

Front webhook HTTP with a buffering TLS reverse proxy. Keep returned webhook
URLs secret; their token authorizes injection. `allow_private_targets` applies
to outbound destinations, independently of this inbound loopback listener.

Web Push additionally requires the account store, saved browser subscriptions,
HTTPS reachability and the configured ACME trust bundle even when ACME renewal
is disabled. Preserve the VAPID key when restarting; do not rotate it during an
ordinary deployment.

Stats publication does not imply a web server serves those paths. Provision
public-reader directory access and an explicit file-creation mask when sharing
with a separate web user; retain private permissions for account, webhook,
identity, recording and backup state. Avoid widening the daemon's entire working
directory to publish a feed. Backups cover the documented included families;
run `--restore-drill` into scratch space and assess excluded state separately.

### Named-class policy and plugin isolation

A class can cap account connections independently of proxy IP sharing. Because
named TOML table order is not guaranteed, use disjoint selectors and inspect
`STATS Y` after reload. A catch-all table can otherwise win before a more specific
policy. For per-class inheritance use integer `0`, not a global zero-duration
string. Changing the global `max_clients` limit does not allocate a larger
connection table through REHASH.

Wasm defaults grant only minimal reply/log/time hostcalls. To expose privileged
message content, both a verified registry tier and the explicit
`allowed_intents = ["message-content"]` policy plus the plugin's matching import
are required. A registry pin is a content digest, not just a filename. Keep
`revoked_blake3` and `disabled_plugins` available as live kill switches, and do
not interpret `net:outbound` as unrestricted filesystem or process access.

## Parser and runtime scope

The tables describe accepted parser keys and identify important consumer gates.
Acceptance alone does not enable a listener, service or protocol: enabled flags,
credentials, account stores, trust anchors, kernel support and peer capability
negotiation still apply. `[mesh.ripple]` is the notable library/runtime distinction
described above. `io.defer_taskrun` is accepted and projected, but Ringlane does
not request `DEFER_TASKRUN`/`SINGLE_ISSUER`; enabling it does not enable those
kernel flags, and combining it with SQPOLL is rejected at configuration check.
OCG2 observe mode deliberately validates durable authority
without projecting privileges; project/mint modes are separate explicit choices.
Unknown keys are not a safe way to reserve future behavior.

`media.hidden_recorder` and `media.record_without_consent` are **rejected**
configuration names, not supported switches. Boolean/string occurrences return
`HiddenRecorderRefused`; do not use them even with `false`. The supported recorder
requires the in-call consent path.

## Comptime-bound values not yet configurable

| Value | Bound | Source |
|---|---:|---|
| Maximum daemon shards | `4096` | `src/daemon/shard.zig` |
| Operator account name length | `128` bytes | `src/daemon/oper.zig` |
| Operator class name length | `64` bytes | `src/daemon/oper.zig` |
| Operator group inheritance depth | `32` links | `src/daemon/operator_groups.zig` |
