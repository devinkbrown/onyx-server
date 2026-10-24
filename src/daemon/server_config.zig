// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Daemon runtime configuration and borrowed boot authorities.
//! Parsing, normalization, and lifecycle transitions remain with their owners.

const std = @import("std");
const linux = std.os.linux;
const wasm_abi = @import("../wasm/host/abi.zig");
const wasm_bridge = @import("../wasm/host/bridge.zig");
const cadence_frame = @import("../substrate/cadence_frame.zig");
const relay_v2_activation = @import("relay_v2_activation.zig");
const sasl = @import("../proto/sasl.zig");
const sasl_mechrouter = @import("../proto/sasl_mechrouter.zig");
const multiline = @import("../proto/multiline.zig");
const search_index_mod = @import("search_index.zig");
const s2s_link = @import("s2s_link.zig");
const rdns = @import("rdns.zig");
const dnsbl_resolver = @import("dnsbl_resolver.zig");
const mail_sender = @import("mail_sender.zig");
const protocol_inventory = @import("../proto/protocol_inventory.zig");
const cloak = @import("../proto/cloak.zig");
const content_filter_mod = @import("content_filter.zig");
const media_room = @import("media_room.zig");
const tls_server = @import("../crypto/tls_server.zig");
const memo_mod = @import("memo.zig");
const transcript_mod = @import("transcript.zig");
const node_identity = @import("node_identity.zig");
const ecdsa_p256 = @import("../crypto/ecdsa_p256.zig");
const rsa_sign = @import("../crypto/rsa_sign.zig");
const oper_mod = @import("oper.zig");
const conn_class = @import("conn_class.zig");
const config_format = @import("config_format.zig");
const services_mod = @import("services.zig");
const ocg2_runtime_mod = @import("ocg2_runtime.zig");
const ocg2_projection_mod = @import("ocg2_projection_runtime.zig");
const audit_trail_mod = @import("audit_trail.zig");
const durable_credential_props = @import("durable_credential_props.zig");
const reactor_mod = @import("../substrate/reactor.zig");
const ringlane = @import("ringlane.zig");
const RingFeatureSet = ringlane.RingFeatures;

const native_upgrade = @import("native_upgrade_contracts.zig");
const ListenerDescriptor = native_upgrade.ListenerDescriptor;
const NativeUpgradeHooks = native_upgrade.NativeUpgradeHooks;
const NativeAdoptBarrier = native_upgrade.NativeAdoptBarrier;

pub const server_name = "onyx.local";

pub const DurableDeviceBoot = union(enum) {
    inactive,
    /// Explicit migration/test mode: remove every legacy device PROP and its
    /// clock without installing a durable authority. Production main never
    /// selects this arm.
    purge_only,
    authoritative: struct {
        /// Strictly restored from the configured account OroStore before the
        /// server is constructed. The owner must outlive both Services and the
        /// server.
        state: *durable_credential_props.State,
        local_origin_node: u64,
    },
};

pub const Config = struct {
    host: []const u8 = "127.0.0.1",
    port: u16,
    /// base64url VAPID public key; when set, advertised as ISUPPORT `VAPID=`
    /// so clients can pushManager.subscribe without any round-trip.
    webpush_vapid_pub: []const u8 = "",
    /// Link previews. Off until an operator opts in. A client still has to opt in.
    unfurl_enabled: bool = false,
    /// Pre-001 challenge ladder. Off keeps a reputation trip as a hard refuse.
    /// On, a reputation trip or an engaged raid shield asks for a challenge
    /// before 001. Passing the challenge is not an account.
    challenge_enabled: bool = false,
    /// WebAuthn (passkey) Relying Party ID — a registrable domain the passkeys
    /// are scoped to (`[webauthn] rp_id`). Null ⇒ the WEBAUTHN command fails
    /// closed (the feature is inert until both this and an origin are set). The
    /// string is borrowed from the parsed config (process-lifetime).
    webauthn_rp_id: ?[]const u8 = null,
    /// Allowed WebAuthn top-level origins (`[webauthn] origins`). A ceremony with
    /// a clientDataJSON `origin` not on this list is rejected. Empty ⇒ inert.
    /// Slices borrowed from the parsed config (process-lifetime).
    webauthn_origins: []const []const u8 = &.{},
    /// Require the UV (User-Verified) flag — not just UP — in authData for both
    /// registration and passwordless login (`[webauthn] require_uv`). Opt-in;
    /// default false leaves the UP-only behaviour byte-identical.
    webauthn_require_uv: bool = false,
    /// Require a verified attestation statement at registration, rejecting `none`
    /// (`[webauthn] require_attestation`). Opt-in; default false keeps
    /// trust-on-first-use while still verifying any attestation that IS present.
    webauthn_require_attestation: bool = false,
    /// Network name advertised in ISUPPORT `NETWORK=` and the welcome burst.
    /// Configurable via `[network] name`; installed into the protocol_inventory
    /// override at boot.
    network_name: []const u8 = protocol_inventory.network_name,
    /// This server's own name (the source prefix in server-originated lines and
    /// the identity presented to S2S peers). MUST be unique per node in a mesh so
    /// replies/identities don't collide. Configurable via `[network] server_name`;
    /// defaults to the build-time `server_name` constant.
    server_name: []const u8 = server_name,
    /// Human description of THIS node, shown in VERSION, the WHOIS RPL_WHOISSERVER
    /// (312) trailing for local users, and advertised to S2S peers so remote
    /// WHOIS names the right per-server description. Configurable via
    /// `[network] description`; defaults to the generic daemon tagline.
    server_description: []const u8 = "Onyx Server - pure-Zig mesh IRC daemon",
    /// IRCv3 network icon URL, advertised as the `NETWORKICON=<url>` ISUPPORT
    /// token when non-empty. Configurable via `[network] icon_url`; empty omits
    /// the token (NETWORKICON support).
    network_icon_url: []const u8 = "",
    /// Opt-in bit for public discovery directories. Exported in status.json so
    /// crawlers can distinguish intentionally public nodes from private meshes.
    network_discoverable: bool = false,
    /// MOTD text served by the MOTD command, split on newlines. Empty = the
    /// built-in default MOTD. Configurable via `[motd] text` (supports @file:).
    motd_text_raw: []const u8 = "",
    /// ADMIN command contact details. Configurable via `[admin] location/email`.
    admin_location: []const u8 = "Onyx IRC network",
    admin_email: []const u8 = "admin@onyx.local",
    /// Localized weather for the MOTD `{weather}` placeholder (`[weather]`).
    /// `weather_source` is a key=value file refreshed by an external updater;
    /// the daemon reads + localizes it per MOTD request.
    weather_enabled: bool = false,
    weather_location: []const u8 = "",
    weather_country: []const u8 = "",
    weather_units: []const u8 = "auto",
    weather_source: []const u8 = "",
    /// Headlines for the MOTD `{news}` placeholder (`[news]`). `news_source` is
    /// a one-headline-per-line file; `news_count` are joined into one line.
    news_enabled: bool = false,
    news_source: []const u8 = "",
    news_count: u32 = 3,
    /// Live `!weather`/`!news` fantasy bot (`[geo]`). When enabled the daemon
    /// fetches wttr.in (weather) + the news_sources RSS feeds in a background
    /// thread and serves them to channel `!weather`/`!news` commands.
    geo_enabled: bool = false,
    /// Skip TLS verification for news feeds (public read-only data) so the
    /// best-effort clean-room TLS reaches more hosts. `[geo] news_insecure_tls`.
    geo_news_insecure_tls: bool = true,
    /// Minimum interval between fantasy-bot (`!weather`/`!news`) replies in a
    /// single channel, in ms (anti-flood). 0 disables. `[geo] cmd_cooldown_ms`.
    geo_cmd_cooldown_ms: u32 = 3000,
    /// Fallback location for `!weather` when a user has no GeoIP/`location`
    /// metadata. `[geo] default_location`.
    geo_default_location: []const u8 = "",
    /// Directory of headline files written by tools/news_update.sh. When set,
    /// `!news` is served from these files (robust full coverage) instead of
    /// in-daemon TLS fetches. `[geo] news_cache_dir`.
    geo_news_cache_dir: []const u8 = "",
    /// Path for persisting mesh display OCG1 grants (GRANT/REVOKE). When set,
    /// non-tombstone records are written here and reloaded at boot so remote
    /// `*` / `+Y` projection can resume after restart. Local OPER/DEOPER
    /// remains the authorization path.
    oper_grants_path: []const u8 = "",
    /// Path for persisting the Event Spine history ring (`[oper]
    /// event_history_path`); loaded at boot, rewritten on the stats cadence.
    /// Empty = in-memory only (per-process lifetime).
    event_history_path: []const u8 = "",
    /// Operator-named flight recorder file (`[trace] file`). Empty keeps the
    /// ring in memory for oper DEBUG and writes nothing on a fault.
    flight_recorder_path: []const u8 = "",
    /// Auto-enable the +j override umode on elevation for opers with the
    /// oper_override privilege (full channel authority without `/mode +j`).
    /// `[oper] auto_override`.
    oper_auto_override: bool = false,
    /// When set, DIE, RESTART, and mesh-scope bans wait for a second distinct
    /// operator. Default off leaves a single-oper network unchanged.
    two_person_rule: bool = false,
    /// Directory scanned at boot/REHASH for `*.wasm` OroWasm control-plane
    /// plugins. Empty = the plugin system stays dormant. `[wasm] plugin_dir`.
    wasm_plugin_dir: []const u8 = "",
    /// Maximum bytes accepted for one `.wasm` plugin file. `[wasm]
    /// max_plugin_bytes`.
    wasm_max_plugin_bytes: usize = wasm_bridge.max_plugin_bytes,
    /// Maximum linear memory bytes per plugin instance. `[wasm]
    /// max_memory_bytes`.
    wasm_max_memory_bytes: usize = wasm_bridge.default_max_memory_bytes,
    /// Instruction fuel per plugin command/hook dispatch. `[wasm] default_fuel`.
    wasm_default_fuel: u64 = wasm_bridge.default_fuel,
    /// Hostcall capability classes plugins may receive. `[wasm] allowed_caps`.
    wasm_allowed_caps: wasm_abi.CapabilitySet = wasm_bridge.default_allowed_caps,
    /// Privileged plugin data-access intents. `[wasm] allowed_intents`.
    wasm_allowed_intents: wasm_abi.IntentSet = .empty,
    /// Content-addressed plugin registry pins. Non-empty means only pinned
    /// plugins whose BLAKE3 digest matches are loadable. `[wasm] registry`.
    wasm_registry: []const wasm_bridge.RegistryPin = &.{},
    /// Revoked plugin BLAKE3 digests refused regardless of name or registry pin.
    /// `[wasm] revoked_blake3`.
    wasm_revoked_hashes: []const [std.crypto.hash.Blake3.digest_length]u8 = &.{},
    /// Plugin names refused by the local trust policy / kill-switch.
    /// `[wasm] disabled_plugins`.
    wasm_disabled_plugins: []const []const u8 = &.{},
    /// Maximum stored channel topic length in bytes (advertised as TOPICLEN and
    /// enforced by handleTopic). Configurable via `[limits] topiclen`.
    topiclen: u32 = 390,
    /// Maximum away-message length in bytes (advertised as AWAYLEN, enforced by
    /// handleAway). Configurable via `[limits] awaylen`; hard-capped by storage.
    awaylen: u32 = 256,
    /// Maximum kick-comment length in bytes (advertised as KICKLEN, enforced by
    /// handleKick). Configurable via `[limits] kicklen`.
    kicklen: u32 = 307,
    /// Maximum nick length in bytes (advertised as NICKLEN, enforced in the
    /// pre-registration dispatch path via the runtime-limits holder). Capped by
    /// the nick store (64). Configurable via `[limits] nicklen`.
    nicklen: u32 = 64,
    /// Maximum channel-name length in bytes (advertised as CHANNELLEN, enforced
    /// by joinOne). Configurable via `[limits] channellen`.
    channellen: u32 = 64,
    /// Per-channel cap on each list mode (+b/+e/+I/+Z) — advertised as MAXLIST
    /// and enforced by world.listAddMask. Configurable via `[limits] maxlist`.
    maxlist: u32 = 100,
    /// Max channels a non-oper client may be in (advertised as CHANLIMIT,
    /// enforced by joinOne). Configurable via `[limits] chanlimit`.
    chanlimit: u32 = 50,
    /// Max comma-separated targets accepted in one PRIVMSG/NOTICE (advertised as
    /// MAXTARGETS, enforced by handleMessage). Configurable via `[limits]
    /// maxtargets`.
    maxtargets: u32 = 4,
    /// Maximum channel-key (+k) length in bytes (advertised as KEYLEN, enforced
    /// by handleMode's +k branch). A value-typed field, so a live REHASH that
    /// rebuilds Config never dangles. Configurable via `[limits] keylen`.
    keylen: u32 = 64,
    /// How many channel-mode changes a client should combine per MODE command
    /// (advertised as MODES). Honored by mIRC/HexChat — set to 1 for one
    /// mode/target per line. Configurable via `[limits] modes_per_line`.
    modes_per_line: u32 = 4,
    /// Max MONITOR targets per client (advertised as MONITOR, enforced by the
    /// MonitorStore). Configurable via `[limits] monitorlimit`.
    monitorlimit: u32 = 128,
    /// Max SILENCE masks per client (advertised as SILENCE, enforced by the
    /// silence Store). Configurable via `[limits] silencelimit`.
    silencelimit: u32 = 32,
    /// draft/multiline inbound batch limits. Advertised through CAP LS 302 and
    /// enforced by the per-connection reassembler. Configurable via `[ircv3]`.
    multiline_max_bytes: usize = multiline.default_max_bytes,
    multiline_max_lines: usize = multiline.default_max_lines,
    multiline_ref_len: usize = multiline.default_max_ref_len,
    multiline_target_len: usize = multiline.default_max_target_len,
    /// Registry command feature toggles disabled by config. A registry command
    /// whose `feature` tag appears here is rejected at dispatch as unavailable.
    /// Borrowed; outlives the server (owned by main/config). Empty = all on.
    disabled_features: []const []const u8 = &.{},
    /// Whether media transports and media-tagged registry commands are enabled.
    media_enabled: bool = false,
    /// Runtime cap for opaque upload payloads that feed media paths. Reserved for
    /// upload-bearing media commands; set from `[media].max_upload_bytes`.
    media_max_upload_bytes: u64 = 16 * 1024 * 1024,
    /// Runtime cap for one UDP media datagram accepted by the WebRTC/native
    /// pumps. Set from `[media].max_frame_bytes` and clamped to the socket bound.
    media_max_frame_bytes: u64 = 64 * 1024,
    /// Runtime Cadence reorder window for media reassembly. Validated by the
    /// config parser to fit the inline reassembly window ceiling.
    media_reorder_window_frames: u32 = cadence_frame.default_reorder_window_frames,
    /// Runtime SFU participant cap per room, bounded by the inline roster
    /// ceiling in media_room/native media link.
    media_max_participants: usize = media_room.default_max_participants,
    /// Runtime cap for MEDIA BREAKOUT label bytes. Configurable via
    /// `[media.sfu].max_breakout_label_bytes`.
    media_sfu_max_breakout_label_bytes: usize = media_room.max_breakout_bytes,
    /// Runtime transcript/caption retention limits. Configurable via `[media]`
    /// caption keys.
    transcript_config: transcript_mod.Config = .{},
    /// Runtime PINS channel-prop bounds. Configurable via `[media.pins]`.
    media_pins_max_per_channel: usize = 50,
    media_pins_max_msgid_bytes: usize = 64,
    /// Runtime MEDIA REACT token byte cap. Configurable via `[media.reactions]`.
    media_reactions_max_token_bytes: usize = 32,
    /// Require the native CadenceVox/CadenceVis UDP leg to carry a per-datagram MAC tag.
    /// Defaults false for compatibility until Nexus/Ocean emit matching tags.
    native_media_require_mac: bool = false,
    /// Primary browser media plane: relay binary WebSocket Cadence frames
    /// (client-held E2EE ciphertext) between a channel's call participants.
    /// Off by default; opt-in. When on, MEDIA JOIN issues MACKEY and OFFER
    /// suppresses unroutable NATIVE/TRANSPORT for WS clients.
    ws_media_relay: bool = false,
    /// Require a valid per-stream MAC tag on every browser media datagram. When
    /// false (default), untagged datagrams still relay but a present tag must
    /// verify; the per-stream key is the same `native_stream_key`-derived
    /// `(channel, participant)` key the native UDP leg uses. Prefer true with
    /// `ws_media_relay` in production.
    ws_media_require_mac: bool = false,
    /// Terminate DTLS-SRTP (RFC 5764) on the WebRTC UDP media plane so standard
    /// browser/mobile endpoints can key the SRTP leg via a DTLS handshake
    /// alongside the signaled group key. Off by default; when off the media
    /// pump is byte-identical to today (no DTLS demux branch).
    media_dtls_srtp: bool = false,
    /// Additionally offer the DTLS 1.3 (RFC 9147) handshake on the media plane
    /// (requires `media_dtls_srtp`). Off by default; independent opt-in.
    media_dtls13: bool = false,
    /// Path to a MaxMind GeoIP database (.mmdb); empty = no GeoIP. Loaded lazily
    /// on first GEOIP use via Config.crypto_io. Borrowed; outlives the server.
    geoip_db_path: []const u8 = "",
    /// Optional path to a separate ASN database (.mmdb) for WHOIS AS-number/org
    /// (city DBs don't carry ASN). Empty = no ASN. Loaded lazily. Borrowed.
    geoip_asn_db_path: []const u8 = "",
    /// Directory to publish web stats into (stats.json + index.html), e.g. an
    /// nginx `root`. Empty = disabled. Written periodically via Config.crypto_io.
    stats_web_dir: []const u8 = "",
    /// Directory to publish per-CHANNEL statistics JSON (index.json + one
    /// <slug>.json per channel) for the channel-stats dashboard; nginx serves it
    /// at `/stats/data/`. Empty = channel stats off (no recording, no I/O).
    chanstats_dir: []const u8 = "",
    /// Borrowed nicks excluded from chanstats (from `[stats] ignore_nicks`).
    chanstats_ignore_nicks: []const []const u8 = &.{},
    /// Minimum interval between web-stats writes, in ms.
    stats_interval_ms: i64 = 30_000,
    /// Directory for periodic local backup sets. Empty = disabled. When enabled,
    /// reactor 0 copies the compacted account-store snapshot and chanstats binary
    /// snapshot here on `backup_interval_ms`.
    backup_dir: []const u8 = "",
    /// Minimum interval between backup sets, in ms. Defaults to daily.
    backup_interval_ms: i64 = 24 * 60 * 60 * 1000,
    /// Configured `[sasl] account_db` path, used only for backup manifests.
    account_store_path: []const u8 = "",
    /// TCP port for the live Prometheus `/metrics` HTTP listener. 0 = disabled.
    /// When non-zero, a loopback-by-default listener thread is started in
    /// `start()` and torn down in `deinit()`. See metrics_http.zig.
    metrics_port: u16 = 0,
    /// Bind address (host byte order) for the `/metrics` listener. Defaults to
    /// loopback `127.0.0.1`; only widened deliberately via `[metrics].bind`.
    metrics_bind_addr: u32 = 0x7f00_0001,
    /// Discord-compatible incoming webhook endpoint (Gateway interop). OFF by
    /// default: when `webhook_enabled` is false the listener never binds and the
    /// `WEBHOOK` command is not registered — byte-identical to a build without
    /// the feature. See webhook.zig / webhook_http.zig.
    webhook_enabled: bool = false,
    /// TCP port for the plaintext webhook HTTP listener; 0 = OS-ephemeral (the
    /// feature is gated by `webhook_enabled`, not by the port).
    webhook_port: u16 = 0,
    /// Bind address (host byte order) for the webhook listener; loopback default.
    webhook_bind_addr: u32 = 0x7f00_0001,
    /// TSV path persisting webhook bindings across restart + USR2. Empty = none.
    webhook_store_path: []const u8 = "",
    /// Max accepted webhook request-body bytes (larger ⇒ 413).
    webhook_max_body: u32 = 8192,
    /// Per-webhook sustained rate (requests/min); 0 disables rate limiting.
    webhook_rate_per_min: u32 = 60,
    /// Per-webhook token-bucket burst capacity.
    webhook_rate_burst: u32 = 10,
    /// Public URL base for the WEBHOOK CREATE reply; empty ⇒ derive from bind/port.
    webhook_public_base: []const u8 = "",
    /// When false, outbound webhooks refuse loopback and link-local targets.
    /// The inbound listener is unchanged.
    webhook_allow_private: bool = false,
    /// UDP port for the media (SFU) transport plane; 0 = ephemeral. Bound on boot.
    media_port: u16 = 0,
    /// Host/IP advertised to native/WebRTC clients as the server's media (ICE)
    /// candidate. Default 127.0.0.1 is local-only; production needs a public
    /// address or STUN. Browser WS media uses MACKEY instead; loopback hosts
    /// are suppressed for WS OFFER (see `provisionMediaTransports`).
    media_host: []const u8 = "127.0.0.1",
    /// Optional STUN server (IPv4 literal) queried at boot to discover the
    /// reflexive media candidate behind NAT; overrides media_host when it works.
    media_stun_host: []const u8 = "",
    media_stun_port: u16 = 0,
    /// UDP port for the native media transport (our own CadenceVox/CadenceVis codec leg);
    /// 0 = ephemeral. Bound on boot alongside the WebRTC/UDP media plane.
    native_media_port: u16 = 0,
    /// An already-bound+listening socket fd to ADOPT instead of binding fresh
    /// (Helix hot-UPGRADE listener handoff: the port stays bound across execve).
    /// null = bind a new listener normally. Linux only.
    inherited_listener_fd: ?linux.fd_t = null,
    /// Already-bound listening S2S socket. Shard 0 duplicates it and adopts the
    /// duplicate, so the caller closes the original exactly once and the port
    /// never has a bind gap. Null binds `s2s_port` in the normal way. A zero
    /// `s2s_port` still means there is no S2S listener.
    inherited_s2s_fd: ?linux.fd_t = null,
    /// Multi-shard Helix handoff: per-shard client-listener fds in shard order
    /// (`[k]` adopted by reactor `k`). Takes precedence over
    /// `inherited_listener_fd` (whose fd duplicates entry 0) when non-empty.
    /// Entries past the successor's shard count are closed at init; shards past
    /// the list bind fresh SO_REUSEPORT listeners. Linux only.
    inherited_listener_fds: []const linux.fd_t = &.{},
    /// OpenBSD wildcard listeners have a shard-ordered IPv6 companion to each
    /// IPv4 plaintext listener. An inherited wildcard pair requires both fds;
    /// replacing the companion would discard its queued accepts at Helix.
    inherited_listener_companion_fds: []const linux.fd_t = &.{},
    /// Exact authenticated native listener authority. A successor must carry
    /// every enabled role/family/shard; no missing row is replaced by a bind.
    native_listener_manifest: []const ListenerDescriptor = &.{},
    native_upgrade_hooks: ?NativeUpgradeHooks = null,
    /// Exact Windows boot source and ordered config indirection commitment.
    /// This is populated only after a successful single config-file read.
    windows_helix_source_digest: ?[32]u8 = null,
    /// Raw source transcript, before static effective material is added. A
    /// matching REHASH can retain upgrade eligibility for unchanged policy.
    windows_helix_raw_source_digest: ?[32]u8 = null,
    /// Source-independent static external material, captured at boot. Combined
    /// with a fresh source transcript only after an exact live-policy check.
    windows_helix_static_material_digest: ?[32]u8 = null,
    /// Borrowed from main's owned parsed boot config for the process lifetime.
    /// REHASH may only rebind its Windows proof when restart-only and partially
    /// applied config fields remain semantically equal to this snapshot.
    windows_helix_boot_parsed: ?*const config_format.Config = null,
    /// Auto-created node keyfiles are outside the boot-source commitment.
    windows_helix_explicit_node_secret: bool = false,
    /// A per-boot cloak key would change accepted host masks at handoff.
    windows_helix_explicit_cloak_secret: bool = false,
    /// Authenticated decrypted arena, borrowed from the native process owner.
    /// It stays in memory and never passes through Linux memfd readArena.
    native_arena_bytes: ?[]const u8 = null,
    native_adopt_barrier: ?NativeAdoptBarrier = null,
    /// Inherited Helix state-arena memfd (UPGRADE handoff); `adoptInheritedSessions`
    /// reads it after init and before serving to re-attach clients. null = none.
    resume_arena_fd: ?linux.fd_t = null,
    /// Version-independent authoritative manifest of every client and S2S fd
    /// carried by `resume_arena_fd`. It lets a successor close all inherited
    /// sockets even when the arena is corrupt or uses an unsupported schema.
    /// Empty means a legacy predecessor omitted the manifest.
    inherited_state_fds: []const linux.fd_t = &.{},
    inherited_state_fd_manifest_present: bool = false,
    inherited_state_fd_manifest_valid: bool = false,
    backlog: u31 = 128,
    ring_entries: u16 = 32,
    /// Max CQEs reaped per io_uring completion-drain. Larger values reduce
    /// syscall/loop overhead during bursts; smaller values bound per-iteration
    /// latency. Configurable via `[io].cqe_batch`.
    cqe_batch: u16 = ringlane.default_cqe_batch,
    /// Hard cap on concurrent connections. The client table reserves this many
    /// slots up front so ConnState buffers (targeted by in-flight io_uring I/O)
    /// never move; accepts past the cap are refused.
    max_clients: u31 = 1024,
    /// Requested number of worker reactor shards (one io_uring loop per shard).
    /// 1 = the single-reactor model. Values >1 are accepted and carried but
    /// currently clamped to 1 at `runThreaded` until the per-shard reactor array
    /// + RCU world adoption land (the substrate — EBR/HAMT/RcuMap/world_rcu/
    /// reactor_pool/fabric — is already in tree). See docs/planning/24-multithreading.md.
    num_shards: u16 = 1,
    /// Drop a connection that has not completed registration (NICK+USER) within
    /// this many milliseconds (the io_uring timeout sweep enforces it).
    registration_timeout_ms: i64 = 30_000,
    /// Grace window (ms) an unauthenticated user may hold a REGISTERED nick before
    /// being force-renamed to a Guest nick. 0 disables nick protection.
    nick_grace_ms: i64 = 60_000,
    /// A registered client idle (no inbound bytes) for this long is sent a
    /// server PING; if it does not answer within `ping_timeout_ms` it is dropped
    /// with "Ping timeout". The same periodic sweep enforces both.
    ping_interval_ms: i64 = 120_000,
    /// Grace after a server PING before a silent client is dropped (Ping timeout).
    ping_timeout_ms: i64 = 60_000,
    /// Max concurrent client connections from one exact IP (0 = unlimited). Over
    /// the cap, the accept is refused with an ERROR. Loopback is counted too, so
    /// raise this if local bots/services open many connections.
    max_clones_per_ip: u32 = 0,
    /// Max concurrent client connections aggregated across a /24 (IPv4) or /64
    /// (IPv6) prefix (0 = unlimited).
    max_clones_per_net: u32 = 0,
    /// Nick-delay window (ms): how long a released nick is held against reuse
    /// after its owner exits, so a hijacker cannot grab it the instant the owner
    /// drops. The owning account may reclaim during the window; opers and
    /// `nick_delay_exempt` classes bypass. `0` disables nick delay.
    nick_delay_ms: u64 = 0,
    /// Connection throttle: max new connections one source IP may open within
    /// `throttle_window_ms`. `0` disables it. Loopback / trusted-proxy sources
    /// are exempt so a shared reverse proxy never throttles distinct clients.
    throttle_connects: u32 = 0,
    throttle_window_ms: u64 = 10_000,
    /// Network raid guard: the default join-throttle applied to channels that have
    /// no explicit `+j` mode. At most `raid_joins` joins per `raid_secs` window
    /// before new joins are denied (ERR_THROTTLE) and a one-shot Event-Spine raid
    /// alert fires. `raid_joins == 0` disables the network default; an explicit
    /// `+j` on a channel always overrides it. Opers and invited users bypass.
    raid_joins: u16 = 0,
    raid_secs: u32 = 0,
    /// Network-wide (mesh) concurrent connections per source IP: counts local +
    /// every peer's connections from the same salted-IP-hash. `0` disables it.
    /// Authenticated accounts get +2; opers with `limit_exempt` bypass; loopback
    /// and trusted proxies are exempt (WebSocket-safe).
    max_clones_per_ip_net: u32 = 0,
    /// IP-reputation refuse threshold: a peer whose decaying penalty score
    /// reaches this is refused at accept (0 = reputation disabled entirely).
    reputation_refuse_threshold: u32 = 0,
    /// Half-life (ms) of the IP-reputation penalty decay.
    reputation_half_life_ms: i64 = 60_000,
    /// Period (ms) of the io_uring timeout-sweep timer; enforcement granularity
    /// of registration/ping/idle timeouts.
    sweep_interval_ms: i64 = 2_000,
    /// IP-reputation penalty added when a connection never finishes registration.
    reg_timeout_penalty: f64 = 50.0,
    /// IP-reputation penalty added when accept is refused by the clone limiter.
    clone_refuse_penalty: f64 = 25.0,
    /// Multi-session/bouncer registry sizing.
    session_max_accounts: u64 = 65536,
    session_max_per_account: u32 = 64,
    /// Reader-first rollout barrier for SRM2 composite issuance. Decoders are
    /// always enabled; operators explicitly enable writers only after every
    /// node in the rolling mesh understands srm2l/srm2m.
    session_resume_composite_issuance: bool = false,
    session_migrate_on_detach: bool = true,
    session_max_pending_migrations: u32 = 4096,
    /// Runtime memo offline-mailbox limits. Configurable via `[bouncer]`.
    memo_config: memo_mod.Config = .{},
    /// Runtime draft/search inverted-index limits. Configurable via
    /// `[history.search]`.
    search_index_config: search_index_mod.SearchIndex.Config = .{},
    /// Runtime Koshi content-filter limits. Configurable via `[filter]`.
    content_filter_config: content_filter_mod.Config = .{},
    features: RingFeatureSet = RingFeatureSet.baseline,
    /// Optional SASL PLAIN verifier. Injected (not owned) so the Server does not
    /// take on the account store's I/O lifecycle: a caller that has a store wires
    /// `sasl_bridge.ServicesPlainChecker.checker()` here. Null = SASL fails closed.
    sasl_checker: ?sasl.PlainChecker = null,
    /// Password SASL (PLAIN and SCRAM) completes only on TLS. There is no TOML
    /// key. Test configs that log in over the plaintext listener set this true.
    allow_plaintext_password_sasl: bool = false,
    /// Optional SASL SCRAM-SHA-256 credential lookup (account -> SCRAM record).
    /// Injected from the SCRAM credential store; null = SCRAM fails closed. When
    /// set, each accepted connection also gets a fresh CSPRNG server nonce.
    sasl_scram256: ?sasl_mechrouter.Scram256Lookup = null,
    /// Optional SASL SCRAM-SHA-512 credential lookup (account -> SHA-512 SCRAM
    /// record). Injected from the same SCRAM credential store as
    /// `sasl_scram256`; null = SCRAM-SHA-512 fails closed. Served only for
    /// accounts provisioned with SHA-512 material.
    sasl_scram512: ?sasl_mechrouter.Scram512Lookup = null,
    /// Optional SASL EXTERNAL verifier (TLS certfp -> account). Injected from the
    /// account ⇄ certfp binding bridge; null = EXTERNAL fails closed.
    sasl_external: ?sasl_mechrouter.ExternalLookup = null,
    /// Optional SASL SESSION-TOKEN verifier. Injected from account services;
    /// null = SESSION-TOKEN fails closed and is not advertised.
    sasl_session_token: ?sasl_mechrouter.SessionTokenLookup = null,
    /// Optional SASL OAUTHBEARER verifier. Null = OAUTHBEARER fails closed and
    /// is not advertised.
    sasl_oauthbearer: ?sasl_mechrouter.OAuthBearerLookup = null,
    /// Default-off SASL ANONYMOUS gate.
    sasl_allow_anonymous: bool = false,
    /// Let a valid OAUTHBEARER token bind an unregistered account name.
    sasl_oauth_auto_provision: bool = false,
    /// Mutual TLS: request a client certificate on the TLS listener so SASL
    /// EXTERNAL has a fingerprint to match. Off by default.
    tls_request_client_cert: bool = false,
    /// Optional IRCv3 STS wire value ("duration=..,port=..[,preload]"), built by
    /// main.zig from `[sts]` config when a TLS listener is live. Null = STS not
    /// advertised (the default-off honesty guard). Borrowed for the server's life.
    sts_value: ?[]const u8 = null,
    /// Optional server-to-server listener port (0 = disabled). Accepts on this
    /// socket are driven as Undertow mesh peers via S2sLink, not IRC clients.
    s2s_port: u16 = 0,
    /// Parsed `[listen].webtransport` port. The WebTransport listener is not yet
    /// implemented; main logs an explicit diagnostic when this is configured.
    webtransport_port: u16 = 0,
    /// Optional implicit-TLS client listener port (0 = disabled). Accepts here
    /// are ordinary IRC clients whose bytes are wrapped in TLS 1.3 (no STARTTLS).
    /// Requires `tls_cert_chain` plus an Ed25519 or RSA signing key.
    tls_port: u16 = 0,
    /// Leaf-first DER certificate chain presented on the TLS listener. Borrowed
    /// for the server's lifetime (loaded by main.zig via tls_certs.loadOrBootstrap).
    tls_cert_chain: []const []const u8 = &.{},
    /// Ed25519 key matching the leaf cert's SPKI; signs each TLS CertificateVerify.
    tls_signing_key: ?std.crypto.sign.Ed25519.KeyPair = null,
    /// Cached, verified DER OCSPResponse stapled into the leaf when the client
    /// offers status_request. Null = no staple (byte-identical handshakes).
    /// Published by the OCSP fetch service via `publishOcspStaple` and swapped in
    /// on reactor 0 by `maybeSwapOcspStaple`; borrows a server-owned generation
    /// (`ocsp_staple_owned`).
    tls_ocsp_staple: ?[]const u8 = null,
    /// RSA key matching the leaf cert's SPKI; signs TLS 1.3 CertificateVerify
    /// with rsa_pss_rsae_sha256, and TLS 1.2 ServerKeyExchange with
    /// rsa_pkcs1_sha256 when the hardened 1.2 leg is enabled for an RSA leaf.
    tls_rsa_signing_key: ?rsa_sign.PrivateKey = null,
    /// ECDSA P-256 key matching the leaf cert's SPKI; signs TLS 1.3
    /// CertificateVerify with ecdsa_secp256r1_sha256 (and the 1.2 leg natively).
    /// This is the common Let's Encrypt / ACME leaf type.
    tls_ecdsa_signing_key: ?ecdsa_p256.KeyPair = null,
    /// Additional SNI-selectable certificates (`[[tls.sni]]`, loaded by main.zig).
    /// When a ClientHello's server_name matches an entry, the TLS listener presents
    /// that entry's chain+key instead of the default leaf. Borrowed for the server's
    /// lifetime. Empty ⇒ SNI is not consulted (byte-identical single-cert handshake).
    tls_sni_certs: []const tls_server.SniCert = &.{},
    /// Server-side Encrypted Client Hello keys loaded by main.zig. Empty ⇒ ECH is
    /// not accepted, preserving the existing outer-ClientHello behavior.
    tls_ech_keys: []const tls_server.EchKey = &.{},
    /// RFC 7250 server raw public keys. Default false preserves X.509 Certificate
    /// messages; when true, clients that explicitly offer RawPublicKey may receive
    /// the leaf SPKI instead of the certificate chain.
    tls_raw_public_key: bool = false,
    /// Enable TLS 1.3 NewSessionTicket issuance and PSK resumption on the live
    /// TLS listener. Default false keeps the listener's historical full-handshake
    /// behavior byte-identical.
    tls_enable_resumption: bool = false,
    /// Maximum 0-RTT early application bytes advertised in issued tickets.
    /// Zero disables early data while still allowing 1-RTT PSK resumption.
    tls_early_data_max_size: u32 = 0,
    /// kTLS TX offload gate (roadmap 3.1): true only when `[tls] ktls=tx` AND the
    /// running kernel offers the TLS ULP (resolved in main.zig). When true, a
    /// completed TLS 1.3 client conn offloads server→client encryption to the
    /// kernel once its send buffer drains. Default false ⇒ TLS stays in userspace.
    tls_ktls_tx: bool = false,
    /// kTLS RX offload gate: true only when `[tls] ktls=txrx` AND the kernel is
    /// capable. Offloads client→server decryption to the kernel (recv() returns
    /// plaintext). Default false ⇒ inbound stays in userspace.
    tls_ktls_rx: bool = false,
    /// Optional hardened TLS 1.2 leg. When `tls12_signing_key` is set, the TLS
    /// listener accepts TLS 1.2 ECDHE-AEAD clients (routed by version-dispatch in
    /// tls_conn) presenting this ECDSA-P256 leaf; otherwise the listener is
    /// TLS 1.3-only. The 1.2 ServerKeyExchange is signed with ecdsa_secp256r1_sha256.
    tls12_cert_chain: []const []const u8 = &.{},
    tls12_signing_key: ?ecdsa_p256.KeyPair = null,
    /// Native secure-WebSocket (wss) browser listener (`[listen] ws`). When
    /// enabled, accepts on `ws_port` run the SAME TLS engine as the implicit-TLS
    /// listener (the cert chain + signing key above must be present), then an
    /// HTTP/1.1 WebSocket Upgrade; after the 101 the connection is an ordinary
    /// IRC client whose lines travel one-per-text-frame (RFC 6455).
    ws_enabled: bool = false,
    /// Port for the wss listener; 0 = ephemeral bind (tests), same convention
    /// as the other listeners.
    ws_port: u16 = 0,
    /// TESTING ONLY: stand the ws listener up WITHOUT TLS (plain `ws://`) when
    /// no certificate is configured. Browsers require wss on the production
    /// page; this exists for local debugging (`[listen] ws_plain`). Default OFF.
    ws_allow_plain: bool = false,
    /// Accept HAProxy PROXY protocol headers from trusted proxies before
    /// IRC/TLS/WebSocket framing. Disabled unless both this and trusted_proxies
    /// are set.
    proxy_protocol_enabled: bool = false,
    /// Source IP strings allowed to supply PROXY protocol headers.
    trusted_proxies: []const []const u8 = &.{},
    /// This node's sovereign mesh identity — the single id that keys the server
    /// registry, the CRDT replica lane, and gossip/routing. No legacy server-id
    /// (SID): one identity. MUST be unique per node and non-zero. The default is a
    /// placeholder; real deployments set it per server (ultimately derived from
    /// the node's public key).
    node_id: u64 = 1,
    /// Optional reactor seam for time (and, later, I/O). When set, all daemon
    /// time reads route through it instead of the system monotonic clock,
    /// enabling deterministic simulation (DST). Null = real clock (production).
    reactor: ?reactor_mod.Reactor = null,
    /// Optional PQ-secured S2S: when both are set, server-to-server links run the
    /// Mooring AKE (TOFU) before the CRDT stream. Null = plaintext S2S handshake
    /// (backward compatible). `node_identity` is borrowed (owned by main); `io`
    /// supplies the handshake CSPRNG.
    node_identity: ?*const node_identity.NodeIdentity = null,
    /// Optional configured Ed25519 public identity. This lets config preflight
    /// validate a MESSAGE_V2 roster without reading the persisted private
    /// keyfile; server init binds it to the identity actually loaded by main.
    node_public_key: ?[]const u8 = null,
    crypto_io: ?std.Io = null,
    /// Runtime Undertow peer-driver limits/timers/capacities for plaintext and
    /// secured inner S2S links. Configurable via `[mesh.routing]`,
    /// `[mesh.link]`, `[mesh.gossip]`, and `[mesh.ripple]` Ripple keys.
    s2s_config: s2s_link.PeerConfig = .{},
    mesh_realm: []const u8 = "local",
    mesh_pass: []const u8 = "",
    /// `[mesh].presence_store_path`: private durable issuer/presence WAL. Empty
    /// disables ordinary-guest mesh authority; active meshes fail startup.
    mesh_presence_store_path: []const u8 = "",
    /// Encoded `[mesh].admission_token` text (hex or base64). Decoded once at
    /// server init into `LinuxServer.mesh_admission_token`.
    mesh_admission_token: []const u8 = "",
    /// `[mesh].require_secured` — when true, refuse plaintext S2S entirely: reject
    /// inbound plaintext peers and never dial plaintext outbound links. Only the
    /// Mooring-secured path is permitted; if secured S2S is not configured/available
    /// (`!s2sSecured()`), all S2S is dropped rather than silently falling back to
    /// clear. Signed MeshPass admission roots also require this secured S2S path.
    /// Default false preserves the plaintext fallback for unsigned deployments.
    require_secured: bool = false,
    /// `[mesh].trust_roots` as configured strings; decoded at init into
    /// Ed25519 node signing keys for secured-S2S peer allowlisting.
    mesh_trust_roots: []const []const u8 = &.{},
    /// `[mesh].admission_roots`: signer roots for MeshPass signed-capability
    /// tokens. Distinct from peer node identity pins. Non-empty roots are invalid
    /// unless Mooring secured S2S is configured; signed admission is never enforced
    /// on the plaintext S2S path.
    mesh_admission_roots: []const []const u8 = &.{},
    mesh_admission_min_revocation_epoch: u64 = 0,
    /// MESSAGE_V2 is an explicit two-phase rollout. Compatibility nodes accept
    /// and forward V2 but author legacy only; active nodes author each V2-eligible
    /// mesh event as V2 only.
    relay_v2_authoring: relay_v2_activation.Mode = .compat,
    /// Startup state for the local E2EEGROUP authoring barrier. Production maps
    /// `[e2ee].group_authoring_enabled` here so a cold-started successor remains
    /// quiesced throughout first activation. Default true preserves existing
    /// deployments that have not entered that rollout.
    e2ee_group_authoring_enabled: bool = true,
    /// Monotonic operator rollout generation. A non-zero value is meaningful
    /// only with a complete full-mesh `relay_v2_roster`.
    relay_v2_activation_epoch: u64 = 0,
    /// Full secured-mesh Ed25519 node-key roster. Unlike `mesh_trust_roots`,
    /// this is not limited to direct neighbors.
    relay_v2_roster: []const []const u8 = &.{},
    /// `[mesh].connect` — peers ("host:port"; IPv6 hosts bracketed) this node
    /// dials automatically at boot and re-dials while the link is down, so the
    /// S2S mesh stays up without an oper CONNECT. Strings are borrowed (owned
    /// by the parsed config in main). Empty = no auto-connect (default).
    mesh_connect: []const []const u8 = &.{},
    /// Global SASL gate. Existing verifier pointers are ignored when false.
    sasl_enabled: bool = true,
    /// Informational SASL/account realm from config. Wire SASL mechanisms do not
    /// currently emit a realm challenge, but keeping this in runtime config makes
    /// REHASH/config diagnostics honest.
    sasl_realm: []const u8 = "",
    /// Max decoded SASL AUTHENTICATE payload bytes. Defaults to the protocol
    /// router's compiled ceiling; config may lower it, but never raise past the
    /// fixed per-session buffers.
    sasl_decode_max_bytes: u32 = sasl_mechrouter.MAX_RAW_MESSAGE,
    /// Operator registry from config `[oper]` blocks (account -> class/privileges).
    /// Oper is SASL-only: a client is elevated on SASL login if its account has a
    /// binding here. Null/empty = no operators (the OPER command never grants).
    oper_registry: ?oper_mod.OperRegistry = null,
    /// Connection-class registry (`[class.*]`): per-connection policy (sendq/recvq,
    /// limits, timeouts, admission, flood) chosen by IP/TLS/account/oper matching.
    /// A value copy here shares the heap with `config_boot.Loaded`, which owns the
    /// allocation and frees it once at shutdown (mirrors `oper_registry`). Null =
    /// only the built-in `user`/`server` defaults apply.
    class_registry: ?conn_class.Registry = null,
    /// Account services (REGISTER/IDENTIFY/DROP/…) backed by the WAL store. Null =
    /// account management disabled. Borrowed; outlives the server (owned by main).
    account_services: ?*services_mod.Services = null,
    /// Projection-free OCG2 observer, synchronously primed by the process owner
    /// with elapsed=0 before Server construction. Null keeps it wholly inert.
    /// Borrowed; owner must outlive the server.
    ocg2_runtime: ?*ocg2_runtime_mod.Runtime = null,
    /// Exact monotonic millisecond sample paired with the process owner's
    /// elapsed=0 prime. Required iff `ocg2_runtime` is present.
    ocg2_runtime_monotonic_origin_ms: ?u64 = null,
    /// OCG2 projection runtime. Null keeps live sessions on the observer or
    /// on configured-local oper bindings. Borrowed; owner must outlive the server.
    ocg2_projection: ?*ocg2_projection_mod.Runtime = null,
    /// Monotonic sample paired with the projection runtime's elapsed=0 prime.
    /// Required iff `ocg2_projection` is present.
    ocg2_projection_origin_ms: ?u64 = null,
    /// Audit trail for OCG2 privilege transitions. Required iff projection is set.
    ocg2_audit: ?*audit_trail_mod.AuditTrail = null,
    /// Boot-only DPROP1 authority. Production leaves this inactive unless main
    /// has opened the configured account OroStore, loaded the reserved snapshot
    /// strictly, and attached the exact same State to Services.
    durable_device_boot: DurableDeviceBoot = .inactive,
    /// Hostname cloak key. When set, every client's real IP/host is HMAC-cloaked
    /// on connect so other users never see the raw address. Null = no cloaking
    /// (real host shown). main derives this from `[server] cloak_secret`, or a
    /// random per-boot key when account/SASL features imply privacy is wanted.
    cloak_key: ?cloak.SecretKey = null,
    /// Previous cloak key, kept live across a `[cloak] secret` rotation. New
    /// cloaks always use `cloak_key`; WARD host/mask matching additionally tests
    /// the cloak under this key so bans written before the rotation keep matching
    /// during the grace window. Null = no rotation in progress.
    cloak_prev_key: ?cloak.SecretKey = null,
    /// Network-identifying suffix for cloaked hosts (`[cloak] suffix`). IP
    /// cloaks end in `.ip.<suffix>` / `.ip6.<suffix>`; hostname cloaks carry a
    /// `<suffix>-<token>` leading label. Borrowed; outlives the server.
    cloak_suffix: []const u8 = cloak.default_suffix,
    /// Opaque IP cloak mode (`[cloak] mode = "opaque"`). When true, IP cloaks use
    /// the single-token v3 form (128 bits, no subnet hierarchy, no geo labels)
    /// instead of the hierarchical, subnet-bannable form. Max privacy, at the
    /// cost of subnet-bannability.
    cloak_opaque: bool = false,
    /// Per-account cloak (`[cloak] account_cloak`). When true, a logged-in
    /// client's visible host is the friendly `<account>.users.<suffix>` — stable
    /// across IPs/devices. Requires a cloak key; explicit VHOST personas win.
    cloak_account: bool = false,
    /// Anonymous-client cloak rotation cadence in seconds (`[cloak]
    /// anon_epoch_secs`). When non-zero, an UNAUTHENTICATED client's IP is
    /// cloaked with the 128-bit epoch-salted opaque form (`cloakOpaqueEpochV3`)
    /// so it rotates each `anon_epoch_secs` and never leaks subnet co-membership.
    /// Logged-in clients are unaffected (they keep the account/hierarchical
    /// cloak). 0 = disabled (anonymous clients keep the stable cloak).
    cloak_anon_epoch_secs: u64 = 0,
    /// Background forward-confirmed reverse-DNS resolver (owned by main). When
    /// set, each non-loopback client IP is resolved off the hot path. The
    /// confirmed name is oper/self WHOIS only and never becomes the public
    /// cloak. Null = reverse DNS disabled.
    rdns: ?*rdns.Resolver = null,
    /// Background connect-time DNS blocklist resolver (owned by main). When set,
    /// each non-loopback client IP is checked against the configured zones off
    /// the hot path; a listed IP is enforced at registration. Null = disabled.
    dnsbl: ?*dnsbl_resolver.Resolver = null,
    /// DNSBL enforcement action: false = refuse the connection, true = add a
    /// Warden ban for the listed IP (which also closes it). From `[dnsbl] action`.
    dnsbl_ward: bool = false,
    /// Background SMTP submission sender (owned by main). When set, account
    /// email-verification codes are delivered out-of-band through the configured
    /// relay. Null = no mail transport (emails recorded unverified). From `[mail]`.
    mail_sender: ?*mail_sender.Sender = null,
    /// Config file path + resolver for live REHASH. When set (by main), REHASH
    /// re-reads and re-parses this file and swaps in the new oper registry. Null
    /// = REHASH acknowledges without reloading (e.g. defaults-only boot, tests).
    config_path: ?[]const u8 = null,
    config_resolver: config_format.Resolver = .{},
    /// On-disk path of the running binary (argv[0], absolute), captured by main.
    /// `UPGRADE` re-execs THIS path — not `/proc/self/exe`, which would re-run the
    /// old in-memory image even after the file is replaced — so a swapped-in new
    /// binary is what actually boots. Null falls back to `/proc/self/exe`.
    exe_path: ?[]const u8 = null,
};
