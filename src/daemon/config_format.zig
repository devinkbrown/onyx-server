// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Orochi daemon configuration: a typed `Config` projected from standard TOML.
//!
//! The canonical config format is **TOML v1.0** (parsed by `proto/toml.zig`).
//! `parseToml` reads a TOML document and overlays it onto a defaulted `Config`,
//! preserving the daemon's value conventions:
//!   * `env:NAME` / `@file:path` string indirection, resolved via `Resolver`.
//!   * durations as quoted strings: `"500ms"`, `"30s"`, `"5m"`, `"2h"`.
//!   * operators as a TOML array-of-tables: `[[opers]]` with `account`/`class`.
//! A field is overridden only when the document supplies it; otherwise the
//! defaults stand. Required: `[node].id` and `[listen].irc`.
const std = @import("std");
const toml = @import("../proto/toml.zig");
const acme_cli = @import("acme_cli.zig");
const acme_http01_listener = @import("acme_http01_listener.zig");
const acme_runner = @import("acme_runner.zig");
const conn_class = @import("conn_class.zig");
const content_filter_mod = @import("content_filter.zig");
const services_mod = @import("services.zig");
const shard = @import("shard.zig");
const store_mod = @import("store.zig");
const tegami_mod = @import("tegami.zig");
const transcript_mod = @import("transcript.zig");
const sasl_mechrouter = @import("../proto/sasl_mechrouter.zig");
const crypto_sign = @import("../crypto/sign.zig");
const kagura_frame = @import("../substrate/kagura_frame.zig");
const media_room = @import("media_room.zig");
const multiline_mod = @import("../proto/multiline.zig");
const s2s_peer_mod = @import("../substrate/suimyaku/s2s_peer.zig");
const search_index_mod = @import("search_index.zig");
const wasm_abi = @import("../wasm/host/abi.zig");
const wasm_bridge = @import("../wasm/host/bridge.zig");

const default_search_index_config = search_index_mod.SearchIndex.Config{};

comptime {
    if (@bitSizeOf(usize) != 64) @compileError("config_format requires a 64-bit target");
}

/// Indirection callback: given a name (env var) or path (file), return an owned
/// value. Used to resolve `env:NAME` and `@file:path` string values.
pub const LookupFn = *const fn (?*anyopaque, std.mem.Allocator, []const u8) anyerror![]const u8;

pub const Resolver = struct {
    ctx: ?*anyopaque = null,
    env: ?LookupFn = null,
    file: ?LookupFn = null,
};

pub const acme_default_directory_url = "https://acme-v02.api.letsencrypt.org/directory";

pub const Config = struct {
    node: Node = .{},
    network: Network = .{},
    motd: Motd = .{},
    admin: Admin = .{},
    weather: Weather = .{},
    news: News = .{},
    geo: Geo = .{},
    oper: OperSection = .{},
    wasm: Wasm = .{},
    listen: Listen = .{},
    opers: []Oper = &.{},
    oper_groups: []OperGroup = &.{},
    /// `[class.*]` connection classes (owned). Built into a `conn_class.Registry`
    /// by `config_boot`; assignment/enforcement live in the daemon.
    classes: []ClassDef = &.{},
    mesh: Mesh = .{},
    limits: Limits = .{},
    io: Io = .{},
    reputation: Reputation = .{},
    sessions: Sessions = .{},
    ircv3: Ircv3 = .{},
    history: History = .{},
    media: Media = .{},
    stats: Stats = .{},
    backup: Backup = .{},
    metrics: Metrics = .{},
    accounts: Accounts = .{},
    bouncer: Bouncer = .{},
    filter: Filter = .{},
    storage: store_mod.Config = .{},
    webhook: Webhook = .{},
    geoip: Geoip = .{},
    sasl: Sasl = .{},
    cloak: Cloak = .{},
    tls: Tls = .{},
    acme: Acme = .{},
    ocsp: Ocsp = .{},
    webpush: Webpush = .{},
    sts: Sts = .{},
    dnsbl: Dnsbl = .{},
    mail: Mail = .{},
    webauthn: Webauthn = .{},

    /// `[dnsbl]` connect-time DNS blocklist. When enabled with one or more zones,
    /// each non-loopback client IP is checked against the zones off the hot path;
    /// a listed IP is refused (or network-banned) at registration.
    pub const Dnsbl = struct {
        enabled: bool = false,
        /// Blocklist zones, e.g. ["zen.spamhaus.org", "dnsbl.dronebl.org"].
        zones: []const []const u8 = &.{},
        /// false = refuse the connection; true = add a Warden ban for the IP.
        ward: bool = false,
    };

    /// `[mail]` outbound SMTP submission relay. When enabled with a relay host +
    /// sender, the daemon delivers account email-verification and password-reset
    /// codes out-of-band via the relay (off the hot path, on a background thread).
    /// Disabled (default) = no mail: REGISTER records emails as unverified and the
    /// reset flow is unavailable. Never log in the daemon's own MTA; this is a
    /// submission CLIENT to an existing relay.
    pub const Mail = struct {
        enabled: bool = false,
        /// Submission relay hostname (resolved via DNS A record).
        relay_host: ?[]const u8 = null,
        /// Submission port. 587 = STARTTLS (default); 465 = implicit TLS.
        relay_port: u16 = 587,
        /// false = port 465 implicit TLS (TLS from connect); true = STARTTLS on 587.
        starttls: bool = true,
        /// Skip TLS certificate verification of the relay. Default false. Required
        /// (set true) to use AUTH with a NON-loopback relay until trust-anchor
        /// verification is wired — otherwise AUTH to a remote relay is refused, so
        /// submission credentials are never sent over an unverified TLS session.
        insecure_skip_verify: bool = false,
        /// Envelope sender + `From:` address (e.g. "orochi@example.org").
        from: ?[]const u8 = null,
        /// AUTH credentials for the relay (optional; omitted = no AUTH).
        user: ?[]const u8 = null,
        pass: ?[]const u8 = null,
    };

    pub const Node = struct {
        id: u64 = 0,
        public_key: ?[]const u8 = null,
        secret_key: ?[]const u8 = null,
    };

    /// Network-wide presentation. `name` is advertised in ISUPPORT `NETWORK=`
    /// and the registration welcome burst.
    pub const Network = struct {
        name: []const u8 = "Orochi",
        /// This server's own name (source prefix + S2S identity). Unique per node.
        server_name: ?[]const u8 = null,
        /// Human description of THIS node, shown in VERSION and WHOIS 312 and
        /// gossiped to mesh peers (per-server description). Null = generic tagline.
        description: ?[]const u8 = null,
        /// IRCv3 network icon: a URL to a network logo, advertised as the
        /// `NETWORKICON=<url>` ISUPPORT token when set.
        icon_url: ?[]const u8 = null,
        /// Opt this node into public discovery-directory feeds. Off by default:
        /// status.json still exists, but directories should not index it unless
        /// this flag is explicitly true.
        discoverable: bool = false,
    };

    /// Message of the Day. `text` is served by the MOTD command (split on
    /// newlines into lines). Supports `@file:path` to load from a file; when
    /// empty the daemon's built-in default MOTD is served.
    pub const Motd = struct {
        text: ?[]const u8 = null,
    };

    /// ADMIN command response (RPL_ADMIN*). Operator/network contact details.
    pub const Admin = struct {
        location: []const u8 = "Orochi IRC network",
        email: []const u8 = "admin@orochi.local",
    };

    /// Localized weather for the MOTD `{weather}` placeholder. The daemon reads
    /// `source` (a key=value file written by an external updater: temp_c,
    /// wind_kph, precip_mm, desc, location, country) and renders it in the units
    /// for `units` ("auto" uses `country`/the file's country).
    pub const Weather = struct {
        enabled: bool = false,
        /// Display location override (else the source file's `location`).
        location: ?[]const u8 = null,
        /// ISO country code for unit selection (else the file's `country`).
        country: ?[]const u8 = null,
        /// Unit override: "auto" | "metric" | "imperial" | "uk".
        units: ?[]const u8 = null,
        /// Path to the key=value source file.
        source: ?[]const u8 = null,
    };

    /// Headlines for the MOTD `{news}` placeholder. The daemon reads `source`
    /// (one headline per line) and joins the first `count` into a single line.
    pub const News = struct {
        enabled: bool = false,
        source: ?[]const u8 = null,
        count: u32 = 3,
    };

    /// Live `!weather`/`!news` fantasy bot. When enabled the daemon fetches
    /// wttr.in + the bundled RSS feeds in a background thread.
    pub const Geo = struct {
        enabled: bool = false,
        /// Skip TLS verification for public read-only news feeds.
        news_insecure_tls: bool = true,
        /// Min ms between bot replies per channel (anti-flood). 0 = disabled.
        cmd_cooldown_ms: u32 = 3000,
        /// Fallback `!weather` location when a user has no GeoIP/`location` meta.
        default_location: ?[]const u8 = null,
        /// Directory of updater-written headline files; when set, `!news` reads
        /// these instead of doing in-daemon TLS fetches.
        news_cache_dir: ?[]const u8 = null,
    };

    /// Operator subsystem settings (distinct from the `[[opers]]` bindings).
    /// `[wasm]` — OroWasm plugin module system.
    pub const Wasm = struct {
        /// Directory scanned at boot (and on REHASH) for `*.wasm` control-plane
        /// plugins; each registers IRC commands consulted AFTER the built-in
        /// registry (so a plugin can never shadow a core command). Unset = off.
        plugin_dir: ?[]const u8 = null,
        /// Maximum bytes read for one `.wasm` plugin file.
        max_plugin_bytes: usize = wasm_bridge.max_plugin_bytes,
        /// Maximum linear memory bytes available to one plugin instance.
        max_memory_bytes: usize = wasm_bridge.default_max_memory_bytes,
        /// Instruction fuel budget for each plugin command or hook dispatch.
        default_fuel: u64 = wasm_bridge.default_fuel,
        /// Hostcall capability classes plugins may receive after negotiation.
        allowed_caps: wasm_abi.CapabilitySet = wasm_bridge.default_allowed_caps,
        /// Privileged data-access intents plugins may receive after negotiation.
        allowed_intents: wasm_abi.IntentSet = .empty,
        /// Content-addressed plugin registry pins. Non-empty means only pinned
        /// plugins whose BLAKE3 digest matches are loadable.
        registry: []const wasm_bridge.RegistryPin = &.{},
        /// Revoked plugin BLAKE3 digests. Matching bytes are refused regardless
        /// of plugin name or registry pin.
        revoked_blake3: []const [std.crypto.hash.Blake3.digest_length]u8 = &.{},
        /// Plugin names refused by the local trust policy / kill-switch.
        disabled_plugins: []const []const u8 = &.{},
    };

    pub const OperSection = struct {
        /// Path for persisting runtime GRANT/REVOKE grants across restarts.
        grants_path: ?[]const u8 = null,
        /// Path for persisting the Event Spine history ring so `EVENT REPLAY`
        /// survives a USR2 hot-upgrade and a cold restart. Written on the stats
        /// cadence + loaded at boot. Unset = history is per-process-lifetime.
        event_history_path: ?[]const u8 = null,
        /// Auto-enable the +j override umode on elevation for any operator holding
        /// the `oper_override` privilege, so admins get full channel authority
        /// (KICK/MODE/TOPIC/PROP/…) without a manual `/mode +j`. Default false
        /// keeps override an explicit, audited opt-in.
        auto_override: bool = false,
    };

    pub const Listen = struct {
        host: []const u8 = "",
        irc: u16 = 0,
        /// Secure-WebSocket (wss) port for browser clients; 0 = disabled.
        /// Requires `[tls]` to be enabled (the listener reuses its certificate).
        ws: u16 = 0,
        /// TESTING ONLY: allow the `ws` listener without TLS (plain `ws://`)
        /// when no certificate is configured. Browsers require wss on the
        /// production page, so this defaults OFF.
        ws_plain: bool = false,
        webtransport: u16 = 0,
        /// Accept HAProxy PROXY protocol v1/v2 headers from trusted proxies
        /// before IRC/TLS/WebSocket framing. Requires `trusted_proxies`.
        proxy_protocol: bool = false,
        /// Source IPs allowed to supply PROXY headers.
        trusted_proxies: []const []const u8 = &.{},
        s2s: u16 = 0,
        /// UDP port for the media (SFU) transport plane; 0 = ephemeral.
        media: u16 = 0,
        /// UDP port for the native media transport (our KaguraVox/KaguraVis codec leg);
        /// 0 = ephemeral.
        native_media: u16 = 0,
        /// IP advertised to clients as the server media (ICE) candidate.
        media_host: []const u8 = "",
    };

    /// An operator binding. Orochi grants oper SASL-only: `account` is the SASL
    /// account elevated on login (no password — SASL is the auth), and `class`
    /// names its privilege class. There is no OPER-password credential.
    /// A role-based operator group: a named privilege set (optionally inheriting
    /// another group's privileges). An `[[opers]]` block's `class` names its group.
    pub const OperGroup = struct {
        name: []const u8 = "",
        privileges: []const []const u8 = &.{},
        inherits: []const u8 = "",
    };

    pub const Oper = struct {
        account: []const u8 = "",
        class: []const u8 = "",
        /// Optional custom title shown in WHOIS (e.g. "Network Guardian"). When
        /// empty the generic operator/administrator wording is used.
        title: []const u8 = "",
        /// Event-Spine categories this oper is auto-subscribed to on elevation
        /// (e.g. `["ANNOUNCE", "KILL"]`, or `["ALL"]`). Empty = none — the oper
        /// opts in per-category with `EVENT ADD`.
        presubscribe: []const []const u8 = &.{},
        /// TLS client-certificate fingerprints (lowercase-hex SHA-256, 64 chars)
        /// pre-bound to this oper's `account` at boot, so SASL EXTERNAL works
        /// without a prior runtime `CERTADD` (fixes the chicken-and-egg when a
        /// user authenticates certfp-only). Accepts a single string or an array
        /// of strings; each is seeded into the certfp bind store and COEXISTS with
        /// runtime `CERTADD` bindings. Malformed entries are skipped with a boot
        /// warning rather than failing the boot. Case is normalized to lowercase.
        certfp: []const []const u8 = &.{},
    };

    pub const Mesh = struct {
        realm: []const u8 = "",
        trust_roots: []const []const u8 = &.{},
        mesh_pass: ?[]const u8 = null,
        /// Encoded MeshPass signed-capability token this node presents in the
        /// encrypted Tsumugi M1. Accepts hex or standard base64 text.
        admission_token: ?[]const u8 = null,
        /// Ed25519 signer roots accepted for signed MeshPass admission tokens.
        /// Distinct from `trust_roots`, which pins peer node identities.
        admission_roots: []const []const u8 = &.{},
        admission_min_revocation_epoch: u64 = 0,
        /// Runtime Suimyaku peer-driver limits/timers/capacities projected from
        /// `[mesh.routing]`, `[mesh.link]`, `[mesh.gossip]`, and `[mesh.sazanami]`.
        s2s: s2s_peer_mod.Config = .{},
        /// Peers this node dials automatically at boot (and re-dials while the
        /// link is down), each a "host:port" string (IPv6 hosts bracketed,
        /// e.g. "[::1]:6900"). Empty = no auto-connect.
        connect: []const []const u8 = &.{},
        /// When true, refuse plaintext S2S entirely (reject inbound plaintext
        /// peers, never dial plaintext outbound). Only the Tsumugi-secured path
        /// is permitted; if secured S2S is unavailable, all S2S is dropped rather
        /// than falling back to clear. Default false keeps the plaintext fallback.
        require_secured: bool = false,
        /// When a secured S2S link has a node signing key, require the remote
        /// peer to advertise signed-frame support and reject unsigned state
        /// frames. Default true; explicit false keeps the old mixed-rollout path.
        require_signed_frames: bool = true,
    };

    pub const Limits = struct {
        backlog: u31 = 128,
        max_clients: u31 = 1024,
        /// Number of worker reactor shards (`ReactorPool` threads). 1 = the
        /// single-reactor model; bounded by `shard.max_shards`.
        num_shards: u16 = 1,
        handshake_timeout_ms: u64 = 30_000,
        ping_interval_ms: u64 = 120_000,
        ping_timeout_ms: u64 = 60_000,
        /// Maximum stored channel topic length in bytes (advertised as TOPICLEN).
        topiclen: u32 = 390,
        /// Maximum away-message length in bytes (advertised as AWAYLEN).
        awaylen: u32 = 256,
        /// Maximum kick-comment length in bytes (advertised as KICKLEN).
        kicklen: u32 = 307,
        /// Maximum nick length in bytes (advertised as NICKLEN; capped at 64).
        nicklen: u32 = 64,
        /// Maximum channel-name length in bytes (advertised as CHANNELLEN).
        channellen: u32 = 64,
        /// Per-channel cap on each list mode +b/+e/+I/+Z (advertised as MAXLIST).
        maxlist: u32 = 100,
        /// Max channels a non-oper may be in (advertised as CHANLIMIT).
        chanlimit: u32 = 50,
        /// Max comma-separated targets per PRIVMSG/NOTICE (advertised MAXTARGETS).
        maxtargets: u32 = 4,
        /// Maximum channel-key (+k) length in bytes (advertised as KEYLEN and
        /// enforced by the MODE +k handler). Capped at 64 — the chanmode
        /// parser's hard key ceiling — so the two set-paths stay consistent.
        keylen: u32 = 64,
        /// Channel-mode changes a client should combine per MODE command
        /// (advertised as MODES). Set to 1 for one mode/target per line.
        modes_per_line: u32 = 4,
        /// Max MONITOR targets per client (advertised as MONITOR).
        monitorlimit: u32 = 128,
        /// Max SILENCE masks per client (advertised as SILENCE).
        silencelimit: u32 = 32,
        max_clones_per_ip: u32 = 0,
        max_clones_per_net: u32 = 0,
        /// Nick-delay window (ms): how long a released nick is held against reuse
        /// after its owner exits. `0` disables nick delay entirely.
        nick_delay_ms: u64 = 0,
        /// Connection throttle: max new connections one source IP may open within
        /// `throttle_window_ms`. `0` disables the throttle. Loopback / trusted-proxy
        /// sources are exempt (a shared proxy must not throttle distinct clients).
        throttle_connects: u32 = 0,
        throttle_window_ms: u64 = 10_000,
        /// Network raid guard: default join-throttle for channels without an
        /// explicit `+j`. `raid_joins` joins per `raid_window` before new joins are
        /// denied and a one-shot oper raid alert fires. `0` disables the default.
        raid_joins: u16 = 0,
        raid_window_ms: u64 = 10_000,
        /// Network-wide (mesh) concurrent connections per source IP. `0` disables.
        /// Requires a shared `[mesh] pass` so every node salts IPs identically.
        max_clones_per_ip_net: u32 = 0,
        reputation_refuse_threshold: u32 = 0,
        reputation_half_life_ms: u64 = 60_000,
        /// Period of the io_uring timeout-sweep timer; sets the enforcement
        /// granularity of registration/ping/idle timeouts.
        sweep_interval_ms: u64 = 2_000,
        /// Max decoded SASL AUTHENTICATE payload bytes. May be lowered by config
        /// but not raised above the router's fixed protocol buffer.
        sasl_decode_max_bytes: u32 = sasl_mechrouter.MAX_RAW_MESSAGE,
    };

    /// One `[class.<name>]` connection class as parsed from TOML (owned strings).
    /// `policy` carries the resource/admission/flood limits; the `match_*` fields
    /// carry the criteria a connection must satisfy to be assigned the class.
    pub const ClassDef = struct {
        name: []const u8 = "",
        policy: conn_class.Policy = .{},
        match_texts: []const []const u8 = &.{},
        match_tls: bool = false,
        match_account: bool = false,
        match_oper: bool = false,
        ident_glob: ?[]const u8 = null,
        host_glob: ?[]const u8 = null,
    };

    /// io_uring / per-connection transport tuning.
    pub const Io = struct {
        ring_entries: u32 = 32,
        cqe_batch: u32 = 256,
    };

    /// Decaying IP-reputation penalty weights.
    pub const Reputation = struct {
        registration_timeout_penalty: f64 = 50.0,
        clone_refuse_penalty: f64 = 25.0,
    };

    /// Multi-session / bouncer registry sizing.
    pub const Sessions = struct {
        max_accounts: u64 = 65536,
        max_per_account: u32 = 64,
    };

    /// `[ircv3]` — live IRCv3 protocol limits surfaced in CAP values and
    /// enforced by the daemon.
    pub const Ircv3 = struct {
        multiline_max_bytes: u64 = multiline_mod.default_max_bytes,
        multiline_max_lines: u64 = multiline_mod.default_max_lines,
        multiline_ref_len: u64 = multiline_mod.default_max_ref_len,
        multiline_target_len: u64 = multiline_mod.default_max_target_len,
    };

    /// `[history.search]` — live draft/search inverted-index sizing.
    pub const History = struct {
        search_max_words: u64 = default_search_index_config.max_words,
        search_max_ids_per_word: u64 = default_search_index_config.max_ids_per_word,
        search_max_token_bytes: u64 = default_search_index_config.max_token_bytes,
    };

    pub const Media = struct {
        enabled: bool = false,
        max_upload_bytes: u64 = 16 * 1024 * 1024,
        max_frame_bytes: u64 = 64 * 1024,
        reorder_window_frames: u32 = kagura_frame.default_reorder_window_frames,
        max_participants: u32 = @intCast(media_room.default_max_participants),
        sfu_max_breakout_label_bytes: u64 = media_room.max_breakout_bytes,
        captions_max_text_bytes: u64 = transcript_mod.max_text_bytes,
        captions_max_speaker_bytes: u64 = transcript_mod.max_speaker_bytes,
        captions_ring_depth_per_channel: u64 = transcript_mod.max_per_channel,
        captions_max_channels: u64 = transcript_mod.max_channels,
        pins_max_per_channel: u64 = 50,
        pins_max_msgid_bytes: u64 = 64,
        reactions_max_token_bytes: u64 = 32,
        /// Require HMAC-tagged native KaguraVox/KaguraVis datagrams. Defaults off until
        /// clients implement the matching Kagura-frame tag contract.
        native_media_require_mac: bool = false,
        /// Relay browser media datagrams (binary WebSocket frames) between a
        /// channel's call participants. Off by default; the WS media plane is
        /// opt-in (the browser must encode Kagura frames and append the MAC).
        ws_media_relay: bool = false,
        /// Require a valid per-stream MAC tag on every browser media datagram.
        /// When false (default) untagged datagrams still relay, but a present tag
        /// must verify.
        ws_media_require_mac: bool = false,
        /// Terminate DTLS-SRTP (RFC 5764) on the WebRTC UDP media plane so
        /// standard browser/mobile endpoints can key the SRTP leg via a DTLS
        /// handshake. Off by default; when off the media pump is byte-identical.
        dtls_srtp: bool = false,
        /// Additionally offer the DTLS 1.3 (RFC 9147) handshake on the media
        /// plane. Requires `dtls_srtp`. Off by default and independent of it: a
        /// DTLS 1.3-offering peer routes to the 1.3 engine only when this is set,
        /// otherwise it falls through to the hardened 1.2 path. Kept separate
        /// pending real-browser interop validation of the 1.3 handshake.
        dtls13: bool = false,
        /// STUN server (IPv4 literal) queried at boot for the reflexive media
        /// candidate; with stun_port set, overrides listen.media_host on success.
        stun_host: ?[]const u8 = null,
        stun_port: u16 = 0,
    };

    pub const Stats = struct {
        /// Directory to publish web stats into (stats.json + index.html), e.g. an
        /// nginx `root`. Empty = disabled.
        dir: []const u8 = "",
        /// Directory to publish per-CHANNEL statistics JSON into (index.json +
        /// one <slug>.json per channel) for the channel-stats dashboard. nginx
        /// serves it at `/stats/data/`. Empty = channel stats disabled.
        channel_dir: []const u8 = "",
        /// Minimum interval between stats writes, in ms (parsed from a duration).
        interval_ms: i64 = 30_000,
    };

    /// Periodic local backup publication. Off unless `dir` is set.
    pub const Backup = struct {
        /// Directory that receives timestamped account-store and chanstats snapshot
        /// copies plus `latest.json`. Empty = disabled.
        dir: []const u8 = "",
        /// Minimum interval between backup sets, in ms.
        interval_ms: i64 = 24 * 60 * 60 * 1000,
    };

    /// Live Prometheus `/metrics` HTTP endpoint. Off unless `listen` is set.
    pub const Metrics = struct {
        /// TCP port for the `/metrics` listener. 0 (or absent) = disabled.
        listen: u16 = 0,
        /// Bind address for the listener. SECURITY: defaults to loopback
        /// `127.0.0.1` so metrics are never exposed publicly by default. Set to a
        /// private interface (or "0.0.0.0") only deliberately; front it with a
        /// firewall / reverse proxy for remote scraping.
        bind: []const u8 = "127.0.0.1",
    };

    /// `[accounts]` — durable services/account policy. These values are applied
    /// when main opens `[sasl].account_db` and constructs the Services layer.
    pub const Accounts = struct {
        /// PBKDF2-HMAC-SHA256 iteration count for account password hashes.
        pbkdf2_rounds: u32 = services_mod.default_pbkdf2_rounds,
        /// Minimum length for newly registered or changed account passwords.
        password_min_len: u64 = services_mod.default_password_min_len,
        /// Maximum length for newly registered or changed account passwords.
        password_max_len: u64 = services_mod.default_password_max_len,
    };

    /// `[bouncer]` — per-account bouncer/offline-message retention limits.
    pub const Bouncer = struct {
        /// Max offline DM body length (bytes).
        tegami_text_max_len: u64 = tegami_mod.default_max_text_bytes,
        /// Max sender-name length on an offline DM (bytes).
        tegami_from_max_len: u64 = tegami_mod.default_max_from_bytes,
        /// Offline mailbox depth cap per account (entries).
        tegami_mailbox_depth: u64 = tegami_mod.default_max_per_account,
        /// Max distinct offline mailboxes.
        tegami_max_accounts: u64 = tegami_mod.default_max_accounts,
    };

    /// `[filter]` — oper-managed moderation filter sizing.
    pub const Filter = struct {
        /// Max oper-curated Koshi filter patterns.
        koshi_max_patterns: u64 = content_filter_mod.default_max_patterns,
        /// Max length of a single Koshi pattern (bytes).
        koshi_pattern_max_len: u64 = content_filter_mod.default_max_pattern_len,
    };

    /// Discord-compatible incoming webhook endpoint (Torii interop). OFF by
    /// default: when `enabled` is false the listener never binds and the
    /// `WEBHOOK` command is not registered — the daemon is byte-identical to a
    /// build without this feature.
    pub const Webhook = struct {
        /// Master gate. When false the whole feature is inert.
        enabled: bool = false,
        /// TCP port for the plaintext HTTP listener. 0 = OS-ephemeral (the
        /// feature is gated by `enabled`, not the port; set a fixed port in
        /// production). Front it with a TLS reverse proxy.
        listen: u16 = 0,
        /// Bind address. SECURITY: defaults to loopback `127.0.0.1` (null); set
        /// a private interface only deliberately.
        bind: ?[]const u8 = null,
        /// Path to the TSV binding store (survives restart + USR2). Null = no
        /// persistence (bindings are lost on restart).
        store_path: ?[]const u8 = null,
        /// Max accepted request-body bytes (larger ⇒ 413).
        max_body_bytes: u32 = 8192,
        /// Per-webhook sustained rate (requests/min). 0 disables rate limiting.
        rate_per_min: u32 = 60,
        /// Per-webhook burst capacity.
        rate_burst: u32 = 10,
        /// Public URL base used to render the full webhook URL in the WEBHOOK
        /// CREATE reply (e.g. `https://irc.example.com`). Null ⇒ derived from the
        /// bind/port as `http://<bind>:<port>`.
        public_url_base: ?[]const u8 = null,
    };

    pub const Geoip = struct {
        /// Path to a MaxMind GeoIP database (.mmdb). Empty = GeoIP disabled.
        database: []const u8 = "",
        /// Optional separate ASN database (.mmdb) for the WHOIS AS-number/org
        /// line (city DBs don't carry ASN). Empty = no ASN in WHOIS.
        asn_database: []const u8 = "",
    };

    pub const Sasl = struct {
        enabled: bool = false,
        /// True when `[sasl].enabled` was present. This preserves older configs
        /// where `account_db` alone implied SASL while letting explicit false be
        /// a real off switch.
        enabled_explicit: bool = false,
        allow_anonymous: bool = false,
        realm: ?[]const u8 = null,
        /// Path (relative to the daemon cwd) of the WAL-backed account store. When
        /// set, the daemon opens it and verifies SASL credentials against it.
        account_db: ?[]const u8 = null,
        oauth_issuer: ?[]const u8 = null,
        oauth_audience: ?[]const u8 = null,
        /// Optional claim name mapped to the account. Null means "sub".
        oauth_account_claim: ?[]const u8 = null,
        oauth_hmac_key: ?[]const u8 = null,
        oauth_jwks_file: ?[]const u8 = null,
        oauth_pubkey: ?[]const u8 = null,
    };

    pub const Cloak = struct {
        /// Secret passphrase for hostname cloaking. Hashed to a 32-byte key at
        /// boot; when set, every client's real IP is HMAC-cloaked. When absent,
        /// the daemon generates a random per-boot key (privacy on by default).
        secret: ?[]const u8 = null,
        /// Prior cloak secret kept live for ban continuity across a key rotation.
        /// New cloaks always use `secret`; WARD host/mask matching ALSO tests the
        /// cloak computed under this previous key, so bans written before the
        /// rotation keep matching during the grace window. Drop it once the old
        /// bans have aged out. Null = single-key (no rotation in progress).
        previous_secret: ?[]const u8 = null,
        /// Network-identifying suffix carried by cloaked hosts (IP cloaks end
        /// in `.ip.<suffix>` / `.ip6.<suffix>`; hostname cloaks prefix their
        /// token label with `<suffix>-`). Null = the cloak module's default.
        suffix: ?[]const u8 = null,
        /// IP cloak granularity. `"hierarchical"` (default) emits subnet-bannable
        /// tokens plus `a<asn>.<cc>` geo labels; `"opaque"` emits a single token
        /// over the whole address, so nothing about it leaks (not even country/
        /// ASN or subnet membership) at the cost of not being subnet-bannable.
        mode: ?[]const u8 = null,
        /// When true, a logged-in client's visible host becomes the friendly
        /// `<account>.users.<suffix>` — stable across IPs and devices. Explicit
        /// VHOST personas set the host directly and still override it.
        account_cloak: bool = false,
        /// Anonymous-client cloak rotation cadence, in SECONDS. When non-zero, an
        /// UNAUTHENTICATED (not-logged-in) client gets an OPAQUE cloak salted by
        /// the current wall-clock epoch (`floor(now/anon_epoch_secs)`), so a
        /// static-IP anonymous user is neither linkable across epochs nor leaks
        /// subnet co-membership. Logged-in clients are unaffected — they keep
        /// their stable, moderatable account/hierarchical cloak. Wall-clock based
        /// so every mesh node agrees on the epoch. `0` disables rotation
        /// (anonymous clients keep the stable cloak — pre-2026-07 behavior).
        /// Default 86400 (24 h). Moderation of anonymous abuse shifts to account
        /// bans + registration friction, which these opaque cloaks are designed
        /// to require.
        anon_epoch_secs: u64 = 86400,
    };

    /// TLS listener settings. The live listener is wired elsewhere; this section
    /// only describes intent. When `enabled` and no `cert_path`/`key_path` are
    /// given, the daemon bootstraps a self-signed Ed25519 leaf (see
    /// `tls_certs.loadOrBootstrap`) using `dns_name` as the CN/SAN.
    /// kTLS (kernel TLS offload) mode (roadmap 3.1). `off` keeps TLS wholly in
    /// userspace (the default and current behavior). `tx`/`txrx` opt into kernel
    /// offload; the offload path is wired in Phase 1, so today these only widen
    /// the boot-time capability report — no traffic is offloaded yet.
    pub const KtlsMode = enum { off, tx, txrx };

    pub const Tls = struct {
        /// Whether to stand up a TLS listener at all.
        enabled: bool = false,
        /// TLS listener port (the conventional IRCS port is 6697).
        port: u16 = 6697,
        /// PEM/DER leaf certificate path. When set together with `key_path`,
        /// the on-disk material is loaded instead of bootstrapping.
        cert_path: ?[]const u8 = null,
        /// PEM/DER private key path; paired with `cert_path`.
        key_path: ?[]const u8 = null,
        /// CN/SAN used for the self-signed bootstrap leaf when no files are set.
        dns_name: []const u8 = "localhost",
        /// Request a client certificate (mutual TLS) so SASL EXTERNAL can match
        /// the presented fingerprint to an account. Off by default.
        request_client_cert: bool = false,
        /// Also accept hardened TLS 1.2 (ECDHE-AEAD) clients on the same listener,
        /// via version-dispatch. Off by default to keep the modern TLS-1.3-only
        /// posture; enabling it widens the accepted protocol surface. The 1.2 leg
        /// always presents a freshly bootstrapped ECDSA-P256 leaf (the 1.2 engine
        /// signs ServerKeyExchange with ecdsa_secp256r1_sha256).
        enable_tls12: bool = false,
        /// Enable TLS 1.3 session tickets and PSK resumption on the live TLS
        /// listener. Off by default so existing deployments keep full-handshake
        /// behavior unless they explicitly opt in.
        enable_resumption: bool = false,
        /// Maximum accepted TLS 1.3 0-RTT early application bytes advertised in
        /// issued tickets. Zero disables early data while keeping PSK resumption.
        early_data_max_size: u32 = 0,
        /// RFC 7250 raw public keys. When true, a client that offers
        /// `server_certificate_type = RawPublicKey` may receive the leaf SPKI
        /// instead of the X.509 chain. With `request_client_cert`, a client that
        /// offers `client_certificate_type = RawPublicKey` may present a raw
        /// SPKI for SASL EXTERNAL CertFP. Default false keeps the classic path.
        raw_public_key: bool = false,
        /// kTLS (kernel TLS offload) mode — see `Config.KtlsMode`. Default `off`.
        ktls: KtlsMode = .off,
        /// Additional SNI-selectable certificates (`[[tls.sni]]`, owned). When a
        /// ClientHello's server_name matches an entry's `server_names`, the TLS
        /// layer presents that entry's cert instead of the default leaf above.
        /// Empty ⇒ SNI is not consulted (byte-identical to single-cert behavior).
        sni: []SniCertDef = &.{},
        /// Server-side Encrypted Client Hello keys (`[[tls.ech_keys]]`, owned).
        /// Empty ⇒ ECH acceptance is off and the TLS wire stays byte-identical.
        ech_keys: []EchKeyDef = &.{},
    };

    /// One `[[tls.sni]]` entry. `main.zig` loads `cert_path` + `key_path` with the
    /// SAME loader as the default cert (`tls_certs.loadOrBootstrap`) and hands the
    /// material to the TLS layer as a `crypto/tls_server.SniCert`. All three fields
    /// are required — a partial entry is a fail-fast parse error.
    pub const SniCertDef = struct {
        /// Host names (or `*.`-wildcard patterns) this cert answers to, matched
        /// case-insensitively by the TLS layer. Must be non-empty.
        server_names: []const []const u8 = &.{},
        /// PEM/DER leaf (or fullchain) certificate path.
        cert_path: []const u8 = "",
        /// PEM/DER private key path.
        key_path: []const u8 = "",
    };

    /// One server-side ECH key declaration. `config_path` points at a single-entry
    /// ECHConfigList; `private_key` is the matching X25519 HPKE recipient key.
    pub const EchKeyDef = struct {
        config_path: []const u8 = "",
        private_key: [32]u8 = @splat(0),
    };

    /// In-daemon ACME renewal scheduler. Issuance uses the existing ACME runner
    /// and writes to the configured `[tls]` cert/key paths; this section only
    /// controls cadence and CA/account inputs.
    /// `[webpush]` — browser Web Push delivery for offline DMs (tegami).
    /// Off by default; enabling needs an account store (subscriptions are
    /// account-scoped) and outbound HTTPS (same trust anchors as ACME).
    pub const Webpush = struct {
        enabled: bool = false,
        /// VAPID `sub` claim — an operator contact the push service may use.
        subject: []const u8 = "mailto:ops@eshmaki.me",
        /// Where the ES256 VAPID secret persists (rotating it invalidates
        /// every stored browser subscription).
        vapid_key_path: []const u8 = "orochi-webpush-vapid.key",
    };

    pub const Acme = struct {
        enabled: bool = false,
        directory_url: []const u8 = acme_default_directory_url,
        domain: ?[]const u8 = null,
        contact: ?[]const u8 = null,
        renew_before_days: u16 = 30,
        check_interval_ms: u64 = 12 * 60 * 60 * 1000,
        ca_bundle_path: []const u8 = acme_cli.default_ca_bundle,
        ca_bundle_max_bytes: u64 = acme_cli.default_ca_bundle_max_bytes,
        challenge_port: u16 = acme_cli.default_challenge_port,
        max_steps: u32 = @intCast(acme_runner.default_max_steps),
        debug: bool = false,
        max_response_bytes: u64 = acme_runner.default_max_response_bytes,
        error_body_preview_bytes: u64 = acme_runner.default_error_body_preview_bytes,
        resolv_conf_max_bytes: u64 = acme_runner.default_resolv_conf_max_bytes,
        dns_port: u16 = acme_runner.default_dns_port,
        http01_listen_backlog: u32 = acme_http01_listener.default_listen_backlog,
        http01_accept_poll_ms: u32 = acme_http01_listener.default_accept_poll_ms,
        http01_conn_read_timeout_sec: u32 = acme_http01_listener.default_conn_read_timeout_sec,
    };

    /// Server-side OCSP stapling. When `enabled` and the `[tls]` leaf carries an
    /// AIA OCSP responder URL, a background worker fetches, verifies, and caches a
    /// staple that is attached to the leaf whenever a client offers status_request.
    /// Off by default so handshakes stay byte-identical unless opted in.
    pub const Ocsp = struct {
        enabled: bool = false,
        /// How often the worker wakes to check whether a (re)fetch is due. The
        /// responder is only contacted when the cached staple is stale or missing.
        check_interval_ms: u64 = 15 * 60 * 1000,
    };

    /// IRCv3 STS (Strict Transport Security) advertisement policy. When enabled,
    /// the daemon advertises an `sts=` capability instructing clients to persist
    /// a secure-transport upgrade for `duration` seconds on the secure `port`.
    /// Disabled by default so plaintext deployments are never forced upgrades.
    /// The actual policy build + per-session advertisement lives in `main.zig`
    /// via `proto/sts_policy.zig`; this section only surfaces the parsed config.
    pub const Sts = struct {
        enabled: bool = false,
        /// Persistence lifetime in seconds advertised to secure clients. Default
        /// is 30 days (2592000), the value recommended by the IRCv3 STS spec.
        duration: u32 = 2_592_000,
        /// Secure (TLS) port clients should reconnect to when upgrading. Default
        /// is the conventional IRC-over-TLS port 6697.
        port: u16 = 6697,
        /// When true, advertise `preload`, signaling the policy may be shipped in
        /// client preload lists. Off by default; only opt in deliberately.
        preload: bool = false,
    };

    /// `[webauthn]` — passkey (WebAuthn/FIDO2) registration + passwordless login
    /// (the `WEBAUTHN` command). Inert until an account uses it; the command
    /// fails closed until BOTH `rp_id` and one or more `origins` are configured,
    /// because a passkey ceremony must be bound to the deploy's exact domain.
    pub const Webauthn = struct {
        /// The Relying Party ID (a registrable domain, e.g. "chat.example").
        /// Passkeys are scoped to this; it must match the site the client's
        /// `navigator.credentials` call runs on. Null ⇒ WEBAUTHN is unavailable.
        rp_id: ?[]const u8 = null,
        /// Allowed top-level origins (e.g. ["https://chat.example"]). A ceremony
        /// whose clientDataJSON `origin` is not on this list is rejected. Empty ⇒
        /// WEBAUTHN is unavailable.
        origins: []const []const u8 = &.{},
        /// Require the User-Verified (UV) flag — not just User-Present (UP) — in
        /// authenticatorData for BOTH registration and passwordless login. Opt-in
        /// (default false); when off the wire behaviour is byte-identical to the
        /// UP-only default.
        require_uv: bool = false,
        /// Require a verified attestation statement at registration: REGISTER-FINISH
        /// must carry an attestationObject and its `fmt` may not be "none". Opt-in
        /// (default false); when off, registration keeps trust-on-first-use and a
        /// present attestation is still verified fail-closed. The attestation
        /// SIGNATURE is verified against the presented statement (self key, or the
        /// x5c leaf cert for packed-basic/fido-u2f), but the x5c leaf is NOT anchored
        /// to a trusted attestation root — there is no bundled FIDO metadata trust
        /// store, so this proves tamper-evidence, not hardware provenance.
        require_attestation: bool = false,
    };

    /// True when this node participates in a mesh but has no shared `[cloak]
    /// secret`. A node is meshed whether it dials peers (`[mesh] connect`) OR
    /// merely listens for inbound S2S (`[listen] s2s`) — a listen-only node
    /// (peers dial in) has the identical hazard. With no shared secret each node
    /// generates its own random per-boot cloak key, so cloaked hosts differ per
    /// node and change on restart — `*!*@<cloak>` and subnet WARD bans neither
    /// federate across the mesh nor survive a restart. All mesh nodes must share
    /// one `[cloak] secret`.
    pub fn meshCloakSecretMissing(self: *const Config) bool {
        const meshed = self.mesh.connect.len != 0 or self.listen.s2s != 0;
        return meshed and self.cloak.secret == null;
    }

    pub fn initDefaults(allocator: std.mem.Allocator) !Config {
        const host = try allocator.dupe(u8, "127.0.0.1");
        errdefer allocator.free(host);
        const media_host = try allocator.dupe(u8, "127.0.0.1");
        errdefer allocator.free(media_host);
        const stats_dir = try allocator.dupe(u8, "");
        errdefer allocator.free(stats_dir);
        const stats_channel_dir = try allocator.dupe(u8, "");
        errdefer allocator.free(stats_channel_dir);
        const backup_dir = try allocator.dupe(u8, "");
        errdefer allocator.free(backup_dir);
        const metrics_bind = try allocator.dupe(u8, "127.0.0.1");
        errdefer allocator.free(metrics_bind);
        const geoip_db = try allocator.dupe(u8, "");
        errdefer allocator.free(geoip_db);
        const geoip_asn_db = try allocator.dupe(u8, "");
        errdefer allocator.free(geoip_asn_db);
        const acme_directory_url = try allocator.dupe(u8, acme_default_directory_url);
        errdefer allocator.free(acme_directory_url);
        const acme_ca_bundle_path = try allocator.dupe(u8, acme_cli.default_ca_bundle);
        errdefer allocator.free(acme_ca_bundle_path);
        const webpush_subject = try allocator.dupe(u8, "mailto:ops@eshmaki.me");
        errdefer allocator.free(webpush_subject);
        const webpush_vapid_key_path = try allocator.dupe(u8, "orochi-webpush-vapid.key");
        errdefer allocator.free(webpush_vapid_key_path);
        return .{
            .network = .{ .name = try allocator.dupe(u8, "Orochi") },
            .admin = .{
                .location = try allocator.dupe(u8, "Orochi IRC network"),
                .email = try allocator.dupe(u8, "admin@orochi.local"),
            },
            .listen = .{ .host = host, .media_host = media_host },
            .mesh = .{ .realm = try allocator.dupe(u8, "local") },
            .tls = .{ .dns_name = try allocator.dupe(u8, "localhost") },
            .stats = .{ .dir = stats_dir, .channel_dir = stats_channel_dir },
            .backup = .{ .dir = backup_dir },
            .metrics = .{ .bind = metrics_bind },
            .geoip = .{ .database = geoip_db, .asn_database = geoip_asn_db },
            .webpush = .{ .subject = webpush_subject, .vapid_key_path = webpush_vapid_key_path },
            .acme = .{ .directory_url = acme_directory_url, .ca_bundle_path = acme_ca_bundle_path },
        };
    }

    pub fn deinit(self: *Config, allocator: std.mem.Allocator) void {
        if (self.node.public_key) |value| allocator.free(value);
        if (self.node.secret_key) |value| allocator.free(value);
        allocator.free(self.network.name);
        if (self.network.server_name) |v| allocator.free(v);
        if (self.network.description) |v| allocator.free(v);
        if (self.network.icon_url) |v| allocator.free(v);
        if (self.motd.text) |value| allocator.free(value);
        allocator.free(self.admin.location);
        allocator.free(self.admin.email);
        if (self.weather.location) |v| allocator.free(v);
        if (self.weather.country) |v| allocator.free(v);
        if (self.weather.units) |v| allocator.free(v);
        if (self.weather.source) |v| allocator.free(v);
        if (self.news.source) |v| allocator.free(v);
        if (self.geo.default_location) |v| allocator.free(v);
        if (self.geo.news_cache_dir) |v| allocator.free(v);
        if (self.oper.grants_path) |v| allocator.free(v);
        if (self.oper.event_history_path) |v| allocator.free(v);
        if (self.wasm.plugin_dir) |v| allocator.free(v);
        freeWasmRegistry(allocator, self.wasm.registry);
        allocator.free(self.wasm.revoked_blake3);
        freeStringList(allocator, self.wasm.disabled_plugins);
        allocator.free(self.listen.host);
        freeStringList(allocator, self.listen.trusted_proxies);
        allocator.free(self.listen.media_host);
        for (self.opers) |oper| {
            allocator.free(oper.account);
            allocator.free(oper.class);
            allocator.free(oper.title);
            freeStringList(allocator, oper.presubscribe);
            freeStringList(allocator, oper.certfp);
        }
        allocator.free(self.opers);
        for (self.oper_groups) |g| {
            allocator.free(g.name);
            freeStringList(allocator, g.privileges);
            allocator.free(g.inherits);
        }
        allocator.free(self.oper_groups);
        for (self.classes) |c| {
            allocator.free(c.name);
            freeStringList(allocator, c.match_texts);
            if (c.ident_glob) |g| allocator.free(g);
            if (c.host_glob) |g| allocator.free(g);
        }
        allocator.free(self.classes);
        allocator.free(self.mesh.realm);
        freeStringList(allocator, self.mesh.trust_roots);
        freeStringList(allocator, self.mesh.admission_roots);
        freeStringList(allocator, self.mesh.connect);
        freeStringList(allocator, self.dnsbl.zones);
        if (self.mail.relay_host) |value| allocator.free(value);
        if (self.mail.from) |value| allocator.free(value);
        if (self.mail.user) |value| allocator.free(value);
        if (self.mail.pass) |value| allocator.free(value);
        if (self.webauthn.rp_id) |value| allocator.free(value);
        freeStringList(allocator, self.webauthn.origins);
        if (self.mesh.mesh_pass) |value| allocator.free(value);
        if (self.mesh.admission_token) |value| allocator.free(value);
        if (self.sasl.realm) |value| allocator.free(value);
        if (self.sasl.account_db) |value| allocator.free(value);
        if (self.sasl.oauth_issuer) |value| allocator.free(value);
        if (self.sasl.oauth_audience) |value| allocator.free(value);
        if (self.sasl.oauth_account_claim) |value| allocator.free(value);
        if (self.sasl.oauth_hmac_key) |value| allocator.free(value);
        if (self.sasl.oauth_jwks_file) |value| allocator.free(value);
        if (self.sasl.oauth_pubkey) |value| allocator.free(value);
        if (self.media.stun_host) |value| allocator.free(value);
        allocator.free(self.stats.dir);
        allocator.free(self.stats.channel_dir);
        allocator.free(self.backup.dir);
        allocator.free(self.metrics.bind);
        if (self.webhook.bind) |value| allocator.free(value);
        if (self.webhook.store_path) |value| allocator.free(value);
        if (self.webhook.public_url_base) |value| allocator.free(value);
        allocator.free(self.geoip.database);
        allocator.free(self.geoip.asn_database);
        if (self.cloak.secret) |value| allocator.free(value);
        if (self.cloak.previous_secret) |value| allocator.free(value);
        if (self.cloak.suffix) |value| allocator.free(value);
        if (self.cloak.mode) |value| allocator.free(value);
        allocator.free(self.tls.dns_name);
        if (self.tls.cert_path) |value| allocator.free(value);
        if (self.tls.key_path) |value| allocator.free(value);
        for (self.tls.sni) |s| {
            freeStringList(allocator, s.server_names);
            allocator.free(s.cert_path);
            allocator.free(s.key_path);
        }
        allocator.free(self.tls.sni);
        for (self.tls.ech_keys) |*key| {
            allocator.free(key.config_path);
            std.crypto.secureZero(u8, &key.private_key);
        }
        allocator.free(self.tls.ech_keys);
        allocator.free(self.acme.directory_url);
        allocator.free(self.acme.ca_bundle_path);
        allocator.free(self.webpush.subject);
        allocator.free(self.webpush.vapid_key_path);
        if (self.acme.domain) |value| allocator.free(value);
        if (self.acme.contact) |value| allocator.free(value);
        self.* = .{};
    }
};

pub const TomlError = error{ParseError} || std.mem.Allocator.Error;

/// Parse standard TOML and project it onto a defaulted `Config`.
pub fn parseToml(allocator: std.mem.Allocator, source: []const u8, resolver: Resolver) TomlError!Config {
    var doc = toml.parse(allocator, source) catch return error.ParseError;
    defer doc.deinit(allocator);

    var cfg = try Config.initDefaults(allocator);
    errdefer cfg.deinit(allocator);

    // [node]
    if (doc.getInt("node.id")) |v| {
        if (v < 1) return error.ParseError;
        cfg.node.id = @intCast(v);
    }
    try setOpt(allocator, resolver, doc.getString("node.public_key"), &cfg.node.public_key);
    try setOpt(allocator, resolver, doc.getString("node.secret_key"), &cfg.node.secret_key);

    // [network]
    try setStr(allocator, resolver, doc.getString("network.name"), &cfg.network.name);
    try setOpt(allocator, resolver, doc.getString("network.server_name"), &cfg.network.server_name);
    try setOpt(allocator, resolver, doc.getString("network.description"), &cfg.network.description);
    try setOpt(allocator, resolver, doc.getString("network.icon_url"), &cfg.network.icon_url);
    if (doc.getBool("network.discoverable")) |b| cfg.network.discoverable = b;

    // [motd] — `text` may use `@file:path` to load from disk.
    try setOpt(allocator, resolver, doc.getString("motd.text"), &cfg.motd.text);

    // [admin]
    try setStr(allocator, resolver, doc.getString("admin.location"), &cfg.admin.location);
    try setStr(allocator, resolver, doc.getString("admin.email"), &cfg.admin.email);

    // [weather]
    if (doc.getBool("weather.enabled")) |b| cfg.weather.enabled = b;
    try setOpt(allocator, resolver, doc.getString("weather.location"), &cfg.weather.location);
    try setOpt(allocator, resolver, doc.getString("weather.country"), &cfg.weather.country);
    try setOpt(allocator, resolver, doc.getString("weather.units"), &cfg.weather.units);
    try setOpt(allocator, resolver, doc.getString("weather.source"), &cfg.weather.source);

    // [news]
    if (doc.getBool("news.enabled")) |b| cfg.news.enabled = b;
    try setOpt(allocator, resolver, doc.getString("news.source"), &cfg.news.source);
    cfg.news.count = @intCast(try uintField(doc, "news.count", cfg.news.count, 1, 20));

    // [geo]
    if (doc.getBool("geo.enabled")) |b| cfg.geo.enabled = b;
    if (doc.getBool("geo.news_insecure_tls")) |b| cfg.geo.news_insecure_tls = b;
    cfg.geo.cmd_cooldown_ms = @intCast(try uintField(doc, "geo.cmd_cooldown_ms", cfg.geo.cmd_cooldown_ms, 0, 600000));
    try setOpt(allocator, resolver, doc.getString("geo.default_location"), &cfg.geo.default_location);
    try setOpt(allocator, resolver, doc.getString("geo.news_cache_dir"), &cfg.geo.news_cache_dir);

    // [oper]
    try setOpt(allocator, resolver, doc.getString("oper.grants_path"), &cfg.oper.grants_path);
    try setOpt(allocator, resolver, doc.getString("oper.event_history_path"), &cfg.oper.event_history_path);
    if (doc.getBool("oper.auto_override")) |b| cfg.oper.auto_override = b;
    try setOpt(allocator, resolver, doc.getString("wasm.plugin_dir"), &cfg.wasm.plugin_dir);
    cfg.wasm.max_plugin_bytes = @intCast(try uintField(doc, "wasm.max_plugin_bytes", cfg.wasm.max_plugin_bytes, 1024, 64 * 1024 * 1024));
    cfg.wasm.max_memory_bytes = @intCast(try uintField(doc, "wasm.max_memory_bytes", cfg.wasm.max_memory_bytes, 64 * 1024, 16 * 1024 * 1024));
    cfg.wasm.default_fuel = try uintField(doc, "wasm.default_fuel", cfg.wasm.default_fuel, 1, 10_000_000);
    if (doc.getArray("wasm.allowed_caps")) |arr| cfg.wasm.allowed_caps = try parseWasmCaps(arr);
    if (doc.getArray("wasm.allowed_intents")) |arr| cfg.wasm.allowed_intents = try parseWasmIntents(arr);
    if (doc.getArray("wasm.registry")) |arr| {
        freeWasmRegistry(allocator, cfg.wasm.registry);
        cfg.wasm.registry = try parseWasmRegistry(allocator, resolver, arr);
    }
    if (doc.getArray("wasm.revoked_blake3")) |arr| {
        allocator.free(cfg.wasm.revoked_blake3);
        cfg.wasm.revoked_blake3 = try parseHexArrayList(std.crypto.hash.Blake3.digest_length, allocator, arr);
    }
    if (doc.getArray("wasm.disabled_plugins")) |arr| {
        freeStringList(allocator, cfg.wasm.disabled_plugins);
        cfg.wasm.disabled_plugins = try ownStringArray(allocator, resolver, arr);
    }

    // [listen]
    try setStr(allocator, resolver, doc.getString("listen.host"), &cfg.listen.host);
    cfg.listen.irc = try portField(doc, "listen.irc", cfg.listen.irc);
    cfg.listen.ws = try portField(doc, "listen.ws", cfg.listen.ws);
    if (doc.getBool("listen.ws_plain")) |b| cfg.listen.ws_plain = b;
    cfg.listen.webtransport = try portField(doc, "listen.webtransport", cfg.listen.webtransport);
    if (doc.getBool("listen.proxy_protocol")) |b| cfg.listen.proxy_protocol = b;
    if (doc.getArray("listen.trusted_proxies")) |arr| {
        freeStringList(allocator, cfg.listen.trusted_proxies);
        cfg.listen.trusted_proxies = try ownStringArray(allocator, resolver, arr);
    }
    cfg.listen.s2s = try portField(doc, "listen.s2s", cfg.listen.s2s);
    cfg.listen.media = try portField(doc, "listen.media", cfg.listen.media);
    cfg.listen.native_media = try portField(doc, "listen.native_media", cfg.listen.native_media);
    try setStr(allocator, resolver, doc.getString("listen.media_host"), &cfg.listen.media_host);

    // [mesh]
    try setStr(allocator, resolver, doc.getString("mesh.realm"), &cfg.mesh.realm);
    try setOpt(allocator, resolver, doc.getString("mesh.mesh_pass"), &cfg.mesh.mesh_pass);
    try setOpt(allocator, resolver, doc.getString("mesh.admission_token"), &cfg.mesh.admission_token);
    if (doc.getArray("mesh.trust_roots")) |arr| {
        freeStringList(allocator, cfg.mesh.trust_roots);
        cfg.mesh.trust_roots = try ownStringArray(allocator, resolver, arr);
    }
    if (doc.getArray("mesh.admission_roots")) |arr| {
        freeStringList(allocator, cfg.mesh.admission_roots);
        cfg.mesh.admission_roots = try ownStringArray(allocator, resolver, arr);
    }
    cfg.mesh.admission_min_revocation_epoch = try uintField(
        doc,
        "mesh.admission_min_revocation_epoch",
        cfg.mesh.admission_min_revocation_epoch,
        0,
        std.math.maxInt(u64),
    );
    if (doc.getArray("mesh.connect")) |arr| {
        freeStringList(allocator, cfg.mesh.connect);
        cfg.mesh.connect = try ownStringArray(allocator, resolver, arr);
    }
    if (doc.getBool("mesh.require_secured")) |b| cfg.mesh.require_secured = b;
    if (doc.getBool("mesh.require_signed_frames")) |b| cfg.mesh.require_signed_frames = b;
    try parseMeshS2sConfig(doc, &cfg.mesh.s2s);
    cfg.mesh.s2s.require_signed_frames = cfg.mesh.require_signed_frames;

    // [dnsbl]
    if (doc.getBool("dnsbl.enabled")) |b| cfg.dnsbl.enabled = b;
    if (doc.getArray("dnsbl.zones")) |arr| {
        freeStringList(allocator, cfg.dnsbl.zones);
        cfg.dnsbl.zones = try ownStringArray(allocator, resolver, arr);
    }
    if (doc.getString("dnsbl.action")) |a| cfg.dnsbl.ward = std.ascii.eqlIgnoreCase(a, "ward");

    // [mail]
    if (doc.getBool("mail.enabled")) |b| cfg.mail.enabled = b;
    try setOpt(allocator, resolver, doc.getString("mail.relay_host"), &cfg.mail.relay_host);
    cfg.mail.relay_port = @intCast(try uintField(doc, "mail.relay_port", cfg.mail.relay_port, 1, 65535));
    if (doc.getBool("mail.starttls")) |b| cfg.mail.starttls = b;
    if (doc.getBool("mail.insecure_skip_verify")) |b| cfg.mail.insecure_skip_verify = b;
    try setOpt(allocator, resolver, doc.getString("mail.from"), &cfg.mail.from);
    try setOpt(allocator, resolver, doc.getString("mail.user"), &cfg.mail.user);
    try setOpt(allocator, resolver, doc.getString("mail.pass"), &cfg.mail.pass);

    // [webauthn]
    try setOpt(allocator, resolver, doc.getString("webauthn.rp_id"), &cfg.webauthn.rp_id);
    if (doc.getArray("webauthn.origins")) |arr| {
        freeStringList(allocator, cfg.webauthn.origins);
        cfg.webauthn.origins = try ownStringArray(allocator, resolver, arr);
    }
    if (doc.getBool("webauthn.require_uv")) |b| cfg.webauthn.require_uv = b;
    if (doc.getBool("webauthn.require_attestation")) |b| cfg.webauthn.require_attestation = b;

    // [limits]
    cfg.limits.backlog = @intCast(try uintField(doc, "limits.backlog", cfg.limits.backlog, 1, 32767));
    cfg.limits.max_clients = @intCast(try uintField(doc, "limits.max_clients", cfg.limits.max_clients, 1, 32767));
    cfg.limits.num_shards = @intCast(try uintField(doc, "limits.num_shards", cfg.limits.num_shards, 1, shard.max_shards));
    cfg.limits.max_clones_per_ip = @intCast(try uintField(doc, "limits.max_clones_per_ip", cfg.limits.max_clones_per_ip, 0, 65535));
    cfg.limits.max_clones_per_net = @intCast(try uintField(doc, "limits.max_clones_per_net", cfg.limits.max_clones_per_net, 0, 65535));
    cfg.limits.topiclen = @intCast(try uintField(doc, "limits.topiclen", cfg.limits.topiclen, 1, 8192));
    cfg.limits.awaylen = @intCast(try uintField(doc, "limits.awaylen", cfg.limits.awaylen, 1, 256));
    cfg.limits.kicklen = @intCast(try uintField(doc, "limits.kicklen", cfg.limits.kicklen, 1, 400));
    cfg.limits.nicklen = @intCast(try uintField(doc, "limits.nicklen", cfg.limits.nicklen, 1, 64));
    cfg.limits.channellen = @intCast(try uintField(doc, "limits.channellen", cfg.limits.channellen, 2, 200));
    cfg.limits.maxlist = @intCast(try uintField(doc, "limits.maxlist", cfg.limits.maxlist, 1, 10000));
    cfg.limits.chanlimit = @intCast(try uintField(doc, "limits.chanlimit", cfg.limits.chanlimit, 1, 10000));
    cfg.limits.maxtargets = @intCast(try uintField(doc, "limits.maxtargets", cfg.limits.maxtargets, 1, 64));
    cfg.limits.keylen = @intCast(try uintField(doc, "limits.keylen", cfg.limits.keylen, 1, 64));
    cfg.limits.modes_per_line = @intCast(try uintField(doc, "limits.modes_per_line", cfg.limits.modes_per_line, 1, 20));
    cfg.limits.monitorlimit = @intCast(try uintField(doc, "limits.monitorlimit", cfg.limits.monitorlimit, 1, 100000));
    cfg.limits.silencelimit = @intCast(try uintField(doc, "limits.silencelimit", cfg.limits.silencelimit, 1, 256));
    cfg.limits.reputation_refuse_threshold = @intCast(try uintField(doc, "limits.reputation_refuse_threshold", cfg.limits.reputation_refuse_threshold, 0, 1_000_000));
    if (doc.getString("limits.nick_delay")) |s| cfg.limits.nick_delay_ms = try durationMs(s);
    cfg.limits.throttle_connects = @intCast(try uintField(doc, "limits.throttle_connects", cfg.limits.throttle_connects, 0, 1_000_000));
    if (doc.getString("limits.throttle_window")) |s| cfg.limits.throttle_window_ms = try durationMs(s);
    cfg.limits.raid_joins = @intCast(try uintField(doc, "limits.raid_joins", cfg.limits.raid_joins, 0, 65535));
    if (doc.getString("limits.raid_window")) |s| cfg.limits.raid_window_ms = try durationMs(s);
    cfg.limits.max_clones_per_ip_net = @intCast(try uintField(doc, "limits.max_clones_per_ip_net", cfg.limits.max_clones_per_ip_net, 0, 65535));
    if (doc.getString("limits.handshake_timeout")) |s| cfg.limits.handshake_timeout_ms = try durationMs(s);
    if (doc.getString("limits.ping_interval")) |s| cfg.limits.ping_interval_ms = try durationMs(s);
    if (doc.getString("limits.ping_timeout")) |s| cfg.limits.ping_timeout_ms = try durationMs(s);
    if (doc.getString("limits.reputation_half_life")) |s| cfg.limits.reputation_half_life_ms = try durationMs(s);
    if (doc.getString("limits.sweep_interval")) |s| cfg.limits.sweep_interval_ms = try durationMs(s);
    cfg.limits.sasl_decode_max_bytes = @intCast(try uintField(doc, "limits.sasl_decode_max_bytes", cfg.limits.sasl_decode_max_bytes, 64, sasl_mechrouter.MAX_RAW_MESSAGE));

    // [io]
    cfg.io.ring_entries = @intCast(try uintField(doc, "io.ring_entries", cfg.io.ring_entries, 8, 4096));
    cfg.io.cqe_batch = @intCast(try uintField(doc, "io.cqe_batch", cfg.io.cqe_batch, 16, 4096));

    // [reputation]
    cfg.reputation.registration_timeout_penalty = try floatField(doc, "reputation.registration_timeout_penalty", cfg.reputation.registration_timeout_penalty, 0, 1000);
    cfg.reputation.clone_refuse_penalty = try floatField(doc, "reputation.clone_refuse_penalty", cfg.reputation.clone_refuse_penalty, 0, 1000);

    // [accounts]
    cfg.accounts.pbkdf2_rounds = @intCast(try uintField(doc, "accounts.pbkdf2_rounds", cfg.accounts.pbkdf2_rounds, 10_000, 10_000_000));
    cfg.accounts.password_min_len = try uintField(doc, "accounts.password_min_len", cfg.accounts.password_min_len, 1, 64);
    cfg.accounts.password_max_len = try uintField(doc, "accounts.password_max_len", cfg.accounts.password_max_len, 64, 4096);
    if (cfg.accounts.password_min_len > cfg.accounts.password_max_len) return error.ParseError;

    // [bouncer]
    cfg.bouncer.tegami_text_max_len = try uintField(doc, "bouncer.tegami_text_max_len", cfg.bouncer.tegami_text_max_len, 64, 2048);
    cfg.bouncer.tegami_from_max_len = try uintField(doc, "bouncer.tegami_from_max_len", cfg.bouncer.tegami_from_max_len, 16, 128);
    cfg.bouncer.tegami_mailbox_depth = try uintField(doc, "bouncer.tegami_mailbox_depth", cfg.bouncer.tegami_mailbox_depth, 8, 1024);
    cfg.bouncer.tegami_max_accounts = try uintField(doc, "bouncer.tegami_max_accounts", cfg.bouncer.tegami_max_accounts, 1024, 1048576);

    // [filter]
    cfg.filter.koshi_max_patterns = try uintField(doc, "filter.koshi_max_patterns", cfg.filter.koshi_max_patterns, 16, 4096);
    cfg.filter.koshi_pattern_max_len = try uintField(doc, "filter.koshi_pattern_max_len", cfg.filter.koshi_pattern_max_len, 16, 1024);

    // [storage]
    cfg.storage.max_record_bytes = @intCast(try uintField(doc, "storage.max_record_bytes", cfg.storage.max_record_bytes, 65536, 268435456));
    cfg.storage.max_wal_bytes = @intCast(try uintField(doc, "storage.max_wal_bytes", cfg.storage.max_wal_bytes, 1048576, 4294967296));
    cfg.storage.changefeed_capacity = @intCast(try uintField(doc, "storage.changefeed_capacity", cfg.storage.changefeed_capacity, 8, 4096));

    // [sessions]
    cfg.sessions.max_accounts = try uintField(doc, "sessions.max_accounts", cfg.sessions.max_accounts, 1, std.math.maxInt(u32));
    cfg.sessions.max_per_account = @intCast(try uintField(doc, "sessions.max_per_account", cfg.sessions.max_per_account, 1, 1_000_000));

    // [ircv3]
    cfg.ircv3.multiline_max_bytes = try uintField(doc, "ircv3.multiline_max_bytes", cfg.ircv3.multiline_max_bytes, 4096, 262144);
    cfg.ircv3.multiline_max_lines = try uintField(doc, "ircv3.multiline_max_lines", cfg.ircv3.multiline_max_lines, 2, 1024);
    cfg.ircv3.multiline_ref_len = try uintField(doc, "ircv3.multiline_ref_len", cfg.ircv3.multiline_ref_len, 1, 128);
    cfg.ircv3.multiline_target_len = try uintField(doc, "ircv3.multiline_target_len", cfg.ircv3.multiline_target_len, 8, 255);

    // [history.search]
    cfg.history.search_max_words = try uintField(doc, "history.search.max_words", cfg.history.search_max_words, 256, 1_048_576);
    cfg.history.search_max_ids_per_word = try uintField(doc, "history.search.max_ids_per_word", cfg.history.search_max_ids_per_word, 16, 65_536);
    cfg.history.search_max_token_bytes = try uintField(doc, "history.search.max_token_bytes", cfg.history.search_max_token_bytes, 8, 256);

    // [media]
    if (doc.getBool("media.enabled")) |b| cfg.media.enabled = b;
    cfg.media.max_upload_bytes = try uintField(doc, "media.max_upload_bytes", cfg.media.max_upload_bytes, 0, 1024 * 1024 * 1024);
    cfg.media.max_frame_bytes = try uintField(doc, "media.max_frame_bytes", cfg.media.max_frame_bytes, 0, 16 * 1024 * 1024);
    cfg.media.reorder_window_frames = @intCast(try uintField(doc, "media.reorder_window_frames", cfg.media.reorder_window_frames, 1, kagura_frame.window_cap));
    cfg.media.max_participants = @intCast(try uintField(doc, "media.max_participants", cfg.media.max_participants, 1, media_room.max_participants));
    cfg.media.sfu_max_breakout_label_bytes = try uintField(doc, "media.sfu.max_breakout_label_bytes", cfg.media.sfu_max_breakout_label_bytes, 8, 256);
    cfg.media.captions_max_text_bytes = try uintField(doc, "media.captions_max_text_bytes", cfg.media.captions_max_text_bytes, 64, 4000);
    cfg.media.captions_max_speaker_bytes = try uintField(doc, "media.captions_max_speaker_bytes", cfg.media.captions_max_speaker_bytes, 16, 256);
    cfg.media.captions_ring_depth_per_channel = try uintField(doc, "media.captions_ring_depth_per_channel", cfg.media.captions_ring_depth_per_channel, 16, 4096);
    cfg.media.captions_max_channels = try uintField(doc, "media.captions_max_channels", cfg.media.captions_max_channels, 64, 1048576);
    cfg.media.pins_max_per_channel = try uintField(doc, "media.pins.max_per_channel", cfg.media.pins_max_per_channel, 1, 1024);
    cfg.media.pins_max_msgid_bytes = try uintField(doc, "media.pins.max_msgid_bytes", cfg.media.pins_max_msgid_bytes, 8, 256);
    cfg.media.reactions_max_token_bytes = try uintField(doc, "media.reactions.max_token_bytes", cfg.media.reactions_max_token_bytes, 8, 256);
    if (doc.getBool("media.native_media_require_mac")) |b| cfg.media.native_media_require_mac = b;
    if (doc.getBool("media.ws_media_relay")) |b| cfg.media.ws_media_relay = b;
    if (doc.getBool("media.ws_media_require_mac")) |b| cfg.media.ws_media_require_mac = b;
    if (doc.getBool("media.dtls_srtp")) |b| cfg.media.dtls_srtp = b;
    if (doc.getBool("media.dtls13")) |b| cfg.media.dtls13 = b;
    try setOpt(allocator, resolver, doc.getString("media.stun_host"), &cfg.media.stun_host);

    try setStr(allocator, resolver, doc.getString("stats.dir"), &cfg.stats.dir);
    try setStr(allocator, resolver, doc.getString("stats.channel_dir"), &cfg.stats.channel_dir);
    if (doc.getString("stats.interval")) |s| cfg.stats.interval_ms = @intCast(try durationMs(s));

    try setStr(allocator, resolver, doc.getString("backup.dir"), &cfg.backup.dir);
    if (doc.getString("backup.interval")) |s| cfg.backup.interval_ms = @intCast(try durationMs(s));

    // [metrics] — live Prometheus /metrics endpoint. `listen` = 0/absent off;
    // `bind` defaults to loopback (security: not public by default).
    cfg.metrics.listen = try portField(doc, "metrics.listen", cfg.metrics.listen);
    try setStr(allocator, resolver, doc.getString("metrics.bind"), &cfg.metrics.bind);

    // [webhook] — Discord-compatible incoming webhook endpoint. OFF by default.
    if (doc.getBool("webhook.enabled")) |b| cfg.webhook.enabled = b;
    cfg.webhook.listen = try portField(doc, "webhook.listen", cfg.webhook.listen);
    try setOpt(allocator, resolver, doc.getString("webhook.bind"), &cfg.webhook.bind);
    try setOpt(allocator, resolver, doc.getString("webhook.store_path"), &cfg.webhook.store_path);
    cfg.webhook.max_body_bytes = @intCast(try uintField(doc, "webhook.max_body_bytes", cfg.webhook.max_body_bytes, 1, 1 << 20));
    cfg.webhook.rate_per_min = @intCast(try uintField(doc, "webhook.rate_per_min", cfg.webhook.rate_per_min, 0, 1_000_000));
    cfg.webhook.rate_burst = @intCast(try uintField(doc, "webhook.rate_burst", cfg.webhook.rate_burst, 1, 1_000_000));
    try setOpt(allocator, resolver, doc.getString("webhook.public_url_base"), &cfg.webhook.public_url_base);

    try setStr(allocator, resolver, doc.getString("geoip.database"), &cfg.geoip.database);
    try setStr(allocator, resolver, doc.getString("geoip.asn_database"), &cfg.geoip.asn_database);
    cfg.media.stun_port = try portField(doc, "media.stun_port", cfg.media.stun_port);

    // [sasl]
    if (doc.getBool("sasl.enabled")) |b| {
        cfg.sasl.enabled = b;
        cfg.sasl.enabled_explicit = true;
    }
    try setOpt(allocator, resolver, doc.getString("sasl.realm"), &cfg.sasl.realm);
    try setOpt(allocator, resolver, doc.getString("sasl.account_db"), &cfg.sasl.account_db);
    if (doc.getBool("sasl.allow_anonymous")) |b| cfg.sasl.allow_anonymous = b;
    try setOpt(allocator, resolver, doc.getString("sasl.oauth_issuer"), &cfg.sasl.oauth_issuer);
    try setOpt(allocator, resolver, doc.getString("sasl.oauth_audience"), &cfg.sasl.oauth_audience);
    try setOpt(allocator, resolver, doc.getString("sasl.oauth_account_claim"), &cfg.sasl.oauth_account_claim);
    try setOpt(allocator, resolver, doc.getString("sasl.oauth_hmac_key"), &cfg.sasl.oauth_hmac_key);
    try setOpt(allocator, resolver, doc.getString("sasl.oauth_jwks_file"), &cfg.sasl.oauth_jwks_file);
    try setOpt(allocator, resolver, doc.getString("sasl.oauth_pubkey"), &cfg.sasl.oauth_pubkey);
    const oauth_key_sources: usize =
        @as(usize, @intFromBool(cfg.sasl.oauth_hmac_key != null)) +
        @as(usize, @intFromBool(cfg.sasl.oauth_jwks_file != null)) +
        @as(usize, @intFromBool(cfg.sasl.oauth_pubkey != null));
    if (oauth_key_sources > 1) return error.ParseError;

    // [cloak]
    try setOpt(allocator, resolver, doc.getString("cloak.secret"), &cfg.cloak.secret);
    try setOpt(allocator, resolver, doc.getString("cloak.previous_secret"), &cfg.cloak.previous_secret);
    try setOpt(allocator, resolver, doc.getString("cloak.suffix"), &cfg.cloak.suffix);
    try setOpt(allocator, resolver, doc.getString("cloak.mode"), &cfg.cloak.mode);
    if (doc.getBool("cloak.account_cloak")) |b| cfg.cloak.account_cloak = b;
    // 0 disables anon rotation; cap at ~1 year so a fat-fingered value can't
    // wedge the epoch far in the future.
    cfg.cloak.anon_epoch_secs = try uintField(doc, "cloak.anon_epoch_secs", cfg.cloak.anon_epoch_secs, 0, 31_536_000);

    // [tls]
    if (doc.getBool("tls.enabled")) |b| cfg.tls.enabled = b;
    cfg.tls.port = try portField(doc, "tls.port", cfg.tls.port);
    try setOpt(allocator, resolver, doc.getString("tls.cert_path"), &cfg.tls.cert_path);
    try setOpt(allocator, resolver, doc.getString("tls.key_path"), &cfg.tls.key_path);
    try setStr(allocator, resolver, doc.getString("tls.dns_name"), &cfg.tls.dns_name);
    if (doc.getBool("tls.request_client_cert")) |b| cfg.tls.request_client_cert = b;
    if (doc.getBool("tls.enable_tls12")) |b| cfg.tls.enable_tls12 = b;
    if (doc.getBool("tls.enable_resumption")) |b| cfg.tls.enable_resumption = b;
    cfg.tls.early_data_max_size = @intCast(try uintField(doc, "tls.early_data_max_size", cfg.tls.early_data_max_size, 0, std.math.maxInt(u32)));
    if (doc.getBool("tls.raw_public_key")) |b| cfg.tls.raw_public_key = b;
    if (doc.getString("tls.ktls")) |s| cfg.tls.ktls = parseKtlsMode(s) orelse return error.ParseError;

    // [[tls.sni]] — additional SNI-selectable certificates. Each entry pairs one
    // or more host names with an on-disk cert+key; main.zig loads the material
    // (same loader as the default cert). All three keys are required — a partial
    // entry is a fail-fast config error, matching the `[[opers]]` idiom.
    if (doc.getArray("tls.sni")) |arr| {
        var list: std.ArrayList(Config.SniCertDef) = .empty;
        errdefer {
            for (list.items) |s| {
                freeStringList(allocator, s.server_names);
                allocator.free(s.cert_path);
                allocator.free(s.key_path);
            }
            list.deinit(allocator);
        }
        for (arr) |*item| {
            const names = if (item.getArray("server_names")) |narr|
                try ownStringArray(allocator, resolver, narr)
            else
                return error.ParseError;
            errdefer freeStringList(allocator, names);
            if (names.len == 0) return error.ParseError;
            const cert_path = try resolveStr(allocator, resolver, item.getString("cert_path") orelse return error.ParseError);
            errdefer allocator.free(cert_path);
            const key_path = try resolveStr(allocator, resolver, item.getString("key_path") orelse return error.ParseError);
            errdefer allocator.free(key_path);
            try list.append(allocator, .{ .server_names = names, .cert_path = cert_path, .key_path = key_path });
        }
        cfg.tls.sni = try list.toOwnedSlice(allocator);
    }

    // [[tls.ech_keys]] — server-side ECH acceptance material. The TLS engine wants
    // bytes from a published ECHConfigList plus the matching X25519 private key;
    // main.zig loads the config bytes and tls_server validates the key match before
    // wiring the listener.
    if (doc.getArray("tls.ech_keys")) |arr| {
        var list: std.ArrayList(Config.EchKeyDef) = .empty;
        errdefer {
            for (list.items) |*key| {
                allocator.free(key.config_path);
                std.crypto.secureZero(u8, &key.private_key);
            }
            list.deinit(allocator);
        }
        for (arr) |*item| {
            const config_path = try resolveStr(allocator, resolver, item.getString("config_path") orelse return error.ParseError);
            errdefer allocator.free(config_path);
            const private_key_hex_owned = try resolveStr(allocator, resolver, item.getString("private_key") orelse return error.ParseError);
            defer allocator.free(private_key_hex_owned);
            const private_key_hex = std.mem.trim(u8, private_key_hex_owned, " \t\r\n");
            var private_key: [32]u8 = undefined;
            if (private_key_hex.len != private_key.len * 2) return error.ParseError;
            _ = std.fmt.hexToBytes(&private_key, private_key_hex) catch return error.ParseError;
            errdefer std.crypto.secureZero(u8, &private_key);
            try list.append(allocator, .{ .config_path = config_path, .private_key = private_key });
            std.crypto.secureZero(u8, &private_key);
        }
        cfg.tls.ech_keys = try list.toOwnedSlice(allocator);
    }

    // [acme]
    if (doc.getBool("acme.enabled")) |b| cfg.acme.enabled = b;
    try setStr(allocator, resolver, doc.getString("acme.directory_url"), &cfg.acme.directory_url);
    try setOpt(allocator, resolver, doc.getString("acme.domain"), &cfg.acme.domain);
    try setOpt(allocator, resolver, doc.getString("acme.contact"), &cfg.acme.contact);
    cfg.acme.renew_before_days = @intCast(try uintField(doc, "acme.renew_before_days", cfg.acme.renew_before_days, 1, 89));
    if (doc.getString("acme.check_interval")) |s| cfg.acme.check_interval_ms = try durationMs(s);
    try setStr(allocator, resolver, doc.getString("acme.ca_bundle_path"), &cfg.acme.ca_bundle_path);
    cfg.acme.ca_bundle_max_bytes = try uintField(doc, "acme.ca_bundle_max_bytes", cfg.acme.ca_bundle_max_bytes, 64 * 1024, 64 * 1024 * 1024);
    cfg.acme.challenge_port = try portField(doc, "acme.challenge_port", cfg.acme.challenge_port);
    if (cfg.acme.challenge_port == 0) return error.ParseError;
    cfg.acme.max_steps = @intCast(try uintField(doc, "acme.max_steps", cfg.acme.max_steps, 8, 1024));
    if (doc.getBool("acme.debug")) |b| cfg.acme.debug = b;
    cfg.acme.max_response_bytes = try uintField(doc, "acme.max_response_bytes", cfg.acme.max_response_bytes, 16 * 1024, 4 * 1024 * 1024);
    cfg.acme.error_body_preview_bytes = try uintField(doc, "acme.error_body_preview_bytes", cfg.acme.error_body_preview_bytes, 0, 4096);
    cfg.acme.resolv_conf_max_bytes = try uintField(doc, "acme.resolv_conf_max_bytes", cfg.acme.resolv_conf_max_bytes, 4 * 1024, 1024 * 1024);
    cfg.acme.dns_port = try portField(doc, "acme.dns_port", cfg.acme.dns_port);
    if (cfg.acme.dns_port == 0) return error.ParseError;
    cfg.acme.http01_listen_backlog = @intCast(try uintField(doc, "acme.http01_listen_backlog", cfg.acme.http01_listen_backlog, 1, 1024));
    if (doc.getString("acme.http01_accept_poll")) |s| {
        const ms = try durationMs(s);
        if (ms < 50 or ms > 5000) return error.ParseError;
        cfg.acme.http01_accept_poll_ms = @intCast(ms);
    }
    if (doc.getString("acme.http01_conn_read_timeout")) |s| {
        const ms = try durationMs(s);
        if (ms < 1000 or ms > 60_000 or ms % 1000 != 0) return error.ParseError;
        cfg.acme.http01_conn_read_timeout_sec = @intCast(ms / 1000);
    }

    // [ocsp]
    if (doc.getBool("ocsp.enabled")) |b| cfg.ocsp.enabled = b;
    if (doc.getString("ocsp.check_interval")) |s| cfg.ocsp.check_interval_ms = try durationMs(s);

    // [webpush]
    if (doc.getBool("webpush.enabled")) |b| cfg.webpush.enabled = b;
    try setStr(allocator, resolver, doc.getString("webpush.subject"), &cfg.webpush.subject);
    try setStr(allocator, resolver, doc.getString("webpush.vapid_key_path"), &cfg.webpush.vapid_key_path);

    // [sts]
    if (doc.getBool("sts.enabled")) |b| cfg.sts.enabled = b;
    cfg.sts.duration = @intCast(try uintField(doc, "sts.duration", cfg.sts.duration, 0, std.math.maxInt(u32)));
    cfg.sts.port = try portField(doc, "sts.port", cfg.sts.port);
    if (doc.getBool("sts.preload")) |b| cfg.sts.preload = b;

    // [[opers]] arrays-of-tables
    if (doc.getArray("opers")) |arr| {
        var list: std.ArrayList(Config.Oper) = .empty;
        errdefer {
            for (list.items) |o| {
                allocator.free(o.account);
                allocator.free(o.class);
                allocator.free(o.title);
                freeStringList(allocator, o.presubscribe);
                freeStringList(allocator, o.certfp);
            }
            list.deinit(allocator);
        }
        for (arr) |*item| {
            const account_raw = item.getString("account") orelse return error.ParseError;
            const account = try resolveStr(allocator, resolver, account_raw);
            errdefer allocator.free(account);
            const class = if (item.getString("class")) |c|
                try resolveStr(allocator, resolver, c)
            else
                try allocator.dupe(u8, "");
            errdefer allocator.free(class);
            const title = if (item.getString("title")) |t|
                try resolveStr(allocator, resolver, t)
            else
                try allocator.dupe(u8, "");
            errdefer allocator.free(title);
            const presubscribe: []const []const u8 = if (item.getArray("presubscribe")) |parr|
                try ownStringArray(allocator, resolver, parr)
            else
                &.{};
            errdefer freeStringList(allocator, presubscribe);
            // `certfp` accepts a single string or an array of strings; both are
            // owned verbatim here (validation/normalization happens at seed time
            // so a malformed entry warns-and-skips rather than failing the boot).
            const certfp_list: []const []const u8 = try ownStringOrArray(allocator, resolver, item, "certfp");
            errdefer freeStringList(allocator, certfp_list);
            try list.append(allocator, .{ .account = account, .class = class, .title = title, .presubscribe = presubscribe, .certfp = certfp_list });
        }
        cfg.opers = try list.toOwnedSlice(allocator);
    }

    // [[oper_groups]] role-based privilege sets
    if (doc.getArray("oper_groups")) |arr| {
        var list: std.ArrayList(Config.OperGroup) = .empty;
        errdefer {
            for (list.items) |g| {
                allocator.free(g.name);
                freeStringList(allocator, g.privileges);
                allocator.free(g.inherits);
            }
            list.deinit(allocator);
        }
        for (arr) |*item| {
            const name = try resolveStr(allocator, resolver, item.getString("name") orelse return error.ParseError);
            errdefer allocator.free(name);
            const privileges: []const []const u8 = if (item.getArray("privileges")) |parr|
                try ownStringArray(allocator, resolver, parr)
            else
                &.{};
            errdefer freeStringList(allocator, privileges);
            const inherits = if (item.getString("inherits")) |s|
                try resolveStr(allocator, resolver, s)
            else
                try allocator.dupe(u8, "");
            try list.append(allocator, .{ .name = name, .privileges = privileges, .inherits = inherits });
        }
        cfg.oper_groups = try list.toOwnedSlice(allocator);
    }

    // [class.*] connection classes — a table of named sub-tables. Each becomes a
    // ClassDef (policy + match criteria); config_boot builds the live Registry.
    if (doc.get("class")) |class_val| switch (class_val.*) {
        .table => |tbl| {
            var list: std.ArrayList(Config.ClassDef) = .empty;
            errdefer {
                for (list.items) |c| {
                    allocator.free(c.name);
                    freeStringList(allocator, c.match_texts);
                    if (c.ident_glob) |g| allocator.free(g);
                    if (c.host_glob) |g| allocator.free(g);
                }
                list.deinit(allocator);
            }
            var it = tbl.iterator();
            while (it.next()) |entry| {
                const item = entry.value_ptr;
                if (std.meta.activeTag(item.*) != .table) continue;
                const name = try allocator.dupe(u8, entry.key_ptr.*);
                errdefer allocator.free(name);
                var policy = conn_class.Policy{};
                policy.sendq = try classSize(item, "sendq", policy.sendq);
                policy.recvq = try classSize(item, "recvq", policy.recvq);
                policy.max_clients = try classU32(item, "max_clients", policy.max_clients);
                policy.max_per_ip = try classU32(item, "max_per_ip", policy.max_per_ip);
                policy.max_per_account = try classU32(item, "max_per_account", policy.max_per_account);
                policy.max_per_host = try classU32(item, "max_per_host", policy.max_per_host);
                policy.max_channels = try classU32(item, "max_channels", policy.max_channels);
                policy.ping_interval_ms = try classDur(item, "ping_interval", policy.ping_interval_ms);
                policy.ping_timeout_ms = try classDur(item, "ping_timeout", policy.ping_timeout_ms);
                policy.register_timeout_ms = try classDur(item, "register_timeout", policy.register_timeout_ms);
                policy.flood_lines = try classU32(item, "flood_lines", policy.flood_lines);
                policy.flood_window_ms = try classDur(item, "flood_window", policy.flood_window_ms);
                policy.flood_excess = try classU32(item, "flood_excess", policy.flood_excess);
                policy.flood_targets = try classU32(item, "flood_targets", policy.flood_targets);
                policy.require_tls = item.getBool("require_tls") orelse policy.require_tls;
                policy.require_sasl = item.getBool("require_sasl") orelse policy.require_sasl;
                policy.flood_exempt = item.getBool("flood_exempt") orelse policy.flood_exempt;
                policy.nick_delay_exempt = item.getBool("nick_delay_exempt") orelse policy.nick_delay_exempt;
                policy.max_targets = try classU32(item, "max_targets", policy.max_targets);
                policy.monitor = try classU32(item, "monitor", policy.monitor);
                policy.silence = try classU32(item, "silence", policy.silence);
                const match_texts: []const []const u8 = if (item.getArray("match")) |marr|
                    try ownStringArray(allocator, resolver, marr)
                else
                    &.{};
                errdefer freeStringList(allocator, match_texts);
                const ident_glob: ?[]const u8 = if (item.getString("match_ident")) |g| try resolveStr(allocator, resolver, g) else null;
                errdefer if (ident_glob) |g| allocator.free(g);
                const host_glob: ?[]const u8 = if (item.getString("match_host")) |g| try resolveStr(allocator, resolver, g) else null;
                errdefer if (host_glob) |g| allocator.free(g);
                try list.append(allocator, .{
                    .name = name,
                    .policy = policy,
                    .match_texts = match_texts,
                    .match_tls = item.getBool("match_tls") orelse false,
                    .match_account = item.getBool("match_account") orelse false,
                    .match_oper = item.getBool("match_oper") orelse false,
                    .ident_glob = ident_glob,
                    .host_glob = host_glob,
                });
            }
            cfg.classes = try list.toOwnedSlice(allocator);
        },
        else => {},
    };

    // Required-field validation.
    if (cfg.node.id == 0) return error.ParseError;
    if (cfg.listen.irc == 0) return error.ParseError;
    for (cfg.opers) |o| if (o.account.len == 0) return error.ParseError;

    return cfg;
}

/// Read a class byte-size field: a string ("1M") parsed via `conn_class.parseSize`
/// or a bare integer (bytes). Missing → `current`.
fn classSize(item: *const toml.Value, key: []const u8, current: u64) TomlError!u64 {
    if (item.getString(key)) |s| return conn_class.parseSize(s) catch return error.ParseError;
    if (item.getInt(key)) |n| {
        if (n < 0) return error.ParseError;
        return @intCast(n);
    }
    return current;
}

/// Read a class duration field (ms): a string ("120s") via `parseDurationMs` or a
/// bare integer (ms). Missing → `current`.
fn classDur(item: *const toml.Value, key: []const u8, current: u64) TomlError!u64 {
    if (item.getString(key)) |s| return conn_class.parseDurationMs(s) catch return error.ParseError;
    if (item.getInt(key)) |n| {
        if (n < 0) return error.ParseError;
        return @intCast(n);
    }
    return current;
}

/// Read a class u32 count field. Missing → `current`.
fn classU32(item: *const toml.Value, key: []const u8, current: u32) TomlError!u32 {
    if (item.getInt(key)) |n| {
        if (n < 0 or n > std.math.maxInt(u32)) return error.ParseError;
        return @intCast(n);
    }
    return current;
}

/// Resolve a raw TOML string into an owned value, honoring `env:NAME` /
/// `@file:path` indirection; a plain string is duped verbatim.
fn resolveStr(allocator: std.mem.Allocator, resolver: Resolver, raw: []const u8) TomlError![]const u8 {
    if (std.mem.startsWith(u8, raw, "env:")) {
        const name = raw["env:".len..];
        if (name.len == 0) return error.ParseError;
        const func = resolver.env orelse return error.ParseError;
        return func(resolver.ctx, allocator, name) catch return error.ParseError;
    }
    if (std.mem.startsWith(u8, raw, "@file:")) {
        const path = raw["@file:".len..];
        if (path.len == 0) return error.ParseError;
        const func = resolver.file orelse return error.ParseError;
        return func(resolver.ctx, allocator, path) catch return error.ParseError;
    }
    return allocator.dupe(u8, raw);
}

/// Overlay an optional string field when the TOML supplies one.
fn setOpt(allocator: std.mem.Allocator, resolver: Resolver, raw: ?[]const u8, slot: *?[]const u8) TomlError!void {
    const value = raw orelse return;
    const owned = try resolveStr(allocator, resolver, value);
    if (slot.*) |old| allocator.free(old);
    slot.* = owned;
}

/// Overlay a non-optional (default-duped) string field when supplied.
fn setStr(allocator: std.mem.Allocator, resolver: Resolver, raw: ?[]const u8, slot: *[]const u8) TomlError!void {
    const value = raw orelse return;
    const owned = try resolveStr(allocator, resolver, value);
    allocator.free(slot.*);
    slot.* = owned;
}

fn ownStringArray(allocator: std.mem.Allocator, resolver: Resolver, arr: []const toml.Value) TomlError![]const []const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (list.items) |s| allocator.free(s);
        list.deinit(allocator);
    }
    for (arr) |*item| {
        const raw = switch (item.*) {
            .string => |s| s,
            else => return error.ParseError,
        };
        try list.append(allocator, try resolveStr(allocator, resolver, raw));
    }
    return list.toOwnedSlice(allocator);
}

fn parseWasmCaps(arr: []const toml.Value) TomlError!wasm_abi.CapabilitySet {
    var caps = wasm_abi.CapabilitySet.empty;
    for (arr) |*item| {
        const raw = switch (item.*) {
            .string => |s| s,
            else => return error.ParseError,
        };
        const cap = wasm_abi.Capability.fromToken(raw) orelse return error.ParseError;
        caps.insert(cap);
    }
    return caps;
}

fn parseWasmIntents(arr: []const toml.Value) TomlError!wasm_abi.IntentSet {
    var intents = wasm_abi.IntentSet.empty;
    for (arr) |*item| {
        const raw = switch (item.*) {
            .string => |s| s,
            else => return error.ParseError,
        };
        const intent = wasm_abi.Intent.fromToken(raw) orelse return error.ParseError;
        intents.insert(intent);
    }
    return intents;
}

fn parseWasmRegistry(allocator: std.mem.Allocator, resolver: Resolver, arr: []const toml.Value) TomlError![]const wasm_bridge.RegistryPin {
    var list: std.ArrayList(wasm_bridge.RegistryPin) = .empty;
    errdefer {
        for (list.items) |pin| allocator.free(pin.name);
        list.deinit(allocator);
    }
    for (arr) |*item| {
        if (item.* != .table) return error.ParseError;
        const raw_name = item.getString("name") orelse return error.ParseError;
        const raw_hash = item.getString("blake3") orelse return error.ParseError;
        const raw_tier = item.getString("tier") orelse "listed";
        const raw_publisher = item.getString("publisher");
        const raw_signature = item.getString("signature");
        if (raw_hash.len != std.crypto.hash.Blake3.digest_length * 2) return error.ParseError;
        var digest: [std.crypto.hash.Blake3.digest_length]u8 = undefined;
        _ = std.fmt.hexToBytes(&digest, raw_hash) catch return error.ParseError;
        const tier = wasm_bridge.TrustTier.fromToken(raw_tier) orelse return error.ParseError;
        if ((raw_publisher == null) != (raw_signature == null)) return error.ParseError;
        const publisher = if (raw_publisher) |raw| try parseHexArray(crypto_sign.public_key_len, raw) else null;
        const signature = if (raw_signature) |raw| try parseHexArray(crypto_sign.signature_len, raw) else null;
        const name = try resolveStr(allocator, resolver, raw_name);
        errdefer allocator.free(name);
        try list.append(allocator, .{ .name = name, .blake3 = digest, .tier = tier, .publisher = publisher, .signature = signature });
    }
    return list.toOwnedSlice(allocator);
}

fn parseHexArray(comptime len: usize, raw: []const u8) TomlError![len]u8 {
    if (raw.len != len * 2) return error.ParseError;
    var out: [len]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, raw) catch return error.ParseError;
    return out;
}

fn parseHexArrayList(comptime len: usize, allocator: std.mem.Allocator, arr: []const toml.Value) TomlError![]const [len]u8 {
    var list: std.ArrayList([len]u8) = .empty;
    errdefer list.deinit(allocator);
    for (arr) |*item| {
        const raw = switch (item.*) {
            .string => |s| s,
            else => return error.ParseError,
        };
        try list.append(allocator, try parseHexArray(len, raw));
    }
    return list.toOwnedSlice(allocator);
}

fn freeWasmRegistry(allocator: std.mem.Allocator, pins: []const wasm_bridge.RegistryPin) void {
    for (pins) |pin| allocator.free(pin.name);
    allocator.free(pins);
}

/// Own a TOML field that may be either a single string OR an array of strings
/// (e.g. `certfp = "abc…"` or `certfp = ["abc…", "def…"]`). Returns an owned,
/// resolved string list; an absent field yields the empty slice.
fn ownStringOrArray(
    allocator: std.mem.Allocator,
    resolver: Resolver,
    item: *const toml.Value,
    key: []const u8,
) TomlError![]const []const u8 {
    if (item.getArray(key)) |arr| return ownStringArray(allocator, resolver, arr);
    if (item.getString(key)) |s| {
        var list: std.ArrayList([]const u8) = .empty;
        errdefer {
            for (list.items) |v| allocator.free(v);
            list.deinit(allocator);
        }
        const owned = try resolveStr(allocator, resolver, s);
        errdefer allocator.free(owned);
        try list.append(allocator, owned);
        return list.toOwnedSlice(allocator);
    }
    return &.{};
}

fn portField(doc: toml.Document, path: []const u8, current: u16) TomlError!u16 {
    const v = doc.getInt(path) orelse return current;
    if (v < 0 or v > 65535) return error.ParseError;
    return @intCast(v);
}

/// Map a `[tls] ktls` string to the mode enum, or null for an unknown value.
fn parseKtlsMode(s: []const u8) ?Config.KtlsMode {
    if (std.mem.eql(u8, s, "off")) return .off;
    if (std.mem.eql(u8, s, "tx")) return .tx;
    if (std.mem.eql(u8, s, "txrx")) return .txrx;
    return null;
}

fn parseMeshS2sConfig(doc: toml.Document, cfg: *s2s_peer_mod.Config) TomlError!void {
    cfg.routes.max_nicks = @intCast(try uintField(doc, "mesh.routing.max_nicks", cfg.routes.max_nicks, 64, 10_000_000));
    cfg.routes.max_channels = @intCast(try uintField(doc, "mesh.routing.max_channels", cfg.routes.max_channels, 16, 1_000_000));
    cfg.routes.max_nodes_per_channel = @intCast(try uintField(doc, "mesh.routing.max_nodes_per_channel", cfg.routes.max_nodes_per_channel, 4, 4096));
    cfg.routes.max_name_len = @intCast(try uintField(doc, "mesh.routing.max_name_len", cfg.routes.max_name_len, 16, 256));
    cfg.registry.max_nodes = @intCast(try uintField(doc, "mesh.routing.max_servers", cfg.registry.max_nodes, 8, 65536));
    cfg.registry.max_name_len = @intCast(try uintField(doc, "mesh.routing.max_server_name_len", cfg.registry.max_name_len, 16, 255));
    cfg.registry.max_description_len = @intCast(try uintField(doc, "mesh.routing.max_server_desc_len", cfg.registry.max_description_len, 32, 1024));

    cfg.link.gossip_config.fanout = @intCast(try uintField(doc, "mesh.gossip.round_fanout", cfg.link.gossip_config.fanout, 1, 64));
    cfg.link.gossip_config.max_member_deltas = @intCast(try uintField(doc, "mesh.gossip.max_member_deltas", cfg.link.gossip_config.max_member_deltas, 1, 1024));
    cfg.link.gossip_config.max_suspicions = @intCast(try uintField(doc, "mesh.gossip.max_suspicions", cfg.link.gossip_config.max_suspicions, 1, 1024));
    cfg.link.view_config.active_capacity = @intCast(try uintField(doc, "mesh.gossip.view_active_capacity", cfg.link.view_config.active_capacity, 2, 64));
    cfg.link.view_config.passive_capacity = @intCast(try uintField(doc, "mesh.gossip.view_passive_capacity", cfg.link.view_config.passive_capacity, cfg.link.view_config.active_capacity + 1, 4096));
    cfg.link.view_config.shuffle_active_count = @intCast(try uintField(doc, "mesh.gossip.view_shuffle_active", cfg.link.view_config.shuffle_active_count, 0, cfg.link.view_config.active_capacity));
    cfg.link.view_config.shuffle_passive_count = @intCast(try uintField(doc, "mesh.gossip.view_shuffle_passive", cfg.link.view_config.shuffle_passive_count, 0, cfg.link.view_config.passive_capacity));

    cfg.link.sazanami_config.suspicion_timeout_ms = @intCast(try uintField(doc, "mesh.sazanami.suspicion_timeout_ms", @as(u64, @intCast(cfg.link.sazanami_config.suspicion_timeout_ms)), 0, 120_000));
    // Floor of 2: a single accuser must never bury a peer (see gossip_round.zig
    // SazanamiConfig.sanitized). Reject a configured quorum of 0/1 at parse time.
    cfg.link.sazanami_config.witness_quorum = @intCast(try uintField(doc, "mesh.sazanami.witness_quorum", cfg.link.sazanami_config.witness_quorum, 2, 16));

    cfg.link.peer_link_config.send_credit = @intCast(try uintField(doc, "mesh.link.send_credit_bytes", cfg.link.peer_link_config.send_credit, 4096, 16_777_216));
    cfg.link.peer_link_config.replay_window = try uintField(doc, "mesh.link.replay_window", cfg.link.peer_link_config.replay_window, 8, 4096);
    cfg.link.peer_link_config.handshake_timeout_ms = try uintField(doc, "mesh.link.handshake_timeout_ms", cfg.link.peer_link_config.handshake_timeout_ms, 1000, 120_000);
    cfg.link.peer_link_config.heartbeat_interval_ms = try uintField(doc, "mesh.link.heartbeat_interval_ms", cfg.link.peer_link_config.heartbeat_interval_ms, 1000, 120_000);
    cfg.link.peer_link_config.idle_timeout_ms = try uintField(doc, "mesh.link.idle_timeout_ms", cfg.link.peer_link_config.idle_timeout_ms, 5000, 600_000);
    cfg.link.peer_link_config.drain_timeout_ms = try uintField(doc, "mesh.link.drain_timeout_ms", cfg.link.peer_link_config.drain_timeout_ms, 500, 60_000);
    cfg.link.gossip_interval_ms = try uintField(doc, "mesh.link.gossip_interval_ms", cfg.link.gossip_interval_ms, 100, 60_000);
    cfg.link.repair_interval_ms = try uintField(doc, "mesh.link.repair_interval_ms", cfg.link.repair_interval_ms, 200, 120_000);
    cfg.link.gossip_config.fanout = @intCast(try uintField(doc, "mesh.link.gossip_fanout", cfg.link.gossip_config.fanout, 1, 64));
    cfg.link.view_config.active_capacity = @intCast(try uintField(doc, "mesh.link.view_active_capacity", cfg.link.view_config.active_capacity, 2, 64));
    cfg.link.view_config.passive_capacity = @intCast(try uintField(doc, "mesh.link.view_passive_capacity", cfg.link.view_config.passive_capacity, cfg.link.view_config.active_capacity + 1, 4096));
    cfg.link.burst_limits.max_burst_bytes = @intCast(try uintField(doc, "mesh.link.burst_max_bytes", cfg.link.burst_limits.max_burst_bytes, 4096, 16_777_216));
    cfg.link.burst_limits.max_records = @intCast(try uintField(doc, "mesh.link.burst_max_records", cfg.link.burst_limits.max_records, 16, 65536));

    if (cfg.link.view_config.passive_capacity <= cfg.link.view_config.active_capacity) return error.ParseError;
    if (cfg.link.view_config.shuffle_active_count + cfg.link.view_config.shuffle_passive_count == 0) return error.ParseError;
    if (cfg.link.view_config.shuffle_active_count > cfg.link.view_config.active_capacity) return error.ParseError;
    if (cfg.link.view_config.shuffle_passive_count > cfg.link.view_config.passive_capacity) return error.ParseError;
}

fn uintField(doc: toml.Document, path: []const u8, current: u64, min: u64, max: u64) TomlError!u64 {
    const v = doc.getInt(path) orelse return current;
    if (v < 0) return error.ParseError;
    const u: u64 = @intCast(v);
    if (u < min or u > max) return error.ParseError;
    return u;
}

fn floatField(doc: toml.Document, path: []const u8, current: f64, min: f64, max: f64) TomlError!f64 {
    const v = doc.getFloat(path) orelse return current;
    if (v < min or v > max) return error.ParseError;
    return v;
}

/// Parse a duration string ("500ms" | "30s" | "5m" | "2h") into milliseconds.
fn durationMs(text: []const u8) TomlError!u64 {
    const units = [_]struct { suffix: []const u8, scale: u64 }{
        .{ .suffix = "ms", .scale = 1 },
        .{ .suffix = "s", .scale = 1000 },
        .{ .suffix = "m", .scale = 60_000 },
        .{ .suffix = "h", .scale = 3_600_000 },
    };
    for (units) |unit| {
        if (std.mem.endsWith(u8, text, unit.suffix)) {
            const digits = text[0 .. text.len - unit.suffix.len];
            const n = std.fmt.parseInt(u64, digits, 10) catch return error.ParseError;
            if (n == 0 or n > std.math.maxInt(u64) / unit.scale) return error.ParseError;
            return n * unit.scale;
        }
    }
    return error.ParseError;
}

fn freeStringList(allocator: std.mem.Allocator, list: []const []const u8) void {
    for (list) |item| allocator.free(item);
    allocator.free(list);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "parseToml: core sections project onto Config" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 42
        \\
        \\[listen]
        \\host = "10.0.0.5"
        \\irc = 6700
        \\s2s = 7700
        \\
        \\[limits]
        \\max_clients = 2048
        \\handshake_timeout = "15s"
        \\ping_interval = "90s"
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expectEqual(@as(u64, 42), cfg.node.id);
    try testing.expectEqualStrings("10.0.0.5", cfg.listen.host);
    try testing.expectEqual(@as(u16, 6700), cfg.listen.irc);
    try testing.expectEqual(@as(u16, 7700), cfg.listen.s2s);
    try testing.expectEqual(@as(u31, 2048), cfg.limits.max_clients);
    try testing.expectEqual(@as(u64, 15_000), cfg.limits.handshake_timeout_ms);
    try testing.expectEqual(@as(u64, 90_000), cfg.limits.ping_interval_ms);
    // Unspecified optional fields keep their defaults.
    try testing.expectEqual(@as(u64, 60_000), cfg.limits.ping_timeout_ms);
    try testing.expectEqualStrings("local", cfg.mesh.realm);
}

test "parseToml: [limits] keylen round-trips and rejects out-of-range" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[limits]
        \\keylen = 40
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expectEqual(@as(u32, 40), cfg.limits.keylen);

    // Absent key keeps the default.
    var dflt = try parseToml(allocator, "[node]\nid=1\n[listen]\nirc=6680\n", .{});
    defer dflt.deinit(allocator);
    try testing.expectEqual(@as(u32, 64), dflt.limits.keylen);

    // Parse boundaries accept: 1 (min) and 64 (the parser's key ceiling).
    var lo = try parseToml(allocator, "[node]\nid=1\n[listen]\nirc=6680\n[limits]\nkeylen=1\n", .{});
    defer lo.deinit(allocator);
    try testing.expectEqual(@as(u32, 1), lo.limits.keylen);
    var hi = try parseToml(allocator, "[node]\nid=1\n[listen]\nirc=6680\n[limits]\nkeylen=64\n", .{});
    defer hi.deinit(allocator);
    try testing.expectEqual(@as(u32, 64), hi.limits.keylen);

    // 0 (below min) and 65 (above the parser's 64-byte ceiling) both fail closed.
    try testing.expectError(error.ParseError, parseToml(allocator, "[node]\nid=1\n[listen]\nirc=6680\n[limits]\nkeylen=0\n", .{}));
    try testing.expectError(error.ParseError, parseToml(allocator, "[node]\nid=1\n[listen]\nirc=6680\n[limits]\nkeylen=65\n", .{}));
}

test "parseToml: backup section projects directory and cadence" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[backup]
        \\dir = "/var/backups/orochi"
        \\interval = "12h"
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expectEqualStrings("/var/backups/orochi", cfg.backup.dir);
    try testing.expectEqual(@as(i64, 12 * 60 * 60 * 1000), cfg.backup.interval_ms);
}

test "parseToml: network discoverable defaults private and parses opt-in" {
    const allocator = testing.allocator;

    var dflt = try parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\
    , .{});
    defer dflt.deinit(allocator);
    try testing.expect(!dflt.network.discoverable);

    var public = try parseToml(allocator,
        \\[node]
        \\id = 1
        \\[network]
        \\discoverable = true
        \\[listen]
        \\irc = 6680
        \\
    , .{});
    defer public.deinit(allocator);
    try testing.expect(public.network.discoverable);
}

test "parseToml: wasm allowed_caps parses hostcall policy and rejects unknown tokens" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[wasm]
        \\allowed_caps = ["reply", "STORE", "hooks", "net:outbound"]
        \\allowed_intents = ["message-content"]
        \\registry = [{ name = "guard", blake3 = "0000000000000000000000000000000000000000000000000000000000000000", tier = "verified", publisher = "1111111111111111111111111111111111111111111111111111111111111111", signature = "22222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222" }]
        \\revoked_blake3 = ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
        \\disabled_plugins = ["bad", "bridge-discord.wasm"]
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expect(cfg.wasm.allowed_caps.has(.reply));
    try testing.expect(cfg.wasm.allowed_caps.has(.store));
    try testing.expect(cfg.wasm.allowed_caps.has(.hooks));
    try testing.expect(cfg.wasm.allowed_caps.has(.net_outbound));
    try testing.expect(!cfg.wasm.allowed_caps.has(.time));
    try testing.expect(cfg.wasm.allowed_intents.has(.message_content));
    try testing.expectEqual(@as(usize, 1), cfg.wasm.registry.len);
    try testing.expectEqualStrings("guard", cfg.wasm.registry[0].name);
    try testing.expectEqual(wasm_bridge.TrustTier.verified, cfg.wasm.registry[0].tier);
    try testing.expect(cfg.wasm.registry[0].publisher != null);
    try testing.expect(cfg.wasm.registry[0].signature != null);
    try testing.expectEqual(@as(u8, 0x11), cfg.wasm.registry[0].publisher.?[0]);
    try testing.expectEqual(@as(u8, 0x22), cfg.wasm.registry[0].signature.?[0]);
    try testing.expectEqual(@as(usize, 1), cfg.wasm.revoked_blake3.len);
    try testing.expectEqual(@as(u8, 0xaa), cfg.wasm.revoked_blake3[0][0]);
    try testing.expectEqual(@as(usize, 2), cfg.wasm.disabled_plugins.len);
    try testing.expectEqualStrings("bad", cfg.wasm.disabled_plugins[0]);
    try testing.expectEqualStrings("bridge-discord.wasm", cfg.wasm.disabled_plugins[1]);

    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[wasm]
        \\allowed_caps = ["reply", "net:inbound"]
        \\
    , .{}));

    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[wasm]
        \\allowed_intents = ["plaintext"]
        \\
    , .{}));

    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[wasm]
        \\revoked_blake3 = ["aa"]
        \\
    , .{}));

    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[wasm]
        \\registry = [{ name = "guard", blake3 = "0000000000000000000000000000000000000000000000000000000000000000", publisher = "1111111111111111111111111111111111111111111111111111111111111111" }]
        \\
    , .{}));
}

test "parseToml: [[opers]] array-of-tables + trust_roots list" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[mesh]
        \\realm = "ircxnet"
        \\mesh_pass = "shared-secret"
        \\trust_roots = ["root-a", "root-b"]
        \\admission_token = "aabbcc"
        \\admission_roots = ["signer-a", "signer-b"]
        \\admission_min_revocation_epoch = 7
        \\connect = ["ircx.us:6900", "[::1]:7900"]
        \\[[opers]]
        \\account = "admin"
        \\class = "netadmin"
        \\[[opers]]
        \\account = "helper"
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expectEqualStrings("ircxnet", cfg.mesh.realm);
    try testing.expectEqualStrings("shared-secret", cfg.mesh.mesh_pass.?);
    try testing.expectEqual(@as(usize, 2), cfg.mesh.trust_roots.len);
    try testing.expectEqualStrings("root-b", cfg.mesh.trust_roots[1]);
    try testing.expectEqualStrings("aabbcc", cfg.mesh.admission_token.?);
    try testing.expectEqual(@as(usize, 2), cfg.mesh.admission_roots.len);
    try testing.expectEqualStrings("signer-b", cfg.mesh.admission_roots[1]);
    try testing.expectEqual(@as(u64, 7), cfg.mesh.admission_min_revocation_epoch);
    try testing.expectEqual(@as(usize, 2), cfg.mesh.connect.len);
    try testing.expectEqualStrings("ircx.us:6900", cfg.mesh.connect[0]);
    try testing.expectEqualStrings("[::1]:7900", cfg.mesh.connect[1]);
    try testing.expectEqual(@as(usize, 2), cfg.opers.len);
    try testing.expectEqualStrings("admin", cfg.opers[0].account);
    try testing.expectEqualStrings("netadmin", cfg.opers[0].class);
    try testing.expectEqualStrings("helper", cfg.opers[1].account);
    try testing.expectEqualStrings("", cfg.opers[1].class);
}

test "parseToml: [[opers]] certfp accepts a single string or an array" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[[opers]]
        \\account = "single"
        \\class = "admin"
        \\certfp = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        \\[[opers]]
        \\account = "multi"
        \\class = "admin"
        \\certfp = ["aaaa", "bbbb"]
        \\[[opers]]
        \\account = "none"
        \\class = "admin"
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expectEqual(@as(usize, 3), cfg.opers.len);
    // Single string -> one-element list.
    try testing.expectEqual(@as(usize, 1), cfg.opers[0].certfp.len);
    try testing.expectEqualStrings("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", cfg.opers[0].certfp[0]);
    // Array -> multi-element list (owned verbatim; validation is at seed time).
    try testing.expectEqual(@as(usize, 2), cfg.opers[1].certfp.len);
    try testing.expectEqualStrings("aaaa", cfg.opers[1].certfp[0]);
    try testing.expectEqualStrings("bbbb", cfg.opers[1].certfp[1]);
    // Omitted -> empty (default), no allocation.
    try testing.expectEqual(@as(usize, 0), cfg.opers[2].certfp.len);
}

test "parseToml: [dnsbl] enabled + zones + action project onto Config" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[dnsbl]
        \\enabled = true
        \\zones = ["zen.spamhaus.org", "dnsbl.dronebl.org"]
        \\action = "ward"
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expect(cfg.dnsbl.enabled);
    try testing.expectEqual(@as(usize, 2), cfg.dnsbl.zones.len);
    try testing.expectEqualStrings("zen.spamhaus.org", cfg.dnsbl.zones[0]);
    try testing.expectEqualStrings("dnsbl.dronebl.org", cfg.dnsbl.zones[1]);
    try testing.expect(cfg.dnsbl.ward); // action = "ward"
}

test "parseToml: [dnsbl] defaults are disabled, no zones, refuse" {
    const allocator = testing.allocator;
    var cfg = try parseToml(allocator, "[node]\nid = 1\n[listen]\nirc = 6680\n", .{});
    defer cfg.deinit(allocator);
    try testing.expect(!cfg.dnsbl.enabled);
    try testing.expectEqual(@as(usize, 0), cfg.dnsbl.zones.len);
    try testing.expect(!cfg.dnsbl.ward);
}

test "parseToml: listen proxy protocol and SASL enabled gate project" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\proxy_protocol = true
        \\trusted_proxies = ["127.0.0.1", "::1"]
        \\[sasl]
        \\enabled = false
        \\realm = "ircxnet"
        \\account_db = "accounts.oro"
        \\allow_anonymous = true
        \\oauth_issuer = "https://issuer.example"
        \\oauth_audience = "orochi"
        \\oauth_account_claim = "preferred_username"
        \\oauth_hmac_key = "test-secret"
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expect(cfg.listen.proxy_protocol);
    try testing.expectEqual(@as(usize, 2), cfg.listen.trusted_proxies.len);
    try testing.expectEqualStrings("127.0.0.1", cfg.listen.trusted_proxies[0]);
    try testing.expect(!cfg.sasl.enabled);
    try testing.expect(cfg.sasl.enabled_explicit);
    try testing.expect(cfg.sasl.allow_anonymous);
    try testing.expectEqualStrings("ircxnet", cfg.sasl.realm.?);
    try testing.expectEqualStrings("accounts.oro", cfg.sasl.account_db.?);
    try testing.expectEqualStrings("https://issuer.example", cfg.sasl.oauth_issuer.?);
    try testing.expectEqualStrings("orochi", cfg.sasl.oauth_audience.?);
    try testing.expectEqualStrings("preferred_username", cfg.sasl.oauth_account_claim.?);
    try testing.expectEqualStrings("test-secret", cfg.sasl.oauth_hmac_key.?);

    var omitted = try parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\
    , .{});
    defer omitted.deinit(allocator);
    try testing.expect(!omitted.sasl.enabled_explicit);
    try testing.expect(!omitted.sasl.allow_anonymous);
    try testing.expect(omitted.sasl.oauth_account_claim == null);
}

test "parseToml: [accounts] pbkdf2 rounds project with bounded policy range" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[accounts]
        \\pbkdf2_rounds = 250000
        \\password_min_len = 12
        \\password_max_len = 1024
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expectEqual(@as(u32, 250_000), cfg.accounts.pbkdf2_rounds);
    try testing.expectEqual(@as(u64, 12), cfg.accounts.password_min_len);
    try testing.expectEqual(@as(u64, 1024), cfg.accounts.password_max_len);

    var omitted = try parseToml(allocator, "[node]\nid = 1\n[listen]\nirc = 6680\n", .{});
    defer omitted.deinit(allocator);
    try testing.expectEqual(services_mod.default_pbkdf2_rounds, omitted.accounts.pbkdf2_rounds);
    try testing.expectEqual(@as(u64, services_mod.default_password_min_len), omitted.accounts.password_min_len);
    try testing.expectEqual(@as(u64, services_mod.default_password_max_len), omitted.accounts.password_max_len);

    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[accounts]
        \\pbkdf2_rounds = 9999
        \\
    , .{}));
    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[accounts]
        \\pbkdf2_rounds = 10000001
        \\
    , .{}));
    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[accounts]
        \\password_min_len = 65
        \\
    , .{}));
    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[accounts]
        \\password_max_len = 63
        \\
    , .{}));
}

test "parseToml: [bouncer] tegami limits project with bounded policy ranges" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[bouncer]
        \\tegami_text_max_len = 512
        \\tegami_from_max_len = 48
        \\tegami_mailbox_depth = 16
        \\tegami_max_accounts = 2048
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expectEqual(@as(u64, 512), cfg.bouncer.tegami_text_max_len);
    try testing.expectEqual(@as(u64, 48), cfg.bouncer.tegami_from_max_len);
    try testing.expectEqual(@as(u64, 16), cfg.bouncer.tegami_mailbox_depth);
    try testing.expectEqual(@as(u64, 2048), cfg.bouncer.tegami_max_accounts);

    var omitted = try parseToml(allocator, "[node]\nid = 1\n[listen]\nirc = 6680\n", .{});
    defer omitted.deinit(allocator);
    try testing.expectEqual(@as(u64, tegami_mod.default_max_text_bytes), omitted.bouncer.tegami_text_max_len);
    try testing.expectEqual(@as(u64, tegami_mod.default_max_from_bytes), omitted.bouncer.tegami_from_max_len);
    try testing.expectEqual(@as(u64, tegami_mod.default_max_per_account), omitted.bouncer.tegami_mailbox_depth);
    try testing.expectEqual(@as(u64, tegami_mod.default_max_accounts), omitted.bouncer.tegami_max_accounts);

    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[bouncer]
        \\tegami_text_max_len = 63
        \\
    , .{}));
    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[bouncer]
        \\tegami_mailbox_depth = 1025
        \\
    , .{}));
}

test "parseToml: [filter] koshi limits project with bounded policy ranges" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[filter]
        \\koshi_max_patterns = 512
        \\koshi_pattern_max_len = 128
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expectEqual(@as(u64, 512), cfg.filter.koshi_max_patterns);
    try testing.expectEqual(@as(u64, 128), cfg.filter.koshi_pattern_max_len);

    var omitted = try parseToml(allocator, "[node]\nid = 1\n[listen]\nirc = 6680\n", .{});
    defer omitted.deinit(allocator);
    try testing.expectEqual(@as(u64, content_filter_mod.default_max_patterns), omitted.filter.koshi_max_patterns);
    try testing.expectEqual(@as(u64, content_filter_mod.default_max_pattern_len), omitted.filter.koshi_pattern_max_len);

    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[filter]
        \\koshi_max_patterns = 15
        \\
    , .{}));
    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[filter]
        \\koshi_pattern_max_len = 1025
        \\
    , .{}));
}

test "parseToml: [history.search] limits project with bounded policy ranges" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[history.search]
        \\max_words = 4096
        \\max_ids_per_word = 128
        \\max_token_bytes = 32
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expectEqual(@as(u64, 4096), cfg.history.search_max_words);
    try testing.expectEqual(@as(u64, 128), cfg.history.search_max_ids_per_word);
    try testing.expectEqual(@as(u64, 32), cfg.history.search_max_token_bytes);

    var omitted = try parseToml(allocator, "[node]\nid = 1\n[listen]\nirc = 6680\n", .{});
    defer omitted.deinit(allocator);
    const defaults = search_index_mod.SearchIndex.Config{};
    try testing.expectEqual(@as(u64, defaults.max_words), omitted.history.search_max_words);
    try testing.expectEqual(@as(u64, defaults.max_ids_per_word), omitted.history.search_max_ids_per_word);
    try testing.expectEqual(@as(u64, defaults.max_token_bytes), omitted.history.search_max_token_bytes);

    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[history.search]
        \\max_words = 255
        \\
    , .{}));
    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[history.search]
        \\max_ids_per_word = 15
        \\
    , .{}));
    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[history.search]
        \\max_token_bytes = 257
        \\
    , .{}));
}

test "parseToml: [ircv3] multiline limits project with bounded policy ranges" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[ircv3]
        \\multiline_max_bytes = 8192
        \\multiline_max_lines = 8
        \\multiline_ref_len = 32
        \\multiline_target_len = 64
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expectEqual(@as(u64, 8192), cfg.ircv3.multiline_max_bytes);
    try testing.expectEqual(@as(u64, 8), cfg.ircv3.multiline_max_lines);
    try testing.expectEqual(@as(u64, 32), cfg.ircv3.multiline_ref_len);
    try testing.expectEqual(@as(u64, 64), cfg.ircv3.multiline_target_len);

    var omitted = try parseToml(allocator, "[node]\nid = 1\n[listen]\nirc = 6680\n", .{});
    defer omitted.deinit(allocator);
    try testing.expectEqual(@as(u64, multiline_mod.default_max_bytes), omitted.ircv3.multiline_max_bytes);
    try testing.expectEqual(@as(u64, multiline_mod.default_max_lines), omitted.ircv3.multiline_max_lines);
    try testing.expectEqual(@as(u64, multiline_mod.default_max_ref_len), omitted.ircv3.multiline_ref_len);
    try testing.expectEqual(@as(u64, multiline_mod.default_max_target_len), omitted.ircv3.multiline_target_len);

    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[ircv3]
        \\multiline_max_bytes = 4095
        \\
    , .{}));
    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[ircv3]
        \\multiline_max_lines = 1
        \\
    , .{}));
    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[ircv3]
        \\multiline_ref_len = 129
        \\
    , .{}));
    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[ircv3]
        \\multiline_target_len = 7
        \\
    , .{}));
}

test "parseToml: [storage] store limits project with bounded policy ranges" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[storage]
        \\max_record_bytes = 131072
        \\max_wal_bytes = 2097152
        \\changefeed_capacity = 128
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expectEqual(@as(usize, 131072), cfg.storage.max_record_bytes);
    try testing.expectEqual(@as(usize, 2097152), cfg.storage.max_wal_bytes);
    try testing.expectEqual(@as(usize, 128), cfg.storage.changefeed_capacity);

    var omitted = try parseToml(allocator, "[node]\nid = 1\n[listen]\nirc = 6680\n", .{});
    defer omitted.deinit(allocator);
    const store_defaults = store_mod.Config{};
    try testing.expectEqual(store_defaults.max_record_bytes, omitted.storage.max_record_bytes);
    try testing.expectEqual(store_defaults.max_wal_bytes, omitted.storage.max_wal_bytes);
    try testing.expectEqual(store_defaults.changefeed_capacity, omitted.storage.changefeed_capacity);

    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[storage]
        \\max_record_bytes = 65535
        \\
    , .{}));
    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[storage]
        \\max_wal_bytes = 4294967297
        \\
    , .{}));
    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[storage]
        \\changefeed_capacity = 7
        \\
    , .{}));
}

test "parseToml: [sasl] rejects multiple OAuth key sources" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[sasl]
        \\oauth_hmac_key = "secret"
        \\oauth_pubkey = "{}"
        \\
    ;
    try testing.expectError(error.ParseError, parseToml(allocator, text, .{}));
}

test "parseToml: [mesh].require_secured projects onto Config and defaults false" {
    const allocator = testing.allocator;
    // Explicit true.
    {
        const text =
            \\[node]
            \\id = 1
            \\[listen]
            \\irc = 6680
            \\[mesh]
            \\realm = "ircxnet"
            \\require_secured = true
            \\require_signed_frames = false
            \\
        ;
        var cfg = try parseToml(allocator, text, .{});
        defer cfg.deinit(allocator);
        try testing.expect(cfg.mesh.require_secured);
        try testing.expect(!cfg.mesh.require_signed_frames);
        try testing.expect(!cfg.mesh.s2s.require_signed_frames);
    }
    // Omitted → backward-compatible default (plaintext fallback allowed).
    {
        const text =
            \\[node]
            \\id = 1
            \\[listen]
            \\irc = 6680
            \\[mesh]
            \\realm = "ircxnet"
            \\
        ;
        var cfg = try parseToml(allocator, text, .{});
        defer cfg.deinit(allocator);
        try testing.expect(!cfg.mesh.require_secured);
        try testing.expect(cfg.mesh.require_signed_frames);
        try testing.expect(cfg.mesh.s2s.require_signed_frames);
    }
}

test "parseToml: live mesh S2S sub-sections project onto peer driver config" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[mesh.routing]
        \\max_nicks = 8192
        \\max_channels = 2048
        \\max_nodes_per_channel = 128
        \\max_name_len = 80
        \\max_servers = 1024
        \\max_server_name_len = 90
        \\max_server_desc_len = 512
        \\[mesh.gossip]
        \\round_fanout = 5
        \\max_member_deltas = 128
        \\max_suspicions = 96
        \\view_active_capacity = 10
        \\view_passive_capacity = 80
        \\view_shuffle_active = 3
        \\view_shuffle_passive = 6
        \\[mesh.sazanami]
        \\suspicion_timeout_ms = 9000
        \\witness_quorum = 4
        \\[mesh.link]
        \\send_credit_bytes = 131072
        \\replay_window = 128
        \\handshake_timeout_ms = 11000
        \\heartbeat_interval_ms = 16000
        \\idle_timeout_ms = 60000
        \\drain_timeout_ms = 6000
        \\gossip_interval_ms = 1500
        \\repair_interval_ms = 3000
        \\gossip_fanout = 2
        \\view_active_capacity = 4
        \\view_passive_capacity = 12
        \\burst_max_bytes = 262144
        \\burst_max_records = 1024
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);

    try testing.expectEqual(@as(usize, 8192), cfg.mesh.s2s.routes.max_nicks);
    try testing.expectEqual(@as(usize, 2048), cfg.mesh.s2s.routes.max_channels);
    try testing.expectEqual(@as(usize, 128), cfg.mesh.s2s.routes.max_nodes_per_channel);
    try testing.expectEqual(@as(usize, 80), cfg.mesh.s2s.routes.max_name_len);
    try testing.expectEqual(@as(usize, 1024), cfg.mesh.s2s.registry.max_nodes);
    try testing.expectEqual(@as(usize, 90), cfg.mesh.s2s.registry.max_name_len);
    try testing.expectEqual(@as(usize, 512), cfg.mesh.s2s.registry.max_description_len);
    try testing.expectEqual(@as(u32, 131072), cfg.mesh.s2s.link.peer_link_config.send_credit);
    try testing.expectEqual(@as(u64, 128), cfg.mesh.s2s.link.peer_link_config.replay_window);
    try testing.expectEqual(@as(u64, 11000), cfg.mesh.s2s.link.peer_link_config.handshake_timeout_ms);
    try testing.expectEqual(@as(u64, 16000), cfg.mesh.s2s.link.peer_link_config.heartbeat_interval_ms);
    try testing.expectEqual(@as(u64, 60000), cfg.mesh.s2s.link.peer_link_config.idle_timeout_ms);
    try testing.expectEqual(@as(u64, 6000), cfg.mesh.s2s.link.peer_link_config.drain_timeout_ms);
    try testing.expectEqual(@as(u64, 1500), cfg.mesh.s2s.link.gossip_interval_ms);
    try testing.expectEqual(@as(u64, 3000), cfg.mesh.s2s.link.repair_interval_ms);
    try testing.expectEqual(@as(usize, 2), cfg.mesh.s2s.link.gossip_config.fanout);
    try testing.expectEqual(@as(usize, 128), cfg.mesh.s2s.link.gossip_config.max_member_deltas);
    try testing.expectEqual(@as(usize, 96), cfg.mesh.s2s.link.gossip_config.max_suspicions);
    try testing.expectEqual(@as(usize, 4), cfg.mesh.s2s.link.view_config.active_capacity);
    try testing.expectEqual(@as(usize, 12), cfg.mesh.s2s.link.view_config.passive_capacity);
    try testing.expectEqual(@as(usize, 3), cfg.mesh.s2s.link.view_config.shuffle_active_count);
    try testing.expectEqual(@as(usize, 6), cfg.mesh.s2s.link.view_config.shuffle_passive_count);
    try testing.expectEqual(@as(i64, 9000), cfg.mesh.s2s.link.sazanami_config.suspicion_timeout_ms);
    try testing.expectEqual(@as(u8, 4), cfg.mesh.s2s.link.sazanami_config.witness_quorum);
    try testing.expectEqual(@as(usize, 262144), cfg.mesh.s2s.link.burst_limits.max_burst_bytes);
    try testing.expectEqual(@as(usize, 1024), cfg.mesh.s2s.link.burst_limits.max_records);

    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[mesh.link]
        \\send_credit_bytes = 4095
        \\
    , .{}));
    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[mesh.routing]
        \\max_servers = 7
        \\
    , .{}));
    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[mesh.gossip]
        \\view_shuffle_active = 5
        \\[mesh.link]
        \\view_active_capacity = 4
        \\
    , .{}));
}

test "parseToml: env: indirection resolves through the Resolver" {
    const allocator = testing.allocator;
    const Ctx = struct {
        fn env(_: ?*anyopaque, a: std.mem.Allocator, name: []const u8) anyerror![]const u8 {
            try testing.expectEqualStrings("MIZ_SECRET", name);
            return a.dupe(u8, "s3kr3t");
        }
    };
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[cloak]
        \\secret = "env:MIZ_SECRET"
        \\suffix = "ircxnet"
        \\
    ;
    var cfg = try parseToml(allocator, text, .{ .env = Ctx.env });
    defer cfg.deinit(allocator);
    try testing.expectEqualStrings("s3kr3t", cfg.cloak.secret.?);
    try testing.expectEqualStrings("ircxnet", cfg.cloak.suffix.?);
    // mode/account_cloak default when the keys are absent.
    try testing.expect(cfg.cloak.mode == null);
    try testing.expect(cfg.cloak.account_cloak == false);
}

test "parseToml: [cloak] mode and account_cloak parse" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[cloak]
        \\secret = "s3kr3t"
        \\previous_secret = "old-s3kr3t"
        \\mode = "opaque"
        \\account_cloak = true
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expectEqualStrings("opaque", cfg.cloak.mode.?);
    try testing.expect(cfg.cloak.account_cloak == true);
    try testing.expectEqualStrings("old-s3kr3t", cfg.cloak.previous_secret.?);
    // anon_epoch_secs defaults to 24 h when absent.
    try testing.expectEqual(@as(u64, 86400), cfg.cloak.anon_epoch_secs);
}

test "parseToml: [cloak] anon_epoch_secs parses and 0 disables rotation" {
    const allocator = testing.allocator;
    const on =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[cloak]
        \\anon_epoch_secs = 3600
        \\
    ;
    var cfg_on = try parseToml(allocator, on, .{});
    defer cfg_on.deinit(allocator);
    try testing.expectEqual(@as(u64, 3600), cfg_on.cloak.anon_epoch_secs);

    const off =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[cloak]
        \\anon_epoch_secs = 0
        \\
    ;
    var cfg_off = try parseToml(allocator, off, .{});
    defer cfg_off.deinit(allocator);
    try testing.expectEqual(@as(u64, 0), cfg_off.cloak.anon_epoch_secs);

    // Out-of-range (> ~1 year) is rejected.
    try testing.expectError(error.ParseError, parseToml(
        allocator,
        "[node]\nid=1\n[listen]\nirc=6680\n[cloak]\nanon_epoch_secs=99999999999\n",
        .{},
    ));
}

test "parseToml: required fields and ranges are enforced" {
    const allocator = testing.allocator;
    // Missing [node].id.
    try testing.expectError(error.ParseError, parseToml(allocator, "[listen]\nirc = 6680\n", .{}));
    // Missing [listen].irc.
    try testing.expectError(error.ParseError, parseToml(allocator, "[node]\nid = 1\n", .{}));
    // Port out of range.
    try testing.expectError(error.ParseError, parseToml(allocator, "[node]\nid=1\n[listen]\nirc=70000\n", .{}));
    // Bad duration.
    try testing.expectError(error.ParseError, parseToml(allocator, "[node]\nid=1\n[listen]\nirc=1\n[limits]\nping_interval=\"5x\"\n", .{}));
    // Malformed TOML.
    try testing.expectError(error.ParseError, parseToml(allocator, "[node\nid=1\n", .{}));
}

test "parseToml: [io] / [reputation] / sweep_interval lift" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[limits]
        \\sweep_interval = "500ms"
        \\sasl_decode_max_bytes = 256
        \\[io]
        \\ring_entries = 256
        \\cqe_batch = 512
        \\[reputation]
        \\registration_timeout_penalty = 80.0
        \\clone_refuse_penalty = 10
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expectEqual(@as(u64, 500), cfg.limits.sweep_interval_ms);
    try testing.expectEqual(@as(u32, 256), cfg.limits.sasl_decode_max_bytes);
    try testing.expectEqual(@as(u32, 256), cfg.io.ring_entries);
    try testing.expectEqual(@as(u32, 512), cfg.io.cqe_batch);
    try testing.expectEqual(@as(f64, 80.0), cfg.reputation.registration_timeout_penalty);
    try testing.expectEqual(@as(f64, 10.0), cfg.reputation.clone_refuse_penalty);
    // out-of-range ring_entries rejected
    try testing.expectError(error.ParseError, parseToml(allocator, "[node]\nid=1\n[listen]\nirc=1\n[io]\nring_entries=4\n", .{}));
    try testing.expectError(error.ParseError, parseToml(allocator, "[node]\nid=1\n[listen]\nirc=1\n[io]\ncqe_batch=8\n", .{}));
    // Cannot promise SASL payloads beyond the compiled router buffer.
    try testing.expectError(error.ParseError, parseToml(allocator, "[node]\nid=1\n[listen]\nirc=1\n[limits]\nsasl_decode_max_bytes=4096\n", .{}));
}

test "parseToml: num_shards lifts and defaults to 1" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[limits]
        \\num_shards = 4
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expectEqual(@as(u16, 4), cfg.limits.num_shards);

    // Omitted -> single-reactor default.
    var dflt = try parseToml(allocator, "[node]\nid=1\n[listen]\nirc=6680\n", .{});
    defer dflt.deinit(allocator);
    try testing.expectEqual(@as(u16, 1), dflt.limits.num_shards);

    // Zero shards is invalid (a reactor pool needs >= 1 worker).
    try testing.expectError(error.ParseError, parseToml(allocator, "[node]\nid=1\n[listen]\nirc=1\n[limits]\nnum_shards=0\n", .{}));
}

test "parseToml: minimal config keeps defaults" {
    const allocator = testing.allocator;
    var cfg = try parseToml(allocator, "[node]\nid = 9\n[listen]\nirc = 6680\n", .{});
    defer cfg.deinit(allocator);
    try testing.expectEqual(@as(u64, 9), cfg.node.id);
    try testing.expectEqual(@as(u16, 6680), cfg.listen.irc);
    try testing.expectEqual(@as(u16, 0), cfg.listen.s2s);
    try testing.expectEqualStrings("127.0.0.1", cfg.listen.host);
    try testing.expect(!cfg.media.native_media_require_mac);
    try testing.expect(!cfg.media.dtls_srtp);
}

test "parseToml: media.dtls_srtp defaults off and lifts when set" {
    const allocator = testing.allocator;
    var dflt = try parseToml(allocator, "[node]\nid=1\n[listen]\nirc=6680\n", .{});
    defer dflt.deinit(allocator);
    try testing.expect(!dflt.media.dtls_srtp);

    var cfg = try parseToml(allocator, "[node]\nid=1\n[listen]\nirc=6680\n[media]\ndtls_srtp = true\n", .{});
    defer cfg.deinit(allocator);
    try testing.expect(cfg.media.dtls_srtp);
}

test "parseToml: media.dtls13 defaults off and lifts independently of dtls_srtp" {
    const allocator = testing.allocator;
    var dflt = try parseToml(allocator, "[node]\nid=1\n[listen]\nirc=6680\n", .{});
    defer dflt.deinit(allocator);
    try testing.expect(!dflt.media.dtls13);

    var cfg = try parseToml(allocator, "[node]\nid=1\n[listen]\nirc=6680\n[media]\ndtls_srtp = true\ndtls13 = true\n", .{});
    defer cfg.deinit(allocator);
    try testing.expect(cfg.media.dtls_srtp);
    try testing.expect(cfg.media.dtls13);
}

test "parseToml: media sizing keys default, lift, and validate ranges" {
    const allocator = testing.allocator;
    const base =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\
    ;
    var dflt = try parseToml(allocator, base, .{});
    defer dflt.deinit(allocator);
    try testing.expectEqual(kagura_frame.default_reorder_window_frames, dflt.media.reorder_window_frames);
    try testing.expectEqual(@as(u32, @intCast(media_room.default_max_participants)), dflt.media.max_participants);
    try testing.expectEqual(@as(u64, transcript_mod.max_text_bytes), dflt.media.captions_max_text_bytes);
    try testing.expectEqual(@as(u64, transcript_mod.max_speaker_bytes), dflt.media.captions_max_speaker_bytes);
    try testing.expectEqual(@as(u64, transcript_mod.max_per_channel), dflt.media.captions_ring_depth_per_channel);
    try testing.expectEqual(@as(u64, transcript_mod.max_channels), dflt.media.captions_max_channels);
    try testing.expectEqual(@as(u64, media_room.max_breakout_bytes), dflt.media.sfu_max_breakout_label_bytes);
    try testing.expectEqual(@as(u64, 50), dflt.media.pins_max_per_channel);
    try testing.expectEqual(@as(u64, 64), dflt.media.pins_max_msgid_bytes);
    try testing.expectEqual(@as(u64, 32), dflt.media.reactions_max_token_bytes);

    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[media]
        \\reorder_window_frames = 32
        \\max_participants = 2
        \\captions_max_text_bytes = 512
        \\captions_max_speaker_bytes = 32
        \\captions_ring_depth_per_channel = 16
        \\captions_max_channels = 128
        \\[media.sfu]
        \\max_breakout_label_bytes = 16
        \\[media.pins]
        \\max_per_channel = 10
        \\max_msgid_bytes = 32
        \\[media.reactions]
        \\max_token_bytes = 24
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expectEqual(@as(u32, 32), cfg.media.reorder_window_frames);
    try testing.expectEqual(@as(u32, 2), cfg.media.max_participants);
    try testing.expectEqual(@as(u64, 512), cfg.media.captions_max_text_bytes);
    try testing.expectEqual(@as(u64, 32), cfg.media.captions_max_speaker_bytes);
    try testing.expectEqual(@as(u64, 16), cfg.media.captions_ring_depth_per_channel);
    try testing.expectEqual(@as(u64, 128), cfg.media.captions_max_channels);
    try testing.expectEqual(@as(u64, 16), cfg.media.sfu_max_breakout_label_bytes);
    try testing.expectEqual(@as(u64, 10), cfg.media.pins_max_per_channel);
    try testing.expectEqual(@as(u64, 32), cfg.media.pins_max_msgid_bytes);
    try testing.expectEqual(@as(u64, 24), cfg.media.reactions_max_token_bytes);

    try testing.expectError(error.ParseError, parseToml(allocator, base ++ "[media]\nreorder_window_frames = 0\n", .{}));
    try testing.expectError(error.ParseError, parseToml(allocator, base ++ "[media]\nmax_participants = 0\n", .{}));
    try testing.expectError(error.ParseError, parseToml(allocator, base ++ "[media]\ncaptions_max_text_bytes = 63\n", .{}));
    try testing.expectError(error.ParseError, parseToml(allocator, base ++ "[media]\ncaptions_max_speaker_bytes = 15\n", .{}));
    try testing.expectError(error.ParseError, parseToml(allocator, base ++ "[media]\ncaptions_ring_depth_per_channel = 15\n", .{}));
    try testing.expectError(error.ParseError, parseToml(allocator, base ++ "[media]\ncaptions_max_channels = 63\n", .{}));
    try testing.expectError(error.ParseError, parseToml(allocator, base ++ "[media.sfu]\nmax_breakout_label_bytes = 7\n", .{}));
    try testing.expectError(error.ParseError, parseToml(allocator, base ++ "[media.pins]\nmax_per_channel = 0\n", .{}));
    try testing.expectError(error.ParseError, parseToml(allocator, base ++ "[media.pins]\nmax_msgid_bytes = 7\n", .{}));
    try testing.expectError(error.ParseError, parseToml(allocator, base ++ "[media.reactions]\nmax_token_bytes = 7\n", .{}));

    const too_wide_window = try std.fmt.allocPrint(allocator, "{s}[media]\nreorder_window_frames = {d}\n", .{ base, kagura_frame.window_cap + 1 });
    defer allocator.free(too_wide_window);
    try testing.expectError(error.ParseError, parseToml(allocator, too_wide_window, .{}));

    const too_many_participants = try std.fmt.allocPrint(allocator, "{s}[media]\nmax_participants = {d}\n", .{ base, media_room.max_participants + 1 });
    defer allocator.free(too_many_participants);
    try testing.expectError(error.ParseError, parseToml(allocator, too_many_participants, .{}));
}

test "parseToml: [tls] section projects onto Config" {
    // Arrange
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[tls]
        \\enabled = true
        \\port = 7000
        \\cert_path = "/etc/orochi/leaf.pem"
        \\key_path = "/etc/orochi/leaf.key"
        \\dns_name = "irc.example.test"
        \\request_client_cert = true
        \\enable_tls12 = true
        \\enable_resumption = true
        \\early_data_max_size = 16384
        \\raw_public_key = true
        \\ktls = "tx"
        \\[[tls.ech_keys]]
        \\config_path = "/etc/orochi/echconfig.bin"
        \\private_key = "1111111111111111111111111111111111111111111111111111111111111111"
        \\
    ;

    // Act
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);

    // Assert
    try testing.expect(cfg.tls.enabled);
    try testing.expectEqual(@as(u16, 7000), cfg.tls.port);
    try testing.expectEqualStrings("/etc/orochi/leaf.pem", cfg.tls.cert_path.?);
    try testing.expectEqualStrings("/etc/orochi/leaf.key", cfg.tls.key_path.?);
    try testing.expectEqualStrings("irc.example.test", cfg.tls.dns_name);
    try testing.expect(cfg.tls.request_client_cert);
    // These three keys were declared in the schema but never parsed — a TLS 1.2
    // opt-in (and resumption/0-RTT) was silently ignored. Guard the wiring.
    try testing.expect(cfg.tls.enable_tls12);
    try testing.expect(cfg.tls.enable_resumption);
    try testing.expectEqual(@as(u32, 16384), cfg.tls.early_data_max_size);
    try testing.expect(cfg.tls.raw_public_key);
    try testing.expectEqual(Config.KtlsMode.tx, cfg.tls.ktls);
    try testing.expectEqual(@as(usize, 1), cfg.tls.ech_keys.len);
    try testing.expectEqualStrings("/etc/orochi/echconfig.bin", cfg.tls.ech_keys[0].config_path);
    try testing.expectEqual(@as([32]u8, @splat(0x11)), cfg.tls.ech_keys[0].private_key);
}

test "parseToml: [[tls.ech_keys]] rejects malformed private key" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[tls]
        \\enabled = true
        \\[[tls.ech_keys]]
        \\config_path = "/etc/orochi/echconfig.bin"
        \\private_key = "abcd"
        \\
    ;

    try testing.expectError(error.ParseError, parseToml(allocator, text, .{}));
}

test "parseToml: [[tls.sni]] projects additional SNI certs onto Config" {
    // Arrange
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[tls]
        \\enabled = true
        \\cert_path = "/etc/orochi/default.pem"
        \\key_path = "/etc/orochi/default.key"
        \\[[tls.sni]]
        \\server_names = ["irc.example.test", "*.example.test"]
        \\cert_path = "/etc/orochi/example.pem"
        \\key_path = "/etc/orochi/example.key"
        \\[[tls.sni]]
        \\server_names = ["alt.test"]
        \\cert_path = "/etc/orochi/alt.pem"
        \\key_path = "/etc/orochi/alt.key"
        \\
    ;

    // Act
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);

    // Assert: the default cert is unaffected and both SNI entries parse in order.
    try testing.expectEqualStrings("/etc/orochi/default.pem", cfg.tls.cert_path.?);
    try testing.expectEqual(@as(usize, 2), cfg.tls.sni.len);
    try testing.expectEqual(@as(usize, 2), cfg.tls.sni[0].server_names.len);
    try testing.expectEqualStrings("irc.example.test", cfg.tls.sni[0].server_names[0]);
    try testing.expectEqualStrings("*.example.test", cfg.tls.sni[0].server_names[1]);
    try testing.expectEqualStrings("/etc/orochi/example.pem", cfg.tls.sni[0].cert_path);
    try testing.expectEqualStrings("/etc/orochi/example.key", cfg.tls.sni[0].key_path);
    try testing.expectEqual(@as(usize, 1), cfg.tls.sni[1].server_names.len);
    try testing.expectEqualStrings("alt.test", cfg.tls.sni[1].server_names[0]);
    try testing.expectEqualStrings("/etc/orochi/alt.pem", cfg.tls.sni[1].cert_path);
}

test "parseToml: [[tls.sni]] absent keeps sni empty (byte-identical default path)" {
    const allocator = testing.allocator;
    var cfg = try parseToml(allocator, "[node]\nid=1\n[listen]\nirc=6680\n[tls]\nenabled=true\n", .{});
    defer cfg.deinit(allocator);
    try testing.expectEqual(@as(usize, 0), cfg.tls.sni.len);
}

test "parseToml: a [[tls.sni]] entry missing required keys is rejected" {
    const allocator = testing.allocator;
    const base = "[node]\nid=1\n[listen]\nirc=6680\n[tls]\nenabled=true\n";
    // Missing key_path.
    try testing.expectError(error.ParseError, parseToml(
        allocator,
        base ++ "[[tls.sni]]\nserver_names=[\"a.test\"]\ncert_path=\"a.pem\"\n",
        .{},
    ));
    // Missing cert_path.
    try testing.expectError(error.ParseError, parseToml(
        allocator,
        base ++ "[[tls.sni]]\nserver_names=[\"a.test\"]\nkey_path=\"a.key\"\n",
        .{},
    ));
    // Missing server_names entirely.
    try testing.expectError(error.ParseError, parseToml(
        allocator,
        base ++ "[[tls.sni]]\ncert_path=\"a.pem\"\nkey_path=\"a.key\"\n",
        .{},
    ));
    // Empty server_names list.
    try testing.expectError(error.ParseError, parseToml(
        allocator,
        base ++ "[[tls.sni]]\nserver_names=[]\ncert_path=\"a.pem\"\nkey_path=\"a.key\"\n",
        .{},
    ));
}

test "parseToml: ktls mode parses txrx and rejects an unknown value" {
    const allocator = testing.allocator;
    var cfg = try parseToml(allocator, "[node]\nid=1\n[listen]\nirc=6680\n[tls]\nktls = \"txrx\"\n", .{});
    defer cfg.deinit(allocator);
    try testing.expectEqual(Config.KtlsMode.txrx, cfg.tls.ktls);
    // An unrecognized mode is a hard config error, not a silent fallback.
    try testing.expectError(error.ParseError, parseToml(allocator, "[node]\nid=1\n[listen]\nirc=6680\n[tls]\nktls = \"bogus\"\n", .{}));
}

test "parseToml: [tls] omitted keeps secure defaults" {
    // Arrange
    const allocator = testing.allocator;
    const text = "[node]\nid = 1\n[listen]\nirc = 6680\n";

    // Act
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);

    // Assert
    try testing.expect(!cfg.tls.enabled);
    try testing.expectEqual(@as(u16, 6697), cfg.tls.port);
    try testing.expectEqual(@as(?[]const u8, null), cfg.tls.cert_path);
    try testing.expectEqual(@as(?[]const u8, null), cfg.tls.key_path);
    try testing.expectEqualStrings("localhost", cfg.tls.dns_name);
    try testing.expectEqual(Config.KtlsMode.off, cfg.tls.ktls);
}

test "parseToml: [acme] section projects onto Config" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[acme]
        \\enabled = true
        \\directory_url = "https://acme.example/directory"
        \\domain = "irc.example.test"
        \\contact = "mailto:admin@example.test"
        \\renew_before_days = 45
        \\check_interval = "6h"
        \\ca_bundle_path = "/etc/orochi/acme-ca.pem"
        \\ca_bundle_max_bytes = 1048576
        \\challenge_port = 14403
        \\max_steps = 96
        \\debug = true
        \\max_response_bytes = 131072
        \\error_body_preview_bytes = 256
        \\resolv_conf_max_bytes = 32768
        \\dns_port = 5353
        \\http01_listen_backlog = 32
        \\http01_accept_poll = "500ms"
        \\http01_conn_read_timeout = "10s"
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);

    try testing.expect(cfg.acme.enabled);
    try testing.expectEqualStrings("https://acme.example/directory", cfg.acme.directory_url);
    try testing.expectEqualStrings("irc.example.test", cfg.acme.domain.?);
    try testing.expectEqualStrings("mailto:admin@example.test", cfg.acme.contact.?);
    try testing.expectEqual(@as(u16, 45), cfg.acme.renew_before_days);
    try testing.expectEqual(@as(u64, 6 * 60 * 60 * 1000), cfg.acme.check_interval_ms);
    try testing.expectEqualStrings("/etc/orochi/acme-ca.pem", cfg.acme.ca_bundle_path);
    try testing.expectEqual(@as(u64, 1048576), cfg.acme.ca_bundle_max_bytes);
    try testing.expectEqual(@as(u16, 14403), cfg.acme.challenge_port);
    try testing.expectEqual(@as(u32, 96), cfg.acme.max_steps);
    try testing.expect(cfg.acme.debug);
    try testing.expectEqual(@as(u64, 131072), cfg.acme.max_response_bytes);
    try testing.expectEqual(@as(u64, 256), cfg.acme.error_body_preview_bytes);
    try testing.expectEqual(@as(u64, 32768), cfg.acme.resolv_conf_max_bytes);
    try testing.expectEqual(@as(u16, 5353), cfg.acme.dns_port);
    try testing.expectEqual(@as(u32, 32), cfg.acme.http01_listen_backlog);
    try testing.expectEqual(@as(u32, 500), cfg.acme.http01_accept_poll_ms);
    try testing.expectEqual(@as(u32, 10), cfg.acme.http01_conn_read_timeout_sec);
}

test "parseToml: [acme] omitted keeps renewal disabled defaults and validates ranges" {
    const allocator = testing.allocator;
    var cfg = try parseToml(allocator, "[node]\nid = 1\n[listen]\nirc = 6680\n", .{});
    defer cfg.deinit(allocator);

    try testing.expect(!cfg.acme.enabled);
    try testing.expectEqualStrings(acme_default_directory_url, cfg.acme.directory_url);
    try testing.expectEqual(@as(?[]const u8, null), cfg.acme.domain);
    try testing.expectEqual(@as(?[]const u8, null), cfg.acme.contact);
    try testing.expectEqual(@as(u16, 30), cfg.acme.renew_before_days);
    try testing.expectEqual(@as(u64, 12 * 60 * 60 * 1000), cfg.acme.check_interval_ms);
    try testing.expectEqualStrings(acme_cli.default_ca_bundle, cfg.acme.ca_bundle_path);
    try testing.expectEqual(@as(u64, acme_cli.default_ca_bundle_max_bytes), cfg.acme.ca_bundle_max_bytes);
    try testing.expectEqual(acme_cli.default_challenge_port, cfg.acme.challenge_port);
    try testing.expectEqual(@as(u32, @intCast(acme_runner.default_max_steps)), cfg.acme.max_steps);
    try testing.expect(!cfg.acme.debug);
    try testing.expectEqual(@as(u64, acme_runner.default_max_response_bytes), cfg.acme.max_response_bytes);
    try testing.expectEqual(@as(u64, acme_runner.default_error_body_preview_bytes), cfg.acme.error_body_preview_bytes);
    try testing.expectEqual(@as(u64, acme_runner.default_resolv_conf_max_bytes), cfg.acme.resolv_conf_max_bytes);
    try testing.expectEqual(acme_runner.default_dns_port, cfg.acme.dns_port);
    try testing.expectEqual(@as(u32, acme_http01_listener.default_listen_backlog), cfg.acme.http01_listen_backlog);
    try testing.expectEqual(acme_http01_listener.default_accept_poll_ms, cfg.acme.http01_accept_poll_ms);
    try testing.expectEqual(acme_http01_listener.default_conn_read_timeout_sec, cfg.acme.http01_conn_read_timeout_sec);

    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[acme]
        \\renew_before_days = 0
        \\
    , .{}));
    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[acme]
        \\renew_before_days = 90
        \\
    , .{}));
    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[acme]
        \\check_interval = "0s"
        \\
    , .{}));
}

test "parseToml: [sts] section projects onto Config" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[sts]
        \\enabled = true
        \\duration = 604800
        \\port = 7000
        \\preload = true
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expect(cfg.sts.enabled);
    try testing.expectEqual(@as(u32, 604800), cfg.sts.duration);
    try testing.expectEqual(@as(u16, 7000), cfg.sts.port);
    try testing.expect(cfg.sts.preload);
}

test "parseToml: [sts] omitted keeps secure defaults" {
    const allocator = testing.allocator;
    var cfg = try parseToml(allocator, "[node]\nid = 1\n[listen]\nirc = 6680\n", .{});
    defer cfg.deinit(allocator);
    // STS off by default; never force-upgrade a plaintext deployment.
    try testing.expect(!cfg.sts.enabled);
    try testing.expectEqual(@as(u32, 2_592_000), cfg.sts.duration);
    try testing.expectEqual(@as(u16, 6697), cfg.sts.port);
    try testing.expect(!cfg.sts.preload);
}

test "parseToml: [webauthn] section projects rp_id + origins" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[webauthn]
        \\rp_id = "chat.example"
        \\origins = ["https://chat.example", "https://alt.example:8443"]
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expectEqualStrings("chat.example", cfg.webauthn.rp_id.?);
    try testing.expectEqual(@as(usize, 2), cfg.webauthn.origins.len);
    try testing.expectEqualStrings("https://chat.example", cfg.webauthn.origins[0]);
    try testing.expectEqualStrings("https://alt.example:8443", cfg.webauthn.origins[1]);
    // Hardening flags default off.
    try testing.expect(!cfg.webauthn.require_uv);
    try testing.expect(!cfg.webauthn.require_attestation);
}

test "parseToml: [webauthn] require_uv + require_attestation project when set" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[webauthn]
        \\rp_id = "chat.example"
        \\origins = ["https://chat.example"]
        \\require_uv = true
        \\require_attestation = true
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expect(cfg.webauthn.require_uv);
    try testing.expect(cfg.webauthn.require_attestation);
}

test "parseToml: [webauthn] omitted leaves the feature inert" {
    const allocator = testing.allocator;
    var cfg = try parseToml(allocator, "[node]\nid = 1\n[listen]\nirc = 6680\n", .{});
    defer cfg.deinit(allocator);
    try testing.expect(cfg.webauthn.rp_id == null);
    try testing.expectEqual(@as(usize, 0), cfg.webauthn.origins.len);
    try testing.expect(!cfg.webauthn.require_uv);
    try testing.expect(!cfg.webauthn.require_attestation);
}

test "meshCloakSecretMissing: cloak federation guard flags meshed node with no shared secret" {
    const allocator = testing.allocator;

    // Meshed (has a peer) but no [cloak] secret → per-boot random keys that break
    // ban federation and evaporate on restart. The guard must fire.
    {
        var cfg = try parseToml(allocator,
            \\[node]
            \\id = 1
            \\[listen]
            \\irc = 6680
            \\[mesh]
            \\connect = ["[::1]:6900"]
            \\
        , .{});
        defer cfg.deinit(allocator);
        try testing.expect(cfg.meshCloakSecretMissing());
    }

    // Meshed WITH a shared secret → keys are derived, cloaks federate. No fire.
    {
        var cfg = try parseToml(allocator,
            \\[node]
            \\id = 1
            \\[listen]
            \\irc = 6680
            \\[mesh]
            \\connect = ["[::1]:6900"]
            \\[cloak]
            \\secret = "shared-across-the-mesh"
            \\
        , .{});
        defer cfg.deinit(allocator);
        try testing.expect(!cfg.meshCloakSecretMissing());
    }

    // Listen-only mesh node (peers dial IN, empty [mesh] connect) with no secret
    // → same federation hazard; the guard must fire on [listen] s2s too.
    {
        var cfg = try parseToml(allocator,
            \\[node]
            \\id = 1
            \\[listen]
            \\irc = 6680
            \\s2s = 7700
            \\
        , .{});
        defer cfg.deinit(allocator);
        try testing.expect(cfg.meshCloakSecretMissing());
    }

    // Standalone node (no peers, no s2s listener), no secret → per-boot key is
    // fine, nothing to federate. No fire.
    {
        var cfg = try parseToml(allocator, "[node]\nid = 1\n[listen]\nirc = 6680\n", .{});
        defer cfg.deinit(allocator);
        try testing.expect(!cfg.meshCloakSecretMissing());
    }
}

test {
    testing.refAllDecls(@This());
}
