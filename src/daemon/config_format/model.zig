// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Canonical daemon configuration schema, defaults, and owned-value lifetime.

const std = @import("std");
const acme_cli = @import("../acme_cli.zig");
const acme_http01_listener = @import("../acme_http01_listener.zig");
const acme_runner = @import("../acme_runner.zig");
const conn_class = @import("../conn_class.zig");
const content_filter_mod = @import("../content_filter.zig");
const services_mod = @import("../services.zig");
const store_mod = @import("../store.zig");
const memo_mod = @import("../memo.zig");
const transcript_mod = @import("../transcript.zig");
const sasl_mechrouter = @import("../../proto/sasl_mechrouter.zig");
const crypto_sign = @import("../../crypto/sign.zig");
const cadence_frame = @import("../../substrate/cadence_frame.zig");
const media_room = @import("../media_room.zig");
const multiline_mod = @import("../../proto/multiline.zig");
const s2s_peer_mod = @import("../../substrate/undertow/s2s_peer.zig");
const search_index_mod = @import("../search_index.zig");
const relay_v2_activation = @import("../relay_v2_activation.zig");
const wasm_abi = @import("../../wasm/host/abi.zig");
const wasm_bridge = @import("../../wasm/host/bridge.zig");
const freeStringList = @import("values.zig").freeStringList;
const freeWasmRegistry = @import("wasm_values.zig").freeWasmRegistry;

/// Credential-bearing config strings are secure-zeroed before free.
/// Split out so the wipe is testable on caller memory before the free.
fn wipeSecretBytes(value: []const u8) void {
    std.crypto.secureZero(u8, @constCast(value));
}

fn freeSecret(allocator: std.mem.Allocator, value: []const u8) void {
    wipeSecretBytes(value);
    allocator.free(value);
}

const default_search_index_config = search_index_mod.SearchIndex.Config{};

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
    /// `[trace] file` — operator-named flight-recorder dump. Unset keeps the
    /// ring in memory for oper DEBUG.
    trace: Trace = .{},
    /// Optional process stderr sink, opened again by each Helix successor.
    logging: Logging = .{},
    oper_ocg2: OperOcg2 = .{},
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
    e2ee: E2ee = .{},
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
        /// Skip TLS certificate verification of the relay. Default false.
        /// AUTH to a non-loopback relay is refused unless this is set or
        /// `trust_store_path` loads a non-empty trust anchor.
        insecure_skip_verify: bool = false,
        /// PEM or DER file of relay trust anchors. Empty and unset keep the
        /// sender from treating a remote certificate as verified. Mail stays
        /// disabled unless `[mail] enabled` is set.
        trust_store_path: ?[]const u8 = null,
        /// Envelope sender + `From:` address (e.g. "onyx@example.org").
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
        name: []const u8 = "Onyx",
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
        location: []const u8 = "Onyx IRC network",
        email: []const u8 = "admin@onyx.local",
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
        /// Skip TLS verification for public read-only news feeds. Explicit
        /// operator escape hatch; off by default and warned at boot.
        news_insecure_tls: bool = false,
        /// PEM CA bundle whose certificates are the trust anchors for the live
        /// news fetch. Null = `ca_bundle.default_path`. An unusable bundle
        /// disables the live fetch; it never falls back to insecure.
        news_ca_bundle: ?[]const u8 = null,
        /// Read bound for `news_ca_bundle` (64 KiB..64 MiB).
        news_ca_bundle_max_bytes: u64 = 4 << 20,
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
        /// DIE, RESTART, and mesh-scope bans wait for a second distinct oper.
        /// Default off: a single-oper network is unchanged.
        two_person_rule: bool = false,
    };

    pub const Logging = struct {
        /// Append-only regular file owned by the daemon, mode 0600. Unset keeps
        /// inherited stderr (for example journald); never logs protocol payloads.
        stderr_file: ?[]const u8 = null,
    };

    /// `[trace]` flight-recorder file. A fault overwrites this path with the
    /// existing tracelog text. Unset writes nothing.
    pub const Trace = struct {
        file: ?[]const u8 = null,
    };

    /// Inactive OCG2 durable operator-authority root. Every participating node
    /// carries only this public tuple. The authority private seed is never an
    /// OCG2 config value: it comes exclusively from this process's existing
    /// node identity when that identity is the configured authority.
    pub const OperOcg2 = struct {
        enabled: bool = false,
        /// Allow verified durable OCG2 records to affect live operator-session
        /// projection. Kept separate from `enabled` so existing deployments can
        /// load and observe the durable image without changing session authority.
        projection_enabled: bool = false,
        /// Allow the configured authority node to mint new OCG2 records. This
        /// is the final activation stage and requires projection to be enabled.
        minting_enabled: bool = false,
        authority_node_id: u64 = 0,
        authority_public_key: ?[crypto_sign.public_key_len]u8 = null,
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
        /// UDP port for the native media transport (our CadenceVox/CadenceVis codec leg);
        /// 0 = ephemeral.
        native_media: u16 = 0,
        /// IP advertised to clients as the server media (ICE) candidate.
        media_host: []const u8 = "",
    };

    /// An operator binding. Onyx Server grants oper SASL-only: `account` is the SASL
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
        /// Private leased WAL for signed ordinary-guest presence, incarnation
        /// issuance, and replay-safe retirement. Required for mesh deployments
        /// with a node identity; it is never shared with account/session stores.
        presence_store_path: ?[]const u8 = null,
        mesh_pass: ?[]const u8 = null,
        /// Encoded MeshPass signed-capability token this node presents in the
        /// encrypted Mooring M1. Accepts hex or standard base64 text.
        admission_token: ?[]const u8 = null,
        /// Ed25519 signer roots accepted for signed MeshPass admission tokens.
        /// Distinct from `trust_roots`, which pins peer node identities.
        admission_roots: []const []const u8 = &.{},
        admission_min_revocation_epoch: u64 = 0,
        /// MESSAGE_V2 rollout phase. `compat` receives and forwards V2 but
        /// authors legacy only. `active` authors V2-eligible events as V2 only.
        /// Operators stage the
        /// epoch and full-mesh roster everywhere while still in compatibility
        /// mode, then flip only this field after the bridge is universal.
        relay_v2_authoring: relay_v2_activation.Mode = .compat,
        /// Monotonic operator-assigned rollout generation, not wall-clock time.
        /// Zero means no activation plan is staged.
        relay_v2_activation_epoch: u64 = 0,
        /// Full secured-mesh Ed25519 node-key roster for the staged generation.
        /// This is deliberately distinct from direct-neighbor `trust_roots`.
        relay_v2_roster: []const []const u8 = &.{},
        /// Runtime Undertow peer-driver limits/timers/capacities projected from
        /// `[mesh.routing]`, `[mesh.link]`, `[mesh.gossip]`, and `[mesh.ripple]`.
        ///
        /// Ripple (witnessed failure detection) keys live under **`[mesh.ripple]`**.
        s2s: s2s_peer_mod.Config = .{},
        /// Peers this node dials automatically at boot (and re-dials while the
        /// link is down), each a "host:port" string (IPv6 hosts bracketed,
        /// e.g. "[::1]:6900"). Empty = no auto-connect.
        connect: []const []const u8 = &.{},
        /// When true, refuse plaintext S2S entirely (reject inbound plaintext
        /// peers, never dial plaintext outbound). Only the Mooring-secured path
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
        /// Max WHOWAS history entries returned per query.
        whowas_max_entries: u32 = 20,
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
        /// Parsed and stored. Default off. The live ring never requests
        /// `IORING_SETUP_DEFER_TASKRUN` or `IORING_SETUP_SINGLE_ISSUER`.
        /// `--check-config` still rejects this key together with `sqpoll`.
        defer_taskrun: bool = false,
        /// `IORING_SETUP_SQPOLL` when set. Default off. The live ring keeps
        /// the flag through its setup ladder and falls back only on
        /// `error.ArgumentsInvalid`.
        sqpoll: bool = false,
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
        /// Rollout gate for attachment-bound composite SESSION credentials.
        /// Off keeps issuance on the legacy token shape while current readers
        /// remain capable of accepting already-issued composite credentials.
        resume_composite_issuance: bool = false,
        /// Replicate detached state only for sessions that requested a portable
        /// resume credential. Runtime kill switch for rolling deploys.
        migrate_on_detach: bool = true,
        max_pending_migrations: u32 = 4096,
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
        reorder_window_frames: u32 = cadence_frame.default_reorder_window_frames,
        max_participants: u32 = @intCast(media_room.default_max_participants),
        sfu_max_breakout_label_bytes: u64 = media_room.max_breakout_bytes,
        captions_max_text_bytes: u64 = transcript_mod.max_text_bytes,
        captions_max_speaker_bytes: u64 = transcript_mod.max_speaker_bytes,
        captions_ring_depth_per_channel: u64 = transcript_mod.max_per_channel,
        captions_max_channels: u64 = transcript_mod.max_channels,
        pins_max_per_channel: u64 = 50,
        pins_max_msgid_bytes: u64 = 64,
        reactions_max_token_bytes: u64 = 32,
        /// Require HMAC-tagged native CadenceVox/CadenceVis datagrams. Defaults off until
        /// clients implement the matching Cadence-frame tag contract.
        native_media_require_mac: bool = false,
        /// Primary browser media plane: relay binary WebSocket Cadence frames
        /// (client-held E2EE ciphertext) between call participants. Off by
        /// default; opt-in. Issues MACKEY on MEDIA JOIN; never rewraps onto
        /// native/WebRTC legs (server has no E2EE group key).
        ws_media_relay: bool = false,
        /// Require a valid per-stream MAC tag on every browser media datagram.
        /// When false (default) untagged datagrams still relay, but a present tag
        /// must verify. Prefer true with `ws_media_relay` in production.
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
        /// Strict call recording (packet journal). Off by default; when on,
        /// `recording_dir` is mandatory and recording still requires
        /// unanimous participant consent at runtime.
        recording_enabled: bool = false,
        recording_dir: ?[]const u8 = null,
        recording_retention_days: u32 = 7,
        recording_max_total_bytes: u64 = 512 * 1024 * 1024,
        recording_max_duration_secs: u64 = 4 * 3600,
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
        /// Nicks excluded from chanstats recording (bots/services). Case-insensitive.
        /// Ported from ophion m_chanstats `ignored_nicks`.
        ignore_nicks: []const []const u8 = &.{},
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

    /// `[e2ee]` — process-start policy for E2EEGROUP control authorship.
    pub const E2ee = struct {
        /// New local E2EEGROUP controls are accepted when true. Set false on
        /// every node before the first EGRG cold activation so a restarted
        /// successor remains quiesced until current mesh capability is proven.
        group_authoring_enabled: bool = true,
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
        memo_text_max_len: u64 = memo_mod.default_max_text_bytes,
        /// Max sender-name length on an offline DM (bytes).
        memo_from_max_len: u64 = memo_mod.default_max_from_bytes,
        /// Offline mailbox depth cap per account (entries).
        memo_mailbox_depth: u64 = memo_mod.default_max_per_account,
        /// Max distinct offline mailboxes.
        memo_max_accounts: u64 = memo_mod.default_max_accounts,
    };

    /// `[filter]` — oper-managed moderation filter sizing.
    pub const Filter = struct {
        /// Max oper-curated content filter patterns.
        max_patterns: u64 = content_filter_mod.default_max_patterns,
        /// Max length of a single content filter pattern (bytes).
        max_pattern_len: u64 = content_filter_mod.default_max_pattern_len,
    };

    /// Discord-compatible incoming webhook endpoint (Gateway interop). OFF by
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
        /// Outbound webhooks may target loopback and link-local hosts only when
        /// this is set. Default false. Does not change the inbound listener.
        allow_private_targets: bool = false,
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
        oauth_auto_provision: bool = false,
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
        /// `tx` is the safe opt-in. `txrx` parses, but boot refuses it: a
        /// request_peer KeyUpdate has no kernel TLS_TX reinstall (documented
        /// footgun in `config_boot.ktls_txrx_footgun`).
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
    /// `[webpush]` — browser Web Push delivery for offline DMs (memo).
    /// Off by default; enabling needs an account store (subscriptions are
    /// account-scoped) and outbound HTTPS (same trust anchors as ACME).
    pub const Webpush = struct {
        enabled: bool = false,
        /// VAPID `sub` claim — an operator contact the push service may use.
        subject: []const u8 = "mailto:ops@eshmaki.me",
        /// Where the ES256 VAPID secret persists (rotating it invalidates
        /// every stored browser subscription).
        vapid_key_path: []const u8 = "onyx-webpush-vapid.key",
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
        const webpush_vapid_key_path = try allocator.dupe(u8, "onyx-webpush-vapid.key");
        errdefer allocator.free(webpush_vapid_key_path);
        const network_name = try allocator.dupe(u8, "Onyx");
        errdefer allocator.free(network_name);
        const admin_location = try allocator.dupe(u8, "Onyx IRC network");
        errdefer allocator.free(admin_location);
        const admin_email = try allocator.dupe(u8, "admin@onyx.local");
        errdefer allocator.free(admin_email);
        const mesh_realm = try allocator.dupe(u8, "local");
        errdefer allocator.free(mesh_realm);
        const tls_dns_name = try allocator.dupe(u8, "localhost");
        errdefer allocator.free(tls_dns_name);
        return .{
            .network = .{ .name = network_name },
            .admin = .{
                .location = admin_location,
                .email = admin_email,
            },
            .listen = .{ .host = host, .media_host = media_host },
            .mesh = .{ .realm = mesh_realm },
            .tls = .{ .dns_name = tls_dns_name },
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
        if (self.node.secret_key) |value| freeSecret(allocator, value);
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
        if (self.geo.news_ca_bundle) |v| allocator.free(v);
        if (self.oper.grants_path) |v| allocator.free(v);
        if (self.oper.event_history_path) |v| allocator.free(v);
        if (self.trace.file) |v| allocator.free(v);
        if (self.logging.stderr_file) |v| allocator.free(v);
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
        if (self.mesh.presence_store_path) |value| allocator.free(value);
        freeStringList(allocator, self.mesh.trust_roots);
        freeStringList(allocator, self.mesh.admission_roots);
        freeStringList(allocator, self.mesh.relay_v2_roster);
        freeStringList(allocator, self.mesh.connect);
        freeStringList(allocator, self.dnsbl.zones);
        if (self.mail.relay_host) |value| allocator.free(value);
        if (self.mail.from) |value| allocator.free(value);
        if (self.mail.user) |value| allocator.free(value);
        if (self.mail.pass) |value| freeSecret(allocator, value);
        if (self.mail.trust_store_path) |value| allocator.free(value);
        if (self.webauthn.rp_id) |value| allocator.free(value);
        freeStringList(allocator, self.webauthn.origins);
        if (self.mesh.mesh_pass) |value| freeSecret(allocator, value);
        if (self.mesh.admission_token) |value| freeSecret(allocator, value);
        if (self.sasl.realm) |value| allocator.free(value);
        if (self.sasl.account_db) |value| allocator.free(value);
        if (self.sasl.oauth_issuer) |value| allocator.free(value);
        if (self.sasl.oauth_audience) |value| allocator.free(value);
        if (self.sasl.oauth_account_claim) |value| allocator.free(value);
        if (self.sasl.oauth_hmac_key) |value| freeSecret(allocator, value);
        if (self.sasl.oauth_jwks_file) |value| allocator.free(value);
        if (self.sasl.oauth_pubkey) |value| allocator.free(value);
        if (self.media.recording_dir) |value| allocator.free(value);
        if (self.media.stun_host) |value| allocator.free(value);
        allocator.free(self.stats.dir);
        allocator.free(self.stats.channel_dir);
        freeStringList(allocator, self.stats.ignore_nicks);
        allocator.free(self.backup.dir);
        allocator.free(self.metrics.bind);
        if (self.webhook.bind) |value| allocator.free(value);
        if (self.webhook.store_path) |value| allocator.free(value);
        if (self.webhook.public_url_base) |value| allocator.free(value);
        allocator.free(self.geoip.database);
        allocator.free(self.geoip.asn_database);
        if (self.cloak.secret) |value| freeSecret(allocator, value);
        if (self.cloak.previous_secret) |value| freeSecret(allocator, value);
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

test "wipeSecretBytes zeroes credential bytes" {
    var buf = "node-secret-hex-value".*;
    wipeSecretBytes(&buf);
    for (buf) |b| try std.testing.expectEqual(@as(u8, 0), b);
}
