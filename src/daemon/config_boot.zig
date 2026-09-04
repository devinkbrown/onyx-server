// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Boot glue: map a parsed `config_format.Config` onto the runtime
//! `server.Config`, and load it from a settings file at startup.
//!
//! The daemon previously hardcoded its listen port and ignored config entirely;
//! this wires the (most complete) config parser into the boot path. Mapping is
//! conservative — a field is overridden only when the config supplies a
//! meaningful value, otherwise the caller's defaults stand.
const std = @import("std");
const dlog = @import("dlog.zig");

const config_format = @import("config_format.zig");
const server = @import("server.zig");
const oper_mod = @import("oper.zig");
const conn_class = @import("conn_class.zig");
const og_mod = @import("operator_groups.zig");
const event_spine = @import("event_spine.zig");
const wasm_bridge = @import("../wasm/host/bridge.zig");
const cadence_frame = @import("../substrate/cadence_frame.zig");
const media_session = @import("../substrate/media_session.zig");
const certfp_bind = @import("certfp_bind.zig");
const certfp = @import("../proto/certfp.zig");
const durable_oper_authority = @import("durable_oper_authority.zig");
const durable_oper_authority_boot = @import("durable_oper_authority_boot.zig");
const node_identity = @import("node_identity.zig");
const store_mod = @import("store.zig");

/// Deliberately staged OCG2 runtime authority. `observe` is the historical
/// enabled-only behavior: boot and verify the durable image without allowing it
/// to alter live sessions or mint authority records.
pub const Ocg2RuntimeMode = enum {
    disabled,
    observe,
    project,
    mint,
};

/// Runtime stages implemented by this binary. Keep CLI preflight and normal
/// boot on this single predicate; reserved privilege-changing modes must never
/// pass validation only to fail during service restart.
pub fn ocg2RuntimeModeSupported(mode: Ocg2RuntimeMode) bool {
    return mode == .disabled or mode == .observe;
}

pub const Ocg2BootConfig = struct {
    enabled: bool = false,
    mode: Ocg2RuntimeMode = .disabled,
    authority: ?durable_oper_authority.Config = null,
};

pub const Ocg2LocalRole = enum { authority, receiver };

pub const Ocg2IdentityError = error{
    Ocg2Disabled,
    MissingNodeIdentity,
    Ocg2AuthorityPublicKeyMismatch,
    Ocg2MintingRequiresAuthority,
};

pub const Ocg2ActivationSource = enum { initialized, restored };

pub const Ocg2Activation = struct {
    state: durable_oper_authority.State,
    source: Ocg2ActivationSource,
};

pub fn mapOcg2BootConfig(cfg: config_format.Config) Ocg2BootConfig {
    if (!cfg.oper_ocg2.enabled) return .{};
    const mode: Ocg2RuntimeMode = if (cfg.oper_ocg2.minting_enabled)
        .mint
    else if (cfg.oper_ocg2.projection_enabled)
        .project
    else
        .observe;
    return .{ .enabled = true, .mode = mode, .authority = .{
        .authority_node_id = cfg.oper_ocg2.authority_node_id,
        .authority_pubkey = cfg.oper_ocg2.authority_public_key.?,
    } };
}

/// Classify this process without ever importing authority private material from
/// shared OCG2 config. If the local node claims the authority short ID, require
/// its complete Ed25519 public key to equal the configured root.
pub fn validateOcg2LocalIdentity(
    cfg: Ocg2BootConfig,
    identity: ?*const node_identity.NodeIdentity,
) Ocg2IdentityError!Ocg2LocalRole {
    if (!cfg.enabled) return error.Ocg2Disabled;
    const local = identity orelse return error.MissingNodeIdentity;
    const authority = cfg.authority orelse return error.Ocg2Disabled;
    if (local.shortId() != authority.authority_node_id) {
        if (cfg.mode == .mint) return error.Ocg2MintingRequiresAuthority;
        return .receiver;
    }
    if (!std.crypto.timing_safe.eql(
        [std.crypto.sign.Ed25519.PublicKey.encoded_length]u8,
        local.sign_kp.public_key,
        authority.authority_pubkey,
    )) return error.Ocg2AuthorityPublicKeyMismatch;
    return .authority;
}

/// Activate the local durable image. Exactly two absent rows are the explicit
/// cold-start case. One absent row is partial state and is never repaired; two
/// present rows are validated and restored against the frozen authority tuple.
pub fn activateOcg2Store(
    allocator: std.mem.Allocator,
    store: *store_mod.OroStore,
    cfg: Ocg2BootConfig,
) durable_oper_authority_boot.Error!Ocg2Activation {
    const authority = cfg.authority orelse return error.InvalidAuthority;
    const marker_present = store.get(.props, durable_oper_authority.marker_key) != null;
    const snapshot_present = store.get(.props, durable_oper_authority.snapshot_key) != null;
    if (marker_present != snapshot_present) return error.PartialInitialization;
    if (!marker_present) return .{
        .state = try durable_oper_authority_boot.initialize(allocator, store, authority),
        .source = .initialized,
    };
    return .{
        .state = try durable_oper_authority_boot.load(allocator, store, authority),
        .source = .restored,
    };
}

/// Overlay non-empty/non-zero config values onto `base` (which carries defaults).
/// `cfg`'s string fields (e.g. host) are borrowed — keep `cfg` alive as long as
/// the returned Config is used.
pub fn mapToServerConfig(cfg: config_format.Config, base: server.Config) server.Config {
    var out = base;
    if (cfg.network.name.len != 0) out.network_name = cfg.network.name;
    if (cfg.network.server_name) |v| out.server_name = v;
    if (cfg.network.description) |v| {
        if (v.len != 0) out.server_description = v;
    }
    if (cfg.network.icon_url) |v| {
        if (v.len != 0) out.network_icon_url = v;
    }
    out.network_discoverable = cfg.network.discoverable;
    if (cfg.motd.text) |t| out.motd_text_raw = t;
    if (cfg.admin.location.len != 0) out.admin_location = cfg.admin.location;
    if (cfg.admin.email.len != 0) out.admin_email = cfg.admin.email;
    out.weather_enabled = cfg.weather.enabled;
    if (cfg.weather.location) |v| out.weather_location = v;
    if (cfg.weather.country) |v| out.weather_country = v;
    if (cfg.weather.units) |v| out.weather_units = v;
    if (cfg.weather.source) |v| out.weather_source = v;
    out.news_enabled = cfg.news.enabled;
    if (cfg.news.source) |v| out.news_source = v;
    out.news_count = cfg.news.count;
    out.geo_enabled = cfg.geo.enabled;
    out.geo_news_insecure_tls = cfg.geo.news_insecure_tls;
    out.geo_cmd_cooldown_ms = cfg.geo.cmd_cooldown_ms;
    if (cfg.geo.default_location) |v| out.geo_default_location = v;
    if (cfg.geo.news_cache_dir) |v| out.geo_news_cache_dir = v;
    if (cfg.oper.grants_path) |v| out.oper_grants_path = v;
    if (cfg.oper.event_history_path) |v| out.event_history_path = v;
    out.oper_auto_override = cfg.oper.auto_override;
    if (cfg.wasm.plugin_dir) |v| out.wasm_plugin_dir = v;
    out.wasm_max_plugin_bytes = cfg.wasm.max_plugin_bytes;
    out.wasm_max_memory_bytes = cfg.wasm.max_memory_bytes;
    out.wasm_default_fuel = cfg.wasm.default_fuel;
    out.wasm_allowed_caps = cfg.wasm.allowed_caps;
    out.wasm_allowed_intents = cfg.wasm.allowed_intents;
    out.wasm_registry = cfg.wasm.registry;
    out.wasm_revoked_hashes = cfg.wasm.revoked_blake3;
    out.wasm_disabled_plugins = cfg.wasm.disabled_plugins;
    if (cfg.listen.irc != 0) out.port = cfg.listen.irc;
    if (cfg.listen.host.len != 0) out.host = cfg.listen.host;
    if (cfg.listen.s2s != 0) out.s2s_port = cfg.listen.s2s;
    if (cfg.listen.webtransport != 0) out.webtransport_port = cfg.listen.webtransport;
    out.proxy_protocol_enabled = cfg.listen.proxy_protocol;
    if (cfg.listen.trusted_proxies.len != 0) out.trusted_proxies = cfg.listen.trusted_proxies;
    if (cfg.listen.ws != 0) {
        // Secure-WebSocket browser listener intent. The live listener only
        // stands up once main.zig has loaded the TLS certificate (or in the
        // testing-only `ws_plain` mode) — see server.initReactor's gate.
        out.ws_enabled = true;
        out.ws_port = cfg.listen.ws;
        out.ws_allow_plain = cfg.listen.ws_plain;
    }
    if (cfg.listen.media != 0) out.media_port = cfg.listen.media;
    if (cfg.listen.native_media != 0) out.native_media_port = cfg.listen.native_media;
    if (cfg.listen.media_host.len != 0) out.media_host = cfg.listen.media_host;
    out.media_enabled = cfg.media.enabled;
    if (!out.media_enabled) out.disabled_features = &.{"media"};
    out.media_max_upload_bytes = cfg.media.max_upload_bytes;
    out.media_max_frame_bytes = cfg.media.max_frame_bytes;
    out.media_reorder_window_frames = cfg.media.reorder_window_frames;
    out.media_max_participants = cfg.media.max_participants;
    out.media_sfu_max_breakout_label_bytes = @intCast(cfg.media.sfu_max_breakout_label_bytes);
    out.transcript_config = .{
        .max_text_bytes = @intCast(cfg.media.captions_max_text_bytes),
        .max_speaker_bytes = @intCast(cfg.media.captions_max_speaker_bytes),
        .max_per_channel = @intCast(cfg.media.captions_ring_depth_per_channel),
        .max_channels = @intCast(cfg.media.captions_max_channels),
    };
    out.media_pins_max_per_channel = @intCast(cfg.media.pins_max_per_channel);
    out.media_pins_max_msgid_bytes = @intCast(cfg.media.pins_max_msgid_bytes);
    out.media_reactions_max_token_bytes = @intCast(cfg.media.reactions_max_token_bytes);
    out.native_media_require_mac = cfg.media.native_media_require_mac;
    out.ws_media_relay = cfg.media.ws_media_relay;
    out.ws_media_require_mac = cfg.media.ws_media_require_mac;
    out.media_dtls_srtp = cfg.media.dtls_srtp;
    out.media_dtls13 = cfg.media.dtls13;
    if (cfg.media.stun_host) |h| out.media_stun_host = h;
    if (cfg.media.stun_port != 0) out.media_stun_port = cfg.media.stun_port;
    if (cfg.stats.dir.len != 0) out.stats_web_dir = cfg.stats.dir;
    if (cfg.stats.channel_dir.len != 0) out.chanstats_dir = cfg.stats.channel_dir;
    if (cfg.stats.interval_ms != 0) out.stats_interval_ms = cfg.stats.interval_ms;
    out.chanstats_ignore_nicks = cfg.stats.ignore_nicks;
    if (cfg.backup.dir.len != 0) out.backup_dir = cfg.backup.dir;
    if (cfg.backup.interval_ms != 0) out.backup_interval_ms = cfg.backup.interval_ms;
    if (cfg.sasl.account_db) |db| out.account_store_path = db;
    // [metrics] — live Prometheus /metrics endpoint. Off unless a port is set;
    // the bind defaults to loopback and is only widened by an explicit address.
    if (cfg.metrics.listen != 0) {
        out.metrics_port = cfg.metrics.listen;
        if (parseIp4Host(cfg.metrics.bind)) |addr| out.metrics_bind_addr = addr;
    }
    out.e2ee_group_authoring_enabled = cfg.e2ee.group_authoring_enabled;
    // [webhook] — Discord-compatible incoming webhook endpoint. Fully gated by
    // `enabled`; the bind defaults to loopback and widens only via an address.
    out.webhook_enabled = cfg.webhook.enabled;
    out.webhook_port = cfg.webhook.listen;
    if (cfg.webhook.bind) |b| {
        if (parseIp4Host(b)) |addr| out.webhook_bind_addr = addr;
    }
    if (cfg.webhook.store_path) |p| out.webhook_store_path = p;
    out.webhook_max_body = cfg.webhook.max_body_bytes;
    out.webhook_rate_per_min = cfg.webhook.rate_per_min;
    out.webhook_rate_burst = cfg.webhook.rate_burst;
    if (cfg.webhook.public_url_base) |u| out.webhook_public_base = u;
    if (cfg.geoip.database.len != 0) out.geoip_db_path = cfg.geoip.database;
    if (cfg.geoip.asn_database.len != 0) out.geoip_asn_db_path = cfg.geoip.asn_database;
    out.backlog = cfg.limits.backlog;
    out.max_clients = cfg.limits.max_clients;
    out.topiclen = cfg.limits.topiclen;
    out.awaylen = cfg.limits.awaylen;
    out.kicklen = cfg.limits.kicklen;
    out.nicklen = cfg.limits.nicklen;
    out.channellen = cfg.limits.channellen;
    out.maxlist = cfg.limits.maxlist;
    out.chanlimit = cfg.limits.chanlimit;
    out.maxtargets = cfg.limits.maxtargets;
    out.keylen = cfg.limits.keylen;
    out.modes_per_line = cfg.limits.modes_per_line;
    out.monitorlimit = cfg.limits.monitorlimit;
    out.silencelimit = cfg.limits.silencelimit;
    if (cfg.limits.handshake_timeout_ms != 0) out.registration_timeout_ms = @intCast(cfg.limits.handshake_timeout_ms);
    if (cfg.limits.ping_interval_ms != 0) out.ping_interval_ms = @intCast(cfg.limits.ping_interval_ms);
    if (cfg.limits.ping_timeout_ms != 0) out.ping_timeout_ms = @intCast(cfg.limits.ping_timeout_ms);
    out.max_clones_per_ip = cfg.limits.max_clones_per_ip;
    out.max_clones_per_net = cfg.limits.max_clones_per_net;
    out.nick_delay_ms = cfg.limits.nick_delay_ms;
    out.throttle_connects = cfg.limits.throttle_connects;
    out.throttle_window_ms = cfg.limits.throttle_window_ms;
    out.raid_joins = cfg.limits.raid_joins;
    out.raid_secs = @intCast(@max(@as(u64, 1), cfg.limits.raid_window_ms / 1000));
    out.max_clones_per_ip_net = cfg.limits.max_clones_per_ip_net;
    out.reputation_refuse_threshold = cfg.limits.reputation_refuse_threshold;
    if (cfg.limits.reputation_half_life_ms != 0) out.reputation_half_life_ms = @intCast(cfg.limits.reputation_half_life_ms);
    if (cfg.limits.sweep_interval_ms != 0) out.sweep_interval_ms = @intCast(cfg.limits.sweep_interval_ms);
    out.ring_entries = @intCast(cfg.io.ring_entries);
    out.cqe_batch = @intCast(cfg.io.cqe_batch);
    // Ownership-safe setup flags. `RingCore.init` (`server.zig`) is the
    // fail-closed probe: `IoUring.init` with these flags returns
    // `error.Unsupported` instead of silently narrowing to baseline.
    // Default false = byte-identical. Do not raise `cqe_batch` here.
    out.features.defer_taskrun = cfg.io.defer_taskrun;
    out.features.sqpoll = cfg.io.sqpoll;
    out.reg_timeout_penalty = cfg.reputation.registration_timeout_penalty;
    out.clone_refuse_penalty = cfg.reputation.clone_refuse_penalty;
    out.session_max_accounts = cfg.sessions.max_accounts;
    out.session_max_per_account = cfg.sessions.max_per_account;
    out.session_resume_composite_issuance = cfg.sessions.resume_composite_issuance;
    out.session_migrate_on_detach = cfg.sessions.migrate_on_detach;
    out.session_max_pending_migrations = cfg.sessions.max_pending_migrations;
    out.multiline_max_bytes = @intCast(cfg.ircv3.multiline_max_bytes);
    out.multiline_max_lines = @intCast(cfg.ircv3.multiline_max_lines);
    out.multiline_ref_len = @intCast(cfg.ircv3.multiline_ref_len);
    out.multiline_target_len = @intCast(cfg.ircv3.multiline_target_len);
    out.search_index_config = .{
        .max_words = @intCast(cfg.history.search_max_words),
        .max_ids_per_word = @intCast(cfg.history.search_max_ids_per_word),
        .max_token_bytes = @intCast(cfg.history.search_max_token_bytes),
    };
    out.memo_config = .{
        .max_text_bytes = @intCast(cfg.bouncer.memo_text_max_len),
        .max_from_bytes = @intCast(cfg.bouncer.memo_from_max_len),
        .max_per_account = @intCast(cfg.bouncer.memo_mailbox_depth),
        .max_accounts = @intCast(cfg.bouncer.memo_max_accounts),
    };
    out.content_filter_config = .{
        .max_patterns = @intCast(cfg.filter.koshi_max_patterns),
        .max_pattern_len = @intCast(cfg.filter.koshi_pattern_max_len),
    };
    if (cfg.node.id != 0) out.node_id = cfg.node.id;
    if (cfg.node.public_key) |v| out.node_public_key = v;
    out.s2s_config = cfg.mesh.s2s;
    if (cfg.mesh.realm.len != 0) out.mesh_realm = cfg.mesh.realm;
    if (cfg.mesh.mesh_pass) |v| out.mesh_pass = v;
    if (cfg.mesh.admission_token) |v| out.mesh_admission_token = v;
    if (cfg.mesh.trust_roots.len != 0) out.mesh_trust_roots = cfg.mesh.trust_roots;
    if (cfg.mesh.admission_roots.len != 0) out.mesh_admission_roots = cfg.mesh.admission_roots;
    out.mesh_admission_min_revocation_epoch = cfg.mesh.admission_min_revocation_epoch;
    // The activation tuple is one authority. An empty projection cannot remove
    // a staged plan or hot-downgrade an active base (both are forbidden state
    // transitions); a meaningful plan replaces all three fields together.
    // Never mix generations.
    if (cfg.mesh.relay_v2_authoring == .active or
        cfg.mesh.relay_v2_activation_epoch != 0 or
        cfg.mesh.relay_v2_roster.len != 0)
    {
        out.relay_v2_authoring = cfg.mesh.relay_v2_authoring;
        out.relay_v2_activation_epoch = cfg.mesh.relay_v2_activation_epoch;
        out.relay_v2_roster = cfg.mesh.relay_v2_roster;
    }
    out.sasl_enabled = cfg.sasl.enabled or !cfg.sasl.enabled_explicit;
    if (cfg.sasl.realm) |realm| out.sasl_realm = realm;
    out.sasl_decode_max_bytes = cfg.limits.sasl_decode_max_bytes;
    out.sasl_allow_anonymous = cfg.sasl.allow_anonymous;
    // [mesh].connect — peers this node auto-dials at boot (strings borrow cfg).
    if (cfg.mesh.connect.len != 0) out.mesh_connect = cfg.mesh.connect;
    // [webauthn] — passkey RP id + allowed origins (strings borrow cfg, which
    // lives for the process). Both must be present for WEBAUTHN to activate.
    if (cfg.webauthn.rp_id) |v| {
        if (v.len != 0) out.webauthn_rp_id = v;
    }
    if (cfg.webauthn.origins.len != 0) out.webauthn_origins = cfg.webauthn.origins;
    out.webauthn_require_uv = cfg.webauthn.require_uv;
    out.webauthn_require_attestation = cfg.webauthn.require_attestation;
    return out;
}

/// Parse a dotted-quad IPv4 literal into a host-byte-order u32 (e.g. "127.0.0.1"
/// → 0x7f00_0001). Returns null on any malformed input so the caller keeps its
/// secure loopback default rather than binding an unexpected address.
fn parseIp4Host(s: []const u8) ?u32 {
    var octets: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, s, '.');
    var i: usize = 0;
    while (it.next()) |part| : (i += 1) {
        if (i >= 4) return null;
        octets[i] = std.fmt.parseInt(u8, part, 10) catch return null;
    }
    if (i != 4) return null;
    return (@as(u32, octets[0]) << 24) | (@as(u32, octets[1]) << 16) |
        (@as(u32, octets[2]) << 8) | @as(u32, octets[3]);
}

test "parseIp4Host parses loopback and rejects junk" {
    try std.testing.expectEqual(@as(?u32, 0x7f00_0001), parseIp4Host("127.0.0.1"));
    try std.testing.expectEqual(@as(?u32, 0x0000_0000), parseIp4Host("0.0.0.0"));
    try std.testing.expectEqual(@as(?u32, 0xc0a8_0101), parseIp4Host("192.168.1.1"));
    try std.testing.expectEqual(@as(?u32, null), parseIp4Host("127.0.0"));
    try std.testing.expectEqual(@as(?u32, null), parseIp4Host("not-an-ip"));
    try std.testing.expectEqual(@as(?u32, null), parseIp4Host("256.0.0.1"));
}

test "MESSAGE_V2 activation fields map without reparsing deployment identities" {
    const roster = [_][]const u8{ "local-key", "peer-key" };
    var parsed = config_format.Config{};
    parsed.node.public_key = "local-public-key";
    parsed.mesh.relay_v2_authoring = .active;
    parsed.mesh.relay_v2_activation_epoch = 17;
    parsed.mesh.relay_v2_roster = &roster;

    const mapped = mapToServerConfig(parsed, .{ .port = 0 });
    try testing.expectEqualStrings("local-public-key", mapped.node_public_key.?);
    try testing.expect(mapped.relay_v2_authoring == .active);
    try testing.expectEqual(@as(u64, 17), mapped.relay_v2_activation_epoch);
    try testing.expectEqual(@as(usize, 2), mapped.relay_v2_roster.len);
    try testing.expectEqualStrings("local-key", mapped.relay_v2_roster[0]);
    try testing.expectEqualStrings("peer-key", mapped.relay_v2_roster[1]);
}

test "MESSAGE_V2 empty projection cannot downgrade a base plan" {
    const stale_roster = [_][]const u8{ "stale-local", "stale-peer" };
    const mapped = mapToServerConfig(.{}, .{
        .port = 0,
        .node_public_key = "established-key",
        .relay_v2_authoring = .active,
        .relay_v2_activation_epoch = 42,
        .relay_v2_roster = &stale_roster,
    });

    try testing.expectEqualStrings("established-key", mapped.node_public_key.?);
    try testing.expect(mapped.relay_v2_authoring == .active);
    try testing.expectEqual(@as(u64, 42), mapped.relay_v2_activation_epoch);
    try testing.expectEqual(@as(usize, 2), mapped.relay_v2_roster.len);
}

/// Neutral STS boot projection consumed by `main.zig` to enable IRCv3 STS per
/// session. This struct deliberately holds no wire/policy values — `main.zig`
/// owns the `proto/sts_policy.zig` build + per-session `enableSts` call; here we
/// only surface the parsed `[sts]` config so the boot path stays decoupled.
pub const StsBootConfig = struct {
    enabled: bool = false,
    duration: u32 = 2_592_000,
    port: u16 = 6697,
    preload: bool = false,
};

/// Seed every `[[opers]].certfp` fingerprint into the certfp bind store, binding
/// it to that oper's `account`, so SASL EXTERNAL resolves certfp-only without a
/// prior runtime `CERTADD`. Idempotent: re-applying the same config seed each boot
/// is a no-op replace, and it COEXISTS with runtime `CERTADD` binds (the store is
/// never wiped). Fail-closed per entry: a fingerprint that is not 64 lowercase-hex
/// chars (after case normalization), or whose account is empty/oversize, is
/// skipped with a boot warning rather than aborting. Returns the number of
/// fingerprints successfully bound.
pub fn seedOperCertfpBinds(binds: *certfp_bind.CertfpBindStore, opers: []const config_format.Config.Oper) usize {
    var bound: usize = 0;
    for (opers) |o| {
        if (o.certfp.len == 0) continue;
        if (o.account.len == 0) {
            dlog.log("onyx-server: skipping certfp seed: oper binding has an empty account\n", .{});
            continue;
        }
        for (o.certfp) |raw| {
            if (raw.len != certfp.fingerprint_len) {
                dlog.log("onyx-server: skipping malformed certfp for account '{s}': expected {d} hex chars, got {d}\n", .{ o.account, certfp.fingerprint_len, raw.len });
                continue;
            }
            // Normalize case to lowercase into a fixed buffer; validateFingerprint
            // (via bind) then rejects any non-hex byte fail-closed.
            var lowered: [certfp.fingerprint_len]u8 = undefined;
            for (raw, 0..) |ch, i| lowered[i] = std.ascii.toLower(ch);
            binds.bind(o.account, &lowered) catch |err| {
                dlog.log("onyx-server: skipping invalid certfp for account '{s}': {s}\n", .{ o.account, @errorName(err) });
                continue;
            };
            bound += 1;
        }
    }
    return bound;
}

/// Project the parsed `[sts]` config onto the neutral boot struct. Unlike
/// `mapToServerConfig`, this copies fields verbatim (no zero-means-default
/// overlay): the parser already carries the secure defaults when `[sts]` is
/// omitted, so `main.zig` reads an authoritative snapshot.
pub fn mapStsBootConfig(cfg: config_format.Config) StsBootConfig {
    return .{
        .enabled = cfg.sts.enabled,
        .duration = cfg.sts.duration,
        .port = cfg.sts.port,
        .preload = cfg.sts.preload,
    };
}

/// Parse `text` and overlay it onto `base`. Returns the mapped Config plus the
/// owned parsed config (caller must `deinit` it AFTER it is done using the
/// returned Config, since string fields are borrowed). On parse failure returns
/// the error and, when available, fills `diag_out`.
/// Neutral projection of the `[tls]` section for the boot layer. `server.Config`
/// has no TLS fields (and is owned by another module), so the parsed TLS intent
/// rides alongside the mapped server config here; `main.zig` consumes it to drive
/// `tls_certs.loadOrBootstrap` and the (separately wired) TLS listener. String
/// fields borrow `parsed` — keep the owning `Loaded` alive while they are used.
pub const TlsBootConfig = struct {
    enabled: bool = false,
    port: u16 = 6697,
    cert_path: ?[]const u8 = null,
    key_path: ?[]const u8 = null,
    dns_name: []const u8 = "localhost",
    request_client_cert: bool = false,
    enable_tls12: bool = false,
    enable_resumption: bool = false,
    early_data_max_size: u32 = 0,
    raw_public_key: bool = false,
    ktls: config_format.Config.KtlsMode = .off,
    /// Additional SNI-selectable certificates (`[[tls.sni]]`). Strings borrow
    /// `parsed`; `main.zig` loads each entry's cert+key and hands the material to
    /// the TLS listener. Empty ⇒ no SNI certs (single-cert behavior).
    sni: []const config_format.Config.SniCertDef = &.{},
    /// Server-side ECH acceptance material (`[[tls.ech_keys]]`). Config paths and
    /// key bytes borrow `parsed`; `main.zig` loads the ECHConfigList bytes and the
    /// TLS engine validates the public/private match before wiring the listener.
    ech_keys: []const config_format.Config.EchKeyDef = &.{},
};

/// Project the parsed `[tls]` section onto the neutral boot struct. Borrows
/// `cfg`'s string fields; keep `cfg` alive as long as the result is used.
pub fn mapTlsBootConfig(cfg: config_format.Config) TlsBootConfig {
    return .{
        .enabled = cfg.tls.enabled,
        .port = cfg.tls.port,
        .cert_path = cfg.tls.cert_path,
        .key_path = cfg.tls.key_path,
        .dns_name = cfg.tls.dns_name,
        .request_client_cert = cfg.tls.request_client_cert,
        .enable_tls12 = cfg.tls.enable_tls12,
        .enable_resumption = cfg.tls.enable_resumption,
        .early_data_max_size = cfg.tls.early_data_max_size,
        .raw_public_key = cfg.tls.raw_public_key,
        .ktls = cfg.tls.ktls,
        .sni = cfg.tls.sni,
        .ech_keys = cfg.tls.ech_keys,
    };
}

/// Neutral boot projection for the in-daemon ACME renewal scheduler. Strings
/// borrow `cfg`; keep the parsed config alive while the scheduler is running.
pub const AcmeBootConfig = struct {
    enabled: bool = false,
    directory_url: []const u8 = config_format.acme_default_directory_url,
    domain: ?[]const u8 = null,
    contact: ?[]const u8 = null,
    renew_before_days: u16 = 30,
    check_interval_ms: u64 = 12 * 60 * 60 * 1000,
    ca_bundle_path: []const u8 = (config_format.Config.Acme{}).ca_bundle_path,
    ca_bundle_max_bytes: u64 = (config_format.Config.Acme{}).ca_bundle_max_bytes,
    challenge_port: u16 = (config_format.Config.Acme{}).challenge_port,
    max_steps: u32 = (config_format.Config.Acme{}).max_steps,
    debug: bool = false,
    max_response_bytes: u64 = (config_format.Config.Acme{}).max_response_bytes,
    error_body_preview_bytes: u64 = (config_format.Config.Acme{}).error_body_preview_bytes,
    resolv_conf_max_bytes: u64 = (config_format.Config.Acme{}).resolv_conf_max_bytes,
    dns_port: u16 = (config_format.Config.Acme{}).dns_port,
    http01_listen_backlog: u32 = (config_format.Config.Acme{}).http01_listen_backlog,
    http01_accept_poll_ms: u32 = (config_format.Config.Acme{}).http01_accept_poll_ms,
    http01_conn_read_timeout_sec: u32 = (config_format.Config.Acme{}).http01_conn_read_timeout_sec,
};

/// Neutral `[io]` flag projection for ownership-safe io_uring setup
/// (`defer_taskrun`+`SINGLE_ISSUER`, `sqpoll`). `mapToServerConfig` also
/// copies these onto `server.Config.features` so `RingCore.init` is the
/// fail-closed kernel probe. Default false = byte-identical.
pub const IoBootConfig = struct {
    defer_taskrun: bool = false,
    sqpoll: bool = false,
};

pub fn mapIoBootConfig(cfg: config_format.Config) IoBootConfig {
    return .{
        .defer_taskrun = cfg.io.defer_taskrun,
        .sqpoll = cfg.io.sqpoll,
    };
}

pub fn mapAcmeBootConfig(cfg: config_format.Config) AcmeBootConfig {
    return .{
        .enabled = cfg.acme.enabled,
        .directory_url = cfg.acme.directory_url,
        .domain = cfg.acme.domain,
        .contact = cfg.acme.contact,
        .renew_before_days = cfg.acme.renew_before_days,
        .check_interval_ms = cfg.acme.check_interval_ms,
        .ca_bundle_path = cfg.acme.ca_bundle_path,
        .ca_bundle_max_bytes = cfg.acme.ca_bundle_max_bytes,
        .challenge_port = cfg.acme.challenge_port,
        .max_steps = cfg.acme.max_steps,
        .debug = cfg.acme.debug,
        .max_response_bytes = cfg.acme.max_response_bytes,
        .error_body_preview_bytes = cfg.acme.error_body_preview_bytes,
        .resolv_conf_max_bytes = cfg.acme.resolv_conf_max_bytes,
        .dns_port = cfg.acme.dns_port,
        .http01_listen_backlog = cfg.acme.http01_listen_backlog,
        .http01_accept_poll_ms = cfg.acme.http01_accept_poll_ms,
        .http01_conn_read_timeout_sec = cfg.acme.http01_conn_read_timeout_sec,
    };
}

pub const Loaded = struct {
    config: server.Config,
    parsed: config_format.Config,
    /// Public-only OCG2 root projection. Main validates the local node identity
    /// and owns any activated state; Server receives no pointer or capability.
    ocg2: Ocg2BootConfig = .{},
    /// Owned oper bindings backing `config.oper_registry` (strings borrow `parsed`).
    oper_bindings: []oper_mod.OperBinding = &.{},
    /// Parsed `[tls]` intent (strings borrow `parsed`); the live listener and
    /// certificate loading are wired by `main.zig`, not here.
    tls: TlsBootConfig = .{},
    /// Parsed `[acme]` renewal intent (strings borrow `parsed`); main owns the
    /// scheduler lifetime because it needs the live server pointer.
    acme: AcmeBootConfig = .{},
    /// Neutral IRCv3 STS boot projection; `main.zig` consumes this to enable STS.
    sts: StsBootConfig = .{},
    /// Parsed `[io]` ownership-safe ring flags. Also copied onto
    /// `config.features`; `RingCore.init` refuse-closes if the kernel
    /// rejects the setup flags.
    io: IoBootConfig = .{},
    /// Number of worker reactor shards to spin up (`ReactorPool` size). 1 = the
    /// single-reactor model. `server.Config` carries no thread-topology field,
    /// so the parsed `[limits].num_shards` rides here for `main.zig` to consume.
    num_shards: u16 = 1,

    pub fn deinit(self: *Loaded, allocator: std.mem.Allocator) void {
        allocator.free(self.oper_bindings);
        if (self.config.class_registry) |*r| r.deinit();
        self.parsed.deinit(allocator);
        self.* = undefined;
    }
};

pub fn loadFromText(
    allocator: std.mem.Allocator,
    text: []const u8,
    base: server.Config,
    resolver: config_format.Resolver,
) !Loaded {
    var parsed = try config_format.parseToml(allocator, text, resolver);
    errdefer parsed.deinit(allocator);

    // Role-based operator groups: build a transient registry from `[[oper_groups]]`
    // (each a named privilege set, optionally inheriting another). An oper's
    // privileges are then resolved from its `class` group; an oper whose class
    // names no group falls back to full privileges (back-compatible default).
    var groups = og_mod.Registry.init();
    defer groups.deinit(allocator);
    for (parsed.oper_groups) |g| {
        var pbuf: [32]oper_mod.Privilege = undefined;
        var pn: usize = 0;
        for (g.privileges) |ps| {
            if (std.meta.stringToEnum(oper_mod.Privilege, ps)) |p| {
                if (pn < pbuf.len) {
                    pbuf[pn] = p;
                    pn += 1;
                }
            }
        }
        groups.add(allocator, g.name, oper_mod.OperPrivileges.initMany(pbuf[0..pn]), if (g.inherits.len > 0) g.inherits else null) catch {};
    }

    // Build the SASL-only operator registry from `[[opers]]` blocks.
    var bindings: std.ArrayList(oper_mod.OperBinding) = .empty;
    errdefer bindings.deinit(allocator);
    for (parsed.opers) |o| {
        if (o.class.len == 0 or groups.get(o.class) == null) {
            dlog.log("onyx-server: skipping oper binding for account '{s}': unknown or empty class\n", .{o.account});
            continue;
        }
        const privileges = groups.effectivePrivileges(o.class);
        if (privileges.count() == 0) {
            dlog.log("onyx-server: skipping oper binding for account '{s}': class '{s}' has no privileges\n", .{ o.account, o.class });
            continue;
        }
        try bindings.append(allocator, .{
            .account_name = o.account,
            .class_name = o.class,
            .privileges = privileges,
            .title = o.title,
            .presubscribe_bits = event_spine.categoryMaskFromTokens(o.presubscribe).bits,
        });
    }
    const oper_bindings = try bindings.toOwnedSlice(allocator);

    var config = mapToServerConfig(parsed, base);
    if (oper_bindings.len != 0) {
        config.oper_registry = try oper_mod.OperRegistry.init(oper_bindings);
    }
    // Build the connection-class registry from `[class.*]`. A malformed class is
    // skipped with a warning rather than aborting boot; the registry always ends
    // up with at least the built-in `user`/`server` fallbacks. The registry value
    // lives on `config` (a copy reaches the daemon, sharing the heap); `Loaded`
    // owns the allocation and frees it once in `deinit` — mirroring oper_registry.
    {
        var cb = conn_class.Builder.init(allocator);
        errdefer cb.deinit();
        for (parsed.classes) |c| {
            cb.add(.{
                .name = c.name,
                .policy = c.policy,
                .cidr_texts = c.match_texts,
                .tls_only = c.match_tls,
                .account_only = c.match_account,
                .oper_only = c.match_oper,
                .ident_glob = c.ident_glob,
                .host_glob = c.host_glob,
            }) catch |e| dlog.log("onyx-server: skipping connection class '{s}': {s}\n", .{ c.name, @errorName(e) });
        }
        config.class_registry = try cb.finish();
    }
    return .{
        .config = config,
        .parsed = parsed,
        .ocg2 = mapOcg2BootConfig(parsed),
        .oper_bindings = oper_bindings,
        .tls = mapTlsBootConfig(parsed),
        .acme = mapAcmeBootConfig(parsed),
        .sts = mapStsBootConfig(parsed),
        .io = mapIoBootConfig(parsed),
        .num_shards = parsed.limits.num_shards,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "config text overlays the server config" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 42
        \\[listen]
        \\host = "10.0.0.5"
        \\irc = 6700
        \\s2s = 7700
        \\webtransport = 4433
        \\proxy_protocol = true
        \\trusted_proxies = ["127.0.0.1"]
        \\[network]
        \\discoverable = true
        \\[limits]
        \\max_clients = 2048
        \\keylen = 24
        \\[mesh]
        \\realm = "ircxnet"
        \\mesh_pass = "shared-secret"
        \\trust_roots = ["0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"]
        \\admission_token = "aabbcc"
        \\admission_roots = ["1111111111111111111111111111111111111111111111111111111111111111"]
        \\admission_min_revocation_epoch = 9
        \\connect = ["ircx.us:6900"]
        \\[mesh.routing]
        \\max_nicks = 8192
        \\max_servers = 1024
        \\[mesh.link]
        \\send_credit_bytes = 131072
        \\gossip_interval_ms = 1500
        \\[mesh.gossip]
        \\round_fanout = 5
        \\[mesh.ripple]
        \\witness_quorum = 4
        \\[history.search]
        \\max_words = 4096
        \\max_ids_per_word = 128
        \\max_token_bytes = 32
        \\[ircv3]
        \\multiline_max_bytes = 8192
        \\multiline_max_lines = 8
        \\multiline_ref_len = 32
        \\multiline_target_len = 64
        \\[media]
        \\enabled = true
        \\max_upload_bytes = 12345
        \\max_frame_bytes = 1200
        \\reorder_window_frames = 32
        \\max_participants = 2
        \\captions_max_text_bytes = 512
        \\captions_max_speaker_bytes = 32
        \\captions_ring_depth_per_channel = 16
        \\captions_max_channels = 128
        \\native_media_require_mac = true
        \\[media.sfu]
        \\max_breakout_label_bytes = 16
        \\[media.pins]
        \\max_per_channel = 10
        \\max_msgid_bytes = 32
        \\[media.reactions]
        \\max_token_bytes = 24
        \\[io]
        \\cqe_batch = 512
        \\[bouncer]
        \\memo_text_max_len = 512
        \\memo_from_max_len = 48
        \\memo_mailbox_depth = 16
        \\memo_max_accounts = 4096
        \\[filter]
        \\koshi_max_patterns = 512
        \\koshi_pattern_max_len = 128
        \\[backup]
        \\dir = "/var/backups/onyx"
        \\interval = "6h"
        \\[sasl]
        \\enabled = false
        \\account_db = "/var/lib/onyx/accounts.db"
        \\realm = "ircxnet"
        \\[tls]
        \\enabled = true
        \\request_client_cert = true
        \\raw_public_key = true
        \\[[tls.ech_keys]]
        \\config_path = "/etc/onyx/echconfig.bin"
        \\private_key = "2222222222222222222222222222222222222222222222222222222222222222"
        \\
    ;
    const base = server.Config{ .port = 6680 };
    var loaded = try loadFromText(allocator, text, base, .{});
    defer loaded.deinit(allocator);

    try testing.expectEqual(@as(u16, 6700), loaded.config.port);
    try testing.expectEqualStrings("10.0.0.5", loaded.config.host);
    try testing.expectEqual(@as(u16, 7700), loaded.config.s2s_port);
    try testing.expectEqual(@as(u16, 4433), loaded.config.webtransport_port);
    try testing.expect(loaded.config.proxy_protocol_enabled);
    try testing.expectEqual(@as(usize, 1), loaded.config.trusted_proxies.len);
    try testing.expectEqualStrings("127.0.0.1", loaded.config.trusted_proxies[0]);
    try testing.expect(loaded.config.network_discoverable);
    try testing.expectEqual(@as(u64, 42), loaded.config.node_id);
    try testing.expectEqual(@as(u31, 2048), loaded.config.max_clients);
    try testing.expectEqual(@as(u32, 24), loaded.config.keylen);
    try testing.expectEqualStrings("ircxnet", loaded.config.mesh_realm);
    try testing.expectEqualStrings("shared-secret", loaded.config.mesh_pass);
    try testing.expectEqual(@as(usize, 1), loaded.config.mesh_trust_roots.len);
    try testing.expectEqualStrings("aabbcc", loaded.config.mesh_admission_token);
    try testing.expectEqual(@as(usize, 1), loaded.config.mesh_admission_roots.len);
    try testing.expectEqual(@as(u64, 9), loaded.config.mesh_admission_min_revocation_epoch);
    try testing.expect(loaded.config.relay_v2_authoring == .compat);
    try testing.expectEqual(@as(u64, 0), loaded.config.relay_v2_activation_epoch);
    try testing.expectEqual(@as(usize, 0), loaded.config.relay_v2_roster.len);
    try testing.expectEqual(@as(usize, 1), loaded.config.mesh_connect.len);
    try testing.expectEqualStrings("ircx.us:6900", loaded.config.mesh_connect[0]);
    try testing.expectEqual(@as(usize, 8192), loaded.config.s2s_config.routes.max_nicks);
    try testing.expectEqual(@as(usize, 1024), loaded.config.s2s_config.registry.max_nodes);
    try testing.expectEqual(@as(u32, 131072), loaded.config.s2s_config.link.peer_link_config.send_credit);
    try testing.expectEqual(@as(u64, 1500), loaded.config.s2s_config.link.gossip_interval_ms);
    try testing.expectEqual(@as(usize, 5), loaded.config.s2s_config.link.gossip_config.fanout);
    try testing.expectEqual(@as(u8, 4), loaded.config.s2s_config.link.ripple_config.witness_quorum);
    try testing.expect(loaded.config.media_enabled);
    try testing.expectEqual(@as(u64, 12345), loaded.config.media_max_upload_bytes);
    try testing.expectEqual(@as(u64, 1200), loaded.config.media_max_frame_bytes);
    try testing.expectEqual(@as(u32, 32), loaded.config.media_reorder_window_frames);
    try testing.expectEqual(@as(usize, 2), loaded.config.media_max_participants);
    try testing.expectEqual(@as(usize, 16), loaded.config.media_sfu_max_breakout_label_bytes);
    try testing.expectEqual(@as(usize, 512), loaded.config.transcript_config.max_text_bytes);
    try testing.expectEqual(@as(usize, 32), loaded.config.transcript_config.max_speaker_bytes);
    try testing.expectEqual(@as(usize, 16), loaded.config.transcript_config.max_per_channel);
    try testing.expectEqual(@as(usize, 128), loaded.config.transcript_config.max_channels);
    try testing.expectEqual(@as(usize, 10), loaded.config.media_pins_max_per_channel);
    try testing.expectEqual(@as(usize, 32), loaded.config.media_pins_max_msgid_bytes);
    try testing.expectEqual(@as(usize, 24), loaded.config.media_reactions_max_token_bytes);
    const reassembly_cfg = server.mediaReassemblyConfig(loaded.config);
    try testing.expectEqual(@as(u32, 32), reassembly_cfg.window);
    var rx = media_session.Receiver(media_session.default_max_payload_bytes, cadence_frame.window_cap).init(reassembly_cfg);
    _ = &rx;
    try testing.expect(loaded.config.native_media_require_mac);
    try testing.expectEqual(@as(u16, 512), loaded.config.cqe_batch);
    try testing.expect(!loaded.io.defer_taskrun);
    try testing.expect(!loaded.io.sqpoll);
    try testing.expect(!loaded.config.features.defer_taskrun);
    try testing.expect(!loaded.config.features.sqpoll);
    try testing.expectEqual(@as(usize, 512), loaded.config.memo_config.max_text_bytes);
    try testing.expectEqual(@as(usize, 48), loaded.config.memo_config.max_from_bytes);
    try testing.expectEqual(@as(usize, 16), loaded.config.memo_config.max_per_account);
    try testing.expectEqual(@as(usize, 4096), loaded.config.memo_config.max_accounts);
    try testing.expectEqual(@as(usize, 4096), loaded.config.search_index_config.max_words);
    try testing.expectEqual(@as(usize, 128), loaded.config.search_index_config.max_ids_per_word);
    try testing.expectEqual(@as(usize, 32), loaded.config.search_index_config.max_token_bytes);
    try testing.expectEqual(@as(usize, 8192), loaded.config.multiline_max_bytes);
    try testing.expectEqual(@as(usize, 8), loaded.config.multiline_max_lines);
    try testing.expectEqual(@as(usize, 32), loaded.config.multiline_ref_len);
    try testing.expectEqual(@as(usize, 64), loaded.config.multiline_target_len);
    try testing.expectEqual(@as(usize, 512), loaded.config.content_filter_config.max_patterns);
    try testing.expectEqual(@as(usize, 128), loaded.config.content_filter_config.max_pattern_len);
    try testing.expectEqualStrings("/var/backups/onyx", loaded.config.backup_dir);
    try testing.expectEqual(@as(i64, 6 * 60 * 60 * 1000), loaded.config.backup_interval_ms);
    try testing.expectEqualStrings("/var/lib/onyx/accounts.db", loaded.config.account_store_path);
    try testing.expect(!loaded.config.sasl_enabled);
    try testing.expectEqualStrings("ircxnet", loaded.config.sasl_realm);
    try testing.expect(loaded.tls.enabled);
    try testing.expect(loaded.tls.request_client_cert);
    try testing.expect(loaded.tls.raw_public_key);
    try testing.expectEqual(@as(usize, 1), loaded.tls.ech_keys.len);
    try testing.expectEqualStrings("/etc/onyx/echconfig.bin", loaded.tls.ech_keys[0].config_path);
    try testing.expectEqual(@as([32]u8, @splat(0x22)), loaded.tls.ech_keys[0].private_key);
}

test "io defer_taskrun and sqpoll project onto Loaded.io and Config.features without touching cqe_batch default" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[io]
        \\defer_taskrun = true
        \\sqpoll = true
        \\
    ;
    var loaded = try loadFromText(allocator, text, .{ .port = 6680 }, .{});
    defer loaded.deinit(allocator);
    try testing.expect(loaded.io.defer_taskrun);
    try testing.expect(loaded.io.sqpoll);
    try testing.expect(loaded.config.features.defer_taskrun);
    try testing.expect(loaded.config.features.sqpoll);
    try testing.expectEqual(@as(u16, 256), loaded.config.cqe_batch);
}

test "media listen overlays media port and candidate host" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\media = 7820
        \\media_host = "203.0.113.5"
        \\
    ;
    var loaded = try loadFromText(allocator, text, .{ .port = 6680 }, .{});
    defer loaded.deinit(allocator);
    try testing.expectEqual(@as(u16, 7820), loaded.config.media_port);
    try testing.expectEqualStrings("203.0.113.5", loaded.config.media_host);
}

test "webhook section overlays the server config and parses the bind address" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[webhook]
        \\enabled = true
        \\listen = 9140
        \\bind = "127.0.0.1"
        \\store_path = "webhooks.tsv"
        \\max_body_bytes = 4096
        \\rate_per_min = 30
        \\rate_burst = 5
        \\public_url_base = "https://irc.example.com"
        \\
    ;
    var loaded = try loadFromText(allocator, text, .{ .port = 6680 }, .{});
    defer loaded.deinit(allocator);
    try testing.expect(loaded.config.webhook_enabled);
    try testing.expectEqual(@as(u16, 9140), loaded.config.webhook_port);
    try testing.expectEqual(@as(u32, 0x7f00_0001), loaded.config.webhook_bind_addr);
    try testing.expectEqualStrings("webhooks.tsv", loaded.config.webhook_store_path);
    try testing.expectEqual(@as(u32, 4096), loaded.config.webhook_max_body);
    try testing.expectEqual(@as(u32, 30), loaded.config.webhook_rate_per_min);
    try testing.expectEqual(@as(u32, 5), loaded.config.webhook_rate_burst);
    try testing.expectEqualStrings("https://irc.example.com", loaded.config.webhook_public_base);
}

test "webhook omitted keeps the feature off (byte-identical default)" {
    const allocator = testing.allocator;
    var loaded = try loadFromText(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\
    , .{ .port = 6680 }, .{});
    defer loaded.deinit(allocator);
    try testing.expect(!loaded.config.webhook_enabled);
    try testing.expectEqual(@as(u16, 0), loaded.config.webhook_port);
}

test "media enabled maps to server gate and disabled feature" {
    const allocator = testing.allocator;

    var disabled = try loadFromText(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[media]
        \\enabled = false
        \\
    , .{ .port = 6680 }, .{});
    defer disabled.deinit(allocator);
    try testing.expect(!disabled.config.media_enabled);
    try testing.expectEqual(@as(usize, 1), disabled.config.disabled_features.len);
    try testing.expectEqualStrings("media", disabled.config.disabled_features[0]);

    var enabled = try loadFromText(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[media]
        \\enabled = true
        \\
    , .{ .port = 6680 }, .{});
    defer enabled.deinit(allocator);
    try testing.expect(enabled.config.media_enabled);
    try testing.expectEqual(@as(usize, 0), enabled.config.disabled_features.len);
}

test "media dtls_srtp maps to the server config gate" {
    const allocator = testing.allocator;

    var off = try loadFromText(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[media]
        \\enabled = true
        \\
    , .{ .port = 6680 }, .{});
    defer off.deinit(allocator);
    try testing.expect(!off.config.media_dtls_srtp);

    var on = try loadFromText(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[media]
        \\enabled = true
        \\dtls_srtp = true
        \\
    , .{ .port = 6680 }, .{});
    defer on.deinit(allocator);
    try testing.expect(on.config.media_dtls_srtp);
}

test "media dtls13 maps to the server config gate independently" {
    const allocator = testing.allocator;

    var off = try loadFromText(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[media]
        \\enabled = true
        \\dtls_srtp = true
        \\
    , .{ .port = 6680 }, .{});
    defer off.deinit(allocator);
    try testing.expect(off.config.media_dtls_srtp);
    try testing.expect(!off.config.media_dtls13);

    var on = try loadFromText(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[media]
        \\enabled = true
        \\dtls_srtp = true
        \\dtls13 = true
        \\
    , .{ .port = 6680 }, .{});
    defer on.deinit(allocator);
    try testing.expect(on.config.media_dtls13);
}

test "media stun server overlays discovery config" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[media]
        \\stun_host = "198.51.100.9"
        \\stun_port = 3478
        \\
    ;
    var loaded = try loadFromText(allocator, text, .{ .port = 6680 }, .{});
    defer loaded.deinit(allocator);
    try testing.expectEqualStrings("198.51.100.9", loaded.config.media_stun_host);
    try testing.expectEqual(@as(u16, 3478), loaded.config.media_stun_port);
}

test "limits durations overlay timeout knobs" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[limits]
        \\handshake_timeout = "15s"
        \\ping_interval = "90s"
        \\ping_timeout = "45s"
        \\
    ;
    var loaded = try loadFromText(allocator, text, .{ .port = 6680 }, .{});
    defer loaded.deinit(allocator);
    try testing.expectEqual(@as(i64, 15_000), loaded.config.registration_timeout_ms);
    try testing.expectEqual(@as(i64, 90_000), loaded.config.ping_interval_ms);
    try testing.expectEqual(@as(i64, 45_000), loaded.config.ping_timeout_ms);
}

test "limits overlay clone caps" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[limits]
        \\max_clones_per_ip = 4
        \\max_clones_per_net = 32
        \\
    ;
    var loaded = try loadFromText(allocator, text, .{ .port = 6680 }, .{});
    defer loaded.deinit(allocator);
    try testing.expectEqual(@as(u32, 4), loaded.config.max_clones_per_ip);
    try testing.expectEqual(@as(u32, 32), loaded.config.max_clones_per_net);
}

test "wasm plugin_dir maps into the live config" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[wasm]
        \\plugin_dir = "/var/lib/onyx/plugins"
        \\max_plugin_bytes = 4096
        \\max_memory_bytes = 131072
        \\default_fuel = 1234
        \\allowed_caps = ["reply", "log", "hooks", "net:outbound"]
        \\allowed_intents = ["message-content"]
        \\registry = [{ name = "guard", blake3 = "0000000000000000000000000000000000000000000000000000000000000000", tier = "verified", publisher = "1111111111111111111111111111111111111111111111111111111111111111", signature = "22222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222" }]
        \\revoked_blake3 = ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
        \\disabled_plugins = ["bridge-discord", "bad.wasm"]
        \\
    ;
    var loaded = try loadFromText(allocator, text, .{ .port = 6680 }, .{});
    defer loaded.deinit(allocator);
    try testing.expectEqualStrings("/var/lib/onyx/plugins", loaded.config.wasm_plugin_dir);
    try testing.expectEqual(@as(usize, 4096), loaded.config.wasm_max_plugin_bytes);
    try testing.expectEqual(@as(usize, 131072), loaded.config.wasm_max_memory_bytes);
    try testing.expectEqual(@as(u64, 1234), loaded.config.wasm_default_fuel);
    try testing.expect(loaded.config.wasm_allowed_caps.has(.reply));
    try testing.expect(loaded.config.wasm_allowed_caps.has(.log));
    try testing.expect(loaded.config.wasm_allowed_caps.has(.hooks));
    try testing.expect(loaded.config.wasm_allowed_caps.has(.net_outbound));
    try testing.expect(!loaded.config.wasm_allowed_caps.has(.time));
    try testing.expect(loaded.config.wasm_allowed_intents.has(.message_content));
    try testing.expectEqual(@as(usize, 1), loaded.config.wasm_registry.len);
    try testing.expectEqualStrings("guard", loaded.config.wasm_registry[0].name);
    try testing.expectEqual(wasm_bridge.TrustTier.verified, loaded.config.wasm_registry[0].tier);
    try testing.expect(loaded.config.wasm_registry[0].publisher != null);
    try testing.expect(loaded.config.wasm_registry[0].signature != null);
    try testing.expectEqual(@as(usize, 1), loaded.config.wasm_revoked_hashes.len);
    try testing.expectEqual(@as(u8, 0xaa), loaded.config.wasm_revoked_hashes[0][0]);
    try testing.expectEqual(@as(usize, 2), loaded.config.wasm_disabled_plugins.len);
    try testing.expectEqualStrings("bridge-discord", loaded.config.wasm_disabled_plugins[0]);
    try testing.expectEqualStrings("bad.wasm", loaded.config.wasm_disabled_plugins[1]);
}

test "limits overlay reputation knobs" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[limits]
        \\reputation_refuse_threshold = 120
        \\reputation_half_life = "90s"
        \\
    ;
    var loaded = try loadFromText(allocator, text, .{ .port = 6680 }, .{});
    defer loaded.deinit(allocator);
    try testing.expectEqual(@as(u32, 120), loaded.config.reputation_refuse_threshold);
    try testing.expectEqual(@as(i64, 90_000), loaded.config.reputation_half_life_ms);
}

test "num_shards lifts onto the boot config and defaults to 1" {
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
    var loaded = try loadFromText(allocator, text, .{ .port = 6680 }, .{});
    defer loaded.deinit(allocator);
    try testing.expectEqual(@as(u16, 4), loaded.num_shards);

    // Omitted -> single reactor.
    var dflt = try loadFromText(allocator, "[node]\nid=1\n[listen]\nirc=6680\n", .{ .port = 6680 }, .{});
    defer dflt.deinit(allocator);
    try testing.expectEqual(@as(u16, 1), dflt.num_shards);
}

test "acme section lifts onto the boot config" {
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
        \\renew_before_days = 15
        \\check_interval = "2h"
        \\ca_bundle_path = "/etc/onyx/acme-ca.pem"
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
    var loaded = try loadFromText(allocator, text, .{ .port = 6680 }, .{});
    defer loaded.deinit(allocator);

    try testing.expect(loaded.acme.enabled);
    try testing.expectEqualStrings("https://acme.example/directory", loaded.acme.directory_url);
    try testing.expectEqualStrings("irc.example.test", loaded.acme.domain.?);
    try testing.expectEqualStrings("mailto:admin@example.test", loaded.acme.contact.?);
    try testing.expectEqual(@as(u16, 15), loaded.acme.renew_before_days);
    try testing.expectEqual(@as(u64, 2 * 60 * 60 * 1000), loaded.acme.check_interval_ms);
    try testing.expectEqualStrings("/etc/onyx/acme-ca.pem", loaded.acme.ca_bundle_path);
    try testing.expectEqual(@as(u64, 1048576), loaded.acme.ca_bundle_max_bytes);
    try testing.expectEqual(@as(u16, 14403), loaded.acme.challenge_port);
    try testing.expectEqual(@as(u32, 96), loaded.acme.max_steps);
    try testing.expect(loaded.acme.debug);
    try testing.expectEqual(@as(u64, 131072), loaded.acme.max_response_bytes);
    try testing.expectEqual(@as(u64, 256), loaded.acme.error_body_preview_bytes);
    try testing.expectEqual(@as(u64, 32768), loaded.acme.resolv_conf_max_bytes);
    try testing.expectEqual(@as(u16, 5353), loaded.acme.dns_port);
    try testing.expectEqual(@as(u32, 32), loaded.acme.http01_listen_backlog);
    try testing.expectEqual(@as(u32, 500), loaded.acme.http01_accept_poll_ms);
    try testing.expectEqual(@as(u32, 10), loaded.acme.http01_conn_read_timeout_sec);
}

test "oper groups project configured privileges and titles" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[[oper_groups]]
        \\name = "observer"
        \\privileges = ["audit_read"]
        \\[[oper_groups]]
        \\name = "admin"
        \\inherits = "observer"
        \\privileges = ["server_rehash"]
        \\[[opers]]
        \\account = "alice"
        \\class = "admin"
        \\title = "Network Guardian"
        \\
    ;
    var loaded = try loadFromText(allocator, text, .{ .port = 6680 }, .{});
    defer loaded.deinit(allocator);

    const registry = loaded.config.oper_registry.?;
    const grant = try registry.elevateAuthenticated(.{ .name = "alice" });
    try testing.expect(grant.privileges.has(.server_rehash));
    try testing.expect(grant.privileges.has(.audit_read));
    try testing.expect(!grant.privileges.has(.server_admin));
    try testing.expectEqualStrings("Network Guardian", grant.title);
}

test "oper certfp seeds the bind store at boot (string + array, normalized, malformed skipped)" {
    const allocator = testing.allocator;
    // alice: a single lowercase fingerprint. bob: an array with one UPPERCASE
    // fingerprint (must normalize to lowercase) plus one malformed entry (skipped).
    const fp_alice = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const fp_bob_upper = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789";
    const fp_bob_lower = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[[oper_groups]]
        \\name = "admin"
        \\privileges = ["server_rehash"]
        \\[[opers]]
        \\account = "alice"
        \\class = "admin"
        \\certfp = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        \\[[opers]]
        \\account = "bob"
        \\class = "admin"
        \\certfp = ["ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789", "not-a-valid-fingerprint"]
        \\
    ;
    var loaded = try loadFromText(allocator, text, .{ .port = 6680 }, .{});
    defer loaded.deinit(allocator);

    // The parser owns both certfp forms verbatim.
    try testing.expectEqual(@as(usize, 1), loaded.parsed.opers[0].certfp.len);
    try testing.expectEqualStrings(fp_alice, loaded.parsed.opers[0].certfp[0]);
    try testing.expectEqual(@as(usize, 2), loaded.parsed.opers[1].certfp.len);

    var binds = certfp_bind.CertfpBindStore.init(allocator);
    defer binds.deinit();
    // A pre-existing runtime CERTADD binding must survive the config seed.
    const fp_runtime = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    try binds.bind("carol", fp_runtime);

    const seeded = seedOperCertfpBinds(&binds, loaded.parsed.opers);
    try testing.expectEqual(@as(usize, 2), seeded); // alice's 1 + bob's 1 valid (malformed skipped)

    // A subsequent SASL EXTERNAL with either bound fingerprint resolves the account.
    try testing.expectEqualStrings("alice", binds.accountForFingerprint(fp_alice).?);
    try testing.expectEqualStrings("bob", binds.accountForFingerprint(fp_bob_lower).?); // uppercase normalized
    _ = fp_bob_upper;
    // The malformed entry never bound anything.
    try testing.expect(binds.accountForFingerprint("not-a-valid-fingerprint") == null);
    // Runtime binding untouched (config seed coexists, never wipes).
    try testing.expectEqualStrings("carol", binds.accountForFingerprint(fp_runtime).?);

    // Re-applying the same seed each boot is idempotent (no double count issue at
    // the store level: same account replaces the same key).
    const reseeded = seedOperCertfpBinds(&binds, loaded.parsed.opers);
    try testing.expectEqual(@as(usize, 2), reseeded);
    try testing.expectEqualStrings("alice", binds.accountForFingerprint(fp_alice).?);
    try testing.expectEqualStrings("carol", binds.accountForFingerprint(fp_runtime).?);
}

test "minimal config: unspecified optional fields keep defaults" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 9
        \\[listen]
        \\irc = 6680
        \\
    ;
    const base = server.Config{ .port = 6680 };
    var loaded = try loadFromText(allocator, text, base, .{});
    defer loaded.deinit(allocator);
    try testing.expectEqual(@as(u16, 6680), loaded.config.port);
    try testing.expectEqual(@as(u64, 9), loaded.config.node_id);
    try testing.expectEqual(@as(u16, 0), loaded.config.s2s_port); // unspecified -> default
}

test "[sessions] registry and composite issuance project onto boot config" {
    const allocator = testing.allocator;
    const base = server.Config{ .port = 6680 };

    // Omitted section: the built-in defaults reach the server config the
    // SessionStore is constructed from (server.zig initWithConfig).
    var defaults = try loadFromText(allocator, "[node]\nid = 1\n[listen]\nirc = 6680\n", base, .{});
    defer defaults.deinit(allocator);
    try testing.expectEqual(@as(u64, 65536), defaults.config.session_max_accounts);
    try testing.expectEqual(@as(u32, 64), defaults.config.session_max_per_account);
    try testing.expect(!defaults.config.session_resume_composite_issuance);
    try testing.expect(defaults.config.session_migrate_on_detach);
    try testing.expectEqual(@as(u32, 4096), defaults.config.session_max_pending_migrations);

    // Explicit override projects through loadFromText -> mapToServerConfig.
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[sessions]
        \\max_accounts = 2048
        \\max_per_account = 9
        \\resume_composite_issuance = true
        \\migrate_on_detach = false
        \\max_pending_migrations = 128
        \\
    ;
    var loaded = try loadFromText(allocator, text, base, .{});
    defer loaded.deinit(allocator);
    try testing.expectEqual(@as(u64, 2048), loaded.config.session_max_accounts);
    try testing.expectEqual(@as(u32, 9), loaded.config.session_max_per_account);
    try testing.expect(loaded.config.session_resume_composite_issuance);
    try testing.expect(!loaded.config.session_migrate_on_detach);
    try testing.expectEqual(@as(u32, 128), loaded.config.session_max_pending_migrations);

    var explicitly_off = try loadFromText(
        allocator,
        "[node]\nid = 1\n[listen]\nirc = 6680\n[sessions]\nresume_composite_issuance = false\n",
        base,
        .{},
    );
    defer explicitly_off.deinit(allocator);
    try testing.expect(!explicitly_off.config.session_resume_composite_issuance);
}

test "tls section projects onto the boot tls config" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[tls]
        \\enabled = true
        \\port = 7001
        \\cert_path = "leaf.pem"
        \\key_path = "leaf.key"
        \\dns_name = "irc.example.test"
        \\
    ;
    var loaded = try loadFromText(allocator, text, .{ .port = 6680 }, .{});
    defer loaded.deinit(allocator);
    try testing.expect(loaded.tls.enabled);
    try testing.expectEqual(@as(u16, 7001), loaded.tls.port);
    try testing.expectEqualStrings("leaf.pem", loaded.tls.cert_path.?);
    try testing.expectEqualStrings("leaf.key", loaded.tls.key_path.?);
    try testing.expectEqualStrings("irc.example.test", loaded.tls.dns_name);
}

test "tls sni entries surface on the boot tls projection" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[tls]
        \\enabled = true
        \\cert_path = "default.pem"
        \\key_path = "default.key"
        \\[[tls.sni]]
        \\server_names = ["irc.example.test"]
        \\cert_path = "example.pem"
        \\key_path = "example.key"
        \\
    ;
    var loaded = try loadFromText(allocator, text, .{ .port = 6680 }, .{});
    defer loaded.deinit(allocator);
    try testing.expect(loaded.tls.enabled);
    try testing.expectEqual(@as(usize, 1), loaded.tls.sni.len);
    try testing.expectEqualStrings("irc.example.test", loaded.tls.sni[0].server_names[0]);
    try testing.expectEqualStrings("example.pem", loaded.tls.sni[0].cert_path);
    try testing.expectEqualStrings("example.key", loaded.tls.sni[0].key_path);
}

test "tls omitted keeps sni empty on the boot projection" {
    const allocator = testing.allocator;
    var loaded = try loadFromText(allocator, "[node]\nid = 1\n[listen]\nirc = 6680\n", .{ .port = 6680 }, .{});
    defer loaded.deinit(allocator);
    try testing.expectEqual(@as(usize, 0), loaded.tls.sni.len);
}

test "tls omitted keeps boot defaults" {
    const allocator = testing.allocator;
    const text = "[node]\nid = 1\n[listen]\nirc = 6680\n";
    var loaded = try loadFromText(allocator, text, .{ .port = 6680 }, .{});
    defer loaded.deinit(allocator);
    try testing.expect(!loaded.tls.enabled);
    try testing.expectEqual(@as(u16, 6697), loaded.tls.port);
    try testing.expectEqual(@as(?[]const u8, null), loaded.tls.cert_path);
    try testing.expectEqualStrings("localhost", loaded.tls.dns_name);
}

test "sts boot projection maps the parsed [sts] section" {
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
    var loaded = try loadFromText(allocator, text, .{ .port = 6680 }, .{});
    defer loaded.deinit(allocator);
    try testing.expect(loaded.sts.enabled);
    try testing.expectEqual(@as(u32, 604800), loaded.sts.duration);
    try testing.expectEqual(@as(u16, 7000), loaded.sts.port);
    try testing.expect(loaded.sts.preload);
}

test "sts boot projection defaults when [sts] omitted" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 9
        \\[listen]
        \\irc = 6680
        \\
    ;
    var loaded = try loadFromText(allocator, text, .{ .port = 6680 }, .{});
    defer loaded.deinit(allocator);
    // STS disabled by default; secure defaults still surface to main.zig.
    try testing.expect(!loaded.sts.enabled);
    try testing.expectEqual(@as(u32, 2_592_000), loaded.sts.duration);
    try testing.expectEqual(@as(u16, 6697), loaded.sts.port);
    try testing.expect(!loaded.sts.preload);
}

test "missing required [node].id is rejected" {
    const allocator = testing.allocator;
    const text = "[listen]\nirc = 6680\n";
    try testing.expectError(error.ParseError, loadFromText(allocator, text, .{ .port = 6680 }, .{}));
}

fn testOcg2BootConfig(seed: u8, mode: Ocg2RuntimeMode) !Ocg2BootConfig {
    var identity = try node_identity.fromSeed(@as([32]u8, @splat(seed)), "ocg2-test");
    defer identity.deinit();
    return .{ .enabled = true, .mode = mode, .authority = .{
        .authority_node_id = identity.shortId(),
        .authority_pubkey = identity.sign_kp.public_key,
    } };
}

test "OCG2 config boot mapping exposes disabled observe project and mint modes" {
    const disabled = mapOcg2BootConfig(.{});
    try testing.expect(!disabled.enabled);
    try testing.expectEqual(Ocg2RuntimeMode.disabled, disabled.mode);
    try testing.expect(disabled.authority == null);

    var identity = try node_identity.fromSeed(@as([32]u8, @splat(0xC0)), "ocg2-test");
    defer identity.deinit();
    const root = config_format.Config.OperOcg2{
        .enabled = true,
        .authority_node_id = identity.shortId(),
        .authority_public_key = identity.sign_kp.public_key,
    };

    var cfg = config_format.Config{ .oper_ocg2 = root };
    const observe = mapOcg2BootConfig(cfg);
    try testing.expect(observe.enabled);
    try testing.expectEqual(Ocg2RuntimeMode.observe, observe.mode);
    try testing.expectEqual(identity.shortId(), observe.authority.?.authority_node_id);
    try testing.expectEqualSlices(u8, &identity.sign_kp.public_key, &observe.authority.?.authority_pubkey);

    cfg.oper_ocg2.projection_enabled = true;
    const project = mapOcg2BootConfig(cfg);
    try testing.expect(project.enabled);
    try testing.expectEqual(Ocg2RuntimeMode.project, project.mode);

    cfg.oper_ocg2.minting_enabled = true;
    const mint = mapOcg2BootConfig(cfg);
    try testing.expect(mint.enabled);
    try testing.expectEqual(Ocg2RuntimeMode.mint, mint.mode);
}

test "OCG2 runtime support predicate admits only disabled and observe" {
    try testing.expect(ocg2RuntimeModeSupported(.disabled));
    try testing.expect(ocg2RuntimeModeSupported(.observe));
    try testing.expect(!ocg2RuntimeModeSupported(.project));
    try testing.expect(!ocg2RuntimeModeSupported(.mint));
}

test "OCG2 boot identity classification keeps receivers public-only and exact authority full-key bound" {
    const config = try testOcg2BootConfig(0xC1, .observe);
    var authority_identity = try node_identity.fromSeed(@as([32]u8, @splat(0xC1)), "ocg2-test");
    defer authority_identity.deinit();
    try testing.expectEqual(Ocg2LocalRole.authority, try validateOcg2LocalIdentity(config, &authority_identity));

    var receiver_identity = try node_identity.fromSeed(@as([32]u8, @splat(0xC2)), "ocg2-test");
    defer receiver_identity.deinit();
    try testing.expectEqual(Ocg2LocalRole.receiver, try validateOcg2LocalIdentity(config, &receiver_identity));
    try testing.expectError(error.MissingNodeIdentity, validateOcg2LocalIdentity(config, null));

    authority_identity.sign_kp.public_key[0] ^= 1;
    try testing.expectError(
        error.Ocg2AuthorityPublicKeyMismatch,
        validateOcg2LocalIdentity(config, &authority_identity),
    );
}

test "OCG2 config boot permits projection on both roles and restricts minting to authority" {
    const project = try testOcg2BootConfig(0xC5, .project);
    const mint = try testOcg2BootConfig(0xC5, .mint);
    var authority_identity = try node_identity.fromSeed(@as([32]u8, @splat(0xC5)), "ocg2-test");
    defer authority_identity.deinit();
    var receiver_identity = try node_identity.fromSeed(@as([32]u8, @splat(0xC6)), "ocg2-test");
    defer receiver_identity.deinit();

    try testing.expectEqual(Ocg2LocalRole.authority, try validateOcg2LocalIdentity(project, &authority_identity));
    try testing.expectEqual(Ocg2LocalRole.receiver, try validateOcg2LocalIdentity(project, &receiver_identity));
    try testing.expectEqual(Ocg2LocalRole.authority, try validateOcg2LocalIdentity(mint, &authority_identity));
    try testing.expectError(
        error.Ocg2MintingRequiresAuthority,
        validateOcg2LocalIdentity(mint, &receiver_identity),
    );
}

test "OCG2 store activation cold restores and rejects key change and partial state" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const config = try testOcg2BootConfig(0xC3, .observe);
    const wrong = try testOcg2BootConfig(0xC4, .observe);
    var store = try store_mod.OroStore.openWithConfig(
        testing.allocator,
        testing.io,
        tmp.dir,
        "config-boot-ocg2.wal",
        .{},
    );
    defer store.deinit();
    var cold = try activateOcg2Store(testing.allocator, &store, config);
    defer cold.state.deinit();
    try testing.expectEqual(Ocg2ActivationSource.initialized, cold.source);
    try testing.expect(store.get(.props, durable_oper_authority.marker_key) != null);
    try testing.expect(store.get(.props, durable_oper_authority.snapshot_key) != null);

    var restored = try activateOcg2Store(testing.allocator, &store, config);
    defer restored.state.deinit();
    try testing.expectEqual(Ocg2ActivationSource.restored, restored.source);
    try testing.expectError(error.InvalidAuthority, activateOcg2Store(testing.allocator, &store, wrong));

    try store.delete(.props, durable_oper_authority.snapshot_key);
    try testing.expectError(error.PartialInitialization, activateOcg2Store(testing.allocator, &store, config));
}

test "[class.*] parses into the connection-class registry with v4/v6 + TLS match" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[class.user]
        \\sendq = "2M"
        \\max_per_ip = 4
        \\[class.server]
        \\sendq = "16M"
        \\[class.trusted]
        \\sendq = "8M"
        \\flood_exempt = true
        \\match = ["10.0.0.0/8", "::1"]
        \\match_tls = true
        \\
    ;
    var loaded = try loadFromText(allocator, text, .{ .port = 6680 }, .{});
    defer loaded.deinit(allocator);
    const reg = &loaded.config.class_registry.?;
    // Built-in overrides honored; custom class present.
    try testing.expectEqual(@as(u64, 2 << 20), reg.byName("user").?.policy.sendq);
    try testing.expectEqual(@as(u32, 4), reg.byName("user").?.policy.max_per_ip);
    try testing.expectEqual(@as(u64, 16 << 20), reg.byName("server").?.policy.sendq);
    try testing.expect(reg.byName("trusted").?.policy.flood_exempt);
    // Matching: 10.x over TLS -> trusted; without TLS -> user; v6 ::1 TLS -> trusted.
    try testing.expectEqualStrings("trusted", reg.classFor(.{ .ip_text = "10.1.2.3", .is_tls = true }).name);
    try testing.expectEqualStrings("user", reg.classFor(.{ .ip_text = "10.1.2.3", .is_tls = false }).name);
    try testing.expectEqualStrings("trusted", reg.classFor(.{ .ip_text = "::1", .is_tls = true }).name);
    try testing.expectEqualStrings("server", reg.classFor(.{ .is_server_link = true }).name);
}
