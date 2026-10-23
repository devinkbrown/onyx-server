// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Ordered TOML projection transaction. Keep validation and ownership order stable.

const std = @import("std");
const toml = @import("../../proto/toml.zig");
const conn_class = @import("../conn_class.zig");
const durable_oper_authority = @import("../durable_oper_authority.zig");
const shard = @import("../shard.zig");
const sasl_mechrouter = @import("../../proto/sasl_mechrouter.zig");
const cadence_frame = @import("../../substrate/cadence_frame.zig");
const media_room = @import("../media_room.zig");
const node_identity = @import("../node_identity.zig");
const node_short_id = @import("../../crypto/node_short_id.zig");
const Config = @import("model.zig").Config;
const Resolver = @import("contracts.zig").Resolver;
const TomlError = @import("contracts.zig").TomlError;
const classDur = @import("values.zig").classDur;
const classSize = @import("values.zig").classSize;
const classU32 = @import("values.zig").classU32;
const durationMs = @import("values.zig").durationMs;
const floatField = @import("values.zig").floatField;
const freeStringList = @import("values.zig").freeStringList;
const freeWasmRegistry = @import("wasm_values.zig").freeWasmRegistry;
const ownStringArray = @import("values.zig").ownStringArray;
const ownStringOrArray = @import("values.zig").ownStringOrArray;
const parseHexArrayList = @import("wasm_values.zig").parseHexArrayList;
const parseKtlsMode = @import("tls_mode.zig").parseKtlsMode;
const parseMeshS2sConfig = @import("mesh.zig").parseMeshS2sConfig;
const parseOcg2NodeId = @import("authority.zig").parseOcg2NodeId;
const parseOcg2PublicKey = @import("authority.zig").parseOcg2PublicKey;
const parseRelayV2Authoring = @import("mesh.zig").parseRelayV2Authoring;
const parseWasmCaps = @import("wasm_values.zig").parseWasmCaps;
const parseWasmIntents = @import("wasm_values.zig").parseWasmIntents;
const parseWasmRegistry = @import("wasm_values.zig").parseWasmRegistry;
const portField = @import("values.zig").portField;
const resolveStr = @import("values.zig").resolveStr;
const setOpt = @import("values.zig").setOpt;
const setStr = @import("values.zig").setStr;
const uintField = @import("values.zig").uintField;
const validateRelayV2ActivationConfig = @import("mesh.zig").validateRelayV2ActivationConfig;

/// Parse standard TOML and project it onto a defaulted `Config`.
pub fn parseToml(allocator: std.mem.Allocator, source: []const u8, resolver: Resolver) TomlError!Config {
    var doc = toml.parse(allocator, source) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.ParseError,
    };
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

    // [oper.ocg2] — exact public authority tuple. There is intentionally no
    // private-key field; receivers must never be provisioned with authority
    // signing material through a shared daemon config. A quoted, exactly
    // 16-digit hexadecimal node id is accepted because TOML integers are signed
    // i64 while Ed25519-derived node ids occupy the full u64 domain.
    if (doc.get("oper.ocg2")) |ocg2_value| {
        if (ocg2_value.* != .table) return error.ParseError;
        var fields = ocg2_value.table.iterator();
        while (fields.next()) |entry| {
            const key = entry.key_ptr.*;
            if (!std.mem.eql(u8, key, "enabled") and
                !std.mem.eql(u8, key, "projection_enabled") and
                !std.mem.eql(u8, key, "minting_enabled") and
                !std.mem.eql(u8, key, "authority_node_id") and
                !std.mem.eql(u8, key, "authority_public_key"))
                return error.UnknownOcg2Field;
        }
    }
    if (doc.get("oper.ocg2.enabled")) |value| {
        if (value.* != .boolean) return error.ParseError;
        cfg.oper_ocg2.enabled = value.boolean;
    }
    if (doc.get("oper.ocg2.projection_enabled")) |value| {
        if (value.* != .boolean) return error.ParseError;
        cfg.oper_ocg2.projection_enabled = value.boolean;
    }
    if (doc.get("oper.ocg2.minting_enabled")) |value| {
        if (value.* != .boolean) return error.ParseError;
        cfg.oper_ocg2.minting_enabled = value.boolean;
    }
    if (doc.get("oper.ocg2.authority_node_id")) |value| {
        cfg.oper_ocg2.authority_node_id = switch (value.*) {
            .integer => |number| if (number > 0) @intCast(number) else return error.MissingOcg2AuthorityNodeId,
            .string => |text| parseOcg2NodeId(text) orelse return error.MissingOcg2AuthorityNodeId,
            else => return error.ParseError,
        };
    }
    if (doc.get("oper.ocg2.authority_public_key")) |value| {
        if (value.* != .string) return error.ParseError;
        cfg.oper_ocg2.authority_public_key = try parseOcg2PublicKey(allocator, resolver, value.string);
    }

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
    try setOpt(allocator, resolver, doc.getString("trace.file"), &cfg.trace.file);
    if (doc.get("logging")) |value| {
        if (value.* != .table) return error.ParseError;
    }
    if (doc.get("logging.stderr_file")) |value| {
        if (value.* != .string) return error.ParseError;
        try setOpt(allocator, resolver, value.string, &cfg.logging.stderr_file);
        const log_path = cfg.logging.stderr_file.?;
        if (log_path.len == 0 or log_path.len >= 4096 or std.mem.indexOfScalar(u8, log_path, 0) != null)
            return error.ParseError;
    }
    if (doc.getBool("oper.auto_override")) |b| cfg.oper.auto_override = b;
    if (doc.getBool("oper.two_person_rule")) |b| cfg.oper.two_person_rule = b;
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
    if (doc.get("mesh.relay_v2_authoring")) |value| {
        cfg.mesh.relay_v2_authoring = switch (value.*) {
            .string => |raw| parseRelayV2Authoring(raw) orelse return error.ParseError,
            else => return error.ParseError,
        };
    }
    if (doc.get("mesh.relay_v2_activation_epoch")) |value| {
        cfg.mesh.relay_v2_activation_epoch = switch (value.*) {
            .integer => |raw| if (raw >= 0) @intCast(raw) else return error.ParseError,
            else => return error.ParseError,
        };
    }
    if (doc.get("mesh.relay_v2_roster")) |value| {
        const items = switch (value.*) {
            .array => |items| items,
            else => return error.ParseError,
        };
        freeStringList(allocator, cfg.mesh.relay_v2_roster);
        cfg.mesh.relay_v2_roster = try ownStringArray(allocator, resolver, items);
    }
    const relay_v2_plan_empty = cfg.mesh.relay_v2_activation_epoch == 0 and
        cfg.mesh.relay_v2_roster.len == 0;
    const relay_v2_plan_complete = cfg.mesh.relay_v2_activation_epoch != 0 and
        cfg.mesh.relay_v2_roster.len != 0;
    if (!relay_v2_plan_empty and !relay_v2_plan_complete) return error.ParseError;
    if (cfg.mesh.relay_v2_authoring == .active and !relay_v2_plan_complete)
        return error.ParseError;
    if (doc.getArray("mesh.connect")) |arr| {
        freeStringList(allocator, cfg.mesh.connect);
        cfg.mesh.connect = try ownStringArray(allocator, resolver, arr);
    }
    if (doc.getBool("mesh.require_secured")) |b| cfg.mesh.require_secured = b;
    if (doc.getBool("mesh.require_signed_frames")) |b| cfg.mesh.require_signed_frames = b;
    try validateRelayV2ActivationConfig(allocator, cfg);
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
    try setOpt(allocator, resolver, doc.getString("mail.trust_store_path"), &cfg.mail.trust_store_path);
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
    if (doc.getBool("io.defer_taskrun")) |b| cfg.io.defer_taskrun = b;
    if (doc.getBool("io.sqpoll")) |b| cfg.io.sqpoll = b;

    // [reputation]
    cfg.reputation.registration_timeout_penalty = try floatField(doc, "reputation.registration_timeout_penalty", cfg.reputation.registration_timeout_penalty, 0, 1000);
    cfg.reputation.clone_refuse_penalty = try floatField(doc, "reputation.clone_refuse_penalty", cfg.reputation.clone_refuse_penalty, 0, 1000);

    // [accounts]
    cfg.accounts.pbkdf2_rounds = @intCast(try uintField(doc, "accounts.pbkdf2_rounds", cfg.accounts.pbkdf2_rounds, 10_000, 10_000_000));
    cfg.accounts.password_min_len = try uintField(doc, "accounts.password_min_len", cfg.accounts.password_min_len, 1, 64);
    cfg.accounts.password_max_len = try uintField(doc, "accounts.password_max_len", cfg.accounts.password_max_len, 64, 4096);
    if (cfg.accounts.password_min_len > cfg.accounts.password_max_len) return error.ParseError;

    // [bouncer]
    cfg.bouncer.memo_text_max_len = try uintField(doc, "bouncer.memo_text_max_len", cfg.bouncer.memo_text_max_len, 64, 2048);
    cfg.bouncer.memo_from_max_len = try uintField(doc, "bouncer.memo_from_max_len", cfg.bouncer.memo_from_max_len, 16, 128);
    cfg.bouncer.memo_mailbox_depth = try uintField(doc, "bouncer.memo_mailbox_depth", cfg.bouncer.memo_mailbox_depth, 8, 1024);
    cfg.bouncer.memo_max_accounts = try uintField(doc, "bouncer.memo_max_accounts", cfg.bouncer.memo_max_accounts, 1024, 1048576);

    // [filter]
    cfg.filter.koshi_max_patterns = try uintField(doc, "filter.koshi_max_patterns", cfg.filter.koshi_max_patterns, 16, 4096);
    cfg.filter.koshi_pattern_max_len = try uintField(doc, "filter.koshi_pattern_max_len", cfg.filter.koshi_pattern_max_len, 16, 1024);

    // [storage]
    cfg.storage.max_record_bytes = @intCast(try uintField(doc, "storage.max_record_bytes", cfg.storage.max_record_bytes, 65536, 268435456));
    cfg.storage.max_wal_bytes = @intCast(try uintField(doc, "storage.max_wal_bytes", cfg.storage.max_wal_bytes, 1048576, 4294967296));
    cfg.storage.changefeed_capacity = @intCast(try uintField(doc, "storage.changefeed_capacity", cfg.storage.changefeed_capacity, 8, 4096));

    // [sessions]
    cfg.sessions.max_accounts = try uintField(doc, "sessions.max_accounts", cfg.sessions.max_accounts, 1, std.math.maxInt(u32));
    // Session registry capsules encode the per-account count as u16. Keep the
    // runtime cap inside that durable/hot-upgrade representation.
    cfg.sessions.max_per_account = @intCast(try uintField(doc, "sessions.max_per_account", cfg.sessions.max_per_account, 1, std.math.maxInt(u16)));
    if (doc.getBool("sessions.resume_composite_issuance")) |b|
        cfg.sessions.resume_composite_issuance = b;
    if (doc.getBool("sessions.migrate_on_detach")) |b| cfg.sessions.migrate_on_detach = b;
    cfg.sessions.max_pending_migrations = @intCast(try uintField(doc, "sessions.max_pending_migrations", cfg.sessions.max_pending_migrations, 16, 1_000_000));

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
    // A recorder that bypasses the in-call consent bit cannot be configured.
    if (doc.getBool("media.hidden_recorder") != null or
        doc.getString("media.hidden_recorder") != null or
        doc.getBool("media.record_without_consent") != null or
        doc.getString("media.record_without_consent") != null)
        return error.HiddenRecorderRefused;
    if (doc.getBool("media.enabled")) |b| cfg.media.enabled = b;
    cfg.media.max_upload_bytes = try uintField(doc, "media.max_upload_bytes", cfg.media.max_upload_bytes, 0, 1024 * 1024 * 1024);
    cfg.media.max_frame_bytes = try uintField(doc, "media.max_frame_bytes", cfg.media.max_frame_bytes, 0, 16 * 1024 * 1024);
    cfg.media.reorder_window_frames = @intCast(try uintField(doc, "media.reorder_window_frames", cfg.media.reorder_window_frames, 1, cadence_frame.window_cap));
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
    if (doc.getArray("stats.ignore_nicks")) |arr| {
        freeStringList(allocator, cfg.stats.ignore_nicks);
        cfg.stats.ignore_nicks = try ownStringArray(allocator, resolver, arr);
    }

    try setStr(allocator, resolver, doc.getString("backup.dir"), &cfg.backup.dir);
    if (doc.getString("backup.interval")) |s| cfg.backup.interval_ms = @intCast(try durationMs(s));

    // [metrics] — live Prometheus /metrics endpoint. `listen` = 0/absent off;
    // `bind` defaults to loopback (security: not public by default).
    cfg.metrics.listen = try portField(doc, "metrics.listen", cfg.metrics.listen);
    try setStr(allocator, resolver, doc.getString("metrics.bind"), &cfg.metrics.bind);

    if (doc.getBool("e2ee.group_authoring_enabled")) |b|
        cfg.e2ee.group_authoring_enabled = b;

    // [webhook] — Discord-compatible incoming webhook endpoint. OFF by default.
    if (doc.getBool("webhook.enabled")) |b| cfg.webhook.enabled = b;
    cfg.webhook.listen = try portField(doc, "webhook.listen", cfg.webhook.listen);
    try setOpt(allocator, resolver, doc.getString("webhook.bind"), &cfg.webhook.bind);
    try setOpt(allocator, resolver, doc.getString("webhook.store_path"), &cfg.webhook.store_path);
    cfg.webhook.max_body_bytes = @intCast(try uintField(doc, "webhook.max_body_bytes", cfg.webhook.max_body_bytes, 1, 1 << 20));
    cfg.webhook.rate_per_min = @intCast(try uintField(doc, "webhook.rate_per_min", cfg.webhook.rate_per_min, 0, 1_000_000));
    cfg.webhook.rate_burst = @intCast(try uintField(doc, "webhook.rate_burst", cfg.webhook.rate_burst, 1, 1_000_000));
    try setOpt(allocator, resolver, doc.getString("webhook.public_url_base"), &cfg.webhook.public_url_base);
    if (doc.getBool("webhook.allow_private_targets")) |b| cfg.webhook.allow_private_targets = b;

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
    if (doc.getBool("sasl.oauth_auto_provision")) |b| cfg.sasl.oauth_auto_provision = b;
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

    if (cfg.oper_ocg2.minting_enabled and !cfg.oper_ocg2.enabled)
        return error.Ocg2MintingRequiresEnabled;
    if (cfg.oper_ocg2.minting_enabled and !cfg.oper_ocg2.projection_enabled)
        return error.Ocg2MintingRequiresProjection;
    if (cfg.oper_ocg2.projection_enabled and !cfg.oper_ocg2.enabled)
        return error.Ocg2ProjectionRequiresEnabled;

    if (cfg.oper_ocg2.enabled) {
        if (cfg.oper_ocg2.authority_node_id == 0) return error.MissingOcg2AuthorityNodeId;
        const public_key = cfg.oper_ocg2.authority_public_key orelse return error.MissingOcg2AuthorityPublicKey;
        _ = std.crypto.sign.Ed25519.PublicKey.fromBytes(public_key) catch
            return error.InvalidOcg2AuthorityPublicKey;
        if (node_short_id.shortId(node_identity.nodeIdFromPublicKey(public_key)) !=
            cfg.oper_ocg2.authority_node_id)
            return error.Ocg2AuthorityNodeIdMismatch;
        const sasl_enabled = cfg.sasl.enabled or !cfg.sasl.enabled_explicit;
        if (!sasl_enabled or cfg.sasl.account_db == null) return error.Ocg2RequiresAccountStore;
        if (cfg.storage.max_record_bytes < durable_oper_authority.max_store_payload_bytes)
            return error.Ocg2StorageRecordLimitTooSmall;
        if (cfg.storage.max_wal_bytes < durable_oper_authority.max_store_wal_record_bytes)
            return error.Ocg2StorageWalLimitTooSmall;
    } else if (cfg.oper_ocg2.authority_node_id != 0 or cfg.oper_ocg2.authority_public_key != null) {
        return error.ParseError;
    }

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
