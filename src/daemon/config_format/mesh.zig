// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Typed mesh projection and MESSAGE_V2 activation validation.

const std = @import("std");
const toml = @import("../../proto/toml.zig");
const s2s_peer_mod = @import("../../substrate/undertow/s2s_peer.zig");
const relay_v2_activation = @import("../relay_v2_activation.zig");
const relay_v2_event_log = @import("../relay_v2_event_log.zig");
const node_identity = @import("../node_identity.zig");
const node_short_id = @import("../../crypto/node_short_id.zig");
const Config = @import("model.zig").Config;
const TomlError = @import("contracts.zig").TomlError;
const uintField = @import("values.zig").uintField;

pub fn parseRelayV2Authoring(s: []const u8) ?relay_v2_activation.Mode {
    if (std.mem.eql(u8, s, "compat")) return .compat;
    if (std.mem.eql(u8, s, "active")) return .active;
    return null;
}

/// Non-mutating deployment validation for every MESSAGE_V2 activation input.
/// An explicit seed or public identity makes the local roster identity knowable
/// to `--check-config`. Runtime init then binds a configured public identity to
/// the private identity loaded from the persisted keyfile.
pub fn validateRelayV2ActivationConfig(allocator: std.mem.Allocator, cfg: Config) TomlError!void {
    if (cfg.mesh.relay_v2_activation_epoch == 0) return;
    if (!cfg.mesh.require_secured or !cfg.mesh.require_signed_frames or
        cfg.mesh.trust_roots.len == 0 or
        cfg.mesh.trust_roots.len + 1 > relay_v2_event_log.default_max_confirmed_nodes_per_row or
        cfg.mesh.relay_v2_roster.len < 2 or cfg.mesh.relay_v2_roster.len > 4096)
        return error.ParseError;

    var derived_local: ?node_identity.NodeIdentity = null;
    defer if (derived_local) |*local| local.deinit();
    const local_key: [32]u8 = if (cfg.node.secret_key) |configured_seed| blk: {
        derived_local = node_identity.fromConfig(configured_seed, cfg.mesh.realm) catch
            return error.ParseError;
        const derived_key = derived_local.?.sign_kp.public_key;
        if (cfg.node.public_key) |encoded| {
            const expected = relay_v2_activation.decodePublicKey(encoded) catch return error.ParseError;
            if (!std.crypto.timing_safe.eql([32]u8, expected, derived_key))
                return error.ParseError;
        }
        break :blk derived_key;
    } else relay_v2_activation.decodePublicKey(cfg.node.public_key orelse return error.ParseError) catch
        return error.ParseError;

    var roster = relay_v2_activation.canonicalizeRoster(allocator, cfg.mesh.relay_v2_roster) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.ParseError,
    };
    defer roster.deinit();
    if (!roster.contains(local_key)) return error.ParseError;
    relay_v2_activation.validate(.{
        .mode = cfg.mesh.relay_v2_authoring,
        .activation_epoch = cfg.mesh.relay_v2_activation_epoch,
        .roster_digest = roster.digest,
    }) catch return error.ParseError;

    const direct_nodes = try allocator.alloc(u64, cfg.mesh.trust_roots.len + 1);
    defer allocator.free(direct_nodes);
    direct_nodes[0] = node_short_id.shortId(node_identity.nodeIdFromPublicKey(local_key));
    for (cfg.mesh.trust_roots, direct_nodes[1..]) |encoded, *short_id| {
        const key = relay_v2_activation.decodePublicKey(encoded) catch return error.ParseError;
        if (!roster.contains(key)) return error.ParseError;
        short_id.* = node_short_id.shortId(node_identity.nodeIdFromPublicKey(key));
    }
    std.mem.sort(u64, direct_nodes, {}, std.sort.asc(u64));
    for (direct_nodes[1..], direct_nodes[0 .. direct_nodes.len - 1]) |node, prior| {
        if (node == prior) return error.ParseError;
    }
}

pub fn parseMeshS2sConfig(doc: toml.Document, cfg: *s2s_peer_mod.Config) TomlError!void {
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

    // Ripple (witnessed failure detection): [mesh.ripple] only.
    cfg.link.ripple_config.suspicion_timeout_ms = @intCast(try uintField(doc, "mesh.ripple.suspicion_timeout_ms", @as(u64, @intCast(cfg.link.ripple_config.suspicion_timeout_ms)), 0, 120_000));
    // Floor of 2: a single accuser must never bury a peer (see gossip_round.zig
    // RippleConfig.sanitized). Reject a configured quorum of 0/1 at parse time.
    cfg.link.ripple_config.witness_quorum = @intCast(try uintField(doc, "mesh.ripple.witness_quorum", cfg.link.ripple_config.witness_quorum, 2, 16));

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
