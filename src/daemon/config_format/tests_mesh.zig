// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Configuration regression tests: mesh.

const std = @import("std");
const s2s_peer_mod = @import("../../substrate/undertow/s2s_peer.zig");
const relay_v2_activation = @import("../relay_v2_activation.zig");
const node_identity = @import("../node_identity.zig");
const testing = std.testing;
const Config = @import("model.zig").Config;
const parseToml = @import("projection.zig").parseToml;

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

test "parseToml: MESSAGE_V2 activation plan is explicit complete and type-strict" {
    const allocator = testing.allocator;
    const local_seed: [32]u8 = @splat(0x11);
    const local_seed_hex = std.fmt.bytesToHex(local_seed, .lower);
    var local = try node_identity.fromSeed(local_seed, "activation-test");
    defer local.deinit();
    var peer = try node_identity.fromSeed(@as([32]u8, @splat(0x22)), "activation-test");
    defer peer.deinit();
    var third = try node_identity.fromSeed(@as([32]u8, @splat(0x33)), "activation-test");
    defer third.deinit();
    const local_key = std.fmt.bytesToHex(local.sign_kp.public_key, .lower);
    const peer_key = std.fmt.bytesToHex(peer.sign_kp.public_key, .lower);
    const third_key = std.fmt.bytesToHex(third.sign_kp.public_key, .lower);
    const base =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\
    ;

    {
        var cfg = try parseToml(allocator, base, .{});
        defer cfg.deinit(allocator);
        try testing.expectEqual(relay_v2_activation.Mode.compat, cfg.mesh.relay_v2_authoring);
        try testing.expectEqual(@as(u64, 0), cfg.mesh.relay_v2_activation_epoch);
        try testing.expectEqual(@as(usize, 0), cfg.mesh.relay_v2_roster.len);
    }

    inline for (.{ relay_v2_activation.Mode.compat, .active }) |mode| {
        const mode_text = if (mode == .compat) "compat" else "active";
        const text = try std.fmt.allocPrint(
            allocator,
            "[node]\nid = 1\nsecret_key = \"{s}\"\n[listen]\nirc = 6680\n[mesh]\nrealm = \"activation-test\"\nrequire_secured = true\nrequire_signed_frames = true\ntrust_roots = [\"{s}\"]\nrelay_v2_authoring = \"{s}\"\nrelay_v2_activation_epoch = 7\nrelay_v2_roster = [\"{s}\", \"{s}\"]\n",
            .{ &local_seed_hex, &peer_key, mode_text, &local_key, &peer_key },
        );
        defer allocator.free(text);
        var cfg = try parseToml(allocator, text, .{});
        defer cfg.deinit(allocator);
        try testing.expectEqual(mode, cfg.mesh.relay_v2_authoring);
        try testing.expectEqual(@as(u64, 7), cfg.mesh.relay_v2_activation_epoch);
        try testing.expectEqual(@as(usize, 2), cfg.mesh.relay_v2_roster.len);
    }

    // Persisted-keyfile deployments preflight with the matching public key;
    // runtime init binds it to the private identity loaded by main.
    {
        const text = try std.fmt.allocPrint(
            allocator,
            "[node]\nid = 1\npublic_key = \"{s}\"\n[listen]\nirc = 6680\n[mesh]\nrealm = \"activation-test\"\nrequire_secured = true\nrequire_signed_frames = true\ntrust_roots = [\"{s}\"]\nrelay_v2_activation_epoch = 7\nrelay_v2_roster = [\"{s}\", \"{s}\"]\n",
            .{ &local_key, &peer_key, &local_key, &peer_key },
        );
        defer allocator.free(text);
        var cfg = try parseToml(allocator, text, .{});
        defer cfg.deinit(allocator);
        try testing.expectEqualStrings(&local_key, cfg.node.public_key.?);
    }
    {
        const text = try std.fmt.allocPrint(
            allocator,
            "[node]\nid = 1\npublic_key = \"{s}\"\nsecret_key = \"{s}\"\n[listen]\nirc = 6680\n[mesh]\nrealm = \"activation-test\"\nrequire_secured = true\nrequire_signed_frames = true\ntrust_roots = [\"{s}\"]\nrelay_v2_activation_epoch = 7\nrelay_v2_roster = [\"{s}\", \"{s}\"]\n",
            .{ &peer_key, &local_seed_hex, &peer_key, &local_key, &peer_key },
        );
        defer allocator.free(text);
        try testing.expectError(error.ParseError, parseToml(allocator, text, .{}));
    }

    // A preflight must reject an unsecured activation plan.
    {
        const text = try std.fmt.allocPrint(
            allocator,
            "[node]\nid = 1\nsecret_key = \"{s}\"\n[listen]\nirc = 6680\n[mesh]\nrealm = \"activation-test\"\nrequire_secured = false\nrequire_signed_frames = true\ntrust_roots = [\"{s}\"]\nrelay_v2_activation_epoch = 7\nrelay_v2_roster = [\"{s}\", \"{s}\"]\n",
            .{ &local_seed_hex, &peer_key, &local_key, &peer_key },
        );
        defer allocator.free(text);
        try testing.expectError(error.ParseError, parseToml(allocator, text, .{}));
    }
    // Direct roots are mandatory and bind every configured neighbor.
    {
        const text = try std.fmt.allocPrint(
            allocator,
            "[node]\nid = 1\nsecret_key = \"{s}\"\n[listen]\nirc = 6680\n[mesh]\nrealm = \"activation-test\"\nrequire_secured = true\nrequire_signed_frames = true\nrelay_v2_activation_epoch = 7\nrelay_v2_roster = [\"{s}\", \"{s}\"]\n",
            .{ &local_seed_hex, &local_key, &peer_key },
        );
        defer allocator.free(text);
        try testing.expectError(error.ParseError, parseToml(allocator, text, .{}));
    }
    {
        const text = try std.fmt.allocPrint(
            allocator,
            "[node]\nid = 1\n[listen]\nirc = 6680\n[mesh]\nrealm = \"activation-test\"\nrequire_secured = true\nrequire_signed_frames = true\ntrust_roots = [\"{s}\"]\nrelay_v2_activation_epoch = 7\nrelay_v2_roster = [\"{s}\", \"{s}\"]\n",
            .{ &peer_key, &local_key, &peer_key },
        );
        defer allocator.free(text);
        try testing.expectError(error.ParseError, parseToml(allocator, text, .{}));
    }
    const duplicate_roster = try std.fmt.allocPrint(allocator, "[\"{s}\", \"{s}\"]", .{ &local_key, &local_key });
    defer allocator.free(duplicate_roster);
    const missing_local_roster = try std.fmt.allocPrint(allocator, "[\"{s}\", \"{s}\"]", .{ &peer_key, &third_key });
    defer allocator.free(missing_local_roster);
    for ([_][]const u8{ "[\"aa\", \"bb\"]", duplicate_roster, missing_local_roster }) |roster_text| {
        const text = try std.fmt.allocPrint(
            allocator,
            "[node]\nid = 1\nsecret_key = \"{s}\"\n[listen]\nirc = 6680\n[mesh]\nrealm = \"activation-test\"\nrequire_secured = true\nrequire_signed_frames = true\ntrust_roots = [\"{s}\"]\nrelay_v2_activation_epoch = 7\nrelay_v2_roster = {s}\n",
            .{ &local_seed_hex, &peer_key, roster_text },
        );
        defer allocator.free(text);
        try testing.expectError(error.ParseError, parseToml(allocator, text, .{}));
    }

    const invalid_mesh = [_][]const u8{
        "relay_v2_authoring = 1\n",
        "relay_v2_authoring = \"ACTIVE\"\n",
        "relay_v2_activation_epoch = \"7\"\n",
        "relay_v2_activation_epoch = -1\nrelay_v2_roster = [\"aa\"]\n",
        "relay_v2_activation_epoch = 7\n",
        "relay_v2_roster = [\"aa\"]\n",
        "relay_v2_roster = \"aa\"\n",
        "relay_v2_activation_epoch = 7\nrelay_v2_roster = [1]\n",
        "relay_v2_authoring = \"active\"\n",
    };
    for (invalid_mesh) |mesh| {
        const text = try std.fmt.allocPrint(allocator, "{s}[mesh]\n{s}", .{ base, mesh });
        defer allocator.free(text);
        try testing.expectError(error.ParseError, parseToml(allocator, text, .{}));
    }
}

test "parseToml: MESSAGE_V2 activation plan survives every allocation failure" {
    const AllocationSweep = struct {
        fn run(allocator: std.mem.Allocator) !void {
            const local_seed: [32]u8 = @splat(0x61);
            const local_seed_hex = std.fmt.bytesToHex(local_seed, .lower);
            var local = try node_identity.fromSeed(local_seed, "activation-oom");
            defer local.deinit();
            var peer = try node_identity.fromSeed(@as([32]u8, @splat(0x62)), "activation-oom");
            defer peer.deinit();
            const local_key = std.fmt.bytesToHex(local.sign_kp.public_key, .lower);
            const peer_key = std.fmt.bytesToHex(peer.sign_kp.public_key, .lower);
            const text = try std.fmt.allocPrint(
                allocator,
                "[node]\nid = 1\nsecret_key = \"{s}\"\n[listen]\nirc = 6680\n[mesh]\nrealm = \"activation-oom\"\nrequire_secured = true\nrequire_signed_frames = true\ntrust_roots = [\"{s}\"]\nrelay_v2_activation_epoch = 7\nrelay_v2_roster = [\"{s}\", \"{s}\"]\n",
                .{ &local_seed_hex, &peer_key, &peer_key, &local_key },
            );
            defer allocator.free(text);
            var cfg = try parseToml(allocator, text, .{});
            defer cfg.deinit(allocator);
            try testing.expectEqual(@as(u64, 7), cfg.mesh.relay_v2_activation_epoch);
            try testing.expectEqual(@as(usize, 2), cfg.mesh.relay_v2_roster.len);
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, AllocationSweep.run, .{});
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
        \\[mesh.ripple]
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
    try testing.expectEqual(@as(i64, 9000), cfg.mesh.s2s.link.ripple_config.suspicion_timeout_ms);
    try testing.expectEqual(@as(u8, 4), cfg.mesh.s2s.link.ripple_config.witness_quorum);
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

test "parseToml: mesh.ripple only (no Japanese sazanami alias)" {
    const allocator = testing.allocator;
    {
        const text =
            \\[node]
            \\id = 1
            \\[listen]
            \\irc = 6680
            \\[mesh.ripple]
            \\suspicion_timeout_ms = 7000
            \\witness_quorum = 3
            \\
        ;
        var cfg = try parseToml(allocator, text, .{});
        defer cfg.deinit(allocator);
        try testing.expectEqual(@as(u32, 7000), cfg.mesh.s2s.link.ripple_config.suspicion_timeout_ms);
        try testing.expectEqual(@as(u8, 3), cfg.mesh.s2s.link.ripple_config.witness_quorum);
    }
    {
        // Japanese legacy section name must not apply any settings.
        const text =
            \\[node]
            \\id = 1
            \\[listen]
            \\irc = 6680
            \\[mesh.sazanami]
            \\suspicion_timeout_ms = 9999
            \\witness_quorum = 9
            \\
        ;
        var cfg = try parseToml(allocator, text, .{});
        defer cfg.deinit(allocator);
        const dflt = s2s_peer_mod.Config{};
        try testing.expectEqual(dflt.link.ripple_config.suspicion_timeout_ms, cfg.mesh.s2s.link.ripple_config.suspicion_timeout_ms);
        try testing.expectEqual(dflt.link.ripple_config.witness_quorum, cfg.mesh.s2s.link.ripple_config.witness_quorum);
    }
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
