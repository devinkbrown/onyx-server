// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Configuration regression tests: core.

const std = @import("std");
const testing = std.testing;
const parseToml = @import("projection.zig").parseToml;

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

test "GAP-O3 trace file is the operator path" {
    const allocator = testing.allocator;
    var cfg = try parseToml(allocator, "[node]\nid=1\n[listen]\nirc=6680\n[trace]\nfile = \"/var/lib/onyx/flight.log\"\n", .{});
    defer cfg.deinit(allocator);
    try testing.expectEqualStrings("/var/lib/onyx/flight.log", cfg.trace.file.?);

    var absent = try parseToml(allocator, "[node]\nid=1\n[listen]\nirc=6680\n", .{});
    defer absent.deinit(allocator);
    try testing.expect(absent.trace.file == null);
}

test "parseToml: backup section projects directory and cadence" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[backup]
        \\dir = "/var/backups/onyx"
        \\interval = "12h"
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expectEqualStrings("/var/backups/onyx", cfg.backup.dir);
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

test "parseToml: network name defaults to Onyx and parses an override" {
    const allocator = testing.allocator;

    // No [network] name -> the built-in public network-name default (Onyx),
    // which feeds ISUPPORT NETWORK= and the 001 RPL_WELCOME burst via
    // config_boot -> setNetworkName at boot.
    var dflt = try parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\
    , .{});
    defer dflt.deinit(allocator);
    try testing.expectEqualStrings("Onyx", dflt.network.name);

    // An explicit [network] name overrides the default verbatim.
    var named = try parseToml(allocator,
        \\[node]
        \\id = 1
        \\[network]
        \\name = "Acme"
        \\[listen]
        \\irc = 6680
        \\
    , .{});
    defer named.deinit(allocator);
    try testing.expectEqualStrings("Acme", named.network.name);
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
    try testing.expect(!cfg.io.defer_taskrun);
    try testing.expect(!cfg.io.sqpoll);
    try testing.expectEqual(@as(f64, 80.0), cfg.reputation.registration_timeout_penalty);
    try testing.expectEqual(@as(f64, 10.0), cfg.reputation.clone_refuse_penalty);
    // out-of-range ring_entries rejected
    try testing.expectError(error.ParseError, parseToml(allocator, "[node]\nid=1\n[listen]\nirc=1\n[io]\nring_entries=4\n", .{}));
    try testing.expectError(error.ParseError, parseToml(allocator, "[node]\nid=1\n[listen]\nirc=1\n[io]\ncqe_batch=8\n", .{}));
    var flagged = try parseToml(allocator, "[node]\nid=1\n[listen]\nirc=1\n[io]\ndefer_taskrun=true\nsqpoll=true\n", .{});
    defer flagged.deinit(allocator);
    try testing.expect(flagged.io.defer_taskrun);
    try testing.expect(flagged.io.sqpoll);
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

test "persistent logging configuration owns its path and rejects malformed settings" {
    const base = "[node]\nid=1\n[listen]\nirc=6680\n";
    var cfg = try parseToml(testing.allocator, base ++ "[logging]\nstderr_file=\"/var/log/onyx-server.log\"\n", .{});
    defer cfg.deinit(testing.allocator);
    try testing.expectEqualStrings("/var/log/onyx-server.log", cfg.logging.stderr_file.?);
    var absent = try parseToml(testing.allocator, base, .{});
    defer absent.deinit(testing.allocator);
    try testing.expect(absent.logging.stderr_file == null);
    try testing.expectError(error.ParseError, parseToml(testing.allocator, base ++ "[logging]\nstderr_file=42\n", .{}));
    try testing.expectError(error.ParseError, parseToml(testing.allocator, base ++ "[logging]\nstderr_file=\"\"\n", .{}));
}

test "persistent logging configuration releases ownership at every allocation failure" {
    const Sweep = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var cfg = try parseToml(allocator, "[node]\nid=1\n[listen]\nirc=6680\n[logging]\nstderr_file=\"/var/log/onyx-server.log\"\n", .{});
            defer cfg.deinit(allocator);
            try testing.expectEqualStrings("/var/log/onyx-server.log", cfg.logging.stderr_file.?);
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Sweep.run, .{});
}
