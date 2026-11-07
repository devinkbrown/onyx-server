// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! `[[tls.ech_keys]]` material loader, shared by boot (`main.zig`) and the
//! transactional TLS reload on REHASH and ACME renewal (`server.zig`).
//!
//! Each entry names a file holding a single-entry ECHConfigList plus the
//! matching X25519 HPKE recipient key. Besides the per-key material the TLS
//! engine needs, the loader builds one merged ECHConfigList of every configured
//! config: the server sends it as draft-ietf-tls-esni §7.1 `retry_configs` to a
//! client whose ECH it could not decrypt, so a client holding a stale config
//! recovers on its next connection.
//!
//! Ownership: `Loaded` owns the config bytes, the key array and the retry list.
//! `deinit` secure-zeroes every private key before freeing. On any error the
//! partial material is released and wiped before the error returns.
const std = @import("std");

const config_format = @import("config_format.zig");
const tls_server = @import("../crypto/tls_server.zig");

const EchKeyDef = config_format.Config.EchKeyDef;

/// Largest ECHConfigList file accepted per entry.
pub const max_config_file_bytes: usize = 64 * 1024;

pub const Error = error{
    /// A config file is not a length-prefixed ECHConfigList whose prefix covers
    /// exactly the rest of the file, or the merged list would not fit the
    /// 2-byte ECHConfigList length.
    BadEchConfigList,
};

pub const Loaded = struct {
    configs: [][]u8 = &.{},
    keys: []tls_server.EchKey = &.{},
    /// Merged ECHConfigList of every key's config, in configuration order.
    /// Empty when no keys are configured.
    retry_config_list: []u8 = &.{},

    pub fn deinit(self: *Loaded, allocator: std.mem.Allocator) void {
        for (self.keys) |*key| std.crypto.secureZero(u8, &key.private_key);
        allocator.free(self.keys);
        for (self.configs) |bytes| allocator.free(bytes);
        allocator.free(self.configs);
        allocator.free(self.retry_config_list);
        self.* = .{};
    }
};

/// Read every configured ECHConfigList file and build the engine key list and
/// the merged `retry_configs` list. Key/config agreement is checked later by
/// `tls_server.Server.init`; this only checks the list framing.
pub fn load(allocator: std.mem.Allocator, io: std.Io, defs: []const EchKeyDef) !Loaded {
    var configs: std.ArrayList([]u8) = .empty;
    errdefer {
        for (configs.items) |bytes| allocator.free(bytes);
        configs.deinit(allocator);
    }
    var keys: std.ArrayList(tls_server.EchKey) = .empty;
    errdefer {
        for (keys.items) |*key| std.crypto.secureZero(u8, &key.private_key);
        keys.deinit(allocator);
    }
    try configs.ensureTotalCapacity(allocator, defs.len);
    try keys.ensureTotalCapacity(allocator, defs.len);
    for (defs) |def| {
        const config = try std.Io.Dir.cwd().readFileAlloc(io, def.config_path, allocator, .limited(max_config_file_bytes));
        configs.appendAssumeCapacity(config);
        keys.appendAssumeCapacity(.{ .config = config, .private_key = def.private_key });
    }
    return fromParts(allocator, &configs, &keys);
}

/// Finish a load from already-read parts. On success both lists are moved into
/// the result; on failure whatever is still in the lists stays the caller's.
fn fromParts(
    allocator: std.mem.Allocator,
    configs: *std.ArrayList([]u8),
    keys: *std.ArrayList(tls_server.EchKey),
) !Loaded {
    const retry = try buildRetryConfigList(allocator, keys.items);
    errdefer allocator.free(retry);
    const key_slice = try keys.toOwnedSlice(allocator);
    errdefer {
        for (key_slice) |*key| std.crypto.secureZero(u8, &key.private_key);
        allocator.free(key_slice);
    }
    const config_slice = try configs.toOwnedSlice(allocator);
    return .{ .configs = config_slice, .keys = key_slice, .retry_config_list = retry };
}

/// Concatenate the ECHConfig entries of each single-list `key.config` under one
/// ECHConfigList length prefix. Returns an empty (owned, zero-length) slice
/// when `keys` is empty.
pub fn buildRetryConfigList(allocator: std.mem.Allocator, keys: []const tls_server.EchKey) (Error || std.mem.Allocator.Error)![]u8 {
    if (keys.len == 0) return allocator.alloc(u8, 0);
    var body_len: usize = 0;
    for (keys) |key| {
        if (key.config.len < 2) return error.BadEchConfigList;
        const inner_len = std.mem.readInt(u16, key.config[0..2], .big);
        if (inner_len == 0 or @as(usize, inner_len) + 2 != key.config.len) return error.BadEchConfigList;
        body_len += inner_len;
        if (body_len > std.math.maxInt(u16)) return error.BadEchConfigList;
    }
    const out = try allocator.alloc(u8, body_len + 2);
    std.mem.writeInt(u16, out[0..2], @intCast(body_len), .big);
    var at: usize = 2;
    for (keys) |key| {
        const inner = key.config[2..];
        @memcpy(out[at..][0..inner.len], inner);
        at += inner.len;
    }
    std.debug.assert(at == out.len);
    return out;
}

const testing = std.testing;

test "buildRetryConfigList merges single-entry lists in order under one prefix" {
    const a = [_]u8{ 0x00, 0x03, 0xaa, 0xbb, 0xcc };
    const b = [_]u8{ 0x00, 0x02, 0x11, 0x22 };
    const keys = [_]tls_server.EchKey{
        .{ .config = &a, .private_key = @splat(1) },
        .{ .config = &b, .private_key = @splat(2) },
    };
    const merged = try buildRetryConfigList(testing.allocator, &keys);
    defer testing.allocator.free(merged);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x05, 0xaa, 0xbb, 0xcc, 0x11, 0x22 }, merged);

    const single = try buildRetryConfigList(testing.allocator, keys[0..1]);
    defer testing.allocator.free(single);
    try testing.expectEqualSlices(u8, &a, single);

    const none = try buildRetryConfigList(testing.allocator, &.{});
    defer testing.allocator.free(none);
    try testing.expectEqual(@as(usize, 0), none.len);
}

test "buildRetryConfigList refuses misframed lists" {
    const short = [_]u8{0x00};
    const over = [_]u8{ 0x00, 0x04, 0xaa };
    const under = [_]u8{ 0x00, 0x01, 0xaa, 0xbb };
    const empty_body = [_]u8{ 0x00, 0x00 };
    for ([_][]const u8{ &short, &over, &under, &empty_body }) |config| {
        const keys = [_]tls_server.EchKey{.{ .config = config, .private_key = @splat(0) }};
        try testing.expectError(error.BadEchConfigList, buildRetryConfigList(testing.allocator, &keys));
    }
}

test "buildRetryConfigList refuses a merged list beyond the 2-byte length" {
    const big = try testing.allocator.alloc(u8, 40_002);
    defer testing.allocator.free(big);
    @memset(big, 0x5a);
    std.mem.writeInt(u16, big[0..2], 40_000, .big);
    const keys = [_]tls_server.EchKey{
        .{ .config = big, .private_key = @splat(0) },
        .{ .config = big, .private_key = @splat(0) },
    };
    try testing.expectError(error.BadEchConfigList, buildRetryConfigList(testing.allocator, &keys));
}

test "load releases every partial allocation on failure" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const good = [_]u8{ 0x00, 0x02, 0x01, 0x02 };
    const bad = [_]u8{ 0x00, 0x09, 0x01 };
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "good.bin", .data = &good });
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "bad.bin", .data = &bad });
    const good_path = try std.fmt.allocPrint(testing.allocator, ".zig-cache/tmp/{s}/good.bin", .{tmp.sub_path});
    defer testing.allocator.free(good_path);
    const bad_path = try std.fmt.allocPrint(testing.allocator, ".zig-cache/tmp/{s}/bad.bin", .{tmp.sub_path});
    defer testing.allocator.free(bad_path);

    var loaded = try load(testing.allocator, testing.io, &.{
        .{ .config_path = good_path, .private_key = @splat(7) },
        .{ .config_path = good_path, .private_key = @splat(8) },
    });
    defer loaded.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 2), loaded.keys.len);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x04, 0x01, 0x02, 0x01, 0x02 }, loaded.retry_config_list);

    try testing.expectError(error.BadEchConfigList, load(testing.allocator, testing.io, &.{
        .{ .config_path = good_path, .private_key = @splat(7) },
        .{ .config_path = bad_path, .private_key = @splat(8) },
    }));
    try testing.expectError(error.FileNotFound, load(testing.allocator, testing.io, &.{
        .{ .config_path = good_path, .private_key = @splat(7) },
        .{ .config_path = "does/not/exist.bin", .private_key = @splat(8) },
    }));
    try testing.checkAllAllocationFailures(testing.allocator, loadForAllocTest, .{good_path});
}

fn loadForAllocTest(allocator: std.mem.Allocator, path: []const u8) !void {
    var loaded = try load(allocator, testing.io, &.{
        .{ .config_path = path, .private_key = @splat(7) },
        .{ .config_path = path, .private_key = @splat(8) },
    });
    loaded.deinit(allocator);
}
