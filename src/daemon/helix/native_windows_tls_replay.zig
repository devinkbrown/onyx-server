// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact shared TLS 1.2 resumption / TLS 1.3 early-data replay custody for
//! Windows Helix. A detached candidate is validated before READY and installed
//! into the stable guard address without allocation at COMMIT.

const std = @import("std");
const frame = @import("native_windows_companion_wire.zig");
const tls_resumption = @import("../../crypto/tls_resumption.zig");

const ReplayGuard = tls_resumption.ReplayGuard;
pub const checkpoint_magic = [_]u8{ 'H', 'X', 'R', 'G' };
const domain = "onyx-windows-tls-replay-guard-v1";
const payload_header_len: usize = 4;
pub const max_checkpoint_bytes: usize = frame.header_len + payload_header_len +
    ReplayGuard.capacity * (1 + tls_resumption.max_binder_len) + frame.checksum_len;
pub const Error = error{InvalidSnapshot} || std.mem.Allocator.Error;

/// Allocated candidate ring. `install` leaves the guard's address stable for
/// existing TLS.Config.replay_guard pointers, then wipes the detached copy.
pub const Owned = struct {
    allocator: std.mem.Allocator,
    snapshot: ?*ReplayGuard.Snapshot,

    pub fn deinit(self: *Owned) void {
        if (self.snapshot) |snapshot| {
            std.crypto.secureZero(u8, std.mem.asBytes(snapshot));
            self.allocator.destroy(snapshot);
            self.snapshot = null;
        }
    }

    pub fn install(self: *Owned, guard: *ReplayGuard) void {
        guard.installSnapshot(self.snapshot.?);
        self.deinit();
    }
};

pub fn isCheckpoint(bytes: []const u8) bool {
    return frame.isCheckpoint(bytes, checkpoint_magic);
}

/// Validate the entire variable-length frame before any allocation. Each
/// canonical record has one length byte followed by a 16-byte TLS 1.2 ticket
/// tag or a 32/48-byte TLS 1.3 binder, oldest first.
pub fn validateCheckpoint(bytes: []const u8) error{InvalidSnapshot}!void {
    if (bytes.len < frame.header_len + payload_header_len + frame.checksum_len or
        bytes.len > max_checkpoint_bytes) return error.InvalidSnapshot;
    const payload_len = bytes.len - frame.header_len - frame.checksum_len;
    const payload = try frame.validateFrame(bytes, checkpoint_magic, domain, payload_len);
    const count = std.mem.readInt(u16, payload[0..2], .little);
    if (count > ReplayGuard.capacity or !std.mem.eql(u8, payload[2..4], &.{ 0, 0 }))
        return error.InvalidSnapshot;
    var pos: usize = payload_header_len;
    var starts: [ReplayGuard.capacity]usize = undefined;
    for (0..count) |i| {
        if (pos == payload.len) return error.InvalidSnapshot;
        const start = pos;
        const len = payload[pos];
        pos += 1;
        if ((len != 16 and len != 32 and len != 48) or payload.len - pos < len)
            return error.InvalidSnapshot;
        // A live ReplayGuard rejects repeats; an authenticated but impossible
        // duplicate ring must not become candidate state.
        for (starts[0..i]) |previous| {
            if (payload[previous] == len and
                std.mem.eql(u8, payload[previous + 1 ..][0..len], payload[pos..][0..len]))
                return error.InvalidSnapshot;
        }
        starts[i] = start;
        pos += len;
    }
    if (pos != payload.len) return error.InvalidSnapshot;
}

pub fn encodeSnapshot(allocator: std.mem.Allocator, guard: *ReplayGuard) Error![]u8 {
    const snapshot = try guard.captureSnapshot(allocator);
    defer {
        std.crypto.secureZero(u8, std.mem.asBytes(snapshot));
        allocator.destroy(snapshot);
    }
    var payload_len: usize = payload_header_len;
    for (0..snapshot.count) |i| {
        const len = snapshot.lens[i];
        if (len != 16 and len != 32 and len != 48) return error.InvalidSnapshot;
        payload_len += 1 + len;
    }
    const bytes = try frame.create(allocator, checkpoint_magic, payload_len);
    errdefer {
        std.crypto.secureZero(u8, bytes);
        allocator.free(bytes);
    }
    const payload = bytes[frame.header_len .. bytes.len - frame.checksum_len];
    std.mem.writeInt(u16, payload[0..2], @intCast(snapshot.count), .little);
    @memset(payload[2..4], 0);
    var pos: usize = payload_header_len;
    for (0..snapshot.count) |i| {
        const len = snapshot.lens[i];
        payload[pos] = len;
        pos += 1;
        @memcpy(payload[pos..][0..len], snapshot.entries[i][0..len]);
        pos += len;
    }
    std.debug.assert(pos == payload.len);
    frame.finish(bytes, domain);
    return bytes;
}

pub fn decodeOwned(allocator: std.mem.Allocator, bytes: []const u8) Error!Owned {
    try validateCheckpoint(bytes);
    const snapshot = try allocator.create(ReplayGuard.Snapshot);
    errdefer allocator.destroy(snapshot);
    snapshot.* = .{};
    const payload = bytes[frame.header_len .. bytes.len - frame.checksum_len];
    snapshot.count = std.mem.readInt(u16, payload[0..2], .little);
    var pos: usize = payload_header_len;
    for (0..snapshot.count) |i| {
        const len = payload[pos];
        pos += 1;
        snapshot.lens[i] = len;
        @memcpy(snapshot.entries[i][0..len], payload[pos..][0..len]);
        pos += len;
    }
    return .{ .allocator = allocator, .snapshot = snapshot };
}

test "HXRG round-trip preserves mixed lengths and next eviction" {
    const alloc = std.testing.allocator;
    var source = ReplayGuard{};
    const tag = @as([16]u8, @splat(0x12));
    const binder32 = @as([32]u8, @splat(0x32));
    const binder48 = @as([48]u8, @splat(0x48));
    try std.testing.expect(source.checkAndRecord(&tag));
    try std.testing.expect(source.checkAndRecord(&binder32));
    try std.testing.expect(source.checkAndRecord(&binder48));
    const bytes = try encodeSnapshot(alloc, &source);
    defer alloc.free(bytes);
    var owned = try decodeOwned(alloc, bytes);
    defer owned.deinit();
    var candidate = ReplayGuard{};
    const address = @intFromPtr(&candidate);
    owned.install(&candidate);
    try std.testing.expectEqual(address, @intFromPtr(&candidate));
    try std.testing.expect(!candidate.checkAndRecord(&tag));
    try std.testing.expect(!candidate.checkAndRecord(&binder32));
    try std.testing.expect(!candidate.checkAndRecord(&binder48));

    // Fill past wrap with distinct 16-byte tags and preserve oldest eviction.
    var wrapped = ReplayGuard{};
    for (0..ReplayGuard.capacity + 7) |n| {
        var entry = @as([16]u8, @splat(0));
        std.mem.writeInt(u32, entry[0..4], @intCast(n), .little);
        try std.testing.expect(wrapped.checkAndRecord(&entry));
    }
    const wrapped_bytes = try encodeSnapshot(alloc, &wrapped);
    defer alloc.free(wrapped_bytes);
    var staged = try decodeOwned(alloc, wrapped_bytes);
    defer staged.deinit();
    staged.install(&candidate);
    var evicted = @as([16]u8, @splat(0));
    std.mem.writeInt(u32, evicted[0..4], 7, .little);
    try std.testing.expect(!candidate.checkAndRecord(&evicted));
    // Inserting one distinct value evicts source's oldest live entry (7).
    var next = @as([16]u8, @splat(0));
    std.mem.writeInt(u32, next[0..4], ReplayGuard.capacity + 7, .little);
    try std.testing.expect(candidate.checkAndRecord(&next));
    try std.testing.expect(candidate.checkAndRecord(&evicted));
}

test "HXRG rejects truncated, wrong length, trailing, count, and checksum" {
    const alloc = std.testing.allocator;
    var guard = ReplayGuard{};
    const tag = @as([16]u8, @splat(0x78));
    try std.testing.expect(guard.checkAndRecord(&tag));
    const bytes = try encodeSnapshot(alloc, &guard);
    defer alloc.free(bytes);
    for (0..bytes.len) |len| try std.testing.expectError(error.InvalidSnapshot, validateCheckpoint(bytes[0..len]));
    var bad = try alloc.dupe(u8, bytes);
    defer alloc.free(bad);
    bad[frame.header_len + payload_header_len] = 17;
    frame.finish(bad, domain);
    try std.testing.expectError(error.InvalidSnapshot, decodeOwned(alloc, bad));
    bad[frame.header_len + payload_header_len] = 16;
    std.mem.writeInt(u16, bad[frame.header_len..][0..2], 0, .little);
    frame.finish(bad, domain);
    try std.testing.expectError(error.InvalidSnapshot, validateCheckpoint(bad));
    std.mem.writeInt(u16, bad[frame.header_len..][0..2], 1, .little);
    bad[frame.header_len + 2] = 1;
    frame.finish(bad, domain);
    try std.testing.expectError(error.InvalidSnapshot, validateCheckpoint(bad));
    bad[frame.header_len + 2] = 0;
    frame.finish(bad, domain);
    bad[bad.len - 1] ^= 1;
    try std.testing.expectError(error.InvalidSnapshot, validateCheckpoint(bad));

    var two = ReplayGuard{};
    try std.testing.expect(two.checkAndRecord(&tag));
    const other = @as([16]u8, @splat(0x79));
    try std.testing.expect(two.checkAndRecord(&other));
    const two_bytes = try encodeSnapshot(alloc, &two);
    defer alloc.free(two_bytes);
    var duplicate = try alloc.dupe(u8, two_bytes);
    defer alloc.free(duplicate);
    const second = frame.header_len + payload_header_len + 1 + tag.len;
    @memcpy(duplicate[second + 1 ..][0..tag.len], &tag);
    frame.finish(duplicate, domain);
    try std.testing.expectError(error.InvalidSnapshot, validateCheckpoint(duplicate));
}

test "HXRG allocation failure leaves live guard unchanged" {
    const alloc = std.testing.allocator;
    var guard = ReplayGuard{};
    const tag = @as([16]u8, @splat(0x55));
    try std.testing.expect(guard.checkAndRecord(&tag));
    const Sweep = struct {
        fn run(a: std.mem.Allocator, g: *ReplayGuard) !void {
            const bytes = try encodeSnapshot(a, g);
            defer a.free(bytes);
            var staged = try decodeOwned(a, bytes);
            defer staged.deinit();
        }
    };
    try std.testing.checkAllAllocationFailures(alloc, Sweep.run, .{&guard});
    try std.testing.expect(!guard.checkAndRecord(&tag));
}
