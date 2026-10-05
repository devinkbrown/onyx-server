// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded Windows Helix custody for Server-owned OCSP staple generations and
//! a reactor rejection signal that must make the scheduler retry promptly.
//! The OCSP worker's scheduler is carried separately by HXOC. The caller must
//! pause that worker and quiesce reactor 0 before taking this snapshot, then
//! validate the active staple against the candidate's live leaf before READY.

const std = @import("std");
const frame = @import("native_windows_companion_wire.zig");

pub const checkpoint_magic = [_]u8{ 'H', 'X', 'O', 'S' };
pub const max_der_bytes: usize = 64 * 1024;
pub const max_checkpoint_bytes: usize = frame.header_len + payload_header_len + 3 * max_der_bytes + frame.checksum_len;
pub const Error = error{ InvalidSnapshot, TooLarge } || std.mem.Allocator.Error;

const checksum_domain = "onyx-windows-ocsp-state-checkpoint-v1";
const payload_header_len: usize = 16;

/// Borrowed source view. A null active staple can coexist with an owned current
/// generation after a TLS certificate reload. A stale true pending bit with no
/// incoming DER is possible at the worker/reactor handoff and is harmless.
/// `rejected` is consumed by the resumed worker before its freshness check.
pub const Snapshot = struct {
    pending: bool,
    active: bool,
    rejected: bool = false,
    incoming: ?[]const u8 = null,
    current: ?[]const u8 = null,
    previous: ?[]const u8 = null,
};

/// Detached candidate allocations. Call `deinit` on every pre-COMMIT failure;
/// `release` transfers all buffers to Server in one allocation-free step.
pub const Owned = struct {
    allocator: std.mem.Allocator,
    pending: bool,
    active: bool,
    rejected: bool,
    incoming: ?[]u8 = null,
    current: ?[]u8 = null,
    previous: ?[]u8 = null,

    pub fn deinit(self: *Owned) void {
        if (self.incoming) |bytes| self.allocator.free(bytes);
        if (self.current) |bytes| self.allocator.free(bytes);
        if (self.previous) |bytes| self.allocator.free(bytes);
        self.incoming = null;
        self.current = null;
        self.previous = null;
    }

    pub fn release(self: *Owned) State {
        const result = State{
            .pending = self.pending,
            .active = self.active,
            .rejected = self.rejected,
            .incoming = self.incoming,
            .current = self.current,
            .previous = self.previous,
        };
        self.incoming = null;
        self.current = null;
        self.previous = null;
        return result;
    }
};

/// The caller owns these buffers after `Owned.release` and must free them with
/// the same allocator when the server retires each generation.
pub const State = struct {
    pending: bool,
    active: bool,
    rejected: bool,
    incoming: ?[]u8,
    current: ?[]u8,
    previous: ?[]u8,
};

pub fn isCheckpoint(bytes: []const u8) bool {
    return frame.isCheckpoint(bytes, checkpoint_magic);
}

/// Checks canonical framing, lengths, flags, and checksum without allocation.
/// DER trust and its relation to the candidate leaf are checked by the caller.
pub fn validateCheckpoint(bytes: []const u8) error{InvalidSnapshot}!void {
    _ = try parse(bytes);
}

pub fn encodeSnapshot(allocator: std.mem.Allocator, snapshot: Snapshot) Error![]u8 {
    const incoming_len = try checkedLength(snapshot.incoming);
    const current_len = try checkedLength(snapshot.current);
    const previous_len = try checkedLength(snapshot.previous);
    if ((snapshot.active and current_len == 0) or
        (incoming_len != 0 and !snapshot.pending) or
        (previous_len != 0 and current_len == 0)) return error.InvalidSnapshot;
    const payload_len = payload_header_len + incoming_len + current_len + previous_len;
    const bytes = try frame.create(allocator, checkpoint_magic, payload_len);
    errdefer freeEncoded(allocator, bytes);
    const payload = bytes[frame.header_len .. bytes.len - frame.checksum_len];
    payload[0] = @intFromBool(snapshot.pending);
    payload[1] = @intFromBool(snapshot.active);
    payload[2] = @intFromBool(snapshot.rejected);
    payload[3] = 0;
    std.mem.writeInt(u32, payload[4..8], @intCast(incoming_len), .little);
    std.mem.writeInt(u32, payload[8..12], @intCast(current_len), .little);
    std.mem.writeInt(u32, payload[12..16], @intCast(previous_len), .little);
    var cursor: usize = payload_header_len;
    if (snapshot.incoming) |der| {
        @memcpy(payload[cursor..][0..der.len], der);
        cursor += der.len;
    }
    if (snapshot.current) |der| {
        @memcpy(payload[cursor..][0..der.len], der);
        cursor += der.len;
    }
    if (snapshot.previous) |der| {
        @memcpy(payload[cursor..][0..der.len], der);
        cursor += der.len;
    }
    std.debug.assert(cursor == payload.len);
    frame.finish(bytes, checksum_domain);
    try validateCheckpoint(bytes);
    return bytes;
}

/// Allocation-failure atomic: no partially decoded generation escapes.
pub fn decodeOwned(allocator: std.mem.Allocator, bytes: []const u8) Error!Owned {
    const parsed = try parse(bytes);
    var owned = Owned{ .allocator = allocator, .pending = parsed.pending, .active = parsed.active, .rejected = parsed.rejected };
    errdefer owned.deinit();
    if (parsed.incoming) |der| owned.incoming = try allocator.dupe(u8, der);
    if (parsed.current) |der| owned.current = try allocator.dupe(u8, der);
    if (parsed.previous) |der| owned.previous = try allocator.dupe(u8, der);
    return owned;
}

pub fn freeEncoded(allocator: std.mem.Allocator, bytes: []u8) void {
    std.crypto.secureZero(u8, bytes);
    allocator.free(bytes);
}

fn checkedLength(optional: ?[]const u8) Error!usize {
    if (optional) |bytes| {
        if (bytes.len == 0) return error.InvalidSnapshot;
        if (bytes.len > max_der_bytes) return error.TooLarge;
        return bytes.len;
    }
    return 0;
}

fn parse(bytes: []const u8) error{InvalidSnapshot}!Snapshot {
    if (bytes.len < frame.header_len + payload_header_len + frame.checksum_len or
        bytes.len > max_checkpoint_bytes) return error.InvalidSnapshot;
    const payload = try frame.validateFrame(bytes, checkpoint_magic, checksum_domain, bytes.len - frame.header_len - frame.checksum_len);
    if (payload[0] > 1 or payload[1] > 1 or payload[2] > 1 or payload[3] != 0) return error.InvalidSnapshot;
    const incoming_len: usize = std.mem.readInt(u32, payload[4..8], .little);
    const current_len: usize = std.mem.readInt(u32, payload[8..12], .little);
    const previous_len: usize = std.mem.readInt(u32, payload[12..16], .little);
    if (incoming_len > max_der_bytes or current_len > max_der_bytes or previous_len > max_der_bytes or
        payload_header_len + incoming_len + current_len + previous_len != payload.len) return error.InvalidSnapshot;
    const pending = payload[0] == 1;
    const active = payload[1] == 1;
    const rejected = payload[2] == 1;
    if ((active and current_len == 0) or (incoming_len != 0 and !pending) or
        (previous_len != 0 and current_len == 0)) return error.InvalidSnapshot;
    var cursor: usize = payload_header_len;
    const incoming: ?[]const u8 = if (incoming_len != 0) blk: {
        defer cursor += incoming_len;
        break :blk payload[cursor..][0..incoming_len];
    } else null;
    const current: ?[]const u8 = if (current_len != 0) blk: {
        defer cursor += current_len;
        break :blk payload[cursor..][0..current_len];
    } else null;
    const previous: ?[]const u8 = if (previous_len != 0) payload[cursor..][0..previous_len] else null;
    return .{ .pending = pending, .active = active, .rejected = rejected, .incoming = incoming, .current = current, .previous = previous };
}

test "HXOS carries pending, active, current, and retained DER generations independently" {
    const allocator = std.testing.allocator;
    const wire = try encodeSnapshot(allocator, .{
        .pending = true,
        .active = true,
        .incoming = "incoming",
        .current = "current",
        .previous = "previous",
    });
    defer freeEncoded(allocator, wire);
    var owned = try decodeOwned(allocator, wire);
    defer owned.deinit();
    try std.testing.expect(owned.pending and owned.active);
    try std.testing.expectEqualStrings("incoming", owned.incoming.?);
    try std.testing.expectEqualStrings("current", owned.current.?);
    try std.testing.expectEqualStrings("previous", owned.previous.?);
    wire[frame.header_len + payload_header_len] = 'X';
    try std.testing.expectEqualStrings("incoming", owned.incoming.?);
    const transferred = owned.release();
    try std.testing.expect(owned.incoming == null and owned.current == null and owned.previous == null);
    allocator.free(transferred.incoming.?);
    allocator.free(transferred.current.?);
    allocator.free(transferred.previous.?);
}

test "HXOS accepts null active after reload and stale pending signal" {
    const allocator = std.testing.allocator;
    const wire = try encodeSnapshot(allocator, .{ .pending = true, .active = false, .rejected = true, .current = "stale", .previous = "older" });
    defer freeEncoded(allocator, wire);
    var owned = try decodeOwned(allocator, wire);
    defer owned.deinit();
    try std.testing.expect(owned.incoming == null);
    try std.testing.expect(!owned.active and owned.pending and owned.rejected);
    try std.testing.expectEqualStrings("stale", owned.current.?);
    const empty = try encodeSnapshot(allocator, .{ .pending = false, .active = false });
    defer freeEncoded(allocator, empty);
    try validateCheckpoint(empty);
}

test "HXOS rejects malformed flags, lengths, checksum, and impossible ownership" {
    const allocator = std.testing.allocator;
    const wire = try encodeSnapshot(allocator, .{ .pending = true, .active = true, .incoming = "i", .current = "c" });
    defer freeEncoded(allocator, wire);
    const payload = wire[frame.header_len .. wire.len - frame.checksum_len];
    payload[0] = 2;
    frame.finish(wire, checksum_domain);
    try std.testing.expectError(error.InvalidSnapshot, validateCheckpoint(wire));
    payload[0] = 1;
    payload[1] = 0;
    payload[2] = 2;
    frame.finish(wire, checksum_domain);
    try std.testing.expectError(error.InvalidSnapshot, validateCheckpoint(wire));
    payload[2] = 0;
    std.mem.writeInt(u32, payload[4..8], max_der_bytes + 1, .little);
    frame.finish(wire, checksum_domain);
    try std.testing.expectError(error.InvalidSnapshot, validateCheckpoint(wire));
    std.mem.writeInt(u32, payload[4..8], 1, .little);
    payload[1] = 1;
    frame.finish(wire, checksum_domain);
    wire[wire.len - 1] ^= 1;
    try std.testing.expectError(error.InvalidSnapshot, validateCheckpoint(wire));
    try std.testing.expectError(error.InvalidSnapshot, encodeSnapshot(allocator, .{ .pending = false, .active = true }));
    try std.testing.expectError(error.InvalidSnapshot, encodeSnapshot(allocator, .{ .pending = false, .active = false, .incoming = "orphan" }));
    try std.testing.expectError(error.InvalidSnapshot, encodeSnapshot(allocator, .{ .pending = false, .active = false, .current = "" }));
    const oversized = try allocator.alloc(u8, max_der_bytes + 1);
    defer allocator.free(oversized);
    try std.testing.expectError(error.TooLarge, encodeSnapshot(allocator, .{ .pending = false, .active = false, .current = oversized }));
}

test "HXOS owned decode allocation sweep rolls back every partial allocation" {
    const allocator = std.testing.allocator;
    const wire = try encodeSnapshot(allocator, .{ .pending = true, .active = true, .incoming = "incoming", .current = "current", .previous = "previous" });
    defer freeEncoded(allocator, wire);
    const Sweep = struct {
        fn run(a: std.mem.Allocator, bytes: []const u8) !void {
            var decoded = try decodeOwned(a, bytes);
            defer decoded.deinit();
            try std.testing.expectEqualStrings("previous", decoded.previous.?);
        }
    };
    try std.testing.checkAllAllocationFailures(allocator, Sweep.run, .{wire});
}

test "HXOS encoded framing allocation sweep is all or nothing" {
    const allocator = std.testing.allocator;
    const snapshot = Snapshot{ .pending = true, .active = true, .incoming = "incoming", .current = "current", .previous = "previous" };
    const Sweep = struct {
        fn run(a: std.mem.Allocator, source: Snapshot) !void {
            const wire = try encodeSnapshot(a, source);
            defer freeEncoded(a, wire);
            try validateCheckpoint(wire);
        }
    };
    try std.testing.checkAllAllocationFailures(allocator, Sweep.run, .{snapshot});
}
