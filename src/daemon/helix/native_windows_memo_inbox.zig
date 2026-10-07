// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact Windows Helix custody for the RAM MemoBox and durable reconciliation bit.
//! A decode owns detached state; the server publishes it only after the entire
//! handoff has validated and staged successfully.

const std = @import("std");
const memo = @import("../memo.zig");
const wire = @import("abuse_checkpoint_wire.zig");

pub const magic = [_]u8{ 'H', 'X', 'M', 'B' };
pub const max_checkpoint_bytes = wire.max_checkpoint_bytes;
pub const Error = wire.Error || error{ConfigMismatch};

const domain = "onyx-windows-memo-inbox-checkpoint-v1";
const header_len: usize = 56;
const row_header_len: usize = 8;
const message_header_len: usize = 16;

pub const State = struct {
    box: memo.MemoBox,
    dirty: bool,

    pub fn deinit(self: *State) void {
        var boxes = self.box.boxes.iterator();
        while (boxes.next()) |entry| {
            std.crypto.secureZero(u8, @constCast(entry.key_ptr.*));
            for (entry.value_ptr.items.items) |message| {
                std.crypto.secureZero(u8, message.from);
                std.crypto.secureZero(u8, message.text);
            }
        }
        self.box.deinit();
        self.* = undefined;
    }
};

pub fn isCheckpoint(bytes: []const u8) bool {
    return wire.isCheckpoint(bytes, magic);
}

fn readLimit(bytes: []const u8) Error!usize {
    const raw = std.mem.readInt(u64, bytes[0..8], .little);
    if (raw > std.math.maxInt(usize)) return error.InvalidField;
    return @intCast(raw);
}

fn readConfig(bytes: []const u8) Error!memo.Config {
    return .{
        .max_text_bytes = try readLimit(bytes[16..24]),
        .max_from_bytes = try readLimit(bytes[24..32]),
        .max_per_account = try readLimit(bytes[32..40]),
        .max_accounts = try readLimit(bytes[40..48]),
    };
}

fn sameConfig(a: memo.Config, b: memo.Config) bool {
    return a.max_text_bytes == b.max_text_bytes and a.max_from_bytes == b.max_from_bytes and
        a.max_per_account == b.max_per_account and a.max_accounts == b.max_accounts;
}

/// Verify frame integrity and all variable-length semantics without allocating.
/// Strictly ordered account keys make duplicates and noncanonical encodings fatal.
pub fn validateCheckpoint(bytes: []const u8) Error!void {
    const body = try wire.parseFrame(bytes, magic, header_len, domain);
    if (bytes[48] > 1 or !std.mem.allEqual(u8, bytes[49..56], 0)) return error.InvalidField;
    const cfg = try readConfig(bytes);
    const count: usize = std.mem.readInt(u32, bytes[12..16], .little);
    if (count > cfg.max_accounts) return error.CheckpointTooLarge;
    if (count > body.len / row_header_len) return error.Truncated;
    var reader = wire.Reader{ .bytes = body };
    var previous: ?[]const u8 = null;
    for (0..count) |_| {
        const account_len: usize = try reader.readU32();
        const messages: usize = try reader.readU32();
        if (account_len == 0 or messages > cfg.max_per_account) return error.InvalidField;
        const account = try reader.take(account_len);
        if (previous) |prior| {
            if (!std.mem.lessThan(u8, prior, account)) return error.NonCanonicalOrder;
        }
        previous = account;
        if (messages > reader.remaining() / message_header_len) return error.Truncated;
        for (0..messages) |_| {
            const from_len: usize = try reader.readU32();
            const text_len: usize = try reader.readU32();
            _ = try reader.readI64();
            if (from_len == 0 or from_len > cfg.max_from_bytes or
                text_len == 0 or text_len > cfg.max_text_bytes) return error.InvalidField;
            _ = try reader.take(from_len);
            _ = try reader.take(text_len);
        }
    }
    if (reader.remaining() != 0) return error.TrailingBytes;
}

fn addLen(total: *usize, len: usize) Error!void {
    try wire.addLen(total, len);
    if (total.* > std.math.maxInt(u32)) return error.CheckpointTooLarge;
}

fn lessText(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

/// Account order is canonical; message order is the live mailbox order. The
/// SHA-256 checksum binds this exact format and its configured limits.
pub fn encode(allocator: std.mem.Allocator, source: *const memo.MemoBox, dirty: bool) Error![]u8 {
    const count = source.boxes.count();
    if (count > source.cfg.max_accounts or count > std.math.maxInt(u32)) return error.CheckpointTooLarge;
    const keys = try allocator.alloc([]const u8, count);
    defer allocator.free(keys);
    var size: usize = header_len + wire.checksum_len;
    var it = source.boxes.iterator();
    var index: usize = 0;
    while (it.next()) |entry| {
        const account = entry.key_ptr.*;
        const messages = entry.value_ptr.items.items;
        if (account.len == 0 or account.len > std.math.maxInt(u32) or
            messages.len > source.cfg.max_per_account or messages.len > std.math.maxInt(u32))
            return error.InvalidField;
        keys[index] = account;
        index += 1;
        try addLen(&size, row_header_len);
        try addLen(&size, account.len);
        for (messages) |message| {
            if (message.from.len == 0 or message.from.len > source.cfg.max_from_bytes or
                message.from.len > std.math.maxInt(u32) or message.text.len == 0 or
                message.text.len > source.cfg.max_text_bytes or message.text.len > std.math.maxInt(u32))
                return error.InvalidField;
            try addLen(&size, message_header_len);
            try addLen(&size, message.from.len);
            try addLen(&size, message.text.len);
        }
    }
    std.debug.assert(index == count);
    std.mem.sort([]const u8, keys, {}, lessText);
    const bytes = try allocator.alloc(u8, size);
    errdefer {
        std.crypto.secureZero(u8, bytes);
        allocator.free(bytes);
    }
    var writer = wire.Writer{ .bytes = bytes };
    writer.writeBytes(&magic);
    writer.writeByte(1);
    writer.writeBytes(&.{ 0, 0, 0 });
    writer.writeU32(@intCast(size - header_len - wire.checksum_len));
    writer.writeU32(@intCast(count));
    writer.writeU64(@intCast(source.cfg.max_text_bytes));
    writer.writeU64(@intCast(source.cfg.max_from_bytes));
    writer.writeU64(@intCast(source.cfg.max_per_account));
    writer.writeU64(@intCast(source.cfg.max_accounts));
    writer.writeByte(@intFromBool(dirty));
    writer.writeBytes(&.{ 0, 0, 0, 0, 0, 0, 0 });
    for (keys) |account| {
        const messages = source.boxes.get(account).?.items.items;
        writer.writeU32(@intCast(account.len));
        writer.writeU32(@intCast(messages.len));
        writer.writeBytes(account);
        for (messages) |message| {
            writer.writeU32(@intCast(message.from.len));
            writer.writeU32(@intCast(message.text.len));
            writer.writeI64(message.sent_ms);
            writer.writeBytes(message.from);
            writer.writeBytes(message.text);
        }
    }
    wire.finish(&writer, domain);
    try validateCheckpoint(bytes);
    return bytes;
}

/// Decode is detached and allocation-failure atomic with respect to the live
/// server. Config mismatch is rejected before any state allocation.
pub fn decode(allocator: std.mem.Allocator, bytes: []const u8, expected_cfg: memo.Config) Error!State {
    try validateCheckpoint(bytes);
    if (!sameConfig(try readConfig(bytes), expected_cfg)) return error.ConfigMismatch;
    const count: usize = std.mem.readInt(u32, bytes[12..16], .little);
    var result = State{ .box = memo.MemoBox.initWithConfig(allocator, expected_cfg), .dirty = bytes[48] == 1 };
    errdefer result.deinit();
    var reader = wire.Reader{ .bytes = bytes[header_len .. bytes.len - wire.checksum_len] };
    for (0..count) |_| {
        const account_len: usize = try reader.readU32();
        const messages: usize = try reader.readU32();
        const account = try reader.take(account_len);
        const owned = try allocator.dupe(u8, account);
        result.box.boxes.putNoClobber(owned, .{}) catch |err| {
            allocator.free(owned);
            return err;
        };
        for (0..messages) |_| {
            const from_len: usize = try reader.readU32();
            const text_len: usize = try reader.readU32();
            const sent_ms = try reader.readI64();
            const from = try reader.take(from_len);
            const text = try reader.take(text_len);
            _ = result.box.send(account, from, text, sent_ms) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.InvalidField,
            };
        }
    }
    return result;
}

fn rechecksum(bytes: []u8) void {
    var digest: [wire.checksum_len]u8 = undefined;
    wire.checksum(domain, bytes[0 .. bytes.len - wire.checksum_len], &digest);
    @memcpy(bytes[bytes.len - wire.checksum_len ..], &digest);
}

test "HXMB preserves empty account keys, FIFO messages, configured limits and dirty bit" {
    const alloc = std.testing.allocator;
    const cfg: memo.Config = .{ .max_text_bytes = 6, .max_from_bytes = 4, .max_per_account = 2, .max_accounts = 3 };
    var source = memo.MemoBox.initWithConfig(alloc, cfg);
    defer source.deinit();
    _ = try source.send("z", "a", "one", -7);
    _ = try source.send("z", "b", "two", 9);
    _ = try source.send("a", "c", "three", 11);
    const empty = try alloc.dupe(u8, "empty");
    try source.boxes.putNoClobber(empty, .{});
    const bytes = try encode(alloc, &source, true);
    defer alloc.free(bytes);
    try validateCheckpoint(bytes);
    var staged = try decode(alloc, bytes, cfg);
    defer staged.deinit();
    try std.testing.expect(staged.dirty);
    try std.testing.expectEqual(@as(usize, 3), staged.box.boxes.count());
    try std.testing.expectEqual(@as(usize, 0), staged.box.pending("empty").len);
    try std.testing.expect(staged.box.boxes.contains("empty"));
    const messages = staged.box.pending("z");
    try std.testing.expectEqual(@as(usize, 2), messages.len);
    try std.testing.expectEqualStrings("a", messages[0].from);
    try std.testing.expectEqualStrings("one", messages[0].text);
    try std.testing.expectEqual(@as(i64, -7), messages[0].sent_ms);
    try std.testing.expectEqualStrings("b", messages[1].from);
    try std.testing.expectEqualStrings("two", messages[1].text);
    try std.testing.expectEqual(@as(i64, 9), messages[1].sent_ms);
    var failing = std.testing.FailingAllocator.init(alloc, .{ .fail_index = 0 });
    try std.testing.expectError(error.ConfigMismatch, decode(failing.allocator(), bytes, .{}));
    try std.testing.expectEqual(@as(usize, 0), failing.alloc_index);
    const again = try encode(alloc, &staged.box, staged.dirty);
    defer alloc.free(again);
    try std.testing.expectEqualSlices(u8, bytes, again);
}

test "HXMB canonical output does not depend on hash insertion order" {
    const alloc = std.testing.allocator;
    var first = memo.MemoBox.init(alloc);
    defer first.deinit();
    var second = memo.MemoBox.init(alloc);
    defer second.deinit();
    _ = try first.send("z", "s", "last", 2);
    _ = try first.send("a", "s", "first", 1);
    _ = try second.send("a", "s", "first", 1);
    _ = try second.send("z", "s", "last", 2);
    const a = try encode(alloc, &first, false);
    defer alloc.free(a);
    const b = try encode(alloc, &second, false);
    defer alloc.free(b);
    try std.testing.expectEqualSlices(u8, a, b);
}

test "HXMB rejects checksum, reserved, duplicate, malformed and oversized state" {
    const alloc = std.testing.allocator;
    var source = memo.MemoBox.init(alloc);
    defer source.deinit();
    _ = try source.send("a", "b", "one", 1);
    _ = try source.send("z", "b", "two", 2);
    const bytes = try encode(alloc, &source, false);
    defer alloc.free(bytes);
    const bad = try alloc.dupe(u8, bytes);
    defer alloc.free(bad);
    bad[header_len] ^= 1;
    try std.testing.expectError(error.ChecksumMismatch, validateCheckpoint(bad));
    @memcpy(bad, bytes);
    bad[49] = 1;
    rechecksum(bad);
    try std.testing.expectError(error.InvalidField, validateCheckpoint(bad));
    @memcpy(bad, bytes);
    bad[48] = 2;
    rechecksum(bad);
    try std.testing.expectError(error.InvalidField, validateCheckpoint(bad));
    @memcpy(bad, bytes);
    const second_row = header_len + row_header_len + 1 + message_header_len + 1 + 3;
    bad[second_row + row_header_len] = 'a';
    rechecksum(bad);
    try std.testing.expectError(error.NonCanonicalOrder, validateCheckpoint(bad));
    @memcpy(bad, bytes);
    std.mem.writeInt(u32, bad[header_len + 4 ..][0..4], 65, .little);
    rechecksum(bad);
    try std.testing.expectError(error.InvalidField, validateCheckpoint(bad));
    @memcpy(bad, bytes);
    std.mem.writeInt(u64, bad[40..48], 1, .little);
    rechecksum(bad);
    try std.testing.expectError(error.CheckpointTooLarge, validateCheckpoint(bad));
    @memcpy(bad, bytes);
    std.mem.writeInt(u32, bad[header_len..][0..4], 0, .little);
    rechecksum(bad);
    try std.testing.expectError(error.InvalidField, validateCheckpoint(bad));
    try std.testing.expectError(error.Truncated, validateCheckpoint(bytes[0 .. bytes.len - 1]));
}

fn allocationRollback(failing_allocator: std.mem.Allocator, bytes: []const u8) !void {
    const stable = std.testing.allocator;
    var live = memo.MemoBox.init(stable);
    defer live.deinit();
    _ = try live.send("old", "x", "preserved", 44);
    const before = try encode(stable, &live, true);
    defer stable.free(before);
    var staged = decode(failing_allocator, bytes, live.cfg) catch |err| {
        const after = try encode(stable, &live, true);
        defer stable.free(after);
        try std.testing.expectEqualSlices(u8, before, after);
        return err;
    };
    staged.deinit();
    const after = try encode(stable, &live, true);
    defer stable.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
}

test "HXMB detached decode sweeps allocation failures without changing live state" {
    const alloc = std.testing.allocator;
    var source = memo.MemoBox.init(alloc);
    defer source.deinit();
    _ = try source.send("a", "b", "one", 1);
    _ = try source.send("a", "c", "two", 2);
    _ = try source.send("z", "b", "three", 3);
    const empty = try alloc.dupe(u8, "empty");
    try source.boxes.putNoClobber(empty, .{});
    const bytes = try encode(alloc, &source, true);
    defer alloc.free(bytes);
    try std.testing.checkAllAllocationFailures(alloc, allocationRollback, .{bytes});
}
