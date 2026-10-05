// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Nick-delay registry: holds a recently released nick for a configured window
//! so it cannot be grabbed by a hijacker the instant its owner drops (the
//! classic "nick camping" race, and services-bypass during netsplits/quits).
//!
//! A nick is held when its owner exits (disconnect / QUIT). During the hold:
//!   - the owning account (when the releaser was authenticated) may reclaim it,
//!   - server operators bypass the hold entirely,
//!   - a connection-class flagged `nick_delay_exempt` bypasses it,
//!   - everyone else is refused until the hold expires.
//!
//! Pure: it reads no clock and touches no sockets — the caller supplies `now`
//! (monotonic ms). Nick keys are folded to ASCII lowercase, matching the
//! daemon's RFC1459-ish case-insensitive nick comparison.

const std = @import("std");

pub const max_checkpoint_bytes: usize = @import("helix/live.zig").max_arena_bytes;
pub const max_checkpoint_entries: usize = 1_048_576;
pub const max_checkpoint_owner_bytes: usize = 65_535;
pub const checkpoint_magic = [_]u8{ 'N', 'K', 'D', 'L' };
pub const checkpoint_version: u8 = 1;
const checkpoint_header_len: usize = 4 + 1 + 3 + 4 + 8 + 4;
const checkpoint_checksum_len: usize = 32;
const checkpoint_row_min_len: usize = 1 + 1 + 8 + 1;
const checkpoint_domain = "onyx-nick-delay-checkpoint-v1";

pub const CheckpointError = error{
    BadMagic,
    UnsupportedVersion,
    Truncated,
    TrailingBytes,
    InvalidField,
    ConfigMismatch,
    NonCanonicalOrder,
    ChecksumMismatch,
    CheckpointTooLarge,
} || std.mem.Allocator.Error;

pub fn isUpgradeCheckpoint(bytes: []const u8) bool {
    return bytes.len >= checkpoint_magic.len and std.mem.eql(u8, bytes[0..checkpoint_magic.len], &checkpoint_magic);
}

/// Allocation-free validation for Helix's relation pass. The caller's
/// configured nick-delay interval is checked during staged restore.
pub fn validateUpgradeCheckpoint(bytes: []const u8) CheckpointError!void {
    if (bytes.len < checkpoint_header_len + checkpoint_checksum_len) return error.Truncated;
    if (bytes.len > max_checkpoint_bytes) return error.CheckpointTooLarge;
    if (!isUpgradeCheckpoint(bytes)) return error.BadMagic;
    if (bytes[4] != checkpoint_version) return error.UnsupportedVersion;
    if (!std.mem.eql(u8, bytes[5..8], &.{ 0, 0, 0 })) return error.InvalidField;
    const body_len: usize = std.mem.readInt(u32, bytes[8..12], .little);
    const expected_len = std.math.add(usize, checkpoint_header_len + checkpoint_checksum_len, body_len) catch return error.CheckpointTooLarge;
    if (expected_len > max_checkpoint_bytes) return error.CheckpointTooLarge;
    if (bytes.len < expected_len) return error.Truncated;
    if (bytes.len > expected_len) return error.TrailingBytes;
    var digest: [checkpoint_checksum_len]u8 = undefined;
    checkpointChecksum(bytes[0 .. bytes.len - checkpoint_checksum_len], &digest);
    const saved_digest: [checkpoint_checksum_len]u8 = bytes[bytes.len - checkpoint_checksum_len ..][0..checkpoint_checksum_len].*;
    if (!std.crypto.timing_safe.eql([checkpoint_checksum_len]u8, digest, saved_digest)) return error.ChecksumMismatch;

    var reader = CheckpointReader{ .bytes = bytes[12 .. bytes.len - checkpoint_checksum_len] };
    _ = try reader.readU64(); // configured delay, compared at restore
    const count: usize = try reader.readU32();
    if (count > max_checkpoint_entries) return error.CheckpointTooLarge;
    if (count > body_len / checkpoint_row_min_len) return error.Truncated;
    var previous_key: ?[]const u8 = null;
    for (0..count) |_| {
        const key_len: usize = try reader.readByte();
        if (key_len == 0 or key_len > NickDelay.max_nick) return error.InvalidField;
        const key = try reader.take(key_len);
        if (!isCanonicalNick(key)) return error.InvalidField;
        if (previous_key) |previous| {
            if (std.mem.order(u8, previous, key) != .lt) return error.NonCanonicalOrder;
        }
        previous_key = key;
        _ = try reader.readI64();
        const owner_tag = try reader.readByte();
        switch (owner_tag) {
            0 => {},
            1 => {
                const owner_len: usize = try reader.readU32();
                if (owner_len > max_checkpoint_owner_bytes) return error.CheckpointTooLarge;
                _ = try reader.take(owner_len);
            },
            else => return error.InvalidField,
        }
    }
    if (reader.remaining() != 0) return error.TrailingBytes;
}

pub const NickDelay = struct {
    allocator: std.mem.Allocator,
    held: std.StringHashMapUnmanaged(Entry) = .empty,

    pub const Entry = struct {
        /// Monotonic-ms deadline; the hold lapses once `now >= expires_ms`.
        expires_ms: i64,
        /// Owning account (owned copy), or null when the releasing user was
        /// anonymous. Only this account may reclaim the nick during the hold.
        owner: ?[]u8,
    };

    /// A live hold, returned by `check`. `owner` is null for an anonymous holder.
    pub const Held = struct { owner: ?[]const u8 };

    /// Longest nick handled (the daemon NICKLEN ceiling). Anything longer is
    /// never a valid nick, so it is never held.
    pub const max_nick = 64;

    pub fn init(allocator: std.mem.Allocator) NickDelay {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *NickDelay) void {
        var it = self.held.iterator();
        while (it.next()) |e| {
            self.allocator.free(e.key_ptr.*);
            if (e.value_ptr.owner) |o| self.allocator.free(o);
        }
        self.held.deinit(self.allocator);
        self.* = undefined;
    }

    /// Fold `nick` to ASCII lowercase into `buf`; null if empty or too long.
    fn fold(buf: []u8, nick: []const u8) ?[]const u8 {
        if (nick.len == 0 or nick.len > buf.len) return null;
        for (nick, 0..) |c, i| buf[i] = std.ascii.toLower(c);
        return buf[0..nick.len];
    }

    /// Hold `nick` until `expires_ms`, recording `owner` (account) when any.
    /// Replaces any prior hold for the same (case-insensitive) nick.
    pub fn hold(self: *NickDelay, nick: []const u8, expires_ms: i64, owner: ?[]const u8) !void {
        var kb: [max_nick]u8 = undefined;
        const key = fold(&kb, nick) orelse return;

        const owner_copy: ?[]u8 = if (owner) |o| try self.allocator.dupe(u8, o) else null;
        errdefer if (owner_copy) |o| self.allocator.free(o);

        if (self.held.getPtr(key)) |e| {
            if (e.owner) |old| self.allocator.free(old);
            e.* = .{ .expires_ms = expires_ms, .owner = owner_copy };
            return;
        }
        const key_copy = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(key_copy);
        try self.held.put(self.allocator, key_copy, .{ .expires_ms = expires_ms, .owner = owner_copy });
    }

    /// The live hold for `nick` at `now`, or null when it is not held. An expired
    /// entry is evicted in passing. The returned `owner` slice is valid until the
    /// next mutation of this registry.
    pub fn check(self: *NickDelay, nick: []const u8, now: i64) ?Held {
        var kb: [max_nick]u8 = undefined;
        const key = fold(&kb, nick) orelse return null;
        const e = self.held.getPtr(key) orelse return null;
        if (now >= e.expires_ms) {
            self.releaseKey(key);
            return null;
        }
        return .{ .owner = e.owner };
    }

    /// Explicitly drop any hold for `nick` (a legitimate reclaim / re-register).
    pub fn release(self: *NickDelay, nick: []const u8) void {
        var kb: [max_nick]u8 = undefined;
        const key = fold(&kb, nick) orelse return;
        self.releaseKey(key);
    }

    fn releaseKey(self: *NickDelay, key: []const u8) void {
        if (self.held.fetchRemove(key)) |kv| {
            self.allocator.free(kv.key);
            if (kv.value.owner) |o| self.allocator.free(o);
        }
    }

    /// Evict entries expired at `now` (up to a bounded batch; the remainder is
    /// reclaimed on the next call). Returns the number removed. Called from the
    /// periodic timeout sweep so churned nicks do not accumulate.
    pub fn sweep(self: *NickDelay, now: i64) usize {
        var batch: [64][]const u8 = undefined;
        var n: usize = 0;
        var it = self.held.iterator();
        while (it.next()) |e| {
            if (now >= e.value_ptr.expires_ms) {
                batch[n] = e.key_ptr.*;
                n += 1;
                if (n == batch.len) break;
            }
        }
        for (batch[0..n]) |k| self.releaseKey(k);
        return n;
    }

    /// Number of nicks currently held (includes not-yet-swept expired entries).
    pub fn count(self: *const NickDelay) usize {
        return self.held.count();
    }

    /// Capture every live map entry, including a timer that has expired but
    /// has not yet been swept. The configured interval is included so the
    /// successor cannot reinterpret a hold under a changed policy.
    pub fn exportUpgradeCheckpoint(
        self: *const NickDelay,
        allocator: std.mem.Allocator,
        configured_delay_ms: u64,
    ) CheckpointError![]u8 {
        const count_rows = self.held.count();
        if (count_rows > max_checkpoint_entries) return error.CheckpointTooLarge;
        const keys = try allocator.alloc([]const u8, count_rows);
        defer allocator.free(keys);
        var it = self.held.iterator();
        var index: usize = 0;
        while (it.next()) |row| : (index += 1) {
            if (index >= keys.len) return error.InvalidField;
            keys[index] = row.key_ptr.*;
        }
        if (index != keys.len) return error.InvalidField;
        std.mem.sort([]const u8, keys, {}, keyLess);

        var total_len: usize = checkpoint_header_len + checkpoint_checksum_len;
        for (keys) |key| {
            const entry = self.held.get(key) orelse return error.InvalidField;
            if (key.len == 0 or key.len > max_nick or !isCanonicalNick(key)) return error.InvalidField;
            try checkpointAddLen(&total_len, checkpoint_row_min_len - 1);
            try checkpointAddLen(&total_len, key.len);
            if (entry.owner) |owner| {
                if (owner.len > max_checkpoint_owner_bytes) return error.CheckpointTooLarge;
                try checkpointAddLen(&total_len, 4);
                try checkpointAddLen(&total_len, owner.len);
            }
        }

        const out = try allocator.alloc(u8, total_len);
        errdefer allocator.free(out);
        var writer = CheckpointWriter{ .bytes = out };
        writer.writeBytes(&checkpoint_magic);
        writer.writeByte(checkpoint_version);
        writer.writeBytes(&.{ 0, 0, 0 });
        writer.writeU32(@intCast(total_len - checkpoint_header_len - checkpoint_checksum_len));
        writer.writeU64(configured_delay_ms);
        writer.writeU32(@intCast(count_rows));
        for (keys) |key| {
            const entry = self.held.get(key).?;
            writer.writeByte(@intCast(key.len));
            writer.writeBytes(key);
            writer.writeI64(entry.expires_ms);
            if (entry.owner) |owner| {
                writer.writeByte(1);
                writer.writeU32(@intCast(owner.len));
                writer.writeBytes(owner);
            } else {
                writer.writeByte(0);
            }
        }
        std.debug.assert(writer.pos + checkpoint_checksum_len == out.len);
        var digest: [checkpoint_checksum_len]u8 = undefined;
        checkpointChecksum(out[0..writer.pos], &digest);
        writer.writeBytes(&digest);
        return out;
    }

    /// Return an independent, fully validated registry for pre-COMMIT staging.
    pub fn restoreUpgradeCheckpoint(
        allocator: std.mem.Allocator,
        expected_delay_ms: u64,
        bytes: []const u8,
    ) CheckpointError!NickDelay {
        try validateUpgradeCheckpoint(bytes);
        var reader = CheckpointReader{ .bytes = bytes[12 .. bytes.len - checkpoint_checksum_len] };
        if (try reader.readU64() != expected_delay_ms) return error.ConfigMismatch;
        const count_rows: usize = try reader.readU32();
        var restored = NickDelay.init(allocator);
        errdefer restored.deinit();
        for (0..count_rows) |_| {
            const key_len: usize = try reader.readByte();
            const key = try reader.take(key_len);
            const expires_ms = try reader.readI64();
            const owner_tag = try reader.readByte();
            const owner: ?[]const u8 = if (owner_tag == 1) blk: {
                const owner_len: usize = try reader.readU32();
                break :blk try reader.take(owner_len);
            } else null;
            const owned_key = try allocator.dupe(u8, key);
            errdefer allocator.free(owned_key);
            const owned_owner: ?[]u8 = if (owner) |value| try allocator.dupe(u8, value) else null;
            errdefer if (owned_owner) |value| allocator.free(value);
            try restored.held.putNoClobber(allocator, owned_key, .{
                .expires_ms = expires_ms,
                .owner = owned_owner,
            });
        }
        std.debug.assert(reader.remaining() == 0);
        return restored;
    }

    pub fn replaceFromUpgradeCheckpoint(
        self: *NickDelay,
        expected_delay_ms: u64,
        bytes: []const u8,
    ) CheckpointError!void {
        var replacement = try restoreUpgradeCheckpoint(self.allocator, expected_delay_ms, bytes);
        const old = self.*;
        self.* = replacement;
        replacement = old;
        replacement.deinit();
    }
};

fn isCanonicalNick(key: []const u8) bool {
    for (key) |c| if (c != std.ascii.toLower(c)) return false;
    return true;
}

fn keyLess(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

fn checkpointAddLen(total: *usize, amount: usize) CheckpointError!void {
    total.* = std.math.add(usize, total.*, amount) catch return error.CheckpointTooLarge;
    if (total.* > max_checkpoint_bytes) return error.CheckpointTooLarge;
}

fn checkpointChecksum(bytes: []const u8, out: *[checkpoint_checksum_len]u8) void {
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update(checkpoint_domain);
    hasher.update(bytes);
    hasher.final(out);
}

const CheckpointWriter = struct {
    bytes: []u8,
    pos: usize = 0,

    fn writeBytes(self: *CheckpointWriter, value: []const u8) void {
        @memcpy(self.bytes[self.pos..][0..value.len], value);
        self.pos += value.len;
    }

    fn writeByte(self: *CheckpointWriter, value: u8) void {
        self.bytes[self.pos] = value;
        self.pos += 1;
    }

    fn writeU32(self: *CheckpointWriter, value: u32) void {
        std.mem.writeInt(u32, self.bytes[self.pos..][0..4], value, .little);
        self.pos += 4;
    }

    fn writeU64(self: *CheckpointWriter, value: u64) void {
        std.mem.writeInt(u64, self.bytes[self.pos..][0..8], value, .little);
        self.pos += 8;
    }

    fn writeI64(self: *CheckpointWriter, value: i64) void {
        std.mem.writeInt(i64, self.bytes[self.pos..][0..8], value, .little);
        self.pos += 8;
    }
};

const CheckpointReader = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn remaining(self: *const CheckpointReader) usize {
        return self.bytes.len - self.pos;
    }

    fn take(self: *CheckpointReader, len: usize) CheckpointError![]const u8 {
        if (len > self.remaining()) return error.Truncated;
        const result = self.bytes[self.pos..][0..len];
        self.pos += len;
        return result;
    }

    fn readByte(self: *CheckpointReader) CheckpointError!u8 {
        return (try self.take(1))[0];
    }

    fn readU32(self: *CheckpointReader) CheckpointError!u32 {
        return std.mem.readInt(u32, (try self.take(4))[0..4], .little);
    }

    fn readU64(self: *CheckpointReader) CheckpointError!u64 {
        return std.mem.readInt(u64, (try self.take(8))[0..8], .little);
    }

    fn readI64(self: *CheckpointReader) CheckpointError!i64 {
        return std.mem.readInt(i64, (try self.take(8))[0..8], .little);
    }
};

// -- Tests -------------------------------------------------------------------

test "held nick is reported within the window and evicted after it lapses" {
    var nd = NickDelay.init(std.testing.allocator);
    defer nd.deinit();

    try nd.hold("Alice", 1000, null);
    // Case-insensitive: "alice" matches the held "Alice".
    try std.testing.expect(nd.check("alice", 500) != null);
    // At/after the deadline the hold lapses and is evicted in passing.
    try std.testing.expect(nd.check("alice", 1000) == null);
    try std.testing.expectEqual(@as(usize, 0), nd.count());
}

test "owner account is recorded and returned for reclaim checks" {
    var nd = NickDelay.init(std.testing.allocator);
    defer nd.deinit();

    try nd.hold("Bob", 2000, "bob-acct");
    const h = nd.check("bob", 100) orelse return error.TestUnexpectedResult;
    try std.testing.expect(h.owner != null);
    try std.testing.expectEqualStrings("bob-acct", h.owner.?);
}

test "explicit release drops the hold immediately" {
    var nd = NickDelay.init(std.testing.allocator);
    defer nd.deinit();

    try nd.hold("Carol", 5000, "carol");
    nd.release("CAROL");
    try std.testing.expect(nd.check("carol", 0) == null);
    try std.testing.expectEqual(@as(usize, 0), nd.count());
}

test "hold replaces a prior entry and frees the old owner" {
    var nd = NickDelay.init(std.testing.allocator);
    defer nd.deinit();

    try nd.hold("Dave", 1000, "old-acct");
    try nd.hold("dave", 9000, "new-acct"); // same nick, new deadline + owner
    try std.testing.expectEqual(@as(usize, 1), nd.count());
    const h = nd.check("Dave", 8000) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("new-acct", h.owner.?);
}

test "sweep evicts only the expired entries" {
    var nd = NickDelay.init(std.testing.allocator);
    defer nd.deinit();

    try nd.hold("aaa", 100, null);
    try nd.hold("bbb", 100, null);
    try nd.hold("ccc", 9000, null);
    const removed = nd.sweep(500);
    try std.testing.expectEqual(@as(usize, 2), removed);
    try std.testing.expectEqual(@as(usize, 1), nd.count());
    try std.testing.expect(nd.check("ccc", 500) != null);
}

test "nick delay checkpoint preserves owners, deadlines, and unswept expiry" {
    var source = NickDelay.init(std.testing.allocator);
    defer source.deinit();
    try source.hold("Gamma", 100, "");
    try source.hold("Alpha", 900, "Acct");
    try source.hold("Beta", -5, null);
    const wire = try source.exportUpgradeCheckpoint(std.testing.allocator, 700);
    defer std.testing.allocator.free(wire);
    try validateUpgradeCheckpoint(wire);
    var restored = try NickDelay.restoreUpgradeCheckpoint(std.testing.allocator, 700, wire);
    defer restored.deinit();
    try std.testing.expectEqual(@as(usize, 3), restored.count());
    try std.testing.expectEqual(@as(i64, -5), restored.held.get("beta").?.expires_ms);
    try std.testing.expect(restored.held.get("beta").?.owner == null);
    try std.testing.expectEqualStrings("Acct", restored.check("ALPHA", 800).?.owner.?);
    try std.testing.expectEqualStrings("", restored.check("gamma", 0).?.owner.?);
    const reencoded = try restored.exportUpgradeCheckpoint(std.testing.allocator, 700);
    defer std.testing.allocator.free(reencoded);
    try std.testing.expectEqualSlices(u8, wire, reencoded);
    try std.testing.expect(restored.check("beta", 0) == null);
    try std.testing.expectEqual(@as(usize, 2), restored.count());

    var reverse = NickDelay.init(std.testing.allocator);
    defer reverse.deinit();
    try reverse.hold("Beta", -5, null);
    try reverse.hold("Alpha", 900, "Acct");
    try reverse.hold("Gamma", 100, "");
    const reverse_wire = try reverse.exportUpgradeCheckpoint(std.testing.allocator, 700);
    defer std.testing.allocator.free(reverse_wire);
    try std.testing.expectEqualSlices(u8, wire, reverse_wire);
}

test "nick delay checkpoint rejects malformed rows and policy mismatch" {
    var source = NickDelay.init(std.testing.allocator);
    defer source.deinit();
    try source.hold("aa", 100, null);
    try source.hold("bb", 200, "owner");
    const wire = try source.exportUpgradeCheckpoint(std.testing.allocator, 50);
    defer std.testing.allocator.free(wire);
    for (0..wire.len) |n| {
        try std.testing.expectError(error.Truncated, NickDelay.restoreUpgradeCheckpoint(std.testing.allocator, 50, wire[0..n]));
    }
    try std.testing.expectError(error.ConfigMismatch, NickDelay.restoreUpgradeCheckpoint(std.testing.allocator, 51, wire));

    var damaged = try std.testing.allocator.dupe(u8, wire);
    defer std.testing.allocator.free(damaged);
    damaged[4] = 2;
    try std.testing.expectError(error.UnsupportedVersion, validateUpgradeCheckpoint(damaged));
    damaged[4] = checkpoint_version;
    damaged[checkpoint_header_len + 1] ^= 1;
    try std.testing.expectError(error.ChecksumMismatch, validateUpgradeCheckpoint(damaged));

    @memcpy(damaged, wire);
    const second_key_offset = checkpoint_header_len + (checkpoint_row_min_len - 1 + 2) + 1;
    @memcpy(damaged[second_key_offset..][0..2], "aa");
    testRechecksum(damaged);
    try std.testing.expectError(error.NonCanonicalOrder, validateUpgradeCheckpoint(damaged));

    @memcpy(damaged, wire);
    damaged[checkpoint_header_len + 1] = 'A';
    testRechecksum(damaged);
    try std.testing.expectError(error.InvalidField, validateUpgradeCheckpoint(damaged));

    @memcpy(damaged, wire);
    damaged[checkpoint_header_len + 1 + 2 + 8] = 2;
    testRechecksum(damaged);
    try std.testing.expectError(error.InvalidField, validateUpgradeCheckpoint(damaged));

    @memcpy(damaged, wire);
    const second_owner_len_offset = checkpoint_header_len + (checkpoint_row_min_len - 1 + 2) + 1 + 2 + 8 + 1;
    std.mem.writeInt(u32, damaged[second_owner_len_offset..][0..4], max_checkpoint_owner_bytes + 1, .little);
    testRechecksum(damaged);
    try std.testing.expectError(error.CheckpointTooLarge, validateUpgradeCheckpoint(damaged));

    const trailing = try std.testing.allocator.alloc(u8, wire.len + 1);
    defer std.testing.allocator.free(trailing);
    @memcpy(trailing[0..wire.len], wire);
    trailing[wire.len] = 0;
    try std.testing.expectError(error.TrailingBytes, validateUpgradeCheckpoint(trailing));
}

test "nick delay checkpoint replacement is atomic across allocation failures" {
    var source = NickDelay.init(std.testing.allocator);
    defer source.deinit();
    try source.hold("alice", 100, "acct");
    try source.hold("bob", 200, null);
    const EncodeSweep = struct {
        fn run(allocator: std.mem.Allocator, nd: *const NickDelay) !void {
            const bytes = try nd.exportUpgradeCheckpoint(allocator, 50);
            defer allocator.free(bytes);
            try std.testing.expectEqual(@as(usize, 2), nd.count());
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, EncodeSweep.run, .{&source});
    const wire = try source.exportUpgradeCheckpoint(std.testing.allocator, 50);
    defer std.testing.allocator.free(wire);
    const RestoreSweep = struct {
        fn run(allocator: std.mem.Allocator, bytes: []const u8) !void {
            var target = NickDelay.init(allocator);
            defer target.deinit();
            try target.hold("keeper", 999, "old");
            target.replaceFromUpgradeCheckpoint(50, bytes) catch |err| {
                try std.testing.expectEqual(@as(usize, 1), target.count());
                try std.testing.expectEqualStrings("old", target.check("keeper", 0).?.owner.?);
                return err;
            };
            try std.testing.expectEqual(@as(usize, 2), target.count());
            try std.testing.expect(target.check("keeper", 0) == null);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, RestoreSweep.run, .{wire});
}

fn testRechecksum(bytes: []u8) void {
    var digest: [checkpoint_checksum_len]u8 = undefined;
    checkpointChecksum(bytes[0 .. bytes.len - checkpoint_checksum_len], &digest);
    @memcpy(bytes[bytes.len - checkpoint_checksum_len ..], &digest);
}
