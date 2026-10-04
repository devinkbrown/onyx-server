// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Original signed complete origin retirement cut. Active counters are only
//! exceptions to retirement; they prove neither presence nor reachability.
//! There is no expiry: permanent negative evidence must survive cold/Helix repair.
//! Decode, verify, approve the full origin key and initially admit the clock
//! before retaining or applying any negative proof.
const std = @import("std");
const sign = @import("../crypto/sign.zig");

pub const domain = "onyx-mesh-presence-frontier-v1";
pub const magic = "OPRF";
pub const version: u8 = 1;
pub const max_active: usize = 4096;
pub const prefix_len: usize = 4 + 1 + 32 + 8 * 4 + 2;
pub const max_wire_len: usize = prefix_len + max_active * 8 + sign.signature_len;
pub const Error = error{ Truncated, BadVersion, InvalidField, TrailingBytes, BadSignature, OriginMismatch, FutureIssued, InvalidClock };

pub const Record = struct {
    origin: sign.PublicKey,
    epoch: u64,
    revision: u64,
    through: u64,
    issued_ms: i64,
    /// Strictly increasing, nonzero counters within the complete prefix.
    active: []const u64,
};

pub const Decoded = struct {
    origin: sign.PublicKey,
    epoch: u64,
    revision: u64,
    through: u64,
    issued_ms: i64,
    /// Borrowed immutable network-order counters, validated and sorted.
    active_bytes: []const u8,
    wire: []const u8,

    pub fn count(self: Decoded) usize {
        return self.active_bytes.len / 8;
    }

    pub fn counter(self: Decoded, index: usize) u64 {
        std.debug.assert(index < self.count());
        return std.mem.readInt(u64, self.active_bytes[index * 8 ..][0..8], .big);
    }

    pub fn contains(self: Decoded, value: u64) bool {
        var lo: usize = 0;
        var hi = self.count();
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            const found = self.counter(mid);
            if (found == value) return true;
            if (found < value) lo = mid + 1 else hi = mid;
        }
        return false;
    }

    /// The candidate's full origin is mandatory: a certificate for one node
    /// must never compact another node's subjects with matching counters.
    pub fn retires(self: Decoded, origin: sign.PublicKey, epoch: u64, value: u64) bool {
        if (!std.mem.eql(u8, &origin, &self.origin) or epoch == 0 or value == 0) return false;
        if (epoch < self.epoch) return true;
        return epoch == self.epoch and value <= self.through and !self.contains(value);
    }

    pub fn verify(self: Decoded) Error!void {
        const body_end = self.wire.len - sign.signature_len;
        const signature: sign.Signature = self.wire[body_end..][0..sign.signature_len].*;
        const valid = sign.verifyCtx(domain, self.wire[0..body_end], signature, self.origin) catch return error.BadSignature;
        if (!valid) return error.BadSignature;
    }

    /// INITIAL admission eligibility only; never re-run this check to revoke
    /// already retained retirement after a wall-clock rollback. Age
    /// never expires this proof; current root approval remains caller-owned.
    pub fn validateClock(self: Decoded, now_ms: i64, future_skew_ms: i64) Error!void {
        if (now_ms < 0 or future_skew_ms < 0 or self.issued_ms < 0) return error.InvalidClock;
        if (self.issued_ms > now_ms and self.issued_ms - now_ms > future_skew_ms) return error.FutureIssued;
    }
};

pub const Update = enum { duplicate, obsolete, advance, conflict };

fn consistentProgress(older: Decoded, newer: Decoded) bool {
    if (newer.through < older.through) return false;
    for (0..newer.count()) |index| {
        const value = newer.counter(index);
        if (value <= older.through and !older.contains(value)) return false;
    }
    return true;
}

/// Compare independently authenticated, admitted, immutable same-origin cuts.
/// A late older cut can prove that the newer cut resurrected a retired counter.
/// Caller must retain conflict evidence and keep origin quarantine irreversible.
pub fn compare(current: Decoded, incoming: Decoded) Error!Update {
    if (!std.mem.eql(u8, &current.origin, &incoming.origin)) return error.OriginMismatch;
    if (incoming.epoch < current.epoch) return .obsolete;
    if (incoming.epoch > current.epoch) return .advance;
    if (incoming.revision == current.revision) {
        const current_body = current.wire[0 .. current.wire.len - sign.signature_len];
        const incoming_body = incoming.wire[0 .. incoming.wire.len - sign.signature_len];
        return if (std.mem.eql(u8, current_body, incoming_body)) .duplicate else .conflict;
    }
    if (incoming.revision < current.revision) {
        return if (consistentProgress(incoming, current)) .obsolete else .conflict;
    }
    return if (consistentProgress(current, incoming)) .advance else .conflict;
}

fn validHeader(epoch: u64, revision: u64, issued_ms: i64, count: usize) Error!void {
    if (epoch == 0 or revision == 0 or issued_ms < 0 or count > max_active) return error.InvalidField;
}

pub fn encode(record: Record, key: *const sign.KeyPair, out: []u8) ![]const u8 {
    try validHeader(record.epoch, record.revision, record.issued_ms, record.active.len);
    var prior: u64 = 0;
    for (record.active) |counter| {
        if (counter <= prior or counter > record.through) return error.InvalidField;
        prior = counter;
    }
    if (!std.mem.eql(u8, &record.origin, &key.public_key)) return error.OriginMismatch;
    const length = prefix_len + record.active.len * 8 + sign.signature_len;
    if (out.len < length) return error.Truncated;
    @memcpy(out[0..4], magic);
    out[4] = version;
    @memcpy(out[5..37], &record.origin);
    std.mem.writeInt(u64, out[37..45], record.epoch, .big);
    std.mem.writeInt(u64, out[45..53], record.revision, .big);
    std.mem.writeInt(u64, out[53..61], record.through, .big);
    std.mem.writeInt(i64, out[61..69], record.issued_ms, .big);
    std.mem.writeInt(u16, out[69..71], @intCast(record.active.len), .big);
    for (record.active, 0..) |counter, index| std.mem.writeInt(u64, out[prefix_len + index * 8 ..][0..8], counter, .big);
    const end = length - sign.signature_len;
    const signature = try key.signCtx(domain, out[0..end]);
    @memcpy(out[end..][0..sign.signature_len], &signature);
    return out[0..length];
}

/// Structural decode only; caller keeps wire immutable through all uses.
pub fn decode(original: []const u8) Error!Decoded {
    if (original.len < prefix_len + sign.signature_len) return error.Truncated;
    if (!std.mem.eql(u8, original[0..4], magic) or original[4] != version) return error.BadVersion;
    const epoch = std.mem.readInt(u64, original[37..45], .big);
    const revision = std.mem.readInt(u64, original[45..53], .big);
    const issued = std.mem.readInt(i64, original[61..69], .big);
    const count = std.mem.readInt(u16, original[69..71], .big);
    try validHeader(epoch, revision, issued, count);
    const expected = prefix_len + @as(usize, count) * 8 + sign.signature_len;
    if (original.len < expected) return error.Truncated;
    if (original.len != expected) return error.TrailingBytes;
    const decoded: Decoded = .{ .origin = original[5..37].*, .epoch = epoch, .revision = revision, .through = std.mem.readInt(u64, original[53..61], .big), .issued_ms = issued, .active_bytes = original[prefix_len .. expected - sign.signature_len], .wire = original };
    var prior: u64 = 0;
    for (0..decoded.count()) |index| {
        const counter = decoded.counter(index);
        if (counter <= prior or counter > decoded.through) return error.InvalidField;
        prior = counter;
    }
    return decoded;
}

fn fixture(origin: sign.PublicKey) Record {
    return .{ .origin = origin, .epoch = 3, .revision = 9, .through = 1000, .issued_ms = 1000, .active = &.{ 1, 999 } };
}

test "mesh presence frontier long lived exception and permanent epoch retirement" {
    var key = try sign.KeyPair.fromSeed(@splat(72));
    defer key.deinit();
    const buffer = try std.testing.allocator.alloc(u8, max_wire_len);
    defer std.testing.allocator.free(buffer);
    const original = try encode(fixture(key.public_key), &key, buffer);
    const decoded = try decode(original);
    try decoded.verify();
    try std.testing.expect(!decoded.retires(key.public_key, 3, 1));
    try std.testing.expect(decoded.retires(key.public_key, 3, 2));
    try std.testing.expect(decoded.retires(key.public_key, 3, 1000));
    try std.testing.expect(!decoded.retires(key.public_key, 3, 1001));
    try std.testing.expect(decoded.retires(key.public_key, 2, std.math.maxInt(u64)));
    try std.testing.expect(!decoded.retires(key.public_key, 4, 1));
    try std.testing.expect(!decoded.retires(@splat(0), 2, 1));
    try std.testing.expect(!decoded.retires(key.public_key, 0, 1));
    try std.testing.expect(!decoded.retires(key.public_key, 3, 0));
    try decoded.validateClock(std.math.maxInt(i64), 0);
    try std.testing.expectError(error.FutureIssued, decoded.validateClock(0, 999));
}

test "mesh presence frontier sorted complete prefix rejects invalid exceptions" {
    var key = try sign.KeyPair.fromSeed(@splat(73));
    defer key.deinit();
    const buffer = try std.testing.allocator.alloc(u8, max_wire_len);
    defer std.testing.allocator.free(buffer);
    var record = fixture(key.public_key);
    for ([_][]const u64{ &.{0}, &.{ 1, 1 }, &.{ 2, 1 }, &.{1001} }) |active| {
        record.active = active;
        try std.testing.expectError(error.InvalidField, encode(record, &key, buffer));
    }
    record.active = &.{};
    record.through = 0;
    try (try decode(try encode(record, &key, buffer))).verify();
}

test "mesh presence frontier authenticates every byte and rejects truncation" {
    var key = try sign.KeyPair.fromSeed(@splat(74));
    defer key.deinit();
    const buffer = try std.testing.allocator.alloc(u8, max_wire_len);
    defer std.testing.allocator.free(buffer);
    const original = try encode(fixture(key.public_key), &key, buffer);
    for (0..original.len) |index| {
        if (decode(original[0..index])) |_| return error.TestUnexpectedResult else |_| {}
        buffer[index] ^= 1;
        if (decode(original)) |decoded| try std.testing.expectError(error.BadSignature, decoded.verify()) else |_| {}
        buffer[index] ^= 1;
    }
    buffer[original.len] = 0;
    try std.testing.expectError(error.TrailingBytes, decode(buffer[0 .. original.len + 1]));
}

test "mesh presence frontier progress forbids resurrection in either arrival order" {
    var key = try sign.KeyPair.fromSeed(@splat(75));
    defer key.deinit();
    const first_buffer = try std.testing.allocator.alloc(u8, max_wire_len);
    defer std.testing.allocator.free(first_buffer);
    const second_buffer = try std.testing.allocator.alloc(u8, max_wire_len);
    defer std.testing.allocator.free(second_buffer);
    var older = fixture(key.public_key);
    older.through = 3;
    older.active = &.{1};
    const first = try decode(try encode(older, &key, first_buffer));
    try first.verify();
    var newer = older;
    newer.revision += 1;
    newer.through = 4;
    newer.active = &.{ 1, 4 };
    var second = try decode(try encode(newer, &key, second_buffer));
    try second.verify();
    try std.testing.expectEqual(Update.advance, try compare(first, second));
    try std.testing.expectEqual(Update.obsolete, try compare(second, first));
    newer.active = &.{ 1, 2, 4 };
    second = try decode(try encode(newer, &key, second_buffer));
    try second.verify();
    try std.testing.expectEqual(Update.conflict, try compare(first, second));
    try std.testing.expectEqual(Update.conflict, try compare(second, first));
    newer.active = &.{1};
    newer.through = 2;
    second = try decode(try encode(newer, &key, second_buffer));
    try std.testing.expectEqual(Update.conflict, try compare(first, second));
    newer.epoch += 1;
    newer.revision = 1;
    newer.through = 0;
    newer.active = &.{};
    second = try decode(try encode(newer, &key, second_buffer));
    try std.testing.expectEqual(Update.advance, try compare(first, second));
    try std.testing.expectEqual(Update.obsolete, try compare(second, first));
}

test "mesh presence frontier bounds full active set without partial absence proof" {
    var key = try sign.KeyPair.fromSeed(@splat(76));
    defer key.deinit();
    const counters = try std.testing.allocator.alloc(u64, max_active + 1);
    defer std.testing.allocator.free(counters);
    for (counters, 0..) |*value, index| value.* = index + 1;
    const buffer = try std.testing.allocator.alloc(u8, max_wire_len);
    defer std.testing.allocator.free(buffer);
    var record = fixture(key.public_key);
    record.through = max_active;
    record.active = counters[0..max_active];
    const original = try encode(record, &key, buffer);
    try std.testing.expectEqual(@as(usize, max_wire_len), original.len);
    const decoded = try decode(original);
    try decoded.verify();
    try std.testing.expect(!decoded.retires(key.public_key, record.epoch, max_active));
    record.active = counters;
    try std.testing.expectError(error.InvalidField, encode(record, &key, buffer));
}
