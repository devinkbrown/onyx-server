// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Compact fallback wire form for a channel-CRDT member's causal context.
//!
//! The canonical member wire form (`delta_codec.DeltaView`, magic `"GDLT"`)
//! reconstructs a member's causal context by expanding its `VersionVector`
//! frontier into DENSE per-counter dots — `{(R,1), (R,2), … (R,counter)}`. That
//! expansion is bounded at `max_context_dots` (512), so on a busy channel where
//! one replica has authored more than 512 membership adds, the most recently
//! joined members carry `context.counter(R) > 512` and the dense form returns
//! `error.Oversize`. That silently disables the burst and Merkle anti-entropy
//! backstops for the whole channel.
//!
//! A member receiver only ever consumes the folded-back context frontier plus
//! the live adds — it never reads the dense removes. This form therefore
//! transmits the context as the COMPACT frontier it already is (a list of at
//! most `VersionVector.max_entries` `(replica, counter)` pairs) plus the live
//! adds, with no dense expansion and no unbounded byte cost.
//!
//! Wire compatibility: this is a self-describing, additive alternative. Callers
//! keep emitting the canonical dense `"GDLT"` form byte-for-byte whenever it
//! fits (so a legacy peer still parses it and Merkle hashes still match), and
//! fall back to this compact form ONLY for members the dense form could neither
//! encode nor consume. A legacy peer that sees this distinct `"GMBC"` magic
//! rejects it fail-closed (`BadMagic`/`UnknownRecord`), exactly as it already
//! failed on those members — no silent divergence, no cross-version corruption.

const std = @import("std");
const clock = @import("clock.zig");

pub const magic = [_]u8{ 'G', 'M', 'B', 'C' };
pub const version: u8 = 1;

/// Frontier width matches `VersionVector.max_entries`, so a merged vector of
/// that many replicas round-trips. One more entry is `Oversize`.
pub const max_context = clock.VersionVector.max_entries;
/// Live adds carried per member. Matches the dense codec's `max_adds` bound so a
/// member the dense form accepts on adds is never rejected here for adds alone.
pub const max_adds = 128;
/// Serialized `{replica, counter, hlc, status}` add value — identical layout to
/// the dense codec's add value, so callers reuse their existing add codecs.
pub const add_value_len = 25;

const varint_max = 10;

/// Upper bound on a single encoded compact member payload.
pub const max_bytes = magic.len + 1 + 8 + 8 +
    varint_max + max_context * 16 +
    varint_max + max_adds * add_value_len;

pub const Entry = struct { replica: u64, counter: u64 };

pub const DecodeError = error{
    Truncated,
    BadMagic,
    UnsupportedVersion,
    Oversize,
    InvalidMember,
    TrailingBytes,
    VarintTooLong,
    VarintOverflow,
    NonCanonicalVarint,
};

pub const EncodeError = error{ BufferTooSmall, Oversize, InvalidMember };

/// Decoded, alloc-free view. Add values point into the caller's decode buffer.
pub const View = struct {
    member_id: u64,
    hlc_key: u64,
    context: [max_context]Entry = undefined,
    context_len: usize = 0,
    adds: [max_adds][add_value_len]u8 = undefined,
    adds_len: usize = 0,
};

/// True when `bytes` begins with the compact member magic.
pub fn matches(bytes: []const u8) bool {
    return bytes.len >= magic.len and std.mem.eql(u8, bytes[0..magic.len], &magic);
}

fn lessEntry(_: void, a: Entry, b: Entry) bool {
    if (a.replica != b.replica) return a.replica < b.replica;
    return a.counter < b.counter;
}

fn lessAdd(_: void, a: [add_value_len]u8, b: [add_value_len]u8) bool {
    return std.mem.order(u8, &a, &b) == .lt;
}

fn readAddU64(add: *const [add_value_len]u8, offset: usize) u64 {
    var value: u64 = 0;
    var idx: usize = 0;
    while (idx < 8) : (idx += 1) {
        value |= @as(u64, add[offset + idx]) << @as(u6, @intCast(idx * 8));
    }
    return value;
}

fn contextCounter(context: []const Entry, replica: u64) u64 {
    for (context) |entry| {
        if (entry.replica == replica) return entry.counter;
    }
    return 0;
}

fn validateContext(context: []const Entry) error{InvalidMember}!void {
    var prev_replica: ?u64 = null;
    for (context) |entry| {
        if (entry.counter == 0) return error.InvalidMember;
        if (prev_replica) |prev| {
            // A VersionVector frontier carries one maximum counter per replica,
            // so equal replicas are duplicates even when their counters differ.
            if (entry.replica <= prev) return error.InvalidMember;
        }
        prev_replica = entry.replica;
    }
}

fn validateAdds(context: []const Entry, adds: []const [add_value_len]u8) error{InvalidMember}!void {
    for (adds, 0..) |*add, idx| {
        const replica = readAddU64(add, 0);
        const counter = readAddU64(add, 8);
        if (counter == 0 or contextCounter(context, replica) < counter) return error.InvalidMember;
        if (idx > 0) {
            if (std.mem.order(u8, &adds[idx - 1], add) != .lt) return error.InvalidMember;
            if (std.mem.eql(u8, adds[idx - 1][0..16], add[0..16])) return error.InvalidMember;
        }
    }
}

/// Encode a canonical compact member payload. The context frontier and add
/// values are sorted so equal logical state ALWAYS yields identical bytes,
/// regardless of the internal merge/delivery order of the caller's arrays. This
/// is load-bearing: anti-entropy hashes the encoded payload into a Merkle
/// digest, so two replicas that reached the same member state via different
/// orders must produce the same bytes or they would repair forever. Mirrors the
/// dense codec's `sortDots`/`sortAdds`.
pub fn encode(
    out: []u8,
    member_id: u64,
    hlc_key: u64,
    context: []const Entry,
    adds: []const [add_value_len]u8,
) EncodeError![]const u8 {
    if (context.len > max_context or adds.len > max_adds) return error.Oversize;

    var ctx: [max_context]Entry = undefined;
    @memcpy(ctx[0..context.len], context);
    std.mem.sort(Entry, ctx[0..context.len], {}, lessEntry);
    try validateContext(ctx[0..context.len]);

    var av: [max_adds][add_value_len]u8 = undefined;
    for (adds, 0..) |a, i| av[i] = a;
    std.mem.sort([add_value_len]u8, av[0..adds.len], {}, lessAdd);
    try validateAdds(ctx[0..context.len], av[0..adds.len]);

    var w = Writer{ .buf = out };
    try w.writeBytes(&magic);
    try w.writeU8(version);
    try w.writeU64(member_id);
    try w.writeU64(hlc_key);
    try w.writeVarint(context.len);
    for (ctx[0..context.len]) |e| {
        try w.writeU64(e.replica);
        try w.writeU64(e.counter);
    }
    try w.writeVarint(adds.len);
    for (av[0..adds.len]) |a| try w.writeBytes(&a);
    return w.written();
}

pub fn decode(bytes: []const u8) DecodeError!View {
    var r = Reader{ .buf = bytes };
    for (magic) |want| {
        if (try r.readU8() != want) return error.BadMagic;
    }
    if (try r.readU8() != version) return error.UnsupportedVersion;

    var v = View{ .member_id = try r.readU64(), .hlc_key = try r.readU64() };

    const cc = try r.readVarint();
    if (cc > max_context) return error.Oversize;
    v.context_len = cc;
    var i: usize = 0;
    var prev_entry: ?Entry = null;
    while (i < cc) : (i += 1) {
        const replica = try r.readU64();
        const counter = try r.readU64();
        const entry = Entry{ .replica = replica, .counter = counter };
        // Enforce the canonical strict-replica order the encoder emits. A
        // frontier has one maximum counter per replica; accepting two counters
        // for one replica would admit multiple bytes for the same logical state.
        if (entry.counter == 0) return error.InvalidMember;
        if (prev_entry) |p| if (entry.replica <= p.replica) return error.InvalidMember;
        prev_entry = entry;
        v.context[i] = entry;
    }

    const ac = try r.readVarint();
    if (ac > max_adds) return error.Oversize;
    v.adds_len = ac;
    i = 0;
    while (i < ac) : (i += 1) {
        const slice = try r.readFixed(add_value_len);
        @memcpy(&v.adds[i], slice);
    }
    try validateAdds(v.context[0..v.context_len], v.adds[0..v.adds_len]);

    if (!r.done()) return error.TrailingBytes;
    return v;
}

const Writer = struct {
    buf: []u8,
    pos: usize = 0,

    fn written(self: *const Writer) []const u8 {
        return self.buf[0..self.pos];
    }
    fn writeU8(self: *Writer, value: u8) EncodeError!void {
        if (self.pos + 1 > self.buf.len) return error.BufferTooSmall;
        self.buf[self.pos] = value;
        self.pos += 1;
    }
    fn writeU64(self: *Writer, value: u64) EncodeError!void {
        if (self.pos + 8 > self.buf.len) return error.BufferTooSmall;
        var idx: usize = 0;
        while (idx < 8) : (idx += 1) {
            self.buf[self.pos + idx] = @intCast((value >> @as(u6, @intCast(idx * 8))) & 0xff);
        }
        self.pos += 8;
    }
    fn writeVarint(self: *Writer, value: usize) EncodeError!void {
        var n: u64 = value;
        while (n >= 0x80) {
            try self.writeU8(@as(u8, @intCast(n & 0x7f)) | 0x80);
            n >>= 7;
        }
        try self.writeU8(@intCast(n));
    }
    fn writeBytes(self: *Writer, bytes: []const u8) EncodeError!void {
        if (self.pos + bytes.len > self.buf.len) return error.BufferTooSmall;
        @memcpy(self.buf[self.pos .. self.pos + bytes.len], bytes);
        self.pos += bytes.len;
    }
};

const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn done(self: *const Reader) bool {
        return self.pos == self.buf.len;
    }
    fn readU8(self: *Reader) DecodeError!u8 {
        if (self.pos >= self.buf.len) return error.Truncated;
        const byte = self.buf[self.pos];
        self.pos += 1;
        return byte;
    }
    fn readU64(self: *Reader) DecodeError!u64 {
        if (self.pos + 8 > self.buf.len) return error.Truncated;
        var value: u64 = 0;
        var idx: usize = 0;
        while (idx < 8) : (idx += 1) {
            value |= @as(u64, self.buf[self.pos + idx]) << @as(u6, @intCast(idx * 8));
        }
        self.pos += 8;
        return value;
    }
    fn readVarint(self: *Reader) DecodeError!usize {
        const start = self.pos;
        var pos = self.pos;
        var value: u64 = 0;
        var i: usize = 0;
        while (i < varint_max) : (i += 1) {
            if (pos >= self.buf.len) return error.Truncated;
            const byte = self.buf[pos];
            pos += 1;
            const payload = byte & 0x7f;
            if (i == varint_max - 1 and payload > 1) return error.VarintOverflow;
            value |= @as(u64, payload) << @as(u6, @intCast(i * 7));
            if ((byte & 0x80) == 0) {
                if (i + 1 != varintLen(value)) {
                    self.pos = start;
                    return error.NonCanonicalVarint;
                }
                if (value > std.math.maxInt(usize)) return error.Oversize;
                self.pos = pos;
                return @intCast(value);
            }
        }
        self.pos = start;
        return error.VarintTooLong;
    }
    fn readFixed(self: *Reader, len: usize) DecodeError![]const u8 {
        if (self.pos + len > self.buf.len) return error.Truncated;
        const bytes = self.buf[self.pos .. self.pos + len];
        self.pos += len;
        return bytes;
    }
};

fn varintLen(value: u64) usize {
    var n = value;
    var len: usize = 1;
    while (n >= 0x80) : (len += 1) n >>= 7;
    return len;
}

test "Undertow mesh member_compact round-trips context frontier and adds" {
    var ctx = [_]Entry{
        .{ .replica = 1, .counter = 900 },
        .{ .replica = 7, .counter = 3 },
    };
    var adds: [1][add_value_len]u8 = undefined;
    // replica8, counter8, hlc8, status1
    @memset(&adds[0], 0);
    adds[0][0] = 1; // replica = 1 (LE)
    adds[0][8] = 0x84; // counter low byte = 900 & 0xff
    adds[0][9] = 0x03; // counter high byte -> 0x0384 == 900
    adds[0][24] = 0x02; // some status bits

    var buf: [max_bytes]u8 = undefined;
    const bytes = try encode(&buf, 42, 0, ctx[0..], adds[0..]);
    try std.testing.expect(matches(bytes));

    const v = try decode(bytes);
    try std.testing.expectEqual(@as(u64, 42), v.member_id);
    try std.testing.expectEqual(@as(u64, 0), v.hlc_key);
    try std.testing.expectEqual(@as(usize, 2), v.context_len);
    try std.testing.expectEqual(@as(u64, 1), v.context[0].replica);
    try std.testing.expectEqual(@as(u64, 900), v.context[0].counter);
    try std.testing.expectEqual(@as(u64, 7), v.context[1].replica);
    try std.testing.expectEqual(@as(u64, 3), v.context[1].counter);
    try std.testing.expectEqual(@as(usize, 1), v.adds_len);
    try std.testing.expectEqualSlices(u8, &adds[0], &v.adds[0]);
}

test "Undertow mesh member_compact rejects malformed frames fail-closed" {
    var buf: [max_bytes]u8 = undefined;
    var ctx = [_]Entry{.{ .replica = 1, .counter = 5 }};
    const bytes = try encode(&buf, 1, 0, ctx[0..], &.{});

    // Wrong magic.
    var bad_magic = buf;
    bad_magic[0] = 'X';
    try std.testing.expectError(error.BadMagic, decode(bad_magic[0..bytes.len]));

    // Truncated.
    try std.testing.expectError(error.Truncated, decode(bytes[0 .. bytes.len - 1]));

    // Trailing bytes.
    var trailing: [max_bytes + 1]u8 = undefined;
    @memcpy(trailing[0..bytes.len], bytes);
    trailing[bytes.len] = 0;
    try std.testing.expectError(error.TrailingBytes, decode(trailing[0 .. bytes.len + 1]));

    // Zero-counter context entry is rejected.
    var zero = buf;
    // context entry counter occupies 8 bytes right after: magic(4)+ver(1)+id(8)+hlc(8)+ctxlen varint(1)+replica(8)
    const counter_off = magic.len + 1 + 8 + 8 + 1 + 8;
    @memset(zero[counter_off .. counter_off + 8], 0);
    try std.testing.expectError(error.InvalidMember, decode(zero[0..bytes.len]));
}

test "Undertow mesh member_compact encode is canonical regardless of input order" {
    // Two replicas reaching the same logical member state via different merge
    // orders must produce byte-identical payloads, or the anti-entropy Merkle
    // digest never converges and the channel repairs forever.
    var ctx_a = [_]Entry{ .{ .replica = 5, .counter = 2 }, .{ .replica = 1, .counter = 900 } };
    var ctx_b = [_]Entry{ .{ .replica = 1, .counter = 900 }, .{ .replica = 5, .counter = 2 } };

    var add0: [add_value_len]u8 = undefined;
    var add1: [add_value_len]u8 = undefined;
    @memset(&add0, 0);
    @memset(&add1, 0);
    add0[0] = 1; // dot replica 1
    add0[8] = 1; // dot counter 1
    add1[0] = 5; // dot replica 5
    add1[8] = 1; // dot counter 1
    var adds_a = [_][add_value_len]u8{ add1, add0 };
    var adds_b = [_][add_value_len]u8{ add0, add1 };

    var buf_a: [max_bytes]u8 = undefined;
    var buf_b: [max_bytes]u8 = undefined;
    const a = try encode(&buf_a, 9, 0, ctx_a[0..], adds_a[0..]);
    const b = try encode(&buf_b, 9, 0, ctx_b[0..], adds_b[0..]);
    try std.testing.expectEqualSlices(u8, a, b);

    // Decode enforces the canonical order the encoder emits.
    const v = try decode(a);
    try std.testing.expectEqual(@as(u64, 1), v.context[0].replica);
    try std.testing.expectEqual(@as(u64, 5), v.context[1].replica);
}

test "Undertow mesh member_compact decode rejects non-canonical order" {
    // Hand-build a frame with descending context replicas (5 then 1).
    var buf: [max_bytes]u8 = undefined;
    var w = Writer{ .buf = &buf };
    try w.writeBytes(&magic);
    try w.writeU8(version);
    try w.writeU64(9); // member_id
    try w.writeU64(0); // hlc
    try w.writeVarint(2); // context_len
    try w.writeU64(5);
    try w.writeU64(1);
    try w.writeU64(1);
    try w.writeU64(1);
    try w.writeVarint(0); // adds
    try std.testing.expectError(error.InvalidMember, decode(w.written()));
}

test "Undertow mesh member_compact rejects duplicate frontier replicas" {
    // A version-vector frontier has exactly one counter per replica. Distinct
    // counters for the same replica are still a duplicate logical entry, not a
    // valid strictly-ascending frontier.
    var buf: [max_bytes]u8 = undefined;
    var w = Writer{ .buf = &buf };
    try w.writeBytes(&magic);
    try w.writeU8(version);
    try w.writeU64(9); // member_id
    try w.writeU64(0); // hlc
    try w.writeVarint(2); // context_len
    try w.writeU64(5);
    try w.writeU64(1);
    try w.writeU64(5);
    try w.writeU64(2);
    try w.writeVarint(0); // adds
    try std.testing.expectError(error.InvalidMember, decode(w.written()));
}

test "Undertow mesh member_compact rejects live adds outside the frontier" {
    var buf: [max_bytes]u8 = undefined;
    var w = Writer{ .buf = &buf };
    try w.writeBytes(&magic);
    try w.writeU8(version);
    try w.writeU64(9);
    try w.writeU64(0);
    try w.writeVarint(1);
    try w.writeU64(5); // context replica
    try w.writeU64(7); // context counter
    try w.writeVarint(1);
    var add: [add_value_len]u8 = @splat(0);
    add[0] = 5; // add replica
    add[8] = 8; // add counter exceeds the frontier
    try w.writeBytes(&add);
    try std.testing.expectError(error.InvalidMember, decode(w.written()));
}

test "Undertow mesh member_compact rejects non-canonical and overflowing varints" {
    var noncanonical_buf: [max_bytes]u8 = undefined;
    var noncanonical = Writer{ .buf = &noncanonical_buf };
    try noncanonical.writeBytes(&magic);
    try noncanonical.writeU8(version);
    try noncanonical.writeU64(9);
    try noncanonical.writeU64(0);
    try noncanonical.writeU8(0x80);
    try noncanonical.writeU8(0x00); // overlong encoding of context_len = 0
    try noncanonical.writeVarint(0); // adds
    try std.testing.expectError(error.NonCanonicalVarint, decode(noncanonical.written()));

    var overflow_buf: [max_bytes]u8 = undefined;
    var overflow = Writer{ .buf = &overflow_buf };
    try overflow.writeBytes(&magic);
    try overflow.writeU8(version);
    try overflow.writeU64(9);
    try overflow.writeU64(0);
    var i: usize = 0;
    while (i < varint_max - 1) : (i += 1) try overflow.writeU8(0xff);
    try overflow.writeU8(0x02); // tenth payload may contain at most bit 0
    try std.testing.expectError(error.VarintOverflow, decode(overflow.written()));
}

test "Undertow mesh member_compact encode rejects oversize context and adds" {
    var buf: [max_bytes]u8 = undefined;
    var big_ctx: [max_context + 1]Entry = undefined;
    for (&big_ctx, 0..) |*e, i| e.* = .{ .replica = i, .counter = 1 };
    try std.testing.expectError(error.Oversize, encode(&buf, 1, 0, big_ctx[0..], &.{}));
}

test "Undertow mesh member_compact encode rejects invalid logical state" {
    var buf: [max_bytes]u8 = undefined;
    const duplicate_ctx = [_]Entry{
        .{ .replica = 1, .counter = 1 },
        .{ .replica = 1, .counter = 2 },
    };
    try std.testing.expectError(error.InvalidMember, encode(&buf, 1, 0, &duplicate_ctx, &.{}));

    const ctx = [_]Entry{.{ .replica = 1, .counter = 5 }};
    var outside: [add_value_len]u8 = @splat(0);
    outside[0] = 1; // replica 1
    outside[8] = 6; // counter 6 is not covered by frontier counter 5
    try std.testing.expectError(error.InvalidMember, encode(&buf, 1, 0, &ctx, &.{outside}));
}

test "GAP-M1 65 replicas merge and round-trip member_compact" {
    var left = clock.VersionVector.init();
    var right = clock.VersionVector.init();
    var i: u64 = 0;
    while (i < 32) : (i += 1) _ = try left.increment(i);
    i = 0;
    while (i < 33) : (i += 1) _ = try right.increment(1_000 + i);

    try left.merge(&right);
    try std.testing.expectEqual(@as(usize, 65), left.len);

    // Callers copy the vector by value and size the compact buffer from the
    // same entry count. Both have to hold every replica.
    const copied = left;
    try std.testing.expectEqual(@as(usize, 65), copied.len);
    var ctx: [65]Entry = undefined;
    for (copied.entries[0..copied.len], 0..) |entry, idx| {
        ctx[idx] = .{ .replica = entry.replica, .counter = entry.counter };
    }

    var buf: [max_bytes]u8 = undefined;
    const bytes = try encode(&buf, 7, 1, ctx[0..], &.{});
    const view = try decode(bytes);
    try std.testing.expectEqual(@as(usize, 65), view.context_len);
    for (ctx, 0..) |entry, idx| {
        try std.testing.expectEqual(entry.replica, view.context[idx].replica);
        try std.testing.expectEqual(entry.counter, view.context[idx].counter);
    }

    var one_more = copied;
    try std.testing.expectError(error.CapacityExceeded, one_more.increment(9_000));
    std.debug.print("GAP-M1 branch=65 replicas merge and round-trip member_compact\n", .{});
}
