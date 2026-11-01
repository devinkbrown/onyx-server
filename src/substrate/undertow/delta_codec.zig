// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! UNDERTOW wire codec for Concord CRDT deltas.
//!
//! The codec is intentionally a narrow wire layer: it canonicalizes and
//! validates dotted OR-Set deltas plus their causal context, HLC, and
//! entity-family lane tag using CoilPack atoms. Decoding attacker bytes never
//! panics; accepted encodings are signature-stable byte strings.
const std = @import("std");

const clock = @import("clock.zig");
const concord = @import("concord.zig");

const coilpack = struct {
    const max_varint_bytes = 10;

    const CDecodeError = error{
        Truncated,
        VarintTooLong,
        VarintOverflow,
        NonCanonicalVarint,
        LengthTooLarge,
    };

    const CEncodeError = error{
        BufferTooSmall,
    };

    const DecodeError = CDecodeError;
    const EncodeError = CEncodeError;

    fn canonicalEqual(a: []const u8, b: []const u8) bool {
        return std.mem.eql(u8, a, b);
    }

    const Cbs = struct {
        buf: []const u8,
        pos: usize = 0,

        fn init(buf: []const u8) Cbs {
            return .{ .buf = buf };
        }

        fn remaining(self: *const Cbs) usize {
            return self.buf.len - self.pos;
        }

        fn done(self: *const Cbs) bool {
            return self.pos == self.buf.len;
        }

        fn readU8(self: *Cbs) CDecodeError!u8 {
            if (self.remaining() < 1) return error.Truncated;
            const value = self.buf[self.pos];
            self.pos += 1;
            return value;
        }

        fn readU64Le(self: *Cbs) CDecodeError!u64 {
            if (self.remaining() < 8) return error.Truncated;
            const p = self.pos;
            self.pos += 8;
            return @as(u64, self.buf[p]) |
                (@as(u64, self.buf[p + 1]) << 8) |
                (@as(u64, self.buf[p + 2]) << 16) |
                (@as(u64, self.buf[p + 3]) << 24) |
                (@as(u64, self.buf[p + 4]) << 32) |
                (@as(u64, self.buf[p + 5]) << 40) |
                (@as(u64, self.buf[p + 6]) << 48) |
                (@as(u64, self.buf[p + 7]) << 56);
        }

        fn readVarint(self: *Cbs) CDecodeError!u64 {
            const start = self.pos;
            var p = self.pos;
            var value: u64 = 0;

            var i: usize = 0;
            while (i < max_varint_bytes) : (i += 1) {
                if (p >= self.buf.len) return error.Truncated;

                const byte = self.buf[p];
                p += 1;
                const payload = byte & 0x7f;

                if (i == max_varint_bytes - 1 and payload > 1) {
                    return error.VarintOverflow;
                }

                value |= @as(u64, payload) << @as(u6, @intCast(i * 7));
                if ((byte & 0x80) == 0) {
                    if (i + 1 != varintLen(value)) {
                        self.pos = start;
                        return error.NonCanonicalVarint;
                    }
                    self.pos = p;
                    return value;
                }
            }

            self.pos = start;
            return error.VarintTooLong;
        }

        fn readBytes(self: *Cbs) CDecodeError![]const u8 {
            const start = self.pos;
            const len64 = self.readVarint() catch |err| {
                self.pos = start;
                return err;
            };
            if (len64 > @as(u64, std.math.maxInt(usize))) {
                self.pos = start;
                return error.LengthTooLarge;
            }

            const len: usize = @intCast(len64);
            if (self.remaining() < len) {
                self.pos = start;
                return error.Truncated;
            }

            const p = self.pos;
            self.pos += len;
            return self.buf[p..self.pos];
        }
    };

    const Cbb = struct {
        buf: []u8,
        pos: usize = 0,

        fn init(buf: []u8) Cbb {
            return .{ .buf = buf };
        }

        fn bytesWritten(self: *const Cbb) usize {
            return self.pos;
        }

        fn written(self: *const Cbb) []const u8 {
            return self.buf[0..self.pos];
        }

        fn remaining(self: *const Cbb) usize {
            return self.buf.len - self.pos;
        }

        fn writeU8(self: *Cbb, value: u8) CEncodeError!usize {
            try self.ensure(1);
            self.buf[self.pos] = value;
            self.pos += 1;
            return 1;
        }

        fn writeU64Le(self: *Cbb, value: u64) CEncodeError!usize {
            try self.ensure(8);
            const p = self.pos;
            self.buf[p] = @intCast(value & 0xff);
            self.buf[p + 1] = @intCast((value >> 8) & 0xff);
            self.buf[p + 2] = @intCast((value >> 16) & 0xff);
            self.buf[p + 3] = @intCast((value >> 24) & 0xff);
            self.buf[p + 4] = @intCast((value >> 32) & 0xff);
            self.buf[p + 5] = @intCast((value >> 40) & 0xff);
            self.buf[p + 6] = @intCast((value >> 48) & 0xff);
            self.buf[p + 7] = @intCast(value >> 56);
            self.pos += 8;
            return 8;
        }

        fn writeVarint(self: *Cbb, value: u64) CEncodeError!usize {
            const needed = varintLen(value);
            try self.ensure(needed);

            var n = value;
            const start = self.pos;
            while (n >= 0x80) {
                self.buf[self.pos] = @as(u8, @intCast(n & 0x7f)) | 0x80;
                self.pos += 1;
                n >>= 7;
            }
            self.buf[self.pos] = @intCast(n);
            self.pos += 1;
            return self.pos - start;
        }

        fn writeBytes(self: *Cbb, bytes: []const u8) CEncodeError!usize {
            const needed = varintLen(bytes.len) + bytes.len;
            try self.ensure(needed);

            const start = self.pos;
            _ = try self.writeVarint(bytes.len);
            @memcpy(self.buf[self.pos .. self.pos + bytes.len], bytes);
            self.pos += bytes.len;
            return self.pos - start;
        }

        fn ensure(self: *const Cbb, len: usize) CEncodeError!void {
            if (len > self.remaining()) return error.BufferTooSmall;
        }
    };

    fn varintLen(value: u64) usize {
        var n = value;
        var len: usize = 1;
        while (n >= 0x80) : (len += 1) {
            n >>= 7;
        }
        return len;
    }
};

pub const Dot = concord.Dot;
pub const Hlc = clock.Hlc;

const magic = [_]u8{ 'G', 'D', 'L', 'T' };
const version: u8 = 1;

/// Coarse UNDERTOW entity family carried by a CRDT delta.
pub const EntityFamily = enum(u8) {
    users = 0,
    nicks = 1,
    channels = 2,
    memberships = 3,
    prefix_modes = 4,
    channel_modes = 5,
    bans = 6,
    topics = 7,
    accounts = 8,
    history = 9,
};

/// Caller-tunable bounds used by both encoding and validation.
pub const Limits = struct {
    max_wire_bytes: usize = 64 * 1024,
    max_entity_bytes: usize = 128,
    max_value_bytes: usize = 256,
    max_context_dots: usize = 512,
    max_adds: usize = 256,
    max_add_dots: usize = 512,
    max_remove_dots: usize = 512,
    max_dots_per_add: usize = 64,
};

pub const default_limits = Limits{};

const ValidationError = error{
    InvalidDot,
    InvalidDelta,
    NonCanonicalOrder,
    DuplicateDot,
    DotOutsideCausalContext,
    CausalContextMismatch,
};

pub const DecodeError = coilpack.DecodeError || ValidationError || error{
    Oversize,
    InvalidMagic,
    UnsupportedVersion,
    UnknownEntityFamily,
    TrailingBytes,
};

pub const EncodeError = coilpack.EncodeError || ValidationError || error{
    Oversize,
    ValueTooLarge,
};

/// A validated alloc-free view of one decoded delta. Byte slices point into the
/// input buffer supplied to `decode`.
pub fn DeltaView(comptime limits: Limits) type {
    return struct {
        const Self = @This();

        pub const Add = struct {
            value: []const u8,
            dots_start: usize,
            dots_len: usize,
        };

        family: EntityFamily,
        entity_id: []const u8,
        hlc: Hlc,
        context: [limits.max_context_dots]Dot = undefined,
        context_len: usize = 0,
        adds: [limits.max_adds]Add = undefined,
        adds_len: usize = 0,
        add_dots: [limits.max_add_dots]Dot = undefined,
        add_dots_len: usize = 0,
        removes: [limits.max_remove_dots]Dot = undefined,
        removes_len: usize = 0,

        /// Decode and validate a canonical wire delta without allocating.
        pub fn decode(in: []const u8) DecodeError!Self {
            if (in.len > limits.max_wire_bytes) return error.Oversize;

            var r = coilpack.Cbs.init(in);
            for (magic) |want| {
                if (try r.readU8() != want) return error.InvalidMagic;
            }
            if (try r.readU8() != version) return error.UnsupportedVersion;

            var out = Self{
                .family = try readFamily(&r),
                .entity_id = try readBoundedBytes(&r, limits.max_entity_bytes),
                .hlc = hlcFromKey(try r.readU64Le()),
            };

            out.context_len = try readBoundedCount(&r, limits.max_context_dots);
            var prev_dot: ?Dot = null;
            for (out.context[0..out.context_len]) |*slot| {
                const dot = try readDot(&r);
                try requireStrictDotOrder(prev_dot, dot);
                slot.* = dot;
                prev_dot = dot;
            }

            out.adds_len = try readBoundedCount(&r, limits.max_adds);
            var prev_value: ?[]const u8 = null;
            for (out.adds[0..out.adds_len]) |*add| {
                const value = try readBoundedBytes(&r, limits.max_value_bytes);
                try requireStrictValueOrder(prev_value, value);
                prev_value = value;

                const dots_len = try readBoundedCount(&r, limits.max_dots_per_add);
                if (dots_len == 0) return error.InvalidDelta;
                if (out.add_dots_len + dots_len > limits.max_add_dots) return error.Oversize;

                const start = out.add_dots_len;
                prev_dot = null;
                var idx: usize = 0;
                while (idx < dots_len) : (idx += 1) {
                    const dot = try readDot(&r);
                    try requireStrictDotOrder(prev_dot, dot);
                    if (!out.contextContains(dot)) return error.DotOutsideCausalContext;
                    if (out.liveContains(dot)) return error.DuplicateDot;
                    out.add_dots[out.add_dots_len] = dot;
                    out.add_dots_len += 1;
                    prev_dot = dot;
                }
                add.* = .{ .value = value, .dots_start = start, .dots_len = dots_len };
            }

            out.removes_len = try readBoundedCount(&r, limits.max_remove_dots);
            prev_dot = null;
            for (out.removes[0..out.removes_len]) |*slot| {
                const dot = try readDot(&r);
                try requireStrictDotOrder(prev_dot, dot);
                if (!out.contextContains(dot)) return error.DotOutsideCausalContext;
                if (out.liveContains(dot)) return error.InvalidDelta;
                slot.* = dot;
                prev_dot = dot;
            }

            if (!r.done()) return error.TrailingBytes;
            try out.validateCausalPartition();
            return out;
        }

        /// Encode an already validated delta view into caller-provided storage.
        pub fn encode(self: *const Self, out: []u8) EncodeError![]const u8 {
            try self.validate();
            var w = coilpack.Cbb.init(out);
            for (magic) |byte| _ = try w.writeU8(byte);
            _ = try w.writeU8(version);
            _ = try w.writeU8(@backingInt(self.family));
            _ = try w.writeBytes(self.entity_id);
            _ = try w.writeU64Le(self.hlc.toU64());

            _ = try w.writeVarint(self.context_len);
            for (self.context[0..self.context_len]) |dot| try writeDot(&w, dot);

            _ = try w.writeVarint(self.adds_len);
            for (self.adds[0..self.adds_len]) |add| {
                _ = try w.writeBytes(add.value);
                _ = try w.writeVarint(add.dots_len);
                for (self.addDots(add)) |dot| try writeDot(&w, dot);
            }

            _ = try w.writeVarint(self.removes_len);
            for (self.removes[0..self.removes_len]) |dot| try writeDot(&w, dot);

            if (w.bytesWritten() > limits.max_wire_bytes) return error.Oversize;
            return w.written();
        }

        pub fn addDots(self: *const Self, add: Add) []const Dot {
            return self.add_dots[add.dots_start .. add.dots_start + add.dots_len];
        }

        fn validate(self: *const Self) EncodeError!void {
            if (self.entity_id.len > limits.max_entity_bytes) return error.Oversize;
            if (self.context_len > limits.max_context_dots or
                self.adds_len > limits.max_adds or
                self.add_dots_len > limits.max_add_dots or
                self.removes_len > limits.max_remove_dots)
            {
                return error.Oversize;
            }

            var prev_dot: ?Dot = null;
            for (self.context[0..self.context_len]) |dot| {
                try validateDot(dot);
                try requireStrictDotOrder(prev_dot, dot);
                prev_dot = dot;
            }

            var prev_value: ?[]const u8 = null;
            for (self.adds[0..self.adds_len]) |add| {
                if (add.value.len > limits.max_value_bytes) return error.ValueTooLarge;
                if (add.dots_len == 0 or add.dots_len > limits.max_dots_per_add) return error.InvalidDelta;
                if (add.dots_start + add.dots_len > self.add_dots_len) return error.InvalidDelta;
                try requireStrictValueOrder(prev_value, add.value);
                prev_value = add.value;

                prev_dot = null;
                for (self.addDots(add)) |dot| {
                    try validateDot(dot);
                    try requireStrictDotOrder(prev_dot, dot);
                    if (!self.contextContains(dot)) return error.DotOutsideCausalContext;
                    if (self.liveContainsBefore(add.dots_start, dot)) return error.DuplicateDot;
                    prev_dot = dot;
                }
            }

            prev_dot = null;
            for (self.removes[0..self.removes_len]) |dot| {
                try validateDot(dot);
                try requireStrictDotOrder(prev_dot, dot);
                if (!self.contextContains(dot)) return error.DotOutsideCausalContext;
                if (self.liveContains(dot)) return error.InvalidDelta;
                prev_dot = dot;
            }

            try self.validateCausalPartition();
        }

        fn validateCausalPartition(self: *const Self) ValidationError!void {
            for (self.context[0..self.context_len]) |dot| {
                const live = self.liveContains(dot);
                const removed = self.removeContains(dot);
                if (live and removed) return error.InvalidDelta;
                if (!live and !removed) return error.CausalContextMismatch;
            }
        }

        fn contextContains(self: *const Self, dot: Dot) bool {
            return sortedDotsContain(self.context[0..self.context_len], dot);
        }

        fn liveContains(self: *const Self, dot: Dot) bool {
            return dotsContain(self.add_dots[0..self.add_dots_len], dot);
        }

        fn liveContainsBefore(self: *const Self, end: usize, dot: Dot) bool {
            return dotsContain(self.add_dots[0..end], dot);
        }

        fn removeContains(self: *const Self, dot: Dot) bool {
            return sortedDotsContain(self.removes[0..self.removes_len], dot);
        }
    };
}

/// Generic adapter between a Concord OR-Set delta and the canonical wire shape.
pub fn OrSetCodec(comptime T: type, comptime ValueCodec: type, comptime limits: Limits) type {
    return struct {
        const Set = concord.OrSet(T);

        pub const Decoded = struct {
            family: EntityFamily,
            entity_id: []const u8,
            hlc: Hlc,
            delta: Set,

            pub fn deinit(self: *Decoded) void {
                self.delta.deinit();
            }
        };

        /// Encode a Concord OR-Set delta in canonical order.
        pub fn encode(
            out: []u8,
            family: EntityFamily,
            entity_id: []const u8,
            hlc: Hlc,
            delta: Set,
        ) (EncodeError || ValueCodec.Error)![]const u8 {
            if (entity_id.len > limits.max_entity_bytes) return error.Oversize;
            if (delta.cc.dots.count() > limits.max_context_dots) return error.Oversize;
            if (delta.entries.items.len > limits.max_adds) return error.Oversize;

            var w = coilpack.Cbb.init(out);
            for (magic) |byte| _ = try w.writeU8(byte);
            _ = try w.writeU8(version);
            _ = try w.writeU8(@backingInt(family));
            _ = try w.writeBytes(entity_id);
            _ = try w.writeU64Le(hlc.toU64());

            _ = try w.writeVarint(delta.cc.dots.count());
            var after_dot: ?Dot = null;
            var written_context: usize = 0;
            while (written_context < delta.cc.dots.count()) : (written_context += 1) {
                const dot = nextContextDot(delta, after_dot) orelse return error.InvalidDelta;
                try writeDot(&w, dot);
                after_dot = dot;
            }

            _ = try w.writeVarint(delta.entries.items.len);
            var after_value: [limits.max_value_bytes]u8 = undefined;
            var after_value_set = false;
            var after_value_len: usize = 0;
            var value_buf: [limits.max_value_bytes]u8 = undefined;
            var written_adds: usize = 0;
            while (written_adds < delta.entries.items.len) : (written_adds += 1) {
                const idx = try nextEntryIndex(
                    delta,
                    if (after_value_set) after_value else null,
                    after_value_len,
                );
                const entry = delta.entries.items[idx];
                const value_bytes = try encodeValue(&value_buf, entry.value);
                if (entry.dots.items.len == 0 or entry.dots.items.len > limits.max_dots_per_add) {
                    return error.InvalidDelta;
                }
                if (entry.dots.items.len > limits.max_add_dots) return error.Oversize;

                _ = try w.writeBytes(value_bytes);
                _ = try w.writeVarint(entry.dots.items.len);

                after_dot = null;
                var written_dots: usize = 0;
                while (written_dots < entry.dots.items.len) : (written_dots += 1) {
                    const dot = nextSliceDot(entry.dots.items, after_dot) orelse return error.InvalidDelta;
                    if (!delta.cc.dominates(dot)) return error.DotOutsideCausalContext;
                    try writeDot(&w, dot);
                    after_dot = dot;
                }

                @memcpy(after_value[0..value_bytes.len], value_bytes);
                after_value_set = true;
                after_value_len = value_bytes.len;
            }

            const remove_count = countRemovedDots(delta);
            if (remove_count > limits.max_remove_dots) return error.Oversize;
            _ = try w.writeVarint(remove_count);
            after_dot = null;
            var written_removes: usize = 0;
            while (written_removes < remove_count) : (written_removes += 1) {
                const dot = nextRemovedDot(delta, after_dot) orelse return error.InvalidDelta;
                try writeDot(&w, dot);
                after_dot = dot;
            }

            if (w.bytesWritten() > limits.max_wire_bytes) return error.Oversize;
            return w.written();
        }

        /// Decode wire bytes and reconstruct an equivalent Concord OR-Set delta.
        pub fn decode(
            allocator: std.mem.Allocator,
            replica_id: u64,
            in: []const u8,
        ) (DecodeError || ValueCodec.Error || std.mem.Allocator.Error)!Decoded {
            const view = try DeltaView(limits).decode(in);
            var delta = Set.init(allocator, replica_id);
            errdefer delta.deinit();

            for (view.context[0..view.context_len]) |dot| {
                try delta.cc.observe(dot);
            }

            for (view.adds[0..view.adds_len]) |add| {
                const value = try ValueCodec.decode(add.value);
                var dots = std.ArrayList(Dot).empty;
                errdefer dots.deinit(allocator);
                try dots.appendSlice(allocator, view.addDots(add));
                try delta.entries.append(allocator, .{
                    .value = value,
                    .dots = dots,
                });
            }

            return .{
                .family = view.family,
                .entity_id = view.entity_id,
                .hlc = view.hlc,
                .delta = delta,
            };
        }

        fn encodeValue(buf: []u8, value: T) ValueCodec.Error![]const u8 {
            const encoded = try ValueCodec.encode(buf, value);
            if (encoded.len > limits.max_value_bytes) return error.ValueTooLarge;
            return encoded;
        }

        fn nextEntryIndex(
            delta: Set,
            after_value: ?[limits.max_value_bytes]u8,
            after_value_len: usize,
        ) (EncodeError || ValueCodec.Error)!usize {
            var best_idx: ?usize = null;
            var best_buf: [limits.max_value_bytes]u8 = undefined;
            var best_len: usize = 0;
            var value_buf: [limits.max_value_bytes]u8 = undefined;

            for (delta.entries.items, 0..) |entry, idx| {
                const encoded = try encodeValue(&value_buf, entry.value);
                if (after_value) |prev| {
                    if (std.mem.order(u8, encoded, prev[0..after_value_len]) != .gt) continue;
                }
                if (best_idx == null or std.mem.order(u8, encoded, best_buf[0..best_len]) == .lt) {
                    best_idx = idx;
                    best_len = encoded.len;
                    @memcpy(best_buf[0..best_len], encoded);
                }
            }

            return best_idx orelse error.NonCanonicalOrder;
        }
    };
}

/// Canonical u64 value codec used by tests and simple OR-Set lanes.
pub const U64ValueCodec = struct {
    pub const Error = error{ InvalidValue, ValueTooLarge };

    pub fn encode(out: []u8, value: u64) Error![]const u8 {
        if (out.len < 8) return error.ValueTooLarge;
        out[0] = @intCast(value & 0xff);
        out[1] = @intCast((value >> 8) & 0xff);
        out[2] = @intCast((value >> 16) & 0xff);
        out[3] = @intCast((value >> 24) & 0xff);
        out[4] = @intCast((value >> 32) & 0xff);
        out[5] = @intCast((value >> 40) & 0xff);
        out[6] = @intCast((value >> 48) & 0xff);
        out[7] = @intCast(value >> 56);
        return out[0..8];
    }

    pub fn decode(in: []const u8) Error!u64 {
        if (in.len != 8) return error.InvalidValue;
        return @as(u64, in[0]) |
            (@as(u64, in[1]) << 8) |
            (@as(u64, in[2]) << 16) |
            (@as(u64, in[3]) << 24) |
            (@as(u64, in[4]) << 32) |
            (@as(u64, in[5]) << 40) |
            (@as(u64, in[6]) << 48) |
            (@as(u64, in[7]) << 56);
    }
};

fn readFamily(r: *coilpack.Cbs) DecodeError!EntityFamily {
    const tag = try r.readU8();
    return switch (tag) {
        0 => .users,
        1 => .nicks,
        2 => .channels,
        3 => .memberships,
        4 => .prefix_modes,
        5 => .channel_modes,
        6 => .bans,
        7 => .topics,
        8 => .accounts,
        9 => .history,
        else => error.UnknownEntityFamily,
    };
}

fn readBoundedBytes(r: *coilpack.Cbs, max_len: usize) DecodeError![]const u8 {
    const bytes = try r.readBytes();
    if (bytes.len > max_len) return error.Oversize;
    return bytes;
}

fn readBoundedCount(r: *coilpack.Cbs, max_count: usize) DecodeError!usize {
    const count64 = try r.readVarint();
    if (count64 > max_count) return error.Oversize;
    return @intCast(count64);
}

fn readDot(r: *coilpack.Cbs) DecodeError!Dot {
    const dot = Dot{
        .replica = try r.readVarint(),
        .counter = try r.readVarint(),
    };
    try validateDot(dot);
    return dot;
}

fn writeDot(w: *coilpack.Cbb, dot: Dot) EncodeError!void {
    try validateDot(dot);
    _ = try w.writeVarint(dot.replica);
    _ = try w.writeVarint(dot.counter);
}

fn validateDot(dot: Dot) ValidationError!void {
    if (dot.counter == 0) return error.InvalidDot;
}

fn requireStrictDotOrder(prev: ?Dot, current: Dot) ValidationError!void {
    if (prev) |p| {
        const order = compareDots(p, current);
        if (order == .eq) return error.DuplicateDot;
        if (order == .gt) return error.NonCanonicalOrder;
    }
}

fn requireStrictValueOrder(prev: ?[]const u8, current: []const u8) ValidationError!void {
    if (prev) |p| {
        switch (std.mem.order(u8, p, current)) {
            .lt => {},
            .eq => return error.InvalidDelta,
            .gt => return error.NonCanonicalOrder,
        }
    }
}

fn compareDots(a: Dot, b: Dot) std.math.Order {
    if (a.replica < b.replica) return .lt;
    if (a.replica > b.replica) return .gt;
    if (a.counter < b.counter) return .lt;
    if (a.counter > b.counter) return .gt;
    return .eq;
}

fn sortedDotsContain(dots: []const Dot, dot: Dot) bool {
    for (dots) |candidate| {
        switch (compareDots(candidate, dot)) {
            .lt => {},
            .eq => return true,
            .gt => return false,
        }
    }
    return false;
}

fn dotsContain(dots: []const Dot, dot: Dot) bool {
    for (dots) |candidate| {
        if (compareDots(candidate, dot) == .eq) return true;
    }
    return false;
}

fn hlcFromKey(key: u64) Hlc {
    return .{
        .wall_ms = @intCast(key >> 16),
        .logical = @intCast(key & 0xffff),
    };
}

fn nextSliceDot(dots: []const Dot, after: ?Dot) ?Dot {
    var best: ?Dot = null;
    for (dots) |dot| {
        if (after) |prev| {
            if (compareDots(prev, dot) != .lt) continue;
        }
        if (best == null or compareDots(dot, best.?) == .lt) best = dot;
    }
    return best;
}

fn nextContextDot(delta: anytype, after: ?Dot) ?Dot {
    var best: ?Dot = null;
    var it = delta.cc.dots.iterator();
    while (it.next()) |entry| {
        const dot = entry.key_ptr.*;
        if (after) |prev| {
            if (compareDots(prev, dot) != .lt) continue;
        }
        if (best == null or compareDots(dot, best.?) == .lt) best = dot;
    }
    return best;
}

fn countRemovedDots(delta: anytype) usize {
    var count: usize = 0;
    var it = delta.cc.dots.iterator();
    while (it.next()) |entry| {
        if (!deltaHasLiveDot(delta, entry.key_ptr.*)) count += 1;
    }
    return count;
}

fn nextRemovedDot(delta: anytype, after: ?Dot) ?Dot {
    var best: ?Dot = null;
    var it = delta.cc.dots.iterator();
    while (it.next()) |entry| {
        const dot = entry.key_ptr.*;
        if (deltaHasLiveDot(delta, dot)) continue;
        if (after) |prev| {
            if (compareDots(prev, dot) != .lt) continue;
        }
        if (best == null or compareDots(dot, best.?) == .lt) best = dot;
    }
    return best;
}

fn deltaHasLiveDot(delta: anytype, dot: Dot) bool {
    for (delta.entries.items) |entry| {
        for (entry.dots.items) |candidate| {
            if (compareDots(candidate, dot) == .eq) return true;
        }
    }
    return false;
}

test "encode decode merge equals direct merge for add and remove deltas" {
    const Set = concord.OrSet(u64);
    const Codec = OrSetCodec(u64, U64ValueCodec, default_limits);
    const allocator = std.testing.allocator;

    var source = Set.init(allocator, 1);
    defer source.deinit();
    var direct = Set.init(allocator, 2);
    defer direct.deinit();
    var via_wire = Set.init(allocator, 2);
    defer via_wire.deinit();

    var add_delta = try source.add(42);
    defer add_delta.deinit();
    try direct.mergeDelta(add_delta);

    var add_buf: [512]u8 = undefined;
    const hlc = try Hlc.init(1234, 7);
    const add_wire = try Codec.encode(&add_buf, .memberships, "#zig", hlc, add_delta);
    var decoded_add = try Codec.decode(allocator, 2, add_wire);
    defer decoded_add.deinit();
    try via_wire.mergeDelta(decoded_add.delta);
    try std.testing.expect(Set.eql(direct, via_wire));

    var remove_delta = try source.remove(42);
    defer remove_delta.deinit();
    try direct.mergeDelta(remove_delta);

    var remove_buf: [512]u8 = undefined;
    const remove_wire = try Codec.encode(&remove_buf, .memberships, "#zig", hlc, remove_delta);
    var decoded_remove = try Codec.decode(allocator, 2, remove_wire);
    defer decoded_remove.deinit();
    try via_wire.mergeDelta(decoded_remove.delta);
    try std.testing.expect(Set.eql(direct, via_wire));
}

test "truncation oversize and non canonical varint are rejected" {
    const Set = concord.OrSet(u64);
    const Codec = OrSetCodec(u64, U64ValueCodec, default_limits);
    const allocator = std.testing.allocator;

    var empty = Set.init(allocator, 7);
    defer empty.deinit();

    var buf: [128]u8 = undefined;
    const wire = try Codec.encode(&buf, .channels, "", Hlc{}, empty);
    try std.testing.expectError(error.Truncated, DeltaView(default_limits).decode(wire[0 .. wire.len - 1]));

    var huge: [default_limits.max_wire_bytes + 1]u8 = undefined;
    try std.testing.expectError(error.Oversize, DeltaView(default_limits).decode(&huge));

    var noncanonical: [129]u8 = undefined;
    @memcpy(noncanonical[0..6], wire[0..6]);
    noncanonical[6] = 0x80;
    noncanonical[7] = 0x00;
    @memcpy(noncanonical[8 .. wire.len + 1], wire[7..wire.len]);
    try std.testing.expectError(error.NonCanonicalVarint, DeltaView(default_limits).decode(noncanonical[0 .. wire.len + 1]));
}

test "canonical stability after decode and re-encode" {
    const Set = concord.OrSet(u64);
    const Codec = OrSetCodec(u64, U64ValueCodec, default_limits);
    const allocator = std.testing.allocator;

    var state = Set.init(allocator, 1);
    defer state.deinit();
    var d2 = try state.add(2);
    defer d2.deinit();
    var d1 = try state.add(1);
    defer d1.deinit();

    var combined = try d2.clone();
    defer combined.deinit();
    try combined.mergeDelta(d1);

    var first_buf: [512]u8 = undefined;
    const first = try Codec.encode(&first_buf, .bans, "lane", Hlc{}, combined);
    var decoded = try Codec.decode(allocator, 1, first);
    defer decoded.deinit();

    var second_buf: [512]u8 = undefined;
    const second = try Codec.encode(&second_buf, decoded.family, decoded.entity_id, decoded.hlc, decoded.delta);
    try std.testing.expect(coilpack.canonicalEqual(first, second));
}

test "empty delta round trips without changing merge target" {
    const Set = concord.OrSet(u64);
    const Codec = OrSetCodec(u64, U64ValueCodec, default_limits);
    const allocator = std.testing.allocator;

    var empty = Set.init(allocator, 9);
    defer empty.deinit();
    var target = Set.init(allocator, 10);
    defer target.deinit();
    var expected = try target.clone();
    defer expected.deinit();

    var buf: [128]u8 = undefined;
    const wire = try Codec.encode(&buf, .history, "empty", Hlc{}, empty);
    var decoded = try Codec.decode(allocator, 10, wire);
    defer decoded.deinit();

    try target.mergeDelta(decoded.delta);
    try std.testing.expectEqual(EntityFamily.history, decoded.family);
    try std.testing.expectEqualStrings("empty", decoded.entity_id);
    try std.testing.expect(Set.eql(expected, target));
}
