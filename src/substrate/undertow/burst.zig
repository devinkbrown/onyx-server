// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

const channel_crdt = @import("channel_crdt.zig");
const clock = @import("clock.zig");
const delta_codec = @import("delta_codec.zig");
const member_compact = @import("member_compact.zig");
const toml = @import("../../proto/toml.zig");

pub const ChannelCrdt = channel_crdt.ChannelCrdt;
pub const Hlc = channel_crdt.Hlc;

pub const codec_limits = delta_codec.Limits{
    .max_wire_bytes = 4096,
    .max_entity_bytes = 8,
    .max_value_bytes = 32,
    .max_context_dots = 512,
    .max_adds = 128,
    .max_add_dots = 128,
    .max_remove_dots = 512,
    .max_dots_per_add = 1,
};

pub const Limits = struct {
    max_burst_bytes: usize = 64 * 1024,
    max_records: usize = 512,

    /// Overlay `[mesh.link]` state-burst keys onto these limits.
    pub fn applyToml(cfg: *Limits, doc: *const toml.Document) void {
        if (doc.getUint("mesh.link.burst_max_bytes")) |v| cfg.max_burst_bytes = @intCast(v);
        if (doc.getUint("mesh.link.burst_max_records")) |v| cfg.max_records = @intCast(v);
    }
};

pub const default_limits = Limits{};

const Allocator = std.mem.Allocator;
const Dot = delta_codec.Dot;
const DeltaView = delta_codec.DeltaView(codec_limits);

const magic = [_]u8{ 'S', 'B', 'S', 'T' };
const version: u8 = 1;

const RecordKind = enum(u8) { header = 1, member_delta = 2, mode = 3, member_compact = 4 };
const ModeKind = enum(u8) { invite_only = 1, moderated = 2, no_external = 3, topic_protected = 4, secret = 5, key = 6, limit = 7 };

pub fn serialize(allocator: Allocator, source: *const ChannelCrdt, limits: Limits) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);

    try appendBytes(&out, allocator, &magic, limits);
    try appendByte(&out, allocator, version, limits);
    try writeHeader(&out, allocator, source, limits);

    for (source.members.items) |entry| try writeMember(&out, allocator, source.hlc, entry, limits);

    try writeModes(&out, allocator, source, limits);
    return out.toOwnedSlice(allocator);
}

pub fn deserializeApply(
    allocator: Allocator,
    target: *ChannelCrdt,
    bytes: []const u8,
    limits: Limits,
) !void {
    if (bytes.len > limits.max_burst_bytes) return error.Oversize;
    var r = Reader{ .buf = bytes };
    for (magic) |want| {
        if (try r.readByte() != want) return error.BadMagic;
    }
    if (try r.readByte() != version) return error.UnsupportedVersion;

    var incoming = ChannelCrdt.init(allocator, target.replica_id);
    errdefer incoming.deinit();

    var records: usize = 0;
    var saw_header = false;
    while (!r.done()) {
        records += 1;
        if (records > limits.max_records) return error.Oversize;

        const kind = try readRecordKind(&r);
        const payload = try r.readBytes();
        switch (kind) {
            .header => {
                if (saw_header) return error.InvalidBurst;
                try readHeader(&incoming, payload);
                saw_header = true;
            },
            .member_delta => try readMember(allocator, &incoming, payload),
            .member_compact => try readMemberCompact(allocator, &incoming, payload),
            .mode => try readMode(&incoming, payload),
        }
    }
    if (!saw_header) return error.InvalidBurst;

    try target.merge(&incoming);
    incoming.deinit();
}

pub fn apply(allocator: Allocator, target: *ChannelCrdt, bytes: []const u8, limits: Limits) !void {
    try deserializeApply(allocator, target, bytes, limits);
}

fn writeHeader(out: *std.ArrayList(u8), allocator: Allocator, source: *const ChannelCrdt, limits: Limits) !void {
    var payload: [8 + 1 + clock.VersionVector.max_entries * 16]u8 = undefined;
    var w = Writer{ .buf = &payload };
    try w.writeU64(source.hlc.toU64());
    try w.writeVarint(source.vv.len);
    for (source.vv.entries[0..source.vv.len]) |entry| {
        try w.writeU64(entry.replica);
        try w.writeU64(entry.counter);
    }
    try appendRecord(out, allocator, .header, w.written(), limits);
}

fn readHeader(target: *ChannelCrdt, bytes: []const u8) !void {
    var r = Reader{ .buf = bytes };
    target.hlc = hlcFromKey(try r.readU64());
    var vv = clock.VersionVector.init();
    const count = try r.readVarint();
    if (count > clock.VersionVector.max_entries) return error.InvalidBurst;
    var idx: usize = 0;
    while (idx < count) : (idx += 1) {
        vv.entries[idx] = .{ .replica = try r.readU64(), .counter = try r.readU64() };
    }
    vv.len = count;
    if (!r.done()) return error.TrailingBytes;
    try target.vv.merge(&vv);
}

fn writeMember(
    out: *std.ArrayList(u8),
    allocator: Allocator,
    hlc: Hlc,
    entry: anytype,
    limits: Limits,
) !void {
    // Prefer the canonical dense DeltaView form: it is byte-identical to what a
    // legacy peer emits, so its Merkle/burst bytes still match cross-version. Fall
    // back to the compact frontier form ONLY when the dense causal-context
    // expansion overflows (a member whose context counter exceeds
    // `max_context_dots` on a busy channel) — the exact members a legacy peer
    // could neither encode nor consume, so this is a strict improvement, not a
    // cross-version regression.
    var encoded: [codec_limits.max_wire_bytes]u8 = undefined;
    if (encodeMemberDense(&encoded, hlc, entry)) |delta_bytes| {
        try appendRecord(out, allocator, .member_delta, delta_bytes, limits);
    } else |err| switch (err) {
        error.Oversize => {
            var compact_buf: [member_compact.max_bytes]u8 = undefined;
            const compact_bytes = try encodeMemberCompact(&compact_buf, hlc, entry);
            try appendRecord(out, allocator, .member_compact, compact_bytes, limits);
        },
        else => return err,
    }
}

fn encodeMemberDense(out: []u8, hlc: Hlc, entry: anytype) ![]const u8 {
    var view = DeltaView{
        .family = .memberships,
        .entity_id = undefined,
        .hlc = hlc,
    };

    var entity: [8]u8 = undefined;
    writeU64Le(&entity, entry.member_id);
    view.entity_id = &entity;

    try fillContext(&view, entry.context);
    try fillAdds(&view, entry.adds.items);
    try fillRemoves(&view);

    return view.encode(out);
}

fn encodeMemberCompact(out: []u8, hlc: Hlc, entry: anytype) ![]const u8 {
    if (entry.context.len > member_compact.max_context) return error.Oversize;
    if (entry.adds.items.len > member_compact.max_adds) return error.Oversize;

    var ctx: [member_compact.max_context]member_compact.Entry = undefined;
    for (entry.context.entries[0..entry.context.len], 0..) |e, i| {
        ctx[i] = .{ .replica = e.replica, .counter = e.counter };
    }

    var adds: [member_compact.max_adds][member_compact.add_value_len]u8 = undefined;
    for (entry.adds.items, 0..) |add, i| {
        const dot = Dot{ .replica = add.dot.replica_id, .counter = add.dot.counter };
        encodeAddValue(adds[i][0..], dot, add.hlc, add.status);
    }

    return member_compact.encode(
        out,
        entry.member_id,
        hlc.toU64(),
        ctx[0..entry.context.len],
        adds[0..entry.adds.items.len],
    );
}

fn readMember(allocator: Allocator, target: *ChannelCrdt, bytes: []const u8) !void {
    const view = try DeltaView.decode(bytes);
    if (view.family != .memberships or view.entity_id.len != 8) return error.InvalidMemberRecord;

    var context = clock.VersionVector.init();
    for (view.context[0..view.context_len]) |dot| {
        try observeDot(&context, dot);
    }

    var adds = std.ArrayList(@TypeOf(target.members.items[0].adds.items[0])).empty;
    errdefer adds.deinit(allocator);

    for (view.adds[0..view.adds_len]) |add| {
        const dots = view.addDots(add);
        if (dots.len != 1) return error.InvalidMemberRecord;
        const decoded = try decodeAddValue(add.value);
        if (!dotEql(decoded.dot, dots[0])) return error.InvalidMemberRecord;
        try adds.append(allocator, .{
            .dot = .{ .replica_id = @intCast(decoded.dot.replica), .counter = decoded.dot.counter },
            .hlc = decoded.hlc,
            .status = decoded.status,
        });
    }

    try target.members.append(allocator, .{
        .member_id = readU64Le(view.entity_id),
        .adds = adds,
        .context = context,
    });
}

fn readMemberCompact(allocator: Allocator, target: *ChannelCrdt, bytes: []const u8) !void {
    const view = try member_compact.decode(bytes);

    var context = clock.VersionVector.init();
    for (view.context[0..view.context_len]) |e| {
        var single = clock.VersionVector.init();
        single.entries[0] = .{ .replica = e.replica, .counter = e.counter };
        single.len = 1;
        try context.merge(&single);
    }

    var adds = std.ArrayList(@TypeOf(target.members.items[0].adds.items[0])).empty;
    errdefer adds.deinit(allocator);

    for (view.adds[0..view.adds_len]) |raw| {
        const decoded = try decodeAddValue(&raw);
        // The live dot must lie within the transmitted causal-context frontier,
        // matching the dense codec's `DotOutsideCausalContext` guarantee.
        if (decoded.dot.counter == 0) return error.InvalidMemberRecord;
        if (context.counter(decoded.dot.replica) < decoded.dot.counter) return error.InvalidMemberRecord;
        try adds.append(allocator, .{
            .dot = .{ .replica_id = @intCast(decoded.dot.replica), .counter = decoded.dot.counter },
            .hlc = decoded.hlc,
            .status = decoded.status,
        });
    }

    try target.members.append(allocator, .{
        .member_id = view.member_id,
        .adds = adds,
        .context = context,
    });
}

fn fillContext(view: *DeltaView, vv: clock.VersionVector) !void {
    for (vv.entries[0..vv.len]) |entry| {
        var counter: u64 = 1;
        while (counter <= entry.counter) : (counter += 1) {
            if (view.context_len == codec_limits.max_context_dots) return error.Oversize;
            view.context[view.context_len] = .{ .replica = entry.replica, .counter = counter };
            view.context_len += 1;
        }
    }
    sortDots(view.context[0..view.context_len]);
}

fn fillAdds(view: *DeltaView, adds: anytype) !void {
    var values: [codec_limits.max_adds][25]u8 = undefined;
    if (adds.len > codec_limits.max_adds) return error.Oversize;

    for (adds, 0..) |add, idx| {
        const dot = Dot{ .replica = add.dot.replica_id, .counter = add.dot.counter };
        encodeAddValue(values[idx][0..], dot, add.hlc, add.status);
        view.add_dots[idx] = dot;
        view.adds[idx] = .{ .value = values[idx][0..], .dots_start = idx, .dots_len = 1 };
    }
    view.adds_len = adds.len;
    view.add_dots_len = adds.len;
    sortAdds(view, &values);
}

fn fillRemoves(view: *DeltaView) !void {
    for (view.context[0..view.context_len]) |dot| {
        if (liveContains(view, dot)) continue;
        if (view.removes_len == codec_limits.max_remove_dots) return error.Oversize;
        view.removes[view.removes_len] = dot;
        view.removes_len += 1;
    }
}

const AddValue = struct {
    dot: Dot,
    hlc: Hlc,
    status: channel_crdt.MemberStatus,
};

fn encodeAddValue(out: []u8, dot: Dot, hlc: Hlc, status: channel_crdt.MemberStatus) void {
    writeU64Le(out[0..8], dot.replica);
    writeU64Le(out[8..16], dot.counter);
    writeU64Le(out[16..24], hlc.toU64());
    out[24] = @as(u8, @bitCast(status));
}

fn decodeAddValue(bytes: []const u8) !AddValue {
    if (bytes.len != 25) return error.InvalidMemberRecord;
    return .{
        .dot = .{ .replica = readU64Le(bytes[0..8]), .counter = readU64Le(bytes[8..16]) },
        .hlc = hlcFromKey(readU64Le(bytes[16..24])),
        .status = @bitCast(bytes[24]),
    };
}

fn writeModes(out: *std.ArrayList(u8), allocator: Allocator, source: *const ChannelCrdt, limits: Limits) !void {
    try writeBoolMode(out, allocator, .invite_only, source.modes.invite_only, limits);
    try writeBoolMode(out, allocator, .moderated, source.modes.moderated, limits);
    try writeBoolMode(out, allocator, .no_external, source.modes.no_external, limits);
    try writeBoolMode(out, allocator, .topic_protected, source.modes.topic_protected, limits);
    try writeBoolMode(out, allocator, .secret, source.modes.secret, limits);
    try writeKeyMode(out, allocator, source.modes.key, limits);
    try writeLimitMode(out, allocator, source.modes.limit, limits);
}

fn writeBoolMode(out: *std.ArrayList(u8), allocator: Allocator, kind: ModeKind, reg: anytype, limits: Limits) !void {
    const value = reg.value orelse return;
    var payload: [18]u8 = undefined;
    var w = Writer{ .buf = &payload };
    try w.writeU8(@backingInt(kind));
    try w.writeU64(reg.timestamp);
    try w.writeU64(reg.replica_id);
    try w.writeU8(if (value) 1 else 0);
    try appendRecord(out, allocator, .mode, w.written(), limits);
}

fn writeKeyMode(out: *std.ArrayList(u8), allocator: Allocator, reg: anytype, limits: Limits) !void {
    const value = reg.value orelse return;
    var payload: [1 + 8 + 8 + 1 + 1 + channel_crdt.KeyMode.max_len]u8 = undefined;
    var w = Writer{ .buf = &payload };
    try w.writeU8(@backingInt(ModeKind.key));
    try w.writeU64(reg.timestamp);
    try w.writeU64(reg.replica_id);
    try w.writeU8(if (value.present) 1 else 0);
    try w.writeU8(value.len);
    try w.writeBytes(value.asSlice());
    try appendRecord(out, allocator, .mode, w.written(), limits);
}

fn writeLimitMode(out: *std.ArrayList(u8), allocator: Allocator, reg: anytype, limits: Limits) !void {
    const value = reg.value orelse return;
    var payload: [1 + 8 + 8 + 1 + 4]u8 = undefined;
    var w = Writer{ .buf = &payload };
    try w.writeU8(@backingInt(ModeKind.limit));
    try w.writeU64(reg.timestamp);
    try w.writeU64(reg.replica_id);
    try w.writeU8(if (value.present) 1 else 0);
    try w.writeU32(value.value);
    try appendRecord(out, allocator, .mode, w.written(), limits);
}

fn readMode(target: *ChannelCrdt, bytes: []const u8) !void {
    var r = Reader{ .buf = bytes };
    const kind = try readModeKind(&r);
    const ts = try r.readU64();
    const rid = try r.readU64();

    switch (kind) {
        .invite_only => target.modes.invite_only.merge(.{ .value = try r.readBool(), .timestamp = ts, .replica_id = rid }),
        .moderated => target.modes.moderated.merge(.{ .value = try r.readBool(), .timestamp = ts, .replica_id = rid }),
        .no_external => target.modes.no_external.merge(.{ .value = try r.readBool(), .timestamp = ts, .replica_id = rid }),
        .topic_protected => target.modes.topic_protected.merge(.{ .value = try r.readBool(), .timestamp = ts, .replica_id = rid }),
        .secret => target.modes.secret.merge(.{ .value = try r.readBool(), .timestamp = ts, .replica_id = rid }),
        .key => {
            const present = try r.readBool();
            const len = try r.readByte();
            if (len > channel_crdt.KeyMode.max_len) return error.InvalidModeRecord;
            const value = if (present) try channel_crdt.KeyMode.init(try r.readFixed(len)) else channel_crdt.KeyMode.none();
            target.modes.key.merge(.{ .value = value, .timestamp = ts, .replica_id = rid });
        },
        .limit => {
            const present = try r.readBool();
            const value = if (present) channel_crdt.LimitMode.set(try r.readU32()) else channel_crdt.LimitMode.none();
            target.modes.limit.merge(.{ .value = value, .timestamp = ts, .replica_id = rid });
        },
    }
    if (!r.done()) return error.TrailingBytes;
}

fn appendRecord(out: *std.ArrayList(u8), allocator: Allocator, kind: RecordKind, payload: []const u8, limits: Limits) !void {
    try appendByte(out, allocator, @backingInt(kind), limits);
    try appendVarint(out, allocator, payload.len, limits);
    try appendBytes(out, allocator, payload, limits);
}

fn appendByte(out: *std.ArrayList(u8), allocator: Allocator, byte: u8, limits: Limits) !void {
    if (out.items.len + 1 > limits.max_burst_bytes) return error.Oversize;
    try out.append(allocator, byte);
}

fn appendBytes(out: *std.ArrayList(u8), allocator: Allocator, bytes: []const u8, limits: Limits) !void {
    if (out.items.len + bytes.len > limits.max_burst_bytes) return error.Oversize;
    try out.appendSlice(allocator, bytes);
}

fn appendVarint(out: *std.ArrayList(u8), allocator: Allocator, value: usize, limits: Limits) !void {
    var buf: [10]u8 = undefined;
    var w = Writer{ .buf = &buf };
    try w.writeVarint(value);
    try appendBytes(out, allocator, w.written(), limits);
}

const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn done(self: *const Reader) bool {
        return self.pos == self.buf.len;
    }

    fn readByte(self: *Reader) !u8 {
        if (self.pos >= self.buf.len) return error.Truncated;
        const byte = self.buf[self.pos];
        self.pos += 1;
        return byte;
    }

    fn readBool(self: *Reader) !bool {
        return switch (try self.readByte()) {
            0 => false,
            1 => true,
            else => error.InvalidModeRecord,
        };
    }

    fn readU32(self: *Reader) !u32 {
        return @intCast(try self.readU64Bounded(4));
    }
    fn readU64(self: *Reader) !u64 {
        return self.readU64Bounded(8);
    }

    fn readU64Bounded(self: *Reader, comptime n: usize) !u64 {
        if (self.pos + n > self.buf.len) return error.Truncated;
        const value = readUintLe(self.buf[self.pos .. self.pos + n]);
        self.pos += n;
        return value;
    }

    fn readVarint(self: *Reader) !usize {
        var value: u64 = 0;
        var i: usize = 0;
        while (i < 10) : (i += 1) {
            const byte = try self.readByte();
            const shift = @as(u6, @intCast(i * 7));
            value |= @as(u64, byte & 0x7f) << shift;
            if ((byte & 0x80) == 0) {
                if (value > std.math.maxInt(usize)) return error.Oversize;
                return @intCast(value);
            }
        }
        return error.VarintTooLong;
    }

    fn readBytes(self: *Reader) ![]const u8 {
        return self.readFixed(try self.readVarint());
    }

    fn readFixed(self: *Reader, len: usize) ![]const u8 {
        // Overflow-free bounds check: `len` is varint-sourced and can approach
        // usize-max, so `self.pos + len` would wrap. `self.pos <= self.buf.len`
        // always holds (every cursor advance is guarded by a prior bounds check),
        // so the subtraction never underflows.
        if (len > self.buf.len - self.pos) return error.Truncated;
        const bytes = self.buf[self.pos .. self.pos + len];
        self.pos += len;
        return bytes;
    }
};

const Writer = struct {
    buf: []u8,
    pos: usize = 0,

    fn written(self: *const Writer) []const u8 {
        return self.buf[0..self.pos];
    }

    fn writeU8(self: *Writer, value: u8) !void {
        if (self.pos + 1 > self.buf.len) return error.BufferTooSmall;
        self.buf[self.pos] = value;
        self.pos += 1;
    }

    fn writeU32(self: *Writer, value: u32) !void {
        try self.writeU64Bounded(value, 4);
    }
    fn writeU64(self: *Writer, value: u64) !void {
        try self.writeU64Bounded(value, 8);
    }

    fn writeU64Bounded(self: *Writer, value: u64, comptime n: usize) !void {
        if (self.pos + n > self.buf.len) return error.BufferTooSmall;
        writeUintLe(self.buf[self.pos .. self.pos + n], value);
        self.pos += n;
    }

    fn writeVarint(self: *Writer, value: usize) !void {
        var n: u64 = value;
        while (n >= 0x80) {
            try self.writeU8(@as(u8, @intCast(n & 0x7f)) | 0x80);
            n >>= 7;
        }
        try self.writeU8(@intCast(n));
    }

    fn writeBytes(self: *Writer, bytes: []const u8) !void {
        if (self.pos + bytes.len > self.buf.len) return error.BufferTooSmall;
        @memcpy(self.buf[self.pos .. self.pos + bytes.len], bytes);
        self.pos += bytes.len;
    }
};

fn readRecordKind(r: *Reader) !RecordKind {
    return switch (try r.readByte()) {
        1 => .header,
        2 => .member_delta,
        3 => .mode,
        4 => .member_compact,
        else => error.UnknownRecord,
    };
}

fn readModeKind(r: *Reader) !ModeKind {
    return switch (try r.readByte()) {
        1 => .invite_only,
        2 => .moderated,
        3 => .no_external,
        4 => .topic_protected,
        5 => .secret,
        6 => .key,
        7 => .limit,
        else => error.InvalidModeRecord,
    };
}

fn observeDot(vv: *clock.VersionVector, dot: Dot) !void {
    var single = clock.VersionVector.init();
    single.entries[0] = .{ .replica = dot.replica, .counter = dot.counter };
    single.len = 1;
    try vv.merge(&single);
}

fn sortAdds(view: *DeltaView, values: *[codec_limits.max_adds][25]u8) void {
    var i: usize = 1;
    while (i < view.adds_len) : (i += 1) {
        var j = i;
        while (j > 0 and std.mem.order(u8, view.adds[j].value, view.adds[j - 1].value) == .lt) : (j -= 1) {
            std.mem.swap(DeltaView.Add, &view.adds[j], &view.adds[j - 1]);
            std.mem.swap(Dot, &view.add_dots[j], &view.add_dots[j - 1]);
            std.mem.swap([25]u8, &values[j], &values[j - 1]);
            view.adds[j].value = values[j][0..];
            view.adds[j - 1].value = values[j - 1][0..];
            view.adds[j].dots_start = j;
            view.adds[j - 1].dots_start = j - 1;
        }
    }
}

fn sortDots(dots: []Dot) void {
    std.mem.sort(Dot, dots, {}, struct {
        fn lessThan(_: void, a: Dot, b: Dot) bool {
            return dotOrder(a, b) == .lt;
        }
    }.lessThan);
}

fn liveContains(view: *const DeltaView, dot: Dot) bool {
    for (view.add_dots[0..view.add_dots_len]) |candidate| {
        if (dotEql(candidate, dot)) return true;
    }
    return false;
}

fn dotEql(a: Dot, b: Dot) bool {
    return a.replica == b.replica and a.counter == b.counter;
}

fn dotOrder(a: Dot, b: Dot) std.math.Order {
    if (a.replica < b.replica) return .lt;
    if (a.replica > b.replica) return .gt;
    return std.math.order(a.counter, b.counter);
}

fn hlcFromKey(key: u64) Hlc {
    return .{ .wall_ms = @intCast(key >> 16), .logical = @intCast(key & 0xffff) };
}

fn writeU64Le(out: []u8, value: u64) void {
    writeUintLe(out, value);
}

fn readU64Le(bytes: []const u8) u64 {
    return readUintLe(bytes);
}

fn writeUintLe(out: []u8, value: u64) void {
    for (out, 0..) |*byte, idx| {
        byte.* = @intCast((value >> @as(u6, @intCast(idx * 8))) & 0xff);
    }
}

fn readUintLe(bytes: []const u8) u64 {
    var value: u64 = 0;
    for (bytes, 0..) |byte, idx| {
        value |= @as(u64, byte) << @as(u6, @intCast(idx * 8));
    }
    return value;
}

fn discard(delta: anytype) void {
    var owned = delta;
    owned.deinit();
}

test "round-trip serialize deserialize merge yields converged state" {
    const allocator = std.testing.allocator;
    var source = ChannelCrdt.init(allocator, 1);
    defer source.deinit();
    var target = ChannelCrdt.init(allocator, 2);
    defer target.deinit();

    discard(try source.localJoin(100, .{ .op = true }, 10));
    discard(try source.localSetMode(.{ .key = try channel_crdt.KeyMode.init("burst") }, 11));
    discard(try source.localSetMode(.{ .limit = channel_crdt.LimitMode.set(42) }, 12));

    const bytes = try serialize(allocator, &source, default_limits);
    defer allocator.free(bytes);
    try deserializeApply(allocator, &target, bytes, default_limits);
    try std.testing.expect(ChannelCrdt.eql(&source, &target));
}

test "applying a burst twice is idempotent" {
    const allocator = std.testing.allocator;
    var source = ChannelCrdt.init(allocator, 1);
    defer source.deinit();
    var target = ChannelCrdt.init(allocator, 2);
    defer target.deinit();

    discard(try source.localJoin(100, .{ .voice = true }, 10));
    discard(try source.localPart(100));
    discard(try source.localJoin(101, .{ .founder = true }, 12));

    const bytes = try serialize(allocator, &source, default_limits);
    defer allocator.free(bytes);
    try apply(allocator, &target, bytes, default_limits);
    var once = try target.clone();
    defer once.deinit();
    try apply(allocator, &target, bytes, default_limits);

    try std.testing.expect(ChannelCrdt.eql(&once, &target));
}

test "two nodes bursting to each other converge" {
    const allocator = std.testing.allocator;
    var a = ChannelCrdt.init(allocator, 1);
    defer a.deinit();
    var b = ChannelCrdt.init(allocator, 2);
    defer b.deinit();

    discard(try a.localJoin(10, .{ .op = true }, 10));
    discard(try a.localSetMode(.{ .invite_only = true }, 11));
    discard(try b.localJoin(20, .{ .voice = true }, 12));
    discard(try b.localSetMode(.{ .topic_protected = true }, 13));

    const burst_a = try serialize(allocator, &a, default_limits);
    defer allocator.free(burst_a);
    const burst_b = try serialize(allocator, &b, default_limits);
    defer allocator.free(burst_b);

    try apply(allocator, &a, burst_b, default_limits);
    try apply(allocator, &b, burst_a, default_limits);
    try std.testing.expect(ChannelCrdt.eql(&a, &b));
}

fn countRecordKind(bytes: []const u8, want: u8) !usize {
    var r = Reader{ .buf = bytes };
    for (magic) |_| _ = try r.readByte();
    _ = try r.readByte(); // version
    var n: usize = 0;
    while (!r.done()) {
        const kind = try r.readByte();
        _ = try r.readBytes();
        if (kind == want) n += 1;
    }
    return n;
}

test "Undertow mesh burst: small members stay dense so legacy peers still parse" {
    const allocator = std.testing.allocator;
    var source = ChannelCrdt.init(allocator, 1);
    defer source.deinit();
    discard(try source.localJoin(10, .{ .op = true }, 10));
    discard(try source.localJoin(20, .{ .voice = true }, 11));

    const bytes = try serialize(allocator, &source, default_limits);
    defer allocator.free(bytes);

    // No wire change while the dense form fits: only member_delta (kind 2)
    // records, never member_compact (kind 4). A legacy peer parses this byte for
    // byte.
    try std.testing.expectEqual(@as(usize, 2), try countRecordKind(bytes, @backingInt(RecordKind.member_delta)));
    try std.testing.expectEqual(@as(usize, 0), try countRecordKind(bytes, @backingInt(RecordKind.member_compact)));
}

test "Undertow mesh burst: member past dense context cap round-trips via compact fallback" {
    const allocator = std.testing.allocator;
    var source = ChannelCrdt.init(allocator, 1);
    defer source.deinit();

    // Drive one replica's channel-global dot counter past max_context_dots (512)
    // for a single member via join/part churn, then leave it live. The dense
    // causal-context expansion would return error.Oversize here.
    var i: u64 = 0;
    while (i < 600) : (i += 1) {
        discard(try source.localJoin(77, .{ .voice = true }, 10 + i));
        discard(try source.localPart(77));
    }
    discard(try source.localJoin(77, .{ .op = true }, 700));
    try std.testing.expect(source.members.items[0].context.counter(1) > codec_limits.max_context_dots);

    const bytes = try serialize(allocator, &source, default_limits);
    defer allocator.free(bytes);

    try std.testing.expect((try countRecordKind(bytes, @backingInt(RecordKind.member_compact))) >= 1);

    var target = ChannelCrdt.init(allocator, 2);
    defer target.deinit();
    try deserializeApply(allocator, &target, bytes, default_limits);
    try std.testing.expect(ChannelCrdt.eql(&source, &target));
    try std.testing.expect(target.containsMember(77));
}

test "Limits.applyToml overlays mesh.link burst keys" {
    const allocator = std.testing.allocator;
    var doc = try toml.parse(allocator,
        \\[mesh.link]
        \\burst_max_bytes = 262144
    );
    defer doc.deinit(allocator);

    var cfg = Limits{};
    cfg.applyToml(&doc);
    try std.testing.expectEqual(@as(usize, 262144), cfg.max_burst_bytes);
    try std.testing.expectEqual(@as(usize, 512), cfg.max_records); // default
}

test "exploit: burst record length near usize-max is rejected fail-closed (no OOB slice)" {
    const allocator = std.testing.allocator;

    // A well-framed BURST payload whose FIRST record claims a varint length of
    // 2^64-1. Reached PRE-SIGNATURE: an unsigned BURST frame dispatches straight
    // to `apply`, so a Byzantine (or even unauthenticated) peer controls these
    // bytes. The classic `pos + len > buf.len` bounds check overflows when `len`
    // approaches usize-max, wrapping to a small value that passes the check and
    // yields an out-of-bounds `buf[pos..wrapped]` slice — a remote crash / OOB
    // read in the ReleaseFast ship binary (where the slice safety trap is off).
    // The only acceptable outcome is a returned error: reject, never OOB.
    const payload = [_]u8{
        'S', 'B', 'S', 'T', // magic
        1, //                  version
        1, //                  RecordKind.header
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, // varint 2^64-1
    };

    var target = ChannelCrdt.init(allocator, 2);
    defer target.deinit();

    // Must return an error (Truncated), never trap or read out of bounds.
    try std.testing.expectError(error.Truncated, apply(allocator, &target, &payload, default_limits));
}
