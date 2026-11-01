// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Merkle-guided UNDERTOW anti-entropy repair.
const std = @import("std");
const burst = @import("burst.zig");
const channel_crdt = @import("channel_crdt.zig");
const clock = @import("clock.zig");
const delta_codec = @import("delta_codec.zig");
const member_compact = @import("member_compact.zig");
const merkle = @import("merkle.zig");
const Allocator = std.mem.Allocator;
const ChannelCrdt = channel_crdt.ChannelCrdt;
const Hlc = channel_crdt.Hlc;
const Sha256 = std.crypto.hash.sha2.Sha256;
pub const Hash = merkle.Hash;
pub const codec_limits = burst.codec_limits;
const DeltaView = delta_codec.DeltaView(codec_limits);
const Dot = delta_codec.Dot;
/// A member payload is either the canonical dense DeltaView form or, when the
/// dense causal-context expansion overflows, the compact frontier form. Size the
/// scratch buffer for whichever is larger.
const max_member_payload = @max(codec_limits.max_wire_bytes, member_compact.max_bytes);
const member_prefix = "member:";
const key_invite_only = "mode:invite_only";
const key_moderated = "mode:moderated";
const key_no_external = "mode:no_external";
const key_topic_protected = "mode:topic_protected";
const key_secret = "mode:secret";
const key_key = "mode:key";
const key_limit = "mode:limit";
pub const RecordKind = enum(u8) { member = 1, mode = 2 };
const ModeKind = enum(u8) { invite_only = 1, moderated = 2, no_external = 3, topic_protected = 4, secret = 5, key = 6, limit = 7 };
const SummaryEntry = struct { key: []u8, hash: Hash };

pub const Summary = struct {
    allocator: Allocator,
    tree: merkle.MerkleTree,
    entries: std.ArrayList(SummaryEntry) = .empty,
    entity_count: usize = 0,
    pub fn deinit(self: *Summary) void {
        for (self.entries.items) |entry| self.allocator.free(entry.key);
        self.entries.deinit(self.allocator);
        self.tree.deinit();
    }
    pub fn root(self: *const Summary) Hash {
        return self.tree.root();
    }
    fn hashFor(self: *const Summary, key: []const u8) ?Hash {
        for (self.entries.items) |entry| if (std.mem.eql(u8, entry.key, key)) return entry.hash;
        return null;
    }
};
pub const RepairRange = struct {
    key: []u8,
};
pub const RepairRanges = struct {
    allocator: Allocator,
    ranges: []RepairRange,
    pub fn deinit(self: *RepairRanges) void {
        for (self.ranges) |range| self.allocator.free(range.key);
        self.allocator.free(self.ranges);
    }
};
pub const RepairRequest = struct {
    allocator: Allocator,
    keys: [][]u8,
    pub fn deinit(self: *RepairRequest) void {
        freeKeyList(self.allocator, self.keys);
    }
};
pub const RepairRecord = struct {
    kind: RecordKind,
    key: []u8,
    payload: []u8,
};
pub const RepairResponse = struct {
    allocator: Allocator,
    hlc: Hlc,
    vv: clock.VersionVector,
    records: []RepairRecord,
    pub fn deinit(self: *RepairResponse) void {
        for (self.records) |record| {
            self.allocator.free(record.key);
            self.allocator.free(record.payload);
        }
        self.allocator.free(self.records);
    }
};

pub fn summarize(allocator: Allocator, state: *const ChannelCrdt) !Summary {
    var out = Summary{
        .allocator = allocator,
        .tree = merkle.MerkleTree.init(allocator),
    };
    errdefer out.deinit();

    for (state.members.items) |entry| {
        var key_buf: [32]u8 = undefined;
        const key = try std.fmt.bufPrint(&key_buf, member_prefix ++ "{d}", .{entry.member_id});
        var payload: [max_member_payload]u8 = undefined;
        const encoded = try encodeMemberPayload(&payload, .{}, entry);
        try putDigest(&out, key, entityHash(key, encoded));
        out.entity_count += 1;
    }

    try putBoolMode(&out, key_invite_only, .invite_only, state.modes.invite_only);
    try putBoolMode(&out, key_moderated, .moderated, state.modes.moderated);
    try putBoolMode(&out, key_no_external, .no_external, state.modes.no_external);
    try putBoolMode(&out, key_topic_protected, .topic_protected, state.modes.topic_protected);
    try putBoolMode(&out, key_secret, .secret, state.modes.secret);
    try putKeyMode(&out, state.modes.key);
    try putLimitMode(&out, state.modes.limit);
    return out;
}

pub fn diff(allocator: Allocator, local: *const Summary, remote: *const Summary) !RepairRanges {
    var d = try merkle.diffTrees(allocator, &local.tree, &remote.tree);
    defer d.deinit();

    var ranges = std.ArrayList(RepairRange).empty;
    errdefer {
        for (ranges.items) |range| allocator.free(range.key);
        ranges.deinit(allocator);
    }
    for (d.keys) |key| {
        const remote_hash = remote.hashFor(key) orelse return error.InvalidRepairKey;
        if (local.hashFor(key)) |local_hash| {
            if (std.mem.eql(u8, &local_hash, &remote_hash)) {
                allocator.free(key);
                continue;
            }
        }
        try ranges.append(allocator, .{ .key = key });
    }
    allocator.free(d.keys);
    d.keys = &.{};
    return .{ .allocator = allocator, .ranges = try ranges.toOwnedSlice(allocator) };
}

pub fn buildRepairRequest(allocator: Allocator, ranges: *const RepairRanges) !RepairRequest {
    var keys = std.ArrayList([]u8).empty;
    errdefer {
        for (keys.items) |key| allocator.free(key);
        keys.deinit(allocator);
    }
    for (ranges.ranges) |range| try keys.append(allocator, try allocator.dupe(u8, range.key));
    return .{ .allocator = allocator, .keys = try keys.toOwnedSlice(allocator) };
}

pub fn buildRepairResponse(allocator: Allocator, source: *const ChannelCrdt, request: *const RepairRequest) !RepairResponse {
    var records = std.ArrayList(RepairRecord).empty;
    errdefer {
        for (records.items) |record| {
            allocator.free(record.key);
            allocator.free(record.payload);
        }
        records.deinit(allocator);
    }
    for (request.keys) |key| if (try makeEntityRecord(allocator, source, key)) |record| try records.append(allocator, record);
    return .{ .allocator = allocator, .hlc = source.hlc, .vv = source.vv, .records = try records.toOwnedSlice(allocator) };
}

pub fn applyRepairResponse(allocator: Allocator, target: *ChannelCrdt, response: *const RepairResponse) !void {
    var incoming = ChannelCrdt.init(allocator, target.replica_id);
    errdefer incoming.deinit();
    incoming.hlc = response.hlc;
    try incoming.vv.merge(&response.vv);
    for (response.records) |record| {
        switch (record.kind) {
            .member => {
                if (!std.mem.startsWith(u8, record.key, member_prefix)) return error.InvalidRepairRecord;
                try readMemberPayload(allocator, &incoming, record.payload);
            },
            .mode => try readModePayload(&incoming, record.key, record.payload),
        }
    }
    try target.merge(&incoming);
    incoming.deinit();
}

fn putBoolMode(summary: *Summary, key: []const u8, kind: ModeKind, reg: anytype) !void {
    if (reg.value == null) return;
    var payload: [32]u8 = undefined;
    const encoded = try encodeBoolMode(&payload, kind, reg);
    try putDigest(summary, key, entityHash(key, encoded));
    summary.entity_count += 1;
}

fn putKeyMode(summary: *Summary, reg: anytype) !void {
    if (reg.value == null) return;
    var payload: [96]u8 = undefined;
    const encoded = try encodeKeyMode(&payload, reg);
    try putDigest(summary, key_key, entityHash(key_key, encoded));
    summary.entity_count += 1;
}

fn putLimitMode(summary: *Summary, reg: anytype) !void {
    if (reg.value == null) return;
    var payload: [32]u8 = undefined;
    const encoded = try encodeLimitMode(&payload, reg);
    try putDigest(summary, key_limit, entityHash(key_limit, encoded));
    summary.entity_count += 1;
}

fn putDigest(summary: *Summary, key: []const u8, hash: Hash) !void {
    try summary.tree.put(key, hash);
    const owned = try summary.allocator.dupe(u8, key);
    errdefer summary.allocator.free(owned);
    try summary.entries.append(summary.allocator, .{ .key = owned, .hash = hash });
}

fn makeEntityRecord(allocator: Allocator, source: *const ChannelCrdt, key: []const u8) !?RepairRecord {
    if (std.mem.startsWith(u8, key, member_prefix)) {
        const member_id = try std.fmt.parseInt(channel_crdt.MemberId, key[member_prefix.len..], 10);
        for (source.members.items) |entry| {
            if (entry.member_id == member_id) {
                var payload: [max_member_payload]u8 = undefined;
                const encoded = try encodeMemberPayload(&payload, .{}, entry);
                return try ownedRecord(allocator, .member, key, encoded);
            }
        }
        return null;
    }

    var payload: [96]u8 = undefined;
    const encoded = if (std.mem.eql(u8, key, key_invite_only))
        try encodeBoolMode(&payload, .invite_only, source.modes.invite_only)
    else if (std.mem.eql(u8, key, key_moderated))
        try encodeBoolMode(&payload, .moderated, source.modes.moderated)
    else if (std.mem.eql(u8, key, key_no_external))
        try encodeBoolMode(&payload, .no_external, source.modes.no_external)
    else if (std.mem.eql(u8, key, key_topic_protected))
        try encodeBoolMode(&payload, .topic_protected, source.modes.topic_protected)
    else if (std.mem.eql(u8, key, key_secret))
        try encodeBoolMode(&payload, .secret, source.modes.secret)
    else if (std.mem.eql(u8, key, key_key))
        try encodeKeyMode(&payload, source.modes.key)
    else if (std.mem.eql(u8, key, key_limit))
        try encodeLimitMode(&payload, source.modes.limit)
    else
        return error.InvalidRepairKey;

    return try ownedRecord(allocator, .mode, key, encoded);
}

fn ownedRecord(allocator: Allocator, kind: RecordKind, key: []const u8, payload: []const u8) !RepairRecord {
    const owned_key = try allocator.dupe(u8, key);
    errdefer allocator.free(owned_key);
    const owned_payload = try allocator.dupe(u8, payload);
    return .{ .kind = kind, .key = owned_key, .payload = owned_payload };
}

fn encodeMemberPayload(out: []u8, hlc: Hlc, entry: anytype) ![]const u8 {
    // Prefer the canonical dense DeltaView form (byte-identical to a legacy peer,
    // so Merkle entity hashes still match cross-version). Fall back to the compact
    // frontier form ONLY when the dense causal-context expansion overflows — the
    // exact members a legacy peer could neither summarize nor repair, so no
    // cross-version regression.
    if (encodeMemberDense(out, hlc, entry)) |dense| {
        return dense;
    } else |err| switch (err) {
        error.Oversize => return encodeMemberCompact(out, hlc, entry),
        else => return err,
    }
}

fn encodeMemberDense(out: []u8, hlc: Hlc, entry: anytype) ![]const u8 {
    var entity: [8]u8 = undefined;
    writeU64Le(&entity, entry.member_id);

    var view = DeltaView{
        .family = .memberships,
        .entity_id = &entity,
        .hlc = hlc,
    };
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

fn readMemberPayload(allocator: Allocator, target: *ChannelCrdt, bytes: []const u8) !void {
    if (member_compact.matches(bytes)) return readMemberPayloadCompact(allocator, target, bytes);
    const view = try DeltaView.decode(bytes);
    if (view.family != .memberships or view.entity_id.len != 8) return error.InvalidRepairRecord;
    if (Hlc.compare(view.hlc, target.hlc) == .gt) target.hlc = view.hlc;

    var context = clock.VersionVector.init();
    for (view.context[0..view.context_len]) |dot| try observeDot(&context, dot);

    var adds = std.ArrayList(@TypeOf(target.members.items[0].adds.items[0])).empty;
    errdefer adds.deinit(allocator);

    for (view.adds[0..view.adds_len]) |add| {
        const dots = view.addDots(add);
        if (dots.len != 1) return error.InvalidRepairRecord;
        const decoded = try decodeAddValue(add.value);
        if (!dotEql(decoded.dot, dots[0])) return error.InvalidRepairRecord;
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

fn readMemberPayloadCompact(allocator: Allocator, target: *ChannelCrdt, bytes: []const u8) !void {
    const view = try member_compact.decode(bytes);
    const hlc = hlcFromKey(view.hlc_key);
    if (Hlc.compare(hlc, target.hlc) == .gt) target.hlc = hlc;

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
        if (decoded.dot.counter == 0) return error.InvalidRepairRecord;
        if (context.counter(decoded.dot.replica) < decoded.dot.counter) return error.InvalidRepairRecord;
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
    if (bytes.len != 25) return error.InvalidRepairRecord;
    return .{
        .dot = .{ .replica = readU64Le(bytes[0..8]), .counter = readU64Le(bytes[8..16]) },
        .hlc = hlcFromKey(readU64Le(bytes[16..24])),
        .status = @bitCast(bytes[24]),
    };
}

fn encodeBoolMode(out: []u8, kind: ModeKind, reg: anytype) ![]const u8 {
    const value = reg.value orelse return error.MissingEntity;
    var w = FixedWriter{ .buf = out };
    try w.writeU8(@backingInt(kind));
    try w.writeU64(reg.timestamp);
    try w.writeU64(reg.replica_id);
    try w.writeU8(if (value) 1 else 0);
    return w.written();
}

fn encodeKeyMode(out: []u8, reg: anytype) ![]const u8 {
    const value = reg.value orelse return error.MissingEntity;
    var w = FixedWriter{ .buf = out };
    try w.writeU8(@backingInt(ModeKind.key));
    try w.writeU64(reg.timestamp);
    try w.writeU64(reg.replica_id);
    try w.writeU8(if (value.present) 1 else 0);
    try w.writeU8(value.len);
    try w.writeBytes(value.asSlice());
    return w.written();
}

fn encodeLimitMode(out: []u8, reg: anytype) ![]const u8 {
    const value = reg.value orelse return error.MissingEntity;
    var w = FixedWriter{ .buf = out };
    try w.writeU8(@backingInt(ModeKind.limit));
    try w.writeU64(reg.timestamp);
    try w.writeU64(reg.replica_id);
    try w.writeU8(if (value.present) 1 else 0);
    try w.writeU32(value.value);
    return w.written();
}

fn readModePayload(target: *ChannelCrdt, key: []const u8, bytes: []const u8) !void {
    var r = Reader{ .buf = bytes };
    const kind = try readModeKind(&r);
    const expected_key = modeKey(kind);
    if (!std.mem.eql(u8, key, expected_key)) return error.InvalidRepairRecord;
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
            const len = try r.readU8();
            if (len > channel_crdt.KeyMode.max_len) return error.InvalidRepairRecord;
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

fn readModeKind(r: *Reader) !ModeKind {
    return switch (try r.readU8()) {
        1 => .invite_only,
        2 => .moderated,
        3 => .no_external,
        4 => .topic_protected,
        5 => .secret,
        6 => .key,
        7 => .limit,
        else => error.InvalidRepairRecord,
    };
}

fn modeKey(kind: ModeKind) []const u8 {
    return switch (kind) {
        .invite_only => key_invite_only,
        .moderated => key_moderated,
        .no_external => key_no_external,
        .topic_protected => key_topic_protected,
        .secret => key_secret,
        .key => key_key,
        .limit => key_limit,
    };
}

const FixedWriter = struct {
    buf: []u8,
    pos: usize = 0,
    fn written(self: *const FixedWriter) []const u8 {
        return self.buf[0..self.pos];
    }
    fn writeU8(self: *FixedWriter, value: u8) !void {
        if (self.pos + 1 > self.buf.len) return error.BufferTooSmall;
        self.buf[self.pos] = value;
        self.pos += 1;
    }
    fn writeU32(self: *FixedWriter, value: u32) !void {
        try self.writeU64Bounded(value, 4);
    }
    fn writeU64(self: *FixedWriter, value: u64) !void {
        try self.writeU64Bounded(value, 8);
    }
    fn writeU64Bounded(self: *FixedWriter, value: u64, comptime n: usize) !void {
        if (self.pos + n > self.buf.len) return error.BufferTooSmall;
        writeUintLe(self.buf[self.pos .. self.pos + n], value);
        self.pos += n;
    }
    fn writeBytes(self: *FixedWriter, bytes: []const u8) !void {
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
    fn readU8(self: *Reader) !u8 {
        if (self.pos >= self.buf.len) return error.Truncated;
        const byte = self.buf[self.pos];
        self.pos += 1;
        return byte;
    }
    fn readBool(self: *Reader) !bool {
        return switch (try self.readU8()) {
            0 => false,
            1 => true,
            else => error.InvalidRepairRecord,
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
    fn readFixed(self: *Reader, len: usize) ![]const u8 {
        if (self.pos + len > self.buf.len) return error.Truncated;
        const bytes = self.buf[self.pos .. self.pos + len];
        self.pos += len;
        return bytes;
    }
};

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
fn entityHash(key: []const u8, payload: []const u8) Hash {
    var h = Sha256.init(.{});
    h.update("onyx_server.suimyaku.anti_entropy_repair.entity.v1");
    h.update(key);
    h.update(payload);
    var out: Hash = undefined;
    h.final(&out);
    return out;
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
            if (a.replica != b.replica) return a.replica < b.replica;
            return a.counter < b.counter;
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
fn freeKeyList(allocator: Allocator, keys: [][]u8) void {
    for (keys) |key| allocator.free(key);
    allocator.free(keys);
}
fn hlcFromKey(key: u64) Hlc {
    return .{ .wall_ms = @intCast(key >> 16), .logical = @intCast(key & 0xffff) };
}
fn discard(delta: anytype) void {
    var owned = delta;
    owned.deinit();
}
fn exchangeBoth(allocator: Allocator, a: *ChannelCrdt, b: *ChannelCrdt) !struct { to_a: usize, to_b: usize, a_entities: usize, b_entities: usize } {
    var sa = try summarize(allocator, a);
    defer sa.deinit();
    var sb = try summarize(allocator, b);
    defer sb.deinit();
    var ranges_to_a = try diff(allocator, &sa, &sb);
    defer ranges_to_a.deinit();
    var ranges_to_b = try diff(allocator, &sb, &sa);
    defer ranges_to_b.deinit();
    var req_to_a = try buildRepairRequest(allocator, &ranges_to_a);
    defer req_to_a.deinit();
    var req_to_b = try buildRepairRequest(allocator, &ranges_to_b);
    defer req_to_b.deinit();
    var resp_to_a = try buildRepairResponse(allocator, b, &req_to_a);
    defer resp_to_a.deinit();
    var resp_to_b = try buildRepairResponse(allocator, a, &req_to_b);
    defer resp_to_b.deinit();
    try applyRepairResponse(allocator, a, &resp_to_a);
    try applyRepairResponse(allocator, b, &resp_to_b);
    return .{ .to_a = resp_to_a.records.len, .to_b = resp_to_b.records.len, .a_entities = sa.entity_count, .b_entities = sb.entity_count };
}
fn repairOneWay(allocator: Allocator, dst: *ChannelCrdt, src: *const ChannelCrdt) !usize {
    var sd = try summarize(allocator, dst);
    defer sd.deinit();
    var ss = try summarize(allocator, src);
    defer ss.deinit();
    var ranges = try diff(allocator, &sd, &ss);
    defer ranges.deinit();
    var req = try buildRepairRequest(allocator, &ranges);
    defer req.deinit();
    var resp = try buildRepairResponse(allocator, src, &req);
    defer resp.deinit();
    try applyRepairResponse(allocator, dst, &resp);
    return resp.records.len;
}
test "two divergent replicas repair to identical state exchanging only diffs" {
    const allocator = std.testing.allocator;
    var a = ChannelCrdt.init(allocator, 1);
    defer a.deinit();
    var b = ChannelCrdt.init(allocator, 2);
    defer b.deinit();
    discard(try a.localJoin(1, .{ .voice = true }, 10));
    try b.merge(&a);
    discard(try a.localJoin(10, .{ .op = true }, 20));
    discard(try a.localSetMode(.{ .invite_only = true }, 21));
    discard(try b.localJoin(20, .{ .founder = true }, 22));
    discard(try b.localSetMode(.{ .topic_protected = true }, 23));
    const result = try exchangeBoth(allocator, &a, &b);
    try std.testing.expect(ChannelCrdt.eql(&a, &b));
    try std.testing.expect(result.to_a < result.b_entities);
    try std.testing.expect(result.to_b < result.a_entities);
    try std.testing.expectEqual(@as(usize, 2), result.to_a);
    try std.testing.expectEqual(@as(usize, 2), result.to_b);
}
test "no-op when already equal" {
    const allocator = std.testing.allocator;
    var a = ChannelCrdt.init(allocator, 1);
    defer a.deinit();
    discard(try a.localJoin(44, .{ .owner = true }, 10));
    discard(try a.localSetMode(.{ .key = try channel_crdt.KeyMode.init("equal") }, 11));
    var b = try a.clone();
    defer b.deinit();
    var sa = try summarize(allocator, &a);
    defer sa.deinit();
    var sb = try summarize(allocator, &b);
    defer sb.deinit();
    var ranges = try diff(allocator, &sa, &sb);
    defer ranges.deinit();
    var req = try buildRepairRequest(allocator, &ranges);
    defer req.deinit();
    var resp = try buildRepairResponse(allocator, &b, &req);
    defer resp.deinit();
    try std.testing.expectEqual(@as(usize, 0), ranges.ranges.len);
    try std.testing.expectEqual(@as(usize, 0), req.keys.len);
    try std.testing.expectEqual(@as(usize, 0), resp.records.len);
}
test "idempotent re-apply" {
    const allocator = std.testing.allocator;
    var a = ChannelCrdt.init(allocator, 1);
    defer a.deinit();
    var b = ChannelCrdt.init(allocator, 2);
    defer b.deinit();
    discard(try a.localJoin(7, .{ .voice = true }, 1));
    try b.merge(&a);
    discard(try b.localJoin(8, .{ .op = true }, 2));
    discard(try b.localPart(7));
    var sa = try summarize(allocator, &a);
    defer sa.deinit();
    var sb = try summarize(allocator, &b);
    defer sb.deinit();
    var ranges = try diff(allocator, &sa, &sb);
    defer ranges.deinit();
    var req = try buildRepairRequest(allocator, &ranges);
    defer req.deinit();
    var resp = try buildRepairResponse(allocator, &b, &req);
    defer resp.deinit();
    try applyRepairResponse(allocator, &a, &resp);
    var once = try a.clone();
    defer once.deinit();
    try applyRepairResponse(allocator, &a, &resp);
    try std.testing.expect(ChannelCrdt.eql(&once, &a));
}
test "multi-round convergence" {
    const allocator = std.testing.allocator;
    var a = ChannelCrdt.init(allocator, 1);
    defer a.deinit();
    var b = ChannelCrdt.init(allocator, 2);
    defer b.deinit();
    discard(try a.localJoin(1, .{ .voice = true }, 1));
    try b.merge(&a);
    discard(try a.localJoin(2, .{ .op = true }, 2));
    discard(try a.localSetMode(.{ .secret = true }, 3));
    discard(try b.localJoin(3, .{ .founder = true }, 4));
    discard(try b.localSetMode(.{ .limit = channel_crdt.LimitMode.set(64) }, 5));
    _ = try repairOneWay(allocator, &a, &b);
    try std.testing.expect(!ChannelCrdt.eql(&a, &b));
    _ = try repairOneWay(allocator, &b, &a);
    try std.testing.expect(ChannelCrdt.eql(&a, &b));
}
test "summarize and repair a member whose context exceeds the dense cap" {
    const allocator = std.testing.allocator;
    var src = ChannelCrdt.init(allocator, 1);
    defer src.deinit();

    // Push one replica's channel-global dot counter past max_context_dots (512)
    // for a single member. Before the compact fallback, summarize() → error.Oversize
    // here and the Merkle anti-entropy backstop silently no-oped.
    var i: u64 = 0;
    while (i < 600) : (i += 1) {
        discard(try src.localJoin(77, .{ .voice = true }, 10 + i));
        discard(try src.localPart(77));
    }
    discard(try src.localJoin(77, .{ .op = true }, 700));
    try std.testing.expect(src.members.items[0].context.counter(1) > codec_limits.max_context_dots);

    // summarize must succeed (was error.Oversize) and round-trip through repair.
    var s = try summarize(allocator, &src);
    s.deinit();

    var dst = ChannelCrdt.init(allocator, 2);
    defer dst.deinit();
    _ = try repairOneWay(allocator, &dst, &src);
    try std.testing.expect(ChannelCrdt.eql(&src, &dst));
    try std.testing.expect(dst.containsMember(77));
}
