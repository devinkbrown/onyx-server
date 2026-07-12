// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Verifiable rateless anti-entropy over origin-signed channel CRDT deltas.
const std = @import("std");

const channel_crdt = @import("channel_crdt.zig");
const clock = @import("clock.zig");
const delta_codec = @import("delta_codec.zig");
const prolly = @import("prolly.zig");
const riblt = @import("riblt.zig");
const signed_delta = @import("../../proto/signed_delta.zig");
const toml = @import("../../proto/toml.zig");

const Allocator = std.mem.Allocator;
const Cid = signed_delta.Cid;
const Hash = prolly.Hash;
const SignedDelta = signed_delta.SignedDelta;
const DeltaView = delta_codec.DeltaView(delta_codec.default_limits);

const magic = [_]u8{ 'G', 'Y', 'S', '1' };
const max_op_len = delta_codec.default_limits.max_wire_bytes;

/// Default values for the anti-entropy sync pump/message limits. These mirror
/// the previously-hardcoded module constants, so `Config{}` is behaviorally
/// identical to the prior values.
const default_symbols_per_pump = 24;
const default_max_symbols = 512;
const default_max_requests = 512;
const default_max_fills = 512;
const default_max_scope_len = 4096;

/// Runtime tuning for the RIBLT anti-entropy sync. Carried by `GoryuSync` and
/// copied into each `Session`.
pub const Config = struct {
    symbols_per_pump: usize = default_symbols_per_pump,
    max_symbols: usize = default_max_symbols,
    max_requests: usize = default_max_requests,
    max_fills: usize = default_max_fills,
    max_scope_len: usize = default_max_scope_len,

    /// Overlay `[mesh.antientropy]` sync keys onto this config.
    pub fn applyToml(cfg: *Config, doc: *const toml.Document) void {
        if (doc.getUint("mesh.antientropy.symbols_per_pump")) |v| cfg.symbols_per_pump = @intCast(v);
        if (doc.getUint("mesh.antientropy.max_symbols")) |v| cfg.max_symbols = @intCast(v);
        if (doc.getUint("mesh.antientropy.max_requests")) |v| cfg.max_requests = @intCast(v);
        if (doc.getUint("mesh.antientropy.max_fills")) |v| cfg.max_fills = @intCast(v);
        if (doc.getUint("mesh.antientropy.max_scope_len")) |v| cfg.max_scope_len = @intCast(v);
    }
};

pub const Error = Allocator.Error || error{
    BadCid,
    CapacityExceeded,
    CounterOverflow,
    InvalidMessage,
    MessageTooLarge,
    MissingDelta,
    MissingNode,
    VerificationFailed,
    UnsupportedDeltaFamily,
    InvalidChannelDelta,
};

pub const VerifyFn = *const fn (SignedDelta) bool;

pub const Peer = struct {
    root_hash: Hash,
};

const OwnedDelta = struct {
    signed: SignedDelta,
    scope: []u8,
    op_bytes: []u8,

    fn clone(allocator: Allocator, signed: SignedDelta) Error!OwnedDelta {
        const expected = signed_delta.cid(signed.env);
        if (!std.mem.eql(u8, &expected, &signed.cid)) return error.BadCid;

        const scope = try allocator.dupe(u8, signed.env.scope);
        errdefer allocator.free(scope);
        const op_bytes = try allocator.dupe(u8, signed.env.op_bytes);
        errdefer allocator.free(op_bytes);

        var owned = signed;
        owned.env.scope = scope;
        owned.env.op_bytes = op_bytes;
        return .{ .signed = owned, .scope = scope, .op_bytes = op_bytes };
    }

    fn deinit(self: *OwnedDelta, allocator: Allocator) void {
        allocator.free(self.scope);
        allocator.free(self.op_bytes);
        self.* = undefined;
    }
};

pub const GoryuSync = struct {
    allocator: Allocator,
    index: prolly.Tree,
    store: std.AutoHashMap(Cid, OwnedDelta),
    pending: std.AutoHashMap(Cid, OwnedDelta),
    channel: channel_crdt.ChannelCrdt,
    cfg: Config = .{},

    pub fn init(allocator: Allocator) GoryuSync {
        return initWithConfig(allocator, .{});
    }

    pub fn initWithConfig(allocator: Allocator, cfg: Config) GoryuSync {
        return .{
            .allocator = allocator,
            .index = prolly.Tree.init(allocator),
            .store = std.AutoHashMap(Cid, OwnedDelta).init(allocator),
            .pending = std.AutoHashMap(Cid, OwnedDelta).init(allocator),
            .channel = channel_crdt.ChannelCrdt.init(allocator, 0),
            .cfg = cfg,
        };
    }

    pub fn deinit(self: *GoryuSync) void {
        deinitDeltaMap(self.allocator, &self.store);
        deinitDeltaMap(self.allocator, &self.pending);
        self.index.deinit();
        self.channel.deinit();
        self.* = undefined;
    }

    pub fn addLocalDelta(self: *GoryuSync, signed: SignedDelta) Error!void {
        try self.putVerified(signed);
    }

    pub fn rootHash(self: *const GoryuSync) Hash {
        return self.index.rootHash();
    }

    pub fn peer(self: *const GoryuSync) Peer {
        return .{ .root_hash = self.rootHash() };
    }

    pub fn beginAntiEntropy(self: *GoryuSync, peer_info: Peer) Error!Session {
        return Session.init(self, peer_info.root_hash);
    }

    pub fn applyVerified(self: *GoryuSync, verify_fn: VerifyFn) Error!usize {
        // Snapshot the pending CIDs in a read-only pass, THEN mutate — the same
        // collect-then-remove pattern as dropTombstonesBelow. Mutating
        // self.pending (remove/putOwned) DURING iteration is unsound: Zig's
        // AutoHashMap.remove uses backward-shift deletion, so iterate-while-
        // remove skips unvisited entries, leaving deltas unapplied and
        // convergence never reaching pending.count() == 0.
        var cids: std.ArrayList(Cid) = .empty;
        defer cids.deinit(self.allocator);
        var it = self.pending.iterator();
        while (it.next()) |entry| try cids.append(self.allocator, entry.key_ptr.*);

        var applied: usize = 0;
        var verify_failed = false;
        for (cids.items) |cid| {
            // A concurrent putPending could already own this CID; skip if gone.
            var owned = (self.pending.fetchRemove(cid) orelse continue).value;
            if (!verify_fn(owned.signed)) {
                // A bad delta is dropped but MUST NOT abort the batch — every
                // other pending delta is still processed. The error is raised
                // once at the end so the caller still learns a delta was
                // rejected without losing the good ones.
                owned.deinit(self.allocator);
                verify_failed = true;
                continue;
            }

            // On a decode/apply error the delta is already out of pending, so
            // free it here before propagating (a malformed-but-signed delta is
            // permanently undecodable; retaining it would only loop).
            self.applySignedChannelDelta(owned.signed) catch |err| {
                owned.deinit(self.allocator);
                return err;
            };
            try self.putOwned(owned); // takes ownership; frees owned on error
            applied += 1;
        }
        if (verify_failed) return error.VerificationFailed;
        return applied;
    }

    pub fn dropTombstonesBelow(self: *GoryuSync, frontier: clock.VersionVector) Error!usize {
        var dropped: usize = 0;
        var to_remove: std.ArrayList(Cid) = .empty;
        defer to_remove.deinit(self.allocator);

        var it = self.store.iterator();
        while (it.next()) |entry| {
            if (deltaStableTombstone(entry.value_ptr.signed, frontier)) {
                try to_remove.append(self.allocator, entry.key_ptr.*);
            }
        }

        for (to_remove.items) |cid| {
            if (self.store.fetchRemove(cid)) |kv| {
                var owned = kv.value;
                owned.deinit(self.allocator);
                _ = try self.index.remove(cid);
                dropped += 1;
            }
        }
        return dropped;
    }

    fn putVerified(self: *GoryuSync, signed: SignedDelta) Error!void {
        if (self.store.contains(signed.cid)) return;
        const owned = try OwnedDelta.clone(self.allocator, signed);
        // `putOwned` takes ownership and frees `owned` on EVERY error path via
        // its own errdefer, so no errdefer here — a second one would double-free
        // `owned.scope`/`op_bytes` if index.insert/store.put fails under OOM.
        try self.putOwned(owned);
    }

    fn putOwned(self: *GoryuSync, owned: OwnedDelta) Error!void {
        if (self.store.contains(owned.signed.cid)) {
            var dupe = owned;
            dupe.deinit(self.allocator);
            return;
        }
        errdefer {
            var rollback = owned;
            rollback.deinit(self.allocator);
        }
        try self.index.insert(owned.signed.cid);
        try self.store.put(owned.signed.cid, owned);
    }

    fn putPending(self: *GoryuSync, signed: SignedDelta) Error!void {
        if (self.store.contains(signed.cid) or self.pending.contains(signed.cid)) return;
        const owned = try OwnedDelta.clone(self.allocator, signed);
        errdefer {
            var rollback = owned;
            rollback.deinit(self.allocator);
        }
        try self.pending.put(owned.signed.cid, owned);
    }

    fn applySignedChannelDelta(self: *GoryuSync, signed: SignedDelta) Error!void {
        const view = DeltaView.decode(signed.env.op_bytes) catch return error.InvalidChannelDelta;
        if (signed.env.family != @intFromEnum(view.family)) return error.InvalidChannelDelta;
        if (signed.env.hlc != view.hlc.toU64()) return error.InvalidChannelDelta;

        switch (view.family) {
            .memberships => try applyMembershipDelta(self.allocator, &self.channel, &view),
            else => return error.UnsupportedDeltaFamily,
        }
    }
};

pub const Session = struct {
    owner: *GoryuSync,
    peer_root: Hash,
    cfg: Config,
    encoder: riblt.Encoder,
    decoder: riblt.Decoder,
    decoded: bool = false,
    received_symbols: usize = 0,
    wanted: std.AutoHashMap(Cid, void),
    fills: std.ArrayList(Cid) = .empty,

    fn init(owner: *GoryuSync, peer_root: Hash) Error!Session {
        var encoder = riblt.Encoder.init(owner.allocator);
        errdefer encoder.deinit();
        var decoder = riblt.Decoder.init(owner.allocator);
        errdefer decoder.deinit();

        for (owner.index.keys.items) |cid| {
            try encoder.add(cid);
            try decoder.addLocal(cid);
        }

        return .{
            .owner = owner,
            .peer_root = peer_root,
            .cfg = owner.cfg,
            .encoder = encoder,
            .decoder = decoder,
            .wanted = std.AutoHashMap(Cid, void).init(owner.allocator),
        };
    }

    pub fn deinit(self: *Session) void {
        self.encoder.deinit();
        self.decoder.deinit();
        self.wanted.deinit();
        self.fills.deinit(self.owner.allocator);
        self.* = undefined;
    }

    pub fn converged(self: *const Session) bool {
        return std.mem.eql(u8, &self.peer_root, &self.owner.rootHash()) or
            (self.decoded and self.wanted.count() == 0 and self.owner.pending.count() == 0);
    }

    pub fn applyVerified(self: *Session, verify_fn: VerifyFn) Error!usize {
        const applied = try self.owner.applyVerified(verify_fn);
        self.pruneWanted();
        return applied;
    }

    /// Consume a peer frame and return the next deterministic frame. The caller
    /// owns the returned buffer.
    pub fn pump(self: *Session, bytes: []const u8) Error![]u8 {
        if (bytes.len != 0) try self.consume(bytes);
        if (self.converged()) return self.owner.allocator.alloc(u8, 0);

        try self.tryDecode();

        var out = std.ArrayList(u8).empty;
        errdefer out.deinit(self.owner.allocator);
        try writeFrame(self, &out);
        return out.toOwnedSlice(self.owner.allocator);
    }

    fn consume(self: *Session, bytes: []const u8) Error!void {
        var r = Reader{ .buf = bytes, .max_scope_len = self.cfg.max_scope_len };
        try r.expectMagic();

        const symbol_count = try r.readU16();
        const request_count = try r.readU16();
        const fill_count = try r.readU16();
        if (symbol_count > self.cfg.max_symbols or request_count > self.cfg.max_requests or fill_count > self.cfg.max_fills) {
            return error.MessageTooLarge;
        }

        var i: usize = 0;
        while (i < symbol_count) : (i += 1) {
            try self.decoder.pushSymbol(.{
                .seed = try r.readU64(),
                .index = try r.readU64(),
                .count = try r.readI64(),
                .key_xor = try r.readArray(32),
                .check_xor = try r.readU64(),
            });
            self.received_symbols += 1;
        }

        i = 0;
        while (i < request_count) : (i += 1) {
            const cid = try r.readArray(32);
            if (self.owner.store.get(cid)) |stored| {
                try self.fills.append(self.owner.allocator, stored.signed.cid);
            }
        }

        i = 0;
        while (i < fill_count) : (i += 1) {
            try self.owner.putPending(try r.readSignedDelta());
        }

        if (!r.done()) return error.InvalidMessage;
        self.pruneWanted();
    }

    fn tryDecode(self: *Session) Error!void {
        if (self.decoded) return;
        if (self.received_symbols == 0) return;
        var result = (try self.decoder.tryDecode()) orelse return;
        defer result.deinit();
        self.decoded = true;

        for (result.remote_only) |cid| {
            if (!self.owner.store.contains(cid)) try self.wanted.put(cid, {});
        }
    }

    fn pruneWanted(self: *Session) void {
        var it = self.wanted.iterator();
        while (it.next()) |entry| {
            if (self.owner.store.contains(entry.key_ptr.*)) {
                _ = self.wanted.remove(entry.key_ptr.*);
            }
        }
    }
};

fn writeFrame(session: *Session, out: *std.ArrayList(u8)) Error!void {
    try out.appendSlice(session.owner.allocator, &magic);
    const header = out.items.len;
    try out.appendNTimes(session.owner.allocator, 0, 6);

    var symbol_count: u16 = 0;
    if (!session.decoded) {
        while (symbol_count < session.cfg.symbols_per_pump) : (symbol_count += 1) {
            const sym = session.encoder.nextSymbol();
            try writeSymbol(out, session.owner.allocator, sym);
        }
    }

    var request_count: u16 = 0;
    var req_it = session.wanted.iterator();
    while (req_it.next()) |entry| {
        try out.appendSlice(session.owner.allocator, &entry.key_ptr.*);
        request_count += 1;
    }

    var fill_count: u16 = 0;
    for (session.fills.items) |cid| {
        if (session.owner.store.get(cid)) |stored| {
            try writeSignedDelta(out, session.owner.allocator, stored.signed, session.cfg.max_scope_len);
            fill_count += 1;
        }
    }
    session.fills.clearRetainingCapacity();

    writeU16(out.items[header..][0..2], symbol_count);
    writeU16(out.items[header + 2 ..][0..2], request_count);
    writeU16(out.items[header + 4 ..][0..2], fill_count);
}

fn writeSymbol(out: *std.ArrayList(u8), allocator: Allocator, sym: riblt.CodedSymbol) Error!void {
    try appendU64(out, allocator, sym.seed);
    try appendU64(out, allocator, sym.index);
    try appendI64(out, allocator, sym.count);
    try out.appendSlice(allocator, &sym.key_xor);
    try appendU64(out, allocator, sym.check_xor);
}

fn writeSignedDelta(out: *std.ArrayList(u8), allocator: Allocator, signed: SignedDelta, max_scope_len: usize) Error!void {
    if (signed.env.scope.len > max_scope_len or signed.env.op_bytes.len > max_op_len) {
        return error.MessageTooLarge;
    }
    try out.appendSlice(allocator, &signed.cid);
    try out.appendSlice(allocator, &signed.env.origin_node);
    try appendU64(out, allocator, signed.env.hlc);
    try out.append(allocator, signed.env.family);
    try appendU16(out, allocator, @intCast(signed.env.scope.len));
    try appendU32(out, allocator, @intCast(signed.env.op_bytes.len));
    try out.appendSlice(allocator, signed.env.scope);
    try out.appendSlice(allocator, signed.env.op_bytes);
    try out.appendSlice(allocator, &signed.signature);
}

const Reader = struct {
    buf: []const u8,
    pos: usize = 0,
    max_scope_len: usize = default_max_scope_len,

    fn done(self: *const Reader) bool {
        return self.pos == self.buf.len;
    }

    fn expectMagic(self: *Reader) Error!void {
        if (self.buf.len < magic.len or !std.mem.eql(u8, self.buf[0..magic.len], &magic)) {
            return error.InvalidMessage;
        }
        self.pos = magic.len;
    }

    fn readArray(self: *Reader, comptime len: usize) Error![len]u8 {
        if (self.pos + len > self.buf.len) return error.InvalidMessage;
        var out: [len]u8 = undefined;
        @memcpy(&out, self.buf[self.pos..][0..len]);
        self.pos += len;
        return out;
    }

    fn readU16(self: *Reader) Error!u16 {
        return std.mem.readInt(u16, &(try self.readArray(2)), .little);
    }

    fn readU32(self: *Reader) Error!u32 {
        return std.mem.readInt(u32, &(try self.readArray(4)), .little);
    }

    fn readU64(self: *Reader) Error!u64 {
        return std.mem.readInt(u64, &(try self.readArray(8)), .little);
    }

    fn readI64(self: *Reader) Error!i64 {
        return @bitCast(try self.readU64());
    }

    fn readBytes(self: *Reader, len: usize) Error![]const u8 {
        if (self.pos + len > self.buf.len) return error.InvalidMessage;
        const bytes = self.buf[self.pos..][0..len];
        self.pos += len;
        return bytes;
    }

    fn readSignedDelta(self: *Reader) Error!SignedDelta {
        const cid = try self.readArray(32);
        const origin_node = try self.readArray(20);
        const hlc = try self.readU64();
        const family = (try self.readArray(1))[0];
        const scope_len = try self.readU16();
        const op_len = try self.readU32();
        if (scope_len > self.max_scope_len or op_len > max_op_len) return error.MessageTooLarge;
        const scope = try self.readBytes(scope_len);
        const op_bytes = try self.readBytes(op_len);
        const signature = try self.readArray(signed_delta.signature_len);
        return .{
            .env = .{
                .origin_node = origin_node,
                .hlc = hlc,
                .family = family,
                .scope = scope,
                .op_bytes = op_bytes,
            },
            .cid = cid,
            .signature = signature,
        };
    }
};

fn applyMembershipDelta(allocator: Allocator, target: *channel_crdt.ChannelCrdt, view: *const DeltaView) Error!void {
    if (view.entity_id.len != 8) return error.InvalidChannelDelta;
    var incoming = channel_crdt.ChannelCrdt.init(allocator, target.replica_id);
    errdefer incoming.deinit();
    incoming.hlc = view.hlc;

    var context = clock.VersionVector.init();
    for (view.context[0..view.context_len]) |dot| try observeDot(&context, dot);
    try incoming.vv.merge(&context);

    var adds = std.ArrayList(@TypeOf(incoming.members.items[0].adds.items[0])).empty;
    errdefer adds.deinit(allocator);
    for (view.adds[0..view.adds_len]) |add| {
        const dots = view.addDots(add);
        if (dots.len != 1) return error.InvalidChannelDelta;
        const decoded = try decodeMemberAdd(add.value);
        if (decoded.dot.replica != dots[0].replica or decoded.dot.counter != dots[0].counter) {
            return error.InvalidChannelDelta;
        }
        try adds.append(allocator, .{
            .dot = .{ .replica_id = @intCast(decoded.dot.replica), .counter = decoded.dot.counter },
            .hlc = decoded.hlc,
            .status = decoded.status,
        });
    }

    try incoming.members.append(allocator, .{
        .member_id = std.mem.readInt(u64, view.entity_id[0..8], .little),
        .adds = adds,
        .context = context,
    });
    try target.merge(&incoming);
    incoming.deinit();
}

fn deltaStableTombstone(signed: SignedDelta, frontier: clock.VersionVector) bool {
    const view = DeltaView.decode(signed.env.op_bytes) catch return false;
    if (view.adds_len != 0 or view.context_len == 0) return false;
    for (view.context[0..view.context_len]) |dot| {
        if (!frontier.contains(.{ .replica = dot.replica, .counter = dot.counter })) return false;
    }
    return true;
}

fn observeDot(vv: *clock.VersionVector, dot: delta_codec.Dot) clock.VersionVector.Error!void {
    var single = clock.VersionVector.init();
    single.entries[0] = .{ .replica = dot.replica, .counter = dot.counter };
    single.len = 1;
    try vv.merge(&single);
}

const MemberAdd = struct {
    dot: delta_codec.Dot,
    hlc: clock.Hlc,
    status: channel_crdt.MemberStatus,
};

fn decodeMemberAdd(bytes: []const u8) Error!MemberAdd {
    if (bytes.len != 25) return error.InvalidChannelDelta;
    return .{
        .dot = .{
            .replica = std.mem.readInt(u64, bytes[0..8], .little),
            .counter = std.mem.readInt(u64, bytes[8..16], .little),
        },
        .hlc = hlcFromKey(std.mem.readInt(u64, bytes[16..24], .little)),
        .status = @bitCast(bytes[24]),
    };
}

fn deinitDeltaMap(allocator: Allocator, map: *std.AutoHashMap(Cid, OwnedDelta)) void {
    var it = map.iterator();
    while (it.next()) |entry| entry.value_ptr.deinit(allocator);
    map.deinit();
}

fn appendU16(out: *std.ArrayList(u8), allocator: Allocator, value: u16) Allocator.Error!void {
    var buf: [2]u8 = undefined;
    writeU16(&buf, value);
    try out.appendSlice(allocator, &buf);
}

fn appendU32(out: *std.ArrayList(u8), allocator: Allocator, value: u32) Allocator.Error!void {
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, value, .little);
    try out.appendSlice(allocator, &buf);
}

fn appendU64(out: *std.ArrayList(u8), allocator: Allocator, value: u64) Allocator.Error!void {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, value, .little);
    try out.appendSlice(allocator, &buf);
}

fn appendI64(out: *std.ArrayList(u8), allocator: Allocator, value: i64) Allocator.Error!void {
    try appendU64(out, allocator, @bitCast(value));
}

fn writeU16(out: *[2]u8, value: u16) void {
    std.mem.writeInt(u16, out, value, .little);
}

fn hlcFromKey(key: u64) clock.Hlc {
    return .{ .wall_ms = @intCast(key >> 16), .logical = @intCast(key & 0xffff) };
}

fn encodeMemberDelta(out: []u8, delta: *const channel_crdt.ChannelCrdt, member_id: channel_crdt.MemberId) ![]const u8 {
    var entity: [8]u8 = undefined;
    std.mem.writeInt(u64, &entity, member_id, .little);
    var view = DeltaView{ .family = .memberships, .entity_id = &entity, .hlc = delta.hlc };

    const entry = blk: {
        for (delta.members.items) |item| if (item.member_id == member_id) break :blk item;
        return error.InvalidChannelDelta;
    };

    for (entry.context.entries[0..entry.context.len]) |vv_entry| {
        var counter: u64 = 1;
        while (counter <= vv_entry.counter) : (counter += 1) {
            view.context[view.context_len] = .{ .replica = vv_entry.replica, .counter = counter };
            view.context_len += 1;
        }
    }
    sortDots(view.context[0..view.context_len]);

    var values: [delta_codec.default_limits.max_adds][25]u8 = undefined;
    for (entry.adds.items, 0..) |add, idx| {
        const dot = delta_codec.Dot{ .replica = add.dot.replica_id, .counter = add.dot.counter };
        writeMemberAdd(values[idx][0..], dot, add.hlc, add.status);
        view.add_dots[idx] = dot;
        view.adds[idx] = .{ .value = values[idx][0..], .dots_start = idx, .dots_len = 1 };
        view.adds_len += 1;
        view.add_dots_len += 1;
    }
    sortAdds(&view, &values);

    for (view.context[0..view.context_len]) |dot| {
        if (dotIn(view.add_dots[0..view.add_dots_len], dot)) continue;
        view.removes[view.removes_len] = dot;
        view.removes_len += 1;
    }
    return view.encode(out);
}

fn writeMemberAdd(out: []u8, dot: delta_codec.Dot, hlc: clock.Hlc, status: channel_crdt.MemberStatus) void {
    std.mem.writeInt(u64, out[0..8], dot.replica, .little);
    std.mem.writeInt(u64, out[8..16], dot.counter, .little);
    std.mem.writeInt(u64, out[16..24], hlc.toU64(), .little);
    out[24] = @as(u8, @bitCast(status));
}

fn sortAdds(view: *DeltaView, values: *[delta_codec.default_limits.max_adds][25]u8) void {
    var i: usize = 1;
    while (i < view.adds_len) : (i += 1) {
        var j = i;
        while (j > 0 and std.mem.order(u8, view.adds[j].value, view.adds[j - 1].value) == .lt) : (j -= 1) {
            std.mem.swap(DeltaView.Add, &view.adds[j], &view.adds[j - 1]);
            std.mem.swap(delta_codec.Dot, &view.add_dots[j], &view.add_dots[j - 1]);
            std.mem.swap([25]u8, &values[j], &values[j - 1]);
            view.adds[j].value = values[j][0..];
            view.adds[j - 1].value = values[j - 1][0..];
            view.adds[j].dots_start = j;
            view.adds[j - 1].dots_start = j - 1;
        }
    }
}

fn sortDots(dots: []delta_codec.Dot) void {
    std.mem.sort(delta_codec.Dot, dots, {}, struct {
        fn lessThan(_: void, a: delta_codec.Dot, b: delta_codec.Dot) bool {
            if (a.replica != b.replica) return a.replica < b.replica;
            return a.counter < b.counter;
        }
    }.lessThan);
}

fn dotIn(dots: []const delta_codec.Dot, dot: delta_codec.Dot) bool {
    for (dots) |candidate| {
        if (candidate.replica == dot.replica and candidate.counter == dot.counter) return true;
    }
    return false;
}

var test_pubkey: signed_delta.PublicKey = undefined;

fn verifyTest(signed: SignedDelta) bool {
    return signed_delta.verifyOne(signed, test_pubkey);
}

fn signChannelDelta(kp: *const signed_delta.KeyPair, op_bytes: []const u8, hlc: u64) !SignedDelta {
    return signed_delta.sign(.{
        .origin_node = signed_delta.nodeIdFromPublicKey(kp.public_key.toBytes()),
        .hlc = hlc,
        .family = @intFromEnum(delta_codec.EntityFamily.memberships),
        .scope = "#goryu",
        .op_bytes = op_bytes,
    }, kp);
}

test "overlapping divergent stores converge through bounded pump loop" {
    const allocator = std.testing.allocator;
    const kp = try signed_delta.KeyPair.generateDeterministic(@as([signed_delta.seed_len]u8, @splat(0x51)));
    test_pubkey = kp.public_key.toBytes();

    var state_a = channel_crdt.ChannelCrdt.init(allocator, 1);
    defer state_a.deinit();
    var state_b = channel_crdt.ChannelCrdt.init(allocator, 2);
    defer state_b.deinit();

    var common = try state_a.localJoin(7, .{ .voice = true }, 10);
    defer common.deinit();
    try state_b.merge(&common);
    var only_a = try state_a.localJoin(8, .{ .op = true }, 11);
    defer only_a.deinit();
    var only_b = try state_b.localJoin(9, .{ .founder = true }, 12);
    defer only_b.deinit();

    var buf_common: [1024]u8 = undefined;
    const s_common = try signChannelDelta(&kp, try encodeMemberDelta(&buf_common, &common, 7), common.hlc.toU64());
    var buf_a: [1024]u8 = undefined;
    const s_a = try signChannelDelta(&kp, try encodeMemberDelta(&buf_a, &only_a, 8), only_a.hlc.toU64());
    var buf_b: [1024]u8 = undefined;
    const s_b = try signChannelDelta(&kp, try encodeMemberDelta(&buf_b, &only_b, 9), only_b.hlc.toU64());

    var a = GoryuSync.init(allocator);
    defer a.deinit();
    var b = GoryuSync.init(allocator);
    defer b.deinit();
    try a.addLocalDelta(s_common);
    try a.addLocalDelta(s_a);
    try b.addLocalDelta(s_common);
    try b.addLocalDelta(s_b);
    try a.channel.merge(&state_a);
    try b.channel.merge(&state_b);

    var sa = try a.beginAntiEntropy(b.peer());
    defer sa.deinit();
    var sb = try b.beginAntiEntropy(a.peer());
    defer sb.deinit();

    var to_b = try sa.pump(&.{});
    defer allocator.free(to_b);
    var to_a = try sb.pump(&.{});
    defer allocator.free(to_a);

    var round: usize = 0;
    while (!std.mem.eql(u8, &a.rootHash(), &b.rootHash()) and round < 32) : (round += 1) {
        const next_b = try sa.pump(to_a);
        defer allocator.free(next_b);
        const next_a = try sb.pump(to_b);
        defer allocator.free(next_a);
        _ = try sa.applyVerified(verifyTest);
        _ = try sb.applyVerified(verifyTest);
        allocator.free(to_b);
        allocator.free(to_a);
        to_b = try allocator.dupe(u8, next_b);
        to_a = try allocator.dupe(u8, next_a);
    }

    try std.testing.expect(sa.converged());
    try std.testing.expect(sb.converged());
    try std.testing.expectEqual(a.rootHash(), b.rootHash());
    try std.testing.expect(channel_crdt.ChannelCrdt.eql(&a.channel, &b.channel));
}

test "identical stores exchange zero bytes" {
    const allocator = std.testing.allocator;
    var a = GoryuSync.init(allocator);
    defer a.deinit();
    var b = GoryuSync.init(allocator);
    defer b.deinit();

    var sa = try a.beginAntiEntropy(b.peer());
    defer sa.deinit();
    const out = try sa.pump(&.{});
    defer allocator.free(out);
    try std.testing.expect(sa.converged());
    try std.testing.expectEqual(@as(usize, 0), out.len);
}

test "invalid signed delta is rejected and not applied" {
    const allocator = std.testing.allocator;
    const kp = try signed_delta.KeyPair.generateDeterministic(@as([signed_delta.seed_len]u8, @splat(0x52)));
    test_pubkey = kp.public_key.toBytes();

    var source = channel_crdt.ChannelCrdt.init(allocator, 1);
    defer source.deinit();
    var delta = try source.localJoin(42, .{ .voice = true }, 50);
    defer delta.deinit();
    var buf: [1024]u8 = undefined;
    var bad = try signChannelDelta(&kp, try encodeMemberDelta(&buf, &delta, 42), delta.hlc.toU64());
    bad.signature[0] ^= 0xff;

    var sync = GoryuSync.init(allocator);
    defer sync.deinit();
    try sync.putPending(bad);
    try std.testing.expectError(error.VerificationFailed, sync.applyVerified(verifyTest));
    try std.testing.expect(!sync.channel.containsMember(42));
    try std.testing.expectEqual(@as(usize, 0), sync.store.count());
}

test "applyVerified processes every good pending delta even when one fails verify" {
    const allocator = std.testing.allocator;
    const kp = try signed_delta.KeyPair.generateDeterministic(@as([signed_delta.seed_len]u8, @splat(0x63)));
    test_pubkey = kp.public_key.toBytes();

    var sync = GoryuSync.init(allocator);
    defer sync.deinit();

    // Three deltas that verify, queued as pending.
    const good_members = [_]channel_crdt.MemberId{ 50, 51, 52 };
    for (good_members) |m| {
        var src = channel_crdt.ChannelCrdt.init(allocator, 1);
        defer src.deinit();
        var delta = try src.localJoin(m, .{ .voice = true }, 100 + m);
        defer delta.deinit();
        var buf: [1024]u8 = undefined;
        const good = try signChannelDelta(&kp, try encodeMemberDelta(&buf, &delta, m), delta.hlc.toU64());
        try sync.putPending(good);
    }

    // A fourth delta whose signature is corrupt — it fails verify.
    var bad_src = channel_crdt.ChannelCrdt.init(allocator, 1);
    defer bad_src.deinit();
    var bad_delta = try bad_src.localJoin(53, .{ .op = true }, 200);
    defer bad_delta.deinit();
    var bad_buf: [1024]u8 = undefined;
    var bad = try signChannelDelta(&kp, try encodeMemberDelta(&bad_buf, &bad_delta, 53), bad_delta.hlc.toU64());
    bad.signature[0] ^= 0xff;
    try sync.putPending(bad);

    // The one bad delta signals VerificationFailed, but every good delta is
    // still applied and pending is fully drained (no iterate-while-remove skip,
    // no early abort leaving the rest unprocessed).
    try std.testing.expectError(error.VerificationFailed, sync.applyVerified(verifyTest));
    try std.testing.expect(sync.channel.containsMember(50));
    try std.testing.expect(sync.channel.containsMember(51));
    try std.testing.expect(sync.channel.containsMember(52));
    try std.testing.expect(!sync.channel.containsMember(53));
    try std.testing.expectEqual(@as(usize, 0), sync.pending.count());
    try std.testing.expectEqual(@as(usize, 3), sync.store.count());
}

test "signed channel delta survives a wire crossing and applies on the peer" {
    const allocator = std.testing.allocator;
    const kp = try signed_delta.KeyPair.generateDeterministic(@as([signed_delta.seed_len]u8, @splat(0x71)));
    test_pubkey = kp.public_key.toBytes();

    // Origin builds a membership change locally and signs the canonical delta.
    var src = channel_crdt.ChannelCrdt.init(allocator, 1);
    defer src.deinit();
    var join = try src.localJoin(55, .{ .op = true }, 100);
    defer join.deinit();
    var op_buf: [1024]u8 = undefined;
    const op = try encodeMemberDelta(&op_buf, &join, 55);
    const signed = try signChannelDelta(&kp, op, join.hlc.toU64());

    // Serialize for the wire, then reconstruct and reverify on the far side.
    var wire_buf: [2048]u8 = undefined;
    const wire = try signed_delta.encodeSigned(signed, &wire_buf);
    const received = try signed_delta.decodeSigned(wire);
    try std.testing.expect(signed_delta.verifyOne(received, kp.public_key.toBytes()));

    // Peer ingests the wire delta through verify-before-apply.
    var peer = GoryuSync.init(allocator);
    defer peer.deinit();
    try peer.putPending(received);
    try std.testing.expectEqual(@as(usize, 1), try peer.applyVerified(verifyTest));
    try std.testing.expect(peer.channel.containsMember(55));
    // The reconstructed state matches the origin's, end to end.
    try std.testing.expect(channel_crdt.ChannelCrdt.eql(&peer.channel, &src));

    // A delta carrying the same payload but signed by a different key fails the
    // public-key->origin binding and is never applied.
    const evil = try signed_delta.KeyPair.generateDeterministic(@as([signed_delta.seed_len]u8, @splat(0x7e)));
    const forged = try signChannelDelta(&evil, op, join.hlc.toU64());
    var forged_wire: [2048]u8 = undefined;
    const forged_bytes = try signed_delta.encodeSigned(forged, &forged_wire);
    const forged_recv = try signed_delta.decodeSigned(forged_bytes);
    try std.testing.expect(!signed_delta.verifyOne(forged_recv, kp.public_key.toBytes()));

    var victim = GoryuSync.init(allocator);
    defer victim.deinit();
    try victim.putPending(forged_recv);
    try std.testing.expectError(error.VerificationFailed, victim.applyVerified(verifyTest));
    try std.testing.expect(!victim.channel.containsMember(55));
    try std.testing.expectEqual(@as(usize, 0), victim.store.count());
}

test "Config.applyToml overlays mesh.antientropy sync keys" {
    const allocator = std.testing.allocator;
    var doc = try toml.parse(allocator,
        \\[mesh.antientropy]
        \\symbols_per_pump = 48
        \\max_symbols = 256
    );
    defer doc.deinit(allocator);

    var cfg = Config{};
    cfg.applyToml(&doc);
    try std.testing.expectEqual(@as(usize, 48), cfg.symbols_per_pump);
    try std.testing.expectEqual(@as(usize, 256), cfg.max_symbols);
    try std.testing.expectEqual(@as(usize, 512), cfg.max_requests); // default
}
