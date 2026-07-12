// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure SUIMYAKU S2S link-session orchestrator.
//!
//! `peer_link` owns link sequencing, acknowledgements, and credit. This layer
//! frames convergent SUIMYAKU work over that link: initial channel burst, live
//! deltas, gossip payloads, and Merkle-guided anti-entropy repair.
const std = @import("std");

const anti_entropy_repair = @import("anti_entropy_repair.zig");
const burst = @import("burst.zig");
const channel_crdt = @import("channel_crdt.zig");
const clock_mod = @import("clock.zig");
const gossip_round = @import("gossip_round.zig");
const membership_view = @import("membership_view.zig");
const merkle = @import("merkle.zig");
const peer_link = @import("peer_link.zig");
const toml = @import("../../proto/toml.zig");

const Allocator = std.mem.Allocator;

pub const ChannelCrdt = channel_crdt.ChannelCrdt;
pub const NodeId = gossip_round.NodeId;
pub const PeerLink = peer_link.PeerLink;
pub const LinkState = peer_link.State;

const MessageKind = enum(u8) {
    burst = 1,
    delta = 2,
    gossip = 3,
    repair_summary = 4,
    repair_request = 5,
    repair_response = 6,
};

pub const Config = struct {
    burst_limits: burst.Limits = burst.default_limits,
    gossip_config: gossip_round.Config = .{ .fanout = 1 },
    gossip_interval_ms: u64 = 1_000,
    repair_interval_ms: u64 = 2_000,
    view_config: membership_view.Config = .{ .active_capacity = 4, .passive_capacity = 8 },
    sazanami_config: gossip_round.SazanamiConfig = .{},
    peer_link_config: peer_link.Config = .{},

    /// Overlay `[mesh.link]` keys (session cadence + per-session view/gossip
    /// overrides) and delegate to the embedded sub-configs (peer-link transport,
    /// burst limits). Sub-configs that draw from other `[mesh.*]` sections
    /// (gossip_config, sazanami_config) are applied by the orchestrator separately.
    pub fn applyToml(cfg: *Config, doc: *const toml.Document) void {
        if (doc.getUint("mesh.link.gossip_interval_ms")) |v| cfg.gossip_interval_ms = v;
        if (doc.getUint("mesh.link.repair_interval_ms")) |v| cfg.repair_interval_ms = v;
        if (doc.getUint("mesh.link.gossip_fanout")) |v| cfg.gossip_config.fanout = @intCast(v);
        if (doc.getUint("mesh.link.view_active_capacity")) |v| cfg.view_config.active_capacity = @intCast(v);
        if (doc.getUint("mesh.link.view_passive_capacity")) |v| cfg.view_config.passive_capacity = @intCast(v);
        cfg.peer_link_config.applyToml(doc);
        cfg.burst_limits.applyToml(doc);
    }
};

pub const Options = struct {
    clock: peer_link.Clock,
    local_epoch_ms: u64,
    local_node_id: NodeId,
    remote_node_id: NodeId,
    initial_send_credit: u32 = peer_link.default_send_credit,
    config: Config = .{},
};

pub const OutboundFrame = struct {
    bytes: []u8,

    pub fn deinit(self: *OutboundFrame, allocator: Allocator) void {
        allocator.free(self.bytes);
        self.bytes = &.{};
    }
};

pub const LinkSession = struct {
    allocator: Allocator,
    state: *ChannelCrdt,
    link: PeerLink,
    gossip: gossip_round.GossipRound,
    local_node_id: NodeId,
    remote_node_id: NodeId,
    config: Config,
    outbound: std.ArrayList(OutboundFrame) = .empty,
    last_gossip_ms: u64 = 0,
    last_repair_ms: u64 = 0,

    pub fn init(allocator: Allocator, state: *ChannelCrdt, options: Options) !LinkSession {
        var gossip = try gossip_round.GossipRound.init(
            allocator,
            options.local_node_id,
            options.config.view_config,
            options.config.sazanami_config,
        );
        errdefer gossip.deinit();

        return .{
            .allocator = allocator,
            .state = state,
            .link = PeerLink.init(.{
                .clock = options.clock,
                .local_epoch_ms = options.local_epoch_ms,
                .initial_send_credit = options.initial_send_credit,
                .replay_window = options.config.peer_link_config.replay_window,
                .handshake_timeout_ms = options.config.peer_link_config.handshake_timeout_ms,
                .heartbeat_interval_ms = options.config.peer_link_config.heartbeat_interval_ms,
                .idle_timeout_ms = options.config.peer_link_config.idle_timeout_ms,
                .drain_timeout_ms = options.config.peer_link_config.drain_timeout_ms,
            }),
            .gossip = gossip,
            .local_node_id = options.local_node_id,
            .remote_node_id = options.remote_node_id,
            .config = options.config,
        };
    }

    pub fn deinit(self: *LinkSession) void {
        self.clearOutbound();
        self.outbound.deinit(self.allocator);
        self.gossip.deinit();
    }

    pub fn establish(self: *LinkSession, remote_epoch_ms: u64, now_ms: u64, rng_seed: u64) !void {
        if (self.link.state == .idle) try self.link.beginHandshake();
        if (self.link.state == .handshaking) try self.link.finishHandshake(remote_epoch_ms);
        try self.gossip.observeJoin(self.remote_node_id, try i64Ms(now_ms), rng_seed);
        try self.enqueueCrdt(.burst, self.state);
        self.last_gossip_ms = now_ms;
        self.last_repair_ms = now_ms;
    }

    /// Snapshot the bounded transport state (seq/ack/credit/epoch) for a Helix
    /// resume. The CRDT `state` itself is NOT captured here — the successor starts
    /// with an empty replica and the anti-entropy repair backfills it from the peer
    /// (which never dropped) within one `repair_interval_ms`.
    pub fn snapshotResume(self: *const LinkSession) peer_link.PeerLink.ResumeHeader {
        return self.link.snapshotResume();
    }

    /// Rebuild a session directly in the established state from a resume header,
    /// bypassing the handshake+burst. The peer is marked as a live gossip member so
    /// Sazanami/repair immediately target it. `state` is a FRESH empty replica — the
    /// caller relies on repair (and an explicit local re-burst) to reconverge.
    pub fn resumeEstablished(
        allocator: Allocator,
        state: *ChannelCrdt,
        options: Options,
        hdr: peer_link.PeerLink.ResumeHeader,
        now_ms: u64,
        rng_seed: u64,
    ) !LinkSession {
        var gossip = try gossip_round.GossipRound.init(
            allocator,
            options.local_node_id,
            options.config.view_config,
            options.config.sazanami_config,
        );
        errdefer gossip.deinit();
        try gossip.observeJoin(options.remote_node_id, try i64Ms(now_ms), rng_seed);

        return .{
            .allocator = allocator,
            .state = state,
            .link = PeerLink.resumeEstablished(.{
                .clock = options.clock,
                .local_epoch_ms = options.local_epoch_ms,
                .initial_send_credit = options.initial_send_credit,
                .replay_window = options.config.peer_link_config.replay_window,
                .handshake_timeout_ms = options.config.peer_link_config.handshake_timeout_ms,
                .heartbeat_interval_ms = options.config.peer_link_config.heartbeat_interval_ms,
                .idle_timeout_ms = options.config.peer_link_config.idle_timeout_ms,
                .drain_timeout_ms = options.config.peer_link_config.drain_timeout_ms,
            }, hdr),
            .gossip = gossip,
            .local_node_id = options.local_node_id,
            .remote_node_id = options.remote_node_id,
            .config = options.config,
            .last_gossip_ms = now_ms,
            .last_repair_ms = now_ms,
        };
    }

    pub fn tick(self: *LinkSession, now_ms: u64, rng_seed: u64, peers: []const NodeId) !void {
        switch (self.link.tick()) {
            .heartbeat_due => try self.emitControl(.heartbeat),
            .draining, .closed, .none => {},
        }
        if (self.link.state != .established) return;

        if (elapsed(now_ms, self.last_gossip_ms) >= self.config.gossip_interval_ms) {
            var result = try self.gossip.run(
                try i64Ms(now_ms),
                rng_seed,
                peers,
                &.{},
                self.config.gossip_config,
            );
            defer result.deinit(self.allocator);
            if (containsNode(result.peers.items, self.remote_node_id)) {
                const bytes = try encodeGossip(self.allocator, &result.payload);
                defer self.allocator.free(bytes);
                try self.emitPayload(bytes);
            }
            self.last_gossip_ms = now_ms;
        }

        if (elapsed(now_ms, self.last_repair_ms) >= self.config.repair_interval_ms) {
            const bytes = try encodeRepairSummary(self.allocator, self.state);
            defer self.allocator.free(bytes);
            try self.emitPayload(bytes);
            self.last_repair_ms = now_ms;
        }
    }

    pub fn sendDelta(self: *LinkSession, delta: *const ChannelCrdt) !void {
        try self.enqueueCrdt(.delta, delta);
    }

    pub fn receive(self: *LinkSession, bytes: []const u8, now_ms: u64, rng_seed: u64) !void {
        const received = try self.link.receive(bytes);
        if (received.event != .delta) return;

        try self.applyPayload(received.payload, now_ms, rng_seed);
        if (self.link.state == .established or self.link.state == .draining) {
            try self.emitControl(.ack);
        }
    }

    pub fn outboundCount(self: *const LinkSession) usize {
        return self.outbound.items.len;
    }

    pub fn popOutbound(self: *LinkSession) ?OutboundFrame {
        if (self.outbound.items.len == 0) return null;
        return self.outbound.orderedRemove(0);
    }

    pub fn clearOutbound(self: *LinkSession) void {
        for (self.outbound.items) |*frame| frame.deinit(self.allocator);
        self.outbound.clearRetainingCapacity();
    }

    pub fn linkState(self: *const LinkSession) LinkState {
        return self.link.state;
    }

    pub fn sendCredit(self: *const LinkSession) u32 {
        return self.link.send_credit;
    }

    fn applyPayload(self: *LinkSession, payload: []const u8, now_ms: u64, rng_seed: u64) !void {
        if (payload.len == 0) return error.EmptyPayload;
        const body = payload[1..];
        switch (try decodeKind(payload[0])) {
            .burst, .delta => try burst.apply(self.allocator, self.state, body, self.config.burst_limits),
            .gossip => {
                var gossip_payload = try decodeGossip(self.allocator, body);
                defer gossip_payload.deinit(self.allocator);
                var rng = membership_view.Rng.init(mixSeed(rng_seed, self.local_node_id, self.remote_node_id));
                try self.gossip.applyPayload(&gossip_payload, try i64Ms(now_ms), &rng);
            },
            .repair_summary => {
                var remote = try decodeRepairSummary(self.allocator, body);
                defer remote.deinit();
                var local = try anti_entropy_repair.summarize(self.allocator, self.state);
                defer local.deinit();
                var ranges = try anti_entropy_repair.diff(self.allocator, &local, &remote);
                defer ranges.deinit();
                if (ranges.ranges.len == 0) return;
                var request = try anti_entropy_repair.buildRepairRequest(self.allocator, &ranges);
                defer request.deinit();
                const bytes = try encodeRepairRequest(self.allocator, &request);
                defer self.allocator.free(bytes);
                try self.emitPayload(bytes);
            },
            .repair_request => {
                var request = try decodeRepairRequest(self.allocator, body);
                defer request.deinit();
                var response = try anti_entropy_repair.buildRepairResponse(self.allocator, self.state, &request);
                defer response.deinit();
                if (response.records.len == 0) return;
                const bytes = try encodeRepairResponse(self.allocator, &response);
                defer self.allocator.free(bytes);
                try self.emitPayload(bytes);
            },
            .repair_response => {
                var response = try decodeRepairResponse(self.allocator, body);
                defer response.deinit();
                try anti_entropy_repair.applyRepairResponse(self.allocator, self.state, &response);
            },
        }
    }

    fn enqueueCrdt(self: *LinkSession, kind: MessageKind, source: *const ChannelCrdt) !void {
        const encoded = try burst.serialize(self.allocator, source, self.config.burst_limits);
        defer self.allocator.free(encoded);
        const payload = try withKind(self.allocator, kind, encoded);
        defer self.allocator.free(payload);
        try self.emitPayload(payload);
    }

    fn emitPayload(self: *LinkSession, payload: []const u8) !void {
        var out = try self.allocator.alloc(u8, peer_link.header_len + payload.len);
        errdefer self.allocator.free(out);
        const emitted = try self.link.emitDelta(payload, out);
        try self.outbound.append(self.allocator, .{ .bytes = out[0..emitted.bytes.len] });
    }

    fn emitControl(self: *LinkSession, kind: peer_link.FrameKind) !void {
        var out = try self.allocator.alloc(u8, peer_link.header_len);
        errdefer self.allocator.free(out);
        const emitted = switch (kind) {
            .ack => try self.link.emitAck(out),
            .heartbeat => try self.link.emitHeartbeat(out),
            .close => try self.link.emitClose(out),
            .delta => unreachable,
        };
        try self.outbound.append(self.allocator, .{ .bytes = out[0..emitted.bytes.len] });
    }
};

fn withKind(allocator: Allocator, kind: MessageKind, body: []const u8) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    try out.append(allocator, @intFromEnum(kind));
    try out.appendSlice(allocator, body);
    return out.toOwnedSlice(allocator);
}

fn encodeGossip(allocator: Allocator, payload: *const gossip_round.GossipPayload) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    try out.append(allocator, @intFromEnum(MessageKind.gossip));
    try writeU64(&out, allocator, payload.origin);
    try writeU64(&out, allocator, payload.origin_incarnation);
    try writeVarint(&out, allocator, payload.member_deltas.items.len);
    for (payload.member_deltas.items) |delta| {
        try writeU64(&out, allocator, delta.id);
        try out.append(allocator, @intFromEnum(delta.state));
        try writeU64(&out, allocator, delta.incarnation);
    }
    try writeVarint(&out, allocator, payload.suspicions.items.len);
    for (payload.suspicions.items) |s| {
        try writeU64(&out, allocator, s.node);
        try writeU64(&out, allocator, s.incarnation);
        try writeU64(&out, allocator, s.witness);
    }
    return out.toOwnedSlice(allocator);
}

fn decodeGossip(allocator: Allocator, bytes: []const u8) !gossip_round.GossipPayload {
    var r = Reader{ .buf = bytes };
    var out = gossip_round.GossipPayload{
        .origin = try r.readU64(),
        .origin_incarnation = try r.readU64(),
    };
    errdefer out.deinit(allocator);
    const deltas = try r.readVarint();
    var i: usize = 0;
    while (i < deltas) : (i += 1) {
        try out.member_deltas.append(allocator, .{
            .id = try r.readU64(),
            .state = try decodeMemberState(try r.readByte()),
            .incarnation = try r.readU64(),
        });
    }
    const suspicions = try r.readVarint();
    i = 0;
    while (i < suspicions) : (i += 1) {
        try out.suspicions.append(allocator, .{
            .node = try r.readU64(),
            .incarnation = try r.readU64(),
            .witness = try r.readU64(),
        });
    }
    if (!r.done()) return error.TrailingBytes;
    return out;
}

fn encodeRepairSummary(allocator: Allocator, state: *const ChannelCrdt) ![]u8 {
    var summary = try anti_entropy_repair.summarize(allocator, state);
    defer summary.deinit();

    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    try out.append(allocator, @intFromEnum(MessageKind.repair_summary));
    try writeVarint(&out, allocator, summary.entries.items.len);
    for (summary.entries.items) |entry| {
        try writeBytes(&out, allocator, entry.key);
        try out.appendSlice(allocator, &entry.hash);
    }
    return out.toOwnedSlice(allocator);
}

fn decodeRepairSummary(allocator: Allocator, bytes: []const u8) !anti_entropy_repair.Summary {
    var r = Reader{ .buf = bytes };
    var out = anti_entropy_repair.Summary{
        .allocator = allocator,
        .tree = merkle.MerkleTree.init(allocator),
    };
    errdefer out.deinit();

    const count = try r.readVarint();
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const key_view = try r.readBytes();
        const hash = try r.readHash();
        const key = try allocator.dupe(u8, key_view);
        errdefer allocator.free(key);
        try out.tree.put(key, hash);
        try out.entries.append(allocator, .{ .key = key, .hash = hash });
    }
    if (!r.done()) return error.TrailingBytes;
    return out;
}

fn encodeRepairRequest(allocator: Allocator, request: *const anti_entropy_repair.RepairRequest) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    try out.append(allocator, @intFromEnum(MessageKind.repair_request));
    try writeVarint(&out, allocator, request.keys.len);
    for (request.keys) |key| try writeBytes(&out, allocator, key);
    return out.toOwnedSlice(allocator);
}

fn decodeRepairRequest(allocator: Allocator, bytes: []const u8) !anti_entropy_repair.RepairRequest {
    var r = Reader{ .buf = bytes };
    var keys = std.ArrayList([]u8).empty;
    errdefer {
        for (keys.items) |key| allocator.free(key);
        keys.deinit(allocator);
    }
    const count = try r.readVarint();
    var i: usize = 0;
    while (i < count) : (i += 1) try keys.append(allocator, try allocator.dupe(u8, try r.readBytes()));
    if (!r.done()) return error.TrailingBytes;
    return .{ .allocator = allocator, .keys = try keys.toOwnedSlice(allocator) };
}

fn encodeRepairResponse(allocator: Allocator, response: *const anti_entropy_repair.RepairResponse) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    try out.append(allocator, @intFromEnum(MessageKind.repair_response));
    try writeU64(&out, allocator, response.hlc.toU64());
    try writeVersionVector(&out, allocator, response.vv);
    try writeVarint(&out, allocator, response.records.len);
    for (response.records) |record| {
        try out.append(allocator, @intFromEnum(record.kind));
        try writeBytes(&out, allocator, record.key);
        try writeBytes(&out, allocator, record.payload);
    }
    return out.toOwnedSlice(allocator);
}

fn decodeRepairResponse(allocator: Allocator, bytes: []const u8) !anti_entropy_repair.RepairResponse {
    var r = Reader{ .buf = bytes };
    const hlc = hlcFromKey(try r.readU64());
    const vv = try r.readVersionVector();
    var records = std.ArrayList(anti_entropy_repair.RepairRecord).empty;
    errdefer {
        for (records.items) |record| {
            allocator.free(record.key);
            allocator.free(record.payload);
        }
        records.deinit(allocator);
    }
    const count = try r.readVarint();
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const kind: anti_entropy_repair.RecordKind = switch (try r.readByte()) {
            1 => .member,
            2 => .mode,
            else => return error.InvalidRepairRecord,
        };
        const key = try allocator.dupe(u8, try r.readBytes());
        errdefer allocator.free(key);
        const payload = try allocator.dupe(u8, try r.readBytes());
        errdefer allocator.free(payload);
        try records.append(allocator, .{ .kind = kind, .key = key, .payload = payload });
    }
    if (!r.done()) return error.TrailingBytes;
    return .{ .allocator = allocator, .hlc = hlc, .vv = vv, .records = try records.toOwnedSlice(allocator) };
}

fn writeVersionVector(out: *std.ArrayList(u8), allocator: Allocator, vv: clock_mod.VersionVector) !void {
    try writeVarint(out, allocator, vv.len);
    for (vv.entries[0..vv.len]) |entry| {
        try writeU64(out, allocator, entry.replica);
        try writeU64(out, allocator, entry.counter);
    }
}

fn writeBytes(out: *std.ArrayList(u8), allocator: Allocator, bytes: []const u8) !void {
    try writeVarint(out, allocator, bytes.len);
    try out.appendSlice(allocator, bytes);
}

fn writeU64(out: *std.ArrayList(u8), allocator: Allocator, value: u64) !void {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, value, .little);
    try out.appendSlice(allocator, &buf);
}

fn writeVarint(out: *std.ArrayList(u8), allocator: Allocator, value: usize) !void {
    var n: u64 = @intCast(value);
    while (n >= 0x80) {
        try out.append(allocator, @as(u8, @intCast(n & 0x7f)) | 0x80);
        n >>= 7;
    }
    try out.append(allocator, @intCast(n));
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

    fn readU64(self: *Reader) !u64 {
        const bytes = try self.readFixed(8);
        return std.mem.readInt(u64, bytes[0..8], .little);
    }

    fn readHash(self: *Reader) !anti_entropy_repair.Hash {
        const bytes = try self.readFixed(32);
        var out: anti_entropy_repair.Hash = undefined;
        @memcpy(&out, bytes);
        return out;
    }

    fn readVersionVector(self: *Reader) !clock_mod.VersionVector {
        var vv = clock_mod.VersionVector.init();
        const count = try self.readVarint();
        if (count > clock_mod.VersionVector.max_entries) return error.InvalidVersionVector;
        var i: usize = 0;
        while (i < count) : (i += 1) {
            vv.entries[i] = .{ .replica = try self.readU64(), .counter = try self.readU64() };
        }
        vv.len = count;
        return vv;
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
        // Overflow-free bounds check: `len` is varint-sourced (up to usize-max),
        // so `self.pos + len` would wrap. `self.pos <= self.buf.len` always holds,
        // so the subtraction never underflows.
        if (len > self.buf.len - self.pos) return error.Truncated;
        const out = self.buf[self.pos .. self.pos + len];
        self.pos += len;
        return out;
    }
};

fn decodeKind(value: u8) !MessageKind {
    return switch (value) {
        1 => .burst,
        2 => .delta,
        3 => .gossip,
        4 => .repair_summary,
        5 => .repair_request,
        6 => .repair_response,
        else => error.UnknownMessageKind,
    };
}

fn decodeMemberState(value: u8) !gossip_round.MemberState {
    return switch (value) {
        0 => .alive,
        1 => .suspect,
        2 => .dead,
        3 => .left,
        else => error.UnknownMemberState,
    };
}

fn containsNode(nodes: []const NodeId, node: NodeId) bool {
    for (nodes) |candidate| if (candidate == node) return true;
    return false;
}

fn elapsed(now_ms: u64, since_ms: u64) u64 {
    return if (now_ms > since_ms) now_ms - since_ms else 0;
}

fn i64Ms(now_ms: u64) !i64 {
    if (now_ms > @as(u64, @intCast(std.math.maxInt(i64)))) return error.TimeOutOfRange;
    return @intCast(now_ms);
}

fn hlcFromKey(key: u64) clock_mod.Hlc {
    return .{ .wall_ms = @intCast(key >> 16), .logical = @intCast(key & 0xffff) };
}

fn mixSeed(a: u64, b: u64, c: u64) u64 {
    var x = a ^ (b *% 0x9e3779b97f4a7c15) ^ (c *% 0xbf58476d1ce4e5b9);
    x ^= x >> 30;
    x *%= 0xbf58476d1ce4e5b9;
    x ^= x >> 27;
    x *%= 0x94d049bb133111eb;
    return x ^ (x >> 31);
}

const TestClock = struct {
    now_ms: u64,

    fn clock(self: *TestClock) peer_link.Clock {
        return .{ .ptr = self, .now_fn = nowFn };
    }

    fn nowFn(ptr: *anyopaque) u64 {
        const self: *TestClock = @ptrCast(@alignCast(ptr));
        return self.now_ms;
    }
};

fn discard(delta: anytype) void {
    var owned = delta;
    owned.deinit();
}

fn pump(a: *LinkSession, b: *LinkSession, now_ms: u64, seed: u64) !void {
    var rounds: usize = 0;
    while (rounds < 128) : (rounds += 1) {
        var moved = false;
        while (a.popOutbound()) |frame_value| {
            var frame = frame_value;
            defer frame.deinit(a.allocator);
            try b.receive(frame.bytes, now_ms, seed +% @as(u64, @intCast(rounds)));
            moved = true;
        }
        while (b.popOutbound()) |frame_value| {
            var frame = frame_value;
            defer frame.deinit(b.allocator);
            try a.receive(frame.bytes, now_ms, seed +% 0x100 +% @as(u64, @intCast(rounds)));
            moved = true;
        }
        if (!moved) return;
    }
    return error.PumpDidNotSettle;
}

fn newSession(
    allocator: Allocator,
    state: *ChannelCrdt,
    tc: *TestClock,
    local_node: NodeId,
    remote_node: NodeId,
    epoch: u64,
) !LinkSession {
    return LinkSession.init(allocator, state, .{
        .clock = tc.clock(),
        .local_epoch_ms = epoch,
        .local_node_id = local_node,
        .remote_node_id = remote_node,
        .config = .{
            .gossip_interval_ms = 100,
            .repair_interval_ms = 200,
            .gossip_config = .{ .fanout = 1 },
        },
    });
}

test "two link sessions exchange initial burst and converge channel CRDT state" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();

    discard(try a_state.localJoin(10, .{ .op = true }, 10));
    discard(try a_state.localSetMode(.{ .invite_only = true }, 11));
    discard(try b_state.localJoin(20, .{ .voice = true }, 12));
    discard(try b_state.localSetMode(.{ .topic_protected = true }, 13));

    var a = try newSession(allocator, &a_state, &tc, 1, 2, 1000);
    defer a.deinit();
    var b = try newSession(allocator, &b_state, &tc, 2, 1, 2000);
    defer b.deinit();
    try a.establish(2000, tc.now_ms, 1);
    try b.establish(1000, tc.now_ms, 2);
    try pump(&a, &b, tc.now_ms, 0xA11CE);

    try std.testing.expect(ChannelCrdt.eql(&a_state, &b_state));
    try std.testing.expectEqual(LinkState.established, a.linkState());
    try std.testing.expect(a.sendCredit() > 0);
}

test "partition drops traffic then heal converges through anti entropy repair" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 1 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();
    discard(try a_state.localJoin(7, .{ .voice = true }, 1));

    var a = try newSession(allocator, &a_state, &tc, 1, 2, 10);
    defer a.deinit();
    var b = try newSession(allocator, &b_state, &tc, 2, 1, 20);
    defer b.deinit();
    try a.establish(20, tc.now_ms, 1);
    try b.establish(10, tc.now_ms, 2);
    try pump(&a, &b, tc.now_ms, 0xB00);
    try std.testing.expect(ChannelCrdt.eql(&a_state, &b_state));

    discard(try a_state.localJoin(8, .{ .op = true }, 20));
    discard(try a_state.localSetMode(.{ .secret = true }, 21));
    discard(try b_state.localPart(7));
    discard(try b_state.localJoin(9, .{ .founder = true }, 22));
    a.clearOutbound();
    b.clearOutbound();

    tc.now_ms += 250;
    const peers = [_]NodeId{ 1, 2 };
    try a.tick(tc.now_ms, 0xCAFE, &peers);
    try b.tick(tc.now_ms, 0xCAFE, &peers);
    try pump(&a, &b, tc.now_ms, 0xD00D);
    try std.testing.expect(ChannelCrdt.eql(&a_state, &b_state));
    try std.testing.expect(a_state.containsMember(8));
    try std.testing.expect(a_state.containsMember(9));
}

fn deterministicRun(seed: u64, out_a: *ChannelCrdt, out_b: *ChannelCrdt) !void {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 5 };
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();

    var a = try newSession(allocator, out_a, &tc, 1, 2, 100);
    defer a.deinit();
    var b = try newSession(allocator, out_b, &tc, 2, 1, 200);
    defer b.deinit();
    try a.establish(200, tc.now_ms, seed);
    try b.establish(100, tc.now_ms, seed +% 1);
    try pump(&a, &b, tc.now_ms, seed);

    var step: u64 = 0;
    while (step < 16) : (step += 1) {
        tc.now_ms += 17;
        if (random.boolean()) {
            var delta = try out_a.localJoin(100 + step, .{ .voice = random.boolean(), .op = random.boolean() }, tc.now_ms);
            defer delta.deinit();
            try a.sendDelta(&delta);
        } else {
            var delta = try out_b.localSetMode(.{ .limit = channel_crdt.LimitMode.set(@intCast(32 + step)) }, tc.now_ms);
            defer delta.deinit();
            try b.sendDelta(&delta);
        }
        const peers = [_]NodeId{ 1, 2 };
        try a.tick(tc.now_ms, seed +% step, &peers);
        try b.tick(tc.now_ms, seed +% step, &peers);
        try pump(&a, &b, tc.now_ms, seed +% step);
    }
}

test "link session convergence is deterministic with seed" {
    const allocator = std.testing.allocator;
    var a1 = ChannelCrdt.init(allocator, 1);
    defer a1.deinit();
    var b1 = ChannelCrdt.init(allocator, 2);
    defer b1.deinit();
    var a2 = ChannelCrdt.init(allocator, 1);
    defer a2.deinit();
    var b2 = ChannelCrdt.init(allocator, 2);
    defer b2.deinit();

    try deterministicRun(0x5155_10, &a1, &b1);
    try deterministicRun(0x5155_10, &a2, &b2);
    try std.testing.expect(ChannelCrdt.eql(&a1, &b1));
    try std.testing.expect(ChannelCrdt.eql(&a2, &b2));
    try std.testing.expect(ChannelCrdt.eql(&a1, &a2));
}

test "Config.applyToml overlays mesh.link session + delegates to sub-configs" {
    const allocator = std.testing.allocator;
    var doc = try toml.parse(allocator,
        \\[mesh.link]
        \\gossip_interval_ms = 1500
        \\repair_interval_ms = 3000
        \\gossip_fanout = 4
        \\view_active_capacity = 6
        \\send_credit_bytes = 131072
        \\burst_max_records = 1024
    );
    defer doc.deinit(allocator);

    var cfg = Config{};
    cfg.applyToml(&doc);
    try std.testing.expectEqual(@as(u64, 1500), cfg.gossip_interval_ms);
    try std.testing.expectEqual(@as(u64, 3000), cfg.repair_interval_ms);
    try std.testing.expectEqual(@as(usize, 4), cfg.gossip_config.fanout);
    try std.testing.expectEqual(@as(usize, 6), cfg.view_config.active_capacity);
    // Delegated sub-configs.
    try std.testing.expectEqual(@as(u32, 131072), cfg.peer_link_config.send_credit);
    try std.testing.expectEqual(@as(usize, 1024), cfg.burst_limits.max_records);
}
