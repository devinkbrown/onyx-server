// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded, detached Windows Helix checkpoint for the media control graph.
//!
//! This body is format checked, not authenticated. The Windows arena and its
//! private control exchange must authenticate it before `decode` is called.
//! Neither decoding nor preparing a candidate publishes a Domain or wakes an
//! owner; the active-media source guard stays in force until the physical UDP
//! owners have their own joined transaction.

const std = @import("std");
const crypto_scope = @import("../media_crypto_scope.zig");
const routing = @import("../../substrate/media_routing.zig");
const media = @import("../media_room.zig");
const bridge_mod = @import("../media_bridge.zig");
const native = @import("../native_media_transport.zig");

pub const Bridge = bridge_mod.ChannelBridge(native.max_call_participants);
pub const max_wire_bytes: usize = 64 * 1024 * 1024;
pub const max_alloc_bytes: usize = 128 * 1024 * 1024;
pub const max_rows: usize = routing.max_graph_rows * 2;
const magic = [4]u8{ 'H', 'X', 'M', 'G' };
const version: u16 = 3;
const header_len: usize = 12;
const digest_len: usize = 32;
const digest_domain = "onyx-windows-media-graph-checkpoint-v3";

pub const Error = routing.GraphError || media.SnapshotError || error{Capacity};

/// An exact source identity is joined to its inherited IRC socket, never to a
/// guessed successor slot. The integrator must prove each fd is in the sealed
/// `.clients` manifest; the candidate side supplies the actual adopted IDs.
pub const ClientSocket = struct { source: routing.ClientId, fd: i32 };
pub const AdoptedClient = struct { fd: i32, target: routing.ClientId };

pub const Attachment = struct {
    client: routing.ClientId,
    channel: [128]u8 = @splat(0),
    channel_len: u8 = 0,
    nick: [64]u8 = @splat(0),
    nick_len: u8 = 0,
    kind_bits: u8 = 0,

    pub fn init(client: routing.ClientId, channel: []const u8, nick: []const u8, kind_bits: u8) Error!Attachment {
        if (channel.len == 0 or channel.len > 128 or nick.len == 0 or nick.len > 64) return error.InvalidSnapshot;
        var row = Attachment{ .client = client, .channel_len = @intCast(channel.len), .nick_len = @intCast(nick.len), .kind_bits = kind_bits };
        @memcpy(row.channel[0..channel.len], channel);
        @memcpy(row.nick[0..nick.len], nick);
        try row.validate();
        return row;
    }
    pub fn channelSlice(self: *const Attachment) []const u8 {
        return self.channel[0..self.channel_len];
    }
    pub fn nickSlice(self: *const Attachment) []const u8 {
        return self.nick[0..self.nick_len];
    }
    fn validate(self: *const Attachment) Error!void {
        if (self.client.isNone() or self.channel_len == 0 or self.channel_len > self.channel.len or
            self.nick_len == 0 or self.nick_len > self.nick.len or self.kind_bits == 0 or
            self.kind_bits & ~@as(u8, 7) != 0) return error.InvalidSnapshot;
        for (self.channelSlice()) |byte| if (byte == 0) return error.InvalidSnapshot;
        for (self.nickSlice()) |byte| if (byte == 0) return error.InvalidSnapshot;
        for (self.channel[self.channel_len..]) |byte| if (byte != 0) return error.InvalidSnapshot;
        for (self.nick[self.nick_len..]) |byte| if (byte != 0) return error.InvalidSnapshot;
    }
};

/// Browser route/MAC scope only. Crypto provenance is an independent mandatory
/// array, joined to its exact inherited socket and newly allocated ClientId.
pub const CallBinding = struct {
    client: routing.ClientId,
    channel: [128]u8 = @splat(0),
    channel_len: u8 = 0,
    participant: [64]u8 = @splat(0),
    participant_len: u8 = 0,

    pub fn init(client: routing.ClientId, channel: []const u8, participant: []const u8) Error!CallBinding {
        if (channel.len == 0 or channel.len > 128 or participant.len == 0 or participant.len > 64) return error.InvalidSnapshot;
        var row = CallBinding{ .client = client, .channel_len = @intCast(channel.len), .participant_len = @intCast(participant.len) };
        @memcpy(row.channel[0..channel.len], channel);
        @memcpy(row.participant[0..participant.len], participant);
        try row.validate();
        return row;
    }
    pub fn channelSlice(self: *const CallBinding) []const u8 {
        return self.channel[0..self.channel_len];
    }
    pub fn participantSlice(self: *const CallBinding) []const u8 {
        return self.participant[0..self.participant_len];
    }
    fn validate(self: *const CallBinding) Error!void {
        if (self.client.isNone() or self.channel_len == 0 or self.channel_len > self.channel.len or
            self.participant_len == 0 or self.participant_len > self.participant.len) return error.InvalidSnapshot;
        for (self.channelSlice()) |byte| if (byte == 0) return error.InvalidSnapshot;
        for (self.participantSlice()) |byte| if (byte == 0) return error.InvalidSnapshot;
        for (self.channel[self.channel_len..]) |byte| if (byte != 0) return error.InvalidSnapshot;
        for (self.participant[self.participant_len..]) |byte| if (byte != 0) return error.InvalidSnapshot;
    }
};

pub const BridgeRow = struct { channel: []const u8, snapshot: Bridge.Snapshot };

/// Source fields borrow the already captured leaves. Callers hold the World
/// cut, both paused owner tokens, the producer fence, and the bridge lock while
/// taking those leaf snapshots. The resulting encoded bytes own their image.
/// Dedicated signed-crypto provenance; never inferred from browser routing.
pub const CryptoBinding = struct {
    client: routing.ClientId,
    scope: crypto_scope.Scope,
    pub fn init(client: routing.ClientId, scope: crypto_scope.Scope) Error!CryptoBinding {
        scope.validate() catch return error.InvalidSnapshot;
        if (client.isNone() or !scope.bound) return error.InvalidSnapshot;
        return .{ .client = client, .scope = scope };
    }
};

pub const Source = struct {
    graph: *const routing.GraphSnapshot,
    rooms: *const media.Snapshot,
    bridges: []const BridgeRow,
    clients: []const ClientSocket,
    attachments: []const Attachment,
    bindings: []const CallBinding,
    crypto_bindings: []const CryptoBinding,

    pub fn validate(self: Source) Error!void {
        try self.graph.validate();
        try self.rooms.validateAgainstGraph(self.graph);
        if (self.bridges.len > media.max_snapshot_rooms or self.clients.len > max_rows or
            self.attachments.len > max_rows or self.bindings.len > max_rows or self.crypto_bindings.len > max_rows) return error.Capacity;

        for (self.clients, 0..) |row, i| {
            if (row.fd < 0 or row.source.isNone() or !graphUsesClient(self.graph, row.source)) return error.InvalidSnapshot;
            for (self.clients[0..i]) |prior| if (prior.fd == row.fd or prior.source.eql(row.source)) return error.InvalidSnapshot;
        }
        for (self.graph.endpoints) |row| if (!hasClient(self.clients, row.key.client)) return error.IncompleteRemap;
        for (self.graph.memberships) |row| if (!hasClient(self.clients, row.key.client)) return error.IncompleteRemap;

        for (self.attachments, 0..) |*row, i| {
            try row.validate();
            if (!hasClient(self.clients, row.client)) return error.IncompleteRemap;
            const call = graphCall(self.graph, row.channelSlice()) orelse return error.InvalidSnapshot;
            const member = graphMember(self.graph, call, row.client) orelse return error.InvalidSnapshot;
            if (member.bits != row.kind_bits) return error.InvalidSnapshot;
            const physical = roomMember(self.rooms, call, row.client) orelse return error.InvalidSnapshot;
            if (!std.ascii.eqlIgnoreCase(physical.display.slice(), row.nickSlice())) return error.InvalidSnapshot;
            for (self.attachments[0..i]) |*prior| if (prior.client.eql(row.client) and
                std.ascii.eqlIgnoreCase(prior.channelSlice(), row.channelSlice())) return error.InvalidSnapshot;
        }
        for (self.graph.memberships) |member| {
            var seen = false;
            for (self.attachments) |*row| if (row.client.eql(member.key.client) and
                graphCall(self.graph, row.channelSlice()) != null and
                std.meta.eql(graphCall(self.graph, row.channelSlice()).?, member.key.call))
            {
                seen = true;
                break;
            };
            if (!seen) return error.InvalidSnapshot;
        }

        for (self.bindings, 0..) |*row, i| {
            try row.validate();
            if (!hasClient(self.clients, row.client)) return error.IncompleteRemap;
            var attached = false;
            for (self.attachments) |*member| if (member.client.eql(row.client) and
                std.ascii.eqlIgnoreCase(member.channelSlice(), row.channelSlice()) and
                std.ascii.eqlIgnoreCase(member.nickSlice(), row.participantSlice()))
            {
                attached = true;
                break;
            };
            if (!attached) return error.InvalidSnapshot;
            for (self.bindings[0..i]) |prior| if (prior.client.eql(row.client)) return error.InvalidSnapshot;
        }

        for (self.crypto_bindings, 0..) |row, i| {
            _ = try CryptoBinding.init(row.client, row.scope);
            if (!hasClient(self.clients, row.client)) return error.IncompleteRemap;
            var attached = false;
            for (self.attachments) |*member| if (member.client.eql(row.client) and
                std.ascii.eqlIgnoreCase(member.channelSlice(), row.scope.channelSlice()) and
                std.ascii.eqlIgnoreCase(member.nickSlice(), row.scope.participantSlice()))
            {
                attached = true;
                break;
            };
            if (!attached) return error.InvalidSnapshot;
            for (self.crypto_bindings[0..i]) |prior| {
                if (prior.client.eql(row.client) or prior.scope.sameTuple(&row.scope)) return error.InvalidSnapshot;
            }
        }

        for (self.bridges, 0..) |*row, i| {
            if (row.channel.len == 0 or row.channel.len > 128 or
                graphCall(self.graph, row.channel) == null) return error.InvalidSnapshot;
            try row.snapshot.validate();
            for (self.bridges[0..i]) |prior| if (std.ascii.eqlIgnoreCase(prior.channel, row.channel)) return error.InvalidSnapshot;
            for (row.snapshot.members[0..row.snapshot.len]) |member| {
                var attached = false;
                for (self.attachments) |*physical| if (std.ascii.eqlIgnoreCase(physical.channelSlice(), row.channel) and
                    std.ascii.eqlIgnoreCase(physical.nickSlice(), member.id_buf[0..member.id_len]))
                {
                    attached = true;
                    break;
                };
                if (!attached) return error.InvalidSnapshot;
            }
        }
    }
};

pub const Snapshot = struct {
    allocator: std.mem.Allocator,
    graph: routing.GraphSnapshot,
    rooms: media.Snapshot,
    bridges: []BridgeRow,
    clients: []ClientSocket,
    attachments: []Attachment,
    bindings: []CallBinding,
    crypto_bindings: []CryptoBinding,

    pub fn deinit(self: *Snapshot) void {
        for (self.bridges) |row| self.allocator.free(row.channel);
        freeBindings(self.allocator, self.bindings);
        freeCryptoBindings(self.allocator, self.crypto_bindings);
        self.allocator.free(self.attachments);
        self.allocator.free(self.clients);
        self.allocator.free(self.bridges);
        self.rooms.deinit();
        self.graph.deinit();
        self.* = undefined;
    }
    pub fn validate(self: *const Snapshot) Error!void {
        try (Source{ .graph = &self.graph, .rooms = &self.rooms, .bridges = self.bridges, .clients = self.clients, .attachments = self.attachments, .bindings = self.bindings, .crypto_bindings = self.crypto_bindings }).validate();
        try validateOrder(self);
    }
    /// Construct only private candidate storage. The returned graph remains a
    /// DTO; no Domain, socket, worker, or bridge map has been made routable.
    pub fn prepare(self: *const Snapshot, allocator: std.mem.Allocator, adopted: []const AdoptedClient) Error!Prepared {
        try self.validate();
        if (adopted.len > max_rows) return error.Capacity;
        for (adopted, 0..) |row, i| {
            if (row.fd < 0 or row.target.isNone()) return error.InvalidSnapshot;
            for (adopted[0..i]) |prior| if (prior.fd == row.fd or prior.target.eql(row.target)) return error.InvalidSnapshot;
        }
        const remaps = try allocator.alloc(routing.ClientRemap, self.clients.len);
        errdefer allocator.free(remaps);
        for (self.clients, remaps) |source, *mapping| {
            var target: ?routing.ClientId = null;
            for (adopted) |live| if (live.fd == source.fd) {
                target = live.target;
                break;
            };
            mapping.* = .{ .source = source.source, .target = target orelse return error.IncompleteRemap };
        }
        var graph = try routing.prepareRemappedGraph(allocator, &self.graph, remaps);
        errdefer graph.deinit();
        var rooms = try media.MediaRooms.prepareRestore(allocator, &self.rooms, remaps);
        errdefer rooms.deinit();
        var bridges: std.StringHashMapUnmanaged(Bridge) = .empty;
        errdefer freeBridges(allocator, &bridges);
        try bridges.ensureTotalCapacity(allocator, @intCast(self.bridges.len));
        for (self.bridges) |row| {
            const key = try allocator.dupe(u8, row.channel);
            errdefer allocator.free(key);
            const value = try Bridge.prepareRestore(&row.snapshot);
            bridges.putAssumeCapacity(key, value);
        }
        const attachments = try allocator.dupe(Attachment, self.attachments);
        errdefer allocator.free(attachments);
        for (attachments) |*row| row.client = remapClient(remaps, row.client) orelse unreachable;
        const bindings = try allocator.dupe(CallBinding, self.bindings);
        errdefer freeBindings(allocator, bindings);
        for (bindings) |*row| row.client = remapClient(remaps, row.client) orelse unreachable;
        const crypto_bindings = try allocator.dupe(CryptoBinding, self.crypto_bindings);
        errdefer freeCryptoBindings(allocator, crypto_bindings);
        for (crypto_bindings) |*row| row.client = remapClient(remaps, row.client) orelse unreachable;
        return .{ .allocator = allocator, .graph = graph, .rooms = rooms, .bridges = bridges, .remaps = remaps, .attachments = attachments, .bindings = bindings, .crypto_bindings = crypto_bindings };
    }
};

pub const Prepared = struct {
    allocator: std.mem.Allocator,
    graph: routing.GraphSnapshot,
    rooms: media.MediaRooms,
    bridges: std.StringHashMapUnmanaged(Bridge),
    remaps: []routing.ClientRemap,
    attachments: []Attachment,
    bindings: []CallBinding,
    crypto_bindings: []CryptoBinding,

    pub fn deinit(self: *Prepared) void {
        freeBindings(self.allocator, self.bindings);
        freeCryptoBindings(self.allocator, self.crypto_bindings);
        self.allocator.free(self.attachments);
        self.allocator.free(self.remaps);
        freeBridges(self.allocator, &self.bridges);
        self.rooms.deinit();
        self.graph.deinit();
        self.* = undefined;
    }
};

fn freeCryptoBindings(allocator: std.mem.Allocator, bindings: []CryptoBinding) void {
    std.crypto.secureZero(u8, std.mem.sliceAsBytes(bindings));
    allocator.free(bindings);
}

fn freeBindings(allocator: std.mem.Allocator, bindings: []CallBinding) void {
    std.crypto.secureZero(u8, std.mem.sliceAsBytes(bindings));
    allocator.free(bindings);
}

/// Encoded graph bodies include E2EE attachments. The caller must wipe this
/// cleartext after placing it in the authenticated and encrypted arena.
pub fn freeEncoded(allocator: std.mem.Allocator, bytes: []u8) void {
    std.crypto.secureZero(u8, bytes);
    allocator.free(bytes);
}

fn freeBridges(allocator: std.mem.Allocator, map: *std.StringHashMapUnmanaged(Bridge)) void {
    var keys = map.keyIterator();
    while (keys.next()) |key| allocator.free(key.*);
    map.deinit(allocator);
}
fn clientLess(a: routing.ClientId, b: routing.ClientId) bool {
    if (a.shard != b.shard) return a.shard < b.shard;
    if (a.slot != b.slot) return a.slot < b.slot;
    return a.gen < b.gen;
}
fn callLess(a: routing.CallId, b: routing.CallId) bool {
    if (a.domain.serial != b.domain.serial) return a.domain.serial < b.domain.serial;
    return a.serial < b.serial;
}
fn endpointLess(a: routing.EndpointKey, b: routing.EndpointKey) bool {
    if (!std.meta.eql(a.call, b.call)) return callLess(a.call, b.call);
    if (!a.client.eql(b.client)) return clientLess(a.client, b.client);
    return @backingInt(a.leg) < @backingInt(b.leg);
}
fn membershipLess(a: routing.MembershipKey, b: routing.MembershipKey) bool {
    if (!std.meta.eql(a.call, b.call)) return callLess(a.call, b.call);
    return clientLess(a.client, b.client);
}
fn bytesLess(a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}
fn channelLess(a: routing.ChannelKey, b: routing.ChannelKey) bool {
    return bytesLess(a.bytes[0..a.len], b.bytes[0..b.len]);
}
fn attachmentLess(a: Attachment, b: Attachment) bool {
    if (!a.client.eql(b.client)) return clientLess(a.client, b.client);
    return bytesLess(a.channelSlice(), b.channelSlice());
}
fn sortedRows(comptime T: type, slice: []const T, comptime less: fn (T, T) bool) bool {
    if (slice.len < 2) return true;
    for (slice[1..], 1..) |row, i| if (!less(slice[i - 1], row)) return false;
    return true;
}
fn stringRowLess(comptime T: type, a: T, b: T) bool {
    return bytesLess(a.key, b.key);
}
fn stringLessFn(comptime T: type) fn (T, T) bool {
    return struct {
        fn less(a: T, b: T) bool {
            return stringRowLess(T, a, b);
        }
    }.less;
}
fn sortedCopy(comptime T: type, allocator: std.mem.Allocator, rows: []const T, comptime less: fn (T, T) bool) Error![]T {
    const out = try allocator.dupe(T, rows);
    std.mem.sort(T, out, {}, struct {
        fn order(_: void, a: T, b: T) bool {
            return less(a, b);
        }
    }.order);
    return out;
}
fn validateOrder(snapshot: *const Snapshot) Error!void {
    if (!sortedRows(routing.GraphCall, snapshot.graph.calls, struct {
        fn less(a: routing.GraphCall, b: routing.GraphCall) bool {
            return channelLess(a.channel, b.channel);
        }
    }.less) or
        !sortedRows(routing.GraphEndpoint, snapshot.graph.endpoints, struct {
            fn less(a: routing.GraphEndpoint, b: routing.GraphEndpoint) bool {
                return endpointLess(a.key, b.key);
            }
        }.less) or
        !sortedRows(routing.GraphMembership, snapshot.graph.memberships, struct {
            fn less(a: routing.GraphMembership, b: routing.GraphMembership) bool {
                return membershipLess(a.key, b.key);
            }
        }.less) or
        !sortedRows(routing.GraphBridgePolicy, snapshot.graph.bridge_policy, struct {
            fn less(a: routing.GraphBridgePolicy, b: routing.GraphBridgePolicy) bool {
                return endpointLess(a.key, b.key);
            }
        }.less) or
        !sortedRows(media.PhysicalProfileRow, snapshot.rooms.physical_profiles, struct {
            fn less(a: media.PhysicalProfileRow, b: media.PhysicalProfileRow) bool {
                return endpointLess(a.key, b.key);
            }
        }.less) or
        !sortedRows(media.PhysicalMemberRow, snapshot.rooms.physical_members, struct {
            fn less(a: media.PhysicalMemberRow, b: media.PhysicalMemberRow) bool {
                return membershipLess(.{ .call = a.key.call, .client = a.key.client }, .{ .call = b.key.call, .client = b.key.client });
            }
        }.less) or
        !sortedRows(media.RoomRow, snapshot.rooms.rooms, struct {
            fn less(a: media.RoomRow, b: media.RoomRow) bool {
                return bytesLess(a.key, b.key);
            }
        }.less) or
        !sortedRows(BridgeRow, snapshot.bridges, struct {
            fn less(a: BridgeRow, b: BridgeRow) bool {
                return bytesLess(a.channel, b.channel);
            }
        }.less) or
        !sortedRows(ClientSocket, snapshot.clients, struct {
            fn less(a: ClientSocket, b: ClientSocket) bool {
                return clientLess(a.source, b.source);
            }
        }.less) or
        !sortedRows(Attachment, snapshot.attachments, attachmentLess) or
        !sortedRows(CallBinding, snapshot.bindings, struct {
            fn less(a: CallBinding, b: CallBinding) bool {
                return clientLess(a.client, b.client);
            }
        }.less) or !sortedRows(CryptoBinding, snapshot.crypto_bindings, struct {
        fn less(a: CryptoBinding, b: CryptoBinding) bool {
            return clientLess(a.client, b.client);
        }
    }.less)) return error.InvalidSnapshot;
    inline for (.{ snapshot.rooms.breakouts, snapshot.rooms.positions, snapshot.rooms.hands, snapshot.rooms.profiles, snapshot.rooms.participant_profiles, snapshot.rooms.consents, snapshot.rooms.recordings, snapshot.rooms.qualities, snapshot.rooms.queues }) |rows| {
        const T = @typeInfo(@TypeOf(rows)).pointer.child;
        if (!sortedRows(T, rows, stringLessFn(T))) return error.InvalidSnapshot;
    }
}
fn graphUsesClient(graph: *const routing.GraphSnapshot, client: routing.ClientId) bool {
    for (graph.endpoints) |row| if (row.key.client.eql(client)) return true;
    for (graph.memberships) |row| if (row.key.client.eql(client)) return true;
    return false;
}
fn hasClient(clients: []const ClientSocket, client: routing.ClientId) bool {
    for (clients) |row| if (row.source.eql(client)) return true;
    return false;
}
fn graphCall(graph: *const routing.GraphSnapshot, channel: []const u8) ?routing.CallId {
    const key = routing.ChannelKey.init(channel) catch return null;
    for (graph.calls) |row| if (std.meta.eql(row.channel, key)) return row.row.id;
    return null;
}
fn graphMember(graph: *const routing.GraphSnapshot, call: routing.CallId, client: routing.ClientId) ?routing.MembershipEntry {
    for (graph.memberships) |row| if (std.meta.eql(row.key.call, call) and row.key.client.eql(client)) return row.row;
    return null;
}
fn roomMember(rooms: *const media.Snapshot, call: routing.CallId, client: routing.ClientId) ?media.PhysicalMember {
    for (rooms.physical_members) |row| if (std.meta.eql(row.key.call, call) and row.key.client.eql(client)) return row.member;
    return null;
}
fn remapClient(remaps: []const routing.ClientRemap, id: routing.ClientId) ?routing.ClientId {
    for (remaps) |row| if (row.source.eql(id)) return row.target;
    return null;
}

const Writer = struct {
    bytes: []u8,
    pos: usize = 0,
    fn put(self: *Writer, part: []const u8) void {
        std.debug.assert(part.len <= self.bytes.len - self.pos);
        @memcpy(self.bytes[self.pos..][0..part.len], part);
        self.pos += part.len;
    }
    fn int(self: *Writer, comptime T: type, value: T) void {
        const I = @Int(@typeInfo(T).int.signedness, @sizeOf(T) * 8);
        var buf: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(I, &buf, @intCast(value), .little);
        self.put(&buf);
    }
};
const Reader = struct {
    bytes: []const u8,
    pos: usize = 0,
    alloc_bytes: usize = 0,
    fn take(self: *Reader, len: usize) Error![]const u8 {
        if (len > self.bytes.len - self.pos) return error.InvalidSnapshot;
        const part = self.bytes[self.pos..][0..len];
        self.pos += len;
        return part;
    }
    fn int(self: *Reader, comptime T: type) Error!T {
        const I = @Int(@typeInfo(T).int.signedness, @sizeOf(T) * 8);
        var buf: [@sizeOf(T)]u8 = undefined;
        @memcpy(&buf, try self.take(buf.len));
        return std.math.cast(T, std.mem.readInt(I, &buf, .little)) orelse error.InvalidSnapshot;
    }
    fn budget(self: *Reader, comptime T: type, count: usize) Error!void {
        const bytes = std.math.mul(usize, count, @sizeOf(T)) catch return error.Capacity;
        self.alloc_bytes = std.math.add(usize, self.alloc_bytes, bytes) catch return error.Capacity;
        if (self.alloc_bytes > max_alloc_bytes) return error.Capacity;
    }
};

fn valueSize(comptime T: type, value: T) Error!usize {
    if (T == std.mem.Allocator or T == void) return 0;
    return switch (@typeInfo(T)) {
        .bool => 1,
        .int => @sizeOf(T),
        .float => @sizeOf(T),
        .@"enum" => |e| @sizeOf(e.tag_type),
        .optional => |o| blk: {
            var n: usize = 1;
            if (value) |v| n = try addSize(n, try valueSize(o.child, v));
            break :blk n;
        },
        .array => |a| blk: {
            var n: usize = 0;
            for (value) |v| n = try addSize(n, try valueSize(a.child, v));
            break :blk n;
        },
        .pointer => |p| blk: {
            if (p.size != .slice) @compileError("media graph wire rejects pointers");
            if (value.len > std.math.maxInt(u32)) return error.Capacity;
            var n: usize = 4;
            for (value) |v| n = try addSize(n, try valueSize(p.child, v));
            break :blk n;
        },
        .@"struct" => |s| blk: {
            var n: usize = 0;
            inline for (s.field_names, s.field_types) |name, FieldType| n = try addSize(n, try valueSize(FieldType, @field(value, name)));
            break :blk n;
        },
        else => @compileError("unsupported media graph wire field"),
    };
}
fn addSize(a: usize, b: usize) Error!usize {
    return std.math.add(usize, a, b) catch error.Capacity;
}

fn writeValue(w: *Writer, comptime T: type, value: T) void {
    if (T == std.mem.Allocator or T == void) return;
    switch (@typeInfo(T)) {
        .bool => w.int(u8, @intFromBool(value)),
        .int => w.int(T, value),
        .float => {
            const I = @Int(.unsigned, @sizeOf(T) * 8);
            w.int(I, @bitCast(value));
        },
        .@"enum" => |e| w.int(e.tag_type, @backingInt(value)),
        .optional => |o| {
            w.int(u8, @intFromBool(value != null));
            if (value) |v| writeValue(w, o.child, v);
        },
        .array => |a| for (value) |v| writeValue(w, a.child, v),
        .pointer => |p| {
            if (p.size != .slice) @compileError("media graph wire rejects pointers");
            w.int(u32, @intCast(value.len));
            for (value) |v| writeValue(w, p.child, v);
        },
        .@"struct" => |s| inline for (s.field_names, s.field_types) |name, FieldType| writeValue(w, FieldType, @field(value, name)),
        else => @compileError("unsupported media graph wire field"),
    }
}

/// A no-allocation structural pass over the complete authenticated body.
fn scanValue(r: *Reader, comptime T: type) Error!void {
    if (T == std.mem.Allocator or T == void) return;
    switch (@typeInfo(T)) {
        .bool => if (try r.int(u8) > 1) return error.InvalidSnapshot,
        .int => _ = try r.int(T),
        .float => _ = try r.take(@sizeOf(T)),
        .@"enum" => |e| {
            const raw = try r.int(e.tag_type);
            _ = std.enums.fromInt(T, raw) orelse return error.InvalidSnapshot;
        },
        .optional => |o| {
            const present = try r.int(u8);
            if (present > 1) return error.InvalidSnapshot;
            if (present == 1) try scanValue(r, o.child);
        },
        .array => |a| for (0..a.len) |_| try scanValue(r, a.child),
        .pointer => |p| {
            if (p.size != .slice) @compileError("media graph wire rejects pointers");
            const count = try r.int(u32);
            if (count > (if (p.child == u8) max_wire_bytes else max_rows)) return error.Capacity;
            try r.budget(p.child, count);
            for (0..count) |_| try scanValue(r, p.child);
        },
        .@"struct" => |s| inline for (s.field_types) |FieldType| try scanValue(r, FieldType),
        else => @compileError("unsupported media graph wire field"),
    }
}

fn freeValue(comptime T: type, allocator: std.mem.Allocator, value: T) void {
    if (T == std.mem.Allocator or T == void) return;
    switch (@typeInfo(T)) {
        .optional => |o| if (value) |v| freeValue(o.child, allocator, v),
        .array => |a| for (value) |v| freeValue(a.child, allocator, v),
        .pointer => |p| {
            if (p.size != .slice) @compileError("media graph wire rejects pointers");
            for (value) |v| freeValue(p.child, allocator, v);
            if (p.child == CallBinding) std.crypto.secureZero(u8, @constCast(std.mem.sliceAsBytes(value)));
            allocator.free(value);
        },
        .@"struct" => |s| inline for (s.field_names, s.field_types) |name, FieldType| freeValue(FieldType, allocator, @field(value, name)),
        else => {},
    }
}

fn readValue(r: *Reader, allocator: std.mem.Allocator, comptime T: type) Error!T {
    if (T == std.mem.Allocator) return allocator;
    if (T == void) return {};
    return switch (@typeInfo(T)) {
        .bool => blk: {
            const v = try r.int(u8);
            if (v > 1) return error.InvalidSnapshot;
            break :blk v == 1;
        },
        .int => try r.int(T),
        .float => blk: {
            const I = @Int(.unsigned, @sizeOf(T) * 8);
            break :blk @bitCast(try r.int(I));
        },
        .@"enum" => |e| std.enums.fromInt(T, try r.int(e.tag_type)) orelse return error.InvalidSnapshot,
        .optional => |o| blk: {
            const present = try r.int(u8);
            if (present > 1) return error.InvalidSnapshot;
            break :blk if (present == 1) try readValue(r, allocator, o.child) else null;
        },
        .array => |a| blk: {
            var out: T = undefined;
            var done: usize = 0;
            errdefer for (out[0..done]) |v| freeValue(a.child, allocator, v);
            for (&out) |*slot| {
                slot.* = try readValue(r, allocator, a.child);
                done += 1;
            }
            break :blk out;
        },
        .pointer => |p| blk: {
            if (p.size != .slice) @compileError("media graph wire rejects pointers");
            const count = try r.int(u32);
            if (count > (if (p.child == u8) max_wire_bytes else max_rows)) return error.Capacity;
            var out = try allocator.alloc(p.child, count);
            var done: usize = 0;
            errdefer {
                for (out[0..done]) |v| freeValue(p.child, allocator, v);
                if (p.child == CallBinding) std.crypto.secureZero(u8, std.mem.sliceAsBytes(out[0..done]));
                allocator.free(out);
            }
            for (out) |*slot| {
                slot.* = try readValue(r, allocator, p.child);
                done += 1;
            }
            break :blk out;
        },
        .@"struct" => |s| blk: {
            var out: T = undefined;
            var done: usize = 0;
            errdefer inline for (s.field_names, s.field_types, 0..) |name, FieldType, i| {
                if (done > i) freeValue(FieldType, allocator, @field(out, name));
            };
            inline for (s.field_names, s.field_types) |name, FieldType| {
                @field(out, name) = try readValue(r, allocator, FieldType);
                done += 1;
            }
            break :blk out;
        },
        else => @compileError("unsupported media graph wire field"),
    };
}

pub fn encode(allocator: std.mem.Allocator, source: Source) Error![]u8 {
    // Live graph and room maps iterate in hash order. Sort shallow, private
    // copies so a single semantic state has exactly one wire representation.
    var scratch = std.heap.ArenaAllocator.init(allocator);
    defer scratch.deinit();
    const a = scratch.allocator();
    var graph = source.graph.*;
    graph.calls = try sortedCopy(routing.GraphCall, a, graph.calls, struct {
        fn less(x: routing.GraphCall, y: routing.GraphCall) bool {
            return channelLess(x.channel, y.channel);
        }
    }.less);
    graph.endpoints = try sortedCopy(routing.GraphEndpoint, a, graph.endpoints, struct {
        fn less(x: routing.GraphEndpoint, y: routing.GraphEndpoint) bool {
            return endpointLess(x.key, y.key);
        }
    }.less);
    graph.memberships = try sortedCopy(routing.GraphMembership, a, graph.memberships, struct {
        fn less(x: routing.GraphMembership, y: routing.GraphMembership) bool {
            return membershipLess(x.key, y.key);
        }
    }.less);
    graph.bridge_policy = try sortedCopy(routing.GraphBridgePolicy, a, graph.bridge_policy, struct {
        fn less(x: routing.GraphBridgePolicy, y: routing.GraphBridgePolicy) bool {
            return endpointLess(x.key, y.key);
        }
    }.less);
    var rooms = source.rooms.*;
    rooms.physical_profiles = try sortedCopy(media.PhysicalProfileRow, a, rooms.physical_profiles, struct {
        fn less(x: media.PhysicalProfileRow, y: media.PhysicalProfileRow) bool {
            return endpointLess(x.key, y.key);
        }
    }.less);
    rooms.physical_members = try sortedCopy(media.PhysicalMemberRow, a, rooms.physical_members, struct {
        fn less(x: media.PhysicalMemberRow, y: media.PhysicalMemberRow) bool {
            return membershipLess(.{ .call = x.key.call, .client = x.key.client }, .{ .call = y.key.call, .client = y.key.client });
        }
    }.less);
    rooms.rooms = try sortedCopy(media.RoomRow, a, rooms.rooms, stringLessFn(media.RoomRow));
    rooms.breakouts = try sortedCopy(media.StringRow([]u8), a, rooms.breakouts, stringLessFn(media.StringRow([]u8)));
    rooms.positions = try sortedCopy(media.StringRow(media.Position), a, rooms.positions, stringLessFn(media.StringRow(media.Position)));
    rooms.hands = try sortedCopy(media.StringRow(void), a, rooms.hands, stringLessFn(media.StringRow(void)));
    rooms.profiles = try sortedCopy(media.StringRow(media.CallProfile), a, rooms.profiles, stringLessFn(media.StringRow(media.CallProfile)));
    rooms.participant_profiles = try sortedCopy(media.StringRow(media.CallProfile), a, rooms.participant_profiles, stringLessFn(media.StringRow(media.CallProfile)));
    rooms.consents = try sortedCopy(media.StringRow(void), a, rooms.consents, stringLessFn(media.StringRow(void)));
    rooms.recordings = try sortedCopy(media.StringRow(media.Recording), a, rooms.recordings, stringLessFn(media.StringRow(media.Recording)));
    rooms.qualities = try sortedCopy(media.StringRow(media.Quality), a, rooms.qualities, stringLessFn(media.StringRow(media.Quality)));
    rooms.queues = try sortedCopy(media.QueueRow, a, rooms.queues, stringLessFn(media.QueueRow));
    const bridges = try sortedCopy(BridgeRow, a, source.bridges, struct {
        fn less(x: BridgeRow, y: BridgeRow) bool {
            return bytesLess(x.channel, y.channel);
        }
    }.less);
    const clients = try sortedCopy(ClientSocket, a, source.clients, struct {
        fn less(x: ClientSocket, y: ClientSocket) bool {
            return clientLess(x.source, y.source);
        }
    }.less);
    const attachments = try sortedCopy(Attachment, a, source.attachments, attachmentLess);
    const bindings = try sortedCopy(CallBinding, a, source.bindings, struct {
        fn less(x: CallBinding, y: CallBinding) bool {
            return clientLess(x.client, y.client);
        }
    }.less);
    defer std.crypto.secureZero(u8, std.mem.sliceAsBytes(bindings));
    const crypto_bindings = try sortedCopy(CryptoBinding, a, source.crypto_bindings, struct {
        fn less(x: CryptoBinding, y: CryptoBinding) bool {
            return clientLess(x.client, y.client);
        }
    }.less);
    defer std.crypto.secureZero(u8, std.mem.sliceAsBytes(crypto_bindings));
    const canonical = Source{ .graph = &graph, .rooms = &rooms, .bridges = bridges, .clients = clients, .attachments = attachments, .bindings = bindings, .crypto_bindings = crypto_bindings };
    try canonical.validate();
    var body: usize = 0;
    inline for (.{ graph, rooms, bridges, clients, attachments, bindings, crypto_bindings }) |part| body = try addSize(body, try valueSize(@TypeOf(part), part));
    const total = try addSize(try addSize(header_len, body), digest_len);
    if (total > max_wire_bytes or body > std.math.maxInt(u32)) return error.Capacity;
    const bytes = try allocator.alloc(u8, total);
    errdefer freeEncoded(allocator, bytes);
    var w = Writer{ .bytes = bytes };
    w.put(&magic);
    w.int(u16, version);
    w.int(u16, 0);
    w.int(u32, @intCast(body));
    inline for (.{ graph, rooms, bridges, clients, attachments, bindings, crypto_bindings }) |part| writeValue(&w, @TypeOf(part), part);
    std.debug.assert(w.pos == total - digest_len);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(digest_domain);
    hash.update(bytes[0..w.pos]);
    var digest: [digest_len]u8 = undefined;
    hash.final(&digest);
    w.put(&digest);
    std.debug.assert(w.pos == total);
    return bytes;
}

pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) Error!Snapshot {
    if (bytes.len < header_len + digest_len or bytes.len > max_wire_bytes or !std.mem.eql(u8, bytes[0..4], &magic)) return error.InvalidSnapshot;
    var header = Reader{ .bytes = bytes[4..header_len] };
    if (try header.int(u16) != version or try header.int(u16) != 0) return error.InvalidSnapshot;
    const body_len = try header.int(u32);
    if (body_len != bytes.len - header_len - digest_len) return error.InvalidSnapshot;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(digest_domain);
    hash.update(bytes[0 .. bytes.len - digest_len]);
    var digest: [digest_len]u8 = undefined;
    hash.final(&digest);
    if (!std.crypto.timing_safe.eql([digest_len]u8, digest, bytes[bytes.len - digest_len ..][0..digest_len].*)) return error.InvalidSnapshot;
    const body = bytes[header_len .. bytes.len - digest_len];
    var scan = Reader{ .bytes = body };
    inline for (.{ routing.GraphSnapshot, media.Snapshot, []BridgeRow, []ClientSocket, []Attachment, []CallBinding, []CryptoBinding }) |T| try scanValue(&scan, T);
    if (scan.pos != body.len) return error.InvalidSnapshot;
    var r = Reader{ .bytes = body };
    var graph = try readValue(&r, allocator, routing.GraphSnapshot);
    errdefer graph.deinit();
    var rooms = try readValue(&r, allocator, media.Snapshot);
    errdefer rooms.deinit();
    const bridges = try readValue(&r, allocator, []BridgeRow);
    errdefer freeValue([]BridgeRow, allocator, bridges);
    const clients = try readValue(&r, allocator, []ClientSocket);
    errdefer allocator.free(clients);
    const attachments = try readValue(&r, allocator, []Attachment);
    errdefer allocator.free(attachments);
    const bindings = try readValue(&r, allocator, []CallBinding);
    errdefer freeBindings(allocator, bindings);
    const crypto_bindings = try readValue(&r, allocator, []CryptoBinding);
    errdefer freeCryptoBindings(allocator, crypto_bindings);
    if (r.pos != body.len) return error.InvalidSnapshot;
    const result = Snapshot{ .allocator = allocator, .graph = graph, .rooms = rooms, .bridges = bridges, .clients = clients, .attachments = attachments, .bindings = bindings, .crypto_bindings = crypto_bindings };
    try result.validate();
    return result;
}

const TestFixture = struct {
    arena: *std.heap.ArenaAllocator,
    graph: routing.GraphSnapshot,
    rooms: media.Snapshot,
    bridge_rows: [1]BridgeRow,
    clients: [1]ClientSocket,
    attachments: [1]Attachment,
    bindings: [1]CallBinding,
    crypto_bindings: [1]CryptoBinding,

    fn init() !TestFixture {
        const arena = try std.testing.allocator.create(std.heap.ArenaAllocator);
        errdefer std.testing.allocator.destroy(arena);
        arena.* = std.heap.ArenaAllocator.init(std.testing.allocator);
        errdefer arena.deinit();
        const a = arena.allocator();
        const old: routing.ClientId = .{ .shard = 0, .slot = 7, .gen = 3 };
        const call: routing.CallId = .{ .domain = .{ .serial = 11 }, .serial = 1 };
        const calls = try a.alloc(routing.GraphCall, 1);
        calls[0] = .{ .channel = try routing.ChannelKey.init("#media"), .row = .{ .id = call, .memberships = 1 } };
        const members = try a.alloc(routing.GraphMembership, 1);
        members[0] = .{ .key = .{ .call = call, .client = old }, .row = .{ .bits = 1 } };
        const graph = routing.GraphSnapshot{
            .allocator = a,
            .id = call.domain,
            .revision = 1,
            .next_call = 2,
            .next_endpoint = 1,
            .next_stream = 1,
            .next_scope = 1,
            .next_binding = 3,
            .native_binding_serial = 1,
            .webrtc_binding_serial = 2,
            .calls = calls,
            .endpoints = try a.alloc(routing.GraphEndpoint, 0),
            .memberships = members,
            .bridge_policy = try a.alloc(routing.GraphBridgePolicy, 0),
        };
        const pid = try @import("../../substrate/undertow/media.zig").ParticipantId.init("alice");
        var room = media.Room.init();
        try room.join(pid, .voice);
        const physical = try a.alloc(media.PhysicalMemberRow, 1);
        physical[0] = .{ .key = .{ .call = call, .client = old }, .member = .{ .display = pid, .kind_bits = 1 } };
        const room_rows = try a.alloc(media.RoomRow, 1);
        room_rows[0] = .{ .key = try a.dupe(u8, "#media"), .room = try room.capture() };
        const rooms = media.Snapshot{
            .allocator = a,
            .config = .{},
            .transport_revision = 1,
            .physical_profiles = try a.alloc(media.PhysicalProfileRow, 0),
            .physical_members = physical,
            .rooms = room_rows,
            .breakouts = try a.alloc(media.StringRow([]u8), 0),
            .positions = try a.alloc(media.StringRow(media.Position), 0),
            .hands = try a.alloc(media.StringRow(void), 0),
            .profiles = try a.alloc(media.StringRow(media.CallProfile), 0),
            .participant_profiles = try a.alloc(media.StringRow(media.CallProfile), 0),
            .consents = try a.alloc(media.StringRow(void), 0),
            .recordings = try a.alloc(media.StringRow(media.Recording), 0),
            .qualities = try a.alloc(media.StringRow(media.Quality), 0),
            .queues = try a.alloc(media.QueueRow, 0),
        };
        var bridge = Bridge.init();
        try bridge.register("alice", .{ .leg = .native, .stream_id = 9001, .ssrc = 9001 });
        return .{
            .arena = arena,
            .graph = graph,
            .rooms = rooms,
            .bridge_rows = .{.{ .channel = "#media", .snapshot = try bridge.capture() }},
            .clients = .{.{ .source = old, .fd = 42 }},
            .attachments = .{try Attachment.init(old, "#media", "alice", 1)},
            .bindings = .{try CallBinding.init(old, "#media", "alice")},
            .crypto_bindings = .{try CryptoBinding.init(old, try crypto_scope.Scope.init("#media", "alice", @splat(0x5a)))},
        };
    }
    fn deinit(self: *TestFixture) void {
        self.arena.deinit();
        std.testing.allocator.destroy(self.arena);
    }
    fn source(self: *const TestFixture) Source {
        return .{ .graph = &self.graph, .rooms = &self.rooms, .bridges = &self.bridge_rows, .clients = &self.clients, .attachments = &self.attachments, .bindings = &self.bindings, .crypto_bindings = &self.crypto_bindings };
    }
};

test "media graph checkpoint owns exact socket roster room bridge and E2EE binding" {
    var fixture = try TestFixture.init();
    defer fixture.deinit();
    const wire = try encode(std.testing.allocator, fixture.source());
    defer freeEncoded(std.testing.allocator, wire);
    var decoded = try decode(std.testing.allocator, wire);
    defer decoded.deinit();
    try std.testing.expectEqual(@as(usize, 1), decoded.graph.memberships.len);
    try std.testing.expectEqual(@as(usize, 1), decoded.bridges.len);
    try std.testing.expectEqual(@as(i32, 42), decoded.clients[0].fd);
    try std.testing.expect(decoded.crypto_bindings[0].scope.bound);
    try std.testing.expectEqual(@as(u8, 0x5a), decoded.crypto_bindings[0].scope.attachment[0]);
    const target: routing.ClientId = .{ .shard = 2, .slot = 3, .gen = 4 };
    var candidate = try decoded.prepare(std.testing.allocator, &.{.{ .fd = 42, .target = target }});
    defer candidate.deinit();
    try std.testing.expect(candidate.graph.memberships[0].key.client.eql(target));
    try std.testing.expect(candidate.rooms.physical_members.contains(.{ .call = fixture.graph.calls[0].row.id, .client = target }));
    try std.testing.expect(candidate.attachments[0].client.eql(target));
    try std.testing.expect(candidate.bindings[0].client.eql(target));
    try std.testing.expect(candidate.bridges.contains("#media"));
    try std.testing.expectError(error.IncompleteRemap, decoded.prepare(std.testing.allocator, &.{}));
    try std.testing.expectError(error.InvalidSnapshot, decoded.prepare(std.testing.allocator, &.{
        .{ .fd = 42, .target = target }, .{ .fd = 42, .target = .{ .shard = 3, .slot = 3, .gen = 4 } },
    }));
}

test "media graph checkpoint rejects malformed joins roster and wire before publication" {
    var fixture = try TestFixture.init();
    defer fixture.deinit();
    fixture.attachments[0].kind_bits = 2;
    try std.testing.expectError(error.InvalidSnapshot, fixture.source().validate());
    fixture.attachments[0].kind_bits = 1;
    fixture.clients[0].fd = -1;
    try std.testing.expectError(error.InvalidSnapshot, fixture.source().validate());
    fixture.clients[0].fd = 42;
    fixture.bridge_rows[0].snapshot.members[0].id_buf[0] = 'z';
    try std.testing.expectError(error.InvalidSnapshot, fixture.source().validate());
    fixture.bridge_rows[0].snapshot.members[0].id_buf[0] = 'a';
    var empty_bridge = Bridge.init();
    const occupied_bridge = fixture.bridge_rows[0].snapshot;
    fixture.bridge_rows[0].snapshot = try empty_bridge.capture();
    try fixture.source().validate();
    fixture.bridge_rows[0].snapshot = occupied_bridge;
    const wire = try encode(std.testing.allocator, fixture.source());
    defer freeEncoded(std.testing.allocator, wire);
    const changed = try std.testing.allocator.dupe(u8, wire);
    defer freeEncoded(std.testing.allocator, changed);
    changed[changed.len - 1] ^= 1;
    try std.testing.expectError(error.InvalidSnapshot, decode(std.testing.allocator, changed));
    try std.testing.expectError(error.InvalidSnapshot, decode(std.testing.allocator, wire[0 .. wire.len - 1]));
}

fn mediaGraphAllocationSweep(allocator: std.mem.Allocator) !void {
    var fixture = try TestFixture.init();
    defer fixture.deinit();
    const wire = try encode(std.testing.allocator, fixture.source());
    defer freeEncoded(std.testing.allocator, wire);
    var decoded = try decode(allocator, wire);
    defer decoded.deinit();
    var candidate = try decoded.prepare(allocator, &.{.{ .fd = 42, .target = .{ .shard = 2, .slot = 3, .gen = 4 } }});
    defer candidate.deinit();
    try std.testing.expect(candidate.bridges.contains("#media"));
    try std.testing.expect(candidate.crypto_bindings[0].scope.matches("#media", "alice", @splat(0x5a)));
    try std.testing.expect(decoded.crypto_bindings[0].client.eql(fixture.crypto_bindings[0].client));
    try std.testing.expect(candidate.crypto_bindings[0].client.eql(.{ .shard = 2, .slot = 3, .gen = 4 }));
}
test "media graph checkpoint allocation failure leaves detached decode and prepare atomic" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, mediaGraphAllocationSweep, .{});
}

test "media graph checkpoint v3 independently binds crypto and rejects missing or legacy provenance" {
    const a = std.testing.allocator;
    var fixture = try TestFixture.init();
    defer fixture.deinit();
    const wire = try encode(a, fixture.source());
    defer freeEncoded(a, wire);
    var decoded = try decode(a, wire);
    defer decoded.deinit();
    try std.testing.expectEqual(@as(usize, 1), decoded.bindings.len);
    try std.testing.expectEqual(@as(usize, 1), decoded.crypto_bindings.len);
    // Browser route may be absent for an otherwise exact native crypto member.
    var native_only = fixture.source();
    native_only.bindings = &.{};
    const native_wire = try encode(a, native_only);
    defer freeEncoded(a, native_wire);
    var native_decoded = try decode(a, native_wire);
    defer native_decoded.deinit();
    try std.testing.expectEqual(@as(usize, 0), native_decoded.bindings.len);
    try std.testing.expectEqual(@as(usize, 1), native_decoded.crypto_bindings.len);
    var wrong = fixture.crypto_bindings;
    wrong[0].scope = try crypto_scope.Scope.init("#other", "alice", @splat(0x5a));
    var invalid = fixture.source();
    invalid.crypto_bindings = &wrong;
    try std.testing.expectError(error.InvalidSnapshot, invalid.validate());
    wrong[0].scope = try crypto_scope.Scope.init("#media", "other", @splat(0x5a));
    try std.testing.expectError(error.InvalidSnapshot, invalid.validate());
    wrong[0] = fixture.crypto_bindings[0];
    wrong[0].scope.attachment = @splat(0);
    try std.testing.expectError(error.InvalidSnapshot, invalid.validate());
    wrong[0] = fixture.crypto_bindings[0];
    wrong[0].scope.bound = false;
    try std.testing.expectError(error.InvalidSnapshot, invalid.validate());
    const legacy = try a.dupe(u8, wire);
    defer a.free(legacy);
    std.mem.writeInt(u16, legacy[4..6], 1, .little);
    try std.testing.expectError(error.InvalidSnapshot, decode(a, legacy));
    std.mem.writeInt(u16, legacy[4..6], 2, .little);
    try std.testing.expectError(error.InvalidSnapshot, decode(a, legacy));
    // Truncating the required body cannot be an empty-array default.
    try std.testing.expectError(error.InvalidSnapshot, decode(a, wire[0 .. wire.len - 1]));
    const target: routing.ClientId = .{ .shard = 1, .slot = 7, .gen = 8 };
    var staged = try native_decoded.prepare(a, &.{.{ .fd = 42, .target = target }});
    defer staged.deinit();
    try std.testing.expect(staged.crypto_bindings[0].client.eql(target));
    try std.testing.expect(staged.crypto_bindings[0].scope.matches("#media", "alice", @splat(0x5a)));
}

test "media graph checkpoint rejects uncarried legacy physical owners instead of inferring protected membership" {
    var fixture = try TestFixture.init();
    defer fixture.deinit();
    const original = try encode(std.testing.allocator, fixture.source());
    defer freeEncoded(std.testing.allocator, original);
    // Room-only/flat display compatibility does not relax hot physical-roster
    // provenance. A paid legacy credit is not a Domain member or socket proof.
    const other: routing.ClientId = .{ .shard = 0, .slot = 8, .gen = 4 };
    const extra = [_]Attachment{ fixture.attachments[0], try Attachment.init(other, "#media", "alice", 1) };
    var unsupported = fixture.source();
    unsupported.attachments = &extra;
    try std.testing.expectError(error.IncompleteRemap, unsupported.validate());
    const same_client = [_]Attachment{ fixture.attachments[0], try Attachment.init(fixture.clients[0].source, "#legacy-only", "alice", 1) };
    unsupported.attachments = &same_client;
    try std.testing.expectError(error.InvalidSnapshot, encode(std.testing.allocator, unsupported));
    const after = try encode(std.testing.allocator, fixture.source());
    defer freeEncoded(std.testing.allocator, after);
    try std.testing.expectEqualSlices(u8, original, after);
}

const TwinCryptoFixture = struct {
    base: TestFixture,
    clients: [2]ClientSocket,
    attachments: [2]Attachment,
    crypto: [2]CryptoBinding,

    fn init() !TwinCryptoFixture {
        var base = try TestFixture.init();
        errdefer base.deinit();
        const a = base.arena.allocator();
        const second: routing.ClientId = .{ .shard = 0, .slot = 8, .gen = 4 };
        const members = try a.alloc(routing.GraphMembership, 2);
        members[0] = base.graph.memberships[0];
        members[1] = members[0];
        members[1].key.client = second;
        base.graph.memberships = members;
        base.graph.calls[0].row.memberships = 2;
        const physical = try a.alloc(media.PhysicalMemberRow, 2);
        physical[0] = base.rooms.physical_members[0];
        physical[1] = physical[0];
        physical[1].key.client = second;
        base.rooms.physical_members = physical;
        return .{
            .base = base,
            .clients = .{ base.clients[0], .{ .source = second, .fd = 43 } },
            .attachments = .{ base.attachments[0], try Attachment.init(second, "#media", "alice", 1) },
            .crypto = .{ base.crypto_bindings[0], try CryptoBinding.init(second, try crypto_scope.Scope.init("#MEDIA", "ALICE", @splat(0x6B))) },
        };
    }
    fn source(self: *const TwinCryptoFixture) Source {
        var result = self.base.source();
        result.clients = &self.clients;
        result.attachments = &self.attachments;
        result.crypto_bindings = &self.crypto;
        return result;
    }
    fn deinit(self: *TwinCryptoFixture) void {
        self.base.deinit();
    }
};

/// Mutate a real valid HXMG2 object using its actual structural codec, then
/// recompute its integrity digest. This reaches semantic duplicate rejection;
/// it is not a checksum/truncation failure or guessed raw-pattern replacement.
fn duplicateTupleWireForTest(allocator: std.mem.Allocator, fixture: *const TwinCryptoFixture) ![]u8 {
    const wire = try encode(allocator, fixture.source());
    errdefer freeEncoded(allocator, wire);
    var reader = Reader{ .bytes = wire[header_len .. wire.len - digest_len] };
    inline for (.{ routing.GraphSnapshot, media.Snapshot, []BridgeRow, []ClientSocket, []Attachment, []CallBinding }) |T| try scanValue(&reader, T);
    try std.testing.expectEqual(@as(u32, 2), try reader.int(u32));
    try scanValue(&reader, CryptoBinding);
    const second = fixture.crypto[1];
    const offset = header_len + reader.pos +
        try valueSize(@TypeOf(second.client), second.client) +
        try valueSize(@TypeOf(second.scope.channel), second.scope.channel) +
        try valueSize(@TypeOf(second.scope.participant), second.scope.participant);
    @memcpy(wire[offset..][0..16], &fixture.crypto[0].scope.attachment);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(digest_domain);
    hash.update(wire[0 .. wire.len - digest_len]);
    var digest: [digest_len]u8 = undefined;
    hash.final(&digest);
    @memcpy(wire[wire.len - digest_len ..], &digest);
    return wire;
}

test "media graph checkpoint rejects canonical duplicate crypto tuples across distinct physical clients" {
    const a = std.testing.allocator;
    var fixture = try TwinCryptoFixture.init();
    defer fixture.deinit();
    const valid_wire = try encode(a, fixture.source());
    defer freeEncoded(a, valid_wire);
    var decoded = try decode(a, valid_wire);
    defer decoded.deinit();
    try std.testing.expect(!decoded.crypto_bindings[0].client.eql(decoded.crypto_bindings[1].client));
    const targets = [_]AdoptedClient{
        .{ .fd = 42, .target = .{ .shard = 1, .slot = 7, .gen = 9 } },
        .{ .fd = 43, .target = .{ .shard = 1, .slot = 8, .gen = 9 } },
    };
    var valid_target = try decoded.prepare(a, &targets);
    defer valid_target.deinit();
    try std.testing.expectEqual(@as(usize, 2), valid_target.crypto_bindings.len);
    try std.testing.expect(valid_target.crypto_bindings[0].client.eql(targets[0].target));
    try std.testing.expect(valid_target.crypto_bindings[1].client.eql(targets[1].target));
    try std.testing.expect(!valid_target.crypto_bindings[0].scope.sameTuple(&valid_target.crypto_bindings[1].scope));
    const malformed = try duplicateTupleWireForTest(a, &fixture);
    defer freeEncoded(a, malformed);
    try std.testing.expectError(error.InvalidSnapshot, decode(a, malformed));
    // Capture and prepare reject the same collision, even when the tuple's
    // channel/participant spelling differs only in case. No target allocation
    // or partially remapped crypto authority can escape this boundary.
    const original_aid = fixture.crypto[1].scope.attachment;
    fixture.crypto[1].scope.attachment = fixture.crypto[0].scope.attachment;
    try std.testing.expectError(error.InvalidSnapshot, fixture.source().validate());
    try std.testing.expectError(error.InvalidSnapshot, encode(a, fixture.source()));
    fixture.crypto[1].scope.attachment = original_aid;
    decoded.crypto_bindings[1].scope.attachment = decoded.crypto_bindings[0].scope.attachment;
    var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    try std.testing.expectError(error.InvalidSnapshot, decoded.prepare(failing.allocator(), &targets));
    try std.testing.expect(!failing.has_induced_failure);
    const after = try encode(a, fixture.source());
    defer freeEncoded(a, after);
    try std.testing.expectEqualSlices(u8, valid_wire, after);
}

fn duplicateTupleDecodeOom(allocator: std.mem.Allocator) !void {
    var fixture = try TwinCryptoFixture.init();
    defer fixture.deinit();
    const wire = try duplicateTupleWireForTest(std.testing.allocator, &fixture);
    defer freeEncoded(std.testing.allocator, wire);
    if (decode(allocator, wire)) |accepted| {
        var unexpected = accepted;
        unexpected.deinit();
        return error.TestUnexpectedResult;
    } else |err| switch (err) {
        error.InvalidSnapshot => return,
        else => return err,
    }
}

test "media graph checkpoint duplicate tuple rejection allocation cuts retain no detached authority" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, duplicateTupleDecodeOom, .{});
}

test "media graph v3 carries bounded feedback windows without resetting them" {
    const client: routing.ClientId = .{ .shard = 0, .slot = 7, .gen = 3 };
    const call: routing.CallId = .{ .domain = .{ .serial = 11 }, .serial = 1 };
    const endpoint: routing.EndpointId = .{ .call = call, .serial = 1, .leg = .native };
    const row: routing.EndpointEntry = .{
        .observation = .{
            .reference = .{ .endpoint = endpoint, .offering_client = client, .bridge_policy_revision = 1 },
            .stamp = .{ .endpoint = endpoint, .offering_client = client, .binding_revision = 1, .security_revision = 1 },
            .stream_id = 1,
            .mode = .legacy_group,
        },
        .feedback_source = .{ .started_ms = 1234, .used = 1 },
        .feedback_publisher = .{ .started_ms = 1234, .used = 3 },
        .nack_source = .{ .started_ms = 1250, .used = 64 },
        .nack_publisher = .{ .started_ms = 1250, .used = 500 },
    };
    var bytes: [512]u8 = undefined;
    const size = try valueSize(routing.EndpointEntry, row);
    try std.testing.expect(size <= bytes.len);
    var writer: Writer = .{ .bytes = bytes[0..size] };
    writeValue(&writer, routing.EndpointEntry, row);
    try std.testing.expectEqual(size, writer.pos);
    var reader: Reader = .{ .bytes = bytes[0..size] };
    const decoded = try readValue(&reader, std.testing.allocator, routing.EndpointEntry);
    try std.testing.expectEqualDeep(row, decoded);
    try std.testing.expectEqual(size, reader.pos);
    var truncated: Reader = .{ .bytes = bytes[0 .. size - 1] };
    try std.testing.expectError(error.InvalidSnapshot, readValue(&truncated, std.testing.allocator, routing.EndpointEntry));
}

test "media graph full checkpoint remap and restore retain live feedback budgets" {
    var fixture = try TestFixture.init();
    defer fixture.deinit();
    const a = fixture.arena.allocator();
    const original = fixture.clients[0].source;
    const call = fixture.graph.calls[0].row.id;
    const endpoint: routing.EndpointId = .{ .call = call, .serial = 1, .leg = .native };
    const key: routing.EndpointKey = .{ .call = call, .client = original, .leg = .native };
    const endpoints = try a.alloc(routing.GraphEndpoint, 1);
    endpoints[0] = .{
        .key = key,
        .row = .{
            .observation = .{
                .reference = .{ .endpoint = endpoint, .offering_client = original, .bridge_policy_revision = 1 },
                .stamp = .{ .endpoint = endpoint, .offering_client = original, .binding_revision = 1, .security_revision = 1 },
                .stream_id = 1,
                .mode = .legacy_group,
            },
            .feedback_source = .{ .started_ms = 1000, .used = 1 },
            .feedback_publisher = .{ .started_ms = 1000, .used = 3 },
            .nack_source = .{ .started_ms = 1000, .used = 64 },
            .nack_publisher = .{ .started_ms = 1000, .used = 400 },
        },
    };
    fixture.graph.calls[0].row.offers = 1;
    fixture.graph.next_endpoint = 2;
    fixture.graph.next_stream = 2;
    fixture.graph.endpoints = endpoints;
    const profiles = try a.alloc(media.PhysicalProfileRow, 1);
    var profile: media.CallProfile = .{ .codecs = @splat(.{ .tag = .cadencevox, .clock_rate = 0, .params = 0 }), .codec_count = 1 };
    profile.codecs[0].clock_rate = 48000;
    profiles[0] = .{ .key = key, .profile = profile };
    fixture.rooms.physical_profiles = profiles;
    const wire = try encode(std.testing.allocator, fixture.source());
    defer freeEncoded(std.testing.allocator, wire);
    var decoded = try decode(std.testing.allocator, wire);
    defer decoded.deinit();
    const target: routing.ClientId = .{ .shard = 1, .slot = 8, .gen = 4 };
    var staged = try decoded.prepare(std.testing.allocator, &.{.{ .fd = 42, .target = target }});
    defer staged.deinit();
    var native_owner = native.NativeMediaTransport.init(std.testing.allocator);
    defer native_owner.deinit();
    var plane = try @import("../media_plane.zig").MediaPlane.initFallible(std.testing.allocator);
    defer plane.deinit();
    var prepared = try routing.prepareGraphRestore(std.testing.allocator, &staged.graph, &native_owner, &plane);
    const restored = prepared.publish();
    prepared.deinit();
    defer routing.TestFeedbackClock.retire(restored, call, target) catch @panic("restored pressure fixture leaked graph");
    const actual = try routing.TestFeedbackClock.read(restored.domain, .{ .call = call, .client = target, .leg = .native });
    try std.testing.expectEqual(@as(u16, 1), actual.source_keyframe);
    try std.testing.expectEqual(@as(u16, 3), actual.publisher_keyframe);
    try std.testing.expectEqual(@as(u16, 64), actual.source_nack);
    try std.testing.expectEqual(@as(u16, 400), actual.publisher_nack);
}
