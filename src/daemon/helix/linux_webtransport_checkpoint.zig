// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Linux exec checkpoint for the settled QUIC/H3 graph and physical IRC
//! bridges. Descriptor numbers are borrowed identities, never owned resources.
//! The outer sealed Helix state and native manifest authenticate this body.
const std = @import("std");
const wt = @import("../webtransport_listener.zig");
const codec = @import("native_windows_active_webtransport_snapshot.zig");
const magic = "HXLW";
const version: u16 = 2;
const domain = "onyx-linux-active-webtransport-v2";
pub const Error = codec.Error;
pub const BridgeFd = wt.BridgeFd;
pub const AcceptedIrcSocket = codec.AcceptedIrcSocket;
pub const freeEncoded = codec.freeEncoded;

pub const Body = struct {
    snapshot: wt.ActiveSnapshot,
    udp_fd: i32,
    bridges: []BridgeFd,
    accepted: []AcceptedIrcSocket,

    /// Releases graph memory only. Even on failed adoption, every original
    /// descriptor remains under the outer transaction's custody.
    pub fn deinit(self: *Body, allocator: std.mem.Allocator) void {
        self.snapshot.deinit(allocator);
        allocator.free(self.bridges);
        allocator.free(self.accepted);
        self.* = undefined;
    }

    pub fn validate(self: *const Body, tls: wt.TlsConfig) Error!void {
        self.snapshot.validate(tls) catch return error.InvalidSnapshot;
        if (!validFd(self.udp_fd) or self.snapshot.base.socket.ipv4 != null or
            self.snapshot.base.socket.primary.inode == 0) return error.InvalidSnapshot;
        var cursor: usize = 0;
        for (self.snapshot.connections) |row| if (row.bridge) |expected| {
            if (cursor >= self.bridges.len) return error.InvalidSnapshot;
            const bridge = self.bridges[cursor];
            if (!validFd(bridge.fd) or bridge.inode == 0 or bridge.fd == self.udp_fd or bridge.slot != row.slot or
                @as(usize, @intCast(bridge.fd)) != expected.source_socket) return error.InvalidSnapshot;
            for (self.bridges[0..cursor]) |prior| if (prior.device == bridge.device and prior.inode == bridge.inode) return error.InvalidSnapshot;
            cursor += 1;
        };
        if (cursor != self.bridges.len) return error.InvalidSnapshot;
        try codec.validateSortedAccepted(&self.snapshot, self.accepted);
        for (self.accepted) |accepted| {
            if (accepted.fd == @as(usize, @intCast(self.udp_fd))) return error.InvalidSnapshot;
            for (self.bridges) |bridge| if (accepted.fd == @as(usize, @intCast(bridge.fd))) return error.InvalidSnapshot;
        }
    }
};

fn validFd(fd: i32) bool {
    return fd > 0 and fd < 0x4000_0000;
}

fn validTransportAddress(address: wt.TransportAddress) bool {
    if ((address.ip_len != 4 and address.ip_len != 16) or address.port == 0) return false;
    return std.mem.allEqual(u8, address.ip[address.ip_len..], 0);
}

pub fn isCurrent(bytes: []const u8) bool {
    // Recognize the family, including malformed/unsupported versions, so an
    // invalid mandatory checkpoint cannot fall through to a legacy decoder.
    return bytes.len >= magic.len and std.mem.eql(u8, bytes[0..magic.len], magic);
}

pub fn encode(allocator: std.mem.Allocator, body: *const Body, tls: wt.TlsConfig) Error![]u8 {
    try body.validate(tls);
    return codec.encodeFramed(Body, allocator, body.*, magic, version, domain);
}

pub fn decode(allocator: std.mem.Allocator, bytes: []const u8, tls: wt.TlsConfig) Error!Body {
    _ = try validateWire(bytes);
    var body = try codec.decodeFramed(Body, allocator, bytes, magic, version, domain);
    errdefer body.deinit(allocator);
    try body.validate(tls);
    return body;
}

fn Iterator(comptime T: type) type {
    return struct {
        reader: codec.Reader,
        remaining: usize,
        pub fn next(self: *@This()) ?T {
            if (self.remaining == 0) return null;
            self.remaining -= 1;
            return codec.readFixed(&self.reader, T) catch unreachable;
        }
    };
}

pub const WireView = struct {
    udp_fd: i32,
    bridge_bytes: []const u8,
    bridge_count: usize,
    accepted_bytes: []const u8,
    accepted_count: usize,
    pub fn bridgeIterator(self: WireView) Iterator(BridgeFd) {
        return .{ .reader = .{ .bytes = self.bridge_bytes }, .remaining = self.bridge_count };
    }
    pub fn acceptedIterator(self: WireView) Iterator(AcceptedIrcSocket) {
        return .{ .reader = .{ .bytes = self.accepted_bytes }, .remaining = self.accepted_count };
    }
};

const ExpectedBridge = struct { slot: usize, identity: wt.BridgeIdentity };

/// Validate the entire wire syntax/allocation budget and physical descriptor
/// join without allocating. Semantic QUIC/H3 and TLS checks occur in decode,
/// before candidate construction or descriptor ownership publication.
pub fn validateWire(bytes: []const u8) Error!WireView {
    var r = codec.Reader{ .bytes = try codec.scanFramed(Body, bytes, magic, version, domain) };
    const base = try codec.readFixed(&r, wt.Snapshot);
    base.socket.validate() catch return error.InvalidSnapshot;
    if (base.socket.ipv4 != null or base.socket.primary.inode == 0) return error.InvalidSnapshot;
    _ = try codec.readFixed(&r, [32]u8); // IRC host digest
    const slots = try r.int(usize);
    const connections = try r.int(u32);
    if (slots > wt.snapshot_max_slots or connections > slots or connections > base.max_connections) return error.InvalidSnapshot;
    var expected: [wt.snapshot_max_slots]ExpectedBridge = undefined;
    var expected_count: usize = 0;
    var prior_slot: ?usize = null;
    for (0..connections) |_| {
        const slot = try r.int(usize);
        if (slot >= slots or (prior_slot != null and slot <= prior_slot.?)) return error.InvalidSnapshot;
        prior_slot = slot;
        // Read the exact declared field order. Schema drift is caught by the
        // shared codec's compile-time ActiveConnectionSnapshot field count.
        inline for (@typeInfo(wt.ActiveConnectionSnapshot).@"struct".field_names, @typeInfo(wt.ActiveConnectionSnapshot).@"struct".field_types) |name, T| {
            if (comptime std.mem.eql(u8, name, "slot")) continue;
            if (comptime std.mem.eql(u8, name, "bridge")) {
                if (try codec.readFixed(&r, T)) |bridge| {
                    if (bridge.source_socket == 0 or bridge.source_socket >= 0x4000_0000 or
                        !validTransportAddress(bridge.local) or !validTransportAddress(bridge.peer) or
                        bridge.local.ip_len != bridge.peer.ip_len or bridge.peer.port != base.irc_port)
                        return error.InvalidSnapshot;
                    for (expected[0..expected_count]) |prior| {
                        if (prior.identity.source_socket == bridge.source_socket or
                            (wt.TransportAddress.eql(prior.identity.local, bridge.local) and wt.TransportAddress.eql(prior.identity.peer, bridge.peer))) return error.InvalidSnapshot;
                    }
                    expected[expected_count] = .{ .slot = slot, .identity = bridge };
                    expected_count += 1;
                }
            } else try codec.scanValue(&r, T);
        }
    }
    const fd = try r.int(i32);
    if (!validFd(fd)) return error.InvalidSnapshot;
    const bridge_count = try r.int(u32);
    if (bridge_count != expected_count) return error.InvalidSnapshot;
    const bridge_start = r.pos;
    var identities: [wt.snapshot_max_slots]BridgeFd = undefined;
    for (expected[0..expected_count], 0..) |bridge, i| {
        const row = try codec.readFixed(&r, BridgeFd);
        if (row.inode == 0) return error.InvalidSnapshot;
        for (identities[0..i]) |prior| if (prior.device == row.device and prior.inode == row.inode) return error.InvalidSnapshot;
        identities[i] = row;
        if (!validFd(row.fd) or row.fd == fd or row.slot != bridge.slot or
            @as(usize, @intCast(row.fd)) != bridge.identity.source_socket) return error.InvalidSnapshot;
    }
    const bridge_end = r.pos;
    const accepted_count = try r.int(u32);
    if (accepted_count > codec.max_accepted_clients) return error.Capacity;
    const accepted_start = r.pos;
    var previous_fd: usize = 0;
    var joined: [wt.snapshot_max_slots]bool = @splat(false);
    for (0..accepted_count) |_| {
        const row = try codec.readFixed(&r, AcceptedIrcSocket);
        try codec.validateAcceptedRow(row);
        if (row.fd <= previous_fd or row.fd == @as(usize, @intCast(fd))) return error.InvalidSnapshot;
        previous_fd = row.fd;
        for (expected[0..expected_count], 0..) |bridge, i| {
            if (row.fd == bridge.identity.source_socket) return error.InvalidSnapshot;
            if (wt.TransportAddress.eql(row.local, bridge.identity.peer) and wt.TransportAddress.eql(row.peer, bridge.identity.local)) {
                if (joined[i]) return error.InvalidSnapshot;
                joined[i] = true;
            }
        }
    }
    for (joined[0..expected_count]) |join| if (!join) return error.InvalidSnapshot;
    if (r.pos != r.bytes.len) return error.InvalidSnapshot;
    return .{ .udp_fd = fd, .bridge_bytes = r.bytes[bridge_start..bridge_end], .bridge_count = bridge_count, .accepted_bytes = r.bytes[accepted_start..], .accepted_count = accepted_count };
}

test "Helix Linux WebTransport idle checkpoint rejects malformed wire and round-trips exactly" {
    if (comptime @import("builtin").os.tag != .linux) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const key = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x37)));
    var cert_buf: [1024]u8 = undefined;
    const cert = try @import("../../proto/x509_selfsign.zig").buildSelfSigned(&cert_buf, .{
        .common_name = "wt.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x51, 0x99 },
        .key_pair = key,
        .dns_names = &.{"wt.test"},
        .is_ca = true,
    });
    const chain = [_][]const u8{cert};
    const tls: wt.TlsConfig = .{ .cert_chain = &chain, .signing_key = .{ .ed25519 = key } };
    var owner = wt.WebTransportListener.init(allocator, tls, 6667);
    defer owner.deinit();
    try owner.prepareColdResources(std.testing.io, .{ .v4_mapped = .{ 127, 0, 0, 1 } }, 0);
    var active = try owner.captureUnstartedActive(allocator);
    defer active.deinit(allocator);
    var body: Body = .{ .snapshot = active, .udp_fd = owner.socket.?.fd, .bridges = &.{}, .accepted = &.{} };
    const wire = try encode(allocator, &body, tls);
    defer freeEncoded(allocator, wire);
    const view = try validateWire(wire);
    try std.testing.expectEqual(body.udp_fd, view.udp_fd);
    var bridge = view.bridgeIterator();
    var accepted = view.acceptedIterator();
    try std.testing.expect(bridge.next() == null and accepted.next() == null);
    var decoded = try decode(allocator, wire, tls);
    defer decoded.deinit(allocator);
    try std.testing.expectEqualDeep(body.snapshot.base, decoded.snapshot.base);
    try std.testing.expectEqualDeep(body.snapshot.irc_host_digest, decoded.snapshot.irc_host_digest);
    const restored_wire = try encode(allocator, &decoded, tls);
    defer freeEncoded(allocator, restored_wire);
    try std.testing.expectEqualSlices(u8, wire, restored_wire);
    for (0..wire.len) |len| try std.testing.expectError(error.InvalidSnapshot, validateWire(wire[0..len]));
    wire[4] ^= 1;
    try std.testing.expect(isCurrent(wire));
    try std.testing.expectError(error.InvalidSnapshot, validateWire(wire));
    wire[4] ^= 1;
    wire[12] ^= 1;
    try std.testing.expectError(error.InvalidSnapshot, validateWire(wire));
    wire[12] ^= 1;
    // A correct checksum never authorizes descriptor aliases or unexpected rows.
    var fake_bridges = [_]BridgeFd{.{ .slot = 0, .fd = body.udp_fd, .device = 0, .inode = 1 }};
    body.bridges = &fake_bridges;
    const alias = try codec.encodeFramed(Body, allocator, body, magic, version, domain);
    defer freeEncoded(allocator, alias);
    try std.testing.expectError(error.InvalidSnapshot, validateWire(alias));
    try std.testing.expectError(error.InvalidSnapshot, decode(allocator, alias, tls));
    body.bridges = &.{};
    body.udp_fd = -1;
    const invalid_fd = try codec.encodeFramed(Body, allocator, body, magic, version, domain);
    defer freeEncoded(allocator, invalid_fd);
    try std.testing.expectError(error.InvalidSnapshot, validateWire(invalid_fd));
}

test "Helix Linux WebTransport validates bridge endpoints before equality without allocation" {
    if (comptime @import("builtin").os.tag != .linux) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const key = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x37)));
    var cert_buf: [1024]u8 = undefined;
    const cert = try @import("../../proto/x509_selfsign.zig").buildSelfSigned(&cert_buf, .{
        .common_name = "wt.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x51, 0x99 },
        .key_pair = key,
        .dns_names = &.{"wt.test"},
        .is_ca = true,
    });
    const chain = [_][]const u8{cert};
    const tls: wt.TlsConfig = .{ .cert_chain = &chain, .signing_key = .{ .ed25519 = key } };
    var owner = wt.WebTransportListener.init(allocator, tls, 6667);
    defer owner.deinit();
    try owner.prepareColdResources(std.testing.io, .{ .v4_mapped = .{ 127, 0, 0, 1 } }, 0);
    var active = try owner.captureUnstartedActive(allocator);
    defer active.deinit(allocator);

    const bridge_local = try wt.TransportAddress.fromBytes(&.{ 127, 0, 0, 1 }, 40000);
    const bridge_peer = try wt.TransportAddress.fromBytes(&.{ 127, 0, 0, 1 }, 6667);
    var rows: [2]wt.ActiveConnectionSnapshot = undefined;
    for (&rows) |*row| {
        @memset(std.mem.asBytes(row), 0);
        // CipherSuite has no zero tag; raw-zero initialization is only used
        // for inert wire fixture fields, so set its enum to a valid value.
        row.quic.handshake.suite = .tls_aes_128_gcm_sha256;
    }
    rows[0].slot = 0;
    rows[0].bridge = .{ .source_socket = 103, .local = bridge_local, .peer = bridge_peer };
    rows[1].slot = 1;
    rows[1].bridge = .{ .source_socket = 105, .local = bridge_local, .peer = bridge_peer };
    const snapshot: wt.ActiveSnapshot = .{
        .base = active.base,
        .irc_host_digest = active.irc_host_digest,
        .slot_count = 2,
        .connections = &rows,
    };
    var bridges = [_]BridgeFd{
        .{ .slot = 0, .fd = 103, .device = 1, .inode = 1 },
        .{ .slot = 1, .fd = 105, .device = 2, .inode = 2 },
    };
    var accepted = [_]AcceptedIrcSocket{
        .{ .fd = 104, .local = bridge_peer, .peer = bridge_local },
        .{ .fd = 106, .local = bridge_peer, .peer = bridge_local },
    };
    const body: Body = .{ .snapshot = snapshot, .udp_fd = owner.socket.?.fd, .bridges = &bridges, .accepted = &accepted };

    inline for (.{ true, false }) |bad_local| {
        for (&rows) |*row| {
            var malformed = row.bridge.?;
            if (bad_local) {
                malformed.local.ip_len = 17;
            } else {
                malformed.peer.ip_len = 17;
            }
            row.bridge = malformed;
        }
        {
            // Deliberately bypass Body.validate so the checksum is correct and
            // both untrusted rows reach the allocation-free wire validator.
            // Equal malformed local/peer endpoints used to reach TransportAddress.eql
            // on the second row and slice ip[0..17] before semantic validation.
            const wire = try codec.encodeFramed(Body, allocator, body, magic, version, domain);
            defer freeEncoded(allocator, wire);
            try std.testing.expectError(error.InvalidSnapshot, validateWire(wire));
            var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
            try std.testing.expectError(error.InvalidSnapshot, decode(failing.allocator(), wire, tls));
            try std.testing.expect(!failing.has_induced_failure);
        }
        rows[0].bridge = .{ .source_socket = 103, .local = bridge_local, .peer = bridge_peer };
        rows[1].bridge = .{ .source_socket = 105, .local = bridge_local, .peer = bridge_peer };
    }
}
