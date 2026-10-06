// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Canonical, bounded active WebTransport graph wire. This body is checksummed
//! for diagnostics; native_windows_active_webtransport_custody seals it in an
//! authenticated, read-only Helix arena before any candidate decodes it.
//! No pointer, allocator capacity, or struct padding is serialized.

const std = @import("std");
const wt = @import("../webtransport_listener.zig");
const udp = @import("native_windows_udp_socket.zig");

const magic = "HXWT";
const version: u16 = 2;
const header_len: usize = 12;
const digest_len: usize = 32;
const digest_domain = "onyx-windows-active-webtransport-v2";
pub const max_wire_bytes: usize = 256 * 1024 * 1024;
pub const max_alloc_bytes: usize = 512 * 1024 * 1024;
const max_items: usize = 65_536;
pub const max_accepted_clients: usize = 4096;
pub const Error = std.mem.Allocator.Error || error{ InvalidSnapshot, Capacity };

comptime {
    if (@sizeOf(usize) != 8) @compileError("active WebTransport checkpoint requires 64-bit target");
    if (@typeInfo(wt.ActiveSnapshot).@"struct".field_names.len != 4 or
        @typeInfo(wt.ActiveConnectionSnapshot).@"struct".field_names.len != 15 or
        @typeInfo(wt.BridgeIdentity).@"struct".field_names.len != 3 or
        @typeInfo(wt.BridgeTransfer).@"struct".field_names.len != 4)
        @compileError("active WebTransport snapshot schema changed; review and bump HXWT version");
}

/// Authenticated identity of one accepted IRC-side client. `fd` is the stable
/// canonical descriptor ID in the full Windows state-socket transfer, not a
/// process-local Winsock SOCKET value.
pub const AcceptedIrcSocket = struct {
    fd: usize,
    local: wt.TransportAddress,
    peer: wt.TransportAddress,
};

fn canonicalEndpoint(address: wt.TransportAddress) bool {
    return (address.ip_len == 4 or address.ip_len == 16) and address.port != 0 and
        std.mem.allEqual(u8, address.ip[address.ip_len..], 0);
}

pub fn validateAcceptedRow(row: AcceptedIrcSocket) Error!void {
    if (row.fd == 0 or row.fd >= 0x4000_0000 or
        !canonicalEndpoint(row.local) or !canonicalEndpoint(row.peer) or
        row.local.ip_len != row.peer.ip_len) return error.InvalidSnapshot;
}

/// An accepted roster may include ordinary IRC clients that have no WT bridge.
/// Every live bridge still needs exactly one reverse endpoint pair.
pub fn validateAcceptedJoin(snapshot: *const wt.ActiveSnapshot, accepted: []const AcceptedIrcSocket) Error!void {
    if (accepted.len > max_accepted_clients) return error.Capacity;
    var fds: [max_accepted_clients]usize = undefined;
    for (accepted, 0..) |row, i| {
        try validateAcceptedRow(row);
        fds[i] = row.fd;
    }
    std.mem.sort(usize, fds[0..accepted.len], {}, std.sort.asc(usize));
    if (accepted.len > 1) for (fds[1..accepted.len], 0..) |fd, i| {
        if (fd == fds[i]) return error.InvalidSnapshot;
    };
    for (snapshot.connections, 0..) |row, i| {
        const bridge = row.bridge orelse continue;
        var matches: usize = 0;
        for (accepted) |client| {
            if (wt.TransportAddress.eql(bridge.local, client.peer) and
                wt.TransportAddress.eql(bridge.peer, client.local)) matches += 1;
        }
        if (matches != 1) return error.InvalidSnapshot;
        for (snapshot.connections[0..i]) |prior| if (prior.bridge) |other| {
            if (wt.TransportAddress.eql(bridge.local, other.local) and
                wt.TransportAddress.eql(bridge.peer, other.peer)) return error.InvalidSnapshot;
        };
    }
}

pub fn validateSortedAccepted(snapshot: *const wt.ActiveSnapshot, accepted: []const AcceptedIrcSocket) Error!void {
    try validateAcceptedJoin(snapshot, accepted);
    for (accepted, 0..) |row, i| {
        if (i > 0 and accepted[i - 1].fd >= row.fd) return error.InvalidSnapshot;
    }
}

pub const Body = struct {
    snapshot: wt.ActiveSnapshot,
    udp_transfer: udp.Transfer,
    bridges: []wt.BridgeTransfer,
    accepted: []AcceptedIrcSocket,

    pub fn deinit(self: *Body, allocator: std.mem.Allocator) void {
        self.snapshot.deinit(allocator);
        std.crypto.secureZero(u8, std.mem.asBytes(&self.udp_transfer.info));
        self.udp_transfer.consumed = true;
        for (self.bridges) |*bridge| {
            std.crypto.secureZero(u8, std.mem.asBytes(&bridge.transfer.info));
            bridge.transfer.consumed = true;
        }
        allocator.free(self.bridges);
        allocator.free(self.accepted);
        self.* = undefined;
    }

    pub fn validate(self: *const Body, tls: wt.TlsConfig, target_pid: u32) Error!void {
        self.snapshot.validate(tls) catch return error.InvalidSnapshot;
        if (target_pid == 0 or self.udp_transfer.consumed or
            self.udp_transfer.target_pid != target_pid or
            self.udp_transfer.source_socket != self.snapshot.base.socket.primary.device or
            self.bridges.len > self.snapshot.connections.len) return error.InvalidSnapshot;
        _ = udp.encodeFrame(&self.udp_transfer, .webtransport) catch return error.InvalidSnapshot;
        var next: usize = 0;
        for (self.snapshot.connections) |row| {
            if (row.bridge) |bridge| {
                if (next >= self.bridges.len) return error.InvalidSnapshot;
                const transfer = self.bridges[next];
                if (transfer.slot != row.slot or transfer.source_socket != bridge.source_socket or
                    transfer.target_pid != target_pid or transfer.transfer.consumed or
                    (transfer.transfer.info.address_family != 2 and transfer.transfer.info.address_family != 23) or
                    transfer.transfer.info.socket_type != 1 or transfer.transfer.info.protocol != 6)
                    return error.InvalidSnapshot;
                next += 1;
            }
        }
        if (next != self.bridges.len) return error.InvalidSnapshot;
        try validateSortedAccepted(&self.snapshot, self.accepted);
    }
};

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

fn addSize(a: usize, b: usize) Error!usize {
    return std.math.add(usize, a, b) catch error.Capacity;
}

fn valueSize(comptime T: type, value: T) Error!usize {
    @setEvalBranchQuota(100_000);
    if (T == void) return 0;
    return switch (@typeInfo(T)) {
        .bool => 1,
        .int, .float => @sizeOf(T),
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
            if (p.size != .slice) @compileError("HXWT rejects pointers");
            if (value.len > (if (p.child == u8) max_wire_bytes else max_items)) return error.Capacity;
            if (p.child == u8) break :blk try addSize(4, value.len);
            var n: usize = 4;
            for (value) |v| n = try addSize(n, try valueSize(p.child, v));
            break :blk n;
        },
        .@"struct" => |s| blk: {
            var n: usize = 0;
            inline for (s.field_names, s.field_types) |name, FieldType| n = try addSize(n, try valueSize(FieldType, @field(value, name)));
            break :blk n;
        },
        .@"union" => |u| blk: {
            const Tag = u.tag_type orelse @compileError("HXWT rejects untagged unions");
            var n: usize = @sizeOf(@typeInfo(Tag).@"enum".tag_type);
            switch (value) {
                inline else => |payload| n = try addSize(n, try valueSize(@TypeOf(payload), payload)),
            }
            break :blk n;
        },
        else => @compileError("unsupported HXWT wire field: " ++ @typeName(T)),
    };
}

fn writeValue(w: *Writer, comptime T: type, value: T) void {
    @setEvalBranchQuota(100_000);
    if (T == void) return;
    switch (@typeInfo(T)) {
        .bool => w.int(u8, @intFromBool(value)),
        .int => w.int(T, value),
        .float => {
            const I = @Int(.unsigned, @sizeOf(T) * 8);
            w.int(I, @bitCast(value));
        },
        .@"enum" => |e| w.int(e.tag_type, @intFromEnum(value)),
        .optional => |o| {
            w.int(u8, @intFromBool(value != null));
            if (value) |v| writeValue(w, o.child, v);
        },
        .array => |a| for (value) |v| writeValue(w, a.child, v),
        .pointer => |p| {
            if (p.size != .slice) @compileError("HXWT rejects pointers");
            w.int(u32, @intCast(value.len));
            if (p.child == u8) {
                w.put(value);
                return;
            }
            for (value) |v| writeValue(w, p.child, v);
        },
        .@"struct" => |s| inline for (s.field_names, s.field_types) |name, FieldType| writeValue(w, FieldType, @field(value, name)),
        .@"union" => |u| {
            const Tag = u.tag_type orelse @compileError("HXWT rejects untagged unions");
            const tag: Tag = value;
            w.int(@typeInfo(Tag).@"enum".tag_type, @intFromEnum(tag));
            switch (value) {
                inline else => |payload| writeValue(w, @TypeOf(payload), payload),
            }
        },
        else => @compileError("unsupported HXWT wire field: " ++ @typeName(T)),
    }
}

fn scanValue(r: *Reader, comptime T: type) Error!void {
    @setEvalBranchQuota(100_000);
    if (T == void) return;
    switch (@typeInfo(T)) {
        .bool => if (try r.int(u8) > 1) return error.InvalidSnapshot,
        .int, .float => _ = try r.take(@sizeOf(T)),
        .@"enum" => |e| {
            _ = std.enums.fromInt(T, try r.int(e.tag_type)) orelse return error.InvalidSnapshot;
        },
        .optional => |o| {
            const present = try r.int(u8);
            if (present > 1) return error.InvalidSnapshot;
            if (present == 1) try scanValue(r, o.child);
        },
        .array => |a| for (0..a.len) |_| try scanValue(r, a.child),
        .pointer => |p| {
            if (p.size != .slice) @compileError("HXWT rejects pointers");
            const count: usize = try r.int(u32);
            if (count > (if (p.child == u8) max_wire_bytes else max_items)) return error.Capacity;
            try r.budget(p.child, count);
            if (p.child == u8) {
                _ = try r.take(count);
                return;
            }
            for (0..count) |_| try scanValue(r, p.child);
        },
        .@"struct" => |s| inline for (s.field_types) |FieldType| try scanValue(r, FieldType),
        .@"union" => |u| {
            const Tag = u.tag_type orelse @compileError("HXWT rejects untagged unions");
            const raw = try r.int(@typeInfo(Tag).@"enum".tag_type);
            const tag = std.enums.fromInt(Tag, raw) orelse return error.InvalidSnapshot;
            inline for (u.field_names, u.field_types) |name, FieldType| if (tag == @field(Tag, name)) {
                try scanValue(r, FieldType);
                return;
            };
            return error.InvalidSnapshot;
        },
        else => @compileError("unsupported HXWT wire field: " ++ @typeName(T)),
    }
}

fn freeValue(comptime T: type, allocator: std.mem.Allocator, value: T) void {
    if (T == void) return;
    switch (@typeInfo(T)) {
        .optional => |o| if (value) |v| freeValue(o.child, allocator, v),
        .array => |a| for (value) |v| freeValue(a.child, allocator, v),
        .pointer => |p| {
            if (p.size != .slice) @compileError("HXWT rejects pointers");
            for (value) |v| freeValue(p.child, allocator, v);
            std.crypto.secureZero(u8, std.mem.sliceAsBytes(value));
            allocator.free(value);
        },
        .@"struct" => |s| inline for (s.field_names, s.field_types) |name, FieldType| freeValue(FieldType, allocator, @field(value, name)),
        .@"union" => switch (value) {
            inline else => |payload| freeValue(@TypeOf(payload), allocator, payload),
        },
        else => {},
    }
}

fn readValue(r: *Reader, allocator: std.mem.Allocator, comptime T: type) Error!T {
    @setEvalBranchQuota(100_000);
    if (T == void) return {};
    return switch (@typeInfo(T)) {
        .bool => blk: {
            const raw = try r.int(u8);
            if (raw > 1) return error.InvalidSnapshot;
            break :blk raw == 1;
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
            break :blk if (present == 0) null else try readValue(r, allocator, o.child);
        },
        .array => |a| blk: {
            var out: T = undefined;
            var done: usize = 0;
            errdefer {
                for (out[0..done]) |v| freeValue(a.child, allocator, v);
                std.crypto.secureZero(u8, std.mem.asBytes(&out));
            }
            for (&out) |*slot| {
                slot.* = try readValue(r, allocator, a.child);
                done += 1;
            }
            break :blk out;
        },
        .pointer => |p| blk: {
            if (p.size != .slice) @compileError("HXWT rejects pointers");
            const count: usize = try r.int(u32);
            if (count > (if (p.child == u8) max_wire_bytes else max_items)) return error.Capacity;
            const out = try allocator.alloc(p.child, count);
            if (p.child == u8) {
                errdefer allocator.free(out);
                @memcpy(out, try r.take(count));
                break :blk out;
            }
            var done: usize = 0;
            errdefer {
                for (out[0..done]) |v| freeValue(p.child, allocator, v);
                std.crypto.secureZero(u8, std.mem.sliceAsBytes(out));
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
            errdefer {
                inline for (s.field_names, s.field_types, 0..) |name, FieldType, i| if (done > i) freeValue(FieldType, allocator, @field(out, name));
                std.crypto.secureZero(u8, std.mem.asBytes(&out));
            }
            inline for (s.field_names, s.field_types) |name, FieldType| {
                @field(out, name) = try readValue(r, allocator, FieldType);
                done += 1;
            }
            break :blk out;
        },
        .@"union" => |u| blk: {
            const Tag = u.tag_type orelse @compileError("HXWT rejects untagged unions");
            const raw = try r.int(@typeInfo(Tag).@"enum".tag_type);
            const tag = std.enums.fromInt(Tag, raw) orelse return error.InvalidSnapshot;
            inline for (u.field_names, u.field_types) |name, FieldType| if (tag == @field(Tag, name))
                break :blk @unionInit(T, name, try readValue(r, allocator, FieldType));
            return error.InvalidSnapshot;
        },
        else => @compileError("unsupported HXWT wire field: " ++ @typeName(T)),
    };
}

pub fn freeEncoded(allocator: std.mem.Allocator, bytes: []u8) void {
    std.crypto.secureZero(u8, bytes);
    allocator.free(bytes);
}

pub fn encode(allocator: std.mem.Allocator, body: *const Body, tls: wt.TlsConfig, target_pid: u32) Error![]u8 {
    try body.validate(tls, target_pid);
    const body_len = try valueSize(Body, body.*);
    const total = try addSize(try addSize(header_len, body_len), digest_len);
    if (total > max_wire_bytes or body_len > std.math.maxInt(u32)) return error.Capacity;
    const bytes = try allocator.alloc(u8, total);
    errdefer freeEncoded(allocator, bytes);
    var w = Writer{ .bytes = bytes };
    w.put(magic);
    w.int(u16, version);
    w.int(u16, 0);
    w.int(u32, @intCast(body_len));
    writeValue(&w, Body, body.*);
    std.debug.assert(w.pos == total - digest_len);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(digest_domain);
    hash.update(bytes[0..w.pos]);
    var digest: [digest_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &digest);
    hash.final(&digest);
    w.put(&digest);
    return bytes;
}

/// Complete syntax and allocation-budget scan before any candidate allocation.
/// The caller must AEAD-authenticate `bytes` before calling this decoder.
pub fn decode(allocator: std.mem.Allocator, bytes: []const u8, tls: wt.TlsConfig, target_pid: u32) Error!Body {
    if (bytes.len < header_len + digest_len or bytes.len > max_wire_bytes or !std.mem.eql(u8, bytes[0..4], magic)) return error.InvalidSnapshot;
    var header = Reader{ .bytes = bytes[4..header_len] };
    if (try header.int(u16) != version or try header.int(u16) != 0) return error.InvalidSnapshot;
    const body_len: usize = try header.int(u32);
    if (body_len != bytes.len - header_len - digest_len) return error.InvalidSnapshot;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(digest_domain);
    hash.update(bytes[0 .. bytes.len - digest_len]);
    var expected: [digest_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &expected);
    hash.final(&expected);
    const actual: [digest_len]u8 = bytes[bytes.len - digest_len ..][0..digest_len].*;
    if (!std.crypto.timing_safe.eql([digest_len]u8, expected, actual)) return error.InvalidSnapshot;
    var scan = Reader{ .bytes = bytes[header_len .. bytes.len - digest_len] };
    try scanValue(&scan, Body);
    if (scan.pos != scan.bytes.len) return error.InvalidSnapshot;
    var read = Reader{ .bytes = scan.bytes };
    var body = try readValue(&read, allocator, Body);
    errdefer body.deinit(allocator);
    if (read.pos != read.bytes.len) return error.InvalidSnapshot;
    try body.validate(tls, target_pid);
    return body;
}

test "HXWT wire rejects malformed frame before allocation" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.InvalidSnapshot, decode(allocator, "HXWT", undefined, 1));
    var bad: [header_len + digest_len]u8 = @splat(0);
    @memcpy(bad[0..4], magic);
    std.mem.writeInt(u16, bad[4..6], version, .little);
    try std.testing.expectError(error.InvalidSnapshot, decode(allocator, &bad, undefined, 1));
}

test "HXWT encrypted-body codec round-trips an idle live UDP owner and refuses tamper" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const Ed25519 = std.crypto.sign.Ed25519;
    const x509_selfsign = @import("../../proto/x509_selfsign.zig");
    const key = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x37)));
    var cert_buf: [1024]u8 = undefined;
    const cert = try x509_selfsign.buildSelfSigned(&cert_buf, .{
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
    var source = wt.WebTransportListener.init(allocator, tls, 6667);
    defer source.deinit();
    try source.prepareColdResources(std.testing.io, .{ .v4_mapped = .{ 127, 0, 0, 1 } }, 0);
    var active = try source.captureUnstartedActive(allocator);
    var active_owned = true;
    defer if (active_owned) active.deinit(allocator);
    const pid = std.os.windows.GetCurrentProcessId();
    const transfer = try udp.duplicateForProcess(source.socket.?.fd, pid);
    var body: Body = .{ .snapshot = active, .udp_transfer = transfer, .bridges = try allocator.alloc(wt.BridgeTransfer, 0), .accepted = try allocator.alloc(AcceptedIrcSocket, 0) };
    active_owned = false;
    defer body.deinit(allocator);
    const wire = try encode(allocator, &body, tls, pid);
    defer freeEncoded(allocator, wire);
    var decoded = try decode(allocator, wire, tls, pid);
    defer decoded.deinit(allocator);
    try std.testing.expectEqualDeep(body.snapshot.base, decoded.snapshot.base);
    try std.testing.expectEqual(body.snapshot.slot_count, decoded.snapshot.slot_count);
    try std.testing.expectEqual(@as(usize, 0), decoded.bridges.len);
    try std.testing.expectError(error.InvalidSnapshot, decode(allocator, wire, tls, pid + 1));
    wire[header_len] ^= 1;
    try std.testing.expectError(error.InvalidSnapshot, decode(allocator, wire, tls, pid));
    wire[header_len] ^= 1;
    try std.testing.expectError(error.InvalidSnapshot, decode(allocator, wire[0 .. wire.len - 1], tls, pid));
}
