// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Detached, bounded native-media physical state wire for a future joined
//! Windows Helix transaction. The body is checksummed, not authenticated;
//! the private arena envelope must authenticate it before decoding. This
//! module never publishes a media owner or weakens the active-media guard.

const std = @import("std");
const routing = @import("../../substrate/media_routing.zig");
const capability = @import("../../substrate/media_capability.zig");
const native = @import("../native_media_transport.zig");
const webrtc = @import("../media_plane.zig");
const rooms = @import("../media_room.zig");
const media_transport = @import("../../substrate/media_transport.zig");
const rtp_nack = @import("../../substrate/rtp_nack.zig");
const sfu_srtp = @import("../sfu_srtp.zig");
const dtls12 = @import("../../proto/dtls12_server.zig");
const dtls13 = @import("../../proto/dtls13_server.zig");
const dtls_fingerprint = @import("../../proto/dtls_fingerprint.zig");

pub const max_wire_bytes: usize = 64 * 1024 * 1024;
pub const max_alloc_bytes: usize = 128 * 1024 * 1024;
const max_rows: usize = routing.max_graph_rows * 2;
const magic = [4]u8{ 'H', 'X', 'N', 'A' };
const webrtc_magic = [4]u8{ 'H', 'X', 'W', 'A' };
const version: u16 = 1;
const header_len: usize = 12;
const digest_len: usize = 32;
const digest_domain = "onyx-windows-native-active-media-v1";
const webrtc_digest_domain = "onyx-windows-webrtc-active-media-v1";

// The source owner records this as `anyerror`, a local diagnostic. Error
// ordinals are compiler-local, so only these deliberately versioned names
// have wire meanings. A new diagnostic refuses the cut instead of silently
// becoming another error on the candidate image.
const diagnostic_errors = [_]anyerror{
    error.OutOfMemory,
    error.InvalidIngress,
    error.AddressDenied,
    error.AddressOwned,
    error.EndpointUnavailable,
    error.StaleCandidate,
    error.NotRoutingBound,
    error.NotRoutingPump,
    error.SequenceExhausted,
    error.QueueUnavailable,
    error.ProducerFenced,
    error.InvalidRequest,
    error.InvalidIdentity,
    error.InvalidScope,
    error.Busy,
    error.Closing,
};

fn diagnosticCode(value: anyerror) Error!u8 {
    for (diagnostic_errors, 0..) |known, i| if (value == known) return @intCast(i);
    return error.InvalidSnapshot;
}

pub const Error = std.mem.Allocator.Error || error{ InvalidSnapshot, Capacity };
pub const Limits = struct { max_participants: usize, max_state_bytes: usize };

comptime {
    if (@sizeOf(usize) != 8) @compileError("active-media checkpoint requires a 64-bit target");
    // A field added to any nested source DTO must get an explicit version
    // review. The wire writes fields in declared order, never ABI padding.
    if (@typeInfo(native.PhysicalSnapshot).@"struct".field_names.len != 10 or
        @typeInfo(native.PhysicalSnapshot.Endpoint).@"struct".field_names.len != 11 or
        @typeInfo(native.PhysicalSnapshot.Stream).@"struct".field_names.len != 2 or
        @typeInfo(native.PhysicalSnapshot.Channel).@"struct".field_names.len != 2 or
        @typeInfo(native.PhysicalSnapshot.ChannelIndex).@"struct".field_names.len != 2 or
        @typeInfo(native.Link.Snapshot).@"struct".field_names.len != 4 or
        @typeInfo(native.Link.SnapshotEntry).@"struct".field_names.len != 8 or
        @typeInfo(routing.EndpointObservation).@"struct".field_names.len != 4 or
        @typeInfo(routing.EndpointRef).@"struct".field_names.len != 3 or
        @typeInfo(routing.EndpointStamp).@"struct".field_names.len != 4 or
        @typeInfo(rooms.CallProfile).@"struct".field_names.len != 3)
        @compileError("native media snapshot schema changed; review and bump HXNA version");
    if (@typeInfo(webrtc.PhysicalSnapshot).@"struct".field_names.len != 31 or
        @typeInfo(webrtc.PhysicalSnapshot.Row).@"struct".field_names.len != 15 or
        @typeInfo(webrtc.PhysicalSnapshot.Queue).@"struct".field_names.len != 7 or
        @typeInfo(media_transport.MediaTransport.Snapshot).@"struct".field_names.len != 6 or
        @typeInfo(media_transport.MediaTransport.SnapshotEndpoint).@"struct".field_names.len != 9 or
        @typeInfo(rtp_nack.RetransmitBuffer.Snapshot).@"struct".field_names.len != 4 or
        @typeInfo(rtp_nack.PerSsrcRetransmitBuffer.Snapshot).@"struct".field_names.len != 5 or
        @typeInfo(sfu_srtp.SfuSrtp.Snapshot).@"struct".field_names.len != 6 or
        @typeInfo(sfu_srtp.SfuSrtp.Snapshot.Peer).@"struct".field_names.len != 8 or
        @typeInfo(dtls12.Terminator.Snapshot).@"struct".field_names.len != 5 or
        @typeInfo(dtls13.Terminator.Snapshot).@"struct".field_names.len != 5)
        @compileError("WebRTC media snapshot schema changed; review and bump HXWA version");
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
    alloc_limit: usize,
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
        if (self.alloc_bytes > self.alloc_limit) return error.Capacity;
    }
};

fn addSize(a: usize, b: usize) Error!usize {
    return std.math.add(usize, a, b) catch error.Capacity;
}

fn valueSize(comptime T: type, value: T) Error!usize {
    if (T == std.mem.Allocator or T == void) return 0;
    if (T == anyerror) {
        _ = try diagnosticCode(value);
        return 1;
    }
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
            if (p.size != .slice) @compileError("HXNA rejects pointers");
            if (value.len > (if (p.child == u8) max_wire_bytes else max_rows)) return error.Capacity;
            var n: usize = 4;
            for (value) |v| n = try addSize(n, try valueSize(p.child, v));
            break :blk n;
        },
        .@"struct" => |s| blk: {
            var n: usize = 0;
            inline for (s.field_names, s.field_types) |name, FieldType| n = try addSize(n, try valueSize(FieldType, @field(value, name)));
            break :blk n;
        },
        else => @compileError("unsupported HXNA wire field"),
    };
}

fn writeValue(w: *Writer, comptime T: type, value: T) void {
    if (T == std.mem.Allocator or T == void) return;
    if (T == anyerror) {
        w.int(u8, diagnosticCode(value) catch unreachable);
        return;
    }
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
            if (p.size != .slice) @compileError("HXNA rejects pointers");
            w.int(u32, @intCast(value.len));
            for (value) |v| writeValue(w, p.child, v);
        },
        .@"struct" => |s| inline for (s.field_names, s.field_types) |name, FieldType| writeValue(w, FieldType, @field(value, name)),
        else => @compileError("unsupported HXNA wire field"),
    }
}

/// Walk every byte and every allocation size before allocating any state.
fn scanValue(r: *Reader, comptime T: type) Error!void {
    if (T == std.mem.Allocator or T == void) return;
    if (T == anyerror) {
        if (try r.int(u8) >= diagnostic_errors.len) return error.InvalidSnapshot;
        return;
    }
    switch (@typeInfo(T)) {
        .bool => if (try r.int(u8) > 1) return error.InvalidSnapshot,
        .int => _ = try r.int(T),
        .float => _ = try r.take(@sizeOf(T)),
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
            if (p.size != .slice) @compileError("HXNA rejects pointers");
            const count: usize = try r.int(u32);
            if (count > (if (p.child == u8) max_wire_bytes else max_rows)) return error.Capacity;
            try r.budget(p.child, count);
            for (0..count) |_| try scanValue(r, p.child);
        },
        .@"struct" => |s| inline for (s.field_types) |FieldType| try scanValue(r, FieldType),
        else => @compileError("unsupported HXNA wire field"),
    }
}

fn freeValue(comptime T: type, allocator: std.mem.Allocator, value: T) void {
    if (T == std.mem.Allocator or T == void or T == anyerror) return;
    switch (@typeInfo(T)) {
        .optional => |o| if (value) |v| freeValue(o.child, allocator, v),
        .array => |a| for (value) |v| freeValue(a.child, allocator, v),
        .pointer => |p| {
            if (p.size != .slice) @compileError("HXNA rejects pointers");
            for (value) |v| freeValue(p.child, allocator, v);
            std.crypto.secureZero(u8, std.mem.sliceAsBytes(value));
            allocator.free(value);
        },
        .@"struct" => |s| inline for (s.field_names, s.field_types) |name, FieldType| freeValue(FieldType, allocator, @field(value, name)),
        else => {},
    }
}

fn readValue(r: *Reader, allocator: std.mem.Allocator, comptime T: type) Error!T {
    @setEvalBranchQuota(100_000);
    if (T == std.mem.Allocator) return allocator;
    if (T == void) return {};
    if (T == anyerror) {
        const code = try r.int(u8);
        if (code >= diagnostic_errors.len) return error.InvalidSnapshot;
        return diagnostic_errors[code];
    }
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
            if (present == 0) break :blk null;
            if (o.child == anyerror) {
                const code = try r.int(u8);
                if (code >= diagnostic_errors.len) return error.InvalidSnapshot;
                const diagnostic: ?anyerror = diagnostic_errors[code];
                break :blk diagnostic;
            }
            break :blk try readValue(r, allocator, o.child);
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
            if (p.size != .slice) @compileError("HXNA rejects pointers");
            const count: usize = try r.int(u32);
            if (count > (if (p.child == u8) max_wire_bytes else max_rows)) return error.Capacity;
            var out = try allocator.alloc(p.child, count);
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
        else => @compileError("unsupported HXNA wire field"),
    };
}

pub fn freeEncoded(allocator: std.mem.Allocator, bytes: []u8) void {
    std.crypto.secureZero(u8, bytes);
    allocator.free(bytes);
}

/// Canonical native endpoint, stream, channel/link and index image. Callers
/// retain the source DTO until the encompassing World cut commits or aborts.
pub fn encodeNative(allocator: std.mem.Allocator, snapshot: *const native.PhysicalSnapshot, limits: Limits) Error![]u8 {
    if (limits.max_state_bytes == 0 or limits.max_state_bytes > max_alloc_bytes) return error.Capacity;
    snapshot.validate(limits.max_participants, limits.max_state_bytes) catch |err| return if (err == error.Capacity) error.Capacity else error.InvalidSnapshot;
    const body_len = try valueSize(native.PhysicalSnapshot, snapshot.*);
    const total = try addSize(try addSize(header_len, body_len), digest_len);
    if (total > max_wire_bytes or body_len > std.math.maxInt(u32)) return error.Capacity;
    const bytes = try allocator.alloc(u8, total);
    errdefer freeEncoded(allocator, bytes);
    var w = Writer{ .bytes = bytes };
    w.put(&magic);
    w.int(u16, version);
    w.int(u16, 0);
    w.int(u32, @intCast(body_len));
    writeValue(&w, native.PhysicalSnapshot, snapshot.*);
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

/// No dynamic allocation occurs until the entire frame, every count, and the
/// maximum candidate allocation footprint have been checked.
pub fn decodeNative(allocator: std.mem.Allocator, bytes: []const u8, limits: Limits) Error!native.PhysicalSnapshot {
    if (limits.max_state_bytes == 0 or limits.max_state_bytes > max_alloc_bytes) return error.Capacity;
    if (bytes.len < header_len + digest_len or bytes.len > max_wire_bytes or !std.mem.eql(u8, bytes[0..4], &magic)) return error.InvalidSnapshot;
    var header = Reader{ .bytes = bytes[4..header_len], .alloc_limit = limits.max_state_bytes };
    if (try header.int(u16) != version or try header.int(u16) != 0) return error.InvalidSnapshot;
    const body_len: usize = try header.int(u32);
    if (body_len != bytes.len - header_len - digest_len) return error.InvalidSnapshot;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(digest_domain);
    hash.update(bytes[0 .. bytes.len - digest_len]);
    var digest: [digest_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &digest);
    hash.final(&digest);
    if (!std.crypto.timing_safe.eql([digest_len]u8, digest, bytes[bytes.len - digest_len ..][0..digest_len].*)) return error.InvalidSnapshot;
    const body = bytes[header_len .. bytes.len - digest_len];
    var scan = Reader{ .bytes = body, .alloc_limit = limits.max_state_bytes };
    try scanValue(&scan, native.PhysicalSnapshot);
    if (scan.pos != body.len) return error.InvalidSnapshot;
    var r = Reader{ .bytes = body, .alloc_limit = limits.max_state_bytes };
    var result = try readValue(&r, allocator, native.PhysicalSnapshot);
    errdefer result.deinit();
    if (r.pos != body.len) return error.InvalidSnapshot;
    result.validate(limits.max_participants, limits.max_state_bytes) catch |err| return if (err == error.Capacity) error.Capacity else error.InvalidSnapshot;
    return result;
}

/// Complete WebRTC physical state, including the source DTLS identity and
/// sessions, SRTP replay/nonce windows, transport indexes, and packet history.
/// This remains a detached component of a future authenticated graph capsule.
pub fn encodeWebrtc(allocator: std.mem.Allocator, snapshot: *const webrtc.PhysicalSnapshot, limits: webrtc.PhysicalSnapshot.Limits) Error![]u8 {
    if (limits.max_bytes == 0 or limits.max_bytes > max_alloc_bytes) return error.Capacity;
    snapshot.validate(limits) catch |err| return if (err == error.Capacity) error.Capacity else error.InvalidSnapshot;
    const body_len = try valueSize(webrtc.PhysicalSnapshot, snapshot.*);
    const total = try addSize(try addSize(header_len, body_len), digest_len);
    if (total > max_wire_bytes or body_len > std.math.maxInt(u32)) return error.Capacity;
    const bytes = try allocator.alloc(u8, total);
    errdefer freeEncoded(allocator, bytes);
    var w = Writer{ .bytes = bytes };
    w.put(&webrtc_magic);
    w.int(u16, version);
    w.int(u16, 0);
    w.int(u32, @intCast(body_len));
    writeValue(&w, webrtc.PhysicalSnapshot, snapshot.*);
    std.debug.assert(w.pos == total - digest_len);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(webrtc_digest_domain);
    hash.update(bytes[0..w.pos]);
    var digest: [digest_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &digest);
    hash.final(&digest);
    w.put(&digest);
    return bytes;
}

/// Scan the complete frame before allocating a single candidate byte. The
/// queue has no serialized payload rows, but its empty backing is still funded
/// here because prepareRemappedRestore allocates it before publication.
fn scanWebrtcBody(body: []const u8, limits: webrtc.PhysicalSnapshot.Limits) Error!void {
    if (@sizeOf(webrtc.PhysicalSnapshot) > limits.max_bytes) return error.Capacity;
    var scan = Reader{ .bytes = body, .alloc_limit = limits.max_bytes, .alloc_bytes = @sizeOf(webrtc.PhysicalSnapshot) };
    var queue: webrtc.PhysicalSnapshot.Queue = undefined;
    const fields = @typeInfo(webrtc.PhysicalSnapshot).@"struct";
    inline for (fields.field_names, fields.field_types) |name, FieldType| {
        if (comptime std.mem.eql(u8, name, "queue")) {
            queue = try readValue(&scan, std.heap.page_allocator, FieldType);
        } else {
            try scanValue(&scan, FieldType);
        }
    }
    if (scan.pos != body.len or queue.capacity == 0 or queue.payload_limit == 0) return error.InvalidSnapshot;
    const QueuePtr = @typeInfo(@FieldType(webrtc.MediaPlane, "routing_egress")).optional.child;
    const QueueType = @typeInfo(QueuePtr).pointer.child;
    const EgressRow = @typeInfo(@FieldType(QueueType, "rows")).pointer.child;
    try scan.budget(EgressRow, queue.capacity);
    const payload_bytes = std.math.mul(usize, queue.capacity, queue.payload_limit) catch return error.Capacity;
    try scan.budget(u8, payload_bytes);
}

/// Digest verifies accidental corruption; the outer private Helix envelope
/// must authenticate the graph and this component together before adoption.
pub fn decodeWebrtc(allocator: std.mem.Allocator, bytes: []const u8, limits: webrtc.PhysicalSnapshot.Limits) Error!webrtc.PhysicalSnapshot {
    if (limits.max_bytes == 0 or limits.max_bytes > max_alloc_bytes) return error.Capacity;
    if (bytes.len < header_len + digest_len or bytes.len > max_wire_bytes or !std.mem.eql(u8, bytes[0..4], &webrtc_magic)) return error.InvalidSnapshot;
    var header = Reader{ .bytes = bytes[4..header_len], .alloc_limit = limits.max_bytes };
    if (try header.int(u16) != version or try header.int(u16) != 0) return error.InvalidSnapshot;
    const body_len: usize = try header.int(u32);
    if (body_len != bytes.len - header_len - digest_len) return error.InvalidSnapshot;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(webrtc_digest_domain);
    hash.update(bytes[0 .. bytes.len - digest_len]);
    var digest: [digest_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &digest);
    hash.final(&digest);
    if (!std.crypto.timing_safe.eql([digest_len]u8, digest, bytes[bytes.len - digest_len ..][0..digest_len].*)) return error.InvalidSnapshot;
    const body = bytes[header_len .. bytes.len - digest_len];
    try scanWebrtcBody(body, limits);
    var r = Reader{ .bytes = body, .alloc_limit = limits.max_bytes };
    var result = try readValue(&r, allocator, webrtc.PhysicalSnapshot);
    errdefer result.deinit();
    if (r.pos != body.len) return error.InvalidSnapshot;
    result.validate(limits) catch |err| return if (err == error.Capacity) error.Capacity else error.InvalidSnapshot;
    return result;
}

fn fixture(allocator: std.mem.Allocator) !native.PhysicalSnapshot {
    const key: routing.EndpointKey = .{ .call = .{ .domain = .{ .serial = 17 }, .serial = 29 }, .client = .{ .shard = 2, .slot = 3, .gen = 4 }, .leg = .native };
    const endpoint_id: routing.EndpointId = .{ .call = key.call, .serial = 31, .leg = .native };
    const observation: routing.EndpointObservation = .{ .reference = .{ .endpoint = endpoint_id, .offering_client = key.client, .bridge_policy_revision = 5 }, .stamp = .{ .endpoint = endpoint_id, .binding_revision = 6, .security_revision = 7, .offering_client = key.client }, .stream_id = 401, .mode = .legacy_group };
    var profile: rooms.CallProfile = .{ .codecs = @splat(.{ .tag = .raw, .clock_rate = 0, .params = 0 }), .codec_count = 1, .fec = .{ .scheme = .none, .redundancy = 0 } };
    profile.codecs[0] = .{ .tag = .cadencevox, .clock_rate = 48_000, .params = 0 };
    const master: [32]u8 = @splat(0x5a);
    var link = native.Link.initConfig(native.max_call_participants);
    const address = try native.TransportAddress.fromBytes(&.{ 127, 0, 0, 1 }, 9001);
    try link.register("alice", .voice, 401, address);
    link.setSelection("alice", .{ .max_spatial = 1, .max_temporal = 2 });
    const link_snapshot = try link.capture();
    const endpoints = try allocator.alloc(native.PhysicalSnapshot.Endpoint, 1);
    errdefer allocator.free(endpoints);
    const streams = try allocator.alloc(native.PhysicalSnapshot.Stream, 1);
    errdefer allocator.free(streams);
    const channels = try allocator.alloc(native.PhysicalSnapshot.Channel, 1);
    errdefer allocator.free(channels);
    const name = try allocator.dupe(u8, "#one");
    errdefer allocator.free(name);
    const index = try allocator.alloc(native.PhysicalSnapshot.ChannelIndex, 1);
    endpoints[0] = .{ .key = key, .selection = .{ .max_spatial = 1, .max_temporal = 2 }, .profile = profile, .identity = observation, .kind_bits = 1, .codecs = 1, .master = master, .keys = try capability.derive(&master, 401), .remote = address, .display_nick = @splat(0), .display_len = 5 };
    @memcpy(endpoints[0].display_nick[0..5], "alice");
    streams[0] = .{ .stream_id = 401, .key = key };
    channels[0] = .{ .name = name, .link = link_snapshot };
    index[0] = .{ .stream_id = 401, .channel = 0 };
    return .{ .allocator = allocator, .endpoints = endpoints, .streams = streams, .channels = channels, .stream_index = index, .physical_revision = 19, .next_ingress_serial = 23, .routed_accepted = 7, .routed_refused = 8, .routed_errors = 9 };
}

test "Windows active native-media physical checkpoint roundtrips exact owned state" {
    const testing = std.testing;
    const limits: Limits = .{ .max_participants = native.max_call_participants, .max_state_bytes = 1 << 20 };
    var source = try fixture(testing.allocator);
    defer source.deinit();
    try source.validate(limits.max_participants, limits.max_state_bytes);
    const bytes = try encodeNative(testing.allocator, &source, limits);
    defer freeEncoded(testing.allocator, bytes);
    var decoded = try decodeNative(testing.allocator, bytes, limits);
    defer decoded.deinit();
    try testing.expect(decoded.endpoints.ptr != source.endpoints.ptr);
    try testing.expect(decoded.channels[0].name.ptr != source.channels[0].name.ptr);
    try testing.expectEqualDeep(source.endpoints[0], decoded.endpoints[0]);
    try testing.expectEqualDeep(source.channels[0].link, decoded.channels[0].link);
    const again = try encodeNative(testing.allocator, &decoded, limits);
    defer freeEncoded(testing.allocator, again);
    try testing.expectEqualSlices(u8, bytes, again);
}

test "Windows active native-media checkpoint rejects tamper truncation trailing and limits" {
    const testing = std.testing;
    const limits: Limits = .{ .max_participants = native.max_call_participants, .max_state_bytes = 1 << 20 };
    var source = try fixture(testing.allocator);
    defer source.deinit();
    const bytes = try encodeNative(testing.allocator, &source, limits);
    defer freeEncoded(testing.allocator, bytes);
    try testing.expectError(error.InvalidSnapshot, decodeNative(testing.allocator, bytes[0 .. bytes.len - 1], limits));
    const trailing = try testing.allocator.alloc(u8, bytes.len + 1);
    defer testing.allocator.free(trailing);
    @memcpy(trailing[0..bytes.len], bytes);
    trailing[bytes.len] = 0;
    try testing.expectError(error.InvalidSnapshot, decodeNative(testing.allocator, trailing, limits));
    bytes[header_len + 8] ^= 1;
    try testing.expectError(error.InvalidSnapshot, decodeNative(testing.allocator, bytes, limits));
    bytes[header_len + 8] ^= 1;
    var small = limits;
    small.max_state_bytes = @sizeOf(native.PhysicalSnapshot.Endpoint) - 1;
    try testing.expectError(error.Capacity, decodeNative(testing.allocator, bytes, small));
    try testing.expectError(error.Capacity, encodeNative(testing.allocator, &source, small));
}

test "Windows active native-media checkpoint decode allocation failures are atomic" {
    const testing = std.testing;
    const limits: Limits = .{ .max_participants = native.max_call_participants, .max_state_bytes = 1 << 20 };
    var source = try fixture(testing.allocator);
    defer source.deinit();
    const bytes = try encodeNative(testing.allocator, &source, limits);
    defer freeEncoded(testing.allocator, bytes);
    var fail = testing.FailingAllocator.init(testing.allocator, .{});
    const baseline = fail.allocated_bytes - fail.freed_bytes;
    var failures: usize = 0;
    var succeeded = false;
    for (0..32) |n| {
        fail.fail_index = fail.alloc_index + n;
        var decoded = decodeNative(fail.allocator(), bytes, limits) catch |err| {
            fail.fail_index = std.math.maxInt(usize);
            try testing.expectEqual(error.OutOfMemory, err);
            try testing.expectEqual(baseline, fail.allocated_bytes - fail.freed_bytes);
            var retry = try decodeNative(testing.allocator, bytes, limits);
            retry.deinit();
            failures += 1;
            continue;
        };
        fail.fail_index = std.math.maxInt(usize);
        decoded.deinit();
        try testing.expectEqual(baseline, fail.allocated_bytes - fail.freed_bytes);
        succeeded = true;
        break;
    }
    try testing.expect(failures > 0 and succeeded);
}

fn webrtcLimits() webrtc.PhysicalSnapshot.Limits {
    return .{
        .max_rows = 8,
        .max_offered = 8,
        .max_bytes = 16 * 1024 * 1024,
        .transport = .{ .max_endpoints = 8, .max_groups = 8, .max_bytes = 8 * 1024 * 1024 },
    };
}

fn webrtcFixture(allocator: std.mem.Allocator) !webrtc.PhysicalSnapshot {
    const limits = webrtcLimits();
    var transport_owner = media_transport.MediaTransport.init(allocator);
    defer transport_owner.deinit();
    var transport = try transport_owner.capture(allocator, limits.transport);
    errdefer transport.deinit();
    var srtp_owner = sfu_srtp.SfuSrtp.init(allocator);
    defer srtp_owner.wipe();
    var srtp = try srtp_owner.capture(allocator);
    errdefer srtp.deinit();
    const rows = try allocator.alloc(webrtc.PhysicalSnapshot.Row, 0);
    errdefer allocator.free(rows);
    const ufrags = try allocator.alloc(webrtc.PhysicalSnapshot.Ufrag, 0);
    errdefer allocator.free(ufrags);
    const groups = try allocator.alloc(webrtc.PhysicalSnapshot.Group, 0);
    errdefer allocator.free(groups);
    const offered = try allocator.alloc(webrtc.PhysicalSnapshot.Fingerprint, 0);
    errdefer allocator.free(offered);
    var rng = std.Random.DefaultCsprng.init(@splat(0x34));
    const snapshot: webrtc.PhysicalSnapshot = .{
        .allocator = allocator,
        .socket = .{ .device = 91, .inode = 0, .address_be = webrtc.loopback_be, .port = 9001, .recv_timeout_ms = 250 },
        .csprng = webrtc.RngState.capture(&rng),
        .stun_server = null,
        .discovered = null,
        .max_frame_bytes = 1200,
        .max_upload_bytes = 4096,
        .cross_configured = false,
        .dtls_enabled = false,
        .dtls_requested = false,
        .dtls13_enabled = false,
        .dtls13_requested = false,
        .dtls_fingerprint_buf = @splat(0),
        .dtls_fingerprint_len = 0,
        .dtls12 = null,
        .dtls13 = null,
        .srtp = srtp,
        .transport = transport,
        .rows = rows,
        .ufrags = ufrags,
        .groups = groups,
        .ssrcs = @splat(.{}),
        .crypto = @splat(.{}),
        .offered_fps = offered,
        .queue = .{ .capacity = 4, .payload_limit = 1024, .head = 0, .next_ordinal = 1, .completed = 0, .last_disposition = null, .next_fence = 1 },
        .rtcp_out_head = 0,
        .physical_revision = 1,
        .next_routing_inbound = 1,
        .routing_ingress_refused = 0,
        .routing_ingress_completed = 0,
        .routing_last_ingress_error = null,
    };
    try snapshot.validate(limits);
    return snapshot;
}

fn webrtcHistoryFixture(allocator: std.mem.Allocator) !webrtc.PhysicalSnapshot {
    var snapshot = try webrtcFixture(allocator);
    errdefer snapshot.deinit();
    const packet = [13]u8{ 0x80, 111, 0, 9, 0, 0, 0, 1, 0, 0, 1, 145, 'x' };
    var history = rtp_nack.RetransmitBuffer.init(allocator, media_transport.rtx_capacity);
    defer history.deinit();
    try history.onSent(9, &packet);
    var cache = rtp_nack.PerSsrcRetransmitBuffer.init(allocator, media_transport.rtx_capacity, sfu_srtp.max_owners);
    defer cache.deinit();
    const prepared = try cache.prepareSent(401, 9, &packet);
    defer prepared.deinit();
    try prepared.validate();
    prepared.commitRetainingMetadata();
    var row_rtx = try history.capture(allocator, webrtcLimits().max_bytes);
    errdefer row_rtx.deinit();
    var row_cache = try cache.capture(allocator, webrtcLimits().max_bytes);
    errdefer row_cache.deinit();
    var transport_owner = media_transport.MediaTransport.init(allocator);
    defer transport_owner.deinit();
    var rng = std.Random.DefaultCsprng.init(@splat(0x17));
    const transport_endpoint = try transport_owner.allocate("#one", "alice", rng.random());
    try transport_endpoint.rtx.onSent(9, &packet);
    var transport = try transport_owner.capture(allocator, webrtcLimits().transport);
    errdefer transport.deinit();
    const rows = try allocator.alloc(webrtc.PhysicalSnapshot.Row, 1);
    errdefer allocator.free(rows);
    const key: routing.EndpointKey = .{ .call = .{ .domain = .{ .serial = 17 }, .serial = 29 }, .client = .{ .shard = 2, .slot = 3, .gen = 4 }, .leg = .webrtc };
    const endpoint_id: routing.EndpointId = .{ .call = key.call, .serial = 31, .leg = .webrtc };
    const observation: routing.EndpointObservation = .{ .reference = .{ .endpoint = endpoint_id, .offering_client = key.client, .bridge_policy_revision = 5 }, .stamp = .{ .endpoint = endpoint_id, .binding_revision = 6, .security_revision = 7, .offering_client = key.client }, .stream_id = 401, .mode = .legacy_group };
    var profile: rooms.CallProfile = .{ .codecs = @splat(.{ .tag = .raw, .clock_rate = 0, .params = 0 }), .codec_count = 1, .fec = .{ .scheme = .none, .redundancy = 0 } };
    profile.codecs[0] = .{ .tag = .cadencevox, .clock_rate = 48_000, .params = 0 };
    rows[0] = .{ .key = key, .identity = observation, .profile = profile, .kind_bits = 1, .expected_fp = null, .max_temporal = 1, .ufrag = transport_endpoint.ufrag, .pwd = transport_endpoint.pwd, .remote = null, .max_spatial = 1, .ssrc = 401, .rx_packets = 1, .rx_bytes = packet.len, .rtx = row_rtx, .cache = row_cache };
    var candidate = snapshot;
    candidate.rows = rows;
    candidate.transport = transport;
    try candidate.validate(webrtcLimits());
    allocator.free(snapshot.rows);
    snapshot.transport.deinit();
    snapshot.rows = rows;
    snapshot.transport = transport;
    return snapshot;
}

fn webrtcCryptoFixture(allocator: std.mem.Allocator) !webrtc.PhysicalSnapshot {
    var snapshot = try webrtcHistoryFixture(allocator);
    errdefer snapshot.deinit();
    const sessions12 = try allocator.alloc(dtls12.Session, dtls12.default_max_sessions);
    defer allocator.free(sessions12);
    var server12 = try dtls12.Terminator.init(@splat(0x51), sessions12, 1_700_000_000, 1_800_000_000);
    defer server12.deinit();
    server12.request_client_cert = true;
    const sessions13 = try allocator.alloc(dtls13.Session, dtls13.default_max_sessions);
    defer allocator.free(sessions13);
    var server13 = try dtls13.Terminator.init(@splat(0x62), sessions13, server12.certDer(), server12.cert_key);
    defer server13.deinit();
    server13.request_client_cert = true;
    var carry12 = try server12.capture(allocator);
    errdefer carry12.deinit();
    var carry13 = try server13.capture(allocator);
    errdefer carry13.deinit();
    var hub = sfu_srtp.SfuSrtp.init(allocator);
    defer hub.wipe();
    const addr = try media_transport.TransportAddress.fromBytes(&.{ 127, 0, 0, 1 }, 9041);
    if (!hub.noteEstablished(addr, std.mem.zeroes(sfu_srtp.ExportedKeys))) return error.Unexpected;
    var srtp = try hub.capture(allocator);
    errdefer srtp.deinit();
    var fp_buf: [128]u8 = @splat(0);
    const fingerprint = try dtls_fingerprint.format(.sha256, server12.certDer(), &fp_buf);
    var candidate = snapshot;
    candidate.dtls_enabled = true;
    candidate.dtls_requested = true;
    candidate.dtls13_enabled = true;
    candidate.dtls13_requested = true;
    candidate.dtls_fingerprint_buf = fp_buf;
    candidate.dtls_fingerprint_len = fingerprint.len;
    candidate.dtls12 = carry12;
    candidate.dtls13 = carry13;
    candidate.srtp = srtp;
    try candidate.validate(webrtcLimits());
    snapshot.srtp.deinit();
    snapshot.dtls_enabled = true;
    snapshot.dtls_requested = true;
    snapshot.dtls13_enabled = true;
    snapshot.dtls13_requested = true;
    snapshot.dtls_fingerprint_buf = fp_buf;
    snapshot.dtls_fingerprint_len = fingerprint.len;
    snapshot.dtls12 = carry12;
    snapshot.dtls13 = carry13;
    snapshot.srtp = srtp;
    return snapshot;
}

fn resignWebrtc(bytes: []u8) void {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(webrtc_digest_domain);
    hash.update(bytes[0 .. bytes.len - digest_len]);
    hash.final(bytes[bytes.len - digest_len ..][0..digest_len]);
}

test "Windows active WebRTC physical checkpoint roundtrips canonical owned state" {
    const testing = std.testing;
    var source = try webrtcHistoryFixture(testing.allocator);
    defer source.deinit();
    const limits = webrtcLimits();
    const bytes = try encodeWebrtc(testing.allocator, &source, limits);
    defer freeEncoded(testing.allocator, bytes);
    var decoded = try decodeWebrtc(testing.allocator, bytes, limits);
    defer decoded.deinit();
    try testing.expect(decoded.rows.ptr != source.rows.ptr);
    try testing.expect(decoded.rows[0].rtx.packets[0].bytes.ptr != source.rows[0].rtx.packets[0].bytes.ptr);
    try testing.expectEqualSlices(u8, source.rows[0].cache.streams[0].cache.packets[0].bytes, decoded.rows[0].cache.streams[0].cache.packets[0].bytes);
    try testing.expect(decoded.transport.endpoints.ptr != source.transport.endpoints.ptr);
    try testing.expectEqualDeep(source.queue, decoded.queue);
    const again = try encodeWebrtc(testing.allocator, &decoded, limits);
    defer freeEncoded(testing.allocator, again);
    try testing.expectEqualSlices(u8, bytes, again);
}

test "Windows active WebRTC checkpoint rejects malformed and re-digested input" {
    const testing = std.testing;
    var source = try webrtcFixture(testing.allocator);
    defer source.deinit();
    const limits = webrtcLimits();
    const bytes = try encodeWebrtc(testing.allocator, &source, limits);
    defer freeEncoded(testing.allocator, bytes);
    try testing.expectError(error.InvalidSnapshot, decodeWebrtc(testing.allocator, bytes[0 .. bytes.len - 1], limits));
    bytes[header_len] ^= 1;
    try testing.expectError(error.InvalidSnapshot, decodeWebrtc(testing.allocator, bytes, limits));
    bytes[header_len] ^= 1;
    const diagnostic_len: usize = 1;
    const tail_len: usize = 5 * @sizeOf(u64) + diagnostic_len;
    const next_inbound = bytes.len - digest_len - tail_len + 2 * @sizeOf(u64);
    @memset(bytes[next_inbound..][0..@sizeOf(u64)], 0);
    resignWebrtc(bytes);
    try testing.expectError(error.InvalidSnapshot, decodeWebrtc(testing.allocator, bytes, limits));
    var too_small = limits;
    too_small.max_bytes = @sizeOf(webrtc.PhysicalSnapshot) - 1;
    try testing.expectError(error.Capacity, decodeWebrtc(testing.allocator, bytes, too_small));
}

test "Windows active WebRTC checkpoint owns DTLS 1.2 and 1.3 identity plus SRTP peer state" {
    const testing = std.testing;
    var source = try webrtcCryptoFixture(testing.allocator);
    defer source.deinit();
    const limits = webrtcLimits();
    const bytes = try encodeWebrtc(testing.allocator, &source, limits);
    defer freeEncoded(testing.allocator, bytes);
    var decoded = try decodeWebrtc(testing.allocator, bytes, limits);
    defer decoded.deinit();
    try testing.expect(decoded.dtls12 != null and decoded.dtls13 != null);
    try testing.expect(decoded.dtls12.?.sessions.ptr != source.dtls12.?.sessions.ptr);
    try testing.expect(decoded.srtp.peers.ptr != source.srtp.peers.ptr);
    try testing.expect(decoded.srtp.peers[0].active);
    const again = try encodeWebrtc(testing.allocator, &decoded, limits);
    defer freeEncoded(testing.allocator, again);
    try testing.expectEqualSlices(u8, bytes, again);
}

test "Windows active WebRTC checkpoint rejects unlisted diagnostic tag and source error" {
    const testing = std.testing;
    var source = try webrtcFixture(testing.allocator);
    defer source.deinit();
    source.routing_last_ingress_error = error.BrandNewUnlistedDiagnostic;
    try testing.expectError(error.InvalidSnapshot, encodeWebrtc(testing.allocator, &source, webrtcLimits()));
    source.routing_last_ingress_error = error.InvalidIngress;
    const bytes = try encodeWebrtc(testing.allocator, &source, webrtcLimits());
    defer freeEncoded(testing.allocator, bytes);
    bytes[bytes.len - digest_len - 1] = 255;
    resignWebrtc(bytes);
    try testing.expectError(error.InvalidSnapshot, decodeWebrtc(testing.allocator, bytes, webrtcLimits()));
}

test "Windows active WebRTC checkpoint decode allocation failures are atomic" {
    const testing = std.testing;
    var source = try webrtcHistoryFixture(testing.allocator);
    defer source.deinit();
    const limits = webrtcLimits();
    const bytes = try encodeWebrtc(testing.allocator, &source, limits);
    defer freeEncoded(testing.allocator, bytes);
    var fail = testing.FailingAllocator.init(testing.allocator, .{});
    const baseline = fail.allocated_bytes - fail.freed_bytes;
    var failures: usize = 0;
    var succeeded = false;
    for (0..128) |n| {
        fail.fail_index = fail.alloc_index + n;
        var decoded = decodeWebrtc(fail.allocator(), bytes, limits) catch |err| {
            fail.fail_index = std.math.maxInt(usize);
            try testing.expectEqual(error.OutOfMemory, err);
            try testing.expectEqual(baseline, fail.allocated_bytes - fail.freed_bytes);
            failures += 1;
            continue;
        };
        fail.fail_index = std.math.maxInt(usize);
        decoded.deinit();
        try testing.expectEqual(baseline, fail.allocated_bytes - fail.freed_bytes);
        succeeded = true;
        break;
    }
    try testing.expect(failures > 0 and succeeded);
}
