// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Canonical, bounded companion snapshots for the three Windows UDP owners.
//! The socket observation is an endpoint witness; socket custody travels in
//! the separate PID-scoped, authenticated native_windows_udp_socket record.

const std = @import("std");
const wire = @import("native_windows_companion_wire.zig");
const dualstack_udp = @import("../dualstack_udp.zig");
const media_socket = @import("../../substrate/media_socket.zig");
const ice = @import("../../proto/ice.zig");
const quic_retry = @import("../../proto/quic_retry.zig");
const webtransport = @import("../webtransport_listener.zig");
const webrtc = @import("../media_plane.zig");
const native = @import("../native_media_transport.zig");

pub const max_snapshot_bytes: usize = 64 * 1024;
const observation_len: usize = 8 + 8 + 2 + 16 + 2 + 4 + 4 + 1;
const dual_socket_len: usize = observation_len + 1 + observation_len + 1 + 4 + 1;
const media_socket_len: usize = 8 + 8 + 4 + 2 + 4;
const address_len: usize = 16 + 1 + 2;
const optional_address_len: usize = 1 + address_len;
const rng_len: usize = 512 + 2;
const dtls_len: usize = 1024 + 2 + 32 + 65 + 32 + rng_len + 8 + 1 + 1;
const optional_dtls_len: usize = 1 + dtls_len;
const replay_len: usize = quic_retry.ReplayCache.capacity * (16 + 1) + 8;
const wt_payload_len: usize = dual_socket_len + 32 + 2 + 1 + 1 + 8 + 1 + 8 + 1 + 64 + replay_len + 8 + 8 + 8 + 8 + 4 + 1;
const webrtc_payload_len: usize = media_socket_len + rng_len + optional_address_len * 2 + 8 + 8 + 4 + optional_dtls_len * 2 + 8 + 1 + 1;
const native_payload_len: usize = media_socket_len + 8 + 8 + 8 + 1 + 16 + 1 + 1 + 1;
const wt_magic = [4]u8{ 'H', 'X', 'W', 'T' };
const webrtc_magic = [4]u8{ 'H', 'X', 'W', 'R' };
const native_magic = [4]u8{ 'H', 'X', 'N', 'M' };
const wt_domain = "onyx-windows-webtransport-idle-snapshot-v1";
const webrtc_domain = "onyx-windows-webrtc-idle-snapshot-v1";
const native_domain = "onyx-windows-native-media-idle-snapshot-v1";

comptime {
    if (@sizeOf(usize) != 8) @compileError("Onyx Server UDP snapshots require a 64-bit target");
    if (@typeInfo(webtransport.Snapshot).@"struct".field_names.len != 16 or
        @typeInfo(webrtc.Snapshot).@"struct".field_names.len != 15 or
        @typeInfo(native.Snapshot).@"struct".field_names.len != 9 or
        @typeInfo(dualstack_udp.Snapshot).@"struct".field_names.len != 5 or
        @typeInfo(dualstack_udp.DatagramObservation).@"struct".field_names.len != 8 or
        @typeInfo(media_socket.Snapshot).@"struct".field_names.len != 5 or
        @typeInfo(ice.TransportAddress).@"struct".field_names.len != 3 or
        @typeInfo(webrtc.RngState).@"struct".field_names.len != 2 or
        @typeInfo(webrtc.IdleDtls).@"struct".field_names.len != 9 or
        @typeInfo(quic_retry.Secret).@"struct".field_names.len != 2 or
        @typeInfo(quic_retry.ReplayCache).@"struct".field_names.len != 3)
        @compileError("UDP snapshot fields changed; review wire format and bump version");
    if (@sizeOf(@TypeOf((@as(webrtc.IdleDtls, undefined)).cert_der)) != 1024 or
        @sizeOf(@TypeOf((@as(webrtc.RngState, undefined)).state)) != 512 or
        @sizeOf(@TypeOf((@as(quic_retry.ReplayCache, undefined)).entries[0])) != 16)
        @compileError("UDP snapshot schema changed; review wire format and bump version");
    if (@max(wt_payload_len, @max(webrtc_payload_len, native_payload_len)) + wire.header_len + wire.checksum_len > max_snapshot_bytes)
        @compileError("UDP snapshot exceeds 64 KiB bound");
}

const Writer = struct {
    bytes: []u8,
    pos: usize = 0,

    fn put(self: *Writer, value: []const u8) void {
        std.debug.assert(value.len <= self.bytes.len - self.pos);
        @memcpy(self.bytes[self.pos..][0..value.len], value);
        self.pos += value.len;
    }
    fn int(self: *Writer, comptime T: type, value: T) void {
        var bytes: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &bytes, value, .little);
        self.put(&bytes);
    }
    fn boolean(self: *Writer, value: bool) void {
        self.int(u8, @intFromBool(value));
    }
    fn size(self: *Writer, value: usize) void {
        self.int(u64, @intCast(value));
    }
    fn float(self: *Writer, value: f64) void {
        self.int(u64, @bitCast(value));
    }
    fn zero(self: *Writer, len: usize) void {
        std.debug.assert(len <= self.bytes.len - self.pos);
        @memset(self.bytes[self.pos..][0..len], 0);
        self.pos += len;
    }
};

const Reader = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn take(self: *Reader, len: usize) error{InvalidSnapshot}![]const u8 {
        if (len > self.bytes.len - self.pos) return error.InvalidSnapshot;
        const value = self.bytes[self.pos..][0..len];
        self.pos += len;
        return value;
    }
    fn int(self: *Reader, comptime T: type) error{InvalidSnapshot}!T {
        var bytes: [@sizeOf(T)]u8 = undefined;
        @memcpy(&bytes, try self.take(@sizeOf(T)));
        return std.mem.readInt(T, &bytes, .little);
    }
    fn boolean(self: *Reader) error{InvalidSnapshot}!bool {
        return switch (try self.int(u8)) {
            0 => false,
            1 => true,
            else => error.InvalidSnapshot,
        };
    }
    fn size(self: *Reader) error{InvalidSnapshot}!usize {
        return std.math.cast(usize, try self.int(u64)) orelse error.InvalidSnapshot;
    }
    fn float(self: *Reader) error{InvalidSnapshot}!f64 {
        return @bitCast(try self.int(u64));
    }
    fn bytesArray(self: *Reader, comptime len: usize) error{InvalidSnapshot}![len]u8 {
        var value: [len]u8 = undefined;
        defer std.crypto.secureZero(u8, &value);
        @memcpy(&value, try self.take(len));
        return value;
    }
    fn zero(self: *Reader, len: usize) error{InvalidSnapshot}!void {
        for (try self.take(len)) |byte| if (byte != 0) return error.InvalidSnapshot;
    }
    fn done(self: *const Reader) error{InvalidSnapshot}!void {
        if (self.pos != self.bytes.len) return error.InvalidSnapshot;
    }
};

fn enumByte(comptime E: type, value: u8) error{InvalidSnapshot}!E {
    inline for (@typeInfo(E).@"enum".field_values) |field_value| {
        if (value == field_value) return @enumFromInt(value);
    }
    return error.InvalidSnapshot;
}

fn writeObservation(w: *Writer, value: dualstack_udp.DatagramObservation) void {
    w.int(u64, value.device);
    w.int(u64, value.inode);
    w.int(u16, value.family);
    w.put(&value.address);
    w.int(u16, value.port);
    w.int(u32, value.scope_id);
    w.int(u32, value.flowinfo);
    w.boolean(value.v6only);
}

fn readObservation(r: *Reader) error{InvalidSnapshot}!dualstack_udp.DatagramObservation {
    return .{
        .device = try r.int(u64),
        .inode = try r.int(u64),
        .family = try r.int(u16),
        .address = try r.bytesArray(16),
        .port = try r.int(u16),
        .scope_id = try r.int(u32),
        .flowinfo = try r.int(u32),
        .v6only = try r.boolean(),
    };
}

fn writeDualSocket(w: *Writer, value: dualstack_udp.Snapshot) void {
    writeObservation(w, value.primary);
    w.boolean(value.ipv4 != null);
    if (value.ipv4) |other| writeObservation(w, other) else w.zero(observation_len);
    w.boolean(value.primary_ipv4);
    w.int(u32, value.recv_timeout_ms);
    w.boolean(value.prefer_ipv4);
}

fn readDualSocket(r: *Reader) error{InvalidSnapshot}!dualstack_udp.Snapshot {
    const primary = try readObservation(r);
    const has_ipv4 = try r.boolean();
    const ipv4 = if (has_ipv4) try readObservation(r) else blk: {
        try r.zero(observation_len);
        break :blk null;
    };
    return .{
        .primary = primary,
        .ipv4 = ipv4,
        .primary_ipv4 = try r.boolean(),
        .recv_timeout_ms = try r.int(u32),
        .prefer_ipv4 = try r.boolean(),
    };
}

fn writeMediaSocket(w: *Writer, value: media_socket.Snapshot) void {
    w.int(u64, value.device);
    w.int(u64, value.inode);
    w.int(u32, value.address_be);
    w.int(u16, value.port);
    w.int(u32, value.recv_timeout_ms);
}

fn readMediaSocket(r: *Reader) error{InvalidSnapshot}!media_socket.Snapshot {
    return .{
        .device = try r.int(u64),
        .inode = try r.int(u64),
        .address_be = try r.int(u32),
        .port = try r.int(u16),
        .recv_timeout_ms = try r.int(u32),
    };
}

fn writeAddress(w: *Writer, value: ?ice.TransportAddress) void {
    w.boolean(value != null);
    if (value) |address| {
        w.put(&address.ip);
        w.int(u8, address.ip_len);
        w.int(u16, address.port);
    } else w.zero(address_len);
}

fn readAddress(r: *Reader) error{InvalidSnapshot}!?ice.TransportAddress {
    if (!try r.boolean()) {
        try r.zero(address_len);
        return null;
    }
    return .{ .ip = try r.bytesArray(16), .ip_len = try r.int(u8), .port = try r.int(u16) };
}

fn writeRng(w: *Writer, value: *const webrtc.RngState) void {
    w.put(&value.state);
    w.int(u16, value.offset);
}

fn readRng(r: *Reader) error{InvalidSnapshot}!webrtc.RngState {
    var state: webrtc.RngState = .{ .state = try r.bytesArray(512), .offset = 0 };
    defer std.crypto.secureZero(u8, &state.state);
    state.offset = try r.int(u16);
    return state;
}

fn writeDtls(w: *Writer, value: *const ?webrtc.IdleDtls) void {
    w.boolean(value.* != null);
    if (value.*) |*idle| {
        w.put(&idle.cert_der);
        w.int(u16, idle.cert_len);
        w.put(&idle.secret_key);
        w.put(&idle.public_key);
        w.put(&idle.cookie_secret);
        writeRng(w, &idle.csprng);
        w.int(u64, idle.binding_tick);
        w.boolean(idle.binding_exhausted);
        w.boolean(idle.request_client_cert);
    } else w.zero(dtls_len);
}

fn readDtls(r: *Reader) error{InvalidSnapshot}!?webrtc.IdleDtls {
    if (!try r.boolean()) {
        try r.zero(dtls_len);
        return null;
    }
    var idle: webrtc.IdleDtls = std.mem.zeroes(webrtc.IdleDtls);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&idle));
    idle.cert_der = try r.bytesArray(1024);
    idle.cert_len = try r.int(u16);
    idle.secret_key = try r.bytesArray(32);
    idle.public_key = try r.bytesArray(65);
    idle.cookie_secret = try r.bytesArray(32);
    idle.csprng = try readRng(r);
    idle.binding_tick = try r.int(u64);
    idle.binding_exhausted = try r.boolean();
    idle.request_client_cert = try r.boolean();
    return idle;
}

fn writeRetrySecret(w: *Writer, value: *const ?quic_retry.Secret) void {
    w.boolean(value.* != null);
    if (value.*) |*secret| {
        w.put(&secret.token_key);
        w.put(&secret.reset_key);
    } else w.zero(64);
}

fn readRetrySecret(r: *Reader) error{InvalidSnapshot}!?quic_retry.Secret {
    if (!try r.boolean()) {
        try r.zero(64);
        return null;
    }
    var secret: quic_retry.Secret = std.mem.zeroes(quic_retry.Secret);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&secret));
    secret.token_key = try r.bytesArray(32);
    secret.reset_key = try r.bytesArray(32);
    return secret;
}

fn writeReplay(w: *Writer, value: *const quic_retry.ReplayCache) void {
    for (value.entries) |entry| w.put(&entry);
    for (value.valid) |valid| w.boolean(valid);
    w.size(value.next);
}

fn readReplay(r: *Reader) error{InvalidSnapshot}!quic_retry.ReplayCache {
    var replay: quic_retry.ReplayCache = .{};
    for (&replay.entries) |*entry| entry.* = try r.bytesArray(16);
    for (&replay.valid) |*valid| valid.* = try r.boolean();
    replay.next = try r.size();
    return replay;
}

/// WebTransport validation that does not require the configured TLS identity.
/// The caller must still use Snapshot.validateConfiguration with real TLS.
fn validateWebtransportShape(snapshot: *const webtransport.Snapshot) !void {
    try snapshot.socket.validate();
    if (snapshot.irc_port == 0 or snapshot.max_connections == 0 or
        snapshot.retry_load_threshold == 0 or snapshot.token_replay.next >= quic_retry.ReplayCache.capacity or
        !std.math.isFinite(snapshot.reset_rate_per_s) or snapshot.reset_rate_per_s <= 0 or
        snapshot.reset_burst == 0 or !std.math.isFinite(snapshot.reset_tokens) or
        snapshot.reset_tokens < 0 or snapshot.reset_tokens > @as(f64, @floatFromInt(snapshot.reset_burst)))
        return error.InvalidSnapshot;
    for (snapshot.token_replay.entries, snapshot.token_replay.valid, 0..) |entry, valid, index| {
        if (!valid) {
            for (entry) |byte| if (byte != 0) return error.InvalidSnapshot;
        } else {
            if (snapshot.retry_secret == null) return error.InvalidSnapshot;
            for (snapshot.token_replay.entries[0..index], snapshot.token_replay.valid[0..index]) |prior, used| {
                if (used and std.mem.eql(u8, &entry, &prior)) return error.InvalidSnapshot;
            }
        }
    }
}

/// Wipe and free an encoded snapshot after its authenticated transfer completes.
pub fn freeEncoded(allocator: std.mem.Allocator, bytes: []u8) void {
    std.crypto.secureZero(u8, bytes);
    allocator.free(bytes);
}

pub fn encodeWebtransport(allocator: std.mem.Allocator, snapshot: *const webtransport.Snapshot) ![]u8 {
    try validateWebtransportShape(snapshot);
    const bytes = try wire.create(allocator, wt_magic, wt_payload_len);
    errdefer freeEncoded(allocator, bytes);
    var w = Writer{ .bytes = bytes[wire.header_len .. bytes.len - wire.checksum_len] };
    writeDualSocket(&w, snapshot.socket);
    w.put(&snapshot.tls_digest);
    w.int(u16, snapshot.irc_port);
    w.boolean(snapshot.send_proxy_header);
    w.boolean(snapshot.echo_wt_datagrams);
    w.size(snapshot.max_connections);
    w.int(u8, @intFromEnum(snapshot.retry_policy));
    w.size(snapshot.retry_load_threshold);
    writeRetrySecret(&w, &snapshot.retry_secret);
    writeReplay(&w, &snapshot.token_replay);
    w.int(u64, snapshot.scid_counter);
    w.float(snapshot.reset_tokens);
    w.int(u64, snapshot.reset_last_refill_ns);
    w.float(snapshot.reset_rate_per_s);
    w.int(u32, snapshot.reset_burst);
    w.int(u8, @intFromEnum(snapshot.execution));
    std.debug.assert(w.pos == wt_payload_len);
    wire.finish(bytes, wt_domain);
    return bytes;
}

pub fn decodeWebtransport(bytes: []const u8) !webtransport.Snapshot {
    if (bytes.len > max_snapshot_bytes) return error.InvalidSnapshot;
    const payload = try wire.validateFrame(bytes, wt_magic, wt_domain, wt_payload_len);
    var r = Reader{ .bytes = payload };
    var result: webtransport.Snapshot = std.mem.zeroes(webtransport.Snapshot);
    errdefer std.crypto.secureZero(u8, std.mem.asBytes(&result));
    result.socket = try readDualSocket(&r);
    result.tls_digest = try r.bytesArray(32);
    result.irc_port = try r.int(u16);
    result.send_proxy_header = try r.boolean();
    result.echo_wt_datagrams = try r.boolean();
    result.max_connections = try r.size();
    result.retry_policy = try enumByte(webtransport.RetryPolicy, try r.int(u8));
    result.retry_load_threshold = try r.size();
    result.retry_secret = try readRetrySecret(&r);
    result.token_replay = try readReplay(&r);
    result.scid_counter = try r.int(u64);
    result.reset_tokens = try r.float();
    result.reset_last_refill_ns = try r.int(u64);
    result.reset_rate_per_s = try r.float();
    result.reset_burst = try r.int(u32);
    result.execution = try enumByte(webtransport.Execution, try r.int(u8));
    try r.done();
    try validateWebtransportShape(&result);
    return result;
}

pub fn encodeWebrtc(allocator: std.mem.Allocator, snapshot: *const webrtc.Snapshot) ![]u8 {
    try snapshot.validate();
    const bytes = try wire.create(allocator, webrtc_magic, webrtc_payload_len);
    errdefer freeEncoded(allocator, bytes);
    var w = Writer{ .bytes = bytes[wire.header_len .. bytes.len - wire.checksum_len] };
    writeMediaSocket(&w, snapshot.socket);
    writeRng(&w, &snapshot.csprng);
    writeAddress(&w, snapshot.stun_server);
    writeAddress(&w, snapshot.discovered);
    w.size(snapshot.max_frame_bytes);
    w.int(u64, snapshot.max_upload_bytes);
    w.boolean(snapshot.dtls_enabled);
    w.boolean(snapshot.dtls_requested);
    w.boolean(snapshot.dtls13_enabled);
    w.boolean(snapshot.dtls13_requested);
    writeDtls(&w, &snapshot.dtls12);
    writeDtls(&w, &snapshot.dtls13);
    w.int(u64, snapshot.srtp_clock);
    w.boolean(snapshot.cross_configured);
    w.int(u8, @intFromEnum(snapshot.execution));
    std.debug.assert(w.pos == webrtc_payload_len);
    wire.finish(bytes, webrtc_domain);
    return bytes;
}

pub fn decodeWebrtc(bytes: []const u8) !webrtc.Snapshot {
    if (bytes.len > max_snapshot_bytes) return error.InvalidSnapshot;
    const payload = try wire.validateFrame(bytes, webrtc_magic, webrtc_domain, webrtc_payload_len);
    var r = Reader{ .bytes = payload };
    var result: webrtc.Snapshot = std.mem.zeroes(webrtc.Snapshot);
    errdefer std.crypto.secureZero(u8, std.mem.asBytes(&result));
    result.socket = try readMediaSocket(&r);
    result.csprng = try readRng(&r);
    result.stun_server = try readAddress(&r);
    result.discovered = try readAddress(&r);
    result.max_frame_bytes = try r.size();
    result.max_upload_bytes = try r.int(u64);
    result.dtls_enabled = try r.boolean();
    result.dtls_requested = try r.boolean();
    result.dtls13_enabled = try r.boolean();
    result.dtls13_requested = try r.boolean();
    result.dtls12 = try readDtls(&r);
    result.dtls13 = try readDtls(&r);
    result.srtp_clock = try r.int(u64);
    result.cross_configured = try r.boolean();
    result.execution = try enumByte(webrtc.Execution, try r.int(u8));
    try r.done();
    try result.validate();
    return result;
}

pub fn encodeNative(allocator: std.mem.Allocator, snapshot: *const native.Snapshot) ![]u8 {
    try snapshot.validate();
    const bytes = try wire.create(allocator, native_magic, native_payload_len);
    errdefer freeEncoded(allocator, bytes);
    var w = Writer{ .bytes = bytes[wire.header_len .. bytes.len - wire.checksum_len] };
    writeMediaSocket(&w, snapshot.socket);
    w.size(snapshot.max_frame_bytes);
    w.int(u64, snapshot.max_upload_bytes);
    w.size(snapshot.max_participants);
    w.boolean(snapshot.require_mac);
    w.put(&snapshot.mac_stream_key);
    w.boolean(snapshot.mac_key_configured);
    w.boolean(snapshot.cross_configured);
    w.int(u8, @intFromEnum(snapshot.execution));
    std.debug.assert(w.pos == native_payload_len);
    wire.finish(bytes, native_domain);
    return bytes;
}

pub fn decodeNative(bytes: []const u8) !native.Snapshot {
    if (bytes.len > max_snapshot_bytes) return error.InvalidSnapshot;
    const payload = try wire.validateFrame(bytes, native_magic, native_domain, native_payload_len);
    var r = Reader{ .bytes = payload };
    var result: native.Snapshot = std.mem.zeroes(native.Snapshot);
    errdefer std.crypto.secureZero(u8, std.mem.asBytes(&result));
    result.socket = try readMediaSocket(&r);
    result.max_frame_bytes = try r.size();
    result.max_upload_bytes = try r.int(u64);
    result.max_participants = try r.size();
    result.require_mac = try r.boolean();
    result.mac_stream_key = try r.bytesArray(16);
    result.mac_key_configured = try r.boolean();
    result.cross_configured = try r.boolean();
    result.execution = try enumByte(native.Execution, try r.int(u8));
    try r.done();
    try result.validate();
    return result;
}

test "Windows UDP WebTransport snapshot roundtrip and canonical rejection" {
    var source = webtransport.Snapshot{
        .socket = .{
            .primary = .{ .device = 7, .inode = 9, .family = 2, .address = .{ 127, 0, 0, 1 } ++ @as([12]u8, @splat(0)), .port = 4433, .scope_id = 0, .flowinfo = 0, .v6only = false },
            .ipv4 = null,
            .primary_ipv4 = true,
            .recv_timeout_ms = 100,
            .prefer_ipv4 = true,
        },
        .tls_digest = @splat(0x41),
        .irc_port = 6667,
        .send_proxy_header = true,
        .echo_wt_datagrams = false,
        .max_connections = 256,
        .retry_policy = .always,
        .retry_load_threshold = 128,
        .retry_secret = .{ .token_key = @splat(0x2a), .reset_key = @splat(0x5b) },
        .token_replay = .{},
        .scid_counter = 71,
        .reset_tokens = 3.5,
        .reset_last_refill_ns = 1234,
        .reset_rate_per_s = 100.0,
        .reset_burst = 20,
        .execution = .paused,
    };
    defer source.deinit();
    source.token_replay.entries[0] = @splat(0x33);
    source.token_replay.valid[0] = true;
    source.token_replay.next = 1;
    const bytes = try encodeWebtransport(std.testing.allocator, &source);
    defer freeEncoded(std.testing.allocator, bytes);
    var restored = try decodeWebtransport(bytes);
    defer restored.deinit();
    try std.testing.expectEqualDeep(source, restored);
    try std.testing.expectError(error.InvalidSnapshot, decodeWebtransport(bytes[0 .. bytes.len - 1]));
    var tampered = try std.testing.allocator.dupe(u8, bytes);
    defer freeEncoded(std.testing.allocator, tampered);
    tampered[wire.header_len + dual_socket_len + 32 + 2] = 2;
    try std.testing.expectError(error.InvalidSnapshot, decodeWebtransport(tampered));
    tampered[wire.header_len + dual_socket_len + 32 + 2] = 1;
    tampered[bytes.len - 1] ^= 1;
    try std.testing.expectError(error.InvalidSnapshot, decodeWebtransport(tampered));
}

test "Windows UDP WebRTC and native media snapshots roundtrip" {
    var source = webrtc.Snapshot{
        .socket = .{ .device = 3, .inode = 4, .address_be = media_socket.loopback_be, .port = 5000, .recv_timeout_ms = 100 },
        .csprng = .{ .state = @splat(0x1a), .offset = 0 },
        .stun_server = try ice.TransportAddress.fromBytes(&.{ 1, 2, 3, 4 }, 3478),
        .discovered = try ice.TransportAddress.fromBytes(&.{ 5, 6, 7, 8 }, 5000),
        .max_frame_bytes = 1200,
        .max_upload_bytes = 4567,
        .dtls_enabled = false,
        .dtls_requested = false,
        .dtls13_enabled = false,
        .dtls13_requested = false,
        .dtls12 = null,
        .dtls13 = null,
        .srtp_clock = 88,
        .cross_configured = true,
        .execution = .paused,
    };
    defer source.deinit();
    const bytes = try encodeWebrtc(std.testing.allocator, &source);
    defer freeEncoded(std.testing.allocator, bytes);
    var restored = try decodeWebrtc(bytes);
    defer restored.deinit();
    try std.testing.expectEqualDeep(source, restored);
    try std.testing.expectError(error.InvalidSnapshot, decodeWebrtc(bytes[0 .. bytes.len - 1]));
    var noncanonical = try std.testing.allocator.dupe(u8, bytes);
    defer freeEncoded(std.testing.allocator, noncanonical);
    const absent_dtls = wire.header_len + media_socket_len + rng_len + optional_address_len * 2 + 8 + 8 + 4;
    noncanonical[absent_dtls + 1] = 1;
    wire.finish(noncanonical, webrtc_domain);
    try std.testing.expectError(error.InvalidSnapshot, decodeWebrtc(noncanonical));
    var native_source = native.Snapshot{
        .socket = source.socket,
        .max_frame_bytes = 1200,
        .max_upload_bytes = 4567,
        .max_participants = 8,
        .require_mac = true,
        .mac_stream_key = @splat(0x59),
        .mac_key_configured = true,
        .cross_configured = true,
        .execution = .paused,
    };
    defer native_source.deinit();
    const native_bytes = try encodeNative(std.testing.allocator, &native_source);
    defer freeEncoded(std.testing.allocator, native_bytes);
    var native_restored = try decodeNative(native_bytes);
    defer native_restored.deinit();
    try std.testing.expectEqualDeep(native_source, native_restored);
    try std.testing.expectError(error.InvalidSnapshot, decodeNative(native_bytes[0 .. native_bytes.len - 1]));
    try std.testing.expectError(error.InvalidSnapshot, decodeNative(bytes));
}

test "Windows UDP WebRTC snapshot preserves both idle DTLS secret owners" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var plane = try webrtc.MediaPlane.initFallible(std.testing.allocator);
    defer plane.deinit();
    plane.dtls_enabled = true;
    plane.dtls13_enabled = true;
    try plane.prepareColdResources(std.testing.io, media_socket.loopback_be, 0);
    var source = try plane.captureUnstarted();
    defer source.deinit();
    try std.testing.expect(source.dtls12 != null and source.dtls13 != null);
    const bytes = try encodeWebrtc(std.testing.allocator, &source);
    defer freeEncoded(std.testing.allocator, bytes);
    var restored = try decodeWebrtc(bytes);
    defer restored.deinit();
    try std.testing.expectEqualDeep(source, restored);
}
