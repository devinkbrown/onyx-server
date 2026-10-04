// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-client TLS resume snapshot — the wire format carried across a Helix
//! UPGRADE so an ESTABLISHED TLS connection keeps decrypting/encrypting on the
//! successor (the socket fd survives execve; this carries the crypto state that
//! pairs with it).
//!
//! One snapshot is sealed into a `.tls_session` capsule per carried TLS client;
//! `fd` is the join key back to the matching `.clients` session snapshot. The
//! payload is the adapter-level `TlsConn.ResumeState` (engine + suite + traffic
//! secrets/keys + record sequence numbers + any buffered partial inbound
//! record), plus the connection's not-yet-flushed outbound wire bytes and the
//! mTLS client-cert fingerprint when one was bound.
//!
//! SECURITY: the encoded bytes contain live traffic secrets. They only ever
//! live inside the sealed memfd arena inherited by the successor process —
//! never on disk.
//!
//! Wire format (all integers little-endian):
//!   [i32 fd]
//!   [u8 engine]      1 = TLS 1.3, 2 = TLS 1.2
//!   [u16 suite]
//!   engine 1: [u8 slen][client_app_secret slen][server_app_secret slen]
//!   engine 2: [u8 klen][client key][u8 ivlen][client iv][server key][server iv]
//!   [u64 app_read_seq][u64 app_write_seq]
//!   [u32 len][pending_recv]   partial inbound TLS record buffered at export
//!   [u32 len][pending_out]    queued outbound wire bytes not yet flushed
//!   [u8 len][certfp]          lowercase-hex SHA-256 of the client leaf, or empty
const std = @import("std");

const tls_conn = @import("../tls_conn.zig");
const tls_server = @import("../../crypto/tls_server.zig");
const tls12_server = @import("../../crypto/tls12_server.zig");

pub const Error = error{ Truncated, TrailingBytes, InvalidFlags, BadCertfp, TooLong, BadEngine, BadLength, BadState, UnsupportedVersion };

const engine_tls13: u8 = 1;
const engine_tls12: u8 = 2;

/// Canonical connected-state schema. Live Helix accepts exactly this version.
pub const schema_version: u16 = 3;

const Secret13 = @FieldType(tls_server.Server.ResumeState, "client_app_secret");
const Keys12 = @FieldType(tls12_server.Server.ResumeState, "keys");
const Key12 = @FieldType(@FieldType(Keys12, "client_write"), "key");
const Iv12 = @FieldType(@FieldType(Keys12, "client_write"), "iv");

/// A plain view of one carried TLS connection. Slices borrow the source
/// (encode input) or the decoded buffer (decode output).
pub const Snapshot = struct {
    /// The client's socket fd (inherited across execve) — joins this TLS state
    /// to its `.clients` session snapshot.
    fd: i32 = -1,
    /// The adapter-level resume state (engine, suite, secrets, seqs, pending
    /// inbound bytes).
    state: tls_conn.TlsConn.ResumeState,
    /// Exact queued FIFO: ciphertext TLS records for software TX, application
    /// plaintext for kernel TX. The kernel prefix partitions this stream once;
    /// software deferred plaintext has its separate canonical envelope domain.
    pending_out: []const u8 = &.{},
    /// The bound mTLS client-cert fingerprint (lowercase hex), or empty.
    certfp: []const u8 = &.{},
    /// kTLS TX offload (roadmap 3.1): true when the predecessor had offloaded
    /// server→client encryption to the kernel. The kernel TX state rides the
    /// inherited fd across execve, so the successor re-attaches nothing — it just
    /// resumes sending plaintext (RX + the engine's carried secrets/seqs stay
    /// userspace exactly as for a non-offloaded conn).
    tx_offloaded: bool = false,
    /// kTLS RX offload: true when the predecessor had offloaded client→server
    /// decryption. Same path-A carry: the kernel RX state survives execve on the
    /// inherited fd, so the successor re-attaches nothing and just resumes reading
    /// plaintext from `recv()` (routing it past the userspace TLS engine).
    rx_offloaded: bool = false,
    /// Exact old kernel plaintext prefix; required even when zero.
    kernel_tx_prefix_remaining: u64,
    control_charge: u32 = 0,
    deferred_ciphertext_charge: u64 = 0,
    deferred_plain: []const u8 = &.{},
};

/// Shared validation for encode and decode: canonical state and representation
/// relations are checked before any allocation or successor construction.
pub fn validate(snap: Snapshot) Error!void {
    if (snap.fd < 0) return error.BadState;
    if (snap.pending_out.len > std.math.maxInt(u32) or snap.state.pending_recv.len > std.math.maxInt(u32)) return error.TooLong;
    if (snap.certfp.len != 0) {
        if (snap.certfp.len != 64) return error.BadCertfp;
        for (snap.certfp) |byte| if (!((byte >= '0' and byte <= '9') or (byte >= 'a' and byte <= 'f'))) return error.BadCertfp;
    }
    const st = snap.state;
    tls_conn.validateKernelTxPrefix(snap.tx_offloaded, st.barrier_phase, st.tx_ku_reply_pending, snap.control_charge, snap.kernel_tx_prefix_remaining, snap.pending_out.len) catch return error.BadState;
    tls_conn.validateKernelRxControlPhase(snap.rx_offloaded, st.barrier_phase, if (st.engine == .tls13) st.engine.tls13.ku_prefix_len else 0, st.rx_open_control_type, st.alert_prefix_len) catch return error.BadState;
    if (st.rx_open_control_type != 0 and st.rx_open_control_type != 21 and st.rx_open_control_type != 22) return error.BadState;
    if ((st.alert_prefix_len == 0 and st.alert_prefix_byte != 0) or
        (st.alert_prefix_len != 0 and st.rx_open_control_type != 21) or
        (!st.tx_ku_reply_pending and st.tx_ku_reply_sent != 0) or st.tx_ku_reply_sent > 4) return error.BadState;
    if (!snap.rx_offloaded and (st.rx_open_control_type != 0 or st.alert_prefix_len != 0)) return error.BadState;
    if (snap.rx_offloaded and st.pending_recv.len != 0) return error.BadState;
    if (st.tx_ku_reply_pending and !snap.tx_offloaded) return error.BadState;
    switch (st.engine) {
        .tls13 => |rs| {
            tls_server.Server.validateResumeState(rs) catch return error.BadState;
            if (st.rx_open_control_type == 22 and (rs.ku_prefix_len == 0 or st.alert_prefix_len != 0)) return error.BadState;
            if (snap.tx_offloaded and rs.peer_record_size_limit_raw < 16385) return error.BadState;
            if (snap.rx_offloaded and rs.record_size_limit_negotiated and rs.local_receive_policy != 16385) return error.BadState;
        },
        .tls12 => |rs| {
            tls12_server.Server.validateResumeState(rs) catch return error.BadState;
            if (snap.tx_offloaded or snap.rx_offloaded or st.rx_open_control_type != 0 or st.alert_prefix_len != 0 or st.tx_ku_reply_pending or st.barrier_phase != .none or st.held_record_len != 0 or snap.control_charge != 0 or snap.deferred_plain.len != 0 or snap.deferred_ciphertext_charge != 0) return error.BadState;
        },
    }
    const charge = tls_conn.deferredCiphertextCharge(st.engine, snap.deferred_plain) catch return error.BadState;
    if (charge != snap.deferred_ciphertext_charge or charge > std.math.maxInt(usize) or
        snap.deferred_plain.len > std.math.maxInt(u32) or snap.deferred_plain.len > charge or
        (snap.tx_offloaded and snap.deferred_plain.len != 0)) return error.BadState;
    switch (st.barrier_phase) {
        .none => {
            if (st.held_record_len != 0 or snap.deferred_plain.len != 0) return error.BadState;
            const expected: u32 = if (st.tx_ku_reply_pending) 5 - @as(u32, st.tx_ku_reply_sent) else 0;
            if (snap.control_charge != expected) return error.BadState;
        },
        .userspace_requested_ku_held, .kernel_control_read_held => {
            if (st.engine != .tls13 or st.tx_ku_reply_pending) return error.BadState;
            const expected: u32 = if (snap.tx_offloaded) 5 else 27;
            if (snap.control_charge != 0 and snap.control_charge != expected) return error.BadState;
            if (snap.control_charge == 0 and snap.deferred_plain.len != 0) return error.BadState;
            if (st.barrier_phase == .userspace_requested_ku_held) {
                if (snap.rx_offloaded or st.pending_recv.len < 5 or st.held_record_len < 5 or st.held_record_len > st.pending_recv.len) return error.BadState;
                const wire_len: usize = 5 + @as(usize, std.mem.readInt(u16, st.pending_recv[3..5], .big));
                if (wire_len != st.held_record_len or st.pending_recv[0] != 23 or st.pending_recv[1] != 3 or st.pending_recv[2] != 3) return error.BadState;
            } else if (!snap.rx_offloaded or st.held_record_len != 0 or st.pending_recv.len != 0) return error.BadState;
        },
        .software_tail_ready => {
            if (st.engine != .tls13 or snap.tx_offloaded or st.tx_ku_reply_pending or st.held_record_len != 0 or
                snap.control_charge != 0 or snap.deferred_plain.len == 0) return error.BadState;
        },
    }
}

pub fn encode(allocator: std.mem.Allocator, snap: Snapshot) (Error || std.mem.Allocator.Error)![]u8 {
    try validate(snap);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try appendInt(&out, allocator, i32, snap.fd);
    switch (snap.state.engine) {
        .tls13 => |rs| {
            try out.append(allocator, engine_tls13);
            try appendInt(&out, allocator, u16, rs.suite);
            try out.append(allocator, @intCast(rs.client_app_secret.len));
            try out.appendSlice(allocator, &rs.client_app_secret);
            try out.appendSlice(allocator, &rs.server_app_secret);
            try appendInt(&out, allocator, u64, rs.app_read_seq);
            try appendInt(&out, allocator, u64, rs.app_write_seq);
        },
        .tls12 => |rs| {
            try out.append(allocator, engine_tls12);
            try appendInt(&out, allocator, u16, rs.suite);
            try out.append(allocator, @intCast(rs.keys.client_write.key.len));
            try out.appendSlice(allocator, &rs.keys.client_write.key);
            try out.append(allocator, @intCast(rs.keys.client_write.iv.len));
            try out.appendSlice(allocator, &rs.keys.client_write.iv);
            try out.appendSlice(allocator, &rs.keys.server_write.key);
            try out.appendSlice(allocator, &rs.keys.server_write.iv);
            try appendInt(&out, allocator, u64, rs.app_read_seq);
            try appendInt(&out, allocator, u64, rs.app_write_seq);
        },
    }
    try appendInt(&out, allocator, u32, @intCast(snap.state.pending_recv.len));
    try out.appendSlice(allocator, snap.state.pending_recv);
    try appendInt(&out, allocator, u32, @intCast(snap.pending_out.len));
    try out.appendSlice(allocator, snap.pending_out);
    try out.append(allocator, @intCast(snap.certfp.len));
    try out.appendSlice(allocator, snap.certfp);
    try out.append(allocator, @intFromBool(snap.tx_offloaded));
    try out.append(allocator, @intFromBool(snap.rx_offloaded));
    switch (snap.state.engine) {
        inline else => |rs| {
            try appendInt(&out, allocator, u16, rs.peer_record_size_limit_raw);
            try appendInt(&out, allocator, u16, rs.local_receive_policy);
            try out.append(allocator, @intFromBool(rs.record_size_limit_negotiated));
            try out.append(allocator, @intCast(rs.selected_alpn.len));
            try out.appendSlice(allocator, rs.selected_alpn);
        },
    }
    if (snap.state.engine == .tls13) {
        const rs = snap.state.engine.tls13;
        try out.append(allocator, 48);
        try out.appendSlice(allocator, &rs.exporter_master_secret);
        try out.append(allocator, @intFromBool(rs.exporter_master_secret_ready));
        try out.append(allocator, rs.ku_prefix_len);
        try out.appendSlice(allocator, &rs.ku_prefix);
    }
    try out.appendSlice(allocator, &.{ snap.state.rx_open_control_type, snap.state.alert_prefix_len, snap.state.alert_prefix_byte, @intFromBool(snap.state.tx_ku_reply_pending), snap.state.tx_ku_reply_sent });
    try out.append(allocator, @intFromEnum(snap.state.barrier_phase));
    try appendInt(&out, allocator, u32, snap.state.held_record_len);
    try appendInt(&out, allocator, u64, snap.kernel_tx_prefix_remaining);
    try appendInt(&out, allocator, u32, snap.control_charge);
    try appendInt(&out, allocator, u64, snap.deferred_ciphertext_charge);
    try appendInt(&out, allocator, u32, @intCast(snap.deferred_plain.len));
    try out.appendSlice(allocator, snap.deferred_plain);
    return out.toOwnedSlice(allocator);
}

pub fn decode(bytes: []const u8, version: u16) Error!Snapshot {
    if (version != schema_version) return error.UnsupportedVersion;
    return decodeCurrent(bytes);
}

pub fn decodeCurrent(bytes: []const u8) Error!Snapshot {
    var r = Reader{ .buf = bytes };
    const fd = try r.int(i32);
    const engine = try r.byte();
    const suite = try r.int(u16);
    var state: tls_conn.TlsConn.ResumeState = switch (engine) {
        engine_tls13 => blk: {
            if (try r.byte() != @sizeOf(Secret13)) return error.BadLength;
            var rs: tls_server.Server.ResumeState = undefined;
            rs.suite = suite;
            @memcpy(&rs.client_app_secret, try r.take(48));
            @memcpy(&rs.server_app_secret, try r.take(48));
            rs.app_read_seq = try r.int(u64);
            rs.app_write_seq = try r.int(u64);
            break :blk .{ .barrier_phase = .none, .held_record_len = 0, .engine = .{ .tls13 = rs } };
        },
        engine_tls12 => blk: {
            if (try r.byte() != @sizeOf(Key12)) return error.BadLength;
            var rs: tls12_server.Server.ResumeState = undefined;
            rs.suite = suite;
            @memcpy(&rs.keys.client_write.key, try r.take(32));
            if (try r.byte() != @sizeOf(Iv12)) return error.BadLength;
            @memcpy(&rs.keys.client_write.iv, try r.take(12));
            @memcpy(&rs.keys.server_write.key, try r.take(32));
            @memcpy(&rs.keys.server_write.iv, try r.take(12));
            rs.app_read_seq = try r.int(u64);
            rs.app_write_seq = try r.int(u64);
            break :blk .{ .barrier_phase = .none, .held_record_len = 0, .engine = .{ .tls12 = rs } };
        },
        else => return error.BadEngine,
    };
    state.pending_recv = try r.take(try r.int(u32));
    const pending_out = try r.take(try r.int(u32));
    const certfp = try r.take(try r.byte());
    const tx = try r.boolean();
    const rx = try r.boolean();
    switch (state.engine) {
        inline else => |*rs| {
            rs.peer_record_size_limit_raw = try r.int(u16);
            rs.local_receive_policy = try r.int(u16);
            rs.record_size_limit_negotiated = try r.boolean();
            rs.selected_alpn = try r.take(try r.byte());
        },
    }
    if (state.engine == .tls13) {
        const rs = &state.engine.tls13;
        if (try r.byte() != 48) return error.BadLength;
        @memcpy(&rs.exporter_master_secret, try r.take(48));
        rs.exporter_master_secret_ready = try r.boolean();
        const prefix_len = try r.byte();
        if (prefix_len > 4) return error.BadLength;
        rs.ku_prefix_len = @intCast(prefix_len);
        @memcpy(&rs.ku_prefix, try r.take(4));
    }
    state.rx_open_control_type = try r.byte();
    const alert_len = try r.byte();
    if (alert_len > 1) return error.BadLength;
    state.alert_prefix_len = @intCast(alert_len);
    state.alert_prefix_byte = try r.byte();
    state.tx_ku_reply_pending = try r.boolean();
    const reply_sent = try r.byte();
    if (reply_sent > 4) return error.BadLength;
    state.tx_ku_reply_sent = @intCast(reply_sent);
    state.barrier_phase = std.enums.fromInt(tls_conn.ControlBarrierPhase, try r.byte()) orelse return error.BadState;
    state.held_record_len = try r.int(u32);
    const kernel_prefix = try r.int(u64);
    const control_charge = try r.int(u32);
    const deferred_charge = try r.int(u64);
    const deferred_plain = try r.take(try r.int(u32));
    if (r.pos != bytes.len) return error.TrailingBytes;
    const snap: Snapshot = .{ .kernel_tx_prefix_remaining = kernel_prefix, .fd = fd, .state = state, .pending_out = pending_out, .certfp = certfp, .tx_offloaded = tx, .rx_offloaded = rx, .control_charge = control_charge, .deferred_ciphertext_charge = deferred_charge, .deferred_plain = deferred_plain };
    try validate(snap);
    return snap;
}

fn appendInt(out: *std.ArrayList(u8), allocator: std.mem.Allocator, comptime T: type, value: T) std.mem.Allocator.Error!void {
    var le: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &le, value, .little);
    try out.appendSlice(allocator, &le);
}

const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn boolean(self: *Reader) Error!bool {
        const value = try self.byte();
        if (value > 1) return error.InvalidFlags;
        return value == 1;
    }
    fn byte(self: *Reader) Error!u8 {
        if (self.pos + 1 > self.buf.len) return error.Truncated;
        defer self.pos += 1;
        return self.buf[self.pos];
    }
    fn int(self: *Reader, comptime T: type) Error!T {
        if (self.pos + @sizeOf(T) > self.buf.len) return error.Truncated;
        defer self.pos += @sizeOf(T);
        return std.mem.readInt(T, self.buf[self.pos..][0..@sizeOf(T)], .little);
    }
    fn take(self: *Reader, n: usize) Error![]const u8 {
        if (self.pos + n > self.buf.len) return error.Truncated;
        defer self.pos += n;
        return self.buf[self.pos .. self.pos + n];
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "tls13 snapshot round-trips fd, suite, secrets, seqs, pending + certfp" {
    const allocator = testing.allocator;
    var s13 = tls_server.Server.ResumeState{ .suite = 0x1302, .client_app_secret = undefined, .server_app_secret = undefined, .app_read_seq = 7, .app_write_seq = 9, .peer_record_size_limit_raw = 16385, .local_receive_policy = 16385, .record_size_limit_negotiated = false, .selected_alpn = &.{}, .exporter_master_secret = @splat(0), .exporter_master_secret_ready = true, .ku_prefix_len = 0, .ku_prefix = @splat(0) };
    for (&s13.client_app_secret, 0..) |*b, i| b.* = @truncate(i);
    for (&s13.server_app_secret, 0..) |*b, i| b.* = @truncate(0x80 + i);

    const bytes = try encode(allocator, .{
        .kernel_tx_prefix_remaining = 0,
        .fd = 42,
        .state = .{ .barrier_phase = .none, .held_record_len = 0, .engine = .{ .tls13 = s13 }, .pending_recv = "\x17\x03\x03" },
        .pending_out = "queued-record",
        .certfp = &repeatBytes("ab", 32),
        .tx_offloaded = true,
        .rx_offloaded = false,
    });
    defer allocator.free(bytes);

    const got = try decode(bytes, schema_version);
    try testing.expectEqual(@as(i32, 42), got.fd);
    const g13 = got.state.engine.tls13;
    try testing.expectEqual(@as(u16, 0x1302), g13.suite);
    try testing.expectEqualSlices(u8, &s13.client_app_secret, &g13.client_app_secret);
    try testing.expectEqualSlices(u8, &s13.server_app_secret, &g13.server_app_secret);
    try testing.expectEqual(@as(u64, 7), g13.app_read_seq);
    try testing.expectEqual(@as(u64, 9), g13.app_write_seq);
    try testing.expectEqualStrings("\x17\x03\x03", got.state.pending_recv);
    try testing.expectEqualStrings("queued-record", got.pending_out);
    try testing.expectEqualStrings(&repeatBytes("ab", 32), got.certfp);
    try testing.expect(got.tx_offloaded);
    try testing.expect(!got.rx_offloaded);

    try testing.expectError(error.UnsupportedVersion, decode(bytes, 1));
    try testing.expectError(error.UnsupportedVersion, decode(bytes, 2));
}

test "tls12 snapshot round-trips key material and seqs" {
    const allocator = testing.allocator;
    var s12 = tls12_server.Server.ResumeState{
        .suite = 0xcca9,
        .keys = .{},
        .app_read_seq = 3,
        .app_write_seq = 4,
        .peer_record_size_limit_raw = 16384,
        .local_receive_policy = 16384,
        .record_size_limit_negotiated = false,
        .selected_alpn = &.{},
    };
    for (&s12.keys.client_write.key, 0..) |*b, i| b.* = @truncate(i + 1);
    for (&s12.keys.client_write.iv, 0..) |*b, i| b.* = @truncate(i + 2);
    for (&s12.keys.server_write.key, 0..) |*b, i| b.* = @truncate(i + 3);
    for (&s12.keys.server_write.iv, 0..) |*b, i| b.* = @truncate(i + 4);

    const bytes = try encode(allocator, .{
        .kernel_tx_prefix_remaining = 0,
        .fd = 7,
        .state = .{ .barrier_phase = .none, .held_record_len = 0, .engine = .{ .tls12 = s12 } },
    });
    defer allocator.free(bytes);

    const got = try decode(bytes, schema_version);
    try testing.expectEqual(@as(i32, 7), got.fd);
    const g12 = got.state.engine.tls12;
    try testing.expectEqual(@as(u16, 0xcca9), g12.suite);
    try testing.expectEqualSlices(u8, &s12.keys.client_write.key, &g12.keys.client_write.key);
    try testing.expectEqualSlices(u8, &s12.keys.client_write.iv, &g12.keys.client_write.iv);
    try testing.expectEqualSlices(u8, &s12.keys.server_write.key, &g12.keys.server_write.key);
    try testing.expectEqualSlices(u8, &s12.keys.server_write.iv, &g12.keys.server_write.iv);
    try testing.expectEqual(@as(u64, 3), g12.app_read_seq);
    try testing.expectEqual(@as(u64, 4), g12.app_write_seq);
    try testing.expectEqual(@as(usize, 0), got.pending_out.len);
    try testing.expectEqual(@as(usize, 0), got.certfp.len);
}

test "decode rejects truncation, unknown engines, and unknown versions" {
    const allocator = testing.allocator;
    try testing.expectError(error.Truncated, decode(&[_]u8{ 1, 0, 0 }, schema_version));
    // fd(4) + engine byte 9 = unknown.
    try testing.expectError(error.BadEngine, decode(&[_]u8{ 1, 0, 0, 0, 9, 0x01, 0x13 }, schema_version));
    // A full, valid v2 blob decoded under a too-new (or zero) version reaches the
    // version switch and is rejected fail-closed — a layout this binary cannot
    // parse.
    const s13 = tls_server.Server.ResumeState{ .suite = 0x1302, .client_app_secret = @splat(1), .server_app_secret = @splat(2), .app_read_seq = 0, .app_write_seq = 0, .peer_record_size_limit_raw = 16385, .local_receive_policy = 16385, .record_size_limit_negotiated = false, .selected_alpn = &.{}, .exporter_master_secret = @splat(0), .exporter_master_secret_ready = true, .ku_prefix_len = 0, .ku_prefix = @splat(0) };
    const bytes = try encode(allocator, .{ .kernel_tx_prefix_remaining = 0, .fd = 5, .state = .{ .barrier_phase = .none, .held_record_len = 0, .engine = .{ .tls13 = s13 } } });
    defer allocator.free(bytes);
    try testing.expectError(error.UnsupportedVersion, decode(bytes, schema_version + 1));
    try testing.expectError(error.UnsupportedVersion, decode(bytes, 0));
}

test "current decode requires canonical flags fingerprint and exact EOF" {
    const allocator = testing.allocator;
    const s13 = tls_server.Server.ResumeState{ .suite = 0x1302, .client_app_secret = @splat(1), .server_app_secret = @splat(2), .app_read_seq = 1, .app_write_seq = 2, .peer_record_size_limit_raw = 16385, .local_receive_policy = 16385, .record_size_limit_negotiated = false, .selected_alpn = &.{}, .exporter_master_secret = @splat(0), .exporter_master_secret_ready = true, .ku_prefix_len = 0, .ku_prefix = @splat(0) };
    const bytes = try encode(allocator, .{
        .kernel_tx_prefix_remaining = 0,
        .fd = 17,
        .state = .{ .barrier_phase = .none, .held_record_len = 0, .engine = .{ .tls13 = s13 } },
        .certfp = &repeatBytes("ab", 32),
    });
    defer allocator.free(bytes);
    _ = try decodeCurrent(bytes);
    try testing.expectError(error.Truncated, decodeCurrent(bytes[0 .. bytes.len - 1]));

    const trailing = try allocator.alloc(u8, bytes.len + 1);
    defer allocator.free(trailing);
    @memcpy(trailing[0..bytes.len], bytes);
    trailing[bytes.len] = 0;
    try testing.expectError(error.TrailingBytes, decodeCurrent(trailing));

    const bad_flag = try allocator.dupe(u8, bytes);
    defer allocator.free(bad_flag);
    bad_flag[193] = 2;
    try testing.expectError(error.InvalidFlags, decodeCurrent(bad_flag));

    const bad_certfp = try allocator.dupe(u8, bytes);
    defer allocator.free(bad_certfp);
    bad_certfp[129] = 'A';
    try testing.expectError(error.BadCertfp, decodeCurrent(bad_certfp));
}

fn repeatBytes(comptime s: []const u8, comptime n: usize) [s.len * n]u8 {
    var b: [s.len * n]u8 = undefined;
    for (0..n) |i| @memcpy(b[i * s.len ..][0..s.len], s);
    return b;
}

test "TLS3: canonical mandatory minimum every prefix and inactive suite tails" {
    const a = testing.allocator;
    const s13: tls_server.Server.ResumeState = .{
        .suite = 0x1301,
        .client_app_secret = @splat(0),
        .server_app_secret = @splat(0),
        .exporter_master_secret = @splat(0),
        .exporter_master_secret_ready = true,
        .app_read_seq = std.math.maxInt(u64),
        .app_write_seq = std.math.maxInt(u64),
        .peer_record_size_limit_raw = 16385,
        .local_receive_policy = 16385,
        .record_size_limit_negotiated = false,
        .selected_alpn = &.{},
        .ku_prefix_len = 0,
        .ku_prefix = @splat(0),
    };
    const s12: tls12_server.Server.ResumeState = .{
        .suite = 0xc02b,
        .keys = .{},
        .app_read_seq = std.math.maxInt(u64),
        .app_write_seq = std.math.maxInt(u64),
        .peer_record_size_limit_raw = 16384,
        .local_receive_policy = 16384,
        .record_size_limit_negotiated = false,
        .selected_alpn = &.{},
    };
    for ([_]tls_conn.TlsConn.ResumeState.EngineState{ .{ .tls13 = s13 }, .{ .tls12 = s12 } }) |engine| {
        const snap: Snapshot = .{ .kernel_tx_prefix_remaining = 0, .fd = 17, .state = .{ .engine = engine, .barrier_phase = .none, .held_record_len = 0 } };
        const wire = try encode(a, snap);
        defer a.free(wire);
        try testing.expectEqual(@as(usize, if (engine == .tls13) 226 else 164), wire.len);
        for (0..wire.len) |n| {
            if (decodeCurrent(wire[0..n])) |_| return error.TestUnexpectedResult else |_| {}
        }
        _ = try decodeCurrent(wire);
        var bad = snap;
        if (engine == .tls13) bad.state.engine.tls13.client_app_secret[32] = 1 else bad.state.engine.tls12.keys.client_write.key[16] = 1;
        try testing.expectError(error.BadState, validate(bad));
        bad = snap;
        if (engine == .tls13) bad.state.engine.tls13.exporter_master_secret_ready = false else bad.state.engine.tls12.keys.client_write.iv[4] = 1;
        try testing.expectError(error.BadState, validate(bad));
        // Missing control extension and unknown phase never decode as defaults.
        try testing.expectError(error.Truncated, decodeCurrent(wire[0 .. wire.len - 29]));
        const changed = try a.dupe(u8, wire);
        defer a.free(changed);
        changed[wire.len - 29] = 4;
        try testing.expectError(error.BadState, decodeCurrent(changed));
    }
}

test "TLS3: typed tail charge control modes and cursor relations refuse tampering" {
    const a = testing.allocator;
    const s13: tls_server.Server.ResumeState = .{
        .suite = 0x1302,
        .client_app_secret = @splat(1),
        .server_app_secret = @splat(2),
        .exporter_master_secret = @splat(3),
        .exporter_master_secret_ready = true,
        .app_read_seq = 1,
        .app_write_seq = 2,
        .peer_record_size_limit_raw = 65535,
        .local_receive_policy = 64,
        .record_size_limit_negotiated = true,
        .selected_alpn = "irc",
        .ku_prefix_len = 0,
        .ku_prefix = @splat(0),
    };
    const tail = "\x03\x00\x00\x00one\x03\x00\x00\x00two";
    const snap: Snapshot = .{
        .kernel_tx_prefix_remaining = 0,
        .fd = 23,
        .state = .{ .engine = .{ .tls13 = s13 }, .barrier_phase = .software_tail_ready, .held_record_len = 0 },
        .deferred_plain = tail,
        .deferred_ciphertext_charge = 50,
    };
    const wire = try encode(a, snap);
    defer a.free(wire);
    const decoded = try decodeCurrent(wire);
    try testing.expectEqual(@as(u16, 65535), decoded.state.engine.tls13.peer_record_size_limit_raw);
    try testing.expectEqual(@as(u16, 64), decoded.state.engine.tls13.local_receive_policy);
    try testing.expectEqualStrings("irc", decoded.state.engine.tls13.selected_alpn);
    try testing.expectEqualSlices(u8, tail, decoded.deferred_plain);
    for (0..wire.len) |n| if (decodeCurrent(wire[0..n])) |_| return error.TestUnexpectedResult else |_| {};
    for (0..8) |which| {
        var bad = snap;
        switch (which) {
            0 => bad.deferred_ciphertext_charge += 1,
            1 => bad.deferred_plain = "\x00\x00\x00\x00",
            2 => bad.control_charge = 27,
            3 => bad.tx_offloaded = true,
            4 => bad.rx_offloaded = true,
            5 => bad.state.barrier_phase = .none,
            6 => bad.state.tx_ku_reply_pending = true,
            7 => bad.state.rx_open_control_type = 22,
            else => unreachable,
        }
        try testing.expectError(error.BadState, validate(bad));
    }
}

test "TLS3: required kernel prefix cursor rejects wrong phase domain funding and missing old shape" {
    const a = testing.allocator;
    const rs: tls_server.Server.ResumeState = .{
        .suite = 0x1302,
        .client_app_secret = @splat(1),
        .server_app_secret = @splat(2),
        .exporter_master_secret = @splat(3),
        .exporter_master_secret_ready = true,
        .app_read_seq = 0,
        .app_write_seq = 0,
        .peer_record_size_limit_raw = 16385,
        .local_receive_policy = 16385,
        .record_size_limit_negotiated = true,
        .selected_alpn = &.{},
        .ku_prefix_len = 0,
        .ku_prefix = @splat(0),
    };
    const snap: Snapshot = .{
        .fd = 11,
        .state = .{ .engine = .{ .tls13 = rs }, .barrier_phase = .kernel_control_read_held, .held_record_len = 0 },
        .tx_offloaded = true,
        .rx_offloaded = true,
        .pending_out = "oldnewsuffix",
        .kernel_tx_prefix_remaining = 3,
        .control_charge = 5,
    };
    const wire = try encode(a, snap);
    defer a.free(wire);
    const restored = try decodeCurrent(wire);
    try testing.expectEqual(@as(u64, 3), restored.kernel_tx_prefix_remaining);
    try testing.expectEqualStrings("oldnewsuffix", restored.pending_out);
    for (0..7) |which| {
        var bad = snap;
        switch (which) {
            0 => bad.kernel_tx_prefix_remaining = snap.pending_out.len + 1,
            1 => bad.control_charge = 0, // unfunded hold cannot contain a suffix
            2 => bad.tx_offloaded = false,
            3 => bad.state.barrier_phase = .none,
            4 => {
                bad.state.tx_ku_reply_pending = true;
                bad.state.barrier_phase = .none;
            },
            5 => bad.state.barrier_phase = .software_tail_ready,
            6 => bad.rx_offloaded = false,
            else => unreachable,
        }
        try testing.expectError(error.BadState, validate(bad));
    }
    var unfunded = snap;
    unfunded.control_charge = 0;
    unfunded.kernel_tx_prefix_remaining = snap.pending_out.len;
    try validate(unfunded);
    var pending = snap;
    pending.state.barrier_phase = .none;
    pending.state.tx_ku_reply_pending = true;
    pending.state.tx_ku_reply_sent = 3;
    pending.control_charge = 2;
    pending.kernel_tx_prefix_remaining = 0;
    try validate(pending);
    pending.kernel_tx_prefix_remaining = 1;
    try testing.expectError(error.BadState, validate(pending));
    // Delete the mandatory eight-byte cursor from the earlier provisional v3
    // layout. Exact current decode must not infer zero or accept that shape.
    const extension = wire.len - 29;
    const omitted = try std.mem.concat(a, u8, &.{ wire[0 .. extension + 5], wire[extension + 13 ..] });
    defer a.free(omitted);
    if (decodeCurrent(omitted)) |_| return error.TestUnexpectedResult else |_| {}
}

test "TLS3: kernel RX partial control requires phase2 and cannot overlap reply or ready tail" {
    const a = testing.allocator;
    for (0..3) |which| {
        const rs: tls_server.Server.ResumeState = .{
            .suite = 0x1302,
            .client_app_secret = @splat(1),
            .server_app_secret = @splat(2),
            .exporter_master_secret = @splat(3),
            .exporter_master_secret_ready = true,
            .app_read_seq = 1,
            .app_write_seq = 2,
            .peer_record_size_limit_raw = 16385,
            .local_receive_policy = 16385,
            .record_size_limit_negotiated = true,
            .selected_alpn = &.{},
            .ku_prefix_len = if (which < 2) 1 else 0,
            .ku_prefix = if (which < 2) .{ 24, 0, 0, 0 } else @splat(0),
        };
        const valid: Snapshot = .{
            .fd = 11,
            .kernel_tx_prefix_remaining = 0,
            .rx_offloaded = true,
            .state = .{
                .engine = .{ .tls13 = rs },
                .barrier_phase = .kernel_control_read_held,
                .held_record_len = 0,
                .rx_open_control_type = switch (which) {
                    0 => 0,
                    1 => 22,
                    else => 21,
                },
                .alert_prefix_len = if (which == 2) 1 else 0,
                .alert_prefix_byte = if (which == 2) 2 else 0,
            },
        };
        const original = try encode(a, valid);
        defer a.free(original);
        _ = try decodeCurrent(original);
        var bad = valid;
        bad.state.barrier_phase = .none;
        try testing.expectError(error.BadState, validate(bad));
        const wire = try a.dupe(u8, original);
        defer a.free(wire);
        wire[wire.len - 29] = @intFromEnum(tls_conn.ControlBarrierPhase.none);
        try testing.expectError(error.BadState, decodeCurrent(wire));
        bad.tx_offloaded = true;
        bad.state.tx_ku_reply_pending = true;
        bad.control_charge = 5;
        try testing.expectError(error.BadState, validate(bad));
        bad = valid;
        bad.state.barrier_phase = .software_tail_ready;
        bad.deferred_plain = "\x01\x00\x00\x00x";
        bad.deferred_ciphertext_charge = 23;
        try testing.expectError(error.BadState, validate(bad));
        if (which < 2) {
            // Software RX may retain a complete-record KU prefix without a
            // caller pre-read barrier, and must remain a supported current cut.
            var software = valid;
            software.rx_offloaded = false;
            software.state.barrier_phase = .none;
            software.state.rx_open_control_type = 0;
            const accepted = try encode(a, software);
            defer a.free(accepted);
            _ = try decodeCurrent(accepted);
        }
    }
}
