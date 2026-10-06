// SPDX-License-Identifier: AGPL-3.0-or-later
//! Authenticated custody of the loopback history HTTPS listener on Windows.
//! The frame pins the bound endpoint and complete TLS material digest; the
//! candidate supplies its own TLS config and Server-owned Reader after import.
const std = @import("std");
const builtin = @import("builtin");
const history_http = @import("../history_http.zig");
const tls_server = @import("../../crypto/tls_server.zig");
const tls_resumption = @import("../../crypto/tls_resumption.zig");
const metrics_http = @import("../metrics_http.zig");
const runtime_pause = @import("../runtime_pause.zig");
const socket_mod = @import("native_windows_socket.zig");
pub const material = @import("native_windows_history_material.zig");

const frame_magic = "HXHH";
const version: u16 = 4;
const header_len: usize = 104;
const runtime_len: usize = 24;
const socket_offset: usize = header_len + runtime_len;
pub const frame_len: usize = socket_offset + @sizeOf(socket_mod.ProtocolInfo);
pub const Frame = [frame_len]u8;
const invalid_socket = std.math.maxInt(usize);

comptime {
    if (frame_len > @import("native_windows_control.zig").max_body or
        header_len != 4 + 2 + 2 + 4 + 4 + 8 + 8 + 2 + 2 + 16 + 4 + 4 + 8 + 32 + 1 + 3)
        @compileError("Windows history custody frame exceeds its fixed bounds");
}

extern "kernel32" fn GetProcessId(handle: usize) callconv(.winapi) u32;
extern "kernel32" fn GetCurrentProcess() callconv(.winapi) usize;
extern "kernel32" fn GetCurrentProcessId() callconv(.winapi) u32;

pub const Error = socket_mod.Error || error{ InvalidFrame, InvalidSnapshot, InvalidTarget };

pub const Source = struct {
    owner: *history_http.HttpsListener,
    carry: *const history_http.Snapshot,
    pause_token: runtime_pause.Token,
};

pub const Prepared = struct {
    body: Frame,

    pub fn deinit(self: *Prepared) void {
        std.crypto.secureZero(u8, &self.body);
    }
};

pub const Received = struct {
    carry: history_http.Snapshot,
    runtime_tls: RuntimeTls,
    transfer: socket_mod.Transfer,

    pub fn tlsConfig(self: *const Received, base: tls_server.Config, guard: ?*tls_resumption.ReplayGuard) Error!tls_server.Config {
        return self.runtime_tls.apply(base, guard);
    }

    pub fn deinit(self: *Received) void {
        std.crypto.secureZero(u8, std.mem.asBytes(&self.runtime_tls));
        std.crypto.secureZero(u8, std.mem.asBytes(&self.transfer.info));
        self.transfer.consumed = true;
    }
};

/// The source history listener owns a pinned copy of this policy. HXHL carries
/// its ticket keys in the encrypted arena; this control frame carries their
/// presence only and checks that candidate material has the same shape.
pub const RuntimeTls = struct {
    flags: u16,
    receive_record_size_limit: u16,
    ticket_lifetime_seconds: u32,
    max_early_data_size: u32,
    early_data_age_skew_ms: u32,
    now_unix_seconds: i64,

    const tickets: u16 = 1 << 0;
    const compression: u16 = 1 << 1;
    const enforce_signatures: u16 = 1 << 2;
    const client_cert: u16 = 1 << 3;
    const current_key: u16 = 1 << 4;
    const previous_key: u16 = 1 << 5;
    const clock: u16 = 1 << 6;
    const replay: u16 = 1 << 7;
    const raw_public_key: u16 = 1 << 8;
    const known_flags: u16 = (1 << 9) - 1;

    fn fromConfig(config: *const tls_server.Config) RuntimeTls {
        var result = std.mem.zeroes(RuntimeTls);
        if (config.enable_session_tickets) result.flags |= tickets;
        if (config.enable_cert_compression) result.flags |= compression;
        if (config.enforce_cert_signature_algorithms) result.flags |= enforce_signatures;
        if (config.request_client_cert) result.flags |= client_cert;
        if (config.ticket_key != null) result.flags |= current_key;
        if (config.previous_ticket_key != null) result.flags |= previous_key;
        if (config.now_unix_seconds) |now| {
            result.flags |= clock;
            result.now_unix_seconds = now;
        }
        if (config.replay_guard != null) result.flags |= replay;
        if (config.enable_raw_public_key) result.flags |= raw_public_key;
        result.receive_record_size_limit = config.receive_record_size_limit;
        result.ticket_lifetime_seconds = config.ticket_lifetime_seconds;
        result.max_early_data_size = config.max_early_data_size;
        result.early_data_age_skew_ms = config.early_data_age_skew_ms;
        return result;
    }

    fn apply(self: *const RuntimeTls, base: tls_server.Config, guard: ?*tls_resumption.ReplayGuard) Error!tls_server.Config {
        if (self.flags & ~known_flags != 0 or
            (base.ticket_key != null) != (self.flags & current_key != 0) or
            (base.previous_ticket_key != null) != (self.flags & previous_key != 0) or
            (self.flags & replay != 0 and guard == null) or
            (self.max_early_data_size != 0 and (self.flags & (tickets | current_key | clock | replay)) !=
                (tickets | current_key | clock | replay))) return error.InvalidFrame;
        var cfg = base;
        cfg.receive_record_size_limit = self.receive_record_size_limit;
        cfg.enable_session_tickets = self.flags & tickets != 0;
        cfg.enable_cert_compression = self.flags & compression != 0;
        cfg.enforce_cert_signature_algorithms = self.flags & enforce_signatures != 0;
        cfg.request_client_cert = self.flags & client_cert != 0;
        cfg.now_unix_seconds = if (self.flags & clock != 0) self.now_unix_seconds else null;
        cfg.replay_guard = if (self.flags & replay != 0) guard else null;
        cfg.enable_raw_public_key = self.flags & raw_public_key != 0;
        cfg.ticket_lifetime_seconds = self.ticket_lifetime_seconds;
        cfg.max_early_data_size = self.max_early_data_size;
        cfg.early_data_age_skew_ms = self.early_data_age_skew_ms;
        return cfg;
    }
};

pub fn absentFrame() Frame {
    var body: Frame = @splat(0);
    @memcpy(body[0..4], frame_magic);
    std.mem.writeInt(u16, body[4..6], version, .big);
    return body;
}

fn presentFrame(carry: *const history_http.Snapshot, config: *const tls_server.Config, target_pid: u32, info: *const socket_mod.ProtocolInfo) Frame {
    var body = absentFrame();
    const runtime = RuntimeTls.fromConfig(config);
    std.mem.writeInt(u16, body[6..8], 1, .big);
    std.mem.writeInt(u32, body[8..12], target_pid, .big);
    std.mem.writeInt(u64, body[16..24], carry.listener.device, .big);
    std.mem.writeInt(u64, body[24..32], carry.listener.inode, .big);
    std.mem.writeInt(u16, body[32..34], carry.listener.family, .big);
    std.mem.writeInt(u16, body[34..36], carry.listener.port, .big);
    @memcpy(body[36..52], &carry.listener.address);
    std.mem.writeInt(u32, body[52..56], carry.listener.scope_id, .big);
    std.mem.writeInt(u32, body[56..60], carry.listener.flow_info, .big);
    std.mem.writeInt(u64, body[60..68], carry.listener.recv_timeout_us, .big);
    @memcpy(body[68..100], &carry.tls_digest);
    body[100] = @intFromEnum(carry.execution);
    std.mem.writeInt(u16, body[104..106], runtime.flags, .big);
    std.mem.writeInt(u16, body[106..108], runtime.receive_record_size_limit, .big);
    std.mem.writeInt(u32, body[108..112], runtime.ticket_lifetime_seconds, .big);
    std.mem.writeInt(u32, body[112..116], runtime.max_early_data_size, .big);
    std.mem.writeInt(u32, body[116..120], runtime.early_data_age_skew_ms, .big);
    std.mem.writeInt(i64, body[120..128], runtime.now_unix_seconds, .big);
    @memcpy(body[socket_offset..], std.mem.asBytes(info));
    return body;
}

fn parseRuntime(bytes: []const u8) Error!RuntimeTls {
    const flags = std.mem.readInt(u16, bytes[104..106], .big);
    if (flags & ~RuntimeTls.known_flags != 0) return error.InvalidFrame;
    var runtime = RuntimeTls{
        .flags = flags,
        .receive_record_size_limit = std.mem.readInt(u16, bytes[106..108], .big),
        .ticket_lifetime_seconds = std.mem.readInt(u32, bytes[108..112], .big),
        .max_early_data_size = std.mem.readInt(u32, bytes[112..116], .big),
        .early_data_age_skew_ms = std.mem.readInt(u32, bytes[116..120], .big),
        .now_unix_seconds = std.mem.readInt(i64, bytes[120..128], .big),
    };
    errdefer std.crypto.secureZero(u8, std.mem.asBytes(&runtime));
    if ((flags & RuntimeTls.clock == 0 and runtime.now_unix_seconds != 0) or
        (runtime.max_early_data_size != 0 and
            (flags & (RuntimeTls.tickets | RuntimeTls.current_key | RuntimeTls.clock | RuntimeTls.replay)) !=
                (RuntimeTls.tickets | RuntimeTls.current_key | RuntimeTls.clock | RuntimeTls.replay)))
        return error.InvalidFrame;
    return runtime;
}

fn validListener(listener: metrics_http.ListenerObservation) bool {
    if (listener.device != 0 or listener.inode == invalid_socket or listener.port == 0 or
        listener.scope_id != 0 or listener.flow_info != 0 or
        listener.recv_timeout_us < 200_000 or listener.recv_timeout_us > 210_000) return false;
    var expected: [16]u8 = @splat(0);
    switch (listener.family) {
        2 => @memcpy(expected[0..4], &[_]u8{ 127, 0, 0, 1 }),
        23 => expected[15] = 1,
        else => return false,
    }
    return std.mem.eql(u8, &listener.address, &expected);
}

/// Parse only the authenticated fixed frame; no SOCKET is imported here.
/// The candidate validates the TLS digest again against its actual config.
pub fn parseFrame(bytes: []const u8, target_pid: u32) Error!?Received {
    if (bytes.len != frame_len or !std.mem.eql(u8, bytes[0..4], frame_magic) or
        std.mem.readInt(u16, bytes[4..6], .big) != version or
        std.mem.readInt(u32, bytes[12..16], .big) != 0) return error.InvalidFrame;
    const presence = std.mem.readInt(u16, bytes[6..8], .big);
    if (presence == 0) {
        const canonical = absentFrame();
        if (!std.mem.eql(u8, bytes, &canonical)) return error.InvalidFrame;
        return null;
    }
    if (presence != 1 or target_pid == 0 or std.mem.readInt(u32, bytes[8..12], .big) != target_pid or
        bytes[100] != @intFromEnum(history_http.Execution.paused) or
        !std.mem.eql(u8, bytes[101..104], &[_]u8{ 0, 0, 0 })) return error.InvalidFrame;
    const carry = history_http.Snapshot{
        .listener = .{
            .device = std.mem.readInt(u64, bytes[16..24], .big),
            .inode = std.mem.readInt(u64, bytes[24..32], .big),
            .family = std.mem.readInt(u16, bytes[32..34], .big),
            .port = std.mem.readInt(u16, bytes[34..36], .big),
            .address = bytes[36..52].*,
            .scope_id = std.mem.readInt(u32, bytes[52..56], .big),
            .flow_info = std.mem.readInt(u32, bytes[56..60], .big),
            .recv_timeout_us = std.mem.readInt(u64, bytes[60..68], .big),
        },
        .tls_digest = bytes[68..100].*,
        .execution = .paused,
    };
    if (!validListener(carry.listener)) return error.InvalidFrame;
    var runtime = try parseRuntime(bytes);
    errdefer std.crypto.secureZero(u8, std.mem.asBytes(&runtime));
    var info = std.mem.zeroes(socket_mod.ProtocolInfo);
    @memcpy(std.mem.asBytes(&info), bytes[socket_offset..]);
    if (info.address_family != carry.listener.family or info.socket_type != 1 or info.protocol != 6)
        return error.InvalidFrame;
    return .{ .carry = carry, .runtime_tls = runtime, .transfer = .{ .info = info } };
}

/// Read the source only while its actual accept worker is parked at an exact
/// operation boundary, then duplicate the listener for this child PID.
pub fn prepareSource(source: Source, target_process: usize, target_pid: u32) Error!Prepared {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    if (target_process == 0 or target_pid == 0 or GetProcessId(target_process) != target_pid)
        return error.InvalidTarget;
    const socket: usize = @intCast(source.owner.listen_fd);
    if (!source.owner.listen_open or !source.owner.winsock_started or
        source.owner.stop_flag.load(.acquire) or socket == invalid_socket or
        source.carry.execution != .paused or source.carry.listener.inode != socket or
        source.carry.listener.port != source.owner.port) return error.InvalidSnapshot;
    const observed = source.owner.capturePaused(source.pause_token) catch return error.InvalidSnapshot;
    if (!std.meta.eql(observed, source.carry.*) or !validListener(observed.listener))
        return error.InvalidSnapshot;
    const transfer = try socket_mod.duplicateForProcess(socket, target_pid);
    return .{ .body = presentFrame(source.carry, &source.owner.tls_config, target_pid, &transfer.info) };
}

pub fn receive(bytes: []const u8, target_pid: u32) Error!?Received {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    return parseFrame(bytes, target_pid);
}

test "Windows history frame has canonical absence and strict loopback TLS fields" {
    const pid: u32 = 71;
    var absent = absentFrame();
    try std.testing.expect((try parseFrame(&absent, pid)) == null);
    absent[frame_len - 1] = 1;
    try std.testing.expectError(error.InvalidFrame, parseFrame(&absent, pid));
    var info = std.mem.zeroes(socket_mod.ProtocolInfo);
    info.address_family = 2;
    info.socket_type = 1;
    info.protocol = 6;
    const carry = history_http.Snapshot{
        .listener = .{ .device = 0, .inode = 123, .family = 2, .port = 9131, .address = .{ 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, .scope_id = 0, .flow_info = 0, .recv_timeout_us = 200_000 },
        .tls_digest = @splat(0x33),
        .execution = .paused,
    };
    const config: tls_server.Config = .{ .cert_chain = &.{} };
    const body = presentFrame(&carry, &config, pid, &info);
    var received = (try parseFrame(&body, pid)) orelse return error.TestUnexpectedResult;
    defer received.deinit();
    try std.testing.expectEqualDeep(carry, received.carry);
    try std.testing.expectError(error.InvalidFrame, parseFrame(&body, pid + 1));
    var corrupt = body;
    corrupt[100] = @intFromEnum(history_http.Execution.unstarted);
    try std.testing.expectError(error.InvalidFrame, parseFrame(&corrupt, pid));
    corrupt = body;
    corrupt[101] = 1;
    try std.testing.expectError(error.InvalidFrame, parseFrame(&corrupt, pid));
    corrupt = body;
    corrupt[36] = 0;
    try std.testing.expectError(error.InvalidFrame, parseFrame(&corrupt, pid));
    corrupt = body;
    corrupt[socket_offset + @offsetOf(socket_mod.ProtocolInfo, "address_family")] = 23;
    try std.testing.expectError(error.InvalidFrame, parseFrame(&corrupt, pid));
}

test "Windows history TLS frame carries stale listener ticket policy and requires replay custody" {
    const pid: u32 = 71;
    var info = std.mem.zeroes(socket_mod.ProtocolInfo);
    info.address_family = 2;
    info.socket_type = 1;
    info.protocol = 6;
    var source_guard: tls_resumption.ReplayGuard = .{};
    var candidate_guard: tls_resumption.ReplayGuard = .{};
    const source_cfg: tls_server.Config = .{
        .cert_chain = &.{},
        .enable_session_tickets = true,
        .ticket_key = @splat(0x31),
        .previous_ticket_key = @splat(0x32),
        .max_early_data_size = 4096,
        .now_unix_seconds = 1_700_000_001,
        .replay_guard = &source_guard,
        .ocsp_staple = "pinned staple",
    };
    const carry = history_http.Snapshot{
        .listener = .{ .device = 0, .inode = 123, .family = 2, .port = 9131, .address = .{ 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, .scope_id = 0, .flow_info = 0, .recv_timeout_us = 200_000 },
        .tls_digest = try history_http.tlsConfigDigest(source_cfg),
        .execution = .paused,
    };
    const body = presentFrame(&carry, &source_cfg, pid, &info);
    var received = (try parseFrame(&body, pid)) orelse return error.TestUnexpectedResult;
    defer received.deinit();
    const candidate_base: tls_server.Config = .{ .cert_chain = &.{}, .ticket_key = source_cfg.ticket_key, .previous_ticket_key = source_cfg.previous_ticket_key, .now_unix_seconds = 1_800_000_000, .ocsp_staple = source_cfg.ocsp_staple };
    try std.testing.expectError(error.InvalidFrame, received.tlsConfig(candidate_base, null));
    var missing_key = candidate_base;
    missing_key.previous_ticket_key = null;
    try std.testing.expectError(error.InvalidFrame, received.tlsConfig(missing_key, &candidate_guard));
    const restored = try received.tlsConfig(candidate_base, &candidate_guard);
    try std.testing.expectEqual(source_cfg.ticket_key.?, restored.ticket_key.?);
    try std.testing.expectEqual(source_cfg.previous_ticket_key.?, restored.previous_ticket_key.?);
    try std.testing.expectEqual(source_cfg.now_unix_seconds, restored.now_unix_seconds);
    try std.testing.expectEqual(source_cfg.max_early_data_size, restored.max_early_data_size);
    try std.testing.expectEqualSlices(u8, source_cfg.ocsp_staple, restored.ocsp_staple);
    try std.testing.expect(restored.replay_guard == &candidate_guard);
    try std.testing.expectEqual(carry.tls_digest, try history_http.tlsConfigDigest(restored));
    var corrupt = body;
    corrupt[104] |= 0x80;
    try std.testing.expectError(error.InvalidFrame, parseFrame(&corrupt, pid));
    corrupt = body;
    corrupt[105] &= ~@as(u8, 0x40);
    try std.testing.expectError(error.InvalidFrame, parseFrame(&corrupt, pid));
}

test "Windows history custody requires actual paused accept epoch and imports inert duplicate" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const Reader = struct {
        fn read(_: *anyopaque, _: []const u8, _: []const u8, _: []u8) error{Denied}!usize {
            return error.Denied;
        }
    };
    var marker: u8 = 0;
    var source = try history_http.HttpsListener.open(std.testing.allocator, "127.0.0.1", 0, .{ .cert_chain = &.{} }, .{ .ptr = &marker, .readFn = Reader.read });
    defer source.shutdown();
    try source.runtime_worker.pause.bindIo(std.testing.io);
    try source.spawn();
    const token = try source.requestPause(1);
    try source.awaitPaused(token, std.Io.Clock.Timestamp.fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
    const carry = try source.capturePaused(token);
    const process = GetCurrentProcess();
    const pid = GetCurrentProcessId();
    try std.testing.expectError(error.InvalidSnapshot, prepareSource(.{ .owner = &source, .carry = &carry, .pause_token = .{ .owner = token.owner, .epoch = token.epoch + 1 } }, process, pid));
    var altered = carry;
    altered.tls_digest[0] ^= 1;
    try std.testing.expectError(error.InvalidSnapshot, prepareSource(.{ .owner = &source, .carry = &altered, .pause_token = token }, process, pid));
    var prepared = try prepareSource(.{ .owner = &source, .carry = &carry, .pause_token = token }, process, pid);
    defer prepared.deinit();
    const immutable = prepared.body;
    var received = (try receive(&prepared.body, pid)) orelse return error.TestUnexpectedResult;
    defer received.deinit();
    var adopted = try history_http.HttpsListener.initTransferred(std.testing.allocator, "127.0.0.1", &received.transfer, &received.carry, source.tls_config, source.reader);
    defer adopted.shutdown();
    try std.testing.expect(received.transfer.consumed);
    try std.testing.expectEqual(immutable, prepared.body);
    try std.testing.expect(adopted.thread == null);
    try std.testing.expect(adopted.runtime_worker.view == null);
    try source.resumePaused(token);
    try std.testing.expectError(error.InvalidSnapshot, prepareSource(.{ .owner = &source, .carry = &carry, .pause_token = token }, process, pid));
}
