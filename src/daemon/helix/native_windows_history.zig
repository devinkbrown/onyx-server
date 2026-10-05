// SPDX-License-Identifier: AGPL-3.0-or-later
//! Authenticated custody of the loopback history HTTPS listener on Windows.
//! The frame pins the bound endpoint and complete TLS material digest; the
//! candidate supplies its own TLS config and Server-owned Reader after import.
const std = @import("std");
const builtin = @import("builtin");
const history_http = @import("../history_http.zig");
const metrics_http = @import("../metrics_http.zig");
const runtime_pause = @import("../runtime_pause.zig");
const socket_mod = @import("native_windows_socket.zig");

const frame_magic = "HXHH";
const version: u16 = 1;
const header_len: usize = 104;
pub const frame_len: usize = header_len + @sizeOf(socket_mod.ProtocolInfo);
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
    transfer: socket_mod.Transfer,

    pub fn deinit(self: *Received) void {
        std.crypto.secureZero(u8, std.mem.asBytes(&self.transfer.info));
        self.transfer.consumed = true;
    }
};

pub fn absentFrame() Frame {
    var body: Frame = @splat(0);
    @memcpy(body[0..4], frame_magic);
    std.mem.writeInt(u16, body[4..6], version, .big);
    return body;
}

fn presentFrame(carry: *const history_http.Snapshot, target_pid: u32, info: *const socket_mod.ProtocolInfo) Frame {
    var body = absentFrame();
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
    @memcpy(body[header_len..], std.mem.asBytes(info));
    return body;
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
    var info = std.mem.zeroes(socket_mod.ProtocolInfo);
    @memcpy(std.mem.asBytes(&info), bytes[header_len..]);
    if (info.address_family != carry.listener.family or info.socket_type != 1 or info.protocol != 6)
        return error.InvalidFrame;
    return .{ .carry = carry, .transfer = .{ .info = info } };
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
    return .{ .body = presentFrame(source.carry, target_pid, &transfer.info) };
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
    const body = presentFrame(&carry, pid, &info);
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
    corrupt[header_len + @offsetOf(socket_mod.ProtocolInfo, "address_family")] = 23;
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
