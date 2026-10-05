// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//! One-use, PID-scoped Windows UDP socket custody for Helix. The protocol
//! record must travel inside the authenticated control path together with the
//! source socket observation. Endpoint equality alone is never custody proof.
//! Keep the predecessor socket alive until the candidate commits or aborts.
const std = @import("std");
const builtin = @import("builtin");
pub const ProtocolInfo = @import("native_windows_socket.zig").ProtocolInfo;

const af_inet: i32 = 2;
const af_inet6: i32 = 23;
const sock_dgram: i32 = 2;
const ipproto_udp: i32 = 17;
const from_protocol_info: i32 = -1;
const wsa_flag_overlapped: u32 = 1;
const wsa_flag_no_handle_inherit: u32 = 0x80;
const invalid_socket = std.math.maxInt(usize);
const frame_magic = "HXUD";
const frame_version: u16 = 1;
pub const frame_len: usize = 20 + @sizeOf(ProtocolInfo);
pub const Frame = [frame_len]u8;
pub const Kind = enum(u8) { media = 1, webtransport = 2, native_media = 3 };

comptime {
    if (frame_len > @import("native_windows_control.zig").max_body)
        @compileError("Windows UDP custody exceeds authenticated control frame");
}

extern "ws2_32" fn WSAStartup(version: u16, data: *[408]u8) callconv(.winapi) i32;
extern "ws2_32" fn WSADuplicateSocketW(socket: usize, target_pid: u32, info: *ProtocolInfo) callconv(.winapi) i32;
extern "ws2_32" fn WSASocketW(family: i32, kind: i32, protocol: i32, info: ?*ProtocolInfo, group: u32, flags: u32) callconv(.winapi) usize;
extern "ws2_32" fn closesocket(socket: usize) callconv(.winapi) i32;
extern "kernel32" fn GetCurrentProcessId() callconv(.winapi) u32;

pub const Error = error{
    Unsupported,
    InvalidSocket,
    InvalidTarget,
    InvalidProtocolInfo,
    InvalidFrame,
    AlreadyConsumed,
    WinsockUnavailable,
    DuplicateFailed,
    ImportFailed,
};

var winsock_lock: std.atomic.Mutex = .unlocked;
var winsock_started = false;

fn ensureWinsock() Error!void {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    while (!winsock_lock.tryLock()) std.Thread.yield() catch {};
    defer winsock_lock.unlock();
    if (winsock_started) return;
    var data: [408]u8 = @splat(0);
    if (WSAStartup(0x0202, &data) != 0) return error.WinsockUnavailable;
    winsock_started = true;
}

fn validate(info: *const ProtocolInfo) Error!void {
    if ((info.address_family != af_inet and info.address_family != af_inet6) or
        info.socket_type != sock_dgram or info.protocol != ipproto_udp)
        return error.InvalidProtocolInfo;
}

/// Include both scalar fields in the authenticated custody frame. The source
/// handle binds the transfer to its source snapshot; target_pid rejects a
/// record delivered to any process other than the intended candidate.
pub const Transfer = struct {
    info: ProtocolInfo,
    source_socket: usize,
    target_pid: u32,
    consumed: bool = false,

    /// Consume the one-use record even when validation or import fails. The
    /// caller owns and closes the imported socket on any later failure.
    pub fn import(self: *Transfer) Error!usize {
        if (comptime builtin.os.tag != .windows) return error.Unsupported;
        if (self.consumed) return error.AlreadyConsumed;
        self.consumed = true;
        if (self.target_pid == 0 or self.target_pid != GetCurrentProcessId()) return error.InvalidTarget;
        if (self.source_socket == invalid_socket) return error.InvalidSocket;
        try validate(&self.info);
        try ensureWinsock();
        const socket = WSASocketW(from_protocol_info, from_protocol_info, from_protocol_info, &self.info, 0, wsa_flag_overlapped | wsa_flag_no_handle_inherit);
        if (socket == invalid_socket) return error.ImportFailed;
        return socket;
    }
};

/// Fixed-size, canonical descriptor body. The enclosing Helix control frame
/// authenticates these bytes and the source snapshot before import. A media
/// descriptor cannot be substituted for a WebTransport descriptor.
pub fn encodeFrame(transfer: *const Transfer, kind: Kind) Error!Frame {
    if (transfer.consumed or transfer.target_pid == 0 or transfer.source_socket == invalid_socket)
        return error.InvalidFrame;
    try validate(&transfer.info);
    var body: Frame = @splat(0);
    @memcpy(body[0..4], frame_magic);
    std.mem.writeInt(u16, body[4..6], frame_version, .big);
    body[6] = @intFromEnum(kind);
    std.mem.writeInt(u32, body[8..12], transfer.target_pid, .big);
    std.mem.writeInt(u64, body[12..20], @intCast(transfer.source_socket), .big);
    @memcpy(body[20..], std.mem.asBytes(&transfer.info));
    return body;
}

pub fn decodeFrame(bytes: []const u8, kind: Kind, target_pid: u32, source_socket: usize) Error!Transfer {
    if (bytes.len != frame_len or !std.mem.eql(u8, bytes[0..4], frame_magic) or
        std.mem.readInt(u16, bytes[4..6], .big) != frame_version or
        bytes[6] != @intFromEnum(kind) or bytes[7] != 0 or target_pid == 0 or
        std.mem.readInt(u32, bytes[8..12], .big) != target_pid or
        std.mem.readInt(u64, bytes[12..20], .big) != source_socket or
        source_socket == invalid_socket)
        return error.InvalidFrame;
    var transfer = Transfer{
        .info = std.mem.zeroes(ProtocolInfo),
        .source_socket = source_socket,
        .target_pid = target_pid,
    };
    @memcpy(std.mem.asBytes(&transfer.info), bytes[20..]);
    validate(&transfer.info) catch return error.InvalidFrame;
    return transfer;
}

/// Duplicate only a live UDP socket into the exact candidate PID. Source
/// capture and quiescence are the caller's responsibility; this operation does
/// not read datagrams, close the source, or publish the successor owner.
pub fn duplicateForProcess(socket: usize, target_pid: u32) Error!Transfer {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    if (socket == invalid_socket) return error.InvalidSocket;
    if (target_pid == 0) return error.InvalidTarget;
    try ensureWinsock();
    var transfer = Transfer{
        .info = std.mem.zeroes(ProtocolInfo),
        .source_socket = socket,
        .target_pid = target_pid,
    };
    if (WSADuplicateSocketW(socket, target_pid, &transfer.info) != 0) return error.DuplicateFailed;
    try validate(&transfer.info);
    return transfer;
}

test "Windows UDP custody rejects wrong process and malformed protocol before import" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    try std.testing.expectError(error.InvalidSocket, duplicateForProcess(invalid_socket, 1));
    try std.testing.expectError(error.InvalidTarget, duplicateForProcess(0, 0));
    var transfer = Transfer{ .info = std.mem.zeroes(ProtocolInfo), .source_socket = 1, .target_pid = GetCurrentProcessId() };
    try std.testing.expectError(error.InvalidProtocolInfo, transfer.import());
    try std.testing.expectError(error.AlreadyConsumed, transfer.import());
    transfer.consumed = false;
    transfer.target_pid +%= 1;
    try std.testing.expectError(error.InvalidTarget, transfer.import());
}

test "Windows UDP custody descriptor is fixed size, role-bound and process-bound" {
    var transfer = Transfer{
        .info = std.mem.zeroes(ProtocolInfo),
        .source_socket = 17,
        .target_pid = 71,
    };
    transfer.info.address_family = af_inet6;
    transfer.info.socket_type = sock_dgram;
    transfer.info.protocol = ipproto_udp;
    const frame = try encodeFrame(&transfer, .webtransport);
    const decoded = try decodeFrame(&frame, .webtransport, 71, 17);
    try std.testing.expectEqual(transfer.target_pid, decoded.target_pid);
    try std.testing.expectEqual(transfer.source_socket, decoded.source_socket);
    try std.testing.expectError(error.InvalidFrame, decodeFrame(frame[0 .. frame.len - 1], .webtransport, 71, 17));
    try std.testing.expectError(error.InvalidFrame, decodeFrame(&frame, .media, 71, 17));
    try std.testing.expectError(error.InvalidFrame, decodeFrame(&frame, .webtransport, 72, 17));
    try std.testing.expectError(error.InvalidFrame, decodeFrame(&frame, .webtransport, 71, 18));
    var tampered = frame;
    tampered[7] = 1;
    try std.testing.expectError(error.InvalidFrame, decodeFrame(&tampered, .webtransport, 71, 17));
    tampered = frame;
    tampered[20 + @offsetOf(ProtocolInfo, "socket_type")] = 1;
    try std.testing.expectError(error.InvalidFrame, decodeFrame(&tampered, .webtransport, 71, 17));
}
