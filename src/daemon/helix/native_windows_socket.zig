// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//! One Windows socket-transfer primitive for a future native Helix successor.
//! The caller must first cancel and drain every operation on the predecessor's
//! socket. It must keep that socket alive until the successor commits. This
//! module never closes the source socket or publishes a successor registry ID.
const std = @import("std");
const builtin = @import("builtin");

const af_inet: i32 = 2;
const af_inet6: i32 = 23;
const sock_stream: i32 = 1;
const ipproto_tcp: i32 = 6;
const from_protocol_info: i32 = -1;
const wsa_flag_overlapped: u32 = 1;
const wsa_flag_no_handle_inherit: u32 = 0x80;
const invalid_socket = std.math.maxInt(usize);

// winsock2.h: WSAPROTOCOLCHAIN and WSAPROTOCOL_INFOW. Keep the complete
// provider-owned record opaque after the few fields used for type validation.
const ProtocolChain = extern struct {
    chain_len: i32,
    entries: [7]u32,
};

pub const ProtocolInfo = extern struct {
    service_flags_1: u32,
    service_flags_2: u32,
    service_flags_3: u32,
    service_flags_4: u32,
    provider_flags: u32,
    provider_id: extern struct {
        data_1: u32,
        data_2: u16,
        data_3: u16,
        data_4: [8]u8,
    },
    catalog_entry_id: u32,
    protocol_chain: ProtocolChain,
    version: i32,
    address_family: i32,
    max_sock_addr: i32,
    min_sock_addr: i32,
    socket_type: i32,
    protocol: i32,
    protocol_max_offset: i32,
    network_byte_order: i32,
    security_scheme: i32,
    message_size: u32,
    provider_reserved: u32,
    name: [256]u16,
};

comptime {
    if (@sizeOf(ProtocolChain) != 32 or @sizeOf(ProtocolInfo) != 628 or
        @offsetOf(ProtocolInfo, "address_family") != 76 or
        @offsetOf(ProtocolInfo, "name") != 116)
        @compileError("WSAPROTOCOL_INFOW ABI mismatch");
}

pub const Error = error{
    Unsupported,
    InvalidSocket,
    InvalidTarget,
    InvalidPort,
    InvalidProtocolInfo,
    AlreadyConsumed,
    WinsockUnavailable,
    DuplicateFailed,
    ImportFailed,
    RebindFailed,
};

extern "ws2_32" fn WSAStartup(version: u16, data: *[408]u8) callconv(.winapi) i32;
extern "ws2_32" fn WSADuplicateSocketW(socket: usize, target_pid: u32, info: *ProtocolInfo) callconv(.winapi) i32;
extern "ws2_32" fn WSASocketW(family: i32, kind: i32, protocol: i32, info: ?*ProtocolInfo, group: u32, flags: u32) callconv(.winapi) usize;
extern "ws2_32" fn closesocket(socket: usize) callconv(.winapi) i32;
extern "kernel32" fn GetCurrentProcessId() callconv(.winapi) u32;
extern "kernel32" fn CreateIoCompletionPort(file: usize, existing: usize, key: usize, threads: u32) callconv(.winapi) usize;
extern "kernel32" fn CloseHandle(handle: usize) callconv(.winapi) i32;

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
        info.socket_type != sock_stream or info.protocol != ipproto_tcp)
        return error.InvalidProtocolInfo;
}

/// WSADuplicateSocketW targets an exact PID. Its protocol record is a one-use
/// capability and must travel only over the authenticated Helix control path.
pub const Transfer = struct {
    info: ProtocolInfo,
    consumed: bool = false,

    pub fn import(self: *Transfer) Error!usize {
        if (comptime builtin.os.tag != .windows) return error.Unsupported;
        if (self.consumed) return error.AlreadyConsumed;
        self.consumed = true;
        try validate(&self.info);
        try ensureWinsock();
        const socket = WSASocketW(from_protocol_info, from_protocol_info, from_protocol_info, &self.info, 0, wsa_flag_overlapped | wsa_flag_no_handle_inherit);
        if (socket == invalid_socket) return error.ImportFailed;
        return socket;
    }
};

pub fn duplicateForProcess(socket: usize, target_pid: u32) Error!Transfer {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    if (socket == invalid_socket) return error.InvalidSocket;
    if (target_pid == 0) return error.InvalidTarget;
    try ensureWinsock();
    var result = Transfer{ .info = std.mem.zeroes(ProtocolInfo) };
    if (WSADuplicateSocketW(socket, target_pid, &result.info) != 0) return error.DuplicateFailed;
    try validate(&result.info);
    return result;
}

/// The new process may replace an inherited socket's completion association
/// only after the predecessor has drained its pending I/O and released its
/// completion port. Replacing it earlier changes shared socket ownership.
pub fn replaceCompletionPort(socket: usize, port: usize, key: usize) Error!void {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    if (socket == invalid_socket) return error.InvalidSocket;
    if (port == 0) return error.InvalidPort;
    var completion = extern struct {
        port: std.os.windows.HANDLE,
        key: ?*anyopaque,
    }{ .port = @ptrFromInt(port), .key = @ptrFromInt(key) };
    var iosb = std.mem.zeroes(std.os.windows.IO_STATUS_BLOCK);
    const status = std.os.windows.ntdll.NtSetInformationFile(
        @ptrFromInt(socket),
        &iosb,
        @ptrCast(&completion),
        @sizeOf(@TypeOf(completion)),
        .ReplaceCompletion,
    );
    if (status != .SUCCESS) return error.RebindFailed;
}

test "Windows Helix duplicates a TCP socket into a separately associated IOCP handle" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    try ensureWinsock();
    const source = WSASocketW(af_inet, sock_stream, ipproto_tcp, null, 0, wsa_flag_overlapped | wsa_flag_no_handle_inherit);
    if (source == invalid_socket) return error.SocketCreationFailed;
    var source_open = true;
    defer if (source_open) {
        _ = closesocket(source);
    };
    var transfer = try duplicateForProcess(source, GetCurrentProcessId());
    const adopted = try transfer.import();
    defer _ = closesocket(adopted);
    try std.testing.expect(adopted != source);
    try std.testing.expectError(error.AlreadyConsumed, transfer.import());

    const first_port = CreateIoCompletionPort(source, 0, 1, 0);
    if (first_port == 0) return error.FirstAssociationFailed;
    var first_port_open = true;
    defer if (first_port_open) {
        _ = CloseHandle(first_port);
    };

    // The parent has released its socket and queue after candidate staging.
    _ = closesocket(source);
    source_open = false;
    _ = CloseHandle(first_port);
    first_port_open = false;

    const second_port = CreateIoCompletionPort(invalid_socket, 0, 0, 0);
    if (second_port == 0) return error.SecondPortCreationFailed;
    defer _ = CloseHandle(second_port);
    try replaceCompletionPort(adopted, second_port, 2);
}

test "Windows Helix socket transfer refuses invalid target and malformed protocol" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    try std.testing.expectError(error.InvalidSocket, duplicateForProcess(invalid_socket, 1));
    try std.testing.expectError(error.InvalidTarget, duplicateForProcess(0, 0));
    try std.testing.expectError(error.InvalidSocket, replaceCompletionPort(invalid_socket, 1, 0));
    try std.testing.expectError(error.InvalidPort, replaceCompletionPort(0, 0, 0));
    var transfer = Transfer{ .info = std.mem.zeroes(ProtocolInfo) };
    try std.testing.expectError(error.InvalidProtocolInfo, transfer.import());
    try std.testing.expectError(error.AlreadyConsumed, transfer.import());
}
