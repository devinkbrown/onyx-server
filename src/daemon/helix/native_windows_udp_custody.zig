// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Three distinct, one-use Windows UDP Helix custodians. A present HXUD record
//! carries a PID-bound Winsock duplicate and an AEAD-sealed, exact idle owner
//! snapshot. The predecessor retains its paused socket through COMMIT/abort.
const std = @import("std");
const builtin = @import("builtin");
const platform = @import("../../substrate/platform.zig");
const webtransport = @import("../webtransport_listener.zig");
const webrtc = @import("../media_plane.zig");
const native = @import("../native_media_transport.zig");
const media_routing = @import("../../substrate/media_routing.zig");
const runtime_pause = @import("../runtime_pause.zig");
const envelope = @import("native_arena_envelope.zig");
const arena_mod = @import("native_windows_arena.zig");
const socket_mod = @import("native_windows_udp_socket.zig");
const codec = @import("native_windows_udp_snapshot.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const invalid_socket = std.math.maxInt(usize);
const magic = "HXUD";
const version: u16 = 2;
const header_len: usize = 96;
pub const frame_len: usize = header_len + socket_mod.frame_len;
pub const Frame = [frame_len]u8;
pub const Kind = socket_mod.Kind;

comptime {
    if (frame_len > @import("native_windows_control.zig").max_body)
        @compileError("Windows Helix UDP custody exceeds authenticated control frame");
}

extern "kernel32" fn GetProcessId(handle: usize) callconv(.winapi) u32;
extern "kernel32" fn GetCurrentProcessId() callconv(.winapi) u32;
extern "kernel32" fn CloseHandle(handle: usize) callconv(.winapi) i32;

pub const Error = arena_mod.Error || socket_mod.Error || platform.EntropyError || std.mem.Allocator.Error || error{
    InvalidTarget,
    InvalidSnapshot,
    InvalidFrame,
    DigestMismatch,
};

pub const WebtransportSource = struct {
    owner: *webtransport.WebTransportListener,
    carry: *const webtransport.Snapshot,
    pause_token: ?runtime_pause.Token = null,
};
pub const PristineMediaProof = struct {
    domain: *media_routing.Domain,
    native: *native.NativeMediaTransport,
    native_token: runtime_pause.Token,
    webrtc: *webrtc.MediaPlane,
    webrtc_token: runtime_pause.Token,
};
pub const WebrtcSource = struct {
    owner: *webrtc.MediaPlane,
    carry: *const webrtc.Snapshot,
    pause_token: ?runtime_pause.Token = null,
    pristine: ?PristineMediaProof = null,
};
pub const NativeSource = struct {
    owner: *native.NativeMediaTransport,
    carry: *const native.Snapshot,
    pause_token: ?runtime_pause.Token = null,
    pristine: ?PristineMediaProof = null,
};

pub const Prepared = struct {
    arena: arena_mod.Arena,
    sealer: envelope.Sealer,
    body: Frame,

    pub fn deinit(self: *Prepared) void {
        self.arena.deinit();
        self.sealer.deinit();
        std.crypto.secureZero(u8, &self.body);
    }
};

pub const ReceivedWebtransport = struct {
    carry: webtransport.Snapshot,
    transfer: socket_mod.Transfer,

    pub fn deinit(self: *ReceivedWebtransport) void {
        self.carry.deinit();
        std.crypto.secureZero(u8, std.mem.asBytes(&self.transfer.info));
        self.transfer.consumed = true;
    }
};
pub const ReceivedWebrtc = struct {
    carry: webrtc.Snapshot,
    transfer: socket_mod.Transfer,

    pub fn deinit(self: *ReceivedWebrtc) void {
        self.carry.deinit();
        std.crypto.secureZero(u8, std.mem.asBytes(&self.transfer.info));
        self.transfer.consumed = true;
    }
};
pub const ReceivedNative = struct {
    carry: native.Snapshot,
    transfer: socket_mod.Transfer,

    pub fn deinit(self: *ReceivedNative) void {
        self.carry.deinit();
        std.crypto.secureZero(u8, std.mem.asBytes(&self.transfer.info));
        self.transfer.consumed = true;
    }
};

pub fn absentFrame(kind: Kind) Frame {
    var body: Frame = @splat(0);
    @memcpy(body[0..4], magic);
    std.mem.writeInt(u16, body[4..6], version, .big);
    body[6] = @intFromEnum(kind);
    return body;
}

fn presentFrame(kind: Kind, target_pid: u32, remote_handle: usize, wire_size: usize, key: envelope.Key, digest: [32]u8, transfer: *const socket_mod.Transfer) Error!Frame {
    var body = absentFrame(kind);
    body[7] = 1;
    std.mem.writeInt(u32, body[8..12], target_pid, .big);
    std.mem.writeInt(u64, body[16..24], @intCast(remote_handle), .big);
    std.mem.writeInt(u64, body[24..32], @intCast(wire_size), .big);
    @memcpy(body[32..64], &key);
    @memcpy(body[64..96], &digest);
    const socket_frame = try socket_mod.encodeFrame(transfer, kind);
    @memcpy(body[header_len..], &socket_frame);
    return body;
}

fn validateTarget(target_process: usize, target_pid: u32) Error!void {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    if (target_process == 0 or target_pid == 0 or GetProcessId(target_process) != target_pid)
        return error.InvalidTarget;
}

fn prepare(allocator: std.mem.Allocator, kind: Kind, snapshot: []const u8, source_socket: usize, target_process: usize, target_pid: u32, upgrade_id: envelope.UpgradeId) Error!Prepared {
    try validateTarget(target_process, target_pid);
    if (snapshot.len == 0 or snapshot.len > codec.max_snapshot_bytes or source_socket == invalid_socket)
        return error.InvalidSnapshot;
    var digest: [32]u8 = undefined;
    Sha256.hash(snapshot, &digest, .{});
    var sealer = try envelope.Sealer.initRandom();
    errdefer sealer.deinit();
    sealer.upgrade_id = upgrade_id;
    var arena = try arena_mod.Arena.create(allocator, &sealer, snapshot);
    errdefer arena.deinit();
    var transfer = try socket_mod.duplicateForProcess(source_socket, target_pid);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&transfer.info));
    // A target-owned section HANDLE is only closed by reaping the candidate.
    const remote_handle = try arena.duplicateReadOnlyForProcess(target_process);
    return .{ .arena = arena, .sealer = sealer, .body = try presentFrame(kind, target_pid, remote_handle, arena.size, sealer.key, digest, &transfer) };
}

fn requireWebtransportSource(source: WebtransportSource) Error!usize {
    const socket = source.owner.socket orelse return error.InvalidSnapshot;
    if (socket.fd == invalid_socket or socket.ipv4_fd != invalid_socket) return error.InvalidSnapshot;
    var current = if (source.pause_token) |token|
        source.owner.capturePaused(token) catch return error.InvalidSnapshot
    else
        source.owner.captureUnstarted() catch return error.InvalidSnapshot;
    defer current.deinit();
    if (!std.meta.eql(current, source.carry.*) or source.carry.socket.primary.device != socket.fd or
        source.carry.socket.primary.inode != 0)
        return error.InvalidSnapshot;
    return socket.fd;
}

fn requireWebrtcSource(source: WebrtcSource) Error!usize {
    const socket = source.owner.socket orelse return error.InvalidSnapshot;
    if (socket.fd == invalid_socket) return error.InvalidSnapshot;
    if (source.pristine) |proof| {
        if (source.owner != proof.webrtc or source.pause_token == null or
            !std.meta.eql(source.pause_token.?, proof.webrtc_token)) return error.InvalidSnapshot;
        var current = proof.domain.capturePausedPristineMedia(
            proof.native,
            proof.native_token,
            proof.webrtc,
            proof.webrtc_token,
        ) catch return error.InvalidSnapshot;
        defer current.deinit();
        if (!std.meta.eql(current.webrtc, source.carry.*)) return error.InvalidSnapshot;
    } else {
        var current = if (source.pause_token) |token|
            source.owner.capturePaused(token) catch return error.InvalidSnapshot
        else
            source.owner.captureUnstarted() catch return error.InvalidSnapshot;
        defer current.deinit();
        if (!std.meta.eql(current, source.carry.*)) return error.InvalidSnapshot;
    }
    if (source.carry.socket.device != socket.fd or
        source.carry.socket.inode != 0)
        return error.InvalidSnapshot;
    return socket.fd;
}

fn requireNativeSource(source: NativeSource) Error!usize {
    const socket = source.owner.socket orelse return error.InvalidSnapshot;
    if (socket.fd == invalid_socket) return error.InvalidSnapshot;
    if (source.pristine) |proof| {
        if (source.owner != proof.native or source.pause_token == null or
            !std.meta.eql(source.pause_token.?, proof.native_token)) return error.InvalidSnapshot;
        var current = proof.domain.capturePausedPristineMedia(
            proof.native,
            proof.native_token,
            proof.webrtc,
            proof.webrtc_token,
        ) catch return error.InvalidSnapshot;
        defer current.deinit();
        if (!std.meta.eql(current.native, source.carry.*)) return error.InvalidSnapshot;
    } else {
        var current = if (source.pause_token) |token|
            source.owner.capturePaused(token) catch return error.InvalidSnapshot
        else
            source.owner.captureUnstarted() catch return error.InvalidSnapshot;
        defer current.deinit();
        if (!std.meta.eql(current, source.carry.*)) return error.InvalidSnapshot;
    }
    if (source.carry.socket.device != socket.fd or
        source.carry.socket.inode != 0)
        return error.InvalidSnapshot;
    return socket.fd;
}

pub fn prepareWebtransport(allocator: std.mem.Allocator, source: WebtransportSource, target_process: usize, target_pid: u32, upgrade_id: envelope.UpgradeId) Error!Prepared {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    const socket = try requireWebtransportSource(source);
    const snapshot = codec.encodeWebtransport(allocator, source.carry) catch |err|
        return if (err == error.OutOfMemory) error.OutOfMemory else error.InvalidSnapshot;
    defer {
        std.crypto.secureZero(u8, snapshot);
        allocator.free(snapshot);
    }
    return prepare(allocator, .webtransport, snapshot, socket, target_process, target_pid, upgrade_id);
}

pub fn prepareWebrtc(allocator: std.mem.Allocator, source: WebrtcSource, target_process: usize, target_pid: u32, upgrade_id: envelope.UpgradeId) Error!Prepared {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    const socket = try requireWebrtcSource(source);
    const snapshot = codec.encodeWebrtc(allocator, source.carry) catch |err|
        return if (err == error.OutOfMemory) error.OutOfMemory else error.InvalidSnapshot;
    defer {
        std.crypto.secureZero(u8, snapshot);
        allocator.free(snapshot);
    }
    return prepare(allocator, .media, snapshot, socket, target_process, target_pid, upgrade_id);
}

pub fn prepareNative(allocator: std.mem.Allocator, source: NativeSource, target_process: usize, target_pid: u32, upgrade_id: envelope.UpgradeId) Error!Prepared {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    const socket = try requireNativeSource(source);
    const snapshot = codec.encodeNative(allocator, source.carry) catch |err|
        return if (err == error.OutOfMemory) error.OutOfMemory else error.InvalidSnapshot;
    defer {
        std.crypto.secureZero(u8, snapshot);
        allocator.free(snapshot);
    }
    return prepare(allocator, .native_media, snapshot, socket, target_process, target_pid, upgrade_id);
}

const Parsed = struct {
    handle: usize,
    size: usize,
    key: envelope.Key,
    digest: [32]u8,
    transfer: socket_mod.Transfer,
};

fn parseFrame(bytes: []const u8, kind: Kind, target_pid: u32, forbidden: []const usize) Error!?Parsed {
    if (bytes.len != frame_len or !std.mem.eql(u8, bytes[0..4], magic) or
        std.mem.readInt(u16, bytes[4..6], .big) != version or bytes[6] != @intFromEnum(kind))
        return error.InvalidFrame;
    if (bytes[7] == 0) {
        const canonical = absentFrame(kind);
        if (!std.mem.eql(u8, bytes, &canonical)) return error.InvalidFrame;
        return null;
    }
    if (bytes[7] != 1 or target_pid == 0 or
        std.mem.readInt(u32, bytes[8..12], .big) != target_pid or
        std.mem.readInt(u32, bytes[12..16], .big) != 0)
        return error.InvalidFrame;
    const handle = std.math.cast(usize, std.mem.readInt(u64, bytes[16..24], .big)) orelse return error.InvalidFrame;
    const size = std.math.cast(usize, std.mem.readInt(u64, bytes[24..32], .big)) orelse return error.InvalidFrame;
    if (handle == 0 or handle == std.math.maxInt(usize) or
        size <= envelope.header_len + envelope.tag_len or
        size > envelope.header_len + envelope.tag_len + codec.max_snapshot_bytes)
        return error.InvalidFrame;
    for (forbidden) |reserved| if (reserved == handle) return error.InvalidFrame;
    const socket_bytes = bytes[header_len..];
    const source_socket = std.math.cast(usize, std.mem.readInt(u64, socket_bytes[12..20], .big)) orelse return error.InvalidFrame;
    const transfer = socket_mod.decodeFrame(socket_bytes, kind, target_pid, source_socket) catch return error.InvalidFrame;
    return .{ .handle = handle, .size = size, .key = bytes[32..64].*, .digest = bytes[64..96].*, .transfer = transfer };
}

/// Pure frame validation for the source's immutable READY witness. It must not
/// import a socket or consume the candidate's encrypted section HANDLE.
pub fn validateFrame(bytes: []const u8, kind: Kind, target_pid: u32) Error!bool {
    return (try parseFrame(bytes, kind, target_pid, &.{})) != null;
}

fn receivePlain(allocator: std.mem.Allocator, bytes: []const u8, kind: Kind, target_pid: u32, upgrade_id: envelope.UpgradeId, forbidden: []const usize) Error!?struct { plaintext: []u8, transfer: socket_mod.Transfer } {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    var parsed = (try parseFrame(bytes, kind, target_pid, forbidden)) orelse return null;
    defer _ = CloseHandle(parsed.handle);
    defer std.crypto.secureZero(u8, &parsed.key);
    const plaintext = try arena_mod.read(allocator, parsed.handle, parsed.size, parsed.key, upgrade_id);
    errdefer {
        std.crypto.secureZero(u8, plaintext);
        allocator.free(plaintext);
    }
    if (plaintext.len == 0 or plaintext.len > codec.max_snapshot_bytes) return error.InvalidSnapshot;
    var digest: [32]u8 = undefined;
    Sha256.hash(plaintext, &digest, .{});
    if (!std.crypto.timing_safe.eql([32]u8, digest, parsed.digest)) return error.DigestMismatch;
    return .{ .plaintext = plaintext, .transfer = parsed.transfer };
}

pub fn receiveWebtransport(allocator: std.mem.Allocator, bytes: []const u8, target_pid: u32, upgrade_id: envelope.UpgradeId, forbidden: []const usize) Error!?ReceivedWebtransport {
    const plain = (try receivePlain(allocator, bytes, .webtransport, target_pid, upgrade_id, forbidden)) orelse return null;
    defer {
        std.crypto.secureZero(u8, plain.plaintext);
        allocator.free(plain.plaintext);
    }
    var carry = codec.decodeWebtransport(plain.plaintext) catch return error.InvalidSnapshot;
    errdefer carry.deinit();
    if (carry.socket.primary.device != plain.transfer.source_socket or carry.socket.primary.inode != 0 or
        carry.socket.ipv4 != null or carry.socket.primary.family != plain.transfer.info.address_family)
        return error.InvalidSnapshot;
    return .{ .carry = carry, .transfer = plain.transfer };
}

pub fn receiveWebrtc(allocator: std.mem.Allocator, bytes: []const u8, target_pid: u32, upgrade_id: envelope.UpgradeId, forbidden: []const usize) Error!?ReceivedWebrtc {
    const plain = (try receivePlain(allocator, bytes, .media, target_pid, upgrade_id, forbidden)) orelse return null;
    defer {
        std.crypto.secureZero(u8, plain.plaintext);
        allocator.free(plain.plaintext);
    }
    var carry = codec.decodeWebrtc(plain.plaintext) catch return error.InvalidSnapshot;
    errdefer carry.deinit();
    if (carry.socket.device != plain.transfer.source_socket or carry.socket.inode != 0 or
        plain.transfer.info.address_family != 2)
        return error.InvalidSnapshot;
    return .{ .carry = carry, .transfer = plain.transfer };
}

pub fn receiveNative(allocator: std.mem.Allocator, bytes: []const u8, target_pid: u32, upgrade_id: envelope.UpgradeId, forbidden: []const usize) Error!?ReceivedNative {
    const plain = (try receivePlain(allocator, bytes, .native_media, target_pid, upgrade_id, forbidden)) orelse return null;
    defer {
        std.crypto.secureZero(u8, plain.plaintext);
        allocator.free(plain.plaintext);
    }
    var carry = codec.decodeNative(plain.plaintext) catch return error.InvalidSnapshot;
    errdefer carry.deinit();
    if (carry.socket.device != plain.transfer.source_socket or carry.socket.inode != 0 or
        plain.transfer.info.address_family != 2)
        return error.InvalidSnapshot;
    return .{ .carry = carry, .transfer = plain.transfer };
}

test "Windows UDP custody absent and present records are typed and exact" {
    for ([_]Kind{ .webtransport, .media, .native_media }) |kind| {
        var absent = absentFrame(kind);
        try std.testing.expect((try parseFrame(&absent, kind, 71, &.{})) == null);
        absent[frame_len - 1] = 1;
        try std.testing.expectError(error.InvalidFrame, parseFrame(&absent, kind, 71, &.{}));
        const canonical = absentFrame(kind);
        try std.testing.expectError(error.InvalidFrame, parseFrame(&canonical, if (kind == .webtransport) .media else .webtransport, 71, &.{}));
    }
}
