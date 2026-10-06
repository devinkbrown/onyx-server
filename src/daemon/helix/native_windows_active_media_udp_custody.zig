// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Two typed, one-use UDP transfers for the active HXNA/HXWA media cut.
//! Each Winsock duplicate and its socket witness travel in an authenticated
//! control record; the native transport policy is AEAD sealed with that witness.
//! The predecessor retains both live sockets until COMMIT or abort.
const std = @import("std");
const builtin = @import("builtin");
const platform = @import("../../substrate/platform.zig");
const media_socket = @import("../../substrate/media_socket.zig");
const native = @import("../native_media_transport.zig");
const webrtc = @import("../media_plane.zig");
const media_custody = @import("native_windows_media_custody.zig");
const envelope = @import("native_arena_envelope.zig");
const arena_mod = @import("native_windows_arena.zig");
const socket_mod = @import("native_windows_udp_socket.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const magic = "HXAU";
const plain_magic = "HXAT";
const version: u16 = 1;
const plain_len: usize = 128;
const header_len: usize = 96;
pub const frame_len: usize = header_len + socket_mod.frame_len;
pub const Frame = [frame_len]u8;
pub const Kind = enum(u8) { native = 1, webrtc = 2 };
const invalid_handle = std.math.maxInt(usize);

comptime {
    if (frame_len > @import("native_windows_control.zig").max_body)
        @compileError("Windows active media UDP custody exceeds authenticated control frame");
}

extern "kernel32" fn GetProcessId(handle: usize) callconv(.winapi) u32;
extern "kernel32" fn GetCurrentProcess() callconv(.winapi) usize;
extern "kernel32" fn GetCurrentProcessId() callconv(.winapi) u32;
extern "kernel32" fn CloseHandle(handle: usize) callconv(.winapi) i32;

pub const Error = arena_mod.Error || socket_mod.Error || media_custody.Error || platform.EntropyError || error{
    InvalidFrame,
    InvalidSnapshot,
    DigestMismatch,
    WrongKind,
    AlreadyClaimed,
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

pub const NativeReceived = struct {
    carry: native.PhysicalTransportSnapshot,
    /// Borrowed from the Incoming receiver; import mutates its READY witness.
    transfer: *socket_mod.Transfer,

    pub fn deinit(self: *NativeReceived) void {
        self.carry.deinit();
    }
};

pub const WebrtcReceived = struct {
    /// Borrowed from the Incoming receiver; import mutates its READY witness.
    transfer: *socket_mod.Transfer,
};

fn socketKind(kind: Kind) socket_mod.Kind {
    return switch (kind) {
        .native => .native_media,
        .webrtc => .media,
    };
}

fn mediaKind(kind: Kind) media_custody.Kind {
    return switch (kind) {
        .native => .native_physical,
        .webrtc => .webrtc_physical,
    };
}

pub fn absentFrame(kind: Kind) Frame {
    var frame: Frame = @splat(0);
    @memcpy(frame[0..4], magic);
    std.mem.writeInt(u16, frame[4..6], version, .big);
    frame[6] = @intFromEnum(kind);
    return frame;
}

fn mediaDigest(frame: *const media_custody.Frame, kind: Kind, pid: u32) Error![32]u8 {
    if (!(try media_custody.validateFrame(frame, mediaKind(kind), pid))) return error.InvalidSnapshot;
    return frame[64..96].*;
}

fn encodeSocket(out: []u8, socket: media_socket.Snapshot) void {
    std.mem.writeInt(u64, out[0..8], socket.device, .big);
    std.mem.writeInt(u64, out[8..16], socket.inode, .big);
    std.mem.writeInt(u32, out[16..20], socket.address_be, .big);
    std.mem.writeInt(u16, out[20..22], socket.port, .big);
    std.mem.writeInt(u32, out[24..28], socket.recv_timeout_ms, .big);
}

fn decodeSocket(bytes: []const u8) Error!media_socket.Snapshot {
    if (std.mem.readInt(u16, bytes[22..24], .big) != 0) return error.InvalidSnapshot;
    const snapshot = media_socket.Snapshot{
        .device = std.mem.readInt(u64, bytes[0..8], .big),
        .inode = std.mem.readInt(u64, bytes[8..16], .big),
        .address_be = std.mem.readInt(u32, bytes[16..20], .big),
        .port = std.mem.readInt(u16, bytes[20..22], .big),
        .recv_timeout_ms = std.mem.readInt(u32, bytes[24..28], .big),
    };
    snapshot.validate() catch return error.InvalidSnapshot;
    if (snapshot.inode != 0 or snapshot.device == invalid_handle) return error.InvalidSnapshot;
    return snapshot;
}

fn encodePlain(kind: Kind, socket: media_socket.Snapshot, policy: ?native.Policy, digest: [32]u8) [plain_len]u8 {
    var plain: [plain_len]u8 = @splat(0);
    @memcpy(plain[0..4], plain_magic);
    std.mem.writeInt(u16, plain[4..6], version, .big);
    plain[6] = @intFromEnum(kind);
    @memcpy(plain[8..40], &digest);
    encodeSocket(plain[40..68], socket);
    if (policy) |p| {
        std.mem.writeInt(u64, plain[68..76], @intCast(p.max_frame_bytes), .big);
        std.mem.writeInt(u64, plain[76..84], p.max_upload_bytes, .big);
        std.mem.writeInt(u64, plain[84..92], @intCast(p.max_participants), .big);
        plain[92] = @intFromBool(p.require_mac);
        plain[93] = @intFromBool(p.mac_key_configured);
        plain[94] = @intFromBool(p.cross_configured);
        @memcpy(plain[96..112], &p.mac_stream_key);
    }
    return plain;
}

fn decodePlain(bytes: []const u8, kind: Kind, digest: [32]u8, source_socket: usize) Error!?native.PhysicalTransportSnapshot {
    if (bytes.len != plain_len or !std.mem.eql(u8, bytes[0..4], plain_magic) or
        std.mem.readInt(u16, bytes[4..6], .big) != version or bytes[6] != @intFromEnum(kind) or bytes[7] != 0 or
        !std.crypto.timing_safe.eql([32]u8, bytes[8..40].*, digest) or
        !std.mem.allEqual(u8, bytes[112..128], 0)) return error.InvalidSnapshot;
    const socket = try decodeSocket(bytes[40..68]);
    if (socket.device != source_socket) return error.InvalidSnapshot;
    if (kind == .webrtc) {
        if (!std.mem.allEqual(u8, bytes[68..112], 0)) return error.InvalidSnapshot;
        return null;
    }
    if (bytes[95] != 0 or bytes[92] > 1 or bytes[93] > 1 or bytes[94] > 1)
        return error.InvalidSnapshot;
    const frame_bytes = std.math.cast(usize, std.mem.readInt(u64, bytes[68..76], .big)) orelse return error.InvalidSnapshot;
    const participants = std.math.cast(usize, std.mem.readInt(u64, bytes[84..92], .big)) orelse return error.InvalidSnapshot;
    const carry = native.PhysicalTransportSnapshot{ .socket = socket, .policy = .{
        .max_frame_bytes = frame_bytes,
        .max_upload_bytes = std.mem.readInt(u64, bytes[76..84], .big),
        .max_participants = participants,
        .require_mac = bytes[92] == 1,
        .mac_key_configured = bytes[93] == 1,
        .cross_configured = bytes[94] == 1,
        .mac_stream_key = bytes[96..112].*,
    } };
    carry.validate() catch return error.InvalidSnapshot;
    return carry;
}

fn presentFrame(kind: Kind, pid: u32, handle: usize, size: usize, key: envelope.Key, digest: [32]u8, transfer: *const socket_mod.Transfer) Error!Frame {
    var frame = absentFrame(kind);
    frame[7] = 1;
    std.mem.writeInt(u32, frame[8..12], pid, .big);
    std.mem.writeInt(u64, frame[16..24], @intCast(handle), .big);
    std.mem.writeInt(u64, frame[24..32], @intCast(size), .big);
    @memcpy(frame[32..64], &key);
    @memcpy(frame[64..96], &digest);
    const socket_frame = try socket_mod.encodeFrame(transfer, socketKind(kind));
    @memcpy(frame[header_len..], &socket_frame);
    return frame;
}

fn prepare(allocator: std.mem.Allocator, kind: Kind, socket: media_socket.Snapshot, policy: ?native.Policy, media_frame: *const media_custody.Frame, target_process: usize, target_pid: u32, upgrade_id: envelope.UpgradeId) Error!Prepared {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    if (target_process == 0 or target_pid == 0 or GetProcessId(target_process) != target_pid) return error.InvalidTarget;
    socket.validate() catch return error.InvalidSnapshot;
    if (socket.inode != 0 or socket.device == invalid_handle) return error.InvalidSnapshot;
    const source_socket = std.math.cast(usize, socket.device) orelse return error.InvalidSnapshot;
    const media_digest = try mediaDigest(media_frame, kind, target_pid);
    var plain = encodePlain(kind, socket, policy, media_digest);
    defer std.crypto.secureZero(u8, &plain);
    var digest: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &digest);
    Sha256.hash(&plain, &digest, .{});
    var sealer = try envelope.Sealer.initRandom();
    errdefer sealer.deinit();
    sealer.upgrade_id = upgrade_id;
    var arena = try arena_mod.Arena.create(allocator, &sealer, &plain);
    errdefer arena.deinit();
    var transfer = try socket_mod.duplicateForProcess(source_socket, target_pid);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&transfer.info));
    const remote_handle = try arena.duplicateReadOnlyForProcess(target_process);
    return .{ .arena = arena, .sealer = sealer, .body = try presentFrame(kind, target_pid, remote_handle, arena.size, sealer.key, digest, &transfer) };
}

pub fn prepareNative(allocator: std.mem.Allocator, carry: *const native.PhysicalTransportSnapshot, media_frame: *const media_custody.Frame, target_process: usize, target_pid: u32, upgrade_id: envelope.UpgradeId) Error!Prepared {
    carry.validate() catch return error.InvalidSnapshot;
    return prepare(allocator, .native, carry.socket, carry.policy, media_frame, target_process, target_pid, upgrade_id);
}

pub fn prepareWebrtc(allocator: std.mem.Allocator, carry: *const webrtc.PhysicalSnapshot, media_frame: *const media_custody.Frame, target_process: usize, target_pid: u32, upgrade_id: envelope.UpgradeId) Error!Prepared {
    return prepare(allocator, .webrtc, carry.socket, null, media_frame, target_process, target_pid, upgrade_id);
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
        std.mem.readInt(u16, bytes[4..6], .big) != version or bytes[6] != @intFromEnum(kind)) return error.InvalidFrame;
    if (bytes[7] == 0) {
        const absent = absentFrame(kind);
        if (!std.mem.eql(u8, bytes, &absent)) return error.InvalidFrame;
        return null;
    }
    if (bytes[7] != 1 or target_pid == 0 or std.mem.readInt(u32, bytes[8..12], .big) != target_pid or
        std.mem.readInt(u32, bytes[12..16], .big) != 0) return error.InvalidFrame;
    const handle = std.math.cast(usize, std.mem.readInt(u64, bytes[16..24], .big)) orelse return error.InvalidFrame;
    const size = std.math.cast(usize, std.mem.readInt(u64, bytes[24..32], .big)) orelse return error.InvalidFrame;
    if (handle == 0 or handle == invalid_handle or size != envelope.header_len + envelope.tag_len + plain_len)
        return error.InvalidFrame;
    for (forbidden) |reserved| if (handle == reserved) return error.InvalidFrame;
    const socket_source = std.mem.readInt(u64, bytes[header_len + 12 .. header_len + 20], .big);
    const source_socket = std.math.cast(usize, socket_source) orelse return error.InvalidFrame;
    const transfer = socket_mod.decodeFrame(bytes[header_len..], socketKind(kind), target_pid, source_socket) catch return error.InvalidFrame;
    return .{ .handle = handle, .size = size, .key = bytes[32..64].*, .digest = bytes[64..96].*, .transfer = transfer };
}

pub fn validateFrame(bytes: []const u8, kind: Kind, target_pid: u32) Error!bool {
    return (try parseFrame(bytes, kind, target_pid, &.{})) != null;
}

/// Owns one candidate read-only section HANDLE. Failed decode consumes it.
pub const Receiver = struct {
    kind: Kind,
    parsed: ?Parsed,
    claimed: bool = false,

    pub fn init(bytes: []const u8, kind: Kind, forbidden: []const usize) Error!Receiver {
        if (comptime builtin.os.tag != .windows) return error.Unsupported;
        return .{ .kind = kind, .parsed = try parseFrame(bytes, kind, GetCurrentProcessId(), forbidden) };
    }

    pub fn deinit(self: *Receiver) void {
        if (self.parsed) |*record| {
            if (comptime builtin.os.tag == .windows) {
                if (record.handle != 0 and record.handle != invalid_handle) _ = CloseHandle(record.handle);
            }
            record.handle = 0;
            std.crypto.secureZero(u8, &record.key);
            std.crypto.secureZero(u8, std.mem.asBytes(&record.transfer.info));
            record.transfer.consumed = true;
        }
        self.parsed = null;
        self.claimed = true;
    }

    fn take(self: *Receiver, allocator: std.mem.Allocator, kind: Kind, upgrade_id: envelope.UpgradeId, media_frame: *const media_custody.Frame) Error!?struct { socket: media_socket.Snapshot, policy: ?native.Policy, transfer: *socket_mod.Transfer } {
        if (self.claimed) return error.AlreadyClaimed;
        self.claimed = true;
        const record = if (self.parsed) |*value| value else {
            if (self.kind != kind) return error.WrongKind;
            return null;
        };
        defer {
            if (comptime builtin.os.tag == .windows) _ = CloseHandle(record.handle);
            record.handle = 0;
            std.crypto.secureZero(u8, &record.key);
        }
        if (self.kind != kind) return error.WrongKind;
        const expected_digest = try mediaDigest(media_frame, kind, record.transfer.target_pid);
        const plain = try arena_mod.read(allocator, record.handle, record.size, record.key, upgrade_id);
        defer {
            std.crypto.secureZero(u8, plain);
            allocator.free(plain);
        }
        if (plain.len != plain_len) return error.InvalidSnapshot;
        var actual_digest: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &actual_digest);
        Sha256.hash(plain, &actual_digest, .{});
        if (!std.crypto.timing_safe.eql([32]u8, actual_digest, record.digest)) return error.DigestMismatch;
        const carry = try decodePlain(plain, kind, expected_digest, record.transfer.source_socket);
        return .{ .socket = if (carry) |c| c.socket else try decodeSocket(plain[40..68]), .policy = if (carry) |c| c.policy else null, .transfer = &record.transfer };
    }

    pub fn takeNative(self: *Receiver, allocator: std.mem.Allocator, upgrade_id: envelope.UpgradeId, media_frame: *const media_custody.Frame) Error!?NativeReceived {
        const taken = (try self.take(allocator, .native, upgrade_id, media_frame)) orelse return null;
        const policy = taken.policy orelse return error.InvalidSnapshot;
        return .{ .carry = .{ .socket = taken.socket, .policy = policy }, .transfer = taken.transfer };
    }

    pub fn takeWebrtc(self: *Receiver, allocator: std.mem.Allocator, upgrade_id: envelope.UpgradeId, media_frame: *const media_custody.Frame, carry: *const webrtc.PhysicalSnapshot) Error!?WebrtcReceived {
        const taken = (try self.take(allocator, .webrtc, upgrade_id, media_frame)) orelse return null;
        if (!std.meta.eql(taken.socket, carry.socket) or taken.policy != null) return error.InvalidSnapshot;
        return .{ .transfer = taken.transfer };
    }

    pub fn imported(self: *const Receiver) bool {
        return self.claimed and self.parsed != null and self.parsed.?.handle == 0 and self.parsed.?.transfer.consumed;
    }
};

test "active media UDP frames require exact kind PID and canonical absence" {
    const pid: u32 = 71;
    inline for (.{ Kind.native, Kind.webrtc }) |kind| {
        var absent = absentFrame(kind);
        try std.testing.expect(!(try validateFrame(&absent, kind, pid)));
        absent[frame_len - 1] = 1;
        try std.testing.expectError(error.InvalidFrame, validateFrame(&absent, kind, pid));
    }
    const native_absent = absentFrame(.native);
    try std.testing.expectError(error.InvalidFrame, validateFrame(&native_absent, .webrtc, pid));
}

test "active media UDP native transport is sealed to physical digest, PID and one claim" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const pid = GetCurrentProcessId();
    const upgrade_id: envelope.UpgradeId = @splat(0x31);
    const transport = native.PhysicalTransportSnapshot{ .socket = .{
        .device = 73,
        .inode = 0,
        .address_be = 0,
        .port = 4444,
        .recv_timeout_ms = 100,
    }, .policy = .{
        .max_frame_bytes = 1400,
        .max_upload_bytes = 4096,
        .max_participants = 2,
        .require_mac = true,
        .mac_stream_key = @splat(0x27),
        .mac_key_configured = true,
        .cross_configured = false,
    } };
    try transport.validate();
    var media_frame = media_custody.absentFrame(.native_physical);
    media_frame[7] = 1;
    std.mem.writeInt(u32, media_frame[8..12], pid, .big);
    std.mem.writeInt(u64, media_frame[16..24], 41, .big);
    std.mem.writeInt(u64, media_frame[24..32], envelope.header_len + envelope.tag_len + 1, .big);
    @memset(media_frame[32..64], 0x42);
    @memset(media_frame[64..96], 0x52);
    const media_digest = try mediaDigest(&media_frame, .native, pid);
    var plain = encodePlain(.native, transport.socket, transport.policy, media_digest);
    defer std.crypto.secureZero(u8, &plain);
    var digest: [32]u8 = undefined;
    Sha256.hash(&plain, &digest, .{});
    var sealer = try envelope.Sealer.initRandom();
    defer sealer.deinit();
    sealer.upgrade_id = upgrade_id;
    var arena = try arena_mod.Arena.create(allocator, &sealer, &plain);
    defer arena.deinit();
    const remote = try arena.duplicateReadOnlyForProcess(GetCurrentProcess());
    var transfer = socket_mod.Transfer{ .info = std.mem.zeroes(socket_mod.ProtocolInfo), .source_socket = 73, .target_pid = pid };
    transfer.info.address_family = 2;
    transfer.info.socket_type = 2;
    transfer.info.protocol = 17;
    const frame = try presentFrame(.native, pid, remote, arena.size, sealer.key, digest, &transfer);
    try std.testing.expect(try validateFrame(&frame, .native, pid));
    try std.testing.expectError(error.InvalidFrame, validateFrame(&frame, .webrtc, pid));
    try std.testing.expectError(error.InvalidFrame, validateFrame(&frame, .native, pid + 1));
    var receiver = try Receiver.init(&frame, .native, &.{});
    defer receiver.deinit();
    var taken = (try receiver.takeNative(allocator, upgrade_id, &media_frame)) orelse return error.TestUnexpectedResult;
    defer taken.deinit();
    try std.testing.expect(std.meta.eql(taken.carry.socket, transport.socket));
    try std.testing.expect(std.meta.eql(taken.carry.policy, transport.policy));
    try std.testing.expectEqual(@as(usize, 73), taken.transfer.source_socket);
    try std.testing.expect(!receiver.imported());
    try std.testing.expectError(error.AlreadyClaimed, receiver.takeNative(allocator, upgrade_id, &media_frame));
}

test "active media UDP mismatch consumes target read-only handle" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const pid = GetCurrentProcessId();
    const upgrade_id: envelope.UpgradeId = @splat(0x23);
    var media_frame = media_custody.absentFrame(.webrtc_physical);
    media_frame[7] = 1;
    std.mem.writeInt(u32, media_frame[8..12], pid, .big);
    std.mem.writeInt(u64, media_frame[16..24], 55, .big);
    std.mem.writeInt(u64, media_frame[24..32], envelope.header_len + envelope.tag_len + 1, .big);
    @memset(media_frame[32..64], 0x34);
    @memset(media_frame[64..96], 0x45);
    const socket = media_socket.Snapshot{ .device = 74, .inode = 0, .address_be = 0, .port = 5000, .recv_timeout_ms = 100 };
    var plain = encodePlain(.webrtc, socket, null, media_frame[64..96].*);
    defer std.crypto.secureZero(u8, &plain);
    var digest: [32]u8 = undefined;
    Sha256.hash(&plain, &digest, .{});
    var sealer = try envelope.Sealer.initRandom();
    defer sealer.deinit();
    sealer.upgrade_id = upgrade_id;
    var arena = try arena_mod.Arena.create(allocator, &sealer, &plain);
    defer arena.deinit();
    const remote = try arena.duplicateReadOnlyForProcess(GetCurrentProcess());
    var transfer = socket_mod.Transfer{ .info = std.mem.zeroes(socket_mod.ProtocolInfo), .source_socket = 74, .target_pid = pid };
    transfer.info.address_family = 2;
    transfer.info.socket_type = 2;
    transfer.info.protocol = 17;
    const frame = try presentFrame(.webrtc, pid, remote, arena.size, sealer.key, digest, &transfer);
    var receiver = try Receiver.init(&frame, .webrtc, &.{});
    defer receiver.deinit();
    try std.testing.expectError(error.WrongUpgrade, receiver.take(allocator, .webrtc, @splat(0x24), &media_frame));
    try std.testing.expectEqual(@as(usize, 0), receiver.parsed.?.handle);
    try std.testing.expectError(error.AlreadyClaimed, receiver.take(allocator, .webrtc, upgrade_id, &media_frame));
}
