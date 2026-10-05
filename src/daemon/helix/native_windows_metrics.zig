// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded, typed custody for the standalone Windows /metrics listener.
//! The source keeps accepting ownership until the successor is committed; a
//! received WSADuplicateSocket record is imported only into an inert owner.
const std = @import("std");
const builtin = @import("builtin");
const platform = @import("../../substrate/platform.zig");
const metrics = @import("../metrics_http.zig");
const envelope = @import("native_arena_envelope.zig");
const arena_mod = @import("native_windows_arena.zig");
const socket_mod = @import("native_windows_socket.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const invalid_socket = std.math.maxInt(usize);
const snapshot_magic = "HXMS";
const frame_magic = "HXWM";
const version: u16 = 1;
pub const max_snapshot_bytes: usize = 1024 * 1024;
pub const snapshot_header_len: usize = 80;
pub const frame_len: usize = 96 + @sizeOf(socket_mod.ProtocolInfo);
pub const Frame = [frame_len]u8;

comptime {
    if (snapshot_header_len != 4 + 2 + 2 + 4 + 4 * 4 + 8 + 8 + 2 + 2 + 16 + 4 + 4 + 8 or
        frame_len > @import("native_windows_control.zig").max_body)
        @compileError("Windows metrics custody layout exceeds its bounds");
}

extern "kernel32" fn GetProcessId(handle: usize) callconv(.winapi) u32;
extern "kernel32" fn GetCurrentProcess() callconv(.winapi) usize;
extern "kernel32" fn GetCurrentProcessId() callconv(.winapi) u32;
extern "kernel32" fn CloseHandle(handle: usize) callconv(.winapi) i32;

pub const Error = arena_mod.Error || socket_mod.Error || platform.EntropyError || std.mem.Allocator.Error || error{
    InvalidSnapshot,
    InvalidFrame,
    InvalidTarget,
    TooLarge,
    DigestMismatch,
};

/// The caller keeps this owner paused and this owned capture alive until
/// transfer either fails and resumes the predecessor, or COMMIT exits it.
pub const Source = struct {
    owner: *const metrics.MetricsServer,
    carry: *const metrics.Snapshot,
};

fn requireSnapshot(carry: *const metrics.Snapshot) Error!void {
    carry.validate(carry.config, max_snapshot_bytes) catch |err| switch (err) {
        error.Capacity => return error.TooLarge,
        else => return error.InvalidSnapshot,
    };
    if (carry.listener.device != 0 or carry.listener.inode == std.math.maxInt(u64) or
        carry.listener.family != 2 or carry.listener.port == 0)
        return error.InvalidSnapshot;
}

/// Exact byte encoding, with no native struct padding or allocator pointer.
pub fn encodeSnapshot(allocator: std.mem.Allocator, carry: *const metrics.Snapshot) Error![]u8 {
    try requireSnapshot(carry);
    if (carry.text.len > max_snapshot_bytes - @sizeOf(metrics.Snapshot)) return error.TooLarge;
    const bytes = try allocator.alloc(u8, snapshot_header_len + carry.text.len);
    @memcpy(bytes[0..4], snapshot_magic);
    std.mem.writeInt(u16, bytes[4..6], version, .big);
    std.mem.writeInt(u16, bytes[6..8], 0, .big);
    std.mem.writeInt(u32, bytes[8..12], @intCast(carry.text.len), .big);
    std.mem.writeInt(u32, bytes[12..16], @as(u32, carry.config.listen_backlog), .big);
    std.mem.writeInt(u32, bytes[16..20], carry.config.accept_poll_ms, .big);
    std.mem.writeInt(u32, bytes[20..24], carry.config.conn_read_timeout_sec, .big);
    std.mem.writeInt(u32, bytes[24..28], carry.config.bind_addr, .big);
    std.mem.writeInt(u64, bytes[28..36], carry.listener.device, .big);
    std.mem.writeInt(u64, bytes[36..44], carry.listener.inode, .big);
    std.mem.writeInt(u16, bytes[44..46], carry.listener.family, .big);
    std.mem.writeInt(u16, bytes[46..48], carry.listener.port, .big);
    @memcpy(bytes[48..64], &carry.listener.address);
    std.mem.writeInt(u32, bytes[64..68], carry.listener.scope_id, .big);
    std.mem.writeInt(u32, bytes[68..72], carry.listener.flow_info, .big);
    std.mem.writeInt(u64, bytes[72..80], carry.listener.recv_timeout_us, .big);
    @memcpy(bytes[snapshot_header_len..], carry.text);
    return bytes;
}

pub fn decodeSnapshot(allocator: std.mem.Allocator, bytes: []const u8) Error!metrics.Snapshot {
    if (bytes.len < snapshot_header_len or bytes.len > snapshot_header_len + max_snapshot_bytes - @sizeOf(metrics.Snapshot) or
        !std.mem.eql(u8, bytes[0..4], snapshot_magic) or
        std.mem.readInt(u16, bytes[4..6], .big) != version or
        std.mem.readInt(u16, bytes[6..8], .big) != 0)
        return error.InvalidSnapshot;
    const text_len: usize = std.mem.readInt(u32, bytes[8..12], .big);
    if (bytes.len != snapshot_header_len + text_len) return error.InvalidSnapshot;
    const backlog = std.math.cast(u31, std.mem.readInt(u32, bytes[12..16], .big)) orelse return error.InvalidSnapshot;
    const config = metrics.Config{
        .listen_backlog = backlog,
        .accept_poll_ms = std.mem.readInt(u32, bytes[16..20], .big),
        .conn_read_timeout_sec = std.mem.readInt(u32, bytes[20..24], .big),
        .bind_addr = std.mem.readInt(u32, bytes[24..28], .big),
    };
    const listener = metrics.ListenerObservation{
        .device = std.mem.readInt(u64, bytes[28..36], .big),
        .inode = std.mem.readInt(u64, bytes[36..44], .big),
        .family = std.mem.readInt(u16, bytes[44..46], .big),
        .port = std.mem.readInt(u16, bytes[46..48], .big),
        .address = bytes[48..64].*,
        .scope_id = std.mem.readInt(u32, bytes[64..68], .big),
        .flow_info = std.mem.readInt(u32, bytes[68..72], .big),
        .recv_timeout_us = std.mem.readInt(u64, bytes[72..80], .big),
    };
    var carry = metrics.Snapshot{
        .allocator = allocator,
        .text = try allocator.dupe(u8, bytes[snapshot_header_len..]),
        .listener = listener,
        .config = config,
    };
    errdefer carry.deinit();
    try requireSnapshot(&carry);
    return carry;
}

pub fn absentFrame() Frame {
    var body: Frame = @splat(0);
    @memcpy(body[0..4], frame_magic);
    std.mem.writeInt(u16, body[4..6], version, .big);
    return body;
}

fn presentFrame(remote_handle: usize, wire_size: usize, target_pid: u32, key: envelope.Key, digest: [32]u8, info: *const socket_mod.ProtocolInfo) Frame {
    var body = absentFrame();
    std.mem.writeInt(u16, body[6..8], 1, .big);
    std.mem.writeInt(u32, body[8..12], target_pid, .big);
    std.mem.writeInt(u64, body[16..24], @intCast(remote_handle), .big);
    std.mem.writeInt(u64, body[24..32], @intCast(wire_size), .big);
    @memcpy(body[32..64], &key);
    @memcpy(body[64..96], &digest);
    @memcpy(body[96..], std.mem.asBytes(info));
    return body;
}

pub const Parsed = struct {
    handle: usize,
    size: usize,
    key: envelope.Key,
    digest: [32]u8,
    transfer: socket_mod.Transfer,
};

/// Parse before touching any HANDLE or socket provider record. The caller
/// supplies process-local control/arena handles that may never be consumed.
pub fn parseFrame(bytes: []const u8, target_pid: u32, forbidden: []const usize) Error!?Parsed {
    if (bytes.len != frame_len or !std.mem.eql(u8, bytes[0..4], frame_magic) or
        std.mem.readInt(u16, bytes[4..6], .big) != version or
        std.mem.readInt(u32, bytes[12..16], .big) != 0)
        return error.InvalidFrame;
    const presence = std.mem.readInt(u16, bytes[6..8], .big);
    if (presence == 0) {
        const canonical = absentFrame();
        if (!std.mem.eql(u8, bytes, &canonical)) return error.InvalidFrame;
        return null;
    }
    if (presence != 1 or target_pid == 0 or std.mem.readInt(u32, bytes[8..12], .big) != target_pid)
        return error.InvalidFrame;
    const handle = std.math.cast(usize, std.mem.readInt(u64, bytes[16..24], .big)) orelse return error.InvalidFrame;
    const size = std.math.cast(usize, std.mem.readInt(u64, bytes[24..32], .big)) orelse return error.InvalidFrame;
    if (handle == 0 or handle == std.math.maxInt(usize) or
        size < envelope.header_len + envelope.tag_len + snapshot_header_len or
        size > envelope.header_len + envelope.tag_len + snapshot_header_len + max_snapshot_bytes - @sizeOf(metrics.Snapshot))
        return error.InvalidFrame;
    for (forbidden) |reserved| if (reserved == handle) return error.InvalidFrame;
    var info = std.mem.zeroes(socket_mod.ProtocolInfo);
    @memcpy(std.mem.asBytes(&info), bytes[96..]);
    if (info.address_family != 2 or info.socket_type != 1 or info.protocol != 6) return error.InvalidFrame;
    return .{
        .handle = handle,
        .size = size,
        .key = bytes[32..64].*,
        .digest = bytes[64..96].*,
        .transfer = .{ .info = info },
    };
}

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

/// The remote section HANDLE belongs to the candidate after duplication.
/// On any transfer failure its process must be terminated and reaped before
/// the predecessor resumes; Prepared.deinit closes only source-owned handles.
pub fn prepareSource(allocator: std.mem.Allocator, source: Source, target_process: usize, target_pid: u32, upgrade_id: envelope.UpgradeId) Error!Prepared {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    if (target_process == 0 or target_pid == 0 or GetProcessId(target_process) != target_pid)
        return error.InvalidTarget;
    const source_socket: usize = @intCast(source.owner.listen_fd);
    if (source_socket == invalid_socket or source.carry.listener.inode != @as(u64, @intCast(source_socket)) or
        !std.meta.eql(source.carry.config, source.owner.config) or source.carry.listener.port != source.owner.port)
        return error.InvalidSnapshot;
    const observed = metrics.observeListener(source_socket) catch return error.InvalidSnapshot;
    if (!std.meta.eql(observed, source.carry.listener)) return error.InvalidSnapshot;
    const plaintext = try encodeSnapshot(allocator, source.carry);
    defer {
        std.crypto.secureZero(u8, plaintext);
        allocator.free(plaintext);
    }
    var digest: [32]u8 = undefined;
    Sha256.hash(plaintext, &digest, .{});
    var sealer = try envelope.Sealer.initRandom();
    errdefer sealer.deinit();
    sealer.upgrade_id = upgrade_id;
    var arena = try arena_mod.Arena.create(allocator, &sealer, plaintext);
    errdefer arena.deinit();
    const transfer = try socket_mod.duplicateForProcess(source_socket, target_pid);
    // This is last: a target-owned remote HANDLE cannot be closed by ordinary
    // Prepared.deinit after the authenticated frame has been sent.
    const remote_handle = try arena.duplicateReadOnlyForProcess(target_process);
    return .{
        .arena = arena,
        .sealer = sealer,
        .body = presentFrame(remote_handle, arena.size, target_pid, sealer.key, digest, &transfer.info),
    };
}

pub const Received = struct {
    carry: metrics.Snapshot,
    transfer: socket_mod.Transfer,

    pub fn deinit(self: *Received) void {
        self.carry.deinit();
        std.crypto.secureZero(u8, std.mem.asBytes(&self.transfer.info));
        self.transfer.consumed = true;
    }
};

/// Consumes only the separately authenticated read-only section HANDLE, not
/// the one-use socket transfer. Import into MetricsServer is a later, inert
/// pre-READY action performed at its final stable address.
pub fn receive(allocator: std.mem.Allocator, bytes: []const u8, target_pid: u32, upgrade_id: envelope.UpgradeId, forbidden: []const usize) Error!?Received {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    var parsed = (try parseFrame(bytes, target_pid, forbidden)) orelse return null;
    defer _ = CloseHandle(parsed.handle);
    defer std.crypto.secureZero(u8, &parsed.key);
    const plaintext = try arena_mod.read(allocator, parsed.handle, parsed.size, parsed.key, upgrade_id);
    defer {
        std.crypto.secureZero(u8, plaintext);
        allocator.free(plaintext);
    }
    var digest: [32]u8 = undefined;
    Sha256.hash(plaintext, &digest, .{});
    if (!std.crypto.timing_safe.eql([32]u8, digest, parsed.digest)) return error.DigestMismatch;
    return .{ .carry = try decodeSnapshot(allocator, plaintext), .transfer = parsed.transfer };
}

test "Windows metrics typed snapshot codec is exact and bounded" {
    const allocator = std.testing.allocator;
    const address: [16]u8 = .{ 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    const text = try allocator.dupe(u8, "onyx_metric 7\n");
    var carry = metrics.Snapshot{
        .allocator = allocator,
        .text = text,
        .listener = .{ .device = 0, .inode = 123, .family = 2, .address = address, .port = 9130, .scope_id = 0, .flow_info = 0, .recv_timeout_us = 250_000 },
        .config = .{},
    };
    defer carry.deinit();
    const encoded = try encodeSnapshot(allocator, &carry);
    defer allocator.free(encoded);
    var decoded = try decodeSnapshot(allocator, encoded);
    defer decoded.deinit();
    try std.testing.expectEqualStrings(carry.text, decoded.text);
    try std.testing.expectEqualDeep(carry.listener, decoded.listener);
    try std.testing.expectEqualDeep(carry.config, decoded.config);
    try std.testing.expectError(error.InvalidSnapshot, decodeSnapshot(allocator, encoded[0 .. encoded.len - 1]));
    var corrupt = try allocator.dupe(u8, encoded);
    defer allocator.free(corrupt);
    corrupt[6] = 1;
    try std.testing.expectError(error.InvalidSnapshot, decodeSnapshot(allocator, corrupt));
    corrupt[6] = 0;
    std.mem.writeInt(u32, corrupt[12..16], std.math.maxInt(u32), .big);
    try std.testing.expectError(error.InvalidSnapshot, decodeSnapshot(allocator, corrupt));
}

test "Windows metrics custody frame rejects noncanonical absence and wrong target" {
    const pid: u32 = 71;
    var absent = absentFrame();
    try std.testing.expect((try parseFrame(&absent, pid, &.{})) == null);
    absent[frame_len - 1] = 1;
    try std.testing.expectError(error.InvalidFrame, parseFrame(&absent, pid, &.{}));
    var info = std.mem.zeroes(socket_mod.ProtocolInfo);
    info.address_family = 2;
    info.socket_type = 1;
    info.protocol = 6;
    const body = presentFrame(17, 1024, pid, @splat(3), @splat(4), &info);
    try std.testing.expect((try parseFrame(&body, pid, &.{})) != null);
    try std.testing.expectError(error.InvalidFrame, parseFrame(&body, pid + 1, &.{}));
    try std.testing.expectError(error.InvalidFrame, parseFrame(&body, pid, &.{17}));
    var wrong_type = body;
    wrong_type[96 + @offsetOf(socket_mod.ProtocolInfo, "socket_type")] = 2;
    try std.testing.expectError(error.InvalidFrame, parseFrame(&wrong_type, pid, &.{}));
}

test "Windows metrics encrypted custody imports an inert listener and retains its exact text" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var source_text = metrics.MetricsSnapshot.init(allocator);
    defer source_text.deinit();
    try source_text.set("onyx_metrics_custody 13\n");
    var source = try metrics.MetricsServer.init(&source_text, 0);
    var source_open = true;
    defer if (source_open) source.shutdown();
    var carry = try source.captureUnstarted(allocator, max_snapshot_bytes);
    defer carry.deinit();
    const pid = GetCurrentProcessId();
    const upgrade_id: [16]u8 = @splat(0x37);
    var prepared = try prepareSource(allocator, .{ .owner = &source, .carry = &carry }, GetCurrentProcess(), pid, upgrade_id);
    defer prepared.deinit();
    var received = (try receive(allocator, &prepared.body, pid, upgrade_id, &.{})) orelse return error.TestUnexpectedResult;
    defer received.deinit();
    try std.testing.expectEqualStrings(carry.text, received.carry.text);
    var candidate_text = metrics.MetricsSnapshot.init(allocator);
    defer candidate_text.deinit();
    var candidate = try metrics.MetricsServer.initTransferred(&candidate_text, &received.transfer, &received.carry, .{}, max_snapshot_bytes);
    defer candidate.shutdown();
    try std.testing.expect(received.transfer.consumed);
    try std.testing.expect(candidate.thread == null);
    try std.testing.expect(candidate.runtime.view == null);
    source.shutdown();
    source_open = false;
    var buffer: [128]u8 = undefined;
    try std.testing.expectEqualStrings("onyx_metrics_custody 13\n", try candidate_text.copyInto(&buffer));
}

test "Windows metrics transferred worker parks before READY and enters only after release" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const gate_mod = @import("../runtime_start_gate.zig");
    const allocator = std.testing.allocator;
    var source_text = metrics.MetricsSnapshot.init(allocator);
    defer source_text.deinit();
    try source_text.set("onyx_metrics_gate 17\n");
    var source = try metrics.MetricsServer.init(&source_text, 0);
    var source_open = true;
    defer if (source_open) source.shutdown();
    try source.prepareColdResources(std.testing.io);
    try source.spawn();
    const pause_token = try source.requestPause(1);
    try source.awaitPaused(pause_token, std.Io.Clock.Timestamp.fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
    var carry = try source.capturePaused(allocator, pause_token, max_snapshot_bytes);
    defer carry.deinit();
    const pid = GetCurrentProcessId();
    const upgrade_id: [16]u8 = @splat(0x52);
    var prepared = try prepareSource(allocator, .{ .owner = &source, .carry = &carry }, GetCurrentProcess(), pid, upgrade_id);
    defer prepared.deinit();
    var received = (try receive(allocator, &prepared.body, pid, upgrade_id, &.{})) orelse return error.TestUnexpectedResult;
    defer received.deinit();
    var candidate_text = metrics.MetricsSnapshot.init(allocator);
    defer candidate_text.deinit();
    var candidate = try metrics.MetricsServer.initTransferred(&candidate_text, &received.transfer, &received.carry, .{}, max_snapshot_bytes);
    defer candidate.shutdown();
    try candidate.prepareColdResources(std.testing.io);
    const specs = [_]gate_mod.ParticipantSpec{.{ .kind = .metrics, .instance = 0, .owner_identity = &candidate }};
    const gate = try gate_mod.create(allocator, std.testing.io, &specs);
    defer {
        candidate.requestStopAndWake();
        if (gate.view.inspect().phase == .preparing) gate.control.cancelAllAndJoin() else gate.control.joinAll();
        candidate.detachAfterJoined() catch unreachable;
        gate.control.destroyJoined();
    }
    try candidate.prepareDormantWorker(gate.control, gate.view, try gate.view.slot(.metrics, 0, &candidate));
    try gate.control.awaitAllParked(std.Io.Clock.Timestamp.fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
    try candidate.requireParked();
    try std.testing.expect(!candidate.runtime.entered.load(.acquire));
    try std.testing.expect(candidate.thread == null);
    source.shutdown();
    source_open = false;
    gate.control.releaseAll();
    const deadline = std.Io.Clock.Timestamp.fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) });
    while (!candidate.runtime.entered.load(.acquire)) {
        if (std.Io.Clock.Timestamp.compare(std.Io.Clock.Timestamp.now(std.testing.io, .awake), .gte, deadline))
            return error.TestWorkerTimeout;
        try std.Io.sleep(std.testing.io, .fromMilliseconds(1), .awake);
    }
    try candidate.requireActivated();
}
