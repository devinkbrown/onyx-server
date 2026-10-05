// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Typed Windows Helix transfer after actual-image capability negotiation.
//! The candidate authenticates and decrypts the arena before accepting any
//! socket record. Imported sockets remain inert until a separate COMMIT and
//! predecessor-exit barrier authorizes IOCP reassociation.
const std = @import("std");
const builtin = @import("builtin");
const platform = @import("../../substrate/platform.zig");
const io_backend = @import("../io_backend.zig");
const control = @import("native_windows_control.zig");
const process = @import("native_windows_process.zig");
const envelope = @import("native_arena_envelope.zig");
const arena_mod = @import("native_windows_arena.zig");
const socket_mod = @import("native_windows_socket.zig");

pub const max_listeners = @import("live.zig").max_inherited_listeners;
pub const max_clients = @import("live.zig").max_inherited_state_fds;
pub const max_sockets = max_listeners + max_clients;
pub const rows_per_frame = 3;
pub const arena_body_len = 64;
pub const descriptor_header_len = 20;
pub const descriptor_row_len = 640;
pub const ack_body_len = 16;
const version: u16 = 1;
const max_canonical_id: i32 = 0x3fff_ffff;
const invalid_socket = std.math.maxInt(usize);
const arena_magic = "HXWA";
const descriptors_magic = "HXWD";
const ack_magic = "HXWK";

comptime {
    if (descriptor_header_len + rows_per_frame * descriptor_row_len > control.max_body or
        descriptor_row_len != 12 + @sizeOf(socket_mod.ProtocolInfo))
        @compileError("Windows Helix descriptor frame exceeds the authenticated control body");
}

extern "kernel32" fn GetCurrentProcess() callconv(.winapi) usize;
extern "kernel32" fn GetCurrentProcessId() callconv(.winapi) u32;
extern "kernel32" fn GetProcessId(handle: usize) callconv(.winapi) u32;
extern "kernel32" fn CloseHandle(handle: usize) callconv(.winapi) i32;

pub const Error = control.Error || arena_mod.Error || socket_mod.Error || error{
    InvalidCandidate,
    InvalidManifest,
    InvalidAck,
    AlreadyStaged,
};

/// These are TCP-only roles. Presence leases and native-service HANDLEs need
/// distinct typed custody and cannot be smuggled in as a Winsock socket.
pub const Role = enum(u8) {
    client = 1,
    s2s_state = 2,
    plain_listener = 3,
    tls_listener = 4,
    websocket_listener = 5,
    s2s_listener = 6,
};

pub const SourceRow = struct {
    canonical: i32,
    socket: usize,
    role: Role,
    shard: u16 = 0,
    family: u8 = 0,
};

pub const ReceivedRow = struct {
    canonical: i32,
    role: Role,
    shard: u16,
    family: u8,
    transfer: socket_mod.Transfer,
    server_owned: bool = false,
};

fn isListener(role: Role) bool {
    return switch (role) {
        .plain_listener, .tls_listener, .websocket_listener, .s2s_listener => true,
        .client, .s2s_state => false,
    };
}

fn validateShape(canonical: i32, role: Role, shard: u16, family: u8) Error!void {
    if (canonical <= 0 or canonical > max_canonical_id) return error.InvalidManifest;
    if (isListener(role)) {
        if (shard > std.math.maxInt(u12) or (family != 4 and family != 6)) return error.InvalidManifest;
    } else if (shard != 0 or family != 0) return error.InvalidManifest;
}

fn validateInfo(info: *const socket_mod.ProtocolInfo, role: Role, family: u8) Error!void {
    if ((info.address_family != 2 and info.address_family != 23) or
        info.socket_type != 1 or info.protocol != 6)
        return error.InvalidManifest;
    if (isListener(role) and ((family == 4 and info.address_family != 2) or
        (family == 6 and info.address_family != 23)))
        return error.InvalidManifest;
}

fn validateSources(rows: []const SourceRow) Error!void {
    if (rows.len > max_sockets) return error.TooLarge;
    var listeners: usize = 0;
    var clients: usize = 0;
    var last: i32 = 0;
    for (rows, 0..) |row, index| {
        try validateShape(row.canonical, row.role, row.shard, row.family);
        if (row.canonical <= last or row.socket == invalid_socket) return error.InvalidManifest;
        for (rows[0..index]) |prior| if (row.socket == prior.socket) return error.InvalidManifest;
        if (isListener(row.role)) listeners += 1 else clients += 1;
        if (listeners > max_listeners or clients > max_clients) return error.TooLarge;
        last = row.canonical;
    }
}

const AckPhase = enum(u16) { arena = 1, descriptors = 2 };

fn ackBody(phase: AckPhase, next_index: usize, total: usize) [ack_body_len]u8 {
    var body: [ack_body_len]u8 = undefined;
    @memcpy(body[0..4], ack_magic);
    std.mem.writeInt(u16, body[4..6], version, .big);
    std.mem.writeInt(u16, body[6..8], @intFromEnum(phase), .big);
    std.mem.writeInt(u32, body[8..12], @intCast(next_index), .big);
    std.mem.writeInt(u32, body[12..16], @intCast(total), .big);
    return body;
}

fn awaitAck(endpoint: *control.Endpoint, phase: AckPhase, next_index: usize, total: usize, deadline: i64) Error!void {
    var reply = try endpoint.receive(deadline);
    defer reply.deinit();
    const expected = ackBody(phase, next_index, total);
    if (reply.kind != .ack or !std.mem.eql(u8, reply.bytes(), &expected)) return error.InvalidAck;
}

fn sendAck(endpoint: *control.Endpoint, phase: AckPhase, next_index: usize, total: usize, deadline: i64) Error!void {
    const body = ackBody(phase, next_index, total);
    try endpoint.send(.ack, &body, deadline);
}

fn encodeArenaBody(remote_handle: usize, size: usize, total: usize, key: envelope.Key) [arena_body_len]u8 {
    var body: [arena_body_len]u8 = undefined;
    @memcpy(body[0..4], arena_magic);
    std.mem.writeInt(u16, body[4..6], version, .big);
    std.mem.writeInt(u16, body[6..8], 0, .big);
    std.mem.writeInt(u64, body[8..16], @intCast(remote_handle), .big);
    std.mem.writeInt(u64, body[16..24], @intCast(size), .big);
    std.mem.writeInt(u32, body[24..28], @intCast(total), .big);
    std.mem.writeInt(u32, body[28..32], 0, .big);
    @memcpy(body[32..64], &key);
    return body;
}

const ArenaHeader = struct { handle: usize, size: usize, total: usize, key: envelope.Key };

fn parseArenaBody(bytes: []const u8) Error!ArenaHeader {
    if (bytes.len != arena_body_len or !std.mem.eql(u8, bytes[0..4], arena_magic) or
        std.mem.readInt(u16, bytes[4..6], .big) != version or
        std.mem.readInt(u16, bytes[6..8], .big) != 0 or
        std.mem.readInt(u32, bytes[28..32], .big) != 0)
        return error.InvalidManifest;
    const handle = std.math.cast(usize, std.mem.readInt(u64, bytes[8..16], .big)) orelse return error.InvalidManifest;
    const size = std.math.cast(usize, std.mem.readInt(u64, bytes[16..24], .big)) orelse return error.InvalidManifest;
    const total: usize = std.mem.readInt(u32, bytes[24..28], .big);
    if (handle == 0 or handle == std.math.maxInt(usize) or total > max_sockets or
        size < envelope.header_len + envelope.tag_len or
        size > envelope.max_plaintext_bytes + envelope.header_len + envelope.tag_len)
        return error.InvalidManifest;
    return .{ .handle = handle, .size = size, .total = total, .key = bytes[32..64].* };
}

fn writeBatchHeader(body: []u8, start: usize, total: usize, count: usize) void {
    @memcpy(body[0..4], descriptors_magic);
    std.mem.writeInt(u16, body[4..6], version, .big);
    std.mem.writeInt(u16, body[6..8], descriptor_row_len, .big);
    std.mem.writeInt(u32, body[8..12], @intCast(start), .big);
    std.mem.writeInt(u32, body[12..16], @intCast(total), .big);
    std.mem.writeInt(u16, body[16..18], @intCast(count), .big);
    std.mem.writeInt(u16, body[18..20], 0, .big);
}

fn validateBatchHeader(body: []const u8, start: usize, total: usize) Error!usize {
    if (start > total or body.len < descriptor_header_len or !std.mem.eql(u8, body[0..4], descriptors_magic) or
        std.mem.readInt(u16, body[4..6], .big) != version or
        std.mem.readInt(u16, body[6..8], .big) != descriptor_row_len or
        std.mem.readInt(u32, body[8..12], .big) != start or
        std.mem.readInt(u32, body[12..16], .big) != total or
        std.mem.readInt(u16, body[18..20], .big) != 0)
        return error.InvalidManifest;
    const count: usize = std.mem.readInt(u16, body[16..18], .big);
    const expected = if (total == 0) @as(usize, 0) else @min(rows_per_frame, total - start);
    if (count != expected or body.len != descriptor_header_len + count * descriptor_row_len)
        return error.InvalidManifest;
    return count;
}

fn encodeRow(body: []u8, row: SourceRow, transfer: *const socket_mod.Transfer) void {
    std.mem.writeInt(i32, body[0..4], row.canonical, .big);
    std.mem.writeInt(u16, body[4..6], row.shard, .big);
    body[6] = @intFromEnum(row.role);
    body[7] = row.family;
    body[8] = 1; // TCP stream; no HANDLE or datagram alias is accepted.
    @memset(body[9..12], 0);
    @memcpy(body[12..descriptor_row_len], std.mem.asBytes(&transfer.info));
}

fn decodeRow(body: []const u8, last: i32) Error!ReceivedRow {
    if (body.len != descriptor_row_len or body[8] != 1 or
        !std.mem.eql(u8, body[9..12], &.{ 0, 0, 0 })) return error.InvalidManifest;
    const role = std.enums.fromInt(Role, body[6]) orelse return error.InvalidManifest;
    const canonical = std.mem.readInt(i32, body[0..4], .big);
    const shard = std.mem.readInt(u16, body[4..6], .big);
    const family = body[7];
    try validateShape(canonical, role, shard, family);
    if (canonical <= last) return error.InvalidManifest;
    var info: socket_mod.ProtocolInfo = undefined;
    @memcpy(std.mem.asBytes(&info), body[12..descriptor_row_len]);
    try validateInfo(&info, role, family);
    return .{ .canonical = canonical, .role = role, .shard = shard, .family = family, .transfer = .{ .info = info } };
}

/// Send only to the exact process returned by CreateProcessW. The caller must
/// first quiesce/cancel/drain source I/O, while retaining every original SOCKET
/// and its old IOCP until pre-COMMIT rollback is no longer possible. Any
/// transfer failure aborts/reaps the uncommitted candidate before I/O resumes.
pub fn send(candidate: *process.Process, arena: *const arena_mod.Arena, sealer: *const envelope.Sealer, rows: []const SourceRow, deadline: i64) Error!void {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    if (candidate.committed or candidate.pid == 0 or candidate.pid == GetCurrentProcessId() or
        candidate.process_handle == 0 or GetProcessId(candidate.process_handle) != candidate.pid or
        candidate.endpoint.role != .parent or !std.meta.eql(candidate.endpoint.identity, candidate.identity))
        return error.InvalidCandidate;
    errdefer candidate.deinit();
    // A caller-supplied numeric SOCKET must still be the registry entry whose
    // canonical ID the strict capsule stream will later join.
    for (rows) |row| {
        const owned = io_backend.helixWindowsSourceSocket(row.canonical) catch return error.InvalidManifest;
        if (owned != row.socket) return error.InvalidManifest;
    }
    try sendTo(&candidate.endpoint, candidate.process_handle, candidate.pid, arena, sealer, rows, deadline);
}

fn sendTo(endpoint: *control.Endpoint, target_process: usize, target_pid: u32, arena: *const arena_mod.Arena, sealer: *const envelope.Sealer, rows: []const SourceRow, deadline: i64) Error!void {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    if (target_process == 0 or target_pid == 0 or GetProcessId(target_process) != target_pid or
        endpoint.role != .parent or !sealer.sealed or
        !std.mem.eql(u8, &sealer.upgrade_id, &endpoint.identity.upgrade_id))
        return error.InvalidCandidate;
    try validateSources(rows);
    // The child owns this duplicate. On any later error the public caller
    // terminates/reaps that child; never close a possibly reused remote value.
    const remote_handle = try arena.duplicateReadOnlyForProcess(target_process);
    var arena_body = encodeArenaBody(remote_handle, arena.size, rows.len, sealer.key);
    defer std.crypto.secureZero(u8, &arena_body);
    try endpoint.send(.arena, &arena_body, deadline);
    try awaitAck(endpoint, .arena, 0, rows.len, deadline);

    var start: usize = 0;
    while (true) {
        const count: usize = @min(rows_per_frame, rows.len - start);
        var body: [descriptor_header_len + rows_per_frame * descriptor_row_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &body);
        writeBatchHeader(&body, start, rows.len, count);
        for (rows[start..][0..count], 0..) |row, index| {
            var transfer = try socket_mod.duplicateForProcess(row.socket, target_pid);
            defer std.crypto.secureZero(u8, std.mem.asBytes(&transfer.info));
            try validateInfo(&transfer.info, row.role, row.family);
            const offset = descriptor_header_len + index * descriptor_row_len;
            encodeRow(body[offset..][0..descriptor_row_len], row, &transfer);
        }
        try endpoint.send(.descriptors, body[0 .. descriptor_header_len + count * descriptor_row_len], deadline);
        start += count;
        try awaitAck(endpoint, .descriptors, start, rows.len, deadline);
        if (start == rows.len) break;
    }
}

/// An authenticated, AEAD-opened arena plus unconsumed, PID-scoped socket
/// capabilities. Descriptors are not yet registered or associated with IOCP.
pub const Incoming = struct {
    allocator: std.mem.Allocator,
    identity: control.Identity,
    plaintext: []u8,
    rows: []ReceivedRow,
    stage_attempted: bool = false,
    staged_count: usize = 0,
    release_confirmed: bool = false,

    pub fn deinit(self: *Incoming) void {
        self.rollbackStaged();
        for (self.rows) |*row| std.crypto.secureZero(u8, std.mem.asBytes(&row.transfer.info));
        self.allocator.free(self.rows);
        std.crypto.secureZero(u8, self.plaintext);
        self.allocator.free(self.plaintext);
        self.rows = &.{};
        self.plaintext = &.{};
    }

    /// The exact-ID registry accepts these only before ordinary registrations.
    /// On partial failure, close every staged candidate reference and abort the
    /// candidate process; this same Incoming cannot be staged twice. A later
    /// adoption join must prove listener SO_ACCEPTCONN or connected getpeername
    /// for each declared role before it may emit READY; staging is not that join.
    pub fn stageInert(self: *Incoming) anyerror!void {
        if (comptime builtin.os.tag != .windows) return error.Unsupported;
        if (self.stage_attempted or self.release_confirmed) return error.AlreadyStaged;
        self.stage_attempted = true;
        errdefer self.rollbackStaged();
        for (self.rows) |*row| {
            try io_backend.stageHelixWindowsSocketAtCanonicalId(row.canonical, &row.transfer);
            self.staged_count += 1;
        }
    }

    /// Mark the exact moment a server staging object takes cleanup custody
    /// of one inert canonical socket. The staging object must close this FD
    /// itself on failure, without shutdown; this wrapper will skip it. Call
    /// separately for every listener and client that crosses that boundary.
    pub fn claimStagedForServer(self: *Incoming, canonical: i32) !void {
        if (!self.stage_attempted or self.release_confirmed) return error.InvalidReleaseState;
        for (self.rows[0..self.staged_count]) |*row| {
            if (row.canonical != canonical) continue;
            if (row.server_owned) return error.InvalidReleaseState;
            row.server_owned = true;
            return;
        }
        return error.InvalidSocketId;
    }

    /// Called only after an authenticated COMMIT and a signaled predecessor
    /// process HANDLE with the expected PID. Registry entries remain inert
    /// until the adopter creates its IOCP and submits work. Successful release
    /// transfers cleanup ownership from this wrapper to the descriptor table.
    pub fn releaseAfterWitness(self: *Incoming) anyerror!void {
        if (comptime builtin.os.tag != .windows) return error.Unsupported;
        if (!self.stage_attempted or self.release_confirmed or self.staged_count != self.rows.len)
            return error.InvalidReleaseState;
        for (self.rows) |row| if (!row.server_owned) return error.InvalidReleaseState;
        for (self.rows) |row| try io_backend.confirmHelixPredecessorReleasedWindows(row.canonical);
        self.release_confirmed = true;
        self.staged_count = 0;
    }

    fn rollbackStaged(self: *Incoming) void {
        if (comptime builtin.os.tag != .windows) return;
        while (self.staged_count > 0) {
            self.staged_count -= 1;
            if (self.rows[self.staged_count].server_owned) continue;
            io_backend.discardHelixUnassociatedWindowsSocket(self.rows[self.staged_count].canonical) catch
                @panic("Windows Helix lost staged socket custody before COMMIT");
        }
    }
};

/// Any error is fatal to this inert candidate; it must close the control
/// channel and exit rather than retry a partially consumed transfer.
pub fn receive(allocator: std.mem.Allocator, endpoint: *control.Endpoint, deadline: i64) Error!Incoming {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    if (endpoint.role != .child) return error.InvalidCandidate;
    var arena_message = try endpoint.receive(deadline);
    defer arena_message.deinit();
    if (arena_message.kind != .arena) return error.InvalidManifest;
    var header = try parseArenaBody(arena_message.bytes());
    defer std.crypto.secureZero(u8, &header.key);
    defer _ = CloseHandle(header.handle);
    const plaintext = try arena_mod.read(allocator, header.handle, header.size, header.key, endpoint.identity.upgrade_id);
    errdefer {
        std.crypto.secureZero(u8, plaintext);
        allocator.free(plaintext);
    }
    const rows = try allocator.alloc(ReceivedRow, header.total);
    var accepted: usize = 0;
    errdefer {
        for (rows[0..accepted]) |*row| std.crypto.secureZero(u8, std.mem.asBytes(&row.transfer.info));
        allocator.free(rows);
    }
    try sendAck(endpoint, .arena, 0, header.total, deadline);

    var listeners: usize = 0;
    var clients: usize = 0;
    var last: i32 = 0;
    while (true) {
        var batch = try endpoint.receive(deadline);
        defer batch.deinit();
        if (batch.kind != .descriptors) return error.InvalidManifest;
        const body = batch.bytes();
        const count = try validateBatchHeader(body, accepted, header.total);
        for (0..count) |index| {
            const offset = descriptor_header_len + index * descriptor_row_len;
            const row = try decodeRow(body[offset..][0..descriptor_row_len], last);
            if (isListener(row.role)) listeners += 1 else clients += 1;
            if (listeners > max_listeners or clients > max_clients) return error.TooLarge;
            rows[accepted] = row;
            accepted += 1;
            last = row.canonical;
        }
        try sendAck(endpoint, .descriptors, accepted, header.total, deadline);
        if (accepted == header.total) break;
    }
    return .{ .allocator = allocator, .identity = endpoint.identity, .plaintext = plaintext, .rows = rows };
}

test "Windows Helix typed record rejects malformed, duplicate and out-of-order socket IDs" {
    var info = std.mem.zeroes(socket_mod.ProtocolInfo);
    info.address_family = 2;
    info.socket_type = 1;
    info.protocol = 6;
    const source = SourceRow{ .canonical = 7, .socket = 123, .role = .plain_listener, .family = 4 };
    try validateSources(&.{source});
    try std.testing.expectError(error.InvalidManifest, validateSources(&.{ source, source }));
    try std.testing.expectError(error.InvalidManifest, validateSources(&.{ source, .{ .canonical = 6, .socket = 124, .role = .client } }));
    try std.testing.expectError(error.InvalidManifest, validateSources(&.{.{ .canonical = 0, .socket = 123, .role = .client }}));
    try std.testing.expectError(error.InvalidManifest, validateSources(&.{.{ .canonical = 0x4000_0000, .socket = 123, .role = .client }}));
    try std.testing.expectError(error.InvalidManifest, validateSources(&.{.{ .canonical = 7, .socket = 123, .role = .plain_listener, .family = 0 }}));
    var wire: [descriptor_row_len]u8 = undefined;
    const transfer = socket_mod.Transfer{ .info = info };
    encodeRow(&wire, source, &transfer);
    try std.testing.expectEqual(@as(i32, 7), (try decodeRow(&wire, 0)).canonical);
    try std.testing.expectError(error.InvalidManifest, decodeRow(&wire, 7));
    wire[8] = 2;
    try std.testing.expectError(error.InvalidManifest, decodeRow(&wire, 0));
    wire[8] = 1;
    wire[6] = 255;
    try std.testing.expectError(error.InvalidManifest, decodeRow(&wire, 0));
}

test "Windows Helix transfer header bounds precede mapping and socket allocation" {
    const minimum = envelope.header_len + envelope.tag_len;
    var arena_body = encodeArenaBody(1, minimum, max_sockets, @splat(3));
    try std.testing.expectEqual(@as(usize, max_sockets), (try parseArenaBody(&arena_body)).total);
    std.mem.writeInt(u32, arena_body[24..28], max_sockets + 1, .big);
    try std.testing.expectError(error.InvalidManifest, parseArenaBody(&arena_body));
    std.mem.writeInt(u32, arena_body[24..28], 0, .big);
    std.mem.writeInt(u64, arena_body[16..24], minimum - 1, .big);
    try std.testing.expectError(error.InvalidManifest, parseArenaBody(&arena_body));
    std.mem.writeInt(u64, arena_body[16..24], minimum, .big);
    std.mem.writeInt(u64, arena_body[8..16], 0, .big);
    try std.testing.expectError(error.InvalidManifest, parseArenaBody(&arena_body));

    var batch: [descriptor_header_len + rows_per_frame * descriptor_row_len]u8 = @splat(0);
    writeBatchHeader(&batch, 0, 4, 3);
    try std.testing.expectEqual(@as(usize, 3), try validateBatchHeader(&batch, 0, 4));
    try std.testing.expectError(error.InvalidManifest, validateBatchHeader(&batch, 1, 4));
    std.mem.writeInt(u16, batch[16..18], 4, .big);
    try std.testing.expectError(error.InvalidManifest, validateBatchHeader(&batch, 0, 4));
    std.mem.writeInt(u16, batch[16..18], 3, .big);
    batch[19] = 1;
    try std.testing.expectError(error.InvalidManifest, validateBatchHeader(&batch, 0, 4));
}

test "Windows Helix authenticated arena frame refuses a wrong decryption key" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var pair = try control.Pair.init();
    defer pair.deinit();
    const identity: control.Identity = .{ .generation = 20, .upgrade_id = @splat(6) };
    var sender = pair.takeParent(identity, @splat(7));
    defer sender.deinit();
    var receiver = pair.takeChild(identity, @splat(7));
    defer receiver.deinit();
    var sealer = try envelope.Sealer.initRandom();
    defer sealer.deinit();
    sealer.upgrade_id = identity.upgrade_id;
    var arena = try arena_mod.Arena.create(std.testing.allocator, &sealer, "secret capsule");
    defer arena.deinit();
    const remote = try arena.duplicateReadOnlyForProcess(GetCurrentProcess());
    const body = encodeArenaBody(remote, arena.size, 0, @splat(0));
    try sender.send(.arena, &body, platform.monotonicMillis() + 1000);
    try std.testing.expectError(error.AuthenticationFailed, receive(std.testing.allocator, &receiver, platform.monotonicMillis() + 1000));
}

test "Windows Helix authenticated transfer opens one arena and multiple indexed TCP batches" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    try testWinsockStart();
    defer testWinsockStop();
    var pair = try control.Pair.init();
    defer pair.deinit();
    const identity: control.Identity = .{ .generation = 19, .upgrade_id = @splat(8) };
    var sender = pair.takeParent(identity, @splat(9));
    defer sender.deinit();
    var receiver = pair.takeChild(identity, @splat(9));
    defer receiver.deinit();
    var sealer = try envelope.Sealer.initRandom();
    defer sealer.deinit();
    sealer.upgrade_id = identity.upgrade_id;
    var arena = try arena_mod.Arena.create(allocator, &sealer, "strict capsule bytes");
    defer arena.deinit();
    var raw: [4]usize = undefined;
    var created: usize = 0;
    defer {
        for (raw[0..created]) |socket| testCloseSocket(socket);
    }
    for (&raw) |*socket| {
        socket.* = try testTcpSocket();
        created += 1;
    }
    const sources = [_]SourceRow{
        .{ .canonical = 11, .socket = raw[0], .role = .plain_listener, .family = 4 },
        .{ .canonical = 13, .socket = raw[1], .role = .client },
        .{ .canonical = 14, .socket = raw[2], .role = .s2s_state },
        .{ .canonical = 19, .socket = raw[3], .role = .tls_listener, .family = 4 },
    };
    const Runner = struct {
        endpoint: *control.Endpoint,
        result: ?Incoming = null,
        failure: ?anyerror = null,
        fn run(self: *@This()) void {
            self.result = receive(std.testing.allocator, self.endpoint, platform.monotonicMillis() + 3000) catch |err| {
                self.failure = err;
                return;
            };
        }
    };
    var runner = Runner{ .endpoint = &receiver };
    const thread = try std.Thread.spawn(.{}, Runner.run, .{&runner});
    const sending = sendTo(&sender, GetCurrentProcess(), GetCurrentProcessId(), &arena, &sealer, &sources, platform.monotonicMillis() + 3000);
    thread.join();
    try sending;
    if (runner.failure) |err| return err;
    var incoming = runner.result orelse return error.InvalidManifest;
    defer incoming.deinit();
    try std.testing.expectEqualStrings("strict capsule bytes", incoming.plaintext);
    try std.testing.expectEqual(@as(usize, 4), incoming.rows.len);
    try std.testing.expectEqual(@as(i32, 11), incoming.rows[0].canonical);
    try std.testing.expectEqual(@as(i32, 19), incoming.rows[3].canonical);
    for (incoming.rows, 0..) |*row, index| {
        const imported = try row.transfer.import();
        defer testCloseSocket(imported);
        try std.testing.expect(imported != raw[index]);
        try std.testing.expectError(error.AlreadyConsumed, row.transfer.import());
    }
}

test "Windows Helix authenticated transfer accepts an empty descriptor batch" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var pair = try control.Pair.init();
    defer pair.deinit();
    const identity: control.Identity = .{ .generation = 20, .upgrade_id = @splat(10) };
    var sender = pair.takeParent(identity, @splat(11));
    defer sender.deinit();
    var receiver = pair.takeChild(identity, @splat(11));
    defer receiver.deinit();
    var sealer = try envelope.Sealer.initRandom();
    defer sealer.deinit();
    sealer.upgrade_id = identity.upgrade_id;
    var arena = try arena_mod.Arena.create(allocator, &sealer, "empty strict state");
    defer arena.deinit();
    const Runner = struct {
        endpoint: *control.Endpoint,
        result: ?Incoming = null,
        failure: ?anyerror = null,
        fn run(self: *@This()) void {
            self.result = receive(std.testing.allocator, self.endpoint, platform.monotonicMillis() + 3000) catch |err| {
                self.failure = err;
                return;
            };
        }
    };
    var runner = Runner{ .endpoint = &receiver };
    const thread = try std.Thread.spawn(.{}, Runner.run, .{&runner});
    const sending = sendTo(&sender, GetCurrentProcess(), GetCurrentProcessId(), &arena, &sealer, &.{}, platform.monotonicMillis() + 3000);
    thread.join();
    try sending;
    if (runner.failure) |err| return err;
    var incoming = runner.result orelse return error.InvalidManifest;
    defer incoming.deinit();
    try std.testing.expectEqualStrings("empty strict state", incoming.plaintext);
    try std.testing.expectEqual(@as(usize, 0), incoming.rows.len);
    try std.testing.expect(receiver.awaiting_response);
    try std.testing.expect(!sender.awaiting_response);
}

extern "ws2_32" fn WSAStartup(version: u16, data: *[408]u8) callconv(.winapi) i32;
extern "ws2_32" fn WSACleanup() callconv(.winapi) i32;
extern "ws2_32" fn WSASocketW(family: i32, kind: i32, protocol: i32, info: ?*anyopaque, group: u32, flags: u32) callconv(.winapi) usize;
extern "ws2_32" fn closesocket(socket: usize) callconv(.winapi) i32;

fn testWinsockStart() !void {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    var startup: [408]u8 = @splat(0);
    if (WSAStartup(0x0202, &startup) != 0) return error.SocketCreationFailed;
}

fn testWinsockStop() void {
    if (comptime builtin.os.tag == .windows) _ = WSACleanup();
}

fn testTcpSocket() !usize {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    const raw = WSASocketW(2, 1, 6, null, 0, 1 | 0x80);
    if (raw == invalid_socket) return error.SocketCreationFailed;
    return raw;
}

fn testCloseSocket(socket: usize) void {
    if (comptime builtin.os.tag == .windows) _ = closesocket(socket);
}
