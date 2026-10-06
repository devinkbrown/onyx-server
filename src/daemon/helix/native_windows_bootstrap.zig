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
const wal_mod = @import("native_windows_wal.zig");
const metrics_mod = @import("native_windows_metrics.zig");
const webhook_mod = @import("native_windows_webhook.zig");
const history_mod = @import("native_windows_history.zig");
const udp_mod = @import("native_windows_udp_custody.zig");
const media_mod = @import("native_windows_media_custody.zig");
const active_udp_mod = @import("native_windows_active_media_udp_custody.zig");
const active_wt_mod = @import("native_windows_active_webtransport_custody.zig");
const active_wt_codec = @import("native_windows_active_webtransport_snapshot.zig");
const webtransport_listener = @import("../webtransport_listener.zig");
const media_graph = @import("media_graph_checkpoint.zig");
const media_physical = @import("native_windows_active_media_snapshot.zig");
const native_media = @import("../native_media_transport.zig");
const webrtc_media = @import("../media_plane.zig");
const store = @import("../store.zig");

pub const max_listeners = @import("live.zig").max_inherited_listeners;
pub const max_clients = @import("live.zig").max_inherited_state_fds;
pub const max_sockets = max_listeners + max_clients;
pub const rows_per_frame = 3;
pub const arena_body_len = 64;
pub const descriptor_header_len = 20;
pub const descriptor_row_len = 640;
pub const ack_body_len = 16;
pub const wal_body_len = wal_mod.body_len;
pub const source_digest_body_len = 40;
pub const metrics_body_len = metrics_mod.frame_len;
pub const webhook_body_len = webhook_mod.frame_len;
pub const history_body_len = history_mod.frame_len;
pub const udp_body_len = udp_mod.frame_len;
pub const media_body_len = media_mod.frame_len;
pub const active_media_udp_body_len = active_udp_mod.frame_len;
pub const active_webtransport_body_len = active_wt_mod.frame_len;
const version: u16 = 1;
const max_canonical_id: i32 = 0x3fff_ffff;
const invalid_socket = std.math.maxInt(usize);
const arena_magic = "HXWA";
const descriptors_magic = "HXWD";
const ack_magic = "HXWK";
const source_digest_magic = "HXWS";

comptime {
    if (descriptor_header_len + rows_per_frame * descriptor_row_len > control.max_body or
        source_digest_body_len > control.max_body or metrics_body_len > control.max_body or
        webhook_body_len > control.max_body or history_body_len > control.max_body or
        udp_body_len > control.max_body or media_body_len > control.max_body or active_media_udp_body_len > control.max_body or active_webtransport_body_len > control.max_body or
        descriptor_row_len != 12 + @sizeOf(socket_mod.ProtocolInfo))
        @compileError("Windows Helix descriptor frame exceeds the authenticated control body");
}

extern "kernel32" fn GetCurrentProcess() callconv(.winapi) usize;
extern "kernel32" fn GetCurrentProcessId() callconv(.winapi) u32;
extern "kernel32" fn GetProcessId(handle: usize) callconv(.winapi) u32;
extern "kernel32" fn CloseHandle(handle: usize) callconv(.winapi) i32;

pub const Error = control.Error || arena_mod.Error || socket_mod.Error || wal_mod.Error || metrics_mod.Error || webhook_mod.Error || history_mod.Error || udp_mod.Error || media_mod.Error || active_udp_mod.Error || active_wt_mod.Error || error{
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

const AckPhase = enum(u16) { arena = 1, descriptors = 2, wal_custody = 3, source_digest = 4, metrics_custody = 5, webhook_custody = 6, history_custody = 7, udp_custody = 8, media_custody = 9, webtransport_custody = 10, active_media_udp_custody = 11 };

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
    if (reply.kind == .abort) {
        std.debug.print("onyx-server: Windows Helix candidate rejected transfer: {s}\n", .{reply.bytes()});
        return error.InvalidCandidate;
    }
    const expected = ackBody(phase, next_index, total);
    if (reply.kind != .ack or !std.mem.eql(u8, reply.bytes(), &expected)) return error.InvalidAck;
}

fn sendAck(endpoint: *control.Endpoint, phase: AckPhase, next_index: usize, total: usize, deadline: i64) Error!void {
    const body = ackBody(phase, next_index, total);
    try endpoint.send(.ack, &body, deadline);
}

fn sourceDigestBody(digest: [32]u8) [source_digest_body_len]u8 {
    var body: [source_digest_body_len]u8 = @splat(0);
    @memcpy(body[0..4], source_digest_magic);
    std.mem.writeInt(u16, body[4..6], version, .big);
    @memcpy(body[8..40], &digest);
    return body;
}

fn parseSourceDigestBody(body: []const u8) Error![32]u8 {
    if (body.len != source_digest_body_len or
        !std.mem.eql(u8, body[0..4], source_digest_magic) or
        std.mem.readInt(u16, body[4..6], .big) != version or
        std.mem.readInt(u16, body[6..8], .big) != 0) return error.InvalidManifest;
    return body[8..40].*;
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
    const descriptor = try sendWithWal(candidate, arena, sealer, rows, null, deadline);
    std.debug.assert(descriptor == null);
}

/// `wal_transfer` is created from the quiesced, already-open private account
/// WAL with the exact spawned child process HANDLE. A successful source ACK
/// transfers close responsibility to the candidate and returns the witness
/// needed to bind READY to the complete handoff. The caller retains rollback
/// custody on every error and must abort/reap the child before resuming I/O.
pub fn sendWithWal(candidate: *process.Process, arena: *const arena_mod.Arena, sealer: *const envelope.Sealer, rows: []const SourceRow, wal_transfer: ?*store.WindowsWalTransfer, deadline: i64) Error!?store.WindowsWalDescriptor {
    return (try sendWithWalImpl(candidate, arena, sealer, rows, wal_transfer, @splat(0), null, null, null, false, deadline)).wal;
}

/// Production transfer binds the eventual READY challenge to a nonzero
/// digest of the source snapshot. The digest is a separate authenticated,
/// acknowledged turn after WAL custody; a child never reaches READY before
/// it has both values. The zero-digest wrapper above remains for substrate
/// tests that do not have a source snapshot.
pub fn sendWithWalDigest(candidate: *process.Process, arena: *const arena_mod.Arena, sealer: *const envelope.Sealer, rows: []const SourceRow, wal_transfer: ?*store.WindowsWalTransfer, expected_digest: [32]u8, deadline: i64) Error!?store.WindowsWalDescriptor {
    return (try sendWithWalImpl(candidate, arena, sealer, rows, wal_transfer, expected_digest, null, null, null, true, deadline)).wal;
}

pub const SentCustody = struct {
    wal: ?store.WindowsWalDescriptor,
    /// Exactly the authenticated frame ACKed by the candidate, including the
    /// source snapshot digest. READY must hash this immutable copy.
    metrics_body: metrics_mod.Frame,
    /// Exact authenticated webhook custody bytes retained across socket import.
    webhook_body: webhook_mod.Frame,
    /// Exact authenticated history listener bytes retained across socket import.
    history_body: history_mod.Frame,
    webtransport_udp_body: udp_mod.Frame,
    webrtc_media_udp_body: udp_mod.Frame,
    native_media_udp_body: udp_mod.Frame,
    media_graph_body: media_mod.Frame,
    native_physical_body: media_mod.Frame,
    webrtc_physical_body: media_mod.Frame,
    active_native_udp_body: active_udp_mod.Frame,
    active_webrtc_udp_body: active_udp_mod.Frame,
    active_webtransport_body: active_wt_mod.Frame,
};

pub const UdpPrepared = struct {
    webtransport: ?*const udp_mod.Prepared = null,
    webrtc_media: ?*const udp_mod.Prepared = null,
    native_media: ?*const udp_mod.Prepared = null,
};

/// Active media is one optional aggregate. Supplying only one or two leaves
/// would make a candidate READY witness that cannot describe a complete cut.
pub const MediaPrepared = struct {
    graph: ?*const media_mod.Prepared = null,
    native_physical: ?*const media_mod.Prepared = null,
    webrtc_physical: ?*const media_mod.Prepared = null,
};

pub const ActiveMediaUdpPrepared = struct {
    native: ?*const active_udp_mod.Prepared = null,
    webrtc: ?*const active_udp_mod.Prepared = null,
};

fn validateMediaAggregate(graph_body: *const media_mod.Frame, native_body: *const media_mod.Frame, webrtc_body: *const media_mod.Frame, target_pid: u32) Error!bool {
    const graph_present = try media_mod.validateFrame(graph_body, .graph, target_pid);
    const native_present = try media_mod.validateFrame(native_body, .native_physical, target_pid);
    const webrtc_present = try media_mod.validateFrame(webrtc_body, .webrtc_physical, target_pid);
    if (graph_present != native_present or graph_present != webrtc_present) return error.InvalidManifest;
    if (graph_present) {
        const handles = [_]u64{
            std.mem.readInt(u64, graph_body[16..24], .big),
            std.mem.readInt(u64, native_body[16..24], .big),
            std.mem.readInt(u64, webrtc_body[16..24], .big),
        };
        if (handles[0] == handles[1] or handles[0] == handles[2] or handles[1] == handles[2])
            return error.InvalidManifest;
    }
    return graph_present;
}

fn validateActiveMediaUdpAggregate(native_udp: *const active_udp_mod.Frame, webrtc_udp: *const active_udp_mod.Frame, media_present: bool, native_physical_frame: *const media_mod.Frame, webrtc_physical_frame: *const media_mod.Frame, idle_webrtc: *const udp_mod.Frame, idle_native: *const udp_mod.Frame, target_pid: u32) Error!void {
    const native_present = try active_udp_mod.validateFrame(native_udp, .native, target_pid);
    const webrtc_present = try active_udp_mod.validateFrame(webrtc_udp, .webrtc, target_pid);
    if (native_present != media_present or webrtc_present != media_present) return error.InvalidManifest;
    if (!media_present) return;
    if (try udp_mod.validateFrame(idle_webrtc, .media, target_pid) or
        try udp_mod.validateFrame(idle_native, .native_media, target_pid)) return error.InvalidManifest;
    const handles = [_]u64{
        std.mem.readInt(u64, native_physical_frame[16..24], .big),
        std.mem.readInt(u64, webrtc_physical_frame[16..24], .big),
        std.mem.readInt(u64, native_udp[16..24], .big),
        std.mem.readInt(u64, webrtc_udp[16..24], .big),
    };
    for (handles, 0..) |handle, i| for (handles[i + 1 ..]) |other| if (handle == other) return error.InvalidManifest;
    const native_socket = std.mem.readInt(u64, native_udp[active_udp_mod.frame_len - @import("native_windows_udp_socket.zig").frame_len + 12 ..][0..8], .big);
    const webrtc_socket = std.mem.readInt(u64, webrtc_udp[active_udp_mod.frame_len - @import("native_windows_udp_socket.zig").frame_len + 12 ..][0..8], .big);
    if (native_socket == webrtc_socket) return error.InvalidManifest;
}

/// Production variant with optional metrics listener custody. A canonical
/// absent frame is still sent when metrics is disabled so the child cannot
/// confuse a missing turn with a complete transfer.
pub fn sendWithWalDigestAndMetrics(candidate: *process.Process, arena: *const arena_mod.Arena, sealer: *const envelope.Sealer, rows: []const SourceRow, wal_transfer: ?*store.WindowsWalTransfer, expected_digest: [32]u8, metrics_prepared: ?*const metrics_mod.Prepared, deadline: i64) Error!SentCustody {
    return sendWithWalImpl(candidate, arena, sealer, rows, wal_transfer, expected_digest, metrics_prepared, null, null, true, deadline);
}

/// Production path for both standalone HTTP listeners. Each sends one
/// canonical present-or-absent frame and waits for its own authenticated ACK.
pub fn sendWithWalDigestMetricsAndWebhook(candidate: *process.Process, arena: *const arena_mod.Arena, sealer: *const envelope.Sealer, rows: []const SourceRow, wal_transfer: ?*store.WindowsWalTransfer, expected_digest: [32]u8, metrics_prepared: ?*const metrics_mod.Prepared, webhook_prepared: ?*const webhook_mod.Prepared, deadline: i64) Error!SentCustody {
    return sendWithWalImpl(candidate, arena, sealer, rows, wal_transfer, expected_digest, metrics_prepared, webhook_prepared, null, true, deadline);
}

pub fn sendWithWalDigestMetricsWebhookAndHistory(candidate: *process.Process, arena: *const arena_mod.Arena, sealer: *const envelope.Sealer, rows: []const SourceRow, wal_transfer: ?*store.WindowsWalTransfer, expected_digest: [32]u8, metrics_prepared: ?*const metrics_mod.Prepared, webhook_prepared: ?*const webhook_mod.Prepared, history_prepared: ?*const history_mod.Prepared, deadline: i64) Error!SentCustody {
    return sendWithWalImpl(candidate, arena, sealer, rows, wal_transfer, expected_digest, metrics_prepared, webhook_prepared, history_prepared, true, deadline);
}

/// Three ordered, explicit present-or-absent UDP turns follow all TCP and
/// companion custody. READY binds their exact authenticated bodies.
pub fn sendWithWalDigestMetricsWebhookHistoryAndUdp(candidate: *process.Process, arena: *const arena_mod.Arena, sealer: *const envelope.Sealer, rows: []const SourceRow, wal_transfer: ?*store.WindowsWalTransfer, expected_digest: [32]u8, metrics_prepared: ?*const metrics_mod.Prepared, webhook_prepared: ?*const webhook_mod.Prepared, history_prepared: ?*const history_mod.Prepared, udp: UdpPrepared, deadline: i64) Error!SentCustody {
    return sendWithWalImplUdpMedia(candidate, arena, sealer, rows, wal_transfer, expected_digest, metrics_prepared, webhook_prepared, history_prepared, udp, .{}, .{}, null, true, deadline);
}

pub fn sendWithWalDigestMetricsWebhookHistoryUdpAndMedia(candidate: *process.Process, arena: *const arena_mod.Arena, sealer: *const envelope.Sealer, rows: []const SourceRow, wal_transfer: ?*store.WindowsWalTransfer, expected_digest: [32]u8, metrics_prepared: ?*const metrics_mod.Prepared, webhook_prepared: ?*const webhook_mod.Prepared, history_prepared: ?*const history_mod.Prepared, udp: UdpPrepared, media: MediaPrepared, deadline: i64) Error!SentCustody {
    return sendWithWalImplUdpMedia(candidate, arena, sealer, rows, wal_transfer, expected_digest, metrics_prepared, webhook_prepared, history_prepared, udp, media, .{}, null, true, deadline);
}

pub fn sendWithWalDigestMetricsWebhookHistoryUdpMediaAndActiveWebtransport(candidate: *process.Process, arena: *const arena_mod.Arena, sealer: *const envelope.Sealer, rows: []const SourceRow, wal_transfer: ?*store.WindowsWalTransfer, expected_digest: [32]u8, metrics_prepared: ?*const metrics_mod.Prepared, webhook_prepared: ?*const webhook_mod.Prepared, history_prepared: ?*const history_mod.Prepared, udp: UdpPrepared, media: MediaPrepared, active_webtransport: ?*const active_wt_mod.Prepared, deadline: i64) Error!SentCustody {
    return sendWithWalImplUdpMedia(candidate, arena, sealer, rows, wal_transfer, expected_digest, metrics_prepared, webhook_prepared, history_prepared, udp, media, .{}, active_webtransport, true, deadline);
}

pub fn sendWithWalDigestMetricsWebhookHistoryUdpMediaAndActiveTransfers(candidate: *process.Process, arena: *const arena_mod.Arena, sealer: *const envelope.Sealer, rows: []const SourceRow, wal_transfer: ?*store.WindowsWalTransfer, expected_digest: [32]u8, metrics_prepared: ?*const metrics_mod.Prepared, webhook_prepared: ?*const webhook_mod.Prepared, history_prepared: ?*const history_mod.Prepared, udp: UdpPrepared, media: MediaPrepared, active_udp: ActiveMediaUdpPrepared, active_webtransport: ?*const active_wt_mod.Prepared, deadline: i64) Error!SentCustody {
    return sendWithWalImplUdpMedia(candidate, arena, sealer, rows, wal_transfer, expected_digest, metrics_prepared, webhook_prepared, history_prepared, udp, media, active_udp, active_webtransport, true, deadline);
}

fn sendWithWalImpl(candidate: *process.Process, arena: *const arena_mod.Arena, sealer: *const envelope.Sealer, rows: []const SourceRow, wal_transfer: ?*store.WindowsWalTransfer, expected_digest: [32]u8, metrics_prepared: ?*const metrics_mod.Prepared, webhook_prepared: ?*const webhook_mod.Prepared, history_prepared: ?*const history_mod.Prepared, require_nonzero_digest: bool, deadline: i64) Error!SentCustody {
    return sendWithWalImplUdpMedia(candidate, arena, sealer, rows, wal_transfer, expected_digest, metrics_prepared, webhook_prepared, history_prepared, .{}, .{}, .{}, null, require_nonzero_digest, deadline);
}

fn sendWithWalImplUdpMedia(candidate: *process.Process, arena: *const arena_mod.Arena, sealer: *const envelope.Sealer, rows: []const SourceRow, wal_transfer: ?*store.WindowsWalTransfer, expected_digest: [32]u8, metrics_prepared: ?*const metrics_mod.Prepared, webhook_prepared: ?*const webhook_mod.Prepared, history_prepared: ?*const history_mod.Prepared, udp: UdpPrepared, media: MediaPrepared, active_udp: ActiveMediaUdpPrepared, active_webtransport: ?*const active_wt_mod.Prepared, require_nonzero_digest: bool, deadline: i64) Error!SentCustody {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    if (candidate.committed or candidate.pid == 0 or candidate.pid == GetCurrentProcessId() or
        candidate.process_handle == 0 or GetProcessId(candidate.process_handle) != candidate.pid or
        candidate.endpoint.role != .parent or !std.meta.eql(candidate.endpoint.identity, candidate.identity))
        return error.InvalidCandidate;
    // The caller owns candidate abort. Closing its process HANDLE here would
    // invalidate a pending WAL rollback duplicate that still targets it.
    if (require_nonzero_digest) {
        var nonzero = false;
        for (expected_digest) |byte| nonzero = nonzero or byte != 0;
        if (!nonzero) return error.InvalidManifest;
    }
    // A caller-supplied numeric SOCKET must still be the registry entry whose
    // canonical ID the strict capsule stream will later join.
    for (rows) |row| {
        const owned = io_backend.helixWindowsSourceSocket(row.canonical) catch return error.InvalidManifest;
        if (owned != row.socket) return error.InvalidManifest;
    }
    const metrics_body = if (metrics_prepared) |prepared| prepared.body else metrics_mod.absentFrame();
    if ((try metrics_mod.parseFrame(&metrics_body, candidate.pid, &.{})) == null and metrics_prepared != null)
        return error.InvalidManifest;
    const webhook_body = if (webhook_prepared) |prepared| prepared.body else webhook_mod.absentFrame();
    if ((try webhook_mod.parseFrame(&webhook_body, candidate.pid)) == null and webhook_prepared != null)
        return error.InvalidManifest;
    const history_body = if (history_prepared) |prepared| prepared.body else history_mod.absentFrame();
    if ((try history_mod.parseFrame(&history_body, candidate.pid)) == null and history_prepared != null)
        return error.InvalidManifest;
    const wt_body = if (udp.webtransport) |prepared| prepared.body else udp_mod.absentFrame(.webtransport);
    const webrtc_body = if (udp.webrtc_media) |prepared| prepared.body else udp_mod.absentFrame(.media);
    const native_body = if (udp.native_media) |prepared| prepared.body else udp_mod.absentFrame(.native_media);
    if ((try udp_mod.validateFrame(&wt_body, .webtransport, candidate.pid)) != (udp.webtransport != null) or
        (try udp_mod.validateFrame(&webrtc_body, .media, candidate.pid)) != (udp.webrtc_media != null) or
        (try udp_mod.validateFrame(&native_body, .native_media, candidate.pid)) != (udp.native_media != null))
        return error.InvalidManifest;
    const media_body = if (media.graph) |prepared| prepared.body else media_mod.absentFrame(.graph);
    const native_physical_body = if (media.native_physical) |prepared| prepared.body else media_mod.absentFrame(.native_physical);
    const webrtc_physical_body = if (media.webrtc_physical) |prepared| prepared.body else media_mod.absentFrame(.webrtc_physical);
    const media_present = try validateMediaAggregate(&media_body, &native_physical_body, &webrtc_physical_body, candidate.pid);
    if ((media.graph != null) != (media.native_physical != null) or
        (media.graph != null) != (media.webrtc_physical != null) or
        (try media_mod.validateFrame(&media_body, .graph, candidate.pid)) != (media.graph != null))
        return error.InvalidManifest;
    const active_native_udp_body = if (active_udp.native) |prepared| prepared.body else active_udp_mod.absentFrame(.native);
    const active_webrtc_udp_body = if (active_udp.webrtc) |prepared| prepared.body else active_udp_mod.absentFrame(.webrtc);
    try validateActiveMediaUdpAggregate(&active_native_udp_body, &active_webrtc_udp_body, media_present, &native_physical_body, &webrtc_physical_body, &webrtc_body, &native_body, candidate.pid);
    if ((active_udp.native != null) != media_present or (active_udp.webrtc != null) != media_present)
        return error.InvalidManifest;
    const active_body = if (active_webtransport) |prepared| prepared.body else active_wt_mod.absentFrame();
    if ((try active_wt_mod.validateFrame(&active_body, candidate.pid)) != (active_webtransport != null) or
        (active_webtransport != null and udp.webtransport != null)) return error.InvalidManifest;
    return sendToWithWalDigestMetricsWebhookHistoryUdpMediaAndActiveWebtransport(&candidate.endpoint, candidate.process_handle, candidate.pid, arena, sealer, rows, wal_transfer, expected_digest, metrics_body, webhook_body, history_body, wt_body, webrtc_body, native_body, media_body, native_physical_body, webrtc_physical_body, active_native_udp_body, active_webrtc_udp_body, active_body, deadline);
}

fn sendTo(endpoint: *control.Endpoint, target_process: usize, target_pid: u32, arena: *const arena_mod.Arena, sealer: *const envelope.Sealer, rows: []const SourceRow, deadline: i64) Error!void {
    const descriptor = try sendToWithWal(endpoint, target_process, target_pid, arena, sealer, rows, null, deadline);
    std.debug.assert(descriptor == null);
}

fn sendToWithWal(endpoint: *control.Endpoint, target_process: usize, target_pid: u32, arena: *const arena_mod.Arena, sealer: *const envelope.Sealer, rows: []const SourceRow, wal_transfer: ?*store.WindowsWalTransfer, deadline: i64) Error!?store.WindowsWalDescriptor {
    return sendToWithWalDigest(endpoint, target_process, target_pid, arena, sealer, rows, wal_transfer, @splat(0), deadline);
}

fn sendToWithWalDigest(endpoint: *control.Endpoint, target_process: usize, target_pid: u32, arena: *const arena_mod.Arena, sealer: *const envelope.Sealer, rows: []const SourceRow, wal_transfer: ?*store.WindowsWalTransfer, expected_digest: [32]u8, deadline: i64) Error!?store.WindowsWalDescriptor {
    return (try sendToWithWalDigestAndMetrics(endpoint, target_process, target_pid, arena, sealer, rows, wal_transfer, expected_digest, metrics_mod.absentFrame(), deadline)).wal;
}

fn sendToWithWalDigestAndMetrics(endpoint: *control.Endpoint, target_process: usize, target_pid: u32, arena: *const arena_mod.Arena, sealer: *const envelope.Sealer, rows: []const SourceRow, wal_transfer: ?*store.WindowsWalTransfer, expected_digest: [32]u8, metrics_body: metrics_mod.Frame, deadline: i64) Error!SentCustody {
    return sendToWithWalDigestMetricsAndWebhook(endpoint, target_process, target_pid, arena, sealer, rows, wal_transfer, expected_digest, metrics_body, webhook_mod.absentFrame(), deadline);
}

fn sendToWithWalDigestMetricsAndWebhook(endpoint: *control.Endpoint, target_process: usize, target_pid: u32, arena: *const arena_mod.Arena, sealer: *const envelope.Sealer, rows: []const SourceRow, wal_transfer: ?*store.WindowsWalTransfer, expected_digest: [32]u8, metrics_body: metrics_mod.Frame, webhook_body: webhook_mod.Frame, deadline: i64) Error!SentCustody {
    return sendToWithWalDigestMetricsWebhookAndHistory(endpoint, target_process, target_pid, arena, sealer, rows, wal_transfer, expected_digest, metrics_body, webhook_body, history_mod.absentFrame(), deadline);
}

fn sendToWithWalDigestMetricsWebhookAndHistory(endpoint: *control.Endpoint, target_process: usize, target_pid: u32, arena: *const arena_mod.Arena, sealer: *const envelope.Sealer, rows: []const SourceRow, wal_transfer: ?*store.WindowsWalTransfer, expected_digest: [32]u8, metrics_body: metrics_mod.Frame, webhook_body: webhook_mod.Frame, history_body: history_mod.Frame, deadline: i64) Error!SentCustody {
    return sendToWithWalDigestMetricsWebhookHistoryAndUdp(endpoint, target_process, target_pid, arena, sealer, rows, wal_transfer, expected_digest, metrics_body, webhook_body, history_body, udp_mod.absentFrame(.webtransport), udp_mod.absentFrame(.media), udp_mod.absentFrame(.native_media), deadline);
}

fn sendToWithWalDigestMetricsWebhookHistoryAndUdp(endpoint: *control.Endpoint, target_process: usize, target_pid: u32, arena: *const arena_mod.Arena, sealer: *const envelope.Sealer, rows: []const SourceRow, wal_transfer: ?*store.WindowsWalTransfer, expected_digest: [32]u8, metrics_body: metrics_mod.Frame, webhook_body: webhook_mod.Frame, history_body: history_mod.Frame, wt_body: udp_mod.Frame, webrtc_body: udp_mod.Frame, native_body: udp_mod.Frame, deadline: i64) Error!SentCustody {
    return sendToWithWalDigestMetricsWebhookHistoryUdpAndMedia(endpoint, target_process, target_pid, arena, sealer, rows, wal_transfer, expected_digest, metrics_body, webhook_body, history_body, wt_body, webrtc_body, native_body, media_mod.absentFrame(.graph), media_mod.absentFrame(.native_physical), media_mod.absentFrame(.webrtc_physical), deadline);
}

fn sendToWithWalDigestMetricsWebhookHistoryUdpAndMedia(endpoint: *control.Endpoint, target_process: usize, target_pid: u32, arena: *const arena_mod.Arena, sealer: *const envelope.Sealer, rows: []const SourceRow, wal_transfer: ?*store.WindowsWalTransfer, expected_digest: [32]u8, metrics_body: metrics_mod.Frame, webhook_body: webhook_mod.Frame, history_body: history_mod.Frame, wt_body: udp_mod.Frame, webrtc_body: udp_mod.Frame, native_body: udp_mod.Frame, media_body: media_mod.Frame, native_physical_body: media_mod.Frame, webrtc_physical_body: media_mod.Frame, deadline: i64) Error!SentCustody {
    return sendToWithWalDigestMetricsWebhookHistoryUdpMediaAndActiveWebtransport(endpoint, target_process, target_pid, arena, sealer, rows, wal_transfer, expected_digest, metrics_body, webhook_body, history_body, wt_body, webrtc_body, native_body, media_body, native_physical_body, webrtc_physical_body, active_udp_mod.absentFrame(.native), active_udp_mod.absentFrame(.webrtc), active_wt_mod.absentFrame(), deadline);
}

fn sendToWithWalDigestMetricsWebhookHistoryUdpMediaAndActiveWebtransport(endpoint: *control.Endpoint, target_process: usize, target_pid: u32, arena: *const arena_mod.Arena, sealer: *const envelope.Sealer, rows: []const SourceRow, wal_transfer: ?*store.WindowsWalTransfer, expected_digest: [32]u8, metrics_body: metrics_mod.Frame, webhook_body: webhook_mod.Frame, history_body: history_mod.Frame, wt_body: udp_mod.Frame, webrtc_body: udp_mod.Frame, native_body: udp_mod.Frame, media_body: media_mod.Frame, native_physical_body: media_mod.Frame, webrtc_physical_body: media_mod.Frame, active_native_udp_body: active_udp_mod.Frame, active_webrtc_udp_body: active_udp_mod.Frame, active_webtransport_body: active_wt_mod.Frame, deadline: i64) Error!SentCustody {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    if (target_process == 0 or target_pid == 0 or GetProcessId(target_process) != target_pid or
        endpoint.role != .parent or !sealer.sealed or
        !std.mem.eql(u8, &sealer.upgrade_id, &endpoint.identity.upgrade_id))
        return error.InvalidCandidate;
    try validateSources(rows);
    if (wal_transfer) |transfer| {
        if (transfer.target_process != target_process or transfer.descriptor.destination_pid != target_pid or
            transfer.descriptor.handle == 0 or transfer.descriptor.handle == std.math.maxInt(usize))
            return error.InvalidManifest;
    }
    _ = try udp_mod.validateFrame(&wt_body, .webtransport, target_pid);
    _ = try udp_mod.validateFrame(&webrtc_body, .media, target_pid);
    _ = try udp_mod.validateFrame(&native_body, .native_media, target_pid);
    const media_present = try validateMediaAggregate(&media_body, &native_physical_body, &webrtc_physical_body, target_pid);
    try validateActiveMediaUdpAggregate(&active_native_udp_body, &active_webrtc_udp_body, media_present, &native_physical_body, &webrtc_physical_body, &webrtc_body, &native_body, target_pid);
    const active_present = try active_wt_mod.validateFrame(&active_webtransport_body, target_pid);
    if (active_present and try udp_mod.validateFrame(&wt_body, .webtransport, target_pid)) return error.InvalidManifest;
    if (active_present) {
        const active_handle = std.mem.readInt(u64, active_webtransport_body[16..24], .big);
        for ([_]media_mod.Frame{ media_body, native_physical_body, webrtc_physical_body }) |frame| {
            if (frame[7] == 1 and std.mem.readInt(u64, frame[16..24], .big) == active_handle)
                return error.InvalidManifest;
        }
    }
    // The child owns this duplicate. On any later error the public caller
    // terminates/reaps that child; never close a possibly reused remote value.
    const remote_handle = try arena.duplicateReadOnlyForProcess(target_process);
    var arena_body = encodeArenaBody(remote_handle, arena.size, rows.len, sealer.key);
    defer std.crypto.secureZero(u8, &arena_body);
    endpoint.send(.arena, &arena_body, deadline) catch |err| {
        std.debug.print("onyx-server: Windows Helix arena send failed: {s}\n", .{@errorName(err)});
        return err;
    };
    awaitAck(endpoint, .arena, 0, rows.len, deadline) catch |err| {
        std.debug.print("onyx-server: Windows Helix arena ACK failed: {s}\n", .{@errorName(err)});
        return err;
    };

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
        endpoint.send(.descriptors, body[0 .. descriptor_header_len + count * descriptor_row_len], deadline) catch |err| {
            std.debug.print("onyx-server: Windows Helix descriptor send failed: {s}\n", .{@errorName(err)});
            return err;
        };
        start += count;
        awaitAck(endpoint, .descriptors, start, rows.len, deadline) catch |err| {
            std.debug.print("onyx-server: Windows Helix descriptor ACK failed: {s}\n", .{@errorName(err)});
            return err;
        };
        if (start == rows.len) break;
    }
    const descriptor: ?*const store.WindowsWalDescriptor = if (wal_transfer) |transfer| &transfer.descriptor else null;
    const body = try wal_mod.encode(descriptor, target_pid);
    endpoint.send(.wal_custody, &body, deadline) catch |err| {
        std.debug.print("onyx-server: Windows Helix WAL send failed: {s}\n", .{@errorName(err)});
        return err;
    };
    awaitAck(endpoint, .wal_custody, 1, 1, deadline) catch |err| {
        std.debug.print("onyx-server: Windows Helix WAL ACK failed: {s}\n", .{@errorName(err)});
        return err;
    };
    const digest_body = sourceDigestBody(expected_digest);
    endpoint.send(.source_digest, &digest_body, deadline) catch |err| {
        std.debug.print("onyx-server: Windows Helix source proof send failed: {s}\n", .{@errorName(err)});
        return err;
    };
    awaitAck(endpoint, .source_digest, 1, 1, deadline) catch |err| {
        std.debug.print("onyx-server: Windows Helix source proof ACK failed: {s}\n", .{@errorName(err)});
        return err;
    };
    endpoint.send(.metrics_custody, &metrics_body, deadline) catch |err| {
        std.debug.print("onyx-server: Windows Helix metrics custody send failed: {s}\n", .{@errorName(err)});
        return err;
    };
    awaitAck(endpoint, .metrics_custody, 1, 1, deadline) catch |err| {
        std.debug.print("onyx-server: Windows Helix metrics custody ACK failed: {s}\n", .{@errorName(err)});
        return err;
    };
    endpoint.send(.webhook_custody, &webhook_body, deadline) catch |err| {
        std.debug.print("onyx-server: Windows Helix webhook custody send failed: {s}\n", .{@errorName(err)});
        return err;
    };
    awaitAck(endpoint, .webhook_custody, 1, 1, deadline) catch |err| {
        std.debug.print("onyx-server: Windows Helix webhook custody ACK failed: {s}\n", .{@errorName(err)});
        return err;
    };
    endpoint.send(.history_custody, &history_body, deadline) catch |err| {
        std.debug.print("onyx-server: Windows Helix history custody send failed: {s}\n", .{@errorName(err)});
        return err;
    };
    awaitAck(endpoint, .history_custody, 1, 1, deadline) catch |err| {
        std.debug.print("onyx-server: Windows Helix history custody ACK failed: {s}\n", .{@errorName(err)});
        return err;
    };
    for ([_]udp_mod.Frame{ wt_body, webrtc_body, native_body }, 0..) |udp_body, index| {
        endpoint.send(.udp_custody, &udp_body, deadline) catch |err| {
            std.debug.print("onyx-server: Windows Helix UDP custody send failed: {s}\n", .{@errorName(err)});
            return err;
        };
        awaitAck(endpoint, .udp_custody, index + 1, 3, deadline) catch |err| {
            std.debug.print("onyx-server: Windows Helix UDP custody ACK failed: {s}\n", .{@errorName(err)});
            return err;
        };
    }
    for ([_]media_mod.Frame{ media_body, native_physical_body, webrtc_physical_body }, 0..) |frame, index| {
        endpoint.send(.media_custody, &frame, deadline) catch |err| {
            std.debug.print("onyx-server: Windows Helix media custody send failed: {s}\n", .{@errorName(err)});
            return err;
        };
        awaitAck(endpoint, .media_custody, index + 1, 3, deadline) catch |err| {
            std.debug.print("onyx-server: Windows Helix media custody ACK failed: {s}\n", .{@errorName(err)});
            return err;
        };
    }
    for ([_]active_udp_mod.Frame{ active_native_udp_body, active_webrtc_udp_body }, 0..) |frame, index| {
        try endpoint.send(.active_media_udp_custody, &frame, deadline);
        try awaitAck(endpoint, .active_media_udp_custody, index + 1, 2, deadline);
    }
    endpoint.send(.webtransport_custody, &active_webtransport_body, deadline) catch |err| {
        std.debug.print("onyx-server: Windows Helix active WebTransport custody send failed: {s}\n", .{@errorName(err)});
        return err;
    };
    awaitAck(endpoint, .webtransport_custody, 1, 1, deadline) catch |err| {
        std.debug.print("onyx-server: Windows Helix active WebTransport custody ACK failed: {s}\n", .{@errorName(err)});
        return err;
    };
    return .{
        .wal = if (wal_transfer) |transfer| transfer.release() else null,
        .metrics_body = metrics_body,
        .webhook_body = webhook_body,
        .history_body = history_body,
        .webtransport_udp_body = wt_body,
        .webrtc_media_udp_body = webrtc_body,
        .native_media_udp_body = native_body,
        .media_graph_body = media_body,
        .native_physical_body = native_physical_body,
        .webrtc_physical_body = webrtc_physical_body,
        .active_native_udp_body = active_native_udp_body,
        .active_webrtc_udp_body = active_webrtc_udp_body,
        .active_webtransport_body = active_webtransport_body,
    };
}

/// An authenticated, AEAD-opened arena plus unconsumed, PID-scoped socket
/// capabilities. Descriptors are not yet registered or associated with IOCP.
pub const Incoming = struct {
    allocator: std.mem.Allocator,
    identity: control.Identity,
    plaintext: []u8,
    rows: []ReceivedRow,
    wal: ?store.WindowsWalDescriptor = null,
    /// Immutable authenticated custody bytes for READY. Importing the live
    /// descriptor into OroStore clears its HANDLE, but must not change the
    /// predecessor's digest of the exact frame acknowledged here.
    wal_body: [wal_mod.body_len]u8 = wal_mod.encode(null, 1) catch unreachable,
    /// Exact predecessor claim, carried on its own authenticated turn before
    /// READY and independent of the mutable account-WAL descriptor custody.
    source_digest: [32]u8 = @splat(0),
    metrics: ?metrics_mod.Received = null,
    /// Immutable authenticated companion-custody bytes. Importing its one-use
    /// Winsock record changes the live Transfer but not this READY witness.
    metrics_body: metrics_mod.Frame = metrics_mod.absentFrame(),
    webhook: ?webhook_mod.Received = null,
    webhook_body: webhook_mod.Frame = webhook_mod.absentFrame(),
    history: ?history_mod.Received = null,
    history_body: history_mod.Frame = history_mod.absentFrame(),
    webtransport_udp: ?udp_mod.ReceivedWebtransport = null,
    webtransport_udp_body: udp_mod.Frame = udp_mod.absentFrame(.webtransport),
    webrtc_media_udp: ?udp_mod.ReceivedWebrtc = null,
    webrtc_media_udp_body: udp_mod.Frame = udp_mod.absentFrame(.media),
    native_media_udp: ?udp_mod.ReceivedNative = null,
    native_media_udp_body: udp_mod.Frame = udp_mod.absentFrame(.native_media),
    media_graph_receiver: ?media_mod.Receiver = null,
    media_graph_body: media_mod.Frame = media_mod.absentFrame(.graph),
    media_graph_consumed: bool = false,
    native_physical_receiver: ?media_mod.Receiver = null,
    native_physical_body: media_mod.Frame = media_mod.absentFrame(.native_physical),
    native_physical_consumed: bool = false,
    webrtc_physical_receiver: ?media_mod.Receiver = null,
    webrtc_physical_body: media_mod.Frame = media_mod.absentFrame(.webrtc_physical),
    webrtc_physical_consumed: bool = false,
    active_native_udp_receiver: ?active_udp_mod.Receiver = null,
    active_native_udp_body: active_udp_mod.Frame = active_udp_mod.absentFrame(.native),
    active_native_udp_consumed: bool = false,
    active_webrtc_udp_receiver: ?active_udp_mod.Receiver = null,
    active_webrtc_udp_body: active_udp_mod.Frame = active_udp_mod.absentFrame(.webrtc),
    active_webrtc_udp_consumed: bool = false,
    active_webtransport_receiver: ?active_wt_mod.Receiver = null,
    active_webtransport_body: active_wt_mod.Frame = active_wt_mod.absentFrame(),
    active_webtransport_consumed: bool = false,
    stage_attempted: bool = false,
    staged_count: usize = 0,
    release_confirmed: bool = false,

    pub fn deinit(self: *Incoming) void {
        self.rollbackStaged();
        if (self.wal) |*descriptor| descriptor.deinitReceived();
        if (self.metrics) |*companion| companion.deinit();
        if (self.webhook) |*companion| companion.deinit();
        if (self.history) |*companion| companion.deinit();
        if (self.webtransport_udp) |*received| received.deinit();
        if (self.webrtc_media_udp) |*received| received.deinit();
        if (self.native_media_udp) |*received| received.deinit();
        if (self.media_graph_receiver) |*receiver| receiver.deinit();
        if (self.native_physical_receiver) |*receiver| receiver.deinit();
        if (self.webrtc_physical_receiver) |*receiver| receiver.deinit();
        if (self.active_native_udp_receiver) |*receiver| receiver.deinit();
        if (self.active_webrtc_udp_receiver) |*receiver| receiver.deinit();
        if (self.active_webtransport_receiver) |*receiver| receiver.deinit();
        for (self.rows) |*row| std.crypto.secureZero(u8, std.mem.asBytes(&row.transfer.info));
        self.allocator.free(self.rows);
        std.crypto.secureZero(u8, self.plaintext);
        self.allocator.free(self.plaintext);
        self.rows = &.{};
        self.plaintext = &.{};
        self.wal = null;
        self.metrics = null;
        self.webhook = null;
        self.history = null;
        self.webtransport_udp = null;
        self.webrtc_media_udp = null;
        self.native_media_udp = null;
        self.media_graph_receiver = null;
        self.native_physical_receiver = null;
        self.webrtc_physical_receiver = null;
        self.active_native_udp_receiver = null;
        self.active_webrtc_udp_receiver = null;
        self.active_webtransport_receiver = null;
        std.crypto.secureZero(u8, &self.wal_body);
        std.crypto.secureZero(u8, &self.source_digest);
        std.crypto.secureZero(u8, &self.metrics_body);
        std.crypto.secureZero(u8, &self.webhook_body);
        std.crypto.secureZero(u8, &self.history_body);
        std.crypto.secureZero(u8, &self.webtransport_udp_body);
        std.crypto.secureZero(u8, &self.webrtc_media_udp_body);
        std.crypto.secureZero(u8, &self.native_media_udp_body);
        std.crypto.secureZero(u8, &self.media_graph_body);
        std.crypto.secureZero(u8, &self.native_physical_body);
        std.crypto.secureZero(u8, &self.webrtc_physical_body);
        std.crypto.secureZero(u8, &self.active_native_udp_body);
        std.crypto.secureZero(u8, &self.active_webrtc_udp_body);
        std.crypto.secureZero(u8, &self.active_webtransport_body);
        self.media_graph_consumed = false;
        self.native_physical_consumed = false;
        self.webrtc_physical_consumed = false;
        self.active_native_udp_consumed = false;
        self.active_webrtc_udp_consumed = false;
        self.active_webtransport_consumed = false;
    }

    /// A present graph body is consumed only after authenticated decode succeeds.
    pub fn takeMediaGraph(self: *Incoming, allocator: std.mem.Allocator) Error!?media_graph.Snapshot {
        const receiver = if (self.media_graph_receiver) |*value| value else return null;
        const snapshot = (try receiver.takeGraph(allocator, self.identity.upgrade_id)) orelse return error.InvalidManifest;
        self.media_graph_consumed = true;
        return snapshot;
    }

    pub fn takeMediaNative(self: *Incoming, allocator: std.mem.Allocator, limits: media_physical.Limits) Error!?native_media.PhysicalSnapshot {
        const receiver = if (self.native_physical_receiver) |*value| value else return null;
        const snapshot = (try receiver.takeNative(allocator, self.identity.upgrade_id, limits)) orelse return error.InvalidManifest;
        self.native_physical_consumed = true;
        return snapshot;
    }

    pub fn takeMediaWebrtc(self: *Incoming, allocator: std.mem.Allocator, limits: webrtc_media.PhysicalSnapshot.Limits) Error!?webrtc_media.PhysicalSnapshot {
        const receiver = if (self.webrtc_physical_receiver) |*value| value else return null;
        const snapshot = (try receiver.takeWebrtc(allocator, self.identity.upgrade_id, limits)) orelse return error.InvalidManifest;
        self.webrtc_physical_consumed = true;
        return snapshot;
    }

    pub fn takeActiveNativeUdp(self: *Incoming, allocator: std.mem.Allocator) Error!?active_udp_mod.NativeReceived {
        const receiver = if (self.active_native_udp_receiver) |*value| value else return null;
        const received = (try receiver.takeNative(allocator, self.identity.upgrade_id, &self.native_physical_body)) orelse return error.InvalidManifest;
        self.active_native_udp_consumed = true;
        return received;
    }

    pub fn takeActiveWebrtcUdp(self: *Incoming, allocator: std.mem.Allocator, carry: *const webrtc_media.PhysicalSnapshot) Error!?active_udp_mod.WebrtcReceived {
        const receiver = if (self.active_webrtc_udp_receiver) |*value| value else return null;
        const received = (try receiver.takeWebrtc(allocator, self.identity.upgrade_id, &self.webrtc_physical_body, carry)) orelse return error.InvalidManifest;
        self.active_webrtc_udp_consumed = true;
        return received;
    }

    /// READY requires all three present bodies to have been decoded through
    /// the typed one-use helpers. An absent aggregate requires no receiver.
    pub fn mediaCustodyReady(self: *const Incoming) bool {
        if (comptime builtin.os.tag != .windows) return false;
        const present = validateMediaAggregate(&self.media_graph_body, &self.native_physical_body, &self.webrtc_physical_body, GetCurrentProcessId()) catch return false;
        if (!present) return self.media_graph_receiver == null and self.native_physical_receiver == null and self.webrtc_physical_receiver == null and
            self.active_native_udp_receiver == null and self.active_webrtc_udp_receiver == null and
            !self.media_graph_consumed and !self.native_physical_consumed and !self.webrtc_physical_consumed and
            !self.active_native_udp_consumed and !self.active_webrtc_udp_consumed;
        return self.media_graph_receiver != null and self.native_physical_receiver != null and self.webrtc_physical_receiver != null and
            self.active_native_udp_receiver != null and self.active_webrtc_udp_receiver != null and
            self.media_graph_consumed and self.native_physical_consumed and self.webrtc_physical_consumed and
            self.active_native_udp_consumed and self.active_webrtc_udp_consumed and
            self.active_native_udp_receiver.?.imported() and self.active_webrtc_udp_receiver.?.imported();
    }

    /// Decode after the candidate has loaded and verified its TLS material.
    /// The caller owns the returned detached body and its imported-socket join.
    pub fn takeActiveWebtransport(self: *Incoming, allocator: std.mem.Allocator, tls: webtransport_listener.TlsConfig) Error!?active_wt_codec.Body {
        const receiver = if (self.active_webtransport_receiver) |*value| value else return null;
        const body = (try receiver.take(allocator, tls, self.identity.upgrade_id)) orelse return error.InvalidManifest;
        self.active_webtransport_consumed = true;
        return body;
    }

    pub fn activeWebtransportCustodyReady(self: *const Incoming) bool {
        if (comptime builtin.os.tag != .windows) return false;
        const present = active_wt_mod.validateFrame(&self.active_webtransport_body, GetCurrentProcessId()) catch return false;
        if (present and self.webtransport_udp != null) return false;
        if (!present) return self.active_webtransport_receiver == null and !self.active_webtransport_consumed;
        return self.active_webtransport_receiver != null and self.active_webtransport_consumed;
    }

    /// The exact-ID registry accepts these only before ordinary registrations.
    /// On partial failure, close every staged candidate reference and abort the
    /// candidate process; this same Incoming cannot be staged twice. A later
    /// adoption join must prove listener SO_ACCEPTCONN or TCP SO_CONNECT_TIME
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
    var wal_message = try endpoint.receive(deadline);
    defer wal_message.deinit();
    if (wal_message.kind != .wal_custody) return error.InvalidManifest;
    var wal = try wal_mod.decode(wal_message.bytes(), GetCurrentProcessId(), &.{ endpoint.read_handle, endpoint.write_handle, header.handle });
    errdefer if (wal) |*descriptor| descriptor.deinitReceived();
    const wal_body: [wal_mod.body_len]u8 = wal_message.bytes()[0..wal_mod.body_len].*;
    try sendAck(endpoint, .wal_custody, 1, 1, deadline);
    var digest_message = try endpoint.receive(deadline);
    defer digest_message.deinit();
    if (digest_message.kind != .source_digest) return error.InvalidManifest;
    const source_digest = try parseSourceDigestBody(digest_message.bytes());
    try sendAck(endpoint, .source_digest, 1, 1, deadline);
    var metrics_message = try endpoint.receive(deadline);
    defer metrics_message.deinit();
    if (metrics_message.kind != .metrics_custody or metrics_message.bytes().len != metrics_mod.frame_len)
        return error.InvalidManifest;
    const metrics_body: metrics_mod.Frame = metrics_message.bytes()[0..metrics_mod.frame_len].*;
    const forbidden = [_]usize{ endpoint.read_handle, endpoint.write_handle, header.handle, if (wal) |descriptor| descriptor.handle else 0 };
    var companion = try metrics_mod.receive(allocator, &metrics_body, GetCurrentProcessId(), endpoint.identity.upgrade_id, &forbidden);
    errdefer if (companion) |*received| received.deinit();
    try sendAck(endpoint, .metrics_custody, 1, 1, deadline);
    var webhook_message = try endpoint.receive(deadline);
    defer webhook_message.deinit();
    if (webhook_message.kind != .webhook_custody or webhook_message.bytes().len != webhook_mod.frame_len)
        return error.InvalidManifest;
    const webhook_body: webhook_mod.Frame = webhook_message.bytes()[0..webhook_mod.frame_len].*;
    var webhook = try webhook_mod.receive(&webhook_body, GetCurrentProcessId());
    errdefer if (webhook) |*received| received.deinit();
    try sendAck(endpoint, .webhook_custody, 1, 1, deadline);
    var history_message = try endpoint.receive(deadline);
    defer history_message.deinit();
    if (history_message.kind != .history_custody or history_message.bytes().len != history_mod.frame_len)
        return error.InvalidManifest;
    const history_body: history_mod.Frame = history_message.bytes()[0..history_mod.frame_len].*;
    var history = try history_mod.receive(&history_body, GetCurrentProcessId());
    errdefer if (history) |*received| received.deinit();
    try sendAck(endpoint, .history_custody, 1, 1, deadline);
    var wt_message = try endpoint.receive(deadline);
    defer wt_message.deinit();
    if (wt_message.kind != .udp_custody or wt_message.bytes().len != udp_mod.frame_len)
        return error.InvalidManifest;
    const wt_body: udp_mod.Frame = wt_message.bytes()[0..udp_mod.frame_len].*;
    var wt = try udp_mod.receiveWebtransport(allocator, &wt_body, GetCurrentProcessId(), endpoint.identity.upgrade_id, &forbidden);
    errdefer if (wt) |*received| received.deinit();
    try sendAck(endpoint, .udp_custody, 1, 3, deadline);

    var webrtc_message = try endpoint.receive(deadline);
    defer webrtc_message.deinit();
    if (webrtc_message.kind != .udp_custody or webrtc_message.bytes().len != udp_mod.frame_len)
        return error.InvalidManifest;
    const webrtc_body: udp_mod.Frame = webrtc_message.bytes()[0..udp_mod.frame_len].*;
    var webrtc = try udp_mod.receiveWebrtc(allocator, &webrtc_body, GetCurrentProcessId(), endpoint.identity.upgrade_id, &forbidden);
    errdefer if (webrtc) |*received| received.deinit();
    try sendAck(endpoint, .udp_custody, 2, 3, deadline);

    var native_message = try endpoint.receive(deadline);
    defer native_message.deinit();
    if (native_message.kind != .udp_custody or native_message.bytes().len != udp_mod.frame_len)
        return error.InvalidManifest;
    const native_body: udp_mod.Frame = native_message.bytes()[0..udp_mod.frame_len].*;
    var native = try udp_mod.receiveNative(allocator, &native_body, GetCurrentProcessId(), endpoint.identity.upgrade_id, &forbidden);
    errdefer if (native) |*received| received.deinit();
    if (wt != null and webrtc != null and wt.?.transfer.source_socket == webrtc.?.transfer.source_socket or
        wt != null and native != null and wt.?.transfer.source_socket == native.?.transfer.source_socket or
        webrtc != null and native != null and webrtc.?.transfer.source_socket == native.?.transfer.source_socket)
        return error.InvalidManifest;
    try sendAck(endpoint, .udp_custody, 3, 3, deadline);
    var graph_message = try endpoint.receive(deadline);
    defer graph_message.deinit();
    if (graph_message.kind != .media_custody or graph_message.bytes().len != media_mod.frame_len) return error.InvalidManifest;
    const graph_body: media_mod.Frame = graph_message.bytes()[0..media_mod.frame_len].*;
    const graph_present = try media_mod.validateFrame(&graph_body, .graph, GetCurrentProcessId());
    var graph_receiver: ?media_mod.Receiver = if (graph_present) try media_mod.Receiver.init(&graph_body, .graph, &forbidden) else null;
    errdefer if (graph_receiver) |*receiver| receiver.deinit();
    try sendAck(endpoint, .media_custody, 1, 3, deadline);

    var native_physical_message = try endpoint.receive(deadline);
    defer native_physical_message.deinit();
    if (native_physical_message.kind != .media_custody or native_physical_message.bytes().len != media_mod.frame_len) return error.InvalidManifest;
    const native_physical_body: media_mod.Frame = native_physical_message.bytes()[0..media_mod.frame_len].*;
    const native_physical_present = try media_mod.validateFrame(&native_physical_body, .native_physical, GetCurrentProcessId());
    const graph_handle: usize = if (graph_present) @intCast(std.mem.readInt(u64, graph_body[16..24], .big)) else 0;
    const native_forbidden = [_]usize{ endpoint.read_handle, endpoint.write_handle, header.handle, if (wal) |descriptor| descriptor.handle else 0, graph_handle };
    var native_physical_receiver: ?media_mod.Receiver = if (native_physical_present) try media_mod.Receiver.init(&native_physical_body, .native_physical, &native_forbidden) else null;
    errdefer if (native_physical_receiver) |*receiver| receiver.deinit();
    try sendAck(endpoint, .media_custody, 2, 3, deadline);

    var webrtc_physical_message = try endpoint.receive(deadline);
    defer webrtc_physical_message.deinit();
    if (webrtc_physical_message.kind != .media_custody or webrtc_physical_message.bytes().len != media_mod.frame_len) return error.InvalidManifest;
    const webrtc_physical_body: media_mod.Frame = webrtc_physical_message.bytes()[0..media_mod.frame_len].*;
    const webrtc_physical_present = try media_mod.validateFrame(&webrtc_physical_body, .webrtc_physical, GetCurrentProcessId());
    const native_physical_handle: usize = if (native_physical_present) @intCast(std.mem.readInt(u64, native_physical_body[16..24], .big)) else 0;
    const webrtc_forbidden = [_]usize{ endpoint.read_handle, endpoint.write_handle, header.handle, if (wal) |descriptor| descriptor.handle else 0, graph_handle, native_physical_handle };
    var webrtc_physical_receiver: ?media_mod.Receiver = if (webrtc_physical_present) try media_mod.Receiver.init(&webrtc_physical_body, .webrtc_physical, &webrtc_forbidden) else null;
    errdefer if (webrtc_physical_receiver) |*receiver| receiver.deinit();
    const media_present = try validateMediaAggregate(&graph_body, &native_physical_body, &webrtc_physical_body, GetCurrentProcessId());
    try sendAck(endpoint, .media_custody, 3, 3, deadline);
    var active_native_udp_message = try endpoint.receive(deadline);
    defer active_native_udp_message.deinit();
    if (active_native_udp_message.kind != .active_media_udp_custody or active_native_udp_message.bytes().len != active_udp_mod.frame_len) return error.InvalidManifest;
    const active_native_udp_body: active_udp_mod.Frame = active_native_udp_message.bytes()[0..active_udp_mod.frame_len].*;
    const active_native_present = try active_udp_mod.validateFrame(&active_native_udp_body, .native, GetCurrentProcessId());
    const webrtc_physical_handle: usize = if (webrtc_physical_present) @intCast(std.mem.readInt(u64, webrtc_physical_body[16..24], .big)) else 0;
    const active_native_forbidden = [_]usize{ endpoint.read_handle, endpoint.write_handle, header.handle, if (wal) |descriptor| descriptor.handle else 0, graph_handle, native_physical_handle, webrtc_physical_handle };
    var active_native_receiver: ?active_udp_mod.Receiver = if (active_native_present) try active_udp_mod.Receiver.init(&active_native_udp_body, .native, &active_native_forbidden) else null;
    errdefer if (active_native_receiver) |*receiver| receiver.deinit();
    try sendAck(endpoint, .active_media_udp_custody, 1, 2, deadline);

    var active_webrtc_udp_message = try endpoint.receive(deadline);
    defer active_webrtc_udp_message.deinit();
    if (active_webrtc_udp_message.kind != .active_media_udp_custody or active_webrtc_udp_message.bytes().len != active_udp_mod.frame_len) return error.InvalidManifest;
    const active_webrtc_udp_body: active_udp_mod.Frame = active_webrtc_udp_message.bytes()[0..active_udp_mod.frame_len].*;
    const active_webrtc_present = try active_udp_mod.validateFrame(&active_webrtc_udp_body, .webrtc, GetCurrentProcessId());
    const active_native_handle: usize = if (active_native_present) @intCast(std.mem.readInt(u64, active_native_udp_body[16..24], .big)) else 0;
    const active_webrtc_forbidden = [_]usize{ endpoint.read_handle, endpoint.write_handle, header.handle, if (wal) |descriptor| descriptor.handle else 0, graph_handle, native_physical_handle, webrtc_physical_handle, active_native_handle };
    var active_webrtc_receiver: ?active_udp_mod.Receiver = if (active_webrtc_present) try active_udp_mod.Receiver.init(&active_webrtc_udp_body, .webrtc, &active_webrtc_forbidden) else null;
    errdefer if (active_webrtc_receiver) |*receiver| receiver.deinit();
    try validateActiveMediaUdpAggregate(&active_native_udp_body, &active_webrtc_udp_body, media_present, &native_physical_body, &webrtc_physical_body, &webrtc_body, &native_body, GetCurrentProcessId());
    try sendAck(endpoint, .active_media_udp_custody, 2, 2, deadline);
    var active_message = try endpoint.receive(deadline);
    defer active_message.deinit();
    if (active_message.kind != .webtransport_custody or active_message.bytes().len != active_wt_mod.frame_len) return error.InvalidManifest;
    const active_body: active_wt_mod.Frame = active_message.bytes()[0..active_wt_mod.frame_len].*;
    const active_present = try active_wt_mod.validateFrame(&active_body, GetCurrentProcessId());
    if (active_present and wt != null) return error.InvalidManifest;
    const active_webrtc_handle: usize = if (active_webrtc_present) @intCast(std.mem.readInt(u64, active_webrtc_udp_body[16..24], .big)) else 0;
    const active_forbidden = [_]usize{ endpoint.read_handle, endpoint.write_handle, header.handle, if (wal) |descriptor| descriptor.handle else 0, graph_handle, native_physical_handle, webrtc_physical_handle, active_native_handle, active_webrtc_handle };
    var active_receiver: ?active_wt_mod.Receiver = if (active_present) try active_wt_mod.Receiver.init(&active_body, &active_forbidden) else null;
    errdefer if (active_receiver) |*receiver| receiver.deinit();
    try sendAck(endpoint, .webtransport_custody, 1, 1, deadline);
    return .{ .allocator = allocator, .identity = endpoint.identity, .plaintext = plaintext, .rows = rows, .wal = wal, .wal_body = wal_body, .source_digest = source_digest, .metrics = companion, .metrics_body = metrics_body, .webhook = webhook, .webhook_body = webhook_body, .history = history, .history_body = history_body, .webtransport_udp = wt, .webtransport_udp_body = wt_body, .webrtc_media_udp = webrtc, .webrtc_media_udp_body = webrtc_body, .native_media_udp = native, .native_media_udp_body = native_body, .media_graph_receiver = graph_receiver, .media_graph_body = graph_body, .native_physical_receiver = native_physical_receiver, .native_physical_body = native_physical_body, .webrtc_physical_receiver = webrtc_physical_receiver, .webrtc_physical_body = webrtc_physical_body, .active_native_udp_receiver = active_native_receiver, .active_native_udp_body = active_native_udp_body, .active_webrtc_udp_receiver = active_webrtc_receiver, .active_webrtc_udp_body = active_webrtc_udp_body, .active_webtransport_receiver = active_receiver, .active_webtransport_body = active_body };
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

test "Windows Helix media custody aggregate rejects partial wrong-kind and handle replay" {
    const pid: u32 = 73;
    const absent_graph = media_mod.absentFrame(.graph);
    const absent_native = media_mod.absentFrame(.native_physical);
    const absent_webrtc = media_mod.absentFrame(.webrtc_physical);
    try std.testing.expect(!(try validateMediaAggregate(&absent_graph, &absent_native, &absent_webrtc, pid)));
    const Fake = struct {
        fn frame(kind: media_mod.Kind, target_pid: u32, handle: u64) media_mod.Frame {
            var body = media_mod.absentFrame(kind);
            body[7] = 1;
            std.mem.writeInt(u32, body[8..12], target_pid, .big);
            std.mem.writeInt(u64, body[16..24], handle, .big);
            std.mem.writeInt(u64, body[24..32], envelope.header_len + envelope.tag_len + 1, .big);
            @memset(body[32..64], 0x51);
            @memset(body[64..96], 0x72);
            return body;
        }
    };
    const graph = Fake.frame(.graph, pid, 101);
    const native = Fake.frame(.native_physical, pid, 102);
    var webrtc = Fake.frame(.webrtc_physical, pid, 103);
    try std.testing.expect(try validateMediaAggregate(&graph, &native, &webrtc, pid));
    try std.testing.expectError(error.InvalidManifest, validateMediaAggregate(&graph, &native, &absent_webrtc, pid));
    try std.testing.expectError(error.InvalidFrame, validateMediaAggregate(&graph, &webrtc, &native, pid));
    std.mem.writeInt(u64, webrtc[16..24], 102, .big);
    try std.testing.expectError(error.InvalidManifest, validateMediaAggregate(&graph, &native, &webrtc, pid));
    try std.testing.expectError(error.InvalidFrame, validateMediaAggregate(&graph, &native, &webrtc, pid + 1));
    const ack = ackBody(.media_custody, 2, 3);
    try std.testing.expectEqual(@as(u16, 9), std.mem.readInt(u16, ack[6..8], .big));
    try std.testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, ack[8..12], .big));
}

test "Windows Helix active media UDP aggregate requires both exact transfers" {
    const pid: u32 = 73;
    const udp_socket = @import("native_windows_udp_socket.zig");
    const absent_native = active_udp_mod.absentFrame(.native);
    const absent_webrtc = active_udp_mod.absentFrame(.webrtc);
    const idle_webrtc = udp_mod.absentFrame(.media);
    const idle_native = udp_mod.absentFrame(.native_media);
    const absent_hxna = media_mod.absentFrame(.native_physical);
    const absent_hxwa = media_mod.absentFrame(.webrtc_physical);
    try validateActiveMediaUdpAggregate(&absent_native, &absent_webrtc, false, &absent_hxna, &absent_hxwa, &idle_webrtc, &idle_native, pid);
    const Fake = struct {
        fn media(kind: media_mod.Kind, handle: u64, target_pid: u32) media_mod.Frame {
            var frame = media_mod.absentFrame(kind);
            frame[7] = 1;
            std.mem.writeInt(u32, frame[8..12], target_pid, .big);
            std.mem.writeInt(u64, frame[16..24], handle, .big);
            std.mem.writeInt(u64, frame[24..32], envelope.header_len + envelope.tag_len + 1, .big);
            return frame;
        }
        fn active(kind: active_udp_mod.Kind, handle: u64, source_socket: usize, target_pid: u32) !active_udp_mod.Frame {
            var frame = active_udp_mod.absentFrame(kind);
            frame[7] = 1;
            std.mem.writeInt(u32, frame[8..12], target_pid, .big);
            std.mem.writeInt(u64, frame[16..24], handle, .big);
            std.mem.writeInt(u64, frame[24..32], envelope.header_len + envelope.tag_len + 128, .big);
            var transfer = udp_socket.Transfer{ .info = std.mem.zeroes(udp_socket.ProtocolInfo), .source_socket = source_socket, .target_pid = target_pid };
            transfer.info.address_family = 2;
            transfer.info.socket_type = 2;
            transfer.info.protocol = 17;
            const socket_frame = try udp_socket.encodeFrame(&transfer, if (kind == .native) .native_media else .media);
            @memcpy(frame[96..], &socket_frame);
            return frame;
        }
    };
    const hxna = Fake.media(.native_physical, 101, pid);
    const hxwa = Fake.media(.webrtc_physical, 102, pid);
    var native_frame = try Fake.active(.native, 103, 71, pid);
    var webrtc_frame = try Fake.active(.webrtc, 104, 72, pid);
    try validateActiveMediaUdpAggregate(&native_frame, &webrtc_frame, true, &hxna, &hxwa, &idle_webrtc, &idle_native, pid);
    try std.testing.expectError(error.InvalidManifest, validateActiveMediaUdpAggregate(&native_frame, &absent_webrtc, true, &hxna, &hxwa, &idle_webrtc, &idle_native, pid));
    std.mem.writeInt(u64, webrtc_frame[16..24], 103, .big);
    try std.testing.expectError(error.InvalidManifest, validateActiveMediaUdpAggregate(&native_frame, &webrtc_frame, true, &hxna, &hxwa, &idle_webrtc, &idle_native, pid));
    std.mem.writeInt(u64, webrtc_frame[16..24], 104, .big);
    std.mem.writeInt(u64, webrtc_frame[96 + 12 .. 96 + 20], 71, .big);
    try std.testing.expectError(error.InvalidManifest, validateActiveMediaUdpAggregate(&native_frame, &webrtc_frame, true, &hxna, &hxwa, &idle_webrtc, &idle_native, pid));
    std.mem.writeInt(u64, webrtc_frame[96 + 12 .. 96 + 20], 72, .big);
    native_frame[6] = 2;
    try std.testing.expectError(error.InvalidFrame, validateActiveMediaUdpAggregate(&native_frame, &webrtc_frame, true, &hxna, &hxwa, &idle_webrtc, &idle_native, pid));
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
    try std.testing.expect(incoming.wal == null);
    try std.testing.expectEqual(@as([32]u8, @splat(0)), incoming.source_digest);
}

test "Windows Helix source digest frame rejects malformed shape" {
    const digest: [32]u8 = @splat(0xa5);
    const frame = sourceDigestBody(digest);
    try std.testing.expectEqual(digest, try parseSourceDigestBody(&frame));
    try std.testing.expectError(error.InvalidManifest, parseSourceDigestBody(frame[0 .. frame.len - 1]));
    var altered = frame;
    altered[0] ^= 1;
    try std.testing.expectError(error.InvalidManifest, parseSourceDigestBody(&altered));
    altered = frame;
    altered[5] ^= 1;
    try std.testing.expectError(error.InvalidManifest, parseSourceDigestBody(&altered));
    altered = frame;
    altered[7] = 1;
    try std.testing.expectError(error.InvalidManifest, parseSourceDigestBody(&altered));
}

test "Windows Helix authenticated WAL custody frame stages the private account store" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const runtime = @import("../os_runtime.zig");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    private.close(std.testing.io);
    var source = try store.OroStore.openPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/accounts.wal", .{});
    defer source.deinit();
    try source.put(.accounts, "alice", "same WAL object");
    var transfer = try source.duplicatePrivateWalToWindowsProcess(GetCurrentProcess());
    defer transfer.deinit();

    var pair = try control.Pair.init();
    defer pair.deinit();
    const identity: control.Identity = .{ .generation = 51, .upgrade_id = @splat(6) };
    var sender = pair.takeParent(identity, @splat(7));
    defer sender.deinit();
    var receiver = pair.takeChild(identity, @splat(7));
    defer receiver.deinit();
    var sealer = try envelope.Sealer.initRandom();
    defer sealer.deinit();
    sealer.upgrade_id = identity.upgrade_id;
    var arena = try arena_mod.Arena.create(std.testing.allocator, &sealer, "account custody state");
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
    const expected_source_digest: [32]u8 = @splat(0x3c);
    const sent = sendToWithWalDigest(&sender, GetCurrentProcess(), GetCurrentProcessId(), &arena, &sealer, &.{}, &transfer, expected_source_digest, platform.monotonicMillis() + 3000);
    thread.join();
    const parent_descriptor = (try sent) orelse return error.InvalidManifest;
    if (runner.failure) |err| return err;
    var incoming = runner.result orelse return error.InvalidManifest;
    defer incoming.deinit();
    try std.testing.expectEqualDeep(parent_descriptor.witness, incoming.wal.?.witness);
    try std.testing.expectEqual(parent_descriptor.handle, incoming.wal.?.handle);
    try std.testing.expectEqual(expected_source_digest, incoming.source_digest);
    try std.testing.expect(incoming.metrics == null);
    try std.testing.expectEqual(metrics_mod.absentFrame(), incoming.metrics_body);
    try std.testing.expect(incoming.webhook == null);
    try std.testing.expectEqual(webhook_mod.absentFrame(), incoming.webhook_body);
    const expected_wal_body = try wal_mod.encode(&parent_descriptor, GetCurrentProcessId());
    try std.testing.expectEqual(expected_wal_body, incoming.wal_body);
    try std.testing.expectEqual(@as(usize, 0), transfer.descriptor.handle);
    var staged = try store.OroStore.openTransferredPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/accounts.wal", .{}, &incoming.wal.?);
    defer staged.deinit();
    try std.testing.expect(staged.isReadOnly());
    try std.testing.expectEqualStrings("same WAL object", staged.get(.accounts, "alice").?);
    try std.testing.expectEqual(@as(usize, 0), incoming.wal.?.handle);
    try std.testing.expectEqual(expected_wal_body, incoming.wal_body);
    try std.testing.expectEqual(expected_source_digest, incoming.source_digest);
    try std.testing.expect(receiver.awaiting_response);
    try std.testing.expect(!sender.awaiting_response);
}

test "Windows Helix authenticated metrics custody frame survives one-use socket import" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const metrics_http = @import("../metrics_http.zig");
    const allocator = std.testing.allocator;
    var source_text = metrics_http.MetricsSnapshot.init(allocator);
    defer source_text.deinit();
    try source_text.set("onyx_metrics_handoff 11\n");
    var source = try metrics_http.MetricsServer.init(&source_text, 0);
    defer source.shutdown();
    var carry = try source.captureUnstarted(allocator, metrics_mod.max_snapshot_bytes);
    defer carry.deinit();
    const before = try metrics_http.observeListener(source.listen_fd);

    var pair = try control.Pair.init();
    defer pair.deinit();
    const identity: control.Identity = .{ .generation = 52, .upgrade_id = @splat(0x42) };
    var sender = pair.takeParent(identity, @splat(0x14));
    defer sender.deinit();
    var receiver = pair.takeChild(identity, @splat(0x14));
    defer receiver.deinit();
    var sealer = try envelope.Sealer.initRandom();
    defer sealer.deinit();
    sealer.upgrade_id = identity.upgrade_id;
    var arena = try arena_mod.Arena.create(allocator, &sealer, "metrics custody state");
    defer arena.deinit();
    var prepared = try metrics_mod.prepareSource(allocator, .{ .owner = &source, .carry = &carry }, GetCurrentProcess(), GetCurrentProcessId(), identity.upgrade_id);
    defer prepared.deinit();

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
    const sent_result = sendToWithWalDigestAndMetrics(&sender, GetCurrentProcess(), GetCurrentProcessId(), &arena, &sealer, &.{}, null, @splat(0x31), prepared.body, platform.monotonicMillis() + 3000);
    thread.join();
    const sent = try sent_result;
    if (runner.failure) |err| return err;
    var incoming = runner.result orelse return error.InvalidManifest;
    defer incoming.deinit();
    try std.testing.expect(sent.wal == null);
    try std.testing.expectEqual(sent.metrics_body, incoming.metrics_body);
    try std.testing.expect(incoming.webhook == null);
    try std.testing.expectEqual(webhook_mod.absentFrame(), incoming.webhook_body);
    try std.testing.expectEqualStrings(carry.text, incoming.metrics.?.carry.text);
    var adopted_text = metrics_http.MetricsSnapshot.init(allocator);
    defer adopted_text.deinit();
    var adopted = try metrics_http.MetricsServer.initTransferred(&adopted_text, &incoming.metrics.?.transfer, &incoming.metrics.?.carry, .{}, metrics_mod.max_snapshot_bytes);
    defer adopted.shutdown();
    try std.testing.expect(incoming.metrics.?.transfer.consumed);
    try std.testing.expectEqual(sent.metrics_body, incoming.metrics_body);
    try std.testing.expectEqualDeep(before, try metrics_http.observeListener(source.listen_fd));
    try std.testing.expect(adopted.thread == null);
    try std.testing.expect(receiver.awaiting_response);
    try std.testing.expect(!sender.awaiting_response);
}

test "Windows Helix authenticated webhook frame survives one-use socket import" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const webhook_http = @import("../webhook_http.zig");
    const webhook_store = @import("../webhook.zig");
    const metrics_http = @import("../metrics_http.zig");
    const Sink = struct {
        fn submit(_: *anyopaque, _: *const webhook_store.PendingPost) bool {
            return false;
        }
    };
    var marker: u8 = 0;
    const sink = webhook_store.PostSink{ .ctx = &marker, .submit = Sink.submit };
    var bindings = webhook_store.WebhookStore.init();
    var source = try webhook_http.WebhookServer.init(&bindings, sink, 0, .{});
    defer source.shutdown();
    try source.spawn();
    source.pause();
    const carry = try source.captureQuiescedAfterJoin();
    const before = try metrics_http.observeListener(source.listen_fd);

    var pair = try control.Pair.init();
    defer pair.deinit();
    const identity: control.Identity = .{ .generation = 53, .upgrade_id = @splat(0x43) };
    var sender = pair.takeParent(identity, @splat(0x15));
    defer sender.deinit();
    var receiver = pair.takeChild(identity, @splat(0x15));
    defer receiver.deinit();
    var sealer = try envelope.Sealer.initRandom();
    defer sealer.deinit();
    sealer.upgrade_id = identity.upgrade_id;
    var arena = try arena_mod.Arena.create(std.testing.allocator, &sealer, "webhook custody state");
    defer arena.deinit();
    var prepared = try webhook_mod.prepareSource(.{ .owner = &source, .carry = &carry }, GetCurrentProcess(), GetCurrentProcessId());
    defer prepared.deinit();

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
    const sent_result = sendToWithWalDigestMetricsAndWebhook(&sender, GetCurrentProcess(), GetCurrentProcessId(), &arena, &sealer, &.{}, null, @splat(0x32), metrics_mod.absentFrame(), prepared.body, platform.monotonicMillis() + 3000);
    thread.join();
    const sent = try sent_result;
    if (runner.failure) |err| return err;
    var incoming = runner.result orelse return error.InvalidManifest;
    defer incoming.deinit();
    try std.testing.expect(sent.wal == null);
    try std.testing.expectEqual(sent.webhook_body, incoming.webhook_body);
    try std.testing.expectEqualDeep(carry, incoming.webhook.?.carry);
    try std.testing.expect(incoming.metrics == null);
    var adopted = try webhook_http.WebhookServer.initTransferred(&bindings, sink, &incoming.webhook.?.transfer, &incoming.webhook.?.carry, .{});
    defer adopted.shutdown();
    try std.testing.expect(incoming.webhook.?.transfer.consumed);
    try std.testing.expectEqual(sent.webhook_body, incoming.webhook_body);
    try std.testing.expectEqualDeep(before, try metrics_http.observeListener(source.listen_fd));
    try std.testing.expect(adopted.thread == null);
    try std.testing.expect(receiver.awaiting_response);
    try std.testing.expect(!sender.awaiting_response);
}

test "Windows Helix authenticated history frame survives one-use socket import" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const history_http = @import("../history_http.zig");
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

    var pair = try control.Pair.init();
    defer pair.deinit();
    const identity: control.Identity = .{ .generation = 54, .upgrade_id = @splat(0x44) };
    var sender = pair.takeParent(identity, @splat(0x15));
    defer sender.deinit();
    var receiver = pair.takeChild(identity, @splat(0x15));
    defer receiver.deinit();
    var sealer = try envelope.Sealer.initRandom();
    defer sealer.deinit();
    sealer.upgrade_id = identity.upgrade_id;
    var arena = try arena_mod.Arena.create(std.testing.allocator, &sealer, "history custody state");
    defer arena.deinit();
    var prepared = try history_mod.prepareSource(.{ .owner = &source, .carry = &carry, .pause_token = token }, GetCurrentProcess(), GetCurrentProcessId());
    defer prepared.deinit();

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
    const sent_result = sendToWithWalDigestMetricsWebhookAndHistory(&sender, GetCurrentProcess(), GetCurrentProcessId(), &arena, &sealer, &.{}, null, @splat(0x33), metrics_mod.absentFrame(), webhook_mod.absentFrame(), prepared.body, platform.monotonicMillis() + 3000);
    thread.join();
    const sent = try sent_result;
    if (runner.failure) |err| return err;
    var incoming = runner.result orelse return error.InvalidManifest;
    defer incoming.deinit();
    try std.testing.expect(sent.wal == null);
    try std.testing.expect(incoming.metrics == null and incoming.webhook == null);
    try std.testing.expectEqual(sent.history_body, incoming.history_body);
    try std.testing.expectEqualDeep(carry, incoming.history.?.carry);
    var adopted = try history_http.HttpsListener.initTransferred(std.testing.allocator, "127.0.0.1", &incoming.history.?.transfer, &incoming.history.?.carry, source.tls_config, source.reader);
    defer adopted.shutdown();
    try std.testing.expect(incoming.history.?.transfer.consumed);
    try std.testing.expectEqual(sent.history_body, incoming.history_body);
    try std.testing.expect(adopted.thread == null);
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
