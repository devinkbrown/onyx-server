// SPDX-License-Identifier: AGPL-3.0-or-later
//! Authenticated, bounded custody of the standalone Windows webhook listener.
//! The mandatory Helix webhook-store capsule carries bindings and rate buckets;
//! this frame carries only the parked socket owner's configuration and the
//! one-use Winsock provider record. No candidate request is accepted before
//! COMMIT and the exact predecessor process exit witness.
const std = @import("std");
const builtin = @import("builtin");
const webhook = @import("../webhook.zig");
const webhook_http = @import("../webhook_http.zig");
const metrics_http = @import("../metrics_http.zig");
const runtime_pause = @import("../runtime_pause.zig");
const socket_mod = @import("native_windows_socket.zig");

const frame_magic = "HXWH";
const version: u16 = 1;
const header_len: usize = 104;
pub const frame_len: usize = header_len + @sizeOf(socket_mod.ProtocolInfo);
pub const Frame = [frame_len]u8;
const invalid_socket = std.math.maxInt(usize);

comptime {
    if (frame_len > @import("native_windows_control.zig").max_body or
        header_len != 4 + 2 + 2 + 4 + 4 + 8 + 8 + 2 + 2 + 16 + 4 + 4 + 8 + 4 * 8 + 4)
        @compileError("Windows webhook custody frame exceeds its fixed bounds");
}

extern "kernel32" fn GetProcessId(handle: usize) callconv(.winapi) u32;
extern "kernel32" fn GetCurrentProcess() callconv(.winapi) usize;
extern "kernel32" fn GetCurrentProcessId() callconv(.winapi) u32;

pub const Error = socket_mod.Error || error{ InvalidFrame, InvalidSnapshot, InvalidTarget };

pub const Source = struct {
    owner: *webhook_http.WebhookServer,
    carry: *const webhook_http.Snapshot,
    /// Production uses the source worker's actual parked epoch. A joined
    /// legacy source may instead use the explicit stopped/retained witness.
    pause_token: ?runtime_pause.Token = null,
};

pub const Prepared = struct {
    body: Frame,

    pub fn deinit(self: *Prepared) void {
        std.crypto.secureZero(u8, &self.body);
    }
};

pub const Received = struct {
    carry: webhook_http.Snapshot,
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

fn presentFrame(carry: *const webhook_http.Snapshot, target_pid: u32, info: *const socket_mod.ProtocolInfo) Frame {
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
    std.mem.writeInt(u32, body[68..72], carry.config.listen_backlog, .big);
    std.mem.writeInt(u32, body[72..76], carry.config.accept_poll_ms, .big);
    std.mem.writeInt(u32, body[76..80], carry.config.conn_read_timeout_sec, .big);
    std.mem.writeInt(u32, body[80..84], carry.config.bind_addr, .big);
    std.mem.writeInt(u32, body[84..88], @intCast(carry.config.handler.max_body), .big);
    std.mem.writeInt(u32, body[88..92], carry.config.handler.rate.per_min, .big);
    std.mem.writeInt(u32, body[92..96], carry.config.handler.rate.burst, .big);
    std.mem.writeInt(u32, body[96..100], carry.config.handler.busy_retry_after, .big);
    body[100] = @intFromEnum(carry.execution);
    @memcpy(body[header_len..], std.mem.asBytes(info));
    return body;
}

/// Pure parse of the exact authenticated control-frame body. In particular,
/// the absent frame must be canonical and the provider record remains inert.
pub fn parseFrame(bytes: []const u8, target_pid: u32) Error!?Received {
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
    if (presence != 1 or target_pid == 0 or std.mem.readInt(u32, bytes[8..12], .big) != target_pid or
        bytes[100] != @intFromEnum(webhook_http.Execution.paused) or
        !std.mem.eql(u8, bytes[101..104], &[_]u8{ 0, 0, 0 }))
        return error.InvalidFrame;
    const backlog = std.math.cast(u31, std.mem.readInt(u32, bytes[68..72], .big)) orelse return error.InvalidFrame;
    const config = webhook_http.Config{
        .listen_backlog = backlog,
        .accept_poll_ms = std.mem.readInt(u32, bytes[72..76], .big),
        .conn_read_timeout_sec = std.mem.readInt(u32, bytes[76..80], .big),
        .bind_addr = std.mem.readInt(u32, bytes[80..84], .big),
        .handler = .{
            .max_body = std.mem.readInt(u32, bytes[84..88], .big),
            .rate = .{
                .per_min = std.mem.readInt(u32, bytes[88..92], .big),
                .burst = std.mem.readInt(u32, bytes[92..96], .big),
            },
            .busy_retry_after = std.mem.readInt(u32, bytes[96..100], .big),
        },
    };
    const carry = webhook_http.Snapshot{
        .listener = metrics_http.ListenerObservation{
            .device = std.mem.readInt(u64, bytes[16..24], .big),
            .inode = std.mem.readInt(u64, bytes[24..32], .big),
            .family = std.mem.readInt(u16, bytes[32..34], .big),
            .port = std.mem.readInt(u16, bytes[34..36], .big),
            .address = bytes[36..52].*,
            .scope_id = std.mem.readInt(u32, bytes[52..56], .big),
            .flow_info = std.mem.readInt(u32, bytes[56..60], .big),
            .recv_timeout_us = std.mem.readInt(u64, bytes[60..68], .big),
        },
        .config = config,
        .execution = .paused,
    };
    if (carry.listener.device != 0 or carry.listener.inode == @as(u64, @intCast(invalid_socket)))
        return error.InvalidFrame;
    carry.validate(config) catch return error.InvalidFrame;
    var info = std.mem.zeroes(socket_mod.ProtocolInfo);
    @memcpy(std.mem.asBytes(&info), bytes[header_len..]);
    if (info.address_family != 2 or info.socket_type != 1 or info.protocol != 6) return error.InvalidFrame;
    return .{ .carry = carry, .transfer = .{ .info = info } };
}

/// The source has parked its sole HTTP producer under an exact pause token, or
/// joined that producer while retaining the listener. Accepted posts are
/// drained at the World boundary before this source is handed to the driver.
/// This operation reads the retained socket and duplicates a one-use provider
/// record for the exact child PID.
pub fn prepareSource(source: Source, target_process: usize, target_pid: u32) Error!Prepared {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    if (target_process == 0 or target_pid == 0 or GetProcessId(target_process) != target_pid)
        return error.InvalidTarget;
    const source_socket: usize = @intCast(source.owner.listen_fd);
    if (source_socket == invalid_socket or source.carry.execution != .paused or
        source.carry.listener.inode != @as(u64, @intCast(source_socket)) or source.carry.listener.port != source.owner.port or
        !std.meta.eql(source.carry.config, source.owner.config) or
        !std.meta.eql(source.owner.handler, source.owner.config.handler))
        return error.InvalidSnapshot;
    if (source.pause_token) |token| {
        if (source.owner.stop_flag.load(.acquire) or
            (source.owner.thread == null and source.owner.runtime.view == null))
            return error.InvalidSnapshot;
        source.owner.runtime.pause.requirePaused(token) catch return error.InvalidSnapshot;
    } else if (source.owner.thread != null or source.owner.runtime.view != null or
        !source.owner.stop_flag.load(.acquire)) return error.InvalidSnapshot;
    source.carry.validate(source.owner.config) catch return error.InvalidSnapshot;
    const observed = metrics_http.observeListener(source_socket) catch return error.InvalidSnapshot;
    if (!std.meta.eql(observed, source.carry.listener)) return error.InvalidSnapshot;
    const transfer = try socket_mod.duplicateForProcess(source_socket, target_pid);
    return .{ .body = presentFrame(source.carry, target_pid, &transfer.info) };
}

/// No socket is imported here. The candidate later consumes Received.transfer
/// at its final Server address, validates it, and parks its worker before READY.
pub fn receive(bytes: []const u8, target_pid: u32) Error!?Received {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    return parseFrame(bytes, target_pid);
}

test "Windows webhook frame has canonical absence and exact typed fields" {
    const pid: u32 = 71;
    var absent = absentFrame();
    try std.testing.expect((try parseFrame(&absent, pid)) == null);
    absent[frame_len - 1] = 1;
    try std.testing.expectError(error.InvalidFrame, parseFrame(&absent, pid));
    var info = std.mem.zeroes(socket_mod.ProtocolInfo);
    info.address_family = 2;
    info.socket_type = 1;
    info.protocol = 6;
    const carry = webhook_http.Snapshot{
        .listener = .{ .device = 0, .inode = 123, .family = 2, .port = 9131, .address = .{ 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, .scope_id = 0, .flow_info = 0, .recv_timeout_us = 250_000 },
        .config = .{},
        .execution = .paused,
    };
    const body = presentFrame(&carry, pid, &info);
    var received = (try parseFrame(&body, pid)) orelse return error.TestUnexpectedResult;
    defer received.deinit();
    try std.testing.expectEqualDeep(carry, received.carry);
    try std.testing.expectError(error.InvalidFrame, parseFrame(&body, pid + 1));
    var corrupt = body;
    corrupt[100] = @intFromEnum(webhook_http.Execution.unstarted);
    try std.testing.expectError(error.InvalidFrame, parseFrame(&corrupt, pid));
    corrupt = body;
    corrupt[101] = 1;
    try std.testing.expectError(error.InvalidFrame, parseFrame(&corrupt, pid));
    corrupt = body;
    corrupt[header_len + @offsetOf(socket_mod.ProtocolInfo, "socket_type")] = 2;
    try std.testing.expectError(error.InvalidFrame, parseFrame(&corrupt, pid));
    corrupt = body;
    std.mem.writeInt(u32, corrupt[84..88], @intCast(webhook_http.max_body_hard + 1), .big);
    try std.testing.expectError(error.InvalidFrame, parseFrame(&corrupt, pid));
}

test "Windows webhook custody imports an inert duplicate and preserves immutable frame" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const Sink = struct {
        fn submit(_: *anyopaque, _: *const webhook.PendingPost) bool {
            return false;
        }
    };
    var marker: u8 = 0;
    const sink = webhook.PostSink{ .ctx = &marker, .submit = Sink.submit };
    var store = webhook.WebhookStore.init();
    var source = try webhook_http.WebhookServer.init(&store, sink, 0, .{});
    defer source.shutdown();
    try source.spawn();
    source.pause();
    const carry = try source.captureQuiescedAfterJoin();
    const pid = GetCurrentProcessId();
    var prepared = try prepareSource(.{ .owner = &source, .carry = &carry }, GetCurrentProcess(), pid);
    defer prepared.deinit();
    const immutable = prepared.body;
    var received = (try receive(&prepared.body, pid)) orelse return error.TestUnexpectedResult;
    defer received.deinit();
    var candidate = try webhook_http.WebhookServer.initTransferred(&store, sink, &received.transfer, &received.carry, .{});
    defer candidate.shutdown();
    try std.testing.expect(received.transfer.consumed);
    try std.testing.expectEqual(immutable, prepared.body);
    try std.testing.expect(candidate.thread == null);
    try std.testing.expect(candidate.runtime.view == null);
    try std.testing.expectEqualDeep(carry.listener, try metrics_http.observeListener(source.listen_fd));
}

test "Windows webhook custody requires the source worker's exact parked epoch" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const Sink = struct {
        fn submit(_: *anyopaque, _: *const webhook.PendingPost) bool {
            return false;
        }
    };
    var marker: u8 = 0;
    const sink = webhook.PostSink{ .ctx = &marker, .submit = Sink.submit };
    var store = webhook.WebhookStore.init();
    var source = try webhook_http.WebhookServer.init(&store, sink, 0, .{});
    defer source.shutdown();
    try source.prepareColdResources(std.testing.io);
    try source.spawn();
    const token = try source.requestPause(1);
    try source.awaitPaused(token, std.Io.Clock.Timestamp.fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
    const carry = try source.capturePaused(token);
    try std.testing.expectError(error.InvalidSnapshot, prepareSource(.{ .owner = &source, .carry = &carry }, GetCurrentProcess(), GetCurrentProcessId()));
    try std.testing.expectError(error.InvalidSnapshot, prepareSource(.{ .owner = &source, .carry = &carry, .pause_token = .{ .owner = token.owner, .epoch = token.epoch + 1 } }, GetCurrentProcess(), GetCurrentProcessId()));
    var prepared = try prepareSource(.{ .owner = &source, .carry = &carry, .pause_token = token }, GetCurrentProcess(), GetCurrentProcessId());
    defer prepared.deinit();
    try source.resumePaused(token);
    try std.testing.expectError(error.InvalidSnapshot, prepareSource(.{ .owner = &source, .carry = &carry, .pause_token = token }, GetCurrentProcess(), GetCurrentProcessId()));
}

test "Windows webhook transferred worker parks before READY and enters after release" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const gate_mod = @import("../runtime_start_gate.zig");
    const Sink = struct {
        fn submit(_: *anyopaque, _: *const webhook.PendingPost) bool {
            return false;
        }
    };
    var marker: u8 = 0;
    const sink = webhook.PostSink{ .ctx = &marker, .submit = Sink.submit };
    var store = webhook.WebhookStore.init();
    var source = try webhook_http.WebhookServer.init(&store, sink, 0, .{});
    var source_open = true;
    defer if (source_open) source.shutdown();
    try source.spawn();
    source.pause();
    const carry = try source.captureQuiescedAfterJoin();
    var prepared = try prepareSource(.{ .owner = &source, .carry = &carry }, GetCurrentProcess(), GetCurrentProcessId());
    defer prepared.deinit();
    var received = (try receive(&prepared.body, GetCurrentProcessId())) orelse return error.TestUnexpectedResult;
    defer received.deinit();
    var candidate = try webhook_http.WebhookServer.initTransferred(&store, sink, &received.transfer, &received.carry, .{});
    defer candidate.shutdown();
    try candidate.prepareColdResources(std.testing.io);
    const specs = [_]gate_mod.ParticipantSpec{.{ .kind = .webhook, .instance = 0, .owner_identity = &candidate }};
    const gate = try gate_mod.create(std.testing.allocator, std.testing.io, &specs);
    defer {
        candidate.requestStopAndWake();
        if (gate.view.inspect().phase == .preparing) gate.control.cancelAllAndJoin() else gate.control.joinAll();
        candidate.detachAfterJoined() catch unreachable;
        gate.control.destroyJoined();
    }
    try candidate.prepareDormantWorker(gate.control, gate.view, try gate.view.slot(.webhook, 0, &candidate));
    try gate.control.awaitAllParked(std.Io.Clock.Timestamp.fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
    try candidate.requireParked();
    try std.testing.expect(!candidate.runtime.entered.load(.acquire));
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
