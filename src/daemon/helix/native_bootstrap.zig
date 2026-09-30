// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Native full-daemon Helix bootstrap. No state or service descriptor reaches
//! the successor until its executed image has negotiated the exact contract.
const std = @import("std");
const posix = std.posix;
const sys = posix.system;
const server = @import("../server.zig");
const runtime = @import("../os_runtime.zig");
const platform = @import("../../substrate/platform.zig");
const process = @import("native_process.zig");
const exchange = @import("native_exchange.zig");
const manifest = @import("native_manifest.zig");
const envelope = @import("native_arena_envelope.zig");
const arena_file = @import("native_arena_file.zig");
const live = @import("live.zig");
const capsule = @import("capsule.zig");
const s2s_snapshot = @import("s2s_snapshot.zig");
const session_snapshot = @import("session_snapshot.zig");
pub const timeout_ms = 30_000;
const arena_body_len = 44;

pub const Driver = struct {
    allocator: std.mem.Allocator,
    config_path: ?[]const u8,
    environ: ?std.process.Environ = null,
    candidate: ?process.Process = null,
    deadline: i64 = 0,
    pub fn hooks(self: *Driver) server.NativeUpgradeHooks {
        return .{ .ctx = self, .begin = begin, .transferAndCommit = transferAndCommit, .abort = abort };
    }
    fn begin(ctx: *anyopaque, executable: []const u8) !void {
        const self: *Driver = @ptrCast(@alignCast(ctx));
        if (self.candidate != null) return error.UpgradeAlreadyActive;
        self.deadline = exchange.deadlineAfter(timeout_ms);
        const generation: u64 = @intCast(@max(1, platform.monotonicMillis()));
        self.candidate = try process.Process.spawn(self.allocator, executable, self.config_path, self.environ, generation, self.deadline);
    }
    fn abort(ctx: *anyopaque) void {
        const self: *Driver = @ptrCast(@alignCast(ctx));
        if (self.candidate) |*candidate| candidate.deinit();
        self.candidate = null;
    }
    fn transferAndCommit(ctx: *anyopaque, snapshot: server.NativeUpgradeSnapshot) !noreturn {
        if (comptime @import("builtin").os.tag != .openbsd) return error.Unsupported;
        const self: *Driver = @ptrCast(@alignCast(ctx));
        const candidate = if (self.candidate) |*p| p else return error.NoCandidate;
        var manifested = try live.appendHandoffManifest(self.allocator, snapshot.pieces);
        defer manifested.deinit(self.allocator);
        var plaintext: std.ArrayList(u8) = .empty;
        defer {
            std.crypto.secureZero(u8, plaintext.items);
            plaintext.deinit(self.allocator);
        }
        for (manifested.pieces) |piece| {
            var fields = [_]capsule.Field{.{ .ordinal = 1, .bytes = piece.bytes }};
            var cap = capsule.make(piece.kind, &fields);
            if (piece.min_supported) |minimum| cap.header.min_supported = minimum;
            const encoded = try capsule.encode(self.allocator, cap);
            defer {
                std.crypto.secureZero(u8, encoded);
                self.allocator.free(encoded);
            }
            if (encoded.len > live.max_arena_bytes - plaintext.items.len) return error.ArenaTooLarge;
            try plaintext.appendSlice(self.allocator, encoded);
        }
        // Generate the secret key only after actual-image negotiation.
        var sealer = try envelope.Sealer.initRandom();
        defer sealer.deinit();
        var arena = try arena_file.Arena.create(self.allocator, &sealer, plaintext.items);
        defer arena.deinit();
        const identity: exchange.Identity = .{ .generation = candidate.identity.generation, .upgrade_id = sealer.upgrade_id };
        const rows = try self.allocator.alloc(manifest.Row, snapshot.state_fds.len + snapshot.listeners.len);
        defer self.allocator.free(rows);
        for (snapshot.state_fds, 0..) |fd, index| {
            var role: ?manifest.Role = null;
            for (snapshot.pieces) |piece| {
                const owned_fd = switch (piece.kind) {
                    .clients => session_snapshot.peekFd(piece.bytes),
                    .s2s_link => s2s_snapshot.peekFd(piece.bytes),
                    else => null,
                };
                if (owned_fd != null and owned_fd.? == fd) {
                    if (role != null) return error.InvalidManifest;
                    role = if (piece.kind == .clients) .client else .s2s_state;
                }
            }
            rows[index] = .{ .canonical = fd, .fd = fd, .role = role orelse return error.InvalidManifest, .shard = 0, .family = 0 };
        }
        for (snapshot.listeners, 0..) |listener, index| rows[snapshot.state_fds.len + index] = .{
            .canonical = listener.fd,
            .fd = listener.fd,
            .shard = listener.shard,
            .family = @intFromEnum(listener.family),
            .role = switch (listener.kind) {
                .plain => .plain_listener,
                .tls => .tls_listener,
                .ws => .websocket_listener,
                .s2s => .s2s_listener,
            },
        };
        try manifest.validate(rows);
        var body: [arena_body_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &body);
        @memcpy(body[0..32], &sealer.key);
        std.mem.writeInt(u64, body[32..40], arena.size, .big);
        std.mem.writeInt(u32, body[40..44], @intCast(rows.len), .big);
        try exchange.send(candidate.fd, .{ .kind = .arena, .identity = identity, .index = 0, .total = 1 }, &body, &.{arena.fd}, self.deadline);
        try manifest.send(candidate.fd, identity, rows, self.deadline);
        var ready = try exchange.receive(candidate.fd, .{ .kind = .ready, .identity = identity, .index = 0, .total = 1 }, self.deadline);
        defer ready.deinit();
        if (ready.fd_count != 0 or ready.length != exchange.header_len) return error.InvalidCandidate;
        try exchange.send(candidate.fd, .{ .kind = .commit, .identity = identity, .index = 0, .total = 1 }, &.{}, &.{}, self.deadline);
        // Successful COMMIT is irreversible. Normal deinit would shutdown the
        // shared sockets and destroy the committed successor's attachments.
        candidate.committed = true;
        sys._exit(0);
    }
};

pub const Incoming = struct {
    allocator: std.mem.Allocator,
    control_fd: i32,
    parent_pid: i32,
    arena_fd: i32,
    identity: exchange.Identity,
    deadline: i64,
    plaintext: []u8,
    descriptors: manifest.Manifest,
    listeners: []server.ListenerDescriptor,
    state_fds: []i32,
    committed: bool = false,
    pub fn deinit(self: *Incoming) void {
        if (comptime @import("builtin").os.tag != .openbsd) return;
        runtime.close(self.control_fd);
        runtime.close(self.arena_fd);
        self.descriptors.deinit();
        std.crypto.secureZero(u8, self.plaintext);
        self.allocator.free(self.plaintext);
        self.allocator.free(self.listeners);
        self.allocator.free(self.state_fds);
    }
    pub fn barrier(self: *Incoming) server.NativeAdoptBarrier {
        return .{ .ctx = self, .readyAndAwaitCommit = readyAndAwaitCommit };
    }
    fn readyAndAwaitCommit(ctx: *anyopaque) !void {
        const self: *Incoming = @ptrCast(@alignCast(ctx));
        try exchange.send(self.control_fd, .{ .kind = .ready, .identity = self.identity, .index = 0, .total = 1 }, &.{}, &.{}, self.deadline);
        // Only the predecessor owns the pre-COMMIT deadline and kills/reaps
        // this candidate on timeout. After READY an independent child timer
        // could reject an already queued COMMIT after the parent has exited.
        var commit = try exchange.receive(self.control_fd, .{ .kind = .commit, .identity = self.identity, .index = 0, .total = 1 }, std.math.maxInt(i64));
        defer commit.deinit();
        if (commit.fd_count != 0 or commit.length != exchange.header_len) return error.InvalidCandidate;
        self.committed = true;
        // Server owns all service descriptors after this edge. Keep the manifest
        // allocation for cleanup, but disarm its physical fd custody.
        for (self.descriptors.rows) |*row| row.fd = -1;
        // Parent companion workers still own their ports until bare exit.
        // Wait for kernel reparenting before binding/starting those workers.
        while (posix.system.getppid() == self.parent_pid) {
            if (platform.monotonicMillis() >= self.deadline) sys._exit(124);
            runtime.sleepMillis(1);
        }
    }
    pub fn receive(allocator: std.mem.Allocator, fd: i32, parent_pid: i32, initial: exchange.Identity) !Incoming {
        const deadline = exchange.deadlineAfter(timeout_ms);
        try process.accept(fd, parent_pid, initial, deadline);
        var message = try exchange.receiveAny(fd, deadline);
        defer message.deinit();
        const header = try exchange.parse(message.bytes());
        if (header.kind != .arena or header.identity.generation != initial.generation or header.index != 0 or header.total != 1 or message.fd_count != 1 or message.length != exchange.header_len + arena_body_len) return error.InvalidCandidate;
        const body = message.bytes()[exchange.header_len..];
        var key: envelope.Key = body[0..32].*;
        defer std.crypto.secureZero(u8, &key);
        var arena_fd = message.fds[0];
        message.fds[0] = -1;
        errdefer runtime.close(arena_fd);
        var stat: posix.Stat = undefined;
        if (posix.errno(sys.fstat(arena_fd, &stat)) != .SUCCESS or stat.size < 0 or @as(u64, @intCast(stat.size)) != std.mem.readInt(u64, body[32..40], .big)) return error.InvalidCandidate;
        const plaintext = try arena_file.read(allocator, arena_fd, key, header.identity.upgrade_id);
        errdefer {
            std.crypto.secureZero(u8, plaintext);
            allocator.free(plaintext);
        }
        const caps = try capsule.decodeStream(allocator, plaintext);
        defer {
            for (caps) |*cap| cap.deinit(allocator);
            allocator.free(caps);
        }
        try live.verifyHandoffManifest(caps);
        var descriptors = try manifest.receive(allocator, fd, header.identity, std.mem.readInt(u32, body[40..44], .big), deadline);
        errdefer descriptors.deinit();
        var control_fd = fd;
        try manifest.normalize(allocator, descriptors.rows, &control_fd, &arena_fd);
        var listener_count: usize = 0;
        var state_count: usize = 0;
        for (descriptors.rows) |row| {
            if (row.role == .client or row.role == .s2s_state) state_count += 1 else listener_count += 1;
        }
        const listeners = try allocator.alloc(server.ListenerDescriptor, listener_count);
        errdefer allocator.free(listeners);
        const state_fds = try allocator.alloc(i32, state_count);
        errdefer allocator.free(state_fds);
        listener_count = 0;
        state_count = 0;
        for (descriptors.rows) |row| {
            if (row.role == .client or row.role == .s2s_state) {
                state_fds[state_count] = row.fd;
                state_count += 1;
            } else {
                if (row.shard > std.math.maxInt(u12)) return error.InvalidManifest;
                listeners[listener_count] = .{ .fd = row.fd, .shard = @intCast(row.shard), .family = std.enums.fromInt(server.ListenerFamily, row.family) orelse return error.InvalidManifest, .kind = switch (row.role) {
                    .plain_listener => .plain,
                    .tls_listener => .tls,
                    .websocket_listener => .ws,
                    .s2s_listener => .s2s,
                    else => unreachable,
                } };
                listener_count += 1;
            }
        }
        return .{ .allocator = allocator, .control_fd = control_fd, .parent_pid = parent_pid, .arena_fd = arena_fd, .identity = header.identity, .deadline = deadline, .plaintext = plaintext, .descriptors = descriptors, .listeners = listeners, .state_fds = state_fds };
    }
};
