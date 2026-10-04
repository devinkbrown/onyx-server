// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Native full-daemon Helix bootstrap. No state or service descriptor reaches
//! the successor until its executed image has negotiated the exact contract.
const std = @import("std");
const builtin = @import("builtin");
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
const service = @import("../native_service.zig");
const service_snapshot = @import("native_service_snapshot.zig");
const presence_lease = @import("../mesh_presence_lease.zig");
pub const timeout_ms = 30_000;
const arena_body_len = 44;

const ClassifiedDescriptors = struct {
    listeners: []server.ListenerDescriptor,
    state_fds: []i32,
    presence_lease_fd: ?i32,
    service_listener_fd: ?i32,
    service_lease_fd: ?i32,
};

fn classifyDescriptors(allocator: std.mem.Allocator, rows: []const manifest.Row) !ClassifiedDescriptors {
    try manifest.validate(rows);
    var listener_count: usize = 0;
    var state_count: usize = 0;
    var presence_lease_fd: ?i32 = null;
    var service_listener_fd: ?i32 = null;
    var service_lease_fd: ?i32 = null;
    for (rows) |row| switch (row.role) {
        .client, .s2s_state => state_count += 1,
        .presence_lease => presence_lease_fd = row.fd,
        .service_listener => service_listener_fd = row.fd,
        .service_lifetime_lease => service_lease_fd = row.fd,
        .plain_listener, .tls_listener, .websocket_listener, .s2s_listener => listener_count += 1,
    };
    const listeners = try allocator.alloc(server.ListenerDescriptor, listener_count);
    errdefer allocator.free(listeners);
    const state_fds = try allocator.alloc(i32, state_count);
    errdefer allocator.free(state_fds);
    listener_count = 0;
    state_count = 0;
    for (rows) |row| switch (row.role) {
        .client, .s2s_state => {
            state_fds[state_count] = row.fd;
            state_count += 1;
        },
        .presence_lease, .service_listener, .service_lifetime_lease => {},
        .plain_listener, .tls_listener, .websocket_listener, .s2s_listener => {
            if (row.shard > std.math.maxInt(u12)) return error.InvalidManifest;
            listeners[listener_count] = .{ .fd = row.fd, .shard = @intCast(row.shard), .family = std.enums.fromInt(server.ListenerFamily, row.family) orelse return error.InvalidManifest, .kind = switch (row.role) {
                .plain_listener => .plain,
                .tls_listener => .tls,
                .websocket_listener => .ws,
                .s2s_listener => .s2s,
                else => unreachable,
            } };
            listener_count += 1;
        },
    };
    return .{ .listeners = listeners, .state_fds = state_fds, .presence_lease_fd = presence_lease_fd, .service_listener_fd = service_listener_fd, .service_lease_fd = service_lease_fd };
}

/// Close-only transport custody. This is not a Controller adoption or a
/// Runtime activation receipt; those production source bridges remain separate.
pub const ServiceCarry = struct {
    listener_fd: i32,
    lease_fd: i32,
    state: service.State,
    pub fn deinit(self: *ServiceCarry) void {
        runtime.close(self.listener_fd);
        runtime.close(self.lease_fd);
        self.listener_fd = -1;
        self.lease_fd = -1;
    }
};

fn retainValidationDescriptor(fd: i32) runtime.Error!i32 {
    // A closed standard slot must never turn a valid original row into a
    // reserved descriptor during the later exact manifest validation.
    const retained: i32 = while (true) {
        const rc = sys.fcntl(fd, posix.F.DUPFD, @as(c_int, 3));
        switch (posix.errno(rc)) {
            .SUCCESS => break @intCast(rc),
            .INTR => continue,
            .BADF => return error.InvalidDescriptor,
            .ACCES, .PERM => return error.PermissionDenied,
            .AGAIN => return error.WouldBlock,
            else => return error.Unexpected,
        }
    };
    errdefer runtime.close(retained);
    try runtime.setCloexec(retained, true);
    return retained;
}

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
        // Legacy Server snapshots have no original Controller/descriptor
        // source registration. Never send a service family without that pair.
        for (snapshot.pieces) |piece| if (piece.kind == .native_service) return error.UnboundNativeService;
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
    presence_lease_fd: ?i32 = null,
    // An actual duplicate of the original row, retained for subsequent joins
    // after its issued reference transfers to a separate inert owner.
    presence_validation_row: ?manifest.Row = null,
    service_listener_fd: ?i32 = null,
    service_lease_fd: ?i32 = null,
    service_state: ?service.State = null,
    committed: bool = false,
    pub fn deinit(self: *Incoming) void {
        // The native receiver uses integer POSIX descriptors. Unsupported
        // targets never construct Incoming; do not reinterpret them as HANDLEs.
        if (comptime switch (@import("builtin").os.tag) {
            .linux, .openbsd, .freebsd => false,
            else => true,
        }) return;
        // Abort closes only this candidate's references. In particular, never
        // unlock a lease whose file description is shared with the predecessor.
        runtime.close(self.control_fd);
        runtime.close(self.arena_fd);
        if (self.presence_validation_row) |row| runtime.close(row.fd);
        self.presence_validation_row = null;
        self.descriptors.deinit();
        std.crypto.secureZero(u8, self.plaintext);
        self.allocator.free(self.plaintext);
        self.allocator.free(self.listeners);
        self.allocator.free(self.state_fds);
    }
    /// Transfer close custody to an inert authority stage exactly once. A
    /// later stage failure must close its reference without unlocking it.
    pub fn takePresenceLease(self: *Incoming) (runtime.Error || error{ NoPresenceLease, InvalidManifest, AlreadyCommitted })!i32 {
        if (self.committed) return error.AlreadyCommitted;
        const fd = self.presence_lease_fd orelse return error.NoPresenceLease;
        if (fd < 3 or self.presence_validation_row != null) return error.InvalidManifest;
        var lease_index: ?usize = null;
        for (self.descriptors.rows, 0..) |row, index| {
            if (row.role != .presence_lease) continue;
            if (row.fd != fd or lease_index != null) return error.InvalidManifest;
            lease_index = index;
        }
        const index = lease_index orelse return error.InvalidManifest;
        _ = presence_lease.statRegular(fd) catch return error.InvalidManifest;
        const retained = try retainValidationDescriptor(fd);
        var validation_row = self.descriptors.rows[index];
        validation_row.fd = retained;
        self.presence_validation_row = validation_row;
        self.descriptors.rows[index].fd = -1;
        self.presence_lease_fd = null;
        return fd;
    }
    fn ensurePresenceLeaseClaimed(self: *const Incoming) error{UnclaimedPresenceLease}!void {
        if (self.presence_lease_fd != null) return error.UnclaimedPresenceLease;
        for (self.descriptors.rows) |row| {
            if (row.role == .presence_lease and row.fd != -1) return error.UnclaimedPresenceLease;
        }
    }
    /// Stage the exact inherited pair atomically. All allocation, arena checks
    /// and actual descriptor joins precede disarming either manifest reference.
    /// Caller must retain this close owner through the eventual source stage.
    pub fn takeServiceCarry(self: *Incoming) !ServiceCarry {
        if (self.committed) return error.AlreadyCommitted;
        const listener = self.service_listener_fd orelse return error.NoServiceCarry;
        const lease = self.service_lease_fd orelse return error.InvalidManifest;
        const caps = try capsule.decodeStream(self.allocator, self.plaintext);
        defer {
            for (caps) |*cap| cap.deinit(self.allocator);
            self.allocator.free(caps);
        }
        try live.verifyHandoffManifest(caps);
        // Reconstruct only an exact issued presence loan using its still-owned
        // original open description. Unknown negative cleanup markers remain
        // invalid; no removed role is silently skipped during graph validation.
        const validation_rows = try self.allocator.dupe(manifest.Row, self.descriptors.rows);
        defer self.allocator.free(validation_rows);
        var restored_presence = false;
        for (validation_rows) |*row| {
            if (row.fd >= 3) continue;
            const retained = self.presence_validation_row orelse return error.InvalidManifest;
            if (row.fd != -1 or row.role != .presence_lease or retained.role != .presence_lease or row.canonical != retained.canonical or row.shard != retained.shard or row.family != retained.family or restored_presence) return error.InvalidManifest;
            _ = presence_lease.statRegular(retained.fd) catch return error.InvalidManifest;
            row.* = retained;
            restored_presence = true;
        }
        if ((self.presence_validation_row != null) != restored_presence) return error.InvalidManifest;
        const state = (try service_snapshot.validateHandoff(caps, validation_rows, self.identity.upgrade_id)) orelse return error.InvalidManifest;
        if (self.service_state == null or !std.meta.eql(state, self.service_state.?)) return error.InvalidManifest;
        var listener_index: ?usize = null;
        var lease_index: ?usize = null;
        for (self.descriptors.rows, 0..) |row, index| switch (row.role) {
            .service_listener => {
                if (row.fd != listener or listener_index != null) return error.InvalidManifest;
                listener_index = index;
            },
            .service_lifetime_lease => {
                if (row.fd != lease or lease_index != null) return error.InvalidManifest;
                lease_index = index;
            },
            else => {},
        };
        const li = listener_index orelse return error.InvalidManifest;
        const le = lease_index orelse return error.InvalidManifest;
        self.descriptors.rows[li].fd = -1;
        self.descriptors.rows[le].fd = -1;
        self.service_listener_fd = null;
        self.service_lease_fd = null;
        self.service_state = null;
        return .{ .listener_fd = listener, .lease_fd = lease, .state = state };
    }
    fn ensureServiceCarryClaimed(self: *const Incoming) error{UnclaimedNativeService}!void {
        if (self.service_listener_fd != null or self.service_lease_fd != null or self.service_state != null) return error.UnclaimedNativeService;
        for (self.descriptors.rows) |row| {
            if ((row.role == .service_listener or row.role == .service_lifetime_lease) and row.fd != -1) return error.UnclaimedNativeService;
        }
    }
    pub fn barrier(self: *Incoming) server.NativeAdoptBarrier {
        return .{ .ctx = self, .readyAndAwaitCommit = readyAndAwaitCommit };
    }
    fn readyAndAwaitCommit(ctx: *anyopaque) !void {
        const self: *Incoming = @ptrCast(@alignCast(ctx));
        // A typed authority descriptor must have an explicit owner before the
        // successor tells its predecessor that COMMIT is safe.
        try self.ensurePresenceLeaseClaimed();
        try self.ensureServiceCarryClaimed();
        // Close custody is a transport prerequisite, not the missing managed
        // Runtime/Controller adoption join. Keep that live path closed even
        // after takeServiceCarry; no caller-minted flag can authorize READY.
        for (self.descriptors.rows) |row| {
            if (row.role == .service_listener or row.role == .service_lifetime_lease) return error.UnboundNativeService;
        }
        if (comptime @import("builtin").os.tag != .openbsd) return error.Unsupported;
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
        // Authenticated COMMIT is irreversible. The predecessor's preparation
        // deadline no longer authorizes candidate termination. Retain custody
        // and wait for actual kernel reparenting before admitting any worker.
        while (posix.system.getppid() == self.parent_pid) {
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
        const service_state = try service_snapshot.validateHandoff(caps, descriptors.rows, header.identity.upgrade_id);
        var control_fd = fd;
        try manifest.normalize(allocator, descriptors.rows, &control_fd, &arena_fd);
        const classified = try classifyDescriptors(allocator, descriptors.rows);
        return .{ .allocator = allocator, .control_fd = control_fd, .parent_pid = parent_pid, .arena_fd = arena_fd, .identity = header.identity, .deadline = deadline, .plaintext = plaintext, .descriptors = descriptors, .listeners = classified.listeners, .state_fds = classified.state_fds, .presence_lease_fd = classified.presence_lease_fd, .service_listener_fd = classified.service_listener_fd, .service_lease_fd = classified.service_lease_fd, .service_state = service_state };
    }
};

fn incomingForLeaseTest(rows: []const manifest.Row) !Incoming {
    const allocator = std.testing.allocator;
    const owned_rows = try allocator.dupe(manifest.Row, rows);
    errdefer allocator.free(owned_rows);
    const classified = try classifyDescriptors(allocator, owned_rows);
    return .{ .allocator = allocator, .control_fd = -1, .parent_pid = 0, .arena_fd = -1, .identity = .{ .generation = 1, .upgrade_id = @splat(1) }, .deadline = exchange.deadlineAfter(1000), .plaintext = &.{}, .descriptors = .{ .allocator = allocator, .rows = owned_rows }, .listeners = classified.listeners, .state_fds = classified.state_fds, .presence_lease_fd = classified.presence_lease_fd, .service_listener_fd = classified.service_listener_fd, .service_lease_fd = classified.service_lease_fd };
}

fn incomingForServiceTest(source: *const service.Bootstrap, handoff: service.Handoff) !Incoming {
    return incomingForCombinedServiceTest(source, handoff, null);
}

fn incomingForCombinedServiceTest(source: *const service.Bootstrap, handoff: service.Handoff, presence_fd: ?i32) !Incoming {
    // Fixture duplicates raw POSIX fds; Windows HANDLEs cannot compile here.
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const listener = try runtime.duplicate(source.listener);
    errdefer runtime.close(listener);
    const lease = try runtime.duplicate(source.lease.fd);
    errdefer runtime.close(lease);
    const presence = if (presence_fd) |fd| try runtime.duplicate(fd) else null;
    errdefer if (presence) |fd| runtime.close(fd);
    var fields: [1]capsule.Field = undefined;
    const item = try service_snapshot.capsuleFromHandoff(handoff, &fields);
    const state = try service_snapshot.decode(item.fields[0].bytes);
    var manifested = try live.appendHandoffManifest(allocator, &.{.{ .kind = .native_service, .bytes = item.fields[0].bytes }});
    defer manifested.deinit(allocator);
    var plaintext: std.ArrayList(u8) = .empty;
    defer plaintext.deinit(allocator);
    for (manifested.pieces) |piece| {
        var piece_fields = [_]capsule.Field{.{ .ordinal = 1, .bytes = piece.bytes }};
        const encoded = try capsule.encode(allocator, capsule.make(piece.kind, &piece_fields));
        defer allocator.free(encoded);
        try plaintext.appendSlice(allocator, encoded);
    }
    const owned_plaintext = try plaintext.toOwnedSlice(allocator);
    errdefer allocator.free(owned_plaintext);
    var rows = [_]manifest.Row{
        .{ .canonical = source.listener, .fd = listener, .role = .service_listener, .shard = 0, .family = 0 },
        .{ .canonical = source.lease.fd, .fd = lease, .role = .service_lifetime_lease, .shard = 0, .family = 0 },
        .{ .canonical = presence_fd orelse 0, .fd = presence orelse 0, .role = .presence_lease, .shard = 0, .family = 0 },
    };
    var result = try incomingForLeaseTest(rows[0..if (presence != null) @as(usize, 3) else 2]);
    result.plaintext = owned_plaintext;
    result.identity.upgrade_id = state.upgrade_id;
    result.service_state = state;
    return result;
}

test "native Helix service carry: classification allocation rollback and hidden pair refuse READY" {
    // Helix descriptor fixtures need POSIX fds; skip on Windows.
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const rows = [_]manifest.Row{
        .{ .canonical = 12, .fd = 32, .role = .client, .shard = 0, .family = 0 },
        .{ .canonical = 13, .fd = 33, .role = .service_listener, .shard = 0, .family = 0 },
        .{ .canonical = 14, .fd = 34, .role = .service_lifetime_lease, .shard = 0, .family = 0 },
    };
    const Sweep = struct {
        fn run(allocator: std.mem.Allocator, borrowed: []const manifest.Row) !void {
            const original = [_]manifest.Row{ borrowed[0], borrowed[1], borrowed[2] };
            defer std.testing.expectEqualDeep(original, borrowed[0..3].*) catch unreachable;
            const classified = try classifyDescriptors(allocator, borrowed);
            defer allocator.free(classified.listeners);
            defer allocator.free(classified.state_fds);
            try std.testing.expectEqual(@as(usize, 0), classified.listeners.len);
            try std.testing.expectEqualSlices(i32, &.{32}, classified.state_fds);
            try std.testing.expectEqual(@as(?i32, 33), classified.service_listener_fd);
            try std.testing.expectEqual(@as(?i32, 34), classified.service_lease_fd);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Sweep.run, .{@as([]const manifest.Row, &rows)});
    var sockets: [2]i32 = undefined;
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.socketpair(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0, &sockets)));
    // These real FDs are cleanup custody only; READY refuses before transport.
    var incoming = incomingForLeaseTest(&.{
        .{ .canonical = sockets[0], .fd = sockets[0], .role = .service_listener, .shard = 0, .family = 0 },
        .{ .canonical = sockets[1], .fd = sockets[1], .role = .service_lifetime_lease, .shard = 0, .family = 0 },
    }) catch |err| {
        for (sockets) |fd| runtime.close(fd);
        return err;
    };
    defer incoming.deinit();
    try std.testing.expectError(error.UnclaimedNativeService, Incoming.readyAndAwaitCommit(&incoming));
    incoming.service_listener_fd = null;
    incoming.service_lease_fd = null;
    try std.testing.expectError(error.UnclaimedNativeService, Incoming.readyAndAwaitCommit(&incoming));
    try std.testing.expect(runtime.fdValid(sockets[0]) and runtime.fdValid(sockets[1]));
}

test "native Helix service carry: exact protected source claim OOM rollback and close-only one-shot custody" {
    // Fixture duplicates raw POSIX fds; Windows HANDLEs cannot compile here.
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    var fixture = try service.Fixture.root();
    defer service.Fixture.closeRoot(&fixture);
    const owner = try service.Controller.initStarting(std.testing.allocator, fixture.bootstrap.state.context);
    defer owner.deinit();
    service.Fixture.ready(owner);
    const context = owner.inspect().context;
    _ = try service.Fixture.admitRequest(owner, .{ .verb = .upgrade, .incarnation = context.incarnation, .generation = 0, .serial = 1, .nonce = @splat(3), .candidate_config = @splat(4) });
    const handoff = try owner.prepareHandoff(std.testing.allocator, @splat(18));
    defer handoff.deinit();
    const Sweep = struct {
        fn run(allocator: std.mem.Allocator, source: *const service.Bootstrap, plan: service.Handoff) !void {
            var incoming = try incomingForServiceTest(source, plan);
            defer {
                incoming.allocator = std.testing.allocator;
                incoming.deinit();
            }
            const before = [_]manifest.Row{ incoming.descriptors.rows[0], incoming.descriptors.rows[1] };
            incoming.allocator = allocator;
            var carry = incoming.takeServiceCarry() catch |err| {
                try std.testing.expectEqualDeep(before, incoming.descriptors.rows[0..2].*);
                try std.testing.expectEqual(@as(?i32, before[0].fd), incoming.service_listener_fd);
                try std.testing.expectEqual(@as(?i32, before[1].fd), incoming.service_lease_fd);
                try std.testing.expect(runtime.fdValid(before[0].fd) and runtime.fdValid(before[1].fd));
                return err;
            };
            defer carry.deinit();
            try std.testing.expectEqual(before[0].fd, carry.listener_fd);
            try std.testing.expectEqual(before[1].fd, carry.lease_fd);
            try std.testing.expectEqual(@as(i32, -1), incoming.descriptors.rows[0].fd);
            try std.testing.expectEqual(@as(i32, -1), incoming.descriptors.rows[1].fd);
            try incoming.ensureServiceCarryClaimed();
            try std.testing.expectError(error.NoServiceCarry, incoming.takeServiceCarry());
            try service.validateDescriptors(carry.listener_fd, carry.lease_fd, &carry.state.context);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Sweep.run, .{ @as(*const service.Bootstrap, &fixture.bootstrap), handoff });
    var incoming = try incomingForServiceTest(&fixture.bootstrap, handoff);
    defer incoming.deinit();
    const before = [_]manifest.Row{ incoming.descriptors.rows[0], incoming.descriptors.rows[1] };
    incoming.service_lease_fd = before[0].fd;
    try std.testing.expectError(error.InvalidManifest, incoming.takeServiceCarry());
    try std.testing.expectEqualDeep(before, incoming.descriptors.rows[0..2].*);
    incoming.service_lease_fd = before[1].fd;
    incoming.identity.upgrade_id[0] ^= 1;
    try std.testing.expectError(error.InvalidNativeService, incoming.takeServiceCarry());
    try std.testing.expectEqualDeep(before, incoming.descriptors.rows[0..2].*);
    incoming.identity.upgrade_id[0] ^= 1;
    var carry = try incoming.takeServiceCarry();
    try std.testing.expectError(error.UnboundNativeService, Incoming.readyAndAwaitCommit(&incoming));
    carry.deinit();
    try std.testing.expect(!runtime.fdValid(before[0].fd) and !runtime.fdValid(before[1].fd));
    try service.validateDescriptors(fixture.bootstrap.listener, fixture.bootstrap.lease.fd, &fixture.bootstrap.state.context);
}

test "native Helix service carry: original combined presence and service claims work in both orders with exact retained validation custody" {
    // Fixture duplicates raw POSIX fds; Windows HANDLEs cannot compile here.
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const issuer = @import("../mesh_presence_issuer.zig");
    var fixture = try service.Fixture.root();
    defer service.Fixture.closeRoot(&fixture);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const parent_presence = try issuer.acquireLease(std.testing.allocator, std.testing.io, tmp.dir, "presence.wal");
    defer parent_presence.close(std.testing.io);
    const owner = try service.Controller.initStarting(std.testing.allocator, fixture.bootstrap.state.context);
    defer owner.deinit();
    service.Fixture.ready(owner);
    const context = owner.inspect().context;
    _ = try service.Fixture.admitRequest(owner, .{ .verb = .upgrade, .incarnation = context.incarnation, .generation = 0, .serial = 1, .nonce = @splat(3), .candidate_config = @splat(4) });
    const handoff = try owner.prepareHandoff(std.testing.allocator, @splat(19));
    defer handoff.deinit();
    const Sweep = struct {
        fn run(allocator: std.mem.Allocator, source: *const service.Bootstrap, plan: service.Handoff, presence_fd: i32) !void {
            var incoming = try incomingForCombinedServiceTest(source, plan, presence_fd);
            defer {
                incoming.allocator = std.testing.allocator;
                incoming.deinit();
            }
            const issued = try incoming.takePresenceLease();
            defer runtime.close(issued);
            const original = [_]manifest.Row{ incoming.descriptors.rows[0], incoming.descriptors.rows[1], incoming.descriptors.rows[2] };
            const retained = incoming.presence_validation_row.?;
            incoming.allocator = allocator;
            var carry = incoming.takeServiceCarry() catch |err| {
                try std.testing.expectEqualDeep(original, incoming.descriptors.rows[0..3].*);
                try std.testing.expectEqualDeep(retained, incoming.presence_validation_row.?);
                try std.testing.expect(runtime.fdValid(issued) and runtime.fdValid(retained.fd));
                try std.testing.expect(runtime.fdValid(original[0].fd) and runtime.fdValid(original[1].fd));
                return err;
            };
            defer carry.deinit();
            try service.validateDescriptors(carry.listener_fd, carry.lease_fd, &carry.state.context);
            try incoming.ensurePresenceLeaseClaimed();
            try incoming.ensureServiceCarryClaimed();
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Sweep.run, .{ @as(*const service.Bootstrap, &fixture.bootstrap), handoff, parent_presence.handle });
    for ([_]bool{ true, false }) |presence_first| {
        var incoming = try incomingForCombinedServiceTest(&fixture.bootstrap, handoff, parent_presence.handle);
        var incoming_alive = true;
        defer if (incoming_alive) incoming.deinit();
        const original = [_]manifest.Row{ incoming.descriptors.rows[0], incoming.descriptors.rows[1], incoming.descriptors.rows[2] };
        const issued_presence = if (presence_first) try incoming.takePresenceLease() else null;
        defer if (issued_presence) |fd| runtime.close(fd);
        var carry = if (presence_first) blk: {
            const retained = incoming.presence_validation_row.?;
            try std.testing.expect(retained.fd != original[2].fd);
            try std.testing.expectEqualDeep(try presence_lease.statRegular(original[2].fd), try presence_lease.statRegular(retained.fd));
            incoming.descriptors.rows[2].canonical += 10;
            try std.testing.expectError(error.InvalidManifest, incoming.takeServiceCarry());
            try std.testing.expectEqualDeep(original[0..2].*, incoming.descriptors.rows[0..2].*);
            incoming.descriptors.rows[2].canonical = original[2].canonical;
            incoming.descriptors.rows[0].fd = -1;
            try std.testing.expectError(error.InvalidManifest, incoming.takeServiceCarry());
            incoming.descriptors.rows[0].fd = original[0].fd;
            break :blk try incoming.takeServiceCarry();
        } else try incoming.takeServiceCarry();
        defer carry.deinit();
        const taken_presence = issued_presence orelse try incoming.takePresenceLease();
        defer if (issued_presence == null) runtime.close(taken_presence);
        const validation_fd = incoming.presence_validation_row.?.fd;
        try std.testing.expectEqual(@as(i32, -1), incoming.descriptors.rows[2].fd);
        try incoming.ensurePresenceLeaseClaimed();
        try incoming.ensureServiceCarryClaimed();
        try std.testing.expectError(error.UnboundNativeService, Incoming.readyAndAwaitCommit(&incoming));
        try service.validateDescriptors(carry.listener_fd, carry.lease_fd, &carry.state.context);
        try presence_lease.reaffirmExclusive(taken_presence);
        incoming.deinit();
        incoming_alive = false;
        try std.testing.expect(!runtime.fdValid(validation_fd));
        try std.testing.expect(runtime.fdValid(taken_presence));
        try std.testing.expect(runtime.fdValid(carry.listener_fd) and runtime.fdValid(carry.lease_fd));
        const reopened = try tmp.dir.openFile(std.testing.io, "presence.wal.lock", .{ .mode = .read_write });
        defer reopened.close(std.testing.io);
        try std.testing.expectError(error.WouldBlock, presence_lease.reaffirmExclusive(reopened.handle));
    }
    try presence_lease.reaffirmExclusive(parent_presence.handle);
    try service.validateDescriptors(fixture.bootstrap.listener, fixture.bootstrap.lease.fd, &fixture.bootstrap.state.context);
}

fn closedStandardSlotCarryChild(incoming: *Incoming, workspace: []u8) !void {
    runtime.close(0);
    const issued = try incoming.takePresenceLease();
    defer runtime.close(issued);
    const retained = incoming.presence_validation_row orelse return error.ChildInvariant;
    if (retained.fd < 3 or !std.meta.eql(try presence_lease.statRegular(issued), try presence_lease.statRegular(retained.fd))) return error.ChildInvariant;
    const flags = sys.fcntl(retained.fd, posix.F.GETFD, @as(c_int, 0));
    if (posix.errno(flags) != .SUCCESS or @as(usize, @intCast(flags)) & posix.FD_CLOEXEC == 0) return error.ChildInvariant;
    // Fresh child-local allocation only: never take a Zig allocator/mutex
    // copied from the threaded test process after fork.
    var fixed = std.heap.FixedBufferAllocator.init(workspace);
    incoming.allocator = fixed.allocator();
    var carry = try incoming.takeServiceCarry();
    defer carry.deinit();
    if (incoming.descriptors.rows[0].fd != -1 or incoming.descriptors.rows[1].fd != -1 or incoming.descriptors.rows[2].fd != -1) return error.ChildInvariant;
    try service.validateDescriptors(carry.listener_fd, carry.lease_fd, &carry.state.context);
    try presence_lease.reaffirmExclusive(issued);
    runtime.close(retained.fd);
    incoming.presence_validation_row = null;
}

fn exitCarryTestChild(status: u8) noreturn {
    if (comptime builtin.os.tag == .linux) std.os.linux.exit_group(status);
    if (comptime builtin.os.tag == .openbsd) sys._exit(status);
    unreachable;
}

test "native Helix service carry: isolated closed standard slot keeps original presence validation above reserved descriptors" {
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
    const issuer = @import("../mesh_presence_issuer.zig");
    var fixture = try service.Fixture.root();
    defer service.Fixture.closeRoot(&fixture);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const parent_presence = try issuer.acquireLease(std.testing.allocator, std.testing.io, tmp.dir, "standard-slot.wal");
    defer parent_presence.close(std.testing.io);
    const owner = try service.Controller.initStarting(std.testing.allocator, fixture.bootstrap.state.context);
    defer owner.deinit();
    service.Fixture.ready(owner);
    const context = owner.inspect().context;
    _ = try service.Fixture.admitRequest(owner, .{ .verb = .upgrade, .incarnation = context.incarnation, .generation = 0, .serial = 1, .nonce = @splat(3), .candidate_config = @splat(4) });
    const handoff = try owner.prepareHandoff(std.testing.allocator, @splat(20));
    defer handoff.deinit();
    var incoming = try incomingForCombinedServiceTest(&fixture.bootstrap, handoff, parent_presence.handle);
    defer incoming.deinit();
    const original = [_]manifest.Row{ incoming.descriptors.rows[0], incoming.descriptors.rows[1], incoming.descriptors.rows[2] };
    for (original) |row| try std.testing.expect(row.fd >= 3 and row.canonical >= 3);
    var workspace: [32 * 1024]u8 = undefined;
    const forked = sys.fork();
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(forked));
    var child_pid: i32 = @intCast(forked);
    if (child_pid == 0) {
        closedStandardSlotCarryChild(&incoming, &workspace) catch exitCarryTestChild(104);
        exitCarryTestChild(0);
    }
    defer if (child_pid > 0) {
        _ = sys.kill(child_pid, posix.SIG.KILL);
        var status: c_int = 0;
        while (posix.errno(sys.waitpid(child_pid, &status, 0)) == .INTR) {}
    };
    const deadline = exchange.deadlineAfter(3000);
    var status: c_int = 0;
    while (true) {
        const rc = sys.waitpid(child_pid, &status, posix.W.NOHANG);
        if (posix.errno(rc) == .INTR) continue;
        try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(rc));
        if (rc == child_pid) {
            child_pid = -1;
            break;
        }
        if (platform.monotonicMillis() >= deadline) return error.TestTimeout;
        runtime.sleepMillis(1);
    }
    try std.testing.expectEqual(@as(c_int, 0), status);
    try std.testing.expectEqualDeep(original, incoming.descriptors.rows[0..3].*);
    for (original) |row| try std.testing.expect(runtime.fdValid(row.fd));
    try presence_lease.reaffirmExclusive(parent_presence.handle);
    try service.validateDescriptors(fixture.bootstrap.listener, fixture.bootstrap.lease.fd, &fixture.bootstrap.state.context);
}

test "native Helix presence lease classification is separate and allocation failure preserves borrowed rows" {
    const rows = [_]manifest.Row{
        .{ .canonical = 12, .fd = 32, .role = .client, .shard = 0, .family = 0 },
        .{ .canonical = 13, .fd = 33, .role = .s2s_state, .shard = 0, .family = 0 },
        .{ .canonical = 14, .fd = 34, .role = .tls_listener, .shard = 2, .family = 6 },
        .{ .canonical = 15, .fd = 35, .role = .presence_lease, .shard = 0, .family = 0 },
    };
    const Sweep = struct {
        fn run(allocator: std.mem.Allocator, borrowed: []const manifest.Row) !void {
            const before = try std.testing.allocator.dupe(manifest.Row, borrowed);
            defer std.testing.allocator.free(before);
            defer std.testing.expectEqualDeep(before, borrowed) catch unreachable;
            const classified = try classifyDescriptors(allocator, borrowed);
            defer allocator.free(classified.listeners);
            defer allocator.free(classified.state_fds);
            try std.testing.expectEqualSlices(i32, &.{ 32, 33 }, classified.state_fds);
            try std.testing.expectEqual(@as(usize, 1), classified.listeners.len);
            try std.testing.expectEqual(@as(i32, 34), classified.listeners[0].fd);
            try std.testing.expectEqual(server.ListenerKind.tls, classified.listeners[0].kind);
            try std.testing.expectEqual(server.ListenerFamily.ipv6, classified.listeners[0].family);
            try std.testing.expectEqual(@as(u12, 2), classified.listeners[0].shard);
            try std.testing.expectEqual(@as(?i32, 35), classified.presence_lease_fd);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Sweep.run, .{@as([]const manifest.Row, &rows)});
}

test "native Helix presence lease take is single-use and disarms only exact owned row" {
    // Unix-socketpair/fd fixtures; no `socketpair` on Windows.
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const issuer = @import("../mesh_presence_issuer.zig");
    const lease = @import("../mesh_presence_lease.zig");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const parent = try issuer.acquireLease(std.testing.allocator, std.testing.io, tmp.dir, "lease.wal");
    defer parent.close(std.testing.io);
    var sockets: [2]i32 = undefined;
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.socketpair(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0, &sockets)));
    defer runtime.close(sockets[1]);
    const inherited = runtime.duplicate(parent.handle) catch |err| {
        runtime.close(sockets[0]);
        return err;
    };
    var incoming = incomingForLeaseTest(&.{
        .{ .canonical = sockets[0], .fd = sockets[0], .role = .client, .shard = 0, .family = 0 },
        .{ .canonical = inherited, .fd = inherited, .role = .presence_lease, .shard = 0, .family = 0 },
    }) catch |err| {
        runtime.close(sockets[0]);
        runtime.close(inherited);
        return err;
    };
    var incoming_alive = true;
    defer if (incoming_alive) incoming.deinit();
    try std.testing.expectError(error.UnclaimedPresenceLease, Incoming.readyAndAwaitCommit(&incoming));
    try std.testing.expect(runtime.fdValid(inherited));
    const before = incoming.descriptors.rows[1];
    incoming.presence_lease_fd = sockets[0];
    try std.testing.expectError(error.InvalidManifest, incoming.takePresenceLease());
    try std.testing.expectEqualDeep(before, incoming.descriptors.rows[1]);
    incoming.presence_lease_fd = inherited;
    const taken = try incoming.takePresenceLease();
    defer runtime.close(taken);
    try std.testing.expectEqual(inherited, taken);
    try std.testing.expectEqual(@as(?i32, null), incoming.presence_lease_fd);
    try std.testing.expectEqual(@as(i32, -1), incoming.descriptors.rows[1].fd);
    try std.testing.expectEqual(sockets[0], incoming.descriptors.rows[0].fd);
    try incoming.ensurePresenceLeaseClaimed();
    try std.testing.expectError(error.NoPresenceLease, incoming.takePresenceLease());
    incoming.committed = true;
    try std.testing.expectError(error.AlreadyCommitted, incoming.takePresenceLease());
    incoming.deinit();
    incoming_alive = false;
    try std.testing.expect(!runtime.fdValid(sockets[0]));
    try std.testing.expect(runtime.fdValid(taken));
    try lease.reaffirmExclusive(taken);
    const reopened = try tmp.dir.openFile(std.testing.io, "lease.wal.lock", .{ .mode = .read_write });
    defer reopened.close(std.testing.io);
    try std.testing.expectError(error.WouldBlock, lease.reaffirmExclusive(reopened.handle));
}

test "native Helix presence lease untaken cleanup closes child reference without unlocking parent" {
    // Raw-fd fixtures; Windows HANDLEs cannot compile here.
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const issuer = @import("../mesh_presence_issuer.zig");
    const lease = @import("../mesh_presence_lease.zig");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const parent = try issuer.acquireLease(std.testing.allocator, std.testing.io, tmp.dir, "lease.wal");
    defer parent.close(std.testing.io);
    const inherited = try runtime.duplicate(parent.handle);
    var incoming = incomingForLeaseTest(&.{.{ .canonical = inherited, .fd = inherited, .role = .presence_lease, .shard = 0, .family = 0 }}) catch |err| {
        runtime.close(inherited);
        return err;
    };
    var incoming_alive = true;
    defer if (incoming_alive) incoming.deinit();
    // A missing cached slot cannot hide an unclaimed typed row from READY.
    incoming.presence_lease_fd = null;
    try std.testing.expectError(error.UnclaimedPresenceLease, Incoming.readyAndAwaitCommit(&incoming));
    try std.testing.expectEqual(inherited, incoming.descriptors.rows[0].fd);
    incoming.deinit();
    incoming_alive = false;
    try std.testing.expect(!runtime.fdValid(inherited));
    try std.testing.expect(runtime.fdValid(parent.handle));
    const reopened = try tmp.dir.openFile(std.testing.io, "lease.wal.lock", .{ .mode = .read_write });
    defer reopened.close(std.testing.io);
    try std.testing.expectError(error.WouldBlock, lease.reaffirmExclusive(reopened.handle));
    try lease.reaffirmExclusive(parent.handle);
}

test "native Helix presence lease refusal emits no READY on OpenBSD control socket" {
    if (comptime @import("builtin").os.tag != .openbsd) return error.SkipZigTest;
    const control = @import("native_control.zig");
    var pair = try control.Pair.init();
    defer pair.deinit();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const file = try tmp.dir.createFile(std.testing.io, "lease.lock", .{ .read = true });
    defer file.close(std.testing.io);
    const identity: exchange.Identity = .{ .generation = 13, .upgrade_id = @splat(7) };
    try manifest.send(pair.parent, identity, &.{.{ .canonical = file.handle, .fd = file.handle, .role = .presence_lease, .shard = 0, .family = 0 }}, exchange.deadlineAfter(1000));
    var received = try manifest.receive(std.testing.allocator, pair.child, identity, 1, exchange.deadlineAfter(1000));
    defer received.deinit();
    // Transfer the actual SCM_RIGHTS reference into Incoming's cleanup owner.
    var incoming = try incomingForLeaseTest(received.rows);
    defer incoming.deinit();
    const transferred = received.rows[0].fd;
    received.rows[0].fd = -1;
    incoming.control_fd = try runtime.duplicate(pair.child);
    try std.testing.expectError(error.UnclaimedPresenceLease, Incoming.readyAndAwaitCommit(&incoming));
    try std.testing.expectError(error.WouldBlock, control.receive(pair.parent));
    try std.testing.expect(runtime.fdValid(transferred));
    try std.testing.expect(runtime.fdValid(file.handle));
}

// Actual nested-process entrypoint proof. The helper is the candidate's real
// parent; the test can delay its exit independently of READY/valid COMMIT. No
// service-ready or adoption receipt is forged by this fixture.
const LateCommitFixture = if (@import("builtin").is_test and @import("builtin").os.tag == .openbsd) struct {
    fn readExact(fd: i32, out: []u8, deadline: i64) !void {
        var offset: usize = 0;
        while (offset != out.len) {
            const left = deadline - platform.monotonicMillis();
            if (left <= 0) return error.TestTimeout;
            var ready = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.IN, .revents = 0 }};
            const rc = sys.poll(&ready, 1, @intCast(@min(left, 100)));
            if (posix.errno(rc) == .INTR) continue;
            if (posix.errno(rc) != .SUCCESS) return error.PollFailed;
            if (rc == 0) continue;
            const n = runtime.read(fd, out[offset..]) catch |err| switch (err) {
                error.WouldBlock => continue,
                else => return err,
            };
            if (n == 0) return error.TestUnexpectedEof;
            offset += n;
        }
    }
    fn writeExact(fd: i32, bytes: []const u8, deadline: i64) !void {
        var offset: usize = 0;
        while (offset != bytes.len) {
            if (platform.monotonicMillis() >= deadline) return error.TestTimeout;
            const n = runtime.write(fd, bytes[offset..]) catch |err| switch (err) {
                error.WouldBlock => {
                    var ready = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.OUT, .revents = 0 }};
                    _ = sys.poll(&ready, 1, 10);
                    continue;
                },
                else => return err,
            };
            if (n == 0) return error.TestUnexpectedEof;
            offset += n;
        }
    }
    fn killAndReap(pid: *i32) void {
        if (pid.* <= 0) return;
        _ = sys.kill(pid.*, posix.SIG.KILL);
        var status: c_int = 0;
        while (posix.errno(sys.waitpid(pid.*, &status, 0)) == .INTR) {}
        pid.* = -1;
    }
    fn waitOwned(pid: *i32, deadline: i64) !c_int {
        var status: c_int = 0;
        while (true) {
            const rc = sys.waitpid(pid.*, &status, posix.W.NOHANG);
            if (posix.errno(rc) == .INTR) continue;
            if (posix.errno(rc) != .SUCCESS) return error.WaitFailed;
            if (rc == pid.*) {
                pid.* = -1;
                return status;
            }
            if (platform.monotonicMillis() >= deadline) return error.TestTimeout;
            runtime.sleepMillis(1);
        }
    }
    fn predecessor(report_fd: i32) !void {
        var pair = try @import("native_control.zig").Pair.init();
        defer pair.deinit();
        const parent_pid: i32 = @intCast(sys.getpid());
        const initial_deadline = exchange.deadlineAfter(3000);
        const identity: exchange.Identity = .{ .generation = 71, .upgrade_id = @splat(0x6c) };
        const forked = sys.fork();
        if (posix.errno(forked) != .SUCCESS) return error.ForkFailed;
        var child_pid: i32 = @intCast(forked);
        if (child_pid == 0) {
            runtime.close(pair.parent);
            // Empty descriptor set is an explicit legal barrier fixture, not a
            // complete daemon receive/adopt or configured-owner readiness claim.
            var incoming: Incoming = .{
                .allocator = std.heap.page_allocator,
                .control_fd = pair.child,
                .parent_pid = parent_pid,
                .arena_fd = -1,
                .identity = identity,
                .deadline = initial_deadline,
                .plaintext = &.{},
                .descriptors = .{ .allocator = std.heap.page_allocator, .rows = &.{} },
                .listeners = &.{},
                .state_fds = &.{},
            };
            // The candidate owns its bounded failure timer. After the helper
            // exits, the test never sends a signal to an ambiguous orphan PID.
            var watchdog_done: std.atomic.Value(bool) = .init(false);
            const Watchdog = struct {
                fn run(done: *std.atomic.Value(bool)) void {
                    const deadline = exchange.deadlineAfter(10_000);
                    while (!done.load(.acquire)) {
                        if (platform.monotonicMillis() >= deadline) sys._exit(105);
                        runtime.sleepMillis(1);
                    }
                }
            };
            const watchdog = std.Thread.spawn(.{}, Watchdog.run, .{&watchdog_done}) catch sys._exit(106);
            incoming.barrier().readyAndAwaitCommit(incoming.barrier().ctx) catch sys._exit(101);
            if (!incoming.committed or sys.getppid() == parent_pid) sys._exit(102);
            writeExact(report_fd, "R", exchange.deadlineAfter(3000)) catch sys._exit(103);
            // Hold the actual process until the observer acknowledges survival.
            var ack: [1]u8 = undefined;
            readExact(report_fd, &ack, exchange.deadlineAfter(3000)) catch sys._exit(107);
            if (ack[0] != 'Q') sys._exit(108);
            watchdog_done.store(true, .release);
            watchdog.join();
            sys._exit(0);
        }
        defer killAndReap(&child_pid);
        runtime.close(pair.child);
        pair.child = -1;
        var ready = try exchange.receive(pair.parent, .{ .kind = .ready, .identity = identity, .index = 0, .total = 1 }, initial_deadline);
        defer ready.deinit();
        if (ready.length != exchange.header_len or ready.fd_count != 0) return error.BadReady;
        // The actual valid COMMIT is deliberately sent AFTER the original
        // deadline. The parent remains alive until the test explicitly exits it.
        while (platform.monotonicMillis() <= initial_deadline) runtime.sleepMillis(1);
        try exchange.send(pair.parent, .{ .kind = .commit, .identity = identity, .index = 0, .total = 1 }, &.{}, &.{}, exchange.deadlineAfter(3000));
        var report: [9]u8 = @splat(0);
        report[0] = 'H';
        std.mem.writeInt(i32, report[1..5], child_pid, .little);
        const observe_until = exchange.deadlineAfter(100);
        while (platform.monotonicMillis() < observe_until) {
            var status: c_int = 0;
            const rc = sys.waitpid(child_pid, &status, posix.W.NOHANG);
            if (posix.errno(rc) == .INTR) continue;
            if (posix.errno(rc) != .SUCCESS) return error.WaitFailed;
            if (rc == child_pid) {
                report[0] = 'E';
                std.mem.writeInt(i32, report[5..9], status, .little);
                child_pid = -1;
                break;
            }
            runtime.sleepMillis(1);
        }
        try writeExact(report_fd, &report, exchange.deadlineAfter(3000));
        var command: [1]u8 = undefined;
        try readExact(report_fd, &command, exchange.deadlineAfter(5000));
        if (command[0] != 'E') return;
        // Actual predecessor bare exit: no shared descriptor shutdown/destructors.
        // The candidate must survive COMMIT and finish on kernel reparenting.
        sys._exit(0);
    }
} else struct {};

test "OpenBSD native dormant COMMIT after deadline survives until actual predecessor exit" {
    if (comptime @import("builtin").os.tag != .openbsd) return error.SkipZigTest;
    var report_fds: [2]i32 = undefined;
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.socketpair(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0, &report_fds)));
    defer for (report_fds) |fd| runtime.close(fd);
    for (report_fds) |fd| try runtime.setNonblocking(fd);
    const forked = sys.fork();
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(forked));
    var predecessor_pid: i32 = @intCast(forked);
    if (predecessor_pid == 0) {
        runtime.close(report_fds[0]);
        LateCommitFixture.predecessor(report_fds[1]) catch sys._exit(104);
        sys._exit(0);
    }
    runtime.close(report_fds[1]);
    report_fds[1] = -1;
    defer {
        if (predecessor_pid > 0) {
            LateCommitFixture.writeExact(report_fds[0], "A", exchange.deadlineAfter(100)) catch {};
            _ = LateCommitFixture.waitOwned(&predecessor_pid, exchange.deadlineAfter(1000)) catch {};
            LateCommitFixture.killAndReap(&predecessor_pid);
        }
    }
    var report: [9]u8 = undefined;
    try LateCommitFixture.readExact(report_fds[0], &report, exchange.deadlineAfter(8000));
    if (report[0] == 'E') std.debug.print("native late COMMIT candidate raw_wait_status={d} (OLD124={d})\n", .{ std.mem.readInt(i32, report[5..9], .little), @as(i32, 124 << 8) });
    try std.testing.expectEqual(@as(u8, 'H'), report[0]);
    const candidate_pid = std.mem.readInt(i32, report[1..5], .little);
    try std.testing.expect(candidate_pid > 0);
    try LateCommitFixture.writeExact(report_fds[0], "E", exchange.deadlineAfter(3000));
    try std.testing.expectEqual(@as(c_int, 0), try LateCommitFixture.waitOwned(&predecessor_pid, exchange.deadlineAfter(3000)));
    var returned: [1]u8 = undefined;
    try LateCommitFixture.readExact(report_fds[0], &returned, exchange.deadlineAfter(3000));
    try std.testing.expectEqual(@as(u8, 'R'), returned[0]);
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.kill(candidate_pid, @enumFromInt(0))));
    try LateCommitFixture.writeExact(report_fds[0], "Q", exchange.deadlineAfter(1000));
    const gone_deadline = exchange.deadlineAfter(3000);
    while (posix.errno(sys.kill(candidate_pid, @enumFromInt(0))) != .SRCH) {
        if (platform.monotonicMillis() >= gone_deadline) return error.TestTimeout;
        runtime.sleepMillis(1);
    }
}
