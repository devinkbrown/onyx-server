// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Indexed native descriptor manifest. Canonical fd numbers remain the capsule
//! join keys; normalization runs only in the inert, executed successor.
const std = @import("std");
const posix = std.posix;
const sys = posix.system;
const runtime = @import("../os_runtime.zig");
const control = @import("native_control.zig");
const exchange = @import("native_exchange.zig");
const presence_lease = @import("../mesh_presence_lease.zig");
const service = @import("../native_service.zig");
// Presence and the complete service pair are additional to client/listener capacity.
pub const max_entries = @import("live.zig").max_inherited_state_fds + 512 + 3;
pub const Role = enum(u8) { client = 1, s2s_state, plain_listener, tls_listener, websocket_listener, s2s_listener, presence_lease, service_listener, service_lifetime_lease };
pub const Row = struct { canonical: i32, fd: i32, role: Role, shard: u16, family: u8 };
pub const Error = exchange.Error || std.mem.Allocator.Error || error{InvalidManifest};
const row_size = 8;
pub const Manifest = struct {
    allocator: std.mem.Allocator,
    rows: []Row,
    pub fn deinit(self: *Manifest) void {
        for (self.rows) |row| runtime.close(row.fd);
        self.allocator.free(self.rows);
        self.rows = &.{};
    }
};
fn validateRow(row: Row) Error!void {
    if (row.canonical < 3 or row.fd < 3) return error.InvalidManifest;
    switch (row.role) {
        .client, .s2s_state => if (row.family != 0) return error.InvalidManifest,
        .presence_lease, .service_listener, .service_lifetime_lease => if (row.family != 0 or row.shard != 0) return error.InvalidManifest,
        .plain_listener, .tls_listener, .websocket_listener, .s2s_listener => if (row.family != 4 and row.family != 6) return error.InvalidManifest,
    }
}
fn validateReceivedRow(row: Row) Error!void {
    try validateRow(row);
    if (row.role == .presence_lease) _ = presence_lease.statRegular(row.fd) catch return error.InvalidManifest;
    if (row.role == .service_lifetime_lease) _ = presence_lease.statRegular(row.fd) catch return error.InvalidManifest;
    if (row.role == .service_listener) _ = try inspectServiceListener(row.fd);
}
/// Shape inspection only. The authenticated snapshot subsequently joins the
/// original endpoint, inode and lifetime lease with validateDescriptors.
fn inspectServiceListener(fd: i32) Error!service.FileIdentity {
    var address: posix.sockaddr.un = .{ .path = @splat(0) };
    var length: posix.socklen_t = @sizeOf(@TypeOf(address));
    if (posix.errno(sys.getsockname(fd, @ptrCast(&address), &length)) != .SUCCESS or
        address.family != posix.AF.UNIX or length > @sizeOf(@TypeOf(address)) or
        length <= @offsetOf(posix.sockaddr.un, "path")) return error.InvalidManifest;
    const end = std.mem.indexOfScalar(u8, &address.path, 0) orelse return error.InvalidManifest;
    const path = service.Path.init(address.path[0..end]) catch return error.InvalidManifest;
    return service.inspectListener(fd, &path) catch return error.InvalidManifest;
}
fn isServiceRole(role: Role) bool {
    return role == .service_listener or role == .service_lifetime_lease;
}
fn descriptorIdentity(fd: i32) Error!service.FileIdentity {
    if (comptime switch (@import("builtin").os.tag) {
        .linux, .openbsd, .freebsd => false,
        else => true,
    }) return error.Unsupported;
    if (comptime @import("builtin").os.tag == .linux) {
        const linux = std.os.linux;
        var st: linux.Statx = std.mem.zeroes(linux.Statx);
        while (true) switch (linux.errno(linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .INO = true }, &st))) {
            .SUCCESS => break,
            .INTR => continue,
            else => return error.InvalidManifest,
        };
        if (!st.mask.INO) return error.InvalidManifest;
        return .{ .device = (@as(u64, st.dev_major) << 32) | st.dev_minor, .inode = st.ino };
    } else {
        var st: posix.Stat = undefined;
        while (true) switch (posix.errno(sys.fstat(fd, &st))) {
            .SUCCESS => break,
            .INTR => continue,
            else => return error.InvalidManifest,
        };
        return .{
            .device = @intCast(@as(@Int(.unsigned, @bitSizeOf(@TypeOf(st.dev))), @bitCast(st.dev))),
            .inode = @intCast(@as(@Int(.unsigned, @bitSizeOf(@TypeOf(st.ino))), @bitCast(st.ino))),
        };
    }
}
fn validatePhysicalServiceAliases(prior_rows: []const Row, row: Row) Error!void {
    for (prior_rows) |prior| {
        if (!isServiceRole(prior.role) and !isServiceRole(row.role)) continue;
        if (std.meta.eql(try descriptorIdentity(prior.fd), try descriptorIdentity(row.fd))) return error.InvalidManifest;
    }
}
fn validateUnique(prior_rows: []const Row, row: Row) Error!void {
    for (prior_rows) |prior| {
        if (prior.canonical == row.canonical or prior.fd == row.fd) return error.InvalidManifest;
        if (prior.role == .presence_lease and row.role == .presence_lease) return error.InvalidManifest;
        if (isServiceRole(row.role) and prior.role == row.role) return error.InvalidManifest;
    }
}
pub fn validate(rows: []const Row) Error!void {
    if (rows.len > max_entries) return error.TooLarge;
    var service_listener = false;
    var service_lease = false;
    for (rows, 0..) |row, index| {
        try validateRow(row);
        try validateUnique(rows[0..index], row);
        service_listener = service_listener or row.role == .service_listener;
        service_lease = service_lease or row.role == .service_lifetime_lease;
    }
    // Ordinary unmanaged handoffs have neither. A one-sided carry is never
    // repaired by guessing a role or reopening the protected namespace.
    if (service_listener != service_lease) return error.InvalidManifest;
}
/// Validate the complete pair and all physical aliases without changing any
/// shared open-description flags or taking/closing caller custody.
pub fn validateServiceDescriptors(rows: []const Row) Error!void {
    try validate(rows);
    for (rows, 0..) |row, index| {
        if (isServiceRole(row.role)) try validateReceivedRow(row);
        try validatePhysicalServiceAliases(rows[0..index], row);
    }
}
pub fn send(fd: i32, identity: exchange.Identity, rows: []const Row, deadline: i64) Error!void {
    try validateServiceDescriptors(rows);
    const batches = std.math.divCeil(usize, rows.len, control.max_fds) catch unreachable;
    var index: usize = 0;
    while (index < batches) : (index += 1) {
        const start = index * control.max_fds;
        const batch = rows[start..@min(rows.len, start + control.max_fds)];
        var payload: [control.max_fds * row_size]u8 = undefined;
        var fds: [control.max_fds]i32 = undefined;
        for (batch, 0..) |row, item| {
            const offset = item * row_size;
            std.mem.writeInt(i32, payload[offset..][0..4], row.canonical, .big);
            std.mem.writeInt(u16, payload[offset + 4 ..][0..2], row.shard, .big);
            payload[offset + 6] = @intFromEnum(row.role);
            payload[offset + 7] = row.family;
            fds[item] = row.fd;
        }
        try exchange.send(fd, .{ .kind = .descriptors, .identity = identity, .index = @intCast(index), .total = @intCast(batches) }, payload[0 .. batch.len * row_size], fds[0..batch.len], deadline);
    }
}
pub fn receive(allocator: std.mem.Allocator, fd: i32, identity: exchange.Identity, count: usize, deadline: i64) Error!Manifest {
    if (count > max_entries) return error.TooLarge;
    const rows = try allocator.alloc(Row, count);
    var accepted: usize = 0;
    errdefer {
        for (rows[0..accepted]) |row| runtime.close(row.fd);
        allocator.free(rows);
    }
    const batches = std.math.divCeil(usize, count, control.max_fds) catch unreachable;
    var index: usize = 0;
    while (index < batches) : (index += 1) {
        var message = try exchange.receive(fd, .{ .kind = .descriptors, .identity = identity, .index = @intCast(index), .total = @intCast(batches) }, deadline);
        defer message.deinit();
        const body = message.bytes()[exchange.header_len..];
        const expected: usize = @min(count - accepted, control.max_fds);
        if (message.fd_count != expected or body.len != expected * row_size) return error.InvalidManifest;
        for (0..expected) |item| {
            const offset = item * row_size;
            const row: Row = .{ .canonical = std.mem.readInt(i32, body[offset..][0..4], .big), .fd = message.fds[item], .shard = std.mem.readInt(u16, body[offset + 4 ..][0..2], .big), .role = std.enums.fromInt(Role, body[offset + 6]) orelse return error.InvalidManifest, .family = body[offset + 7] };
            try validateReceivedRow(row);
            try validateUnique(rows[0..accepted], row);
            try validatePhysicalServiceAliases(rows[0..accepted], row);
            rows[accepted] = row;
            accepted += 1;
            message.fds[item] = -1;
        }
    }
    try validate(rows);
    return .{ .allocator = allocator, .rows = rows };
}
fn duplicateAbove(fd: i32, minimum: i32) Error!i32 {
    const rc = sys.fcntl(fd, posix.F.DUPFD, @as(c_int, minimum));
    if (posix.errno(rc) != .SUCCESS) return error.DescriptorFailed;
    const copy: i32 = @intCast(rc);
    errdefer runtime.close(copy);
    runtime.setCloexec(copy, true) catch return error.DescriptorFailed;
    return copy;
}
/// Preserve control/arena and every received descriptor in a disjoint range
/// before changing any canonical number. Failure aborts the inert child; it
/// never shuts down a TCP socket shared with the serving predecessor.
pub fn normalize(allocator: std.mem.Allocator, rows: []Row, control_fd: *i32, arena_fd: *i32) Error!void {
    if (comptime @import("builtin").os.tag != .openbsd) return error.Unsupported;
    try validateServiceDescriptors(rows);
    if (control_fd.* < 3 or arena_fd.* < 3 or control_fd.* == arena_fd.*) return error.InvalidManifest;
    for (rows) |row| {
        if (!isServiceRole(row.role)) continue;
        const identity = try descriptorIdentity(row.fd);
        if (std.meta.eql(identity, try descriptorIdentity(control_fd.*)) or std.meta.eql(identity, try descriptorIdentity(arena_fd.*))) return error.InvalidManifest;
    }
    var highest = @max(control_fd.*, arena_fd.*);
    for (rows) |row| {
        if (row.fd == control_fd.* or row.fd == arena_fd.*) return error.InvalidManifest;
        if (runtime.fdValid(row.canonical) and row.canonical != control_fd.* and row.canonical != arena_fd.*) {
            var owned = false;
            for (rows) |other| if (other.fd == row.canonical) {
                owned = true;
                break;
            };
            if (!owned) return error.InvalidManifest;
        }
        highest = @max(highest, @max(row.canonical, row.fd));
    }
    if (highest == std.math.maxInt(i32)) return error.InvalidManifest;
    const minimum = highest + 1;
    const copies = try allocator.alloc(i32, rows.len);
    defer allocator.free(copies);
    var duplicated: usize = 0;
    defer for (copies[0..duplicated]) |copy| runtime.close(copy);
    const control_copy = try duplicateAbove(control_fd.*, minimum);
    errdefer runtime.close(control_copy);
    const arena_copy = try duplicateAbove(arena_fd.*, minimum);
    errdefer runtime.close(arena_copy);
    for (rows) |row| {
        copies[duplicated] = try duplicateAbove(row.fd, minimum);
        duplicated += 1;
    }
    runtime.close(control_fd.*);
    runtime.close(arena_fd.*);
    control_fd.* = control_copy;
    arena_fd.* = arena_copy;
    for (rows) |row| runtime.close(row.fd);
    for (rows, copies) |*row, copy| {
        // Past the custody edge a partial mapping must never reach caller
        // cleanup or adoption. Abort the inert successor with bare process exit.
        if (posix.errno(sys.dup2(copy, row.canonical)) != .SUCCESS) sys._exit(126);
        row.fd = row.canonical;
        runtime.setCloexec(row.fd, true) catch sys._exit(126);
    }
}

test "OpenBSD native manifest normalization refuses unrelated descriptor collisions" {
    if (comptime @import("builtin").os.tag != .openbsd) return error.SkipZigTest;
    var pair = try control.Pair.init();
    defer pair.deinit();
    const arena = try runtime.openReadZ("/etc/resolv.conf");
    defer runtime.close(arena);
    const sentinel = try runtime.openReadZ("/etc/hosts");
    defer runtime.close(sentinel);
    const received = try runtime.duplicate(pair.child);
    defer runtime.close(received);
    var rows = [_]Row{.{ .canonical = sentinel, .fd = received, .role = .client, .shard = 0, .family = 0 }};
    var ctl = pair.parent;
    var arena_fd = arena;
    try std.testing.expectError(error.InvalidManifest, normalize(std.testing.allocator, &rows, &ctl, &arena_fd));
    try std.testing.expectEqual(pair.parent, ctl);
    try std.testing.expectEqual(arena, arena_fd);
    try std.testing.expect(runtime.fdValid(sentinel));
    var byte: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try runtime.read(sentinel, &byte));
}

test "native Helix descriptor manifest rejects duplicate authority and invalid families" {
    const a: Row = .{ .canonical = 12, .fd = 32, .role = .plain_listener, .shard = 0, .family = 4 };
    try validate(&.{a});
    try std.testing.expectError(error.InvalidManifest, validate(&.{ a, a }));
    var bad = a;
    bad.family = 0;
    try std.testing.expectError(error.InvalidManifest, validate(&.{bad}));
}

test "native Helix descriptor manifest reserves a distinct presence lease role and capacity" {
    try std.testing.expect(std.enums.fromInt(Role, 7) != null);
    try std.testing.expectEqual(@as(usize, @import("live.zig").max_inherited_state_fds + 515), max_entries);
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(Role.client));
    try std.testing.expectEqual(@as(u8, 6), @intFromEnum(Role.s2s_listener));
}

test "native Helix service carry: complete singleton pair has strict shape and no canonical aliases" {
    const listener: Row = .{ .canonical = 12, .fd = 32, .role = .service_listener, .shard = 0, .family = 0 };
    const lease: Row = .{ .canonical = 13, .fd = 33, .role = .service_lifetime_lease, .shard = 0, .family = 0 };
    try validate(&.{}); // Unmanaged handoff.
    try validate(&.{ listener, lease });
    try std.testing.expectEqual(@as(u8, 8), @intFromEnum(Role.service_listener));
    try std.testing.expectEqual(@as(u8, 9), @intFromEnum(Role.service_lifetime_lease));
    try std.testing.expectError(error.InvalidManifest, validate(&.{listener}));
    try std.testing.expectError(error.InvalidManifest, validate(&.{lease}));
    var bad = listener;
    bad.canonical = 14;
    bad.fd = 34;
    try std.testing.expectError(error.InvalidManifest, validate(&.{ listener, lease, bad }));
    bad = lease;
    bad.canonical = 14;
    bad.fd = 34;
    try std.testing.expectError(error.InvalidManifest, validate(&.{ listener, lease, bad }));
    for ([_]Role{ .service_listener, .service_lifetime_lease }) |role| {
        var pair = [_]Row{ listener, lease };
        const index: usize = if (role == .service_listener) 0 else 1;
        pair[index].family = 4;
        try std.testing.expectError(error.InvalidManifest, validate(&pair));
        pair = .{ listener, lease };
        pair[index].shard = 1;
        try std.testing.expectError(error.InvalidManifest, validate(&pair));
        pair = .{ listener, lease };
        pair[index].canonical = pair[1 - index].canonical;
        try std.testing.expectError(error.InvalidManifest, validate(&pair));
        pair = .{ listener, lease };
        pair[index].fd = pair[1 - index].fd;
        try std.testing.expectError(error.InvalidManifest, validate(&pair));
    }
}

test "native Helix service carry: actual nonlistener and duplicate lease descriptions refuse without flag mutation" {
    // Raw-fd descriptor rows; Windows HANDLEs cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const file = try tmp.dir.createFile(std.testing.io, "lifetime.lease", .{ .read = true });
    defer file.close(std.testing.io);
    const duplicate = try runtime.duplicate(file.handle);
    defer runtime.close(duplicate);
    const lease: Row = .{ .canonical = file.handle, .fd = file.handle, .role = .service_lifetime_lease, .shard = 0, .family = 0 };
    try validateReceivedRow(lease);
    const alias: Row = .{ .canonical = duplicate, .fd = duplicate, .role = .client, .shard = 0, .family = 0 };
    try std.testing.expectError(error.InvalidManifest, validatePhysicalServiceAliases(&.{lease}, alias));
    var sockets: [2]i32 = undefined;
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.socketpair(posix.AF.UNIX, posix.SOCK.SEQPACKET | posix.SOCK.CLOEXEC, 0, &sockets)));
    defer for (sockets) |fd| runtime.close(fd);
    const before = sys.fcntl(sockets[0], posix.F.GETFL, @as(c_int, 0));
    const not_listener: Row = .{ .canonical = sockets[0], .fd = sockets[0], .role = .service_listener, .shard = 0, .family = 0 };
    try std.testing.expectError(error.InvalidManifest, validateReceivedRow(not_listener));
    try std.testing.expectEqual(before, sys.fcntl(sockets[0], posix.F.GETFL, @as(c_int, 0)));
    try std.testing.expect(runtime.fdValid(file.handle));
    try std.testing.expect(runtime.fdValid(duplicate));
    try std.testing.expect(runtime.fdValid(sockets[0]));
}

test "native Helix service carry: actual protected SCM_RIGHTS pair rollback retains predecessor lifetime lease" {
    if (comptime @import("builtin").os.tag != .openbsd) return error.SkipZigTest;
    var fixture = try service.Fixture.root();
    defer service.Fixture.closeRoot(&fixture);
    var pair = try control.Pair.init();
    defer pair.deinit();
    const parent = &fixture.bootstrap;
    const identity: exchange.Identity = .{ .generation = 17, .upgrade_id = @splat(8) };
    const rows = [_]Row{
        .{ .canonical = parent.listener, .fd = parent.listener, .role = .service_listener, .shard = 0, .family = 0 },
        .{ .canonical = parent.lease.fd, .fd = parent.lease.fd, .role = .service_lifetime_lease, .shard = 0, .family = 0 },
    };
    try send(pair.parent, identity, &rows, exchange.deadlineAfter(1000));
    var received = try receive(std.testing.allocator, pair.child, identity, 2, exchange.deadlineAfter(1000));
    defer received.deinit();
    try service.validateDescriptors(received.rows[0].fd, received.rows[1].fd, &parent.state.context);
    const child_listener = received.rows[0].fd;
    const child_lease = received.rows[1].fd;
    try std.testing.expect(child_listener != parent.listener and child_lease != parent.lease.fd);
    received.deinit();
    try std.testing.expect(!runtime.fdValid(child_listener) and !runtime.fdValid(child_lease));
    try service.validateDescriptors(parent.listener, parent.lease.fd, &parent.state.context);
    const reopened = try (std.Io.Dir{ .handle = parent.ns.fd }).openFile(std.testing.io, service.lease_name, .{ .mode = .read_write });
    defer reopened.close(std.testing.io);
    try std.testing.expectError(error.WouldBlock, presence_lease.reaffirmExclusive(reopened.handle));
}

test "native Helix presence lease manifest rejects wrong shape singleton and descriptor aliases" {
    const lease: Row = .{ .canonical = 12, .fd = 32, .role = .presence_lease, .shard = 0, .family = 0 };
    try validate(&.{lease});
    var bad = lease;
    bad.family = 4;
    try std.testing.expectError(error.InvalidManifest, validate(&.{bad}));
    bad = lease;
    bad.shard = 1;
    try std.testing.expectError(error.InvalidManifest, validate(&.{bad}));
    bad = lease;
    bad.canonical = 13;
    bad.fd = 33;
    try std.testing.expectError(error.InvalidManifest, validate(&.{ lease, bad }));
    // These aliases must also reject when the second row has another role.
    bad.role = .client;
    bad.canonical = lease.canonical;
    try std.testing.expectError(error.InvalidManifest, validate(&.{ lease, bad }));
    bad.canonical = 13;
    bad.fd = lease.fd;
    try std.testing.expectError(error.InvalidManifest, validate(&.{ lease, bad }));
    try std.testing.expect(std.enums.fromInt(Role, 10) == null);
}

test "native Helix presence lease received descriptor must be a regular file" {
    // Raw-fd descriptor rows; Windows HANDLEs cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const file = try tmp.dir.createFile(std.testing.io, "lease.lock", .{ .read = true });
    defer file.close(std.testing.io);
    var row: Row = .{ .canonical = file.handle, .fd = file.handle, .role = .presence_lease, .shard = 0, .family = 0 };
    try validateReceivedRow(row);
    row.fd = tmp.dir.handle;
    try std.testing.expectError(error.InvalidManifest, validateReceivedRow(row));
    var sockets: [2]i32 = undefined;
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.socketpair(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0, &sockets)));
    defer for (sockets) |fd| runtime.close(fd);
    row.fd = sockets[0];
    try std.testing.expectError(error.InvalidManifest, validateReceivedRow(row));
    try std.testing.expect(runtime.fdValid(file.handle));
    try std.testing.expect(runtime.fdValid(sockets[0]));
}

test "native Helix presence lease SCM_RIGHTS keeps close-only rollback custody" {
    if (comptime @import("builtin").os.tag != .openbsd) return error.SkipZigTest;
    const issuer = @import("../mesh_presence_issuer.zig");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const parent = try issuer.acquireLease(std.testing.allocator, std.testing.io, tmp.dir, "lease.wal");
    defer parent.close(std.testing.io);
    var pair = try control.Pair.init();
    defer pair.deinit();
    const identity: exchange.Identity = .{ .generation = 11, .upgrade_id = @splat(5) };
    const row: Row = .{ .canonical = parent.handle, .fd = parent.handle, .role = .presence_lease, .shard = 0, .family = 0 };
    try send(pair.parent, identity, &.{row}, exchange.deadlineAfter(1000));
    var received = try receive(std.testing.allocator, pair.child, identity, 1, exchange.deadlineAfter(1000));
    defer received.deinit();
    try std.testing.expectEqual(@as(usize, 1), received.rows.len);
    const transferred = received.rows[0].fd;
    try std.testing.expect(transferred != parent.handle);
    try std.testing.expectEqual(row.canonical, received.rows[0].canonical);
    try std.testing.expectEqual(Role.presence_lease, received.rows[0].role);
    try std.testing.expectEqualDeep(try presence_lease.statRegular(parent.handle), try presence_lease.statRegular(transferred));
    try presence_lease.reaffirmExclusive(transferred);
    received.deinit();
    try std.testing.expect(!runtime.fdValid(transferred));
    const reopened = try tmp.dir.openFile(std.testing.io, "lease.wal.lock", .{ .mode = .read_write });
    defer reopened.close(std.testing.io);
    try std.testing.expectError(error.WouldBlock, presence_lease.reaffirmExclusive(reopened.handle));
    try presence_lease.reaffirmExclusive(parent.handle);
}

test "native Helix presence lease SCM_RIGHTS rejects socket and malformed typed roles" {
    if (comptime @import("builtin").os.tag != .openbsd) return error.SkipZigTest;
    var pair = try control.Pair.init();
    defer pair.deinit();
    const identity: exchange.Identity = .{ .generation = 12, .upgrade_id = @splat(6) };
    // Bypass sender validation to test the receiver's actual typed wire checks.
    const cases = [_]struct { role: u8, shard: u16, family: u8 }{
        .{ .role = 7, .shard = 0, .family = 0 }, // Valid shape, wrong received FD type.
        .{ .role = 7, .shard = 1, .family = 0 },
        .{ .role = 7, .shard = 0, .family = 4 },
        .{ .role = 255, .shard = 0, .family = 0 },
    };
    for (cases) |case| {
        var body: [row_size]u8 = undefined;
        std.mem.writeInt(i32, body[0..4], pair.parent, .big);
        std.mem.writeInt(u16, body[4..6], case.shard, .big);
        body[6] = case.role;
        body[7] = case.family;
        try exchange.send(pair.parent, .{ .kind = .descriptors, .identity = identity, .index = 0, .total = 1 }, &body, &.{pair.parent}, exchange.deadlineAfter(1000));
        try std.testing.expectError(error.InvalidManifest, receive(std.testing.allocator, pair.child, identity, 1, exchange.deadlineAfter(1000)));
        try std.testing.expect(runtime.fdValid(pair.parent));
    }
}
