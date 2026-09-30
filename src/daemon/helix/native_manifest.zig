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
pub const max_entries = @import("live.zig").max_inherited_state_fds + 512;
pub const Role = enum(u8) { client = 1, s2s_state, plain_listener, tls_listener, websocket_listener, s2s_listener };
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
    if (row.role == .client or row.role == .s2s_state) {
        if (row.family != 0) return error.InvalidManifest;
    } else if (row.family != 4 and row.family != 6) return error.InvalidManifest;
}
pub fn validate(rows: []const Row) Error!void {
    if (rows.len > max_entries) return error.TooLarge;
    for (rows, 0..) |row, index| {
        try validateRow(row);
        for (rows[0..index]) |prior| if (prior.canonical == row.canonical or prior.fd == row.fd) return error.InvalidManifest;
    }
}
pub fn send(fd: i32, identity: exchange.Identity, rows: []const Row, deadline: i64) Error!void {
    try validate(rows);
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
            try validateRow(row);
            for (rows[0..accepted]) |prior| if (prior.canonical == row.canonical or prior.fd == row.fd) return error.InvalidManifest;
            rows[accepted] = row;
            accepted += 1;
            message.fds[item] = -1;
        }
    }
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
    try validate(rows);
    if (control_fd.* < 3 or arena_fd.* < 3 or control_fd.* == arena_fd.*) return error.InvalidManifest;
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
