// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Normal OpenBSD guest proof of batched custody and inert-child fd remapping.
const std = @import("std");
const root = @import("onyx_server");
const posix = std.posix;
const sys = posix.system;
const runtime = root.daemon.os_runtime;
const helix = root.daemon.helix;
const control = helix.native_control;
const exchange = helix.native_exchange;
const manifest = helix.native_manifest;
const arena_file = helix.native_arena_file;
const envelope = helix.native_arena_envelope;
const count = 65;
const identity: exchange.Identity = .{ .generation = 73, .upgrade_id = @splat(9) };
const expect = std.testing.expect;

const Sources = struct {
    rows: [count]manifest.Row = undefined,
    ports: [count]u16 = @splat(0),
    initialized: usize = 0,
    fn init(self: *Sources) !void {
        errdefer self.deinit();
        for (0..count) |index| {
            const fd = if (index >= count - 2)
                try runtime.openReadZ(if (index == count - 2) "/etc/hosts" else "/etc/resolv.conf")
            else blk: {
                const opened = sys.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
                if (posix.errno(opened) != .SUCCESS) return error.SocketFailed;
                const socket: i32 = @intCast(opened);
                errdefer runtime.close(socket);
                var address: posix.sockaddr.in = .{ .addr = std.mem.nativeToBig(u32, 0x7f00_0001), .port = 0 };
                if (posix.errno(sys.bind(socket, @ptrCast(&address), @sizeOf(@TypeOf(address)))) != .SUCCESS) return error.BindFailed;
                break :blk socket;
            };
            self.rows[index] = .{ .canonical = fd, .fd = fd, .role = if (index >= count - 2) .s2s_state else .client, .shard = @intCast(index % 3), .family = 0 };
            self.initialized += 1;
            try expect(fd < 1024);
            if (index < count - 2) self.ports[index] = try socketPort(fd);
        }
    }
    fn deinit(self: *Sources) void {
        for (self.rows[0..self.initialized]) |row| runtime.close(row.fd);
        self.initialized = 0;
    }
    fn verify(self: *const Sources, rows: []const manifest.Row) !void {
        try std.testing.expectEqual(@as(usize, count), rows.len);
        for (rows, 0..) |row, index| {
            try std.testing.expectEqual(self.rows[index].role, row.role);
            try std.testing.expectEqual(self.rows[index].shard, row.shard);
            try expect(runtime.fdValid(row.fd));
            const flags = sys.fcntl(row.fd, posix.F.GETFD, @as(c_int, 0));
            try expect(posix.errno(flags) == .SUCCESS and flags & posix.FD_CLOEXEC != 0);
            if (index < count - 2) {
                try std.testing.expectEqual(posix.SOCK.STREAM, try runtime.socketType(row.fd));
                try std.testing.expectEqual(self.ports[index], try socketPort(row.fd));
            } else {
                var first: [64]u8 = undefined;
                var actual: [64]u8 = undefined;
                // In the child, the original number can have been remapped;
                // use the configured file as the independent state identity.
                const reference = try runtime.openReadZ(if (index == count - 2) "/etc/hosts" else "/etc/resolv.conf");
                defer runtime.close(reference);
                const n = try runtime.pread(reference, &first, 0);
                const got = try runtime.pread(row.fd, &actual, 0);
                try expect(n > 0);
                try std.testing.expectEqualSlices(u8, first[0..n], actual[0..got]);
            }
        }
    }
};

fn socketPort(fd: i32) !u16 {
    var address: posix.sockaddr.in = undefined;
    var length: posix.socklen_t = @sizeOf(@TypeOf(address));
    if (posix.errno(sys.getsockname(fd, @ptrCast(&address), &length)) != .SUCCESS) return error.AddressFailed;
    try expect(length == @sizeOf(@TypeOf(address)) and address.family == posix.AF.INET);
    return std.mem.bigToNative(u16, address.port);
}
fn fdSet() [1024]bool {
    var result: [1024]bool = undefined;
    for (&result, 0..) |*live, fd| live.* = runtime.fdValid(@intCast(fd));
    return result;
}
fn sameFdSet(before: [1024]bool) !void {
    try std.testing.expectEqualSlices(bool, &before, &fdSet());
}

fn roundTrip(allocator: std.mem.Allocator, sources: *const Sources) !void {
    var pair = try control.Pair.init();
    defer pair.deinit();
    const before = fdSet();
    try manifest.send(pair.parent, identity, &sources.rows, exchange.deadlineAfter(1000));
    var received = try manifest.receive(allocator, pair.child, identity, count, exchange.deadlineAfter(1000));
    defer received.deinit();
    for (received.rows, sources.rows) |row, original| {
        try std.testing.expectEqual(original.canonical, row.canonical);
        try expect(row.fd != original.fd);
    }
    try sources.verify(received.rows);
    received.deinit();
    try sameFdSet(before);
    try sources.verify(&sources.rows);
    std.debug.print("PASS 65 indexed descriptors across 3 batches, exact socket/state identity, CLOEXEC and deinit custody\n", .{});
}

const Fault = enum { interrupted, malformed_last, wrong_generation_last };
fn sendBatch(fd: i32, sources: *const Sources, index: usize, fault: ?Fault) !void {
    const start = index * control.max_fds;
    const rows = sources.rows[start..@min(count, start + control.max_fds)];
    var payload: [control.max_fds * 8]u8 = undefined;
    var fds: [control.max_fds]i32 = undefined;
    for (rows, 0..) |row, i| {
        std.mem.writeInt(i32, payload[i * 8 ..][0..4], row.canonical, .big);
        std.mem.writeInt(u16, payload[i * 8 + 4 ..][0..2], row.shard, .big);
        payload[i * 8 + 6] = @intFromEnum(row.role);
        payload[i * 8 + 7] = row.family;
        fds[i] = row.fd;
    }
    var header: exchange.Header = .{ .kind = .descriptors, .identity = identity, .index = @intCast(index), .total = 3 };
    if (fault == .malformed_last) payload[6] = 255;
    if (fault == .wrong_generation_last) header.identity.generation += 1;
    try exchange.send(fd, header, payload[0 .. rows.len * 8], fds[0..rows.len], exchange.deadlineAfter(1000));
}
fn reject(allocator: std.mem.Allocator, sources: *const Sources, fault: Fault) !void {
    var pair = try control.Pair.init();
    defer pair.deinit();
    try sendBatch(pair.parent, sources, 0, null);
    if (fault == .interrupted) {
        runtime.close(pair.parent);
        pair.parent = -1;
    } else {
        try sendBatch(pair.parent, sources, 1, null);
        try sendBatch(pair.parent, sources, 2, fault);
    }
    const before = fdSet();
    if (manifest.receive(allocator, pair.child, identity, count, exchange.deadlineAfter(1000))) |received| {
        var unexpected = received;
        unexpected.deinit();
        return error.AcceptedInvalidManifest;
    } else |err| switch (fault) {
        .interrupted => try expect(err == error.Protocol or err == error.ReceiveFailed),
        .malformed_last => try expect(err == error.InvalidManifest),
        .wrong_generation_last => try expect(err == error.Protocol),
    }
    try sameFdSet(before);
    try sources.verify(&sources.rows);
    std.debug.print("PASS {s}: all accepted/failed-batch rights closed, parent descriptors intact\n", .{@tagName(fault)});
}

fn normalizedChild(allocator: std.mem.Allocator, sources: *const Sources, pair: control.Pair, arena_fd: i32, sealer: *const envelope.Sealer) !void {
    var rows = sources.rows;
    rows[0].canonical = sources.rows[1].fd;
    rows[1].canonical = sources.rows[0].fd;
    rows[2].canonical = pair.child;
    rows[3].canonical = arena_fd;
    var child_control = pair.child;
    var child_arena = arena_fd;
    try manifest.normalize(allocator, &rows, &child_control, &child_arena);
    try expect(child_control != pair.child and child_arena != arena_fd and child_control != child_arena);
    for (rows) |row| try expect(row.fd == row.canonical and row.fd != child_control and row.fd != child_arena);
    try sources.verify(&rows);
    const decoded = try arena_file.read(allocator, child_arena, sealer.key, sealer.upgrade_id);
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings("private checkpoint", decoded);
    try control.send(child_control, "NORMALIZED 65", &.{});
}
fn normalizeFork(allocator: std.mem.Allocator, sources: *const Sources) !void {
    var pair = try control.Pair.init();
    defer pair.deinit();
    var sealer = try envelope.Sealer.initRandom();
    defer sealer.deinit();
    var arena = try arena_file.Arena.create(allocator, &sealer, "private checkpoint");
    defer arena.deinit();
    const before = fdSet();
    const pid = sys.fork();
    if (pid < 0) return error.ForkFailed;
    if (pid == 0) {
        normalizedChild(allocator, sources, pair, arena.fd, &sealer) catch sys._exit(121);
        sys._exit(0);
    }
    var status: c_int = 0;
    if (sys.waitpid(pid, &status, 0) != pid or status != 0) return error.NormalizationChildFailed;
    var message = try exchange.receiveAny(pair.parent, exchange.deadlineAfter(1000));
    defer message.deinit();
    try std.testing.expectEqualStrings("NORMALIZED 65", message.bytes());
    try sameFdSet(before);
    try sources.verify(&sources.rows);
    const decoded = try arena_file.read(allocator, arena.fd, sealer.key, sealer.upgrade_id);
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings("private checkpoint", decoded);
    std.debug.print("PASS fork-isolated 65-fd normalization: cycles, colliding control/arena targets, state fds, unchanged parent\n", .{});
}

fn failedExec(allocator: std.mem.Allocator, sources: *const Sources) !void {
    var stream: [2]i32 = undefined;
    if (posix.errno(sys.socketpair(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0, &stream)) != .SUCCESS) return error.SocketFailed;
    defer for (stream) |fd| runtime.close(fd);
    const before = fdSet();
    if (helix.native_process.Process.spawn(allocator, "/tmp/onyx-helix-definitely-missing-executable", null, null, 74, exchange.deadlineAfter(1000))) |created| {
        var unexpected = created;
        unexpected.deinit();
        return error.UnexpectedCandidate;
    } else |err| try expect(err == error.Protocol or err == error.ReceiveFailed or err == error.SendFailed);
    try sameFdSet(before);
    try sources.verify(&sources.rows);
    const text = "parent still serving";
    try std.testing.expectEqual(text.len, try runtime.write(stream[0], text));
    var bytes: [64]u8 = undefined;
    const n = try runtime.read(stream[1], &bytes);
    try std.testing.expectEqualStrings(text, bytes[0..n]);
    std.debug.print("PASS actual failed exec before data handoff: candidate reaped, parent fds and stream usable\n", .{});
}

pub fn main(init: std.process.Init) !void {
    if (comptime @import("builtin").os.tag != .openbsd) return error.Unsupported;
    // This same-process oracle holds both source and received descriptor sets.
    // Raise only its own soft limit, within the guest's existing hard limit.
    var original_limit: std.c.rlimit = undefined;
    if (std.c.getrlimit(.NOFILE, &original_limit) != 0) return error.LimitUnavailable;
    var probe_limit = original_limit;
    probe_limit.cur = @max(probe_limit.cur, 512);
    if (probe_limit.cur > probe_limit.max or std.c.setrlimit(.NOFILE, &probe_limit) != 0) return error.LimitUnavailable;
    defer _ = std.c.setrlimit(.NOFILE, &original_limit);
    std.debug.print("probe soft nofile {d} -> {d}, hard {d}\n", .{ original_limit.cur, probe_limit.cur, probe_limit.max });
    var sources: Sources = .{};
    try sources.init();
    defer sources.deinit();
    try roundTrip(init.gpa, &sources);
    for ([_]Fault{ .interrupted, .malformed_last, .wrong_generation_last }) |fault| try reject(init.gpa, &sources, fault);
    try normalizeFork(init.gpa, &sources);
    try failedExec(init.gpa, &sources);
    std.debug.print("PASS all 6 native Helix primitive scenarios\n", .{});
}
