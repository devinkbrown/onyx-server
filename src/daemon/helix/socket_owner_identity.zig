// SPDX-License-Identifier: AGPL-3.0-or-later
//! Native ownership validation for carried IRC/S2S sockets. The caller derives
//! owner indices independently from the capsules and retains exclusive custody
//! of every descriptor until adoption finishes. This checks one snapshot, not
//! intentional sharing between predecessor and successor processes.
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

pub const Error = error{
    Unsupported,
    InvalidOwnerIndex,
    InvalidScratchSize,
    SocketIdentityUnavailable,
    DuplicateSocketOwner,
};

fn socketCookie(fd: linux.fd_t) Error!u64 {
    if (comptime builtin.os.tag != .linux) return error.Unsupported;
    var cookie: u64 = 0;
    var length: linux.socklen_t = @sizeOf(u64);
    while (true) {
        switch (linux.errno(linux.getsockopt(fd, linux.SOL.SOCKET, linux.SO.COOKIE, @ptrCast(&cookie), &length))) {
            .SUCCESS => break,
            .INTR => continue,
            else => return error.SocketIdentityUnavailable,
        }
    }
    if (length != @sizeOf(u64) or cookie == 0) return error.SocketIdentityUnavailable;
    return cookie;
}

/// Scratch is caller-funded and may be modified on failure. No descriptor is
/// closed, no memory is allocated, and no adopted mapping is published here.
/// Gaps in owner_indices deliberately exclude unrelated carried descriptors.
pub fn validateOwnedSockets(inherited_fds: []const linux.fd_t, owner_indices: []const u32, cookie_scratch: []u64) Error!void {
    if (cookie_scratch.len != owner_indices.len) return error.InvalidScratchSize;
    if (owner_indices.len == 0) return;
    if (comptime builtin.os.tag != .linux) return error.Unsupported;
    for (owner_indices, cookie_scratch) |index, *cookie| {
        if (index >= inherited_fds.len) return error.InvalidOwnerIndex;
        cookie.* = try socketCookie(inherited_fds[index]);
    }
    std.mem.sort(u64, cookie_scratch, {}, std.sort.asc(u64));
    for (cookie_scratch[1..], cookie_scratch[0 .. cookie_scratch.len - 1]) |cookie, previous| {
        if (cookie == previous) return error.DuplicateSocketOwner;
    }
}

test "socket owner identity rejects real dup aliases and preserves original sockets" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const handoff = @import("handoff.zig");
    var owners = try handoff.socketPair();
    defer owners.close();
    const duplicate_rc = linux.dup(owners.supervisor);
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(duplicate_rc));
    const duplicate: linux.fd_t = @intCast(duplicate_rc);
    defer _ = linux.close(duplicate);
    try std.testing.expect(duplicate != owners.supervisor);
    var scratch: [2]u64 = undefined;
    try validateOwnedSockets(&.{ owners.supervisor, owners.worker }, &.{ 0, 1 }, &scratch);
    try std.testing.expect(scratch[0] != scratch[1]);
    try std.testing.expectError(error.DuplicateSocketOwner, validateOwnedSockets(&.{ owners.supervisor, duplicate }, &.{ 0, 1 }, &scratch));
    try std.testing.expectError(error.DuplicateSocketOwner, validateOwnedSockets(&.{owners.supervisor}, &.{ 0, 0 }, &scratch));
    // Refusal leaves caller-owned descriptors valid and usable.
    try std.testing.expectEqual(@as(usize, 1), linux.write(owners.supervisor, "x", 1));
    var byte: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), linux.read(owners.worker, &byte, 1));
    try std.testing.expectEqual(@as(u8, 'x'), byte[0]);
}

test "socket owner identity rejects SCM_RIGHTS aliases but accepts distinct transferred owners" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const handoff = @import("handoff.zig");
    const a = std.testing.allocator;
    var owners = try handoff.socketPair();
    defer owners.close();
    var control = try handoff.socketPair();
    defer control.close();
    // SCM_RIGHTS installs two distinct descriptor numbers for the same socket.
    try handoff.sendFdBatch(control.supervisor, &.{ owners.supervisor, owners.supervisor }, "alias");
    var aliased = try handoff.recvFdBatch(a, control.worker, 16);
    defer {
        for (aliased.fds) |fd| _ = linux.close(fd);
        aliased.deinit(a);
    }
    try std.testing.expectEqual(@as(usize, 2), aliased.fds.len);
    try std.testing.expect(aliased.fds[0] != aliased.fds[1]);
    var scratch: [2]u64 = undefined;
    try std.testing.expectError(error.DuplicateSocketOwner, validateOwnedSockets(aliased.fds, &.{ 0, 1 }, &scratch));
    try handoff.sendFdBatch(control.supervisor, &.{ owners.supervisor, owners.worker }, "distinct");
    var distinct = try handoff.recvFdBatch(a, control.worker, 16);
    defer {
        for (distinct.fds) |fd| _ = linux.close(fd);
        distinct.deinit(a);
    }
    try std.testing.expectEqual(@as(usize, 2), distinct.fds.len);
    try validateOwnedSockets(distinct.fds, &.{ 0, 1 }, &scratch);
}

test "socket owner identity bounds scratch and checks only independently selected owners" {
    try validateOwnedSockets(&.{}, &.{}, &.{});
    var wrong_scratch = [_]u64{0};
    try std.testing.expectError(error.InvalidScratchSize, validateOwnedSockets(&.{}, &.{}, &wrong_scratch));
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const handoff = @import("handoff.zig");
    var owners = try handoff.socketPair();
    defer owners.close();
    var scratch: [2]u64 = undefined;
    try validateOwnedSockets(&.{ owners.supervisor, -1, owners.worker }, &.{ 2, 0 }, &scratch);
    try std.testing.expectError(error.InvalidOwnerIndex, validateOwnedSockets(&.{owners.supervisor}, &.{ 0, 1 }, &scratch));
    try std.testing.expectError(error.SocketIdentityUnavailable, validateOwnedSockets(&.{ owners.supervisor, -1 }, &.{ 0, 1 }, &scratch));
    var arena = try handoff.Arena.create("cookie-not-socket");
    defer arena.close();
    try std.testing.expectError(error.SocketIdentityUnavailable, validateOwnedSockets(&.{ owners.supervisor, arena.fd }, &.{ 0, 1 }, &scratch));
}
