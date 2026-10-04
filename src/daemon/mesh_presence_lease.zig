// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regular-file lease custody shared by hot authority and typed FD manifests.
//! Pure Zig wrappers around the existing target OS ABI. Never issue LOCK_UN:
//! closing an inherited duplicate releases only that reference to custody.
const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const sys = posix.system;

pub const Identity = struct {
    device: u64,
    inode: u64,
};
pub const Error = error{ Unsupported, StatFailed, NotRegular, IdentityMismatch, WouldBlock, LockFailed };
const supported = switch (builtin.os.tag) {
    .linux, .openbsd, .freebsd => true,
    else => false,
};

/// Full device/inode identity, never std.Io.File.Stat's inode alone. This is a
/// type/identity check; it does not establish shared lock-description custody.
fn identityBits(value: anytype) u64 {
    const T = @TypeOf(value);
    const U = @Int(.unsigned, @bitSizeOf(T));
    comptime std.debug.assert(@bitSizeOf(T) <= 64);
    return @intCast(@as(U, @bitCast(value)));
}

pub fn statRegular(fd: i32) Error!Identity {
    if (comptime !supported) return error.Unsupported;
    if (comptime builtin.os.tag == .linux) {
        const linux = std.os.linux;
        var stat: linux.Statx = std.mem.zeroes(linux.Statx);
        while (true) {
            switch (linux.errno(linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .TYPE = true, .INO = true }, &stat))) {
                .SUCCESS => break,
                .INTR => continue,
                else => return error.StatFailed,
            }
        }
        if (!stat.mask.TYPE or !stat.mask.INO) return error.StatFailed;
        if ((stat.mode & posix.S.IFMT) != posix.S.IFREG) return error.NotRegular;
        // Preserve the full major/minor pair, without narrowing a Linux dev_t
        // encoding or confusing it with the represented device's rdev fields.
        return .{ .device = (@as(u64, stat.dev_major) << 32) | stat.dev_minor, .inode = stat.ino };
    } else {
        var stat: posix.Stat = undefined;
        while (true) {
            switch (posix.errno(sys.fstat(fd, &stat))) {
                .SUCCESS => break,
                .INTR => continue,
                else => return error.StatFailed,
            }
        }
        if ((stat.mode & posix.S.IFMT) != posix.S.IFREG) return error.NotRegular;
        // BSD dev_t may be signed: identity is its entire same-width bit
        // pattern, not a signed numeric value that can trap on a high bit.
        return .{ .device = identityBits(stat.dev), .inode = identityBits(stat.ino) };
    }
}

/// Reaffirm an already-owned exclusive lock without std.Io.tryLock's unlocked
/// precondition and without any unlock/relock window. A separately reopened
/// same-inode descriptor fails while the predecessor still holds custody.
/// This alone cannot identify a shared description after every prior holder
/// has exited: the caller must perform authenticated transfer while its
/// quiesced predecessor is alive and still holds the exclusive lock.
pub fn reaffirmExclusive(fd: i32) Error!void {
    if (comptime !supported) return error.Unsupported;
    _ = try statRegular(fd);
    while (true) {
        switch (posix.errno(sys.flock(fd, posix.LOCK.EX | posix.LOCK.NB))) {
            .SUCCESS => return,
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            else => return error.LockFailed,
        }
    }
}

/// Borrow the inherited descriptor, open the configured EXISTING stable lock
/// path without following symlinks or creating/replacing it, and bind both to
/// the captured predecessor identity. Ownership remains with the stage caller.
pub fn validateInherited(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, wal_path: []const u8, inherited: std.Io.File, expected: Identity) !Identity {
    if (comptime !supported) return error.Unsupported;
    const actual = try statRegular(inherited.handle);
    if (!std.meta.eql(actual, expected)) return error.IdentityMismatch;
    const path = try std.mem.concat(allocator, u8, &.{ wal_path, ".lock" });
    defer allocator.free(path);
    const configured = try dir.openFile(io, path, .{ .mode = .read_only, .allow_directory = false, .follow_symlinks = false });
    defer configured.close(io);
    if (!std.meta.eql(actual, try statRegular(configured.handle))) return error.IdentityMismatch;
    try reaffirmExclusive(inherited.handle);
    return actual;
}

const runtime = @import("os_runtime.zig");
const issuer = @import("mesh_presence_issuer.zig");

test "mesh presence lease inherited duplicate reaffirms same inode while reopened description fails" {
    if (comptime !supported) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const parent = try issuer.acquireLease(std.testing.allocator, std.testing.io, tmp.dir, "lease.wal");
    defer parent.close(std.testing.io);
    const inherited: std.Io.File = .{ .handle = try runtime.duplicate(parent.handle), .flags = parent.flags };
    defer inherited.close(std.testing.io);
    const identity = try statRegular(parent.handle);
    try std.testing.expectEqualDeep(identity, try validateInherited(std.testing.allocator, std.testing.io, tmp.dir, "lease.wal", inherited, identity));
    try reaffirmExclusive(inherited.handle);
    const reopened = try tmp.dir.openFile(std.testing.io, "lease.wal.lock", .{ .mode = .read_write });
    defer reopened.close(std.testing.io);
    try std.testing.expectEqualDeep(identity, try statRegular(reopened.handle));
    try std.testing.expectError(error.WouldBlock, reaffirmExclusive(reopened.handle));
    try std.testing.expectError(error.WouldBlock, validateInherited(std.testing.allocator, std.testing.io, tmp.dir, "lease.wal", reopened, identity));
    try reaffirmExclusive(parent.handle);
}

test "mesh presence lease rejects wrong regular identity missing path and wrong descriptor type" {
    if (comptime !supported) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const parent = try issuer.acquireLease(std.testing.allocator, std.testing.io, tmp.dir, "lease.wal");
    defer parent.close(std.testing.io);
    var identity = try statRegular(parent.handle);
    identity.device ^= 1;
    try std.testing.expectError(error.IdentityMismatch, validateInherited(std.testing.allocator, std.testing.io, tmp.dir, "lease.wal", parent, identity));
    identity = try statRegular(parent.handle);
    identity.inode ^= 1;
    try std.testing.expectError(error.IdentityMismatch, validateInherited(std.testing.allocator, std.testing.io, tmp.dir, "lease.wal", parent, identity));
    identity = try statRegular(parent.handle);
    try std.testing.expectError(error.FileNotFound, validateInherited(std.testing.allocator, std.testing.io, tmp.dir, "absent.wal", parent, identity));
    const other = try issuer.acquireLease(std.testing.allocator, std.testing.io, tmp.dir, "other.wal");
    defer other.close(std.testing.io);
    try std.testing.expectError(error.IdentityMismatch, validateInherited(std.testing.allocator, std.testing.io, tmp.dir, "other.wal", parent, identity));
    try std.testing.expectError(error.NotRegular, statRegular(tmp.dir.handle));
    try std.testing.expectError(error.StatFailed, statRegular(-1));
    try reaffirmExclusive(parent.handle);
}

test "mesh presence lease identity preserves signed BSD device high bits" {
    try std.testing.expectEqual(@as(u64, 0xffff_ffff), identityBits(@as(i32, -1)));
    try std.testing.expectEqual(@as(u64, 0x8000_0000), identityBits(@as(i32, std.math.minInt(i32))));
    try std.testing.expectEqual(@as(u64, 0xffff_ffff), identityBits(@as(u32, std.math.maxInt(u32))));
    try std.testing.expectEqual(std.math.maxInt(u64), identityBits(@as(i64, -1)));
    try std.testing.expectEqual(std.math.maxInt(u64), identityBits(@as(u64, std.math.maxInt(u64))));
}
