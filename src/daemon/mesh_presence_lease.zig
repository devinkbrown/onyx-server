// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regular-file lease custody shared by hot authority and typed FD manifests.
//! Pure Zig wrappers around the existing target OS ABI. A borrowed duplicate
//! must retain the same lock custody as its predecessor.
const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const sys = posix.system;

pub const Identity = struct {
    device: u64,
    inode: u64,
    /// Upper half of Windows' 128-bit file ID (ReFS); zero on POSIX.
    inode_high: u64 = 0,
};
pub const Error = error{ Unsupported, StatFailed, NotRegular, IdentityMismatch, WouldBlock, LockFailed };
const supported = switch (builtin.os.tag) {
    .linux, .openbsd, .freebsd, .windows => true,
    else => false,
};

/// Full POSIX device/inode or Windows volume/128-bit file identity, never
/// std.Io.File.Stat's inode alone. Identity does not establish lock custody.
fn identityBits(value: anytype) u64 {
    const T = @TypeOf(value);
    const U = @Int(.unsigned, @bitSizeOf(T));
    comptime std.debug.assert(@bitSizeOf(T) <= 64);
    return @intCast(@as(U, @bitCast(value)));
}

const Windows = if (builtin.os.tag == .windows) struct {
    const windows = std.os.windows;
    const Handle = windows.HANDLE;
    const FileIdInfo = extern struct { volume: u64, id: [16]u8 };
    const FileStandardInfo = extern struct {
        allocation_size: i64,
        end_of_file: i64,
        links: u32,
        delete_pending: u8,
        directory: u8,
    };
    const FileAttributeTagInfo = extern struct { attributes: u32, tag: u32 };
    const Overlapped = extern struct {
        internal: usize = 0,
        internal_high: usize = 0,
        offset: u32 = 0,
        offset_high: u32 = 0,
        event: ?Handle = null,
    };

    extern "kernel32" fn GetFileType(Handle) callconv(.winapi) u32;
    extern "kernel32" fn GetFileInformationByHandleEx(Handle, i32, *anyopaque, u32) callconv(.winapi) i32;
    extern "kernel32" fn LockFileEx(Handle, u32, u32, u32, u32, *Overlapped) callconv(.winapi) i32;
    extern "kernel32" fn UnlockFileEx(Handle, u32, u32, u32, *Overlapped) callconv(.winapi) i32;
    extern "kernel32" fn ReadFile(Handle, [*]u8, u32, *u32, *Overlapped) callconv(.winapi) i32;
    extern "kernel32" fn GetOverlappedResult(Handle, *Overlapped, *u32, i32) callconv(.winapi) i32;
    extern "kernel32" fn CreateEventW(?*anyopaque, i32, i32, ?[*:0]const u16) callconv(.winapi) ?Handle;
    extern "kernel32" fn CloseHandle(Handle) callconv(.winapi) i32;
    extern "kernel32" fn GetLastError() callconv(.winapi) u32;
    extern "kernel32" fn GetCurrentProcess() callconv(.winapi) Handle;
    extern "kernel32" fn DuplicateHandle(Handle, Handle, Handle, *Handle, u32, i32, u32) callconv(.winapi) i32;
    extern "kernel32" fn CreateHardLinkW([*:0]const u16, [*:0]const u16, ?*anyopaque) callconv(.winapi) i32;

    comptime {
        if (@sizeOf(FileIdInfo) != 24 or @sizeOf(FileStandardInfo) != 24 or @sizeOf(Overlapped) != 32)
            @compileError("Windows lease file-information ABI mismatch");
    }

    fn statRegular(handle: Handle) Error!Identity {
        if (GetFileType(handle) != 1) return if (GetLastError() == 6) error.StatFailed else error.NotRegular;
        var standard: FileStandardInfo = undefined;
        if (GetFileInformationByHandleEx(handle, 1, &standard, @sizeOf(FileStandardInfo)) == 0) return error.StatFailed;
        if (standard.directory != 0 or standard.delete_pending != 0) return error.NotRegular;
        // A second path to this file could bypass its configured identity.
        if (standard.links != 1) return error.NotRegular;
        var attributes: FileAttributeTagInfo = undefined;
        if (GetFileInformationByHandleEx(handle, 9, &attributes, @sizeOf(FileAttributeTagInfo)) == 0) return error.StatFailed;
        if ((attributes.attributes & 0x400) != 0) return error.NotRegular; // FILE_ATTRIBUTE_REPARSE_POINT
        var info: FileIdInfo = undefined;
        if (GetFileInformationByHandleEx(handle, 18, &info, @sizeOf(FileIdInfo)) == 0) return error.StatFailed;
        return .{
            .device = info.volume,
            .inode = std.mem.readInt(u64, info.id[0..8], .little),
            .inode_high = std.mem.readInt(u64, info.id[8..16], .little),
        };
    }

    fn reaffirmExclusive(handle: Handle) Error!void {
        _ = try @This().statRegular(handle);
        // std.Io.File.tryLock owns byte zero. Windows rejects an overlapping
        // exclusive lock even through a duplicate, so a failed probe alone
        // cannot distinguish the duplicate from a reopened handle.
        const lock_event = CreateEventW(null, 1, 0, null) orelse return error.LockFailed;
        defer _ = CloseHandle(lock_event);
        const unlock_event = CreateEventW(null, 1, 0, null) orelse return error.LockFailed;
        defer _ = CloseHandle(unlock_event);
        var overlap: Overlapped = .{ .event = lock_event };
        var acquired = LockFileEx(handle, 0x3, 0, 1, 0, &overlap) != 0;
        if (!acquired) {
            const code = GetLastError();
            if (code == 997) { // ERROR_IO_PENDING: keep OVERLAPPED alive.
                var transferred: u32 = 0;
                acquired = GetOverlappedResult(handle, &overlap, &transferred, 1) != 0;
                if (!acquired and GetLastError() != 33) return error.LockFailed;
            } else if (code != 33) return error.LockFailed;
        }
        if (acquired) {
            // No predecessor lock existed. Release only this probe's new lock.
            var unlock: Overlapped = .{ .event = unlock_event };
            if (UnlockFileEx(handle, 0, 1, 0, &unlock) == 0) {
                if (GetLastError() != 997) return error.LockFailed;
                var transferred: u32 = 0;
                if (GetOverlappedResult(handle, &unlock, &transferred, 1) == 0) return error.LockFailed;
            }
            return error.WouldBlock;
        }

        // A duplicate in this process shares the locking FILE_OBJECT and can
        // read the marker byte written after acquisition. A separately opened
        // handle, or a child inheriting a parent's locked handle, cannot.
        // EOF is never custody evidence: an empty file has no locked byte to
        // read, regardless of which handle attempted the read.
        const read_event = CreateEventW(null, 1, 0, null) orelse return error.LockFailed;
        defer _ = CloseHandle(read_event);
        var read: Overlapped = .{ .event = read_event };
        var byte: [1]u8 = undefined;
        var count: u32 = 0;
        if (ReadFile(handle, &byte, 1, &count, &read) == 0) {
            const code = GetLastError();
            if (code == 997) { // ERROR_IO_PENDING
                if (GetOverlappedResult(handle, &read, &count, 1) == 0)
                    return if (GetLastError() == 33) error.WouldBlock else error.LockFailed;
            } else return if (code == 33) error.WouldBlock else error.LockFailed;
        }
        if (count != 1) return error.LockFailed;
    }

    fn duplicateWithAccess(file: std.Io.File, access: u32, options: u32) !std.Io.File {
        var copy: Handle = undefined;
        const process = GetCurrentProcess();
        if (DuplicateHandle(process, file.handle, process, &copy, access, 0, options) == 0) return error.LockFailed;
        return .{ .handle = copy, .flags = file.flags };
    }

    fn duplicate(file: std.Io.File) !std.Io.File {
        return duplicateWithAccess(file, 0, 2); // DUPLICATE_SAME_ACCESS
    }
} else struct {};

pub fn statRegular(fd: std.Io.File.Handle) Error!Identity {
    if (comptime !supported) return error.Unsupported;
    if (comptime builtin.os.tag == .windows) {
        return Windows.statRegular(fd);
    } else if (comptime builtin.os.tag == .linux) {
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
/// precondition and without unlocking an already-owned lock. A reopened
/// same-inode descriptor fails while the predecessor still holds custody.
/// This alone cannot identify a shared description after every prior holder
/// has exited: the caller must perform authenticated transfer while its
/// quiesced predecessor is alive and still holds the exclusive lock.
/// Windows proves only same-process DuplicateHandle custody. A child process
/// does not inherit access to the parent's locked byte; cross-process Helix
/// lease adoption is unsupported and must stay gated off by its caller.
pub fn reaffirmExclusive(fd: std.Io.File.Handle) Error!void {
    if (comptime !supported) return error.Unsupported;
    if (comptime builtin.os.tag == .windows) return Windows.reaffirmExclusive(fd);
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
/// On Windows, only a same-process duplicate can pass this custody check;
/// cross-process inherited HANDLE transfer cannot establish hot authority.
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

test "mesh presence lease inherited duplicate reaffirms same file while reopened description fails" {
    if (comptime !supported) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const parent = try issuer.acquireLease(std.testing.allocator, std.testing.io, tmp.dir, "lease.wal");
    defer parent.close(std.testing.io);
    const inherited: std.Io.File = if (comptime builtin.os.tag == .windows)
        try Windows.duplicate(parent)
    else
        .{ .handle = try runtime.duplicate(parent.handle), .flags = parent.flags };
    defer inherited.close(std.testing.io);
    const identity = try statRegular(parent.handle);
    const size_before = (try parent.stat(std.testing.io)).size;
    try std.testing.expectEqualDeep(identity, try validateInherited(std.testing.allocator, std.testing.io, tmp.dir, "lease.wal", inherited, identity));
    try reaffirmExclusive(inherited.handle);
    try std.testing.expectEqual(size_before, (try parent.stat(std.testing.io)).size);
    if (comptime builtin.os.tag == .windows) {
        const read_only = try Windows.duplicateWithAccess(parent, 0x8000_0000, 0); // GENERIC_READ
        defer read_only.close(std.testing.io);
        try std.testing.expectEqualDeep(identity, try validateInherited(std.testing.allocator, std.testing.io, tmp.dir, "lease.wal", read_only, identity));
        try std.testing.expectEqual(size_before, (try parent.stat(std.testing.io)).size);
    }
    const reopened = try tmp.dir.openFile(std.testing.io, "lease.wal.lock", .{ .mode = .read_write });
    defer reopened.close(std.testing.io);
    try std.testing.expectEqualDeep(identity, try statRegular(reopened.handle));
    try std.testing.expectError(error.WouldBlock, reaffirmExclusive(reopened.handle));
    try std.testing.expectError(error.WouldBlock, validateInherited(std.testing.allocator, std.testing.io, tmp.dir, "lease.wal", reopened, identity));
    try reaffirmExclusive(parent.handle);
}

test "mesh presence lease refuses an unlocked regular handle" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const unlocked = try tmp.dir.createFile(std.testing.io, "lease.wal.lock", .{ .read = true });
    defer unlocked.close(std.testing.io);
    const identity = try statRegular(unlocked.handle);
    try std.testing.expectError(error.WouldBlock, reaffirmExclusive(unlocked.handle));
    try std.testing.expectError(error.WouldBlock, validateInherited(std.testing.allocator, std.testing.io, tmp.dir, "lease.wal", unlocked, identity));
}

test "mesh presence lease Windows refuses empty locked file through owner and duplicate" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const owner = try tmp.dir.createFile(std.testing.io, "lease.wal.lock", .{ .read = true });
    defer owner.close(std.testing.io);
    try std.testing.expect(try owner.tryLock(std.testing.io, .exclusive));
    const duplicate = try Windows.duplicate(owner);
    defer duplicate.close(std.testing.io);
    const identity = try statRegular(owner.handle);
    try std.testing.expectEqual(@as(u64, 0), (try owner.stat(std.testing.io)).size);
    try std.testing.expectError(error.LockFailed, reaffirmExclusive(owner.handle));
    try std.testing.expectError(error.LockFailed, reaffirmExclusive(duplicate.handle));
    try std.testing.expectError(error.LockFailed, validateInherited(std.testing.allocator, std.testing.io, tmp.dir, "lease.wal", duplicate, identity));
    const reopened = try tmp.dir.openFile(std.testing.io, "lease.wal.lock", .{ .mode = .read_write });
    defer reopened.close(std.testing.io);
    try std.testing.expectError(error.WouldBlock, reaffirmExclusive(reopened.handle));
}

test "mesh presence lease Windows duplicate retains custody after source close" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const parent = try issuer.acquireLease(std.testing.allocator, std.testing.io, tmp.dir, "lease.wal");
    var parent_open = true;
    defer if (parent_open) parent.close(std.testing.io);
    const inherited = try Windows.duplicate(parent);
    defer inherited.close(std.testing.io);
    const identity = try statRegular(parent.handle);
    parent.close(std.testing.io);
    parent_open = false;
    try std.testing.expectEqualDeep(identity, try validateInherited(std.testing.allocator, std.testing.io, tmp.dir, "lease.wal", inherited, identity));
    const reopened = try tmp.dir.openFile(std.testing.io, "lease.wal.lock", .{ .mode = .read_write });
    defer reopened.close(std.testing.io);
    try std.testing.expectError(error.WouldBlock, reaffirmExclusive(reopened.handle));
}

test "mesh presence lease Windows reads a nonempty locked byte without mutation" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        const existing = try tmp.dir.createFile(std.testing.io, "lease.wal.lock", .{ .read = true });
        defer existing.close(std.testing.io);
        try existing.writePositionalAll(std.testing.io, "Q", 0);
    }
    const parent = try issuer.acquireLease(std.testing.allocator, std.testing.io, tmp.dir, "lease.wal");
    defer parent.close(std.testing.io);
    const inherited = try Windows.duplicate(parent);
    defer inherited.close(std.testing.io);
    const identity = try statRegular(parent.handle);
    try std.testing.expectEqualDeep(identity, try validateInherited(std.testing.allocator, std.testing.io, tmp.dir, "lease.wal", inherited, identity));
    try std.testing.expectEqual(@as(u64, 1), (try parent.stat(std.testing.io)).size);
    var byte: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try parent.readPositionalAll(std.testing.io, &byte, 0));
    try std.testing.expectEqual(@as(u8, 'Q'), byte[0]);
    const reopened = try tmp.dir.openFile(std.testing.io, "lease.wal.lock", .{ .mode = .read_write });
    defer reopened.close(std.testing.io);
    try std.testing.expectError(error.WouldBlock, reaffirmExclusive(reopened.handle));
}

test "mesh presence lease Windows initializes an empty existing lock after acquisition" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        const empty = try tmp.dir.createFile(std.testing.io, "lease.wal.lock", .{ .read = true });
        defer empty.close(std.testing.io);
        try std.testing.expectEqual(@as(u64, 0), (try empty.stat(std.testing.io)).size);
    }
    const parent = try issuer.acquireLease(std.testing.allocator, std.testing.io, tmp.dir, "lease.wal");
    defer parent.close(std.testing.io);
    try std.testing.expectEqual(@as(u64, 1), (try parent.stat(std.testing.io)).size);
    var byte: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try parent.readPositionalAll(std.testing.io, &byte, 0));
    try std.testing.expectEqual(@as(u8, 'L'), byte[0]);
    try reaffirmExclusive(parent.handle);
}

test "mesh presence lease Windows rejects hardlink alias before marker write" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const target_file = try tmp.dir.createFile(std.testing.io, "target.wal.lock", .{ .read = true });
    defer target_file.close(std.testing.io);
    const target_path = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}/target.wal.lock", .{&tmp.sub_path});
    defer std.testing.allocator.free(target_path);
    const alias_path = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}/alias.wal.lock", .{&tmp.sub_path});
    defer std.testing.allocator.free(alias_path);
    const target_w = try std.unicode.utf8ToUtf16LeAllocZ(std.testing.allocator, target_path);
    defer std.testing.allocator.free(target_w);
    const alias_w = try std.unicode.utf8ToUtf16LeAllocZ(std.testing.allocator, alias_path);
    defer std.testing.allocator.free(alias_w);
    try std.testing.expect(Windows.CreateHardLinkW(alias_w.ptr, target_w.ptr, null) != 0);
    try std.testing.expectError(error.NotRegular, issuer.acquireLease(std.testing.allocator, std.testing.io, tmp.dir, "alias.wal"));
    try std.testing.expectEqual(@as(u64, 0), (try target_file.stat(std.testing.io)).size);
}

test "mesh presence lease Windows rejects symlink path before marker write" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const target_file = try tmp.dir.createFile(std.testing.io, "target.wal.lock", .{ .read = true });
    defer target_file.close(std.testing.io);
    tmp.dir.symLink(std.testing.io, "target.wal.lock", "alias.wal.lock", .{}) catch |err| switch (err) {
        error.AccessDenied, error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    if (issuer.acquireLease(std.testing.allocator, std.testing.io, tmp.dir, "alias.wal")) |lease| {
        lease.close(std.testing.io);
        return error.TestUnexpectedResult;
    } else |_| {}
    try std.testing.expectEqual(@as(u64, 0), (try target_file.stat(std.testing.io)).size);
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
    identity.inode_high ^= 1;
    try std.testing.expectError(error.IdentityMismatch, validateInherited(std.testing.allocator, std.testing.io, tmp.dir, "lease.wal", parent, identity));
    identity = try statRegular(parent.handle);
    try std.testing.expectError(error.FileNotFound, validateInherited(std.testing.allocator, std.testing.io, tmp.dir, "absent.wal", parent, identity));
    const other = try issuer.acquireLease(std.testing.allocator, std.testing.io, tmp.dir, "other.wal");
    defer other.close(std.testing.io);
    try std.testing.expectError(error.IdentityMismatch, validateInherited(std.testing.allocator, std.testing.io, tmp.dir, "other.wal", parent, identity));
    try std.testing.expectError(error.NotRegular, statRegular(tmp.dir.handle));
    const wrong_type: std.Io.File = .{ .handle = tmp.dir.handle, .flags = .{ .nonblocking = false } };
    try std.testing.expectError(error.NotRegular, validateInherited(std.testing.allocator, std.testing.io, tmp.dir, "lease.wal", wrong_type, identity));
    if (comptime builtin.os.tag == .windows) {
        try std.testing.expectError(error.StatFailed, statRegular(@ptrFromInt(std.math.maxInt(usize))));
    } else {
        try std.testing.expectError(error.StatFailed, statRegular(-1));
    }
    try reaffirmExclusive(parent.handle);
}

test "mesh presence lease identity preserves signed BSD device high bits" {
    try std.testing.expectEqual(@as(u64, 0xffff_ffff), identityBits(@as(i32, -1)));
    try std.testing.expectEqual(@as(u64, 0x8000_0000), identityBits(@as(i32, std.math.minInt(i32))));
    try std.testing.expectEqual(@as(u64, 0xffff_ffff), identityBits(@as(u32, std.math.maxInt(u32))));
    try std.testing.expectEqual(std.math.maxInt(u64), identityBits(@as(i64, -1)));
    try std.testing.expectEqual(std.math.maxInt(u64), identityBits(@as(u64, std.math.maxInt(u64))));
}
