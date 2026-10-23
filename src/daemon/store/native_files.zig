// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Native descriptor identity, captured files and atomic namespace custody.

const std = @import("std");
const cold_identity = @import("../mesh_presence_lease.zig");
const cold_runtime = @import("../os_runtime.zig");
const StoreError = @import("contracts.zig").StoreError;
const coldDigest = @import("wal.zig").coldDigest;

/// The authenticated Helix manifest binds a Windows WAL HANDLE to its exact
/// disk object and replay cut. FileIdInfo retains the full 128-bit file ID;
/// std.Io.File.Stat.inode alone is insufficient for this transfer.
pub const WindowsWalWitness = struct {
    file: WindowsFileIdInfo,
    parent_directory: WindowsFileIdInfo,
    name_digest: [std.crypto.hash.Blake3.digest_length]u8,
    length: u64,
};

pub const WindowsWalDescriptor = struct {
    handle: usize,
    destination_pid: u32,
    witness: WindowsWalWitness,

    /// Called by the receiving process if staging fails or is aborted. A
    /// descriptor in a different PID's handle table is never closed here.
    pub fn deinitReceived(self: *WindowsWalDescriptor) void {
        if (comptime @import("builtin").os.tag == .windows) {
            if (self.handle != 0 and self.destination_pid == GetCurrentProcessId())
                _ = CloseHandle(self.handle);
        }
        self.handle = 0;
    }
};

/// Parent-side rollback custody until a descriptor has been sent on the
/// authenticated control channel. `release` transfers close responsibility to
/// the child; aborting earlier closes the duplicate in that process.
pub const WindowsWalTransfer = struct {
    target_process: usize,
    descriptor: WindowsWalDescriptor,

    pub fn deinit(self: *WindowsWalTransfer) void {
        if (comptime @import("builtin").os.tag == .windows) {
            if (self.descriptor.handle != 0) {
                var local: usize = 0;
                if (DuplicateHandle(self.target_process, self.descriptor.handle, GetCurrentProcess(), &local, 0, 0, windows_duplicate_same_access | windows_duplicate_close_source) != 0 and local != 0)
                    _ = CloseHandle(local);
            }
        }
        self.descriptor.handle = 0;
    }

    pub fn release(self: *WindowsWalTransfer) WindowsWalDescriptor {
        const descriptor = self.descriptor;
        self.descriptor.handle = 0;
        return descriptor;
    }
};

pub const WindowsFileIdInfo = extern struct {
    volume_serial: u64,
    file_id: [16]u8,
};

comptime {
    if (@sizeOf(WindowsFileIdInfo) != 24) @compileError("Windows FILE_ID_INFO ABI mismatch");
}

pub const windows_file_id_info_class: i32 = 18;

pub const windows_duplicate_same_access: u32 = 2;

pub const windows_duplicate_close_source: u32 = 1;

pub extern "kernel32" fn GetFileInformationByHandleEx(handle: usize, class: i32, info: *anyopaque, size: u32) callconv(.winapi) i32;

pub extern "kernel32" fn CreateHardLinkW(new_name: [*:0]const u16, existing_name: [*:0]const u16, security: ?*anyopaque) callconv(.winapi) i32;

pub extern "kernel32" fn DuplicateHandle(source_process: usize, source_handle: usize, target_process: usize, target_handle: *usize, desired_access: u32, inherit_handle: i32, options: u32) callconv(.winapi) i32;

pub extern "kernel32" fn GetCurrentProcess() callconv(.winapi) usize;

pub extern "kernel32" fn GetCurrentProcessId() callconv(.winapi) u32;

pub extern "kernel32" fn GetProcessId(process: usize) callconv(.winapi) u32;

pub extern "kernel32" fn CloseHandle(handle: usize) callconv(.winapi) i32;

pub extern "kernel32" fn SetFileInformationByHandle(handle: usize, class: i32, info: *const anyopaque, size: u32) callconv(.winapi) i32;

pub extern "kernel32" fn GetVolumeInformationByHandleW(handle: usize, volume_name: ?[*]u16, volume_name_len: u32, serial: ?*u32, max_component: ?*u32, flags: ?*u32, fs_name: ?[*]u16, fs_name_len: u32) callconv(.winapi) i32;

pub fn windowsFileIdentity(handle: usize) !WindowsFileIdInfo {
    if (comptime @import("builtin").os.tag != .windows) return error.Unsupported;
    var info: WindowsFileIdInfo = undefined;
    if (GetFileInformationByHandleEx(handle, windows_file_id_info_class, &info, @sizeOf(WindowsFileIdInfo)) == 0)
        return StoreError.SnapshotCoverageMismatch;
    return info;
}

pub fn windowsColdAtomicIdentity(handle: std.Io.File.Handle) !cold_identity.Identity {
    if (comptime @import("builtin").os.tag != .windows) return error.Unsupported;
    // Zig's initial Atomic handle is GENERIC_WRITE. FileIdInfo remains
    // queryable even when FileAttributeTagInfo is denied on that handle.
    const id = try windowsFileIdentity(@intFromPtr(handle));
    return .{
        .device = id.volume_serial,
        .inode = std.mem.readInt(u64, id.file_id[0..8], .little),
        .inode_high = std.mem.readInt(u64, id.file_id[8..16], .little),
    };
}

pub fn windowsWalWitness(io: std.Io, file: std.Io.File, dir: std.Io.Dir, name: []const u8) !WindowsWalWitness {
    if (comptime @import("builtin").os.tag != .windows) return error.Unsupported;
    const stat = try file.stat(io);
    if (stat.kind != .file) return StoreError.SnapshotCoverageMismatch;
    var digest: [std.crypto.hash.Blake3.digest_length]u8 = undefined;
    std.crypto.hash.Blake3.hash(name, &digest, .{});
    return .{
        .file = try windowsFileIdentity(@intFromPtr(file.handle)),
        .parent_directory = try windowsFileIdentity(@intFromPtr(dir.handle)),
        .name_digest = digest,
        .length = stat.size,
    };
}

/// Flush a directory handle where the platform allows it. Windows rejects
/// FlushFileBuffers on directory handles, so directory-entry durability is
/// not enforced there; the WAL file syncs on every mutation path still cover
/// file data.
pub fn syncDirectory(io: std.Io, directory: std.Io.File) !void {
    if (comptime @import("builtin").os.tag == .windows) return;
    try directory.sync(io);
}

pub const cold_posix = switch (@import("builtin").os.tag) {
    .linux, .openbsd, .freebsd => true,
    else => false,
};

pub const ColdOpenMode = enum { read_only, read_only_share_delete, read_write, directory };

/// Existing cold namespace acquisition never creates and cannot wait for a FIFO
/// peer. Force directory type for parent custody; held regular descriptors are
/// type checked before reading any application bytes.
pub fn openColdExisting(io: std.Io, dir: std.Io.Dir, path: []const u8, mode: ColdOpenMode) !std.Io.File {
    const os = @import("builtin").os.tag;
    if (comptime os == .windows) {
        const windows = std.os.windows;
        if (path.len == 0 or std.mem.indexOfScalar(u8, path, 0) != null) return error.BadPathName;
        const final_name = path[(if (std.mem.lastIndexOfAny(u8, path, "/\\")) |separator| separator + 1 else 0)..];
        if (std.mem.indexOfScalar(u8, final_name, ':') != null) return error.BadPathName;
        var path_w = try std.Io.Threaded.sliceToPrefixedFileW(dir.handle, path, .{});
        var name = path_w.string();
        const attributes: windows.OBJECT.ATTRIBUTES = .{
            .RootDirectory = if (std.Io.Dir.path.isAbsoluteWindowsWtf16(path_w.span())) null else dir.handle,
            .ObjectName = &name,
        };
        var io_status: windows.IO_STATUS_BLOCK = undefined;
        var handle: windows.HANDLE = undefined;
        const status = windows.ntdll.NtCreateFile(
            &handle,
            .{
                .STANDARD = .{ .SYNCHRONIZE = true },
                .GENERIC = .{ .READ = true, .WRITE = mode == .read_write },
            },
            &attributes,
            &io_status,
            null,
            .{ .NORMAL = true },
            if (mode == .read_only_share_delete) .{ .READ = true, .DELETE = true } else .VALID_FLAGS,
            .OPEN,
            .{
                .DIRECTORY_FILE = mode == .directory,
                .NON_DIRECTORY_FILE = mode != .directory,
                .IO = .ASYNCHRONOUS,
                .OPEN_REPARSE_POINT = true,
                .OPEN_FOR_BACKUP_INTENT = mode == .directory,
            },
            null,
            0,
        );
        switch (status) {
            .SUCCESS => {},
            .OBJECT_NAME_NOT_FOUND, .OBJECT_PATH_NOT_FOUND => return error.FileNotFound,
            .OBJECT_NAME_INVALID, .OBJECT_PATH_SYNTAX_BAD => return error.BadPathName,
            .NOT_A_DIRECTORY => return error.NotDir,
            .FILE_IS_A_DIRECTORY => return error.NotRegular,
            .ACCESS_DENIED => return error.AccessDenied,
            .SHARING_VIOLATION => return error.FileBusy,
            else => return error.Unexpected,
        }
        const file: std.Io.File = .{ .handle = handle, .flags = .{ .nonblocking = true } };
        errdefer file.close(io);
        if (mode == .directory) _ = try coldDirectoryIdentity(handle) else _ = try cold_identity.statRegular(handle);
        return file;
    }
    if (comptime os != .linux and os != .openbsd and os != .freebsd) return error.Unsupported;
    if (path.len >= std.fs.max_path_bytes or std.mem.indexOfScalar(u8, path, 0) != null) return error.NameTooLong;
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    @memcpy(buffer[0..path.len], path);
    buffer[path.len] = 0;
    const name: [:0]const u8 = buffer[0..path.len :0];
    const flags: std.posix.O = .{ .ACCMODE = if (mode == .read_write) .RDWR else .RDONLY, .CLOEXEC = true, .NOFOLLOW = true, .NONBLOCK = true, .DIRECTORY = mode == .directory };
    const fd: std.posix.fd_t = while (true) {
        const result = std.posix.system.openat(dir.handle, name, flags, @as(std.posix.mode_t, 0));
        switch (std.posix.errno(result)) {
            .SUCCESS => break @intCast(result),
            .INTR => continue,
            .NOENT => return error.FileNotFound,
            .LOOP => return error.SymLinkLoop,
            .NOTDIR => return error.NotDir,
            .ACCES, .PERM => return error.AccessDenied,
            .NAMETOOLONG => return error.NameTooLong,
            .NFILE, .MFILE, .NOMEM => return error.SystemResources,
            else => return error.Unexpected,
        }
    };
    const file: std.Io.File = .{ .handle = fd, .flags = .{ .nonblocking = true } };
    errdefer file.close(io);
    if (mode == .directory) _ = try coldDirectoryIdentity(fd) else _ = try cold_identity.statRegular(fd);
    return file;
}

pub fn openExistingPersistenceFile(io: std.Io, dir: std.Io.Dir, path: []const u8, mode: ColdOpenMode) !std.Io.File {
    if (comptime cold_posix) return openColdExisting(io, dir, path, mode);
    var file = try dir.openFile(io, path, .{ .mode = if (mode == .read_write) .read_write else .read_only, .allow_directory = false, .follow_symlinks = false });
    if (comptime @import("builtin").os.tag == .windows) {
        // The pinned Zig Threaded backend opens no-follow Windows files for
        // asynchronous I/O, but reports them as blocking. Positional reads can
        // then return PENDING and hit an unreachable in the backend. Keep the
        // no-follow open and report the handle's actual I/O mode to Threaded.
        file.flags.nonblocking = true;
    }
    return file;
}

pub fn coldIdentityBits(value: anytype) u64 {
    return @intCast(@as(@Int(.unsigned, @bitSizeOf(@TypeOf(value))), @bitCast(value)));
}

pub fn coldDirectoryIdentity(fd: std.posix.fd_t) !cold_identity.Identity {
    const os = @import("builtin").os.tag;
    if (comptime os == .windows) {
        const FileStandardInfo = extern struct {
            allocation_size: i64,
            end_of_file: i64,
            links: u32,
            delete_pending: u8,
            directory: u8,
        };
        const FileAttributeTagInfo = extern struct { attributes: u32, tag: u32 };
        comptime {
            if (@sizeOf(FileStandardInfo) != 24) @compileError("Windows FILE_STANDARD_INFO ABI mismatch");
        }
        var standard: FileStandardInfo = undefined;
        if (GetFileInformationByHandleEx(@intFromPtr(fd), 1, &standard, @sizeOf(FileStandardInfo)) == 0) return error.StatFailed;
        if (standard.directory == 0 or standard.delete_pending != 0) return error.NotDir;
        var attributes: FileAttributeTagInfo = undefined;
        if (GetFileInformationByHandleEx(@intFromPtr(fd), 9, &attributes, @sizeOf(FileAttributeTagInfo)) == 0) return error.StatFailed;
        if ((attributes.attributes & 0x400) != 0) return error.NotDir; // FILE_ATTRIBUTE_REPARSE_POINT
        const identity = try windowsFileIdentity(@intFromPtr(fd));
        return .{
            .device = identity.volume_serial,
            .inode = std.mem.readInt(u64, identity.file_id[0..8], .little),
            .inode_high = std.mem.readInt(u64, identity.file_id[8..16], .little),
        };
    } else if (comptime os == .linux) {
        var stat: std.os.linux.Statx = std.mem.zeroes(std.os.linux.Statx);
        while (true) switch (std.os.linux.errno(std.os.linux.statx(fd, "", std.os.linux.AT.EMPTY_PATH, .{ .TYPE = true, .INO = true }, &stat))) {
            .SUCCESS => break,
            .INTR => continue,
            else => return error.StatFailed,
        };
        if (!stat.mask.TYPE or !stat.mask.INO) return error.StatFailed;
        if ((stat.mode & std.posix.S.IFMT) != std.posix.S.IFDIR) return error.NotDir;
        return .{ .device = (@as(u64, stat.dev_major) << 32) | stat.dev_minor, .inode = stat.ino };
    } else if (comptime os == .openbsd or os == .freebsd) {
        var stat: std.posix.Stat = undefined;
        while (true) switch (std.posix.errno(std.posix.system.fstat(fd, &stat))) {
            .SUCCESS => break,
            .INTR => continue,
            else => return error.StatFailed,
        };
        if ((stat.mode & std.posix.S.IFMT) != std.posix.S.IFDIR) return error.NotDir;
        return .{ .device = coldIdentityBits(stat.dev), .inode = coldIdentityBits(stat.ino) };
    } else return error.Unsupported;
}

pub fn coldOpenParent(io: std.Io, dir: std.Io.Dir, path: []const u8) !std.Io.File {
    return openColdExisting(io, dir, std.fs.path.dirname(path) orelse ".", .directory);
}

pub fn validateColdParent(io: std.Io, dir: std.Io.Dir, path: []const u8, held: std.Io.File, expected: cold_identity.Identity, atomic: ?*const std.Io.File.Atomic) !void {
    if (!std.meta.eql(expected, try coldDirectoryIdentity(held.handle))) return StoreError.SnapshotCoverageMismatch;
    const configured = try coldOpenParent(io, dir, path);
    defer configured.close(io);
    if (!std.meta.eql(expected, try coldDirectoryIdentity(configured.handle))) return StoreError.SnapshotCoverageMismatch;
    if (atomic) |file| {
        // Named atomics retain actual dirname+basename; anonymous O_TMPFILE
        // retains base dir+full subpath. Resolve the publication parent in both.
        const actual = try coldOpenParent(io, file.dir, file.dest_sub_path);
        defer actual.close(io);
        if (!std.meta.eql(expected, try coldDirectoryIdentity(actual.handle))) return StoreError.SnapshotCoverageMismatch;
    }
}

pub const ColdFile = struct {
    file: std.Io.File,
    identity: cold_identity.Identity,
    bytes: []u8,
    digest: [32]u8,

    pub fn capture(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, path: []const u8, limit: ?usize) !ColdFile {
        return captureWithPrivateAcl(allocator, io, dir, path, limit, false);
    }
    pub fn captureWithPrivateAcl(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, path: []const u8, limit: ?usize, private_acl: bool) !ColdFile {
        const file = try openColdExisting(io, dir, path, .read_only);
        errdefer file.close(io);
        if (private_acl) try cold_runtime.requireOwnerOnlyPrivateFileHandleWindows(file);
        const identity = try cold_identity.statRegular(file.handle);
        const size = std.math.cast(usize, (try file.stat(io)).size) orelse return StoreError.RecordTooLarge;
        if (limit) |maximum| if (size > maximum) return StoreError.RecordTooLarge;
        const bytes = try allocator.alloc(u8, size);
        errdefer allocator.free(bytes);
        if (try file.readPositionalAll(io, bytes, 0) != size or (try file.stat(io)).size != size or !std.meta.eql(identity, try cold_identity.statRegular(file.handle))) return StoreError.SnapshotCoverageMismatch;
        return .{ .file = file, .identity = identity, .bytes = bytes, .digest = coldDigest(bytes) };
    }
    pub fn deinit(self: *ColdFile, allocator: std.mem.Allocator, io: std.Io) void {
        self.file.close(io);
        allocator.free(self.bytes);
    }
    pub fn pinDeleteShareWindows(self: *ColdFile, io: std.Io, parent: std.Io.Dir, name: []const u8) !void {
        if (comptime @import("builtin").os.tag != .windows) return error.Unsupported;
        _ = try cold_runtime.requirePrivateDirectoryHandleWindows(parent);
        const pinned = try openColdExisting(io, parent, name, .read_only_share_delete);
        errdefer pinned.close(io);
        if (!std.meta.eql(self.identity, try cold_identity.statRegular(pinned.handle)) or
            (try pinned.stat(io)).size != self.bytes.len) return StoreError.SnapshotCoverageMismatch;
        var hasher = std.crypto.hash.Blake3.init(.{});
        var scratch: [4096]u8 = undefined;
        var offset: usize = 0;
        while (offset < self.bytes.len) {
            const take = @min(scratch.len, self.bytes.len - offset);
            if (try pinned.readPositionalAll(io, scratch[0..take], offset) != take or
                !std.mem.eql(u8, scratch[0..take], self.bytes[offset..][0..take])) return StoreError.SnapshotCoverageMismatch;
            hasher.update(scratch[0..take]);
            offset += take;
        }
        var digest: [32]u8 = undefined;
        hasher.final(&digest);
        if (!std.mem.eql(u8, &digest, &self.digest)) return StoreError.SnapshotCoverageMismatch;
        self.file.close(io);
        self.file = pinned;
    }
    pub fn validate(self: *const ColdFile, io: std.Io, dir: std.Io.Dir, path: []const u8) !void {
        const configured = try openColdExisting(io, dir, path, .read_only);
        defer configured.close(io);
        if (!std.meta.eql(self.identity, try cold_identity.statRegular(configured.handle)) or !std.meta.eql(self.identity, try cold_identity.statRegular(self.file.handle)) or (try configured.stat(io)).size != self.bytes.len or (try self.file.stat(io)).size != self.bytes.len) return StoreError.SnapshotCoverageMismatch;
        if (!std.mem.eql(u8, &self.digest, &coldDigest(self.bytes))) return StoreError.SnapshotCoverageMismatch;
        var hasher = std.crypto.hash.Blake3.init(.{});
        var scratch: [4096]u8 = undefined;
        var offset: usize = 0;
        while (offset < self.bytes.len) {
            const take = @min(scratch.len, self.bytes.len - offset);
            if (try self.file.readPositionalAll(io, scratch[0..take], offset) != take) return StoreError.SnapshotCoverageMismatch;
            hasher.update(scratch[0..take]);
            offset += take;
        }
        var digest: [32]u8 = undefined;
        hasher.final(&digest);
        if (!std.mem.eql(u8, &digest, &self.digest)) return StoreError.SnapshotCoverageMismatch;
    }
};

pub fn validateColdLease(io: std.Io, dir: std.Io.Dir, lease: std.Io.File, path: []const u8, identity: cold_identity.Identity) !void {
    if (!std.meta.eql(identity, try cold_identity.statRegular(lease.handle))) return StoreError.SnapshotCoverageMismatch;
    const configured = try openColdExisting(io, dir, path, .read_only);
    defer configured.close(io);
    if (!std.meta.eql(identity, try cold_identity.statRegular(configured.handle))) return StoreError.SnapshotCoverageMismatch;
    try cold_identity.reaffirmExclusive(lease.handle);
}

pub fn validateColdPreparedFile(io: std.Io, file: std.Io.File, bytes: []const u8, identity: cold_identity.Identity) !void {
    if (!std.meta.eql(identity, try cold_identity.statRegular(file.handle)) or (try file.stat(io)).size != bytes.len) return StoreError.SnapshotCoverageMismatch;
    try validateColdPreparedRange(io, file, bytes, 0);
}

pub fn validateColdPreparedRange(io: std.Io, file: std.Io.File, bytes: []const u8, start: u64) !void {
    var buffer: [4096]u8 = undefined;
    var offset: usize = 0;
    while (offset < bytes.len) {
        const take = @min(buffer.len, bytes.len - offset);
        if (try file.readPositionalAll(io, buffer[0..take], start + offset) != take or !std.mem.eql(u8, buffer[0..take], bytes[offset..][0..take])) return StoreError.SnapshotCoverageMismatch;
        offset += take;
    }
}

// A named atomic temporary is a namespace contribution as well as an owned
// descriptor. A correct held FD cannot authenticate a substituted rename source.
// The stable lease serializes cooperating writers; these finite checks do not
// purport to exclude privileged namespace changes after the final check.
pub fn validateColdAtomicName(io: std.Io, atomic: *const std.Io.File.Atomic, identity: cold_identity.Identity) !void {
    if (!atomic.file_exists) return; // Anonymous temp: link uses the held FD.
    const name = std.fmt.hex(atomic.file_basename_hex);
    const named = openColdExisting(io, atomic.dir, &name, .read_only) catch return StoreError.SnapshotCoverageMismatch;
    defer named.close(io);
    if (!std.meta.eql(identity, cold_identity.statRegular(named.handle) catch return StoreError.SnapshotCoverageMismatch)) return StoreError.SnapshotCoverageMismatch;
    // Same inode binds the exact bytes already checked through the held FD.
}

// std.Atomic.deinit unconditionally unlinks its remembered temporary name.
// On Windows delete through a verified handle; never ask std to unlink a name
// which might have been substituted while the stage was preparing.
pub fn deinitColdAtomic(io: std.Io, atomic: *std.Io.File.Atomic, known_identity: ?cold_identity.Identity) void {
    if (comptime @import("builtin").os.tag == .windows) {
        if (atomic.file_exists) {
            const identity = known_identity orelse if (atomic.file_open) windowsColdAtomicIdentity(atomic.file.handle) catch null else null;
            if (identity) |owned| deleteColdAtomicWindows(io, atomic, owned) catch {};
            // A failed proof or disposition leaves an owned orphan. It must
            // never fall through to std's unguarded name-based deletion.
            atomic.file_exists = false;
        }
        atomic.deinit(io);
        return;
    }
    if (atomic.file_exists) {
        const identity = known_identity orelse if (atomic.file_open) cold_identity.statRegular(atomic.file.handle) catch null else null;
        if (identity) |owned| {
            validateColdAtomicName(io, atomic, owned) catch {
                atomic.file_exists = false;
            };
        } else atomic.file_exists = false;
    }
    atomic.deinit(io);
}

pub fn openColdAtomicWindows(io: std.Io, atomic: *const std.Io.File.Atomic) !std.Io.File {
    if (comptime @import("builtin").os.tag != .windows) return error.Unsupported;
    _ = try cold_runtime.requirePrivateDirectoryHandleWindows(atomic.dir);
    const windows = std.os.windows;
    const name = std.fmt.hex(atomic.file_basename_hex);
    var name_w = try std.Io.Threaded.sliceToPrefixedFileW(atomic.dir.handle, &name, .{});
    var object_name = name_w.string();
    const attributes: windows.OBJECT.ATTRIBUTES = .{ .RootDirectory = atomic.dir.handle, .ObjectName = &object_name };
    var io_status: windows.IO_STATUS_BLOCK = undefined;
    var handle: windows.HANDLE = undefined;
    const status = windows.ntdll.NtCreateFile(
        &handle,
        .{ .STANDARD = .{ .SYNCHRONIZE = true, .RIGHTS = .{ .READ_CONTROL = true, .DELETE = true } }, .GENERIC = .{ .READ = true, .WRITE = true } },
        &attributes,
        &io_status,
        null,
        .{ .NORMAL = true },
        .{},
        .OPEN,
        .{ .NON_DIRECTORY_FILE = true, .IO = .SYNCHRONOUS_NONALERT, .OPEN_REPARSE_POINT = true, .WRITE_THROUGH = true },
        null,
        0,
    );
    switch (status) {
        .SUCCESS => {},
        .OBJECT_NAME_NOT_FOUND, .OBJECT_PATH_NOT_FOUND => return error.FileNotFound,
        .ACCESS_DENIED => return error.AccessDenied,
        .SHARING_VIOLATION => return error.FileBusy,
        else => return error.Unexpected,
    }
    const file: std.Io.File = .{ .handle = handle, .flags = .{ .nonblocking = false } };
    errdefer file.close(io);
    _ = try cold_identity.statRegular(file.handle);
    try cold_runtime.requireInheritedPrivateFileWindows(file);
    return file;
}

pub fn markColdAtomicDeletedWindows(file: std.Io.File) bool {
    if (comptime @import("builtin").os.tag != .windows) return false;
    // FileDispositionInfo marks this exact held file for deletion on close.
    // The reopened atomic handle requests DELETE and excludes other openers.
    const disposition: u8 = 1;
    return SetFileInformationByHandle(@intFromPtr(file.handle), 4, &disposition, @sizeOf(u8)) != 0;
}

pub fn deleteColdAtomicWindows(io: std.Io, atomic: *std.Io.File.Atomic, identity: cold_identity.Identity) !void {
    if (comptime @import("builtin").os.tag != .windows) return error.Unsupported;
    if (!atomic.file_exists) return;
    if (atomic.file_open and std.meta.eql(identity, windowsColdAtomicIdentity(atomic.file.handle) catch return StoreError.SnapshotCoverageMismatch)) {
        if (markColdAtomicDeletedWindows(atomic.file)) return;
    }
    if (atomic.file_open) {
        atomic.file.close(io);
        atomic.file_open = false;
    }
    const candidate = try openColdAtomicWindows(io, atomic);
    defer candidate.close(io);
    if (!std.meta.eql(identity, try cold_identity.statRegular(candidate.handle))) return StoreError.SnapshotCoverageMismatch;
    if (!markColdAtomicDeletedWindows(candidate)) return error.Unexpected;
}

// Zig's named Atomic default is write-only. Reacquire a readable, deletable
// handle before writing secrets, and bind it to the full original file ID.
pub fn makeColdAtomicReadable(io: std.Io, atomic: *std.Io.File.Atomic) !void {
    if (comptime @import("builtin").os.tag == .windows) {
        if (!atomic.file_exists or !atomic.file_open) return error.InvalidDescriptor;
        _ = try cold_runtime.requirePrivateDirectoryHandleWindows(atomic.dir);
        try cold_runtime.requireInheritedPrivateFileWindows(atomic.file);
        const original = try windowsColdAtomicIdentity(atomic.file.handle);
        atomic.file.close(io);
        atomic.file_open = false;
        errdefer {
            deleteColdAtomicWindows(io, atomic, original) catch {};
            // The caller's errdefer may lack this captured identity.
            atomic.file_exists = false;
        }
        const file = try openColdAtomicWindows(io, atomic);
        errdefer file.close(io);
        if (!std.meta.eql(original, try cold_identity.statRegular(file.handle))) return StoreError.SnapshotCoverageMismatch;
        atomic.file = file;
        atomic.file_open = true;
        return;
    }
    const name = std.fmt.hex(atomic.file_basename_hex);
    const file = try openColdExisting(io, atomic.dir, &name, .read_write);
    errdefer file.close(io);
    if (!std.meta.eql(try cold_identity.statRegular(file.handle), try cold_identity.statRegular(atomic.file.handle))) return StoreError.SnapshotCoverageMismatch;
    atomic.file.close(io);
    atomic.file = file;
}

/// Rename the exact held, no-share temporary into a verified private parent.
/// This is only a namespace primitive: callers must separately prove prepared
/// bytes, lease custody, configured reopen, and the publication cut. In
/// particular, no cold stage uses this until its whole Windows transaction is
/// available. FILE_WRITE_THROUGH requests NTFS metadata flush for the rename;
/// this does not establish power-loss durability on every filesystem.
pub fn requireColdWriteThroughVolumeWindows(parent: std.Io.File) !void {
    if (comptime @import("builtin").os.tag != .windows) return error.Unsupported;
    // Windows documents rename metadata flushing for write-through requests on
    // NTFS. Reject other filesystems before treating a rename as a durable cut.
    var fs_name: [16]u16 = @splat(0);
    if (GetVolumeInformationByHandleW(@intFromPtr(parent.handle), null, 0, null, null, null, &fs_name, fs_name.len) == 0)
        return error.Unsupported;
    if (!std.mem.eql(u16, fs_name[0..5], &.{ 'N', 'T', 'F', 'S', 0 })) return error.Unsupported;
}

pub fn renameHeldColdAtomicWindows(
    io: std.Io,
    atomic: *std.Io.File.Atomic,
    configured_dir: std.Io.Dir,
    configured_path: []const u8,
    held_parent: std.Io.File,
    expected_parent: cold_identity.Identity,
    expected_file: cold_identity.Identity,
    replace: bool,
) !void {
    if (comptime @import("builtin").os.tag != .windows) return error.Unsupported;
    if (!atomic.file_exists or !atomic.file_open) return StoreError.SnapshotCoverageMismatch;
    const name = std.fs.path.basename(configured_path);
    if (name.len == 0 or std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..") or
        std.mem.indexOfAny(u8, name, "/\\:\x00") != null or name[name.len - 1] == '.' or name[name.len - 1] == ' ' or
        !std.mem.eql(u8, name, std.fs.path.basename(atomic.dest_sub_path))) return StoreError.SnapshotCoverageMismatch;
    _ = try cold_runtime.requirePrivateDirectoryHandleWindows(.{ .handle = held_parent.handle });
    try requireColdWriteThroughVolumeWindows(held_parent);
    try validateColdParent(io, configured_dir, configured_path, held_parent, expected_parent, atomic);
    const windows = std.os.windows;
    var mode_status: windows.IO_STATUS_BLOCK = undefined;
    var mode: u32 = 0;
    if (windows.ntdll.NtQueryInformationFile(atomic.file.handle, &mode_status, &mode, @sizeOf(u32), .Mode) != .SUCCESS or
        (mode & 0x2) == 0) return error.Unsupported; // FILE_WRITE_THROUGH
    if (!std.meta.eql(expected_file, try cold_identity.statRegular(atomic.file.handle))) return StoreError.SnapshotCoverageMismatch;
    var name_w = try std.Io.Threaded.sliceToPrefixedFileW(held_parent.handle, name, .{});
    var info: windows.FILE.RENAME_INFORMATION = .init(.{
        .Flags = .{ .REPLACE_IF_EXISTS = replace, .POSIX_SEMANTICS = replace },
        .RootDirectory = held_parent.handle,
        .FileName = name_w.span(),
    });
    const buffer = info.toBuffer();
    var io_status: windows.IO_STATUS_BLOCK = undefined;
    // NtSetInformationFile may have changed the namespace even if it reports a
    // failure. Deinit must never unlink a path after this boundary.
    atomic.file_exists = false;
    const status = windows.ntdll.NtSetInformationFile(atomic.file.handle, &io_status, buffer.ptr, @intCast(buffer.len), .RenameEx);
    switch (status) {
        .SUCCESS => {},
        .OBJECT_NAME_COLLISION => return error.PathAlreadyExists,
        else => return StoreError.IoAmbiguous,
    }
}
