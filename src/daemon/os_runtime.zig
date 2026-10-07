// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Native OS operations used by the shared daemon lifecycle. Linux retains
//! raw syscalls; BSD uses the target ABI. Windows socket operations use opaque
//! IOCP descriptor IDs; native file HANDLEs have a disjoint opaque range.
//! Cross-process Helix descriptor transfer remains unsupported.
//! Errors never cross an ABI boundary as numeric Linux errno values.
const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const sys = posix.system;
const windows = std.os.windows;
const io_backend = @import("io_backend.zig");

/// Windows socket descriptors are opaque IOCP registry IDs, not raw SOCKETs.
pub const Fd = if (builtin.os.tag == .windows) std.os.linux.fd_t else posix.fd_t;
pub const AddressStorage = posix.sockaddr.storage;
pub const AddressLength = posix.socklen_t;
pub const Error = error{ Interrupted, WouldBlock, PermissionDenied, FileBusy, InsecurePermissions, InvalidDescriptor, FileNotFound, PathAlreadyExists, InvalidPath, OutOfMemory, DescriptorExhausted, Unexpected, Unsupported };

const windows_file_fd_first: Fd = 0x4000_0000;
const windows_file_rollover_at: Fd = 0x6000_0000;
const invalid_windows_handle = std.math.maxInt(usize);
const windows_generic_read: u32 = 0x8000_0000;
const windows_generic_write: u32 = 0x4000_0000;
const windows_file_share_read: u32 = 1;
const windows_file_share_write: u32 = 2;
const windows_file_share_delete: u32 = 4;
const windows_open_existing: u32 = 3;
const windows_open_always: u32 = 4;
const windows_file_attribute_normal: u32 = 0x80;
const windows_handle_flag_inherit: u32 = 1;
const windows_duplicate_same_access: u32 = 2;
const windows_write_dac: u32 = 0x0004_0000;
const windows_file_begin: u32 = 0;
const windows_se_file_object: i32 = 1;
const windows_dacl_security_information: u32 = 4;
const windows_owner_security_information: u32 = 1;
const windows_protected_dacl_security_information: u32 = 0x8000_0000;
const windows_token_query: u32 = 0x0008;
const windows_token_user_class: i32 = 1;
const windows_token_owner_class: i32 = 4;
const owner_only_sddl = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)";
const owner_only_sddl_auto_inherited = "D:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)";
const private_directory_sddl = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)";
const private_directory_sddl_auto_inherited = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)";
const inherited_private_file_sddl = "D:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;OW)";
const inherited_private_file_sddl_no_auto = "D:(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;OW)";

const WindowsSecurityAttributes = extern struct {
    length: u32,
    descriptor: *anyopaque,
    inherit_handle: i32,
};

const WindowsSidAndAttributes = extern struct {
    sid: ?*anyopaque,
    attributes: u32,
};

const WindowsTokenUser = extern struct {
    user: WindowsSidAndAttributes,
};

const WindowsTokenOwner = extern struct {
    owner: ?*anyopaque,
};

comptime {
    if (@sizeOf(WindowsSecurityAttributes) != 24) @compileError("Windows SECURITY_ATTRIBUTES ABI mismatch");
}

/// The server's public fd type is i32, but a Win32 HANDLE is pointer-sized.
/// IDs never overlap IOCP socket IDs and are never reused, so a retired ID
/// cannot accidentally acquire custody of a later file.
const WindowsFiles = struct {
    lock: std.atomic.Mutex = .unlocked,
    handles: std.AutoHashMapUnmanaged(Fd, usize) = .empty,
    next_fd: Fd = windows_file_fd_first,

    fn lockSpin(self: *WindowsFiles) void {
        while (!self.lock.tryLock()) std.Thread.yield() catch {};
    }

    fn register(self: *WindowsFiles, handle: usize) Error!Fd {
        self.lockSpin();
        defer self.lock.unlock();
        return self.registerLocked(handle);
    }

    fn registerLocked(self: *WindowsFiles, handle: usize) Error!Fd {
        if (self.next_fd < windows_file_fd_first) return error.DescriptorExhausted;
        const fd = self.next_fd;
        self.handles.put(std.heap.page_allocator, fd, handle) catch return error.OutOfMemory;
        self.next_fd = if (fd == std.math.maxInt(Fd)) -1 else fd + 1;
        return fd;
    }

    fn rolloverDue(self: *WindowsFiles) bool {
        self.lockSpin();
        defer self.lock.unlock();
        return self.next_fd < windows_file_fd_first or self.next_fd >= windows_file_rollover_at;
    }

    fn valid(self: *WindowsFiles, fd: Fd) bool {
        self.lockSpin();
        defer self.lock.unlock();
        return self.handles.contains(fd);
    }

    fn close(self: *WindowsFiles, fd: Fd) void {
        self.lockSpin();
        defer self.lock.unlock();
        if (self.handles.fetchRemove(fd)) |removed| _ = CloseHandle(removed.value);
    }

    fn read(self: *WindowsFiles, fd: Fd, bytes: []u8) Error!usize {
        self.lockSpin();
        defer self.lock.unlock();
        const handle = self.handles.get(fd) orelse return error.InvalidDescriptor;
        if (bytes.len == 0) return 0;
        var n: u32 = 0;
        const cap: u32 = @intCast(@min(bytes.len, @as(usize, std.math.maxInt(u32))));
        if (ReadFile(handle, bytes.ptr, cap, &n, null) == 0) return windowsFileError(GetLastError());
        return n;
    }

    fn write(self: *WindowsFiles, fd: Fd, bytes: []const u8) Error!usize {
        self.lockSpin();
        defer self.lock.unlock();
        const handle = self.handles.get(fd) orelse return error.InvalidDescriptor;
        if (bytes.len == 0) return 0;
        var n: u32 = 0;
        const cap: u32 = @intCast(@min(bytes.len, @as(usize, std.math.maxInt(u32))));
        if (WriteFile(handle, bytes.ptr, cap, &n, null) == 0) return windowsFileError(GetLastError());
        return n;
    }

    fn duplicate(self: *WindowsFiles, fd: Fd) Error!Fd {
        self.lockSpin();
        defer self.lock.unlock();
        const handle = self.handles.get(fd) orelse return error.InvalidDescriptor;
        var copy: usize = invalid_windows_handle;
        const process = GetCurrentProcess();
        if (DuplicateHandle(process, handle, process, &copy, 0, 0, windows_duplicate_same_access) == 0)
            return windowsFileError(GetLastError());
        errdefer _ = CloseHandle(copy);
        return self.registerLocked(copy);
    }

    fn setCloexec(self: *WindowsFiles, fd: Fd, enabled: bool) Error!void {
        self.lockSpin();
        defer self.lock.unlock();
        const handle = self.handles.get(fd) orelse return error.InvalidDescriptor;
        if (SetHandleInformation(handle, windows_handle_flag_inherit, if (enabled) 0 else windows_handle_flag_inherit) == 0)
            return windowsFileError(GetLastError());
    }
};

var windows_files: WindowsFiles = .{};

fn windowsFileError(code: u32) Error {
    return switch (code) {
        2, 3 => error.FileNotFound,
        5, 32, 33, 1314 => error.PermissionDenied,
        6 => error.InvalidDescriptor,
        8, 14 => error.OutOfMemory,
        123, 206 => error.InvalidPath,
        else => error.Unexpected,
    };
}

fn check(rc: anytype) Error!void {
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        .INTR => return error.Interrupted,
        .AGAIN => return error.WouldBlock,
        .ACCES, .PERM => return error.PermissionDenied,
        .BADF => return error.InvalidDescriptor,
        else => return error.Unexpected,
    }
}

/// Native Helix temporarily holds received and normalization copies alongside
/// canonical descriptor numbers. Use the existing per-process hard allowance;
/// never change the administrator's hard limit or a system-wide setting.
pub fn raiseOpenBsdFdAllowance() Error!void {
    if (comptime builtin.os.tag != .openbsd) return;
    var limit: sys.rlimit = undefined;
    try check(sys.getrlimit(.NOFILE, &limit));
    if (limit.cur < limit.max) {
        limit.cur = limit.max;
        try check(sys.setrlimit(.NOFILE, &limit));
    }
}

/// Preserve the same half-range retry headroom for the disjoint Windows file
/// HANDLE namespace as for IOCP sockets. Helix starts a fresh registry.
pub fn windowsFileIdRolloverDue() bool {
    if (comptime builtin.os.tag != .windows) return false;
    return windows_files.rolloverDue();
}

pub fn read(fd: Fd, bytes: []u8) Error!usize {
    if (comptime builtin.os.tag == .windows) {
        return windows_files.read(fd, bytes);
    }
    const rc = sys.read(fd, bytes.ptr, bytes.len);
    try check(rc);
    return @intCast(rc);
}

pub fn write(fd: Fd, bytes: []const u8) Error!usize {
    if (comptime builtin.os.tag == .windows) {
        return windows_files.write(fd, bytes);
    }
    const rc = sys.write(fd, bytes.ptr, bytes.len);
    try check(rc);
    return @intCast(rc);
}

pub fn pread(fd: Fd, bytes: []u8, offset: u64) Error!usize {
    if (comptime builtin.os.tag == .windows) {
        return error.Unsupported;
    }
    const rc = sys.pread(fd, bytes.ptr, bytes.len, @intCast(offset));
    try check(rc);
    return @intCast(rc);
}

pub fn close(fd: Fd) void {
    if (fd < 0) return;
    if (comptime builtin.os.tag == .windows) {
        if (fd >= windows_file_fd_first)
            windows_files.close(fd)
        else
            io_backend.closeSocket(fd);
    } else {
        _ = sys.close(fd);
    }
}

pub fn duplicate(fd: Fd) Error!Fd {
    if (comptime builtin.os.tag == .windows) {
        if (fd < windows_file_fd_first) return error.Unsupported;
        return windows_files.duplicate(fd);
    }
    const rc = sys.dup(fd);
    try check(rc);
    return @intCast(rc);
}

/// Duplicate a native std.Io.File HANDLE rather than a registry-backed runtime
/// descriptor. The copy retains the exact same file object and I/O flags.
pub fn duplicateFile(file: std.Io.File) Error!std.Io.File {
    if (comptime builtin.os.tag == .windows) {
        var copy: usize = invalid_windows_handle;
        const process = GetCurrentProcess();
        if (DuplicateHandle(process, @intFromPtr(file.handle), process, &copy, 0, 0, windows_duplicate_same_access) == 0 or copy == invalid_windows_handle)
            return windowsFileError(GetLastError());
        return .{ .handle = @ptrFromInt(copy), .flags = file.flags };
    }
    return .{ .handle = try duplicate(file.handle), .flags = file.flags };
}

pub fn setCloexec(fd: Fd, enabled: bool) Error!void {
    if (comptime builtin.os.tag == .windows) {
        if (fd < windows_file_fd_first) return error.Unsupported;
        return windows_files.setCloexec(fd, enabled);
    }
    const old = sys.fcntl(fd, posix.F.GETFD, @as(i32, 0));
    try check(old);
    const flags: usize = @intCast(old);
    const next = if (enabled) flags | posix.FD_CLOEXEC else flags & ~@as(usize, posix.FD_CLOEXEC);
    try check(sys.fcntl(fd, posix.F.SETFD, next));
}

pub fn setNonblocking(fd: Fd) Error!void {
    if (comptime builtin.os.tag == .windows) {
        return error.Unsupported;
    }
    const old = sys.fcntl(fd, posix.F.GETFL, @as(i32, 0));
    try check(old);
    var flags: posix.O = @bitCast(@as(u32, @intCast(old)));
    flags.NONBLOCK = true;
    try check(sys.fcntl(fd, posix.F.SETFL, @as(usize, @as(u32, @bitCast(flags)))));
}

pub fn fdValid(fd: Fd) bool {
    if (fd < 0) return false;
    if (comptime builtin.os.tag == .windows)
        return if (fd >= windows_file_fd_first) windows_files.valid(fd) else io_backend.windowsSocketValid(fd);
    return posix.errno(sys.fcntl(fd, posix.F.GETFD, @as(i32, 0))) == .SUCCESS;
}

pub fn socketType(fd: Fd) Error!u32 {
    if (comptime builtin.os.tag == .windows)
        return io_backend.windowsSocketType(fd) catch return error.InvalidDescriptor;
    var value: u32 = 0;
    var len: AddressLength = @sizeOf(u32);
    try check(sys.getsockopt(fd, posix.SOL.SOCKET, posix.SO.TYPE, @ptrCast(&value), &len));
    if (len != @sizeOf(u32)) return error.Unexpected;
    return value;
}

pub fn getpeername(fd: Fd, addr: *AddressStorage, len: *AddressLength) Error!void {
    if (comptime builtin.os.tag == .windows) {
        return error.Unsupported;
    }
    try check(sys.getpeername(fd, @ptrCast(addr), len));
}

pub fn shutdownBoth(fd: Fd) void {
    if (comptime builtin.os.tag == .windows) {
        io_backend.shutdownSocketBoth(fd);
    } else {
        _ = sys.shutdown(fd, posix.SHUT.RDWR);
    }
}

extern "kernel32" fn Sleep(dwMilliseconds: u32) callconv(.winapi) void;
extern "kernel32" fn CreateFileW(name: [*:0]const u16, desired_access: u32, share_mode: u32, security_attributes: ?*anyopaque, creation_disposition: u32, flags_and_attributes: u32, template_file: ?*anyopaque) callconv(.winapi) usize;
extern "kernel32" fn ReadFile(handle: usize, buffer: [*]u8, len: u32, read_count: *u32, overlapped: ?*anyopaque) callconv(.winapi) i32;
extern "kernel32" fn WriteFile(handle: usize, buffer: [*]const u8, len: u32, write_count: *u32, overlapped: ?*anyopaque) callconv(.winapi) i32;
extern "kernel32" fn CloseHandle(handle: usize) callconv(.winapi) i32;
extern "kernel32" fn GetLastError() callconv(.winapi) u32;
extern "kernel32" fn GetFileInformationByHandleEx(handle: usize, class: i32, info: *anyopaque, size: u32) callconv(.winapi) i32;
extern "kernel32" fn GetCurrentProcess() callconv(.winapi) usize;
extern "kernel32" fn DuplicateHandle(source_process: usize, source_handle: usize, target_process: usize, target_handle: *usize, desired_access: u32, inherit_handle: i32, options: u32) callconv(.winapi) i32;
extern "kernel32" fn SetHandleInformation(handle: usize, mask: u32, flags: u32) callconv(.winapi) i32;
extern "kernel32" fn SetFilePointerEx(handle: usize, distance: i64, new_position: ?*i64, move_method: u32) callconv(.winapi) i32;
extern "kernel32" fn SetEndOfFile(handle: usize) callconv(.winapi) i32;
extern "kernel32" fn LocalFree(pointer: usize) callconv(.winapi) usize;
extern "advapi32" fn OpenProcessToken(process: usize, desired_access: u32, token: *usize) callconv(.winapi) i32;
extern "advapi32" fn GetTokenInformation(token: usize, information_class: i32, information: *anyopaque, length: u32, returned_length: *u32) callconv(.winapi) i32;
extern "advapi32" fn EqualSid(first: *anyopaque, second: *anyopaque) callconv(.winapi) i32;
extern "advapi32" fn ConvertStringSidToSidW(sid_text: [*:0]const u16, sid: *?*anyopaque) callconv(.winapi) i32;
extern "advapi32" fn ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl: [*:0]const u16, revision: u32, descriptor: *?*anyopaque, size: ?*u32) callconv(.winapi) i32;
extern "advapi32" fn GetSecurityDescriptorDacl(descriptor: *anyopaque, present: *i32, dacl: *?*anyopaque, defaulted: *i32) callconv(.winapi) i32;
extern "advapi32" fn SetSecurityInfo(handle: usize, object_type: i32, security_info: u32, owner: ?*anyopaque, group: ?*anyopaque, dacl: ?*anyopaque, sacl: ?*anyopaque) callconv(.winapi) u32;
extern "advapi32" fn GetSecurityInfo(handle: usize, object_type: i32, security_info: u32, owner: ?*?*anyopaque, group: ?*?*anyopaque, dacl: ?*?*anyopaque, sacl: ?*?*anyopaque, descriptor: *?*anyopaque) callconv(.winapi) u32;
extern "advapi32" fn ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor: *anyopaque, revision: u32, security_info: u32, sddl: *?[*:0]u16, len: ?*u32) callconv(.winapi) i32;

const WindowsSockAddr4 = extern struct {
    family: u16,
    port: u16,
    addr: u32,
    zero: [8]u8,
};
extern "ws2_32" fn WSASocketW(address_family: i32, socket_type: i32, protocol: i32, protocol_info: ?*anyopaque, group: u32, flags: u32) callconv(.winapi) usize;
extern "ws2_32" fn closesocket(socket: usize) callconv(.winapi) i32;
extern "ws2_32" fn connect(socket: usize, addr: *const WindowsSockAddr4, namelen: i32) callconv(.winapi) i32;
extern "ws2_32" fn recv(socket: usize, buf: [*]u8, len: i32, flags: i32) callconv(.winapi) i32;
extern "ws2_32" fn setsockopt(socket: usize, level: i32, option: i32, value: *const anyopaque, len: i32) callconv(.winapi) i32;

pub fn sleepMillis(ms: u64) void {
    // Windows libc exposes neither `timespec` nor `nanosleep` here (and this
    // std has no thread sleep outside `Io`); call Win32 `Sleep` directly.
    if (comptime builtin.os.tag == .windows) {
        Sleep(@intCast(@min(ms, std.math.maxInt(u32))));
        return;
    }
    var remaining: sys.timespec = .{ .sec = @intCast(ms / 1000), .nsec = @intCast(ms % 1000 * std.time.ns_per_ms) };
    while (true) {
        var next: sys.timespec = undefined;
        const rc = sys.nanosleep(&remaining, &next);
        switch (posix.errno(rc)) {
            .SUCCESS => return,
            .INTR => remaining = next,
            else => return,
        }
    }
}

pub fn openReadZ(path: [*:0]const u8) Error!Fd {
    if (comptime builtin.os.tag == .windows) {
        return openWindowsFile(path, false);
    }
    const rc = sys.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, @as(posix.mode_t, 0));
    try check(rc);
    return @intCast(rc);
}

pub fn openTruncateZ(path: [*:0]const u8, mode: posix.mode_t) Error!Fd {
    if (comptime builtin.os.tag == .windows) {
        // This API carries private daemon state. Do not silently broaden a
        // POSIX caller's requested permissions on Windows.
        if (mode != 0o600) return error.Unsupported;
        return openWindowsFile(path, true);
    }
    const rc = sys.open(path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .CLOEXEC = true }, mode);
    try check(rc);
    return @intCast(rc);
}

fn openWindowsFile(path: [*:0]const u8, truncate_private: bool) Error!Fd {
    const utf8 = std.mem.span(path);
    if (utf8.len == 0) return error.InvalidPath;
    const wide = std.unicode.utf8ToUtf16LeAllocZ(std.heap.page_allocator, utf8) catch |err| switch (err) {
        error.InvalidUtf8 => return error.InvalidPath,
        error.OutOfMemory => return error.OutOfMemory,
    };
    defer std.heap.page_allocator.free(wide);

    var descriptor: ?*anyopaque = null;
    var attributes: WindowsSecurityAttributes = undefined;
    var dacl: ?*anyopaque = null;
    if (truncate_private) {
        if (ConvertStringSecurityDescriptorToSecurityDescriptorW(std.unicode.utf8ToUtf16LeStringLiteral(owner_only_sddl), 1, &descriptor, null) == 0)
            return windowsFileError(GetLastError());
        if (descriptor == null) return error.Unexpected;
        var present: i32 = 0;
        var defaulted: i32 = 0;
        if (GetSecurityDescriptorDacl(descriptor.?, &present, &dacl, &defaulted) == 0 or
            present == 0 or dacl == null)
        {
            _ = LocalFree(@intFromPtr(descriptor.?));
            return error.Unexpected;
        }
        attributes = .{ .length = @sizeOf(WindowsSecurityAttributes), .descriptor = descriptor.?, .inherit_handle = 0 };
    }
    defer {
        if (descriptor) |owned| _ = LocalFree(@intFromPtr(owned));
    }

    const handle = CreateFileW(
        wide.ptr,
        if (truncate_private) windows_generic_write | windows_write_dac else windows_generic_read,
        if (truncate_private) 0 else windows_file_share_read | windows_file_share_write | windows_file_share_delete,
        if (truncate_private) @ptrCast(&attributes) else null,
        if (truncate_private) windows_open_always else windows_open_existing,
        windows_file_attribute_normal,
        null,
    );
    if (handle == invalid_windows_handle) return windowsFileError(GetLastError());
    errdefer _ = CloseHandle(handle);
    if (truncate_private) {
        // CreateFileW ignores lpSecurityDescriptor for an existing file.
        // Replace and protect its DACL before truncating or writing secrets.
        const security_error = SetSecurityInfo(
            handle,
            windows_se_file_object,
            windows_dacl_security_information | windows_protected_dacl_security_information,
            null,
            null,
            dacl,
            null,
        );
        if (security_error != 0) return windowsFileError(security_error);
        if (SetFilePointerEx(handle, 0, null, windows_file_begin) == 0 or SetEndOfFile(handle) == 0)
            return windowsFileError(GetLastError());
    }
    return windows_files.register(handle);
}

const WindowsPrivateOpen = enum { create_exclusive, verify_existing, remediate_existing, remediate_existing_write };

/// Create a new private file relative to `dir`. The DACL is supplied to the
/// native create operation so no observer can open a default-ACL file between
/// creation and the first write. CREATE preserves the keyfile's collision
/// behavior: an existing file is never opened or truncated.
pub fn createPrivateExclusiveWindows(dir: std.Io.Dir, path: []const u8) Error!std.Io.File {
    return openPrivateWindows(dir, path, .create_exclusive);
}

pub const WindowsPrivateReadMode = enum { verify_only, remediate, remediate_read_write };

/// Both read modes require exclusive custody before exposing file bytes.
/// Preflight verifies without mutation; boot may replace a permissive DACL.
pub fn openExistingPrivateWindows(dir: std.Io.Dir, path: []const u8, mode: WindowsPrivateReadMode) Error!std.Io.File {
    return openPrivateWindows(dir, path, switch (mode) {
        .verify_only => .verify_existing,
        .remediate => .remediate_existing,
        .remediate_read_write => .remediate_existing_write,
    });
}

fn openPrivateWindows(dir: std.Io.Dir, path: []const u8, mode: WindowsPrivateOpen) Error!std.Io.File {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    if (path.len == 0) return error.InvalidPath;

    var path_w = std.Io.Threaded.sliceToPrefixedFileW(dir.handle, path, .{}) catch
        return error.InvalidPath;
    var object_name = path_w.string();
    var descriptor: ?*anyopaque = null;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(std.unicode.utf8ToUtf16LeStringLiteral(owner_only_sddl), 1, &descriptor, null) == 0)
        return windowsFileError(GetLastError());
    const owned_descriptor = descriptor orelse return error.Unexpected;
    defer _ = LocalFree(@intFromPtr(owned_descriptor));

    const attributes: windows.OBJECT.ATTRIBUTES = .{
        .RootDirectory = if (std.Io.Dir.path.isAbsoluteWindowsWtf16(path_w.span())) null else dir.handle,
        .ObjectName = &object_name,
        .SecurityDescriptor = if (mode == .create_exclusive) owned_descriptor else null,
    };
    var io_status: windows.IO_STATUS_BLOCK = undefined;
    var handle: windows.HANDLE = undefined;
    const status = windows.ntdll.NtCreateFile(
        &handle,
        .{
            .STANDARD = .{ .SYNCHRONIZE = true, .RIGHTS = .{
                .READ_CONTROL = mode != .create_exclusive,
                .WRITE_DAC = mode == .remediate_existing or mode == .remediate_existing_write,
            } },
            .GENERIC = .{ .WRITE = mode == .create_exclusive or mode == .remediate_existing_write, .READ = true },
        },
        &attributes,
        &io_status,
        null,
        .{ .NORMAL = true },
        .{}, // no older reader can retain access across ACL remediation
        if (mode == .create_exclusive) .CREATE else .OPEN,
        .{ .NON_DIRECTORY_FILE = true, .IO = .SYNCHRONOUS_NONALERT, .OPEN_REPARSE_POINT = true },
        null,
        0,
    );
    switch (status) {
        .SUCCESS => {},
        .OBJECT_NAME_COLLISION => return error.PathAlreadyExists,
        .OBJECT_NAME_NOT_FOUND, .OBJECT_PATH_NOT_FOUND => return error.FileNotFound,
        .OBJECT_NAME_INVALID, .OBJECT_PATH_SYNTAX_BAD => return error.InvalidPath,
        .ACCESS_DENIED => return error.PermissionDenied,
        .SHARING_VIOLATION => return error.FileBusy,
        else => return error.Unexpected,
    }
    errdefer windows.CloseHandle(handle);
    var basic_status: windows.IO_STATUS_BLOCK = undefined;
    var basic: windows.FILE.BASIC_INFORMATION = undefined;
    if (windows.ntdll.NtQueryInformationFile(handle, &basic_status, &basic, @sizeOf(@TypeOf(basic)), .Basic) != .SUCCESS)
        return error.Unexpected;
    // Opening the link itself prevents an existing WAL or snapshot reparse
    // point from redirecting file custody outside the validated parent.
    if (basic.FileAttributes.REPARSE_POINT) return error.InsecurePermissions;
    if (mode == .remediate_existing or mode == .remediate_existing_write) {
        var present: i32 = 0;
        var dacl: ?*anyopaque = null;
        var defaulted: i32 = 0;
        if (GetSecurityDescriptorDacl(owned_descriptor, &present, &dacl, &defaulted) == 0 or present == 0 or dacl == null)
            return error.Unexpected;
        const security_error = SetSecurityInfo(@intFromPtr(handle), windows_se_file_object, windows_dacl_security_information | windows_protected_dacl_security_information, null, null, dacl, null);
        if (security_error != 0) return windowsFileError(security_error);
    }
    if (!try windowsDaclIsOwnerOnly(@intFromPtr(handle)))
        return error.InsecurePermissions;
    return .{ .handle = handle, .flags = .{ .nonblocking = false } };
}

fn windowsDaclIsOwnerOnly(handle: usize) Error!bool {
    return windowsDaclMatches(handle, owner_only_sddl, owner_only_sddl_auto_inherited);
}

fn windowsDaclMatches(handle: usize, first: []const u8, second: []const u8) Error!bool {
    var descriptor: ?*anyopaque = null;
    var owner: ?*anyopaque = null;
    const security_error = GetSecurityInfo(handle, windows_se_file_object, windows_owner_security_information | windows_dacl_security_information, &owner, null, null, null, &descriptor);
    if (security_error != 0) return windowsFileError(security_error);
    const owned_descriptor = descriptor orelse return error.Unexpected;
    defer _ = LocalFree(@intFromPtr(owned_descriptor));
    if (!try windowsOwnerMatchesCurrentToken(owner)) return false;
    var sddl: ?[*:0]u16 = null;
    if (ConvertSecurityDescriptorToStringSecurityDescriptorW(owned_descriptor, 1, windows_dacl_security_information, &sddl, null) == 0)
        return windowsFileError(GetLastError());
    const text = sddl orelse return error.Unexpected;
    defer _ = LocalFree(@intFromPtr(text));
    const actual = std.mem.span(text);
    const first_w = std.unicode.utf8ToUtf16LeAlloc(std.heap.page_allocator, first) catch return error.OutOfMemory;
    defer std.heap.page_allocator.free(first_w);
    const second_w = std.unicode.utf8ToUtf16LeAlloc(std.heap.page_allocator, second) catch return error.OutOfMemory;
    defer std.heap.page_allocator.free(second_w);
    return std.mem.eql(u16, actual, first_w) or std.mem.eql(u16, actual, second_w);
}

fn windowsOwnerMatchesCurrentToken(owner: ?*anyopaque) Error!bool {
    const owner_sid = owner orelse return false;
    var token: usize = invalid_windows_handle;
    if (OpenProcessToken(GetCurrentProcess(), windows_token_query, &token) == 0)
        return windowsFileError(GetLastError());
    defer _ = CloseHandle(token);
    var token_user_bytes: [256]u8 align(@alignOf(WindowsTokenUser)) = undefined;
    var length: u32 = 0;
    if (GetTokenInformation(token, windows_token_user_class, &token_user_bytes, token_user_bytes.len, &length) == 0)
        return windowsFileError(GetLastError());
    if (length < @sizeOf(WindowsTokenUser)) return error.Unexpected;
    const token_user: *const WindowsTokenUser = @ptrCast(@alignCast(&token_user_bytes));
    const token_sid = token_user.user.sid orelse return error.Unexpected;
    if (EqualSid(owner_sid, token_sid) != 0) return true;
    // Elevated tokens can use Administrators as their default object owner.
    // Accept that SID only when it is this process token's actual TokenOwner.
    var token_owner_bytes: [256]u8 align(@alignOf(WindowsTokenOwner)) = undefined;
    length = 0;
    if (GetTokenInformation(token, windows_token_owner_class, &token_owner_bytes, token_owner_bytes.len, &length) == 0)
        return windowsFileError(GetLastError());
    if (length < @sizeOf(WindowsTokenOwner)) return error.Unexpected;
    const token_owner: *const WindowsTokenOwner = @ptrCast(@alignCast(&token_owner_bytes));
    return if (token_owner.owner) |owner_default_sid| EqualSid(owner_sid, owner_default_sid) != 0 else false;
}

test "Windows private ACL rejects an unrelated object owner" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var everyone: ?*anyopaque = null;
    if (ConvertStringSidToSidW(std.unicode.utf8ToUtf16LeStringLiteral("S-1-1-0"), &everyone) == 0)
        return windowsFileError(GetLastError());
    const sid = everyone orelse return error.Unexpected;
    defer _ = LocalFree(@intFromPtr(sid));
    try std.testing.expect(!try windowsOwnerMatchesCurrentToken(sid));
}

/// An account store accepts only an already-private directory with inheritable
/// owner/SYSTEM/Administrators ACEs. Checking before any WAL/snapshot open keeps
/// atomic temporary files private from their first instant of existence.
pub fn requirePrivateDirectoryWindows(io: std.Io, dir: std.Io.Dir, path: []const u8) !void {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    const parent_path = std.fs.path.dirname(path) orelse ".";
    const parent = try openPrivateDirectoryWindows(io, dir, parent_path);
    parent.close(io);
}

pub const WindowsPrivateDirectoryIdentity = struct {
    volume_serial: u64,
    file_id_low: u64,
    file_id_high: u64,
};

/// Inspect the supplied directory HANDLE, not a path that could name a
/// different object after a rename. The DACL check also verifies its owner.
pub fn requirePrivateDirectoryHandleWindows(dir: std.Io.Dir) Error!WindowsPrivateDirectoryIdentity {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    const FileStandardInfo = extern struct {
        allocation_size: i64,
        end_of_file: i64,
        links: u32,
        delete_pending: u8,
        directory: u8,
    };
    const FileAttributeTagInfo = extern struct { attributes: u32, tag: u32 };
    const FileIdInfo = extern struct { volume_serial: u64, file_id: [16]u8 };
    comptime {
        if (@sizeOf(FileStandardInfo) != 24 or @sizeOf(FileIdInfo) != 24)
            @compileError("Windows private directory information ABI mismatch");
    }
    const handle = @intFromPtr(dir.handle);
    var standard: FileStandardInfo = undefined;
    if (GetFileInformationByHandleEx(handle, 1, &standard, @sizeOf(FileStandardInfo)) == 0)
        return windowsFileError(GetLastError());
    if (standard.directory == 0 or standard.delete_pending != 0)
        return error.InsecurePermissions;
    var attributes: FileAttributeTagInfo = undefined;
    if (GetFileInformationByHandleEx(handle, 9, &attributes, @sizeOf(FileAttributeTagInfo)) == 0)
        return windowsFileError(GetLastError());
    if (attributes.attributes & 0x400 != 0) return error.InsecurePermissions; // FILE_ATTRIBUTE_REPARSE_POINT
    if (!try windowsDaclMatches(handle, private_directory_sddl, private_directory_sddl_auto_inherited))
        return error.InsecurePermissions;
    var identity: FileIdInfo = undefined;
    if (GetFileInformationByHandleEx(handle, 18, &identity, @sizeOf(FileIdInfo)) == 0)
        return windowsFileError(GetLastError());
    return .{
        .volume_serial = identity.volume_serial,
        .file_id_low = std.mem.readInt(u64, identity.file_id[0..8], .little),
        .file_id_high = std.mem.readInt(u64, identity.file_id[8..16], .little),
    };
}

test "Windows held private directory refuses a reparse handle" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const target = try createPrivateDirectoryWindows(tmp.dir, "target");
    defer target.close(std.testing.io);
    tmp.dir.symLink(std.testing.io, "target", "link", .{ .is_directory = true }) catch |err| switch (err) {
        error.AccessDenied, error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    const handle = try openDirectoryHandleWindows(tmp.dir, "link", false);
    defer windows.CloseHandle(handle);
    try std.testing.expectError(error.InsecurePermissions, requirePrivateDirectoryHandleWindows(.{ .handle = handle }));
}

/// Open and validate a private directory as one object. Keep the returned
/// HANDLE for all relative file operations, so a rename or ancestor retarget
/// cannot redirect later WAL, snapshot, or atomic temporary file accesses.
pub fn openPrivateDirectoryWindows(io: std.Io, dir: std.Io.Dir, path: []const u8) !std.Io.Dir {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    const parent = try dir.openDir(io, path, .{ .follow_symlinks = false });
    errdefer parent.close(io);
    _ = try requirePrivateDirectoryHandleWindows(parent);
    return parent;
}

/// Check a fresh std.Io atomic temporary file before writing any secret bytes.
/// Depending on the atomic create path, Windows may apply the parent's private
/// inherited ACEs or an already-protected owner/SYSTEM/Administrators DACL.
pub fn requireInheritedPrivateFileWindows(file: std.Io.File) Error!void {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    // Zig's atomic temp handle lacks the metadata-query access needed by
    // NtQueryInformationFile. The caller reopens it exclusively with
    // OPEN_REPARSE_POINT and rejects a reparse point before any secret write.
    const handle = @intFromPtr(file.handle);
    if (try windowsDaclMatches(handle, inherited_private_file_sddl, inherited_private_file_sddl_no_auto)) return;
    if (try windowsDaclIsOwnerOnly(handle)) return;
    return error.InsecurePermissions;
}

/// Validate a WAL HANDLE received from the authenticated Windows Helix parent.
/// The child must inspect the object itself: its private directory path cannot
/// be reopened while the predecessor retains an exclusive WAL handle.
pub fn requireExistingPrivateFileHandleWindows(file: std.Io.File) Error!void {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    try requireOwnerOnlyPrivateFileHandleWindows(file);
    var access_status: windows.IO_STATUS_BLOCK = undefined;
    var granted_access: u32 = 0;
    if (windows.ntdll.NtQueryInformationFile(file.handle, &access_status, &granted_access, @sizeOf(u32), .Access) != .SUCCESS)
        return error.InvalidDescriptor;
    // Promotion continues writing through this same FILE_OBJECT after the
    // predecessor releases its copy. A read-only duplicate would stage fine
    // and fail only after COMMIT, so reject it before READY.
    if ((granted_access & 0x0003) != 0x0003) return error.PermissionDenied;
}

/// Check the owner-only DACL on a captured read-only private snapshot or WAL.
/// The write-capable variant above also validates granted write access.
pub fn requireOwnerOnlyPrivateFileHandleWindows(file: std.Io.File) Error!void {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    var status: windows.IO_STATUS_BLOCK = undefined;
    var basic: windows.FILE.BASIC_INFORMATION = undefined;
    if (windows.ntdll.NtQueryInformationFile(file.handle, &status, &basic, @sizeOf(@TypeOf(basic)), .Basic) != .SUCCESS)
        return error.InvalidDescriptor;
    if (basic.FileAttributes.REPARSE_POINT or basic.FileAttributes.DIRECTORY)
        return error.InsecurePermissions;
    if (!try windowsDaclIsOwnerOnly(@intFromPtr(file.handle)))
        return error.InsecurePermissions;
}

/// Create a private directory with its inheritable ACL already present at
/// publication. Used by native custody tests to match the Windows setup CLI.
pub fn createPrivateDirectoryWindows(dir: std.Io.Dir, name: []const u8) Error!std.Io.Dir {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    if (name.len == 0 or !std.mem.eql(u8, std.fs.path.basename(name), name) or
        std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return error.InvalidPath;
    var name_w = std.Io.Threaded.sliceToPrefixedFileW(dir.handle, name, .{}) catch return error.InvalidPath;
    var object_name = name_w.string();
    var descriptor: ?*anyopaque = null;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(std.unicode.utf8ToUtf16LeStringLiteral(private_directory_sddl), 1, &descriptor, null) == 0)
        return windowsFileError(GetLastError());
    const owned_descriptor = descriptor orelse return error.Unexpected;
    defer _ = LocalFree(@intFromPtr(owned_descriptor));
    const attributes: windows.OBJECT.ATTRIBUTES = .{
        .RootDirectory = dir.handle,
        .ObjectName = &object_name,
        .SecurityDescriptor = owned_descriptor,
    };
    var io_status: windows.IO_STATUS_BLOCK = undefined;
    var handle: windows.HANDLE = undefined;
    const status = windows.ntdll.NtCreateFile(
        &handle,
        .{ .STANDARD = .{ .SYNCHRONIZE = true, .RIGHTS = .{ .READ_CONTROL = true } }, .GENERIC = .{ .READ = true, .WRITE = true } },
        &attributes,
        &io_status,
        null,
        .{ .NORMAL = true },
        .VALID_FLAGS,
        .CREATE,
        .{ .DIRECTORY_FILE = true, .IO = .SYNCHRONOUS_NONALERT },
        null,
        0,
    );
    switch (status) {
        .SUCCESS => {},
        .OBJECT_NAME_COLLISION => return error.PathAlreadyExists,
        .OBJECT_NAME_NOT_FOUND, .OBJECT_PATH_NOT_FOUND => return error.FileNotFound,
        .OBJECT_NAME_INVALID, .OBJECT_PATH_SYNTAX_BAD => return error.InvalidPath,
        .ACCESS_DENIED => return error.PermissionDenied,
        else => return error.Unexpected,
    }
    errdefer windows.CloseHandle(handle);
    if (!try windowsDaclMatches(@intFromPtr(handle), private_directory_sddl, private_directory_sddl_auto_inherited))
        return error.InsecurePermissions;
    return .{ .handle = handle };
}

/// Test/setup helper: only call on an empty, newly created directory. Runtime
/// account boot never mutates a broad directory ACL because an older handle
/// could retain create/read rights through that mutation.
pub fn protectEmptyDirectoryWindows(io: std.Io, dir: std.Io.Dir, path: []const u8) !void {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    _ = io;
    const parent = try openDirectoryHandleWindows(dir, path, true);
    defer windows.CloseHandle(parent);
    var descriptor: ?*anyopaque = null;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(std.unicode.utf8ToUtf16LeStringLiteral(private_directory_sddl), 1, &descriptor, null) == 0)
        return windowsFileError(GetLastError());
    const owned = descriptor orelse return error.Unexpected;
    defer _ = LocalFree(@intFromPtr(owned));
    var present: i32 = 0;
    var dacl: ?*anyopaque = null;
    var defaulted: i32 = 0;
    if (GetSecurityDescriptorDacl(owned, &present, &dacl, &defaulted) == 0 or present == 0 or dacl == null)
        return error.Unexpected;
    const security_error = SetSecurityInfo(@intFromPtr(parent), windows_se_file_object, windows_dacl_security_information | windows_protected_dacl_security_information, null, null, dacl, null);
    if (security_error != 0) return windowsFileError(security_error);
    if (!try windowsDaclMatches(@intFromPtr(parent), private_directory_sddl, private_directory_sddl_auto_inherited))
        return error.InsecurePermissions;
}

fn openDirectoryHandleWindows(dir: std.Io.Dir, path: []const u8, write_dac: bool) Error!windows.HANDLE {
    var path_w = std.Io.Threaded.sliceToPrefixedFileW(dir.handle, path, .{}) catch return error.InvalidPath;
    var object_name = path_w.string();
    const attributes: windows.OBJECT.ATTRIBUTES = .{
        .RootDirectory = if (std.Io.Dir.path.isAbsoluteWindowsWtf16(path_w.span())) null else dir.handle,
        .ObjectName = &object_name,
    };
    var io_status: windows.IO_STATUS_BLOCK = undefined;
    var handle: windows.HANDLE = undefined;
    const status = windows.ntdll.NtCreateFile(
        &handle,
        .{ .STANDARD = .{ .SYNCHRONIZE = true, .RIGHTS = .{ .READ_CONTROL = true, .WRITE_DAC = write_dac } } },
        &attributes,
        &io_status,
        null,
        .{ .NORMAL = true },
        .VALID_FLAGS,
        .OPEN,
        .{ .DIRECTORY_FILE = true, .IO = .SYNCHRONOUS_NONALERT, .OPEN_REPARSE_POINT = true },
        null,
        0,
    );
    return switch (status) {
        .SUCCESS => handle,
        .OBJECT_NAME_NOT_FOUND, .OBJECT_PATH_NOT_FOUND => error.FileNotFound,
        .OBJECT_NAME_INVALID, .OBJECT_PATH_SYNTAX_BAD => error.InvalidPath,
        .ACCESS_DENIED => error.PermissionDenied,
        .SHARING_VIOLATION => error.FileBusy,
        else => error.Unexpected,
    };
}

test "native runtime descriptors retain CLOEXEC and reject retired handles" {
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
    const fd = try openReadZ("/dev/null");
    defer close(fd);
    var buffer: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 0), try read(fd, &buffer));
    try std.testing.expectEqual(@as(usize, 0), try pread(fd, &buffer, 0));
    try std.testing.expectError(error.InvalidDescriptor, write(fd, "x"));
    try setNonblocking(fd);
    sleepMillis(1);
    const copy = try duplicate(fd);
    try std.testing.expect(fdValid(copy));
    try setCloexec(copy, true);
    const flags = sys.fcntl(copy, posix.F.GETFD, @as(i32, 0));
    try check(flags);
    try std.testing.expect(@as(usize, @intCast(flags)) & posix.FD_CLOEXEC != 0);
    close(copy);
    try std.testing.expect(!fdValid(copy));
    try std.testing.expectError(error.InvalidDescriptor, setCloexec(copy, true));
    try std.testing.expectError(error.InvalidDescriptor, socketType(copy));
    var pair: [2]Fd = undefined;
    try check(sys.socketpair(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0, &pair));
    defer for (pair) |socket| close(socket);
    try std.testing.expectEqual(@as(u32, posix.SOCK.STREAM), try socketType(pair[0]));
    var address: AddressStorage = undefined;
    var address_len: AddressLength = @sizeOf(AddressStorage);
    try getpeername(pair[0], &address, &address_len);
    try std.testing.expectEqual(@as(usize, 1), try write(pair[0], "x"));
    try std.testing.expectEqual(@as(usize, 1), try read(pair[1], &buffer));
    shutdownBoth(pair[0]);
    try std.testing.expectEqual(@as(usize, 0), try read(pair[1], &buffer));
    std.mem.doNotOptimizeAway(&openTruncateZ);
}

test "Windows runtime shutdown uses opaque IOCP socket descriptor" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const listener = try io_backend.listenTcp("127.0.0.1", 0);
    defer io_backend.closeSocket(listener.fd);
    const client = WSASocketW(2, 1, 6, null, 0, 1);
    try std.testing.expect(client != std.math.maxInt(usize));
    defer _ = closesocket(client);
    const timeout_ms: u32 = 1000;
    try std.testing.expectEqual(@as(i32, 0), setsockopt(client, 0xffff, 0x1006, &timeout_ms, @sizeOf(u32)));
    const addr = WindowsSockAddr4{
        .family = 2,
        .port = std.mem.nativeToBig(u16, listener.port),
        .addr = std.mem.nativeToBig(u32, 0x7f00_0001),
        .zero = @splat(0),
    };
    try std.testing.expectEqual(@as(i32, 0), connect(client, &addr, @sizeOf(WindowsSockAddr4)));
    const accepted = try io_backend.pullAccept(listener.fd);
    defer close(accepted);
    try std.testing.expect(fdValid(accepted));
    try std.testing.expectEqual(@as(u32, 1), try socketType(accepted));
    shutdownBoth(accepted);
    var one: [1]u8 = undefined;
    try std.testing.expectEqual(@as(i32, 0), recv(client, &one, 1, 0));
    close(accepted);
    try std.testing.expect(!fdValid(accepted));
    try std.testing.expectError(error.InvalidDescriptor, socketType(accepted));
    try std.testing.expectError(error.Unsupported, duplicate(listener.fd));
}

test "Windows file ID rollover starts halfway and remains due after exhaustion" {
    var files = WindowsFiles{};
    try std.testing.expect(!files.rolloverDue());
    files.next_fd = windows_file_rollover_at - 1;
    try std.testing.expect(!files.rolloverDue());
    files.next_fd = windows_file_rollover_at;
    try std.testing.expect(files.rolloverDue());
    files.next_fd = -1;
    try std.testing.expect(files.rolloverDue());
}

test "Windows runtime file HANDLE registry roundtrips UTF-8 paths and duplicates" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [256]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, ".zig-cache/tmp/{s}/résumé-雪.txt", .{&tmp.sub_path});
    path_buf[path.len] = 0;
    const zpath = path_buf[0..path.len :0];
    try std.testing.expectError(error.FileNotFound, openReadZ(zpath));

    const writer = try openTruncateZ(zpath, 0o600);
    defer close(writer);
    try std.testing.expect(writer >= windows_file_fd_first);
    try std.testing.expect(fdValid(writer));
    try expectOwnerOnlyWindowsDacl(writer);
    var offset: usize = 0;
    const payload = "onyx windows file roundtrip\n";
    while (offset < payload.len) {
        const count = try write(writer, payload[offset..]);
        try std.testing.expect(count > 0);
        offset += count;
    }
    close(writer);
    try std.testing.expect(!fdValid(writer));

    const reader = try openReadZ(zpath);
    defer close(reader);
    const copy = try duplicate(reader);
    defer close(copy);
    try setCloexec(copy, true);
    close(reader);
    try std.testing.expect(!fdValid(reader));
    var buf: [64]u8 = undefined;
    const count = try read(copy, &buf);
    try std.testing.expectEqualStrings(payload, buf[0..count]);
    try std.testing.expectEqual(@as(usize, 0), try read(copy, &buf));
    close(copy);
    try std.testing.expect(!fdValid(copy));
    try std.testing.expectError(error.InvalidDescriptor, read(copy, &buf));
}

fn windowsFileHandleForTest(fd: Fd) !usize {
    windows_files.lockSpin();
    defer windows_files.lock.unlock();
    return windows_files.handles.get(fd) orelse error.TestUnexpectedResult;
}

fn expectOwnerOnlyWindowsDacl(fd: Fd) !void {
    const handle = try windowsFileHandleForTest(fd);
    return expectOwnerOnlyWindowsDaclHandle(handle);
}

fn expectOwnerOnlyWindowsDaclHandle(handle: usize) !void {
    var descriptor: ?*anyopaque = null;
    try std.testing.expectEqual(@as(u32, 0), GetSecurityInfo(handle, windows_se_file_object, windows_dacl_security_information, null, null, null, null, &descriptor));
    const owned = descriptor orelse return error.TestUnexpectedResult;
    defer _ = LocalFree(@intFromPtr(owned));
    var sddl: ?[*:0]u16 = null;
    try std.testing.expectEqual(@as(i32, 1), ConvertSecurityDescriptorToStringSecurityDescriptorW(owned, 1, windows_dacl_security_information, &sddl, null));
    const text = sddl orelse return error.TestUnexpectedResult;
    defer _ = LocalFree(@intFromPtr(text));
    const utf8 = try std.unicode.utf16LeToUtf8Alloc(std.testing.allocator, std.mem.span(text));
    defer std.testing.allocator.free(utf8);
    // Windows may preserve the auto-inherited control bit even when the DACL
    // is protected and contains no inherited ACEs. Both forms require the
    // protected marker and the exact same three owner-only ACEs.
    if (!std.mem.eql(u8, owner_only_sddl, utf8) and !std.mem.eql(u8, owner_only_sddl_auto_inherited, utf8)) {
        std.debug.print("unexpected private file DACL: {s}\n", .{utf8});
        return error.TestUnexpectedResult;
    }
}

test "Windows node keyfile private exclusive creation attaches protected DACL before writing" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var file = try createPrivateExclusiveWindows(tmp.dir, "node-雪.key");
    defer file.close(std.testing.io);
    try expectOwnerOnlyWindowsDaclHandle(@intFromPtr(file.handle));
    try std.testing.expectError(error.PathAlreadyExists, createPrivateExclusiveWindows(tmp.dir, "node-雪.key"));
}

test "Windows node keyfile existing permissive DACL is rejected by preflight and hardened by boot" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const name = "node-雪.key";
    {
        var initial = try createPrivateExclusiveWindows(tmp.dir, name);
        defer initial.close(std.testing.io);
        try initial.writeStreamingAll(std.testing.io, "seed");
    }

    var path_buf: [256]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, ".zig-cache/tmp/{s}/{s}", .{ &tmp.sub_path, name });
    const wide = try std.unicode.utf8ToUtf16LeAllocZ(std.testing.allocator, path);
    defer std.testing.allocator.free(wide);
    var held_reader = CreateFileW(wide.ptr, windows_generic_read | windows_write_dac, windows_file_share_read | windows_file_share_write | windows_file_share_delete, null, windows_open_existing, windows_file_attribute_normal, null);
    try std.testing.expect(held_reader != invalid_windows_handle);
    defer {
        if (held_reader != invalid_windows_handle) _ = CloseHandle(held_reader);
    }
    var broad_descriptor: ?*anyopaque = null;
    try std.testing.expectEqual(@as(i32, 1), ConvertStringSecurityDescriptorToSecurityDescriptorW(std.unicode.utf8ToUtf16LeStringLiteral("D:P(A;;FA;;;WD)"), 1, &broad_descriptor, null));
    const broad = broad_descriptor orelse return error.TestUnexpectedResult;
    defer _ = LocalFree(@intFromPtr(broad));
    var present: i32 = 0;
    var broad_dacl: ?*anyopaque = null;
    var defaulted: i32 = 0;
    try std.testing.expectEqual(@as(i32, 1), GetSecurityDescriptorDacl(broad, &present, &broad_dacl, &defaulted));
    try std.testing.expect(present != 0 and broad_dacl != null);
    try std.testing.expectEqual(@as(u32, 0), SetSecurityInfo(held_reader, windows_se_file_object, windows_dacl_security_information | windows_protected_dacl_security_information, null, null, broad_dacl, null));
    try std.testing.expect(!try windowsDaclIsOwnerOnly(held_reader));

    // An already open reader retains its access after a DACL change. Reject
    // the load while such a reader exists, before returning any seed bytes.
    try std.testing.expectError(error.FileBusy, openExistingPrivateWindows(tmp.dir, name, .remediate));
    var contents: [4]u8 = undefined;
    var count: u32 = 0;
    try std.testing.expectEqual(@as(i32, 1), ReadFile(held_reader, &contents, contents.len, &count, null));
    try std.testing.expectEqualStrings("seed", contents[0..count]);
    try std.testing.expect(!try windowsDaclIsOwnerOnly(held_reader));
    _ = CloseHandle(held_reader);
    held_reader = invalid_windows_handle;

    try std.testing.expectError(error.InsecurePermissions, openExistingPrivateWindows(tmp.dir, name, .verify_only));
    {
        const still_broad = CreateFileW(wide.ptr, windows_generic_read, windows_file_share_read | windows_file_share_write | windows_file_share_delete, null, windows_open_existing, windows_file_attribute_normal, null);
        try std.testing.expect(still_broad != invalid_windows_handle);
        defer _ = CloseHandle(still_broad);
        try std.testing.expect(!try windowsDaclIsOwnerOnly(still_broad));
    }

    var secured = try openExistingPrivateWindows(tmp.dir, name, .remediate);
    defer secured.close(std.testing.io);
    try expectOwnerOnlyWindowsDaclHandle(@intFromPtr(secured.handle));
    count = 0;
    try std.testing.expectEqual(@as(i32, 1), ReadFile(@intFromPtr(secured.handle), &contents, contents.len, &count, null));
    try std.testing.expectEqualStrings("seed", contents[0..count]);
}

test "Windows runtime private file truncation replaces permissive existing DACL" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [256]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, ".zig-cache/tmp/{s}/private.txt", .{&tmp.sub_path});
    path_buf[path.len] = 0;
    const zpath = path_buf[0..path.len :0];
    const first = try openTruncateZ(zpath, 0o600);
    defer close(first);
    try expectOwnerOnlyWindowsDacl(first);
    try std.testing.expectEqual(@as(usize, 4), try write(first, "seed"));

    // Give this empty test file a broad DACL, then prove a subsequent open
    // replaces that DACL before any caller can write private data.
    var broad_descriptor: ?*anyopaque = null;
    try std.testing.expectEqual(@as(i32, 1), ConvertStringSecurityDescriptorToSecurityDescriptorW(std.unicode.utf8ToUtf16LeStringLiteral("D:P(A;;FA;;;WD)"), 1, &broad_descriptor, null));
    const broad = broad_descriptor orelse return error.TestUnexpectedResult;
    defer _ = LocalFree(@intFromPtr(broad));
    var present: i32 = 0;
    var broad_dacl: ?*anyopaque = null;
    var defaulted: i32 = 0;
    try std.testing.expectEqual(@as(i32, 1), GetSecurityDescriptorDacl(broad, &present, &broad_dacl, &defaulted));
    try std.testing.expect(present != 0 and broad_dacl != null);
    try std.testing.expectEqual(@as(u32, 0), SetSecurityInfo(try windowsFileHandleForTest(first), windows_se_file_object, windows_dacl_security_information | windows_protected_dacl_security_information, null, null, broad_dacl, null));
    close(first);

    // A reader admitted under the old broad DACL could otherwise keep its
    // handle after replacement and observe the private payload written next.
    const wide = try std.unicode.utf8ToUtf16LeAllocZ(std.testing.allocator, zpath);
    defer std.testing.allocator.free(wide);
    var held_reader = CreateFileW(wide.ptr, windows_generic_read, windows_file_share_read | windows_file_share_write | windows_file_share_delete, null, windows_open_existing, windows_file_attribute_normal, null);
    try std.testing.expect(held_reader != invalid_windows_handle);
    defer {
        if (held_reader != invalid_windows_handle) _ = CloseHandle(held_reader);
    }
    try std.testing.expectError(error.PermissionDenied, openTruncateZ(zpath, 0o600));
    var read_buf: [4]u8 = undefined;
    var read_count: u32 = 0;
    try std.testing.expectEqual(@as(i32, 1), ReadFile(held_reader, &read_buf, read_buf.len, &read_count, null));
    try std.testing.expectEqualStrings("seed", read_buf[0..read_count]);
    _ = CloseHandle(held_reader);
    held_reader = invalid_windows_handle;

    const hardened = try openTruncateZ(zpath, 0o600);
    defer close(hardened);
    try expectOwnerOnlyWindowsDacl(hardened);
    close(hardened);
    const reader = try openReadZ(zpath);
    defer close(reader);
    var one: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 0), try read(reader, &one));
}
