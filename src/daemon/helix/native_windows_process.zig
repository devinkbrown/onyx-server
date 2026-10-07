// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Windows native Helix candidate launch and capability negotiation. No live
//! socket, arena key, or state handle is sent before the actual child image
//! answers the exact capability challenge on its private control channel.
const std = @import("std");
const builtin = @import("builtin");
const platform = @import("../../substrate/platform.zig");
const control = @import("native_windows_control.zig");
const windows_scm = @import("../windows_scm.zig");

pub const candidate_arg = "--helix-windows-successor-v19";
pub const capability = "onyx-native-helix-windows-v19;strict-capsules;hmac-control;indexed-sockets;encrypted-arena;account-wal-custody-v1;metrics-custody-v1;webhook-custody-v1;history-custody-v4;history-material-custody-v2;udp-custody-v1;media-custody-v1;active-webtransport-custody-v1;webpush-custody-v1;abuse-custody-v1;geo-custody-v1;mail-wal-custody-v2;policy-custody-v1;operator-custody-v1;account-flow-custody-v1;user-settings-custody-v1;memo-custody-v1;memo-inbox-custody-v1;ocsp-custody-v1;acme-custody-v1;tls-material-custody-v1;tls-replay-custody-v1;wasm-custody-v1;scm-custody-v1;inert-ready;commit-ack;release-before-iocp";
const process_query_limited_information: u32 = 0x1000;
const synchronize: u32 = 0x0010_0000;
const extended_startupinfo_present: u32 = 0x0008_0000;
const create_no_window: u32 = 0x0800_0000;
const proc_thread_attribute_handle_list: usize = 0x0002_0002;
const std_error_handle: u32 = 0xffff_fff4;
const std_output_handle: u32 = 0xffff_fff5;
const std_input_handle: u32 = 0xffff_fff6;
const startf_use_std_handles: u32 = 0x0000_0100;
const duplicate_same_access: u32 = 2;
const infinite: u32 = 0xffff_ffff;
const generic_read: u32 = 0x8000_0000;
const generic_write: u32 = 0x4000_0000;
const file_share_read: u32 = 1;
const file_share_write: u32 = 2;
const open_existing: u32 = 3;
const file_attribute_normal: u32 = 0x80;
const file_attribute_directory: u32 = 0x10;
const file_attribute_reparse_point: u32 = 0x400;
const file_type_disk: u32 = 1;
const file_read_attributes: u32 = 0x80;
const file_flag_open_reparse_point: u32 = 0x0020_0000;
const file_flag_backup_semantics: u32 = 0x0200_0000;
const file_id_info: u32 = 18;

const ByHandleFileInformation = extern struct {
    file_attributes: u32,
    creation_time_low: u32,
    creation_time_high: u32,
    access_time_low: u32,
    access_time_high: u32,
    write_time_low: u32,
    write_time_high: u32,
    volume_serial: u32,
    file_size_high: u32,
    file_size_low: u32,
    link_count: u32,
    file_index_high: u32,
    file_index_low: u32,
};

const FileIdInfo = extern struct {
    volume_serial: u64,
    file_id: [16]u8,
};

const StartupInfoEx = extern struct {
    startup: std.os.windows.STARTUPINFOW,
    attributes: ?*anyopaque,
};
const ProcessInformation = extern struct {
    process: usize,
    thread: usize,
    pid: u32,
    thread_id: u32,
};

comptime {
    if (builtin.os.tag == .windows and (@sizeOf(StartupInfoEx) != @sizeOf(std.os.windows.STARTUPINFOW) + @sizeOf(usize) or
        @sizeOf(ProcessInformation) != 2 * @sizeOf(usize) + 8))
        @compileError("Windows process creation ABI mismatch");
}

extern "kernel32" fn GetCurrentProcess() callconv(.winapi) usize;
extern "kernel32" fn GetCurrentProcessId() callconv(.winapi) u32;
extern "kernel32" fn GetConsoleWindow() callconv(.winapi) ?*anyopaque;
extern "kernel32" fn GetStdHandle(which: u32) callconv(.winapi) usize;
extern "kernel32" fn GetProcessId(process: usize) callconv(.winapi) u32;
extern "kernel32" fn GetFileType(handle: usize) callconv(.winapi) u32;
extern "kernel32" fn SetHandleInformation(handle: usize, mask: u32, flags: u32) callconv(.winapi) i32;
extern "kernel32" fn DuplicateHandle(source_process: usize, source_handle: usize, target_process: usize, target_handle: *usize, desired_access: u32, inherit_handle: i32, options: u32) callconv(.winapi) i32;
extern "kernel32" fn InitializeProcThreadAttributeList(list: ?*anyopaque, count: u32, flags: u32, bytes: *usize) callconv(.winapi) i32;
extern "kernel32" fn UpdateProcThreadAttribute(list: *anyopaque, flags: u32, attribute: usize, value: *anyopaque, bytes: usize, previous: ?*anyopaque, returned: ?*usize) callconv(.winapi) i32;
extern "kernel32" fn DeleteProcThreadAttributeList(list: *anyopaque) callconv(.winapi) void;
extern "kernel32" fn CreateProcessW(application: [*:0]const u16, command_line: [*:0]u16, process_attributes: ?*anyopaque, thread_attributes: ?*anyopaque, inherit: i32, creation_flags: u32, environment: ?*anyopaque, cwd: ?[*:0]const u16, startup: *StartupInfoEx, information: *ProcessInformation) callconv(.winapi) i32;
extern "kernel32" fn TerminateProcess(process: usize, exit_code: u32) callconv(.winapi) i32;
extern "kernel32" fn WaitForSingleObject(handle: usize, ms: u32) callconv(.winapi) u32;
extern "kernel32" fn CloseHandle(handle: usize) callconv(.winapi) i32;
extern "kernel32" fn GetSystemDirectoryW(buffer: [*]u16, size: u32) callconv(.winapi) u32;
extern "kernel32" fn CreateFileW(path: [*:0]const u16, access: u32, share: u32, security: ?*anyopaque, disposition: u32, flags: u32, template: usize) callconv(.winapi) usize;
extern "kernel32" fn ReadFile(handle: usize, buffer: [*]u8, count: u32, read: *u32, overlapped: ?*anyopaque) callconv(.winapi) i32;
extern "kernel32" fn GetFinalPathNameByHandleW(handle: usize, buffer: ?[*]u16, length: u32, flags: u32) callconv(.winapi) u32;
extern "kernel32" fn GetFileInformationByHandle(handle: usize, information: *ByHandleFileInformation) callconv(.winapi) i32;
extern "kernel32" fn GetFileInformationByHandleEx(handle: usize, information_class: u32, information: *FileIdInfo, size: u32) callconv(.winapi) i32;

pub const Error = control.Error || std.mem.Allocator.Error || error{
    InvalidCandidate,
    RandomSourceFailed,
    AttributeFailed,
    ProcessCreateFailed,
    ImageOpenFailed,
    ImageReadFailed,
    ImageChanged,
    ImageIdentityFailed,
    DirectoryOpenFailed,
};

fn closeOwned(handle: *usize) void {
    if (comptime builtin.os.tag == .windows) {
        if (handle.* != 0) _ = CloseHandle(handle.*);
    }
    handle.* = 0;
}

/// Open without write or delete sharing so the checked image cannot be
/// rewritten or replaced while the candidate is launched and authenticated.
fn openPinnedImageWithFlags(allocator: std.mem.Allocator, executable: []const u8, flags: u32) Error!usize {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    if (executable.len == 0 or !std.fs.path.isAbsolute(executable) or
        std.mem.indexOfAny(u8, executable, "\x00\r\n\"") != null) return error.InvalidCandidate;
    const path = std.unicode.wtf8ToWtf16LeAllocZ(allocator, executable) catch return error.InvalidCandidate;
    defer allocator.free(path);
    const handle = CreateFileW(path.ptr, generic_read, file_share_read, null, open_existing, flags, 0);
    if (handle == std.math.maxInt(usize)) return error.ImageOpenFailed;
    if (GetFileType(handle) != file_type_disk) {
        _ = CloseHandle(handle);
        return error.InvalidCandidate;
    }
    return handle;
}

fn openPinnedImage(allocator: std.mem.Allocator, executable: []const u8) Error!usize {
    return openPinnedImageWithFlags(allocator, executable, file_attribute_normal);
}

/// Open the final launch name itself, without following a last-component link.
fn openPinnedFinalImage(allocator: std.mem.Allocator, final_path: []const u8) Error!usize {
    var handle = try openPinnedImageWithFlags(allocator, final_path, file_attribute_normal | file_flag_open_reparse_point);
    errdefer closeOwned(&handle);
    var information: ByHandleFileInformation = undefined;
    if (GetFileInformationByHandle(handle, &information) == 0 or
        information.file_attributes & file_attribute_reparse_point != 0 or
        information.file_attributes & file_attribute_directory != 0)
        return error.InvalidCandidate;
    return handle;
}

fn digestPinnedImage(handle: usize) Error![32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    while (true) {
        var count: u32 = 0;
        if (ReadFile(handle, &buffer, buffer.len, &count, null) == 0) return error.ImageReadFailed;
        if (count == 0) break;
        hash.update(buffer[0..count]);
    }
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    return digest;
}

/// The boot path is measured once before maintenance can begin. A later
/// same-image attempt compares against this exact digest.
pub fn digestImageAtPath(allocator: std.mem.Allocator, executable: []const u8) Error![32]u8 {
    var image = try openPinnedImage(allocator, executable);
    defer closeOwned(&image);
    return digestPinnedImage(image);
}

/// Resolve the file handle to its final local DOS path before CreateProcessW.
/// This removes caller-path symlinks and rejects remote shares, whose server
/// need not honor local share locks.
fn pinnedImagePath(allocator: std.mem.Allocator, handle: usize) Error![]u8 {
    const length = GetFinalPathNameByHandleW(handle, null, 0, 0);
    if (length == 0 or length > 32767) return error.InvalidCandidate;
    const wide = try allocator.alloc(u16, length + 1);
    defer allocator.free(wide);
    const actual = GetFinalPathNameByHandleW(handle, wide.ptr, @intCast(wide.len), 0);
    if (actual == 0 or actual >= wide.len) return error.InvalidCandidate;
    const path = std.unicode.wtf16LeToWtf8Alloc(allocator, wide[0..actual]) catch return error.InvalidCandidate;
    if (path.len < 7 or !std.mem.startsWith(u8, path, "\\\\?\\") or
        !std.ascii.isAlphabetic(path[4]) or path[5] != ':' or path[6] != '\\')
    {
        allocator.free(path);
        return error.InvalidCandidate;
    }
    return path;
}

fn imageIdentity(handle: usize) Error!FileIdInfo {
    var result: FileIdInfo = undefined;
    if (GetFileInformationByHandleEx(handle, file_id_info, &result, @sizeOf(FileIdInfo)) == 0)
        return error.ImageIdentityFailed;
    return result;
}

/// Lock the volume root and each directory above the executable. A rename or
/// reparse replacement needs DELETE access, which these handles do not share.
const PinnedAncestors = struct {
    allocator: std.mem.Allocator,
    handles: std.ArrayList(usize) = .empty,

    fn deinit(self: *PinnedAncestors) void {
        for (self.handles.items) |handle| _ = CloseHandle(handle);
        self.handles.deinit(self.allocator);
        self.handles = .empty;
    }
};

fn pinImageAncestors(allocator: std.mem.Allocator, final_path: []const u8) Error!PinnedAncestors {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    if (final_path.len < 8 or !std.mem.startsWith(u8, final_path, "\\\\?\\") or
        !std.ascii.isAlphabetic(final_path[4]) or final_path[5] != ':' or final_path[6] != '\\')
        return error.InvalidCandidate;
    var pins = PinnedAncestors{ .allocator = allocator };
    errdefer pins.deinit();
    var end: usize = 7;
    while (true) {
        const wide = std.unicode.wtf8ToWtf16LeAllocZ(allocator, final_path[0..end]) catch return error.InvalidCandidate;
        const handle = CreateFileW(wide.ptr, file_read_attributes, file_share_read | file_share_write, null, open_existing, file_flag_backup_semantics | file_flag_open_reparse_point, 0);
        allocator.free(wide);
        if (handle == std.math.maxInt(usize)) return error.DirectoryOpenFailed;
        pins.handles.append(allocator, handle) catch |err| {
            _ = CloseHandle(handle);
            return err;
        };
        var information: ByHandleFileInformation = undefined;
        if (GetFileInformationByHandle(handle, &information) == 0 or
            information.file_attributes & file_attribute_directory == 0 or
            information.file_attributes & file_attribute_reparse_point != 0)
            return error.InvalidCandidate;
        const component_start = if (end == 7) end else end + 1;
        const separator = std.mem.indexOfScalarPos(u8, final_path, component_start, '\\') orelse break;
        if (separator == component_start) return error.InvalidCandidate;
        end = separator;
    }
    return pins;
}

/// Maintenance-only successor. Keep the checked file locked until the actual
/// child completes the private capability exchange; transfer starts afterward.
pub fn spawnSameImage(allocator: std.mem.Allocator, executable: []const u8, config: ?[]const u8, generation: u64, deadline: i64, boot_digest: [32]u8) Error!Process {
    var image = try openPinnedImage(allocator, executable);
    defer closeOwned(&image);
    const digest = try digestPinnedImage(image);
    if (!std.crypto.timing_safe.eql([32]u8, digest, boot_digest)) return error.ImageChanged;
    const final_path = try pinnedImagePath(allocator, image);
    defer allocator.free(final_path);
    var ancestors = try pinImageAncestors(allocator, final_path);
    defer ancestors.deinit();
    var final_image = try openPinnedFinalImage(allocator, final_path);
    defer closeOwned(&final_image);
    if (!std.meta.eql(try imageIdentity(image), try imageIdentity(final_image)) or
        !std.crypto.timing_safe.eql([32]u8, digest, try digestPinnedImage(final_image)))
        return error.ImageChanged;
    var candidate = try launchUnverified(allocator, final_path, config, generation, true);
    errdefer candidate.deinit();
    try candidate.negotiate(deadline);
    return candidate;
}

fn appendQuoted(allocator: std.mem.Allocator, output: *std.ArrayList(u8), arg: []const u8) Error!void {
    if (std.mem.indexOfScalar(u8, arg, 0) != null) return error.InvalidCandidate;
    try output.append(allocator, '"');
    var slashes: usize = 0;
    for (arg) |byte| switch (byte) {
        '\\' => slashes += 1,
        '"' => {
            try output.appendNTimes(allocator, '\\', slashes * 2 + 1);
            try output.append(allocator, '"');
            slashes = 0;
        },
        else => {
            try output.appendNTimes(allocator, '\\', slashes);
            try output.append(allocator, byte);
            slashes = 0;
        },
    };
    try output.appendNTimes(allocator, '\\', slashes * 2);
    try output.append(allocator, '"');
}

fn commandLine(allocator: std.mem.Allocator, executable: []const u8, child_read: usize, child_write: usize, parent_process: usize, parent_pid: u32, config: ?[]const u8, service_stop: usize, service_lease: usize) Error![:0]u16 {
    var args: std.ArrayList(u8) = .empty;
    defer args.deinit(allocator);
    try appendQuoted(allocator, &args, executable);
    try args.append(allocator, ' ');
    try appendQuoted(allocator, &args, candidate_arg);
    inline for (.{ child_read, child_write, parent_process, parent_pid }) |number| {
        var buffer: [32]u8 = undefined;
        const decimal = std.fmt.bufPrint(&buffer, "{d}", .{number}) catch return error.InvalidCandidate;
        try args.append(allocator, ' ');
        try appendQuoted(allocator, &args, decimal);
    }
    try args.append(allocator, ' ');
    try appendQuoted(allocator, &args, config orelse "");
    inline for (.{ service_stop, service_lease }) |number| {
        var buffer: [32]u8 = undefined;
        const decimal = std.fmt.bufPrint(&buffer, "{d}", .{number}) catch return error.InvalidCandidate;
        try args.append(allocator, ' ');
        try appendQuoted(allocator, &args, decimal);
    }
    return std.unicode.wtf8ToWtf16LeAllocZ(allocator, args.items) catch return error.InvalidCandidate;
}

pub const Process = struct {
    process_handle: usize = 0,
    pid: u32 = 0,
    endpoint: control.Endpoint,
    identity: control.Identity,
    committed: bool = false,

    /// Abort is transactional: terminate and reap the uncommitted image before
    /// its predecessor is allowed to resume socket I/O. The committed image is
    /// never killed by predecessor cleanup.
    pub fn reapUncommitted(self: *Process) void {
        if (comptime builtin.os.tag == .windows) {
            if (self.process_handle != 0 and !self.committed) {
                _ = TerminateProcess(self.process_handle, 125);
                _ = WaitForSingleObject(self.process_handle, infinite);
            }
        }
    }

    pub fn deinit(self: *Process) void {
        if (comptime builtin.os.tag == .windows) {
            if (self.process_handle != 0) {
                self.reapUncommitted();
                closeOwned(&self.process_handle);
            }
        }
        self.endpoint.deinit();
        self.pid = 0;
    }

    /// The source executable must be an absolute path. CreateProcessW loads
    /// that path; capability checking is against the actual running image.
    pub fn spawn(allocator: std.mem.Allocator, executable: []const u8, config: ?[]const u8, generation: u64, deadline: i64) Error!Process {
        var candidate = try launchUnverified(allocator, executable, config, generation, true);
        errdefer candidate.deinit();
        try candidate.negotiate(deadline);
        return candidate;
    }

    fn negotiate(self: *Process, deadline: i64) Error!void {
        var prelude = control.Prelude{ .identity = self.identity, .key = self.endpoint.key };
        defer std.crypto.secureZero(u8, &prelude.key);
        try control.sendPrelude(self.endpoint.write_handle, prelude, deadline);
        try self.endpoint.send(.hello, capability, deadline);
        var reply = try self.endpoint.receive(deadline);
        defer reply.deinit();
        if (reply.kind != .capabilities or !std.mem.eql(u8, reply.bytes(), capability)) return error.InvalidCandidate;
    }
};

fn launchUnverified(allocator: std.mem.Allocator, executable: []const u8, config: ?[]const u8, generation: u64, inherit_standard_streams: bool) Error!Process {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    if (executable.len == 0 or !std.fs.path.isAbsolute(executable) or std.mem.indexOfAny(u8, executable, "\x00\r\n\"") != null) return error.InvalidCandidate;
    if (config) |path| if (std.mem.indexOfAny(u8, path, "\x00\r\n") != null) return error.InvalidCandidate;
    var identity: control.Identity = .{ .generation = generation, .upgrade_id = undefined };
    try platform.fillOsEntropy(&identity.upgrade_id);
    var key: control.Key = undefined;
    try platform.fillOsEntropy(&key);
    defer std.crypto.secureZero(u8, &key);

    var pair = try control.Pair.init();
    defer pair.deinit();
    const own = GetCurrentProcess();
    const parent_pid = GetCurrentProcessId();
    var child_parent: usize = 0;
    if (DuplicateHandle(own, own, own, &child_parent, synchronize | process_query_limited_information, 1, 0) == 0) return error.DuplicateFailed;
    defer closeOwned(&child_parent);
    // Preserve each usable standard stream through the explicit handle list.
    // STARTF_USESTDHANDLES sets all three; passing only stderr would silently
    // discard a valid service stdin or stdout in the committed successor.
    var child_stdin: usize = 0;
    var child_stdout: usize = 0;
    var child_stderr: usize = 0;
    var child_service_stop: usize = 0;
    var child_service_lease: usize = 0;
    defer closeOwned(&child_stdin);
    defer closeOwned(&child_stdout);
    defer closeOwned(&child_stderr);
    defer closeOwned(&child_service_stop);
    defer closeOwned(&child_service_lease);
    if (windows_scm.activeForHelix()) |service| {
        if (DuplicateHandle(own, service.stop_event, own, &child_service_stop, 0, 1, duplicate_same_access) == 0 or
            DuplicateHandle(own, service.lease_write, own, &child_service_lease, 0, 1, duplicate_same_access) == 0)
            return error.DuplicateFailed;
    }
    if (inherit_standard_streams) {
        inline for (.{ .{ std_input_handle, &child_stdin }, .{ std_output_handle, &child_stdout }, .{ std_error_handle, &child_stderr } }) |row| {
            const parent_handle = GetStdHandle(row[0]);
            if (parent_handle != 0 and parent_handle != std.math.maxInt(usize) and
                DuplicateHandle(own, parent_handle, own, row[1], 0, 1, duplicate_same_access) == 0)
                return error.DuplicateFailed;
        }
    }
    var child_handles = [_]usize{ pair.child_read, pair.child_write, child_parent, 0, 0, 0, 0, 0 };
    var child_handle_count: usize = 3;
    for ([_]usize{ child_stdin, child_stdout, child_stderr }) |handle| {
        if (handle == 0) continue;
        child_handles[child_handle_count] = handle;
        child_handle_count += 1;
    }
    for ([_]usize{ child_service_stop, child_service_lease }) |handle| {
        if (handle == 0) continue;
        child_handles[child_handle_count] = handle;
        child_handle_count += 1;
    }

    var attribute_bytes: usize = 0;
    _ = InitializeProcThreadAttributeList(null, 1, 0, &attribute_bytes);
    if (attribute_bytes == 0 or attribute_bytes > 4096) return error.AttributeFailed;
    const words = try allocator.alloc(usize, std.math.divCeil(usize, attribute_bytes, @sizeOf(usize)) catch unreachable);
    defer allocator.free(words);
    const attributes: *anyopaque = @ptrCast(words.ptr);
    if (InitializeProcThreadAttributeList(attributes, 1, 0, &attribute_bytes) == 0) return error.AttributeFailed;
    defer DeleteProcThreadAttributeList(attributes);
    if (UpdateProcThreadAttribute(attributes, 0, proc_thread_attribute_handle_list, @ptrCast(&child_handles), child_handle_count * @sizeOf(usize), null, null) == 0) return error.AttributeFailed;

    const executable_w = std.unicode.wtf8ToWtf16LeAllocZ(allocator, executable) catch return error.InvalidCandidate;
    defer allocator.free(executable_w);
    const line = try commandLine(allocator, executable, pair.child_read, pair.child_write, child_parent, parent_pid, config, child_service_stop, child_service_lease);
    defer allocator.free(line);
    var startup = StartupInfoEx{ .startup = std.mem.zeroes(std.os.windows.STARTUPINFOW), .attributes = attributes };
    startup.startup.cb = @sizeOf(StartupInfoEx);
    if (child_handle_count > 3) {
        startup.startup.dwFlags |= startf_use_std_handles;
        startup.startup.hStdInput = @ptrFromInt(child_stdin);
        startup.startup.hStdOutput = @ptrFromInt(child_stdout);
        startup.startup.hStdError = @ptrFromInt(child_stderr);
    }
    var information: ProcessInformation = undefined;
    // A foreground successor must stay in the predecessor's console process
    // group so Ctrl+C/Ctrl+Break still reach it after COMMIT. A detached parent
    // retains CREATE_NO_WINDOW to avoid opening a new console at every swap.
    const creation_flags = extended_startupinfo_present |
        (if (GetConsoleWindow() == null) create_no_window else @as(u32, 0));
    if (CreateProcessW(executable_w.ptr, line.ptr, null, null, 1, creation_flags, null, null, &startup, &information) == 0)
        return error.ProcessCreateFailed;
    _ = CloseHandle(information.thread);
    pair.closeChildCopies();
    return .{ .process_handle = information.process, .pid = information.pid, .endpoint = pair.takeParent(identity, key), .identity = identity };
}

/// Inherited handles are meaningful only in the exact spawned child process.
/// The parent process HANDLE binds the private channel to its actual PID and
/// remains the post-COMMIT release witness for future IOCP reassociation.
pub const CandidateHandles = struct {
    read_handle: usize,
    write_handle: usize,
    parent_process: usize,

    pub fn deinit(self: *CandidateHandles) void {
        const read = self.read_handle;
        const write = self.write_handle;
        const parent = self.parent_process;
        self.* = .{ .read_handle = 0, .write_handle = 0, .parent_process = 0 };
        if (comptime builtin.os.tag == .windows) {
            if (read != 0) _ = CloseHandle(read);
            if (write != 0 and write != read) _ = CloseHandle(write);
            if (parent != 0 and parent != read and parent != write) _ = CloseHandle(parent);
        }
    }
};

pub const Incoming = struct {
    endpoint: control.Endpoint,
    parent_process: usize,
    parent_pid: u32,
    identity: control.Identity,

    pub fn deinit(self: *Incoming) void {
        self.endpoint.deinit();
        closeOwned(&self.parent_process);
    }
};

pub fn accept(handles: *CandidateHandles, parent_pid: u32, deadline: i64) Error!Incoming {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    if (handles.read_handle == 0 or handles.write_handle == 0 or handles.parent_process == 0 or
        handles.read_handle == handles.write_handle or handles.read_handle == handles.parent_process or handles.write_handle == handles.parent_process or
        GetFileType(handles.read_handle) != 3 or GetFileType(handles.write_handle) != 3 or
        parent_pid == 0 or parent_pid == GetCurrentProcessId() or GetProcessId(handles.parent_process) != parent_pid)
        return error.InvalidCandidate;
    // The allowlisted bootstrap handles must not escape into any later helper
    // process started by the adopted daemon.
    for ([_]usize{ handles.read_handle, handles.write_handle, handles.parent_process }) |handle| {
        if (SetHandleInformation(handle, 1, 0) == 0) return error.InvalidCandidate;
    }
    for ([_]u32{ std_input_handle, std_output_handle, std_error_handle }) |which| {
        const handle = GetStdHandle(which);
        if (handle != 0 and handle != std.math.maxInt(usize) and
            SetHandleInformation(handle, 1, 0) == 0)
            return error.InvalidCandidate;
    }
    const prelude = try control.receivePrelude(handles.read_handle, deadline);
    var endpoint = control.Endpoint{ .read_handle = handles.read_handle, .write_handle = handles.write_handle, .identity = prelude.identity, .key = prelude.key, .role = .child };
    handles.read_handle = 0;
    handles.write_handle = 0;
    errdefer endpoint.deinit();
    var hello = try endpoint.receive(deadline);
    defer hello.deinit();
    if (hello.kind != .hello or !std.mem.eql(u8, hello.bytes(), capability)) return error.InvalidCandidate;
    try endpoint.send(.capabilities, capability, deadline);
    const parent_process = handles.parent_process;
    handles.parent_process = 0;
    return .{ .endpoint = endpoint, .parent_process = parent_process, .parent_pid = parent_pid, .identity = prelude.identity };
}

test "Windows Helix candidate spawn keeps unverified process abortable" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.InvalidCandidate, launchUnverified(allocator, "cmd.exe", null, 1, false));
    var system_dir: [300]u16 = undefined;
    const length: usize = GetSystemDirectoryW(system_dir[0..].ptr, system_dir.len);
    if (length == 0 or length + 8 >= system_dir.len) return error.InvalidCandidate;
    const suffix = std.unicode.utf8ToUtf16LeStringLiteral("\\cmd.exe");
    @memcpy(system_dir[length..][0..suffix.len], suffix);
    const executable = try std.unicode.wtf16LeToWtf8Alloc(allocator, system_dir[0 .. length + suffix.len]);
    defer allocator.free(executable);
    var pinned = try openPinnedImage(allocator, executable);
    defer closeOwned(&pinned);
    const final_path = try pinnedImagePath(allocator, pinned);
    defer allocator.free(final_path);
    var ancestors = try pinImageAncestors(allocator, final_path);
    defer ancestors.deinit();
    try std.testing.expect(ancestors.handles.items.len >= 3);
    var final_image = try openPinnedFinalImage(allocator, final_path);
    defer closeOwned(&final_image);
    try std.testing.expectEqualDeep(try imageIdentity(pinned), try imageIdentity(final_image));
    // cmd.exe writes to stdout for an unknown private flag. Keep it off Zig's
    // test-runner protocol pipe; production launch preserves standard streams.
    // Exercise CreateProcessW with the resolved \\?\ path while its image is locked.
    var candidate = try launchUnverified(allocator, final_path, null, 7, false);
    try std.testing.expect(candidate.process_handle != 0 and candidate.pid != 0);
    try std.testing.expect(!candidate.committed);
    candidate.deinit();
    try std.testing.expectEqual(@as(usize, 0), candidate.process_handle);
    var incompatible = try launchUnverified(allocator, executable, null, 8, false);
    defer incompatible.deinit();
    if (incompatible.negotiate(platform.monotonicMillis() + 300)) |_| {
        return error.UnverifiedCandidateAccepted;
    } else |_| {}
}

test "Windows Helix same-image digest mismatch refuses launch" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var system_dir: [300]u16 = undefined;
    const length: usize = GetSystemDirectoryW(system_dir[0..].ptr, system_dir.len);
    if (length == 0 or length + 8 >= system_dir.len) return error.InvalidCandidate;
    const suffix = std.unicode.utf8ToUtf16LeStringLiteral("\\cmd.exe");
    @memcpy(system_dir[length..][0..suffix.len], suffix);
    const executable = try std.unicode.wtf16LeToWtf8Alloc(allocator, system_dir[0 .. length + suffix.len]);
    defer allocator.free(executable);
    var wrong_digest = try digestImageAtPath(allocator, executable);
    wrong_digest[0] ^= 0xff;
    try std.testing.expectError(error.ImageChanged, spawnSameImage(allocator, executable, null, 9, platform.monotonicMillis() + 300, wrong_digest));
}

test "Windows Helix pinned image refuses replacement until released" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const file = try tmp.dir.createFile(std.testing.io, "image.bin", .{});
    try file.writePositionalAll(std.testing.io, "original image", 0);
    file.close(std.testing.io);
    const path = try tmp.dir.realPathFileAlloc(std.testing.io, "image.bin", allocator);
    defer allocator.free(path);
    var pinned = try openPinnedImage(allocator, path);
    defer closeOwned(&pinned);
    const before = try digestPinnedImage(pinned);
    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("original image", &expected, .{});
    try std.testing.expectEqual(expected, before);
    const wide = try std.unicode.wtf8ToWtf16LeAllocZ(allocator, path);
    defer allocator.free(wide);
    const writable = CreateFileW(wide.ptr, generic_write, file_share_read, null, open_existing, file_attribute_normal, 0);
    if (writable != std.math.maxInt(usize)) {
        _ = CloseHandle(writable);
        return error.PinnedImageWritable;
    }
    if (tmp.dir.deleteFile(std.testing.io, "image.bin")) |_| {
        return error.PinnedImageReplaceable;
    } else |_| {}
    closeOwned(&pinned);
    try tmp.dir.deleteFile(std.testing.io, "image.bin");
    const replacement = try tmp.dir.createFile(std.testing.io, "image.bin", .{});
    try replacement.writePositionalAll(std.testing.io, "changed image", 0);
    replacement.close(std.testing.io);
    const after = try digestImageAtPath(allocator, path);
    try std.testing.expect(!std.mem.eql(u8, &before, &after));
}

test "Windows Helix nested image ancestors refuse rename until released" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "outer", .default_dir);
    try tmp.dir.createDir(std.testing.io, "outer/inner", .default_dir);
    const file = try tmp.dir.createFile(std.testing.io, "outer/inner/image.bin", .{});
    try file.writePositionalAll(std.testing.io, "pinned", 0);
    file.close(std.testing.io);
    const path = try tmp.dir.realPathFileAlloc(std.testing.io, "outer/inner/image.bin", allocator);
    defer allocator.free(path);
    var image = try openPinnedImage(allocator, path);
    defer closeOwned(&image);
    const final_path = try pinnedImagePath(allocator, image);
    defer allocator.free(final_path);
    var ancestors = try pinImageAncestors(allocator, final_path);
    defer ancestors.deinit();
    closeOwned(&image);
    if (tmp.dir.rename("outer", tmp.dir, "moved", std.testing.io)) |_| {
        return error.PinnedAncestorReplaceable;
    } else |err| switch (err) {
        error.FileBusy, error.AccessDenied => {},
        else => return err,
    }
    ancestors.deinit();
    var moved = false;
    for (0..6) |attempt| {
        tmp.dir.rename("outer", tmp.dir, "moved", std.testing.io) catch |err| switch (err) {
            error.FileBusy, error.AccessDenied => {
                if (attempt == 5) return err;
                try std.Io.sleep(std.testing.io, .fromMilliseconds(50), .awake);
                continue;
            },
            else => return err,
        };
        moved = true;
        break;
    }
    try std.testing.expect(moved);
}

test "Windows Helix candidate rejects a forged parent process identity" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var pair = try control.Pair.init();
    defer pair.deinit();
    var handles = CandidateHandles{ .read_handle = pair.child_read, .write_handle = pair.child_write, .parent_process = GetCurrentProcess() };
    handles.read_handle = 0;
    handles.write_handle = 0;
    try std.testing.expectError(error.InvalidCandidate, accept(&handles, GetCurrentProcessId(), platform.monotonicMillis() + 10));
}

test "Windows Helix candidate command line keeps paths and handles distinct" {
    const allocator = std.testing.allocator;
    const command = try commandLine(allocator, "C:\\Program Files\\Onyx\\onyx-server.exe", 12, 24, 36, 48, "C:\\Onyx Data\\config\\live.toml", 55, 66);
    defer allocator.free(command);
    const utf8 = try std.unicode.wtf16LeToWtf8Alloc(allocator, command);
    defer allocator.free(utf8);
    try std.testing.expectEqualStrings("\"C:\\Program Files\\Onyx\\onyx-server.exe\" \"--helix-windows-successor-v19\" \"12\" \"24\" \"36\" \"48\" \"C:\\Onyx Data\\config\\live.toml\" \"55\" \"66\"", utf8);
    try std.testing.expectError(error.InvalidCandidate, commandLine(allocator, "C:\\Onyx\\server.exe", 1, 2, 3, 4, "bad\x00path", 0, 0));
}

test "Windows Helix v19 rejects v18 capability before candidate transfer" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var pair = try control.Pair.init();
    defer pair.deinit();
    const identity: control.Identity = .{ .generation = 9, .upgrade_id = @splat(4) };
    const key: control.Key = @splat(7);
    var parent = Process{ .endpoint = pair.takeParent(identity, key), .identity = identity };
    defer parent.endpoint.deinit();
    var child = pair.takeChild(identity, key);
    defer child.deinit();
    const previous_capability = "onyx-native-helix-windows-v18;strict-capsules;hmac-control;indexed-sockets;encrypted-arena;account-wal-custody-v1;metrics-custody-v1;webhook-custody-v1;history-custody-v4;history-material-custody-v2;udp-custody-v1;media-custody-v1;active-webtransport-custody-v1;webpush-custody-v1;abuse-custody-v1;geo-custody-v1;mail-wal-custody-v2;policy-custody-v1;operator-custody-v1;account-flow-custody-v1;user-settings-custody-v1;memo-custody-v1;memo-inbox-custody-v1;ocsp-custody-v1;acme-custody-v1;tls-material-custody-v1;tls-replay-custody-v1;wasm-custody-v1;inert-ready;commit-ack;release-before-iocp";
    const Runner = struct {
        endpoint: *control.Endpoint,
        failure: ?anyerror = null,
        fn run(self: *@This()) void {
            const deadline = platform.monotonicMillis() + 3000;
            _ = control.receivePrelude(self.endpoint.read_handle, deadline) catch |err| {
                self.failure = err;
                return;
            };
            var hello = self.endpoint.receive(deadline) catch |err| {
                self.failure = err;
                return;
            };
            defer hello.deinit();
            if (hello.kind != .hello or !std.mem.eql(u8, hello.bytes(), capability)) {
                self.failure = error.InvalidCandidate;
                return;
            }
            self.endpoint.send(.capabilities, previous_capability, deadline) catch |err| {
                self.failure = err;
            };
        }
    };
    var runner = Runner{ .endpoint = &child };
    const thread = try std.Thread.spawn(.{}, Runner.run, .{&runner});
    const outcome = parent.negotiate(platform.monotonicMillis() + 3000);
    thread.join();
    if (runner.failure) |err| return err;
    try std.testing.expectError(error.InvalidCandidate, outcome);
}
