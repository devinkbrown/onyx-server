// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Windows native Helix candidate launch and capability negotiation. No live
//! socket, arena key, or state handle is sent before the actual child image
//! answers the exact capability challenge on its private control channel.
const std = @import("std");
const builtin = @import("builtin");
const platform = @import("../../substrate/platform.zig");
const control = @import("native_windows_control.zig");

pub const candidate_arg = "--helix-windows-successor-v1";
pub const capability = "onyx-native-helix-windows-v1;strict-capsules;hmac-control;indexed-sockets;encrypted-arena;inert-ready;release-before-iocp";
const process_query_limited_information: u32 = 0x1000;
const synchronize: u32 = 0x0010_0000;
const extended_startupinfo_present: u32 = 0x0008_0000;
const create_no_window: u32 = 0x0800_0000;
const proc_thread_attribute_handle_list: usize = 0x0002_0002;
const infinite: u32 = 0xffff_ffff;

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

pub const Error = control.Error || std.mem.Allocator.Error || error{
    InvalidCandidate,
    RandomSourceFailed,
    AttributeFailed,
    ProcessCreateFailed,
};

fn closeOwned(handle: *usize) void {
    if (comptime builtin.os.tag == .windows) {
        if (handle.* != 0) _ = CloseHandle(handle.*);
    }
    handle.* = 0;
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

fn commandLine(allocator: std.mem.Allocator, executable: []const u8, child_read: usize, child_write: usize, parent_process: usize, parent_pid: u32, config: ?[]const u8) Error![:0]u16 {
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
    pub fn deinit(self: *Process) void {
        if (comptime builtin.os.tag == .windows) {
            if (self.process_handle != 0) {
                if (!self.committed) {
                    _ = TerminateProcess(self.process_handle, 125);
                    _ = WaitForSingleObject(self.process_handle, infinite);
                }
                closeOwned(&self.process_handle);
            }
        }
        self.endpoint.deinit();
        self.pid = 0;
    }

    /// The source executable must be an absolute path. CreateProcessW loads
    /// that path; capability checking is against the actual running image.
    pub fn spawn(allocator: std.mem.Allocator, executable: []const u8, config: ?[]const u8, generation: u64, deadline: i64) Error!Process {
        var candidate = try launchUnverified(allocator, executable, config, generation);
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

fn launchUnverified(allocator: std.mem.Allocator, executable: []const u8, config: ?[]const u8, generation: u64) Error!Process {
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
    const child_handles = [_]usize{ pair.child_read, pair.child_write, child_parent };

    var attribute_bytes: usize = 0;
    _ = InitializeProcThreadAttributeList(null, 1, 0, &attribute_bytes);
    if (attribute_bytes == 0 or attribute_bytes > 4096) return error.AttributeFailed;
    const words = try allocator.alloc(usize, std.math.divCeil(usize, attribute_bytes, @sizeOf(usize)) catch unreachable);
    defer allocator.free(words);
    const attributes: *anyopaque = @ptrCast(words.ptr);
    if (InitializeProcThreadAttributeList(attributes, 1, 0, &attribute_bytes) == 0) return error.AttributeFailed;
    defer DeleteProcThreadAttributeList(attributes);
    if (UpdateProcThreadAttribute(attributes, 0, proc_thread_attribute_handle_list, @ptrCast(@constCast(&child_handles)), @sizeOf(@TypeOf(child_handles)), null, null) == 0) return error.AttributeFailed;

    const executable_w = std.unicode.wtf8ToWtf16LeAllocZ(allocator, executable) catch return error.InvalidCandidate;
    defer allocator.free(executable_w);
    const line = try commandLine(allocator, executable, pair.child_read, pair.child_write, child_parent, parent_pid, config);
    defer allocator.free(line);
    var startup = StartupInfoEx{ .startup = std.mem.zeroes(std.os.windows.STARTUPINFOW), .attributes = attributes };
    startup.startup.cb = @sizeOf(StartupInfoEx);
    var information: ProcessInformation = undefined;
    if (CreateProcessW(executable_w.ptr, line.ptr, null, null, 1, extended_startupinfo_present | create_no_window, null, null, &startup, &information) == 0)
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
    try std.testing.expectError(error.InvalidCandidate, launchUnverified(allocator, "cmd.exe", null, 1));
    var system_dir: [300]u16 = undefined;
    const length: usize = GetSystemDirectoryW(system_dir[0..].ptr, system_dir.len);
    if (length == 0 or length + 8 >= system_dir.len) return error.InvalidCandidate;
    const suffix = std.unicode.utf8ToUtf16LeStringLiteral("\\cmd.exe");
    @memcpy(system_dir[length..][0..suffix.len], suffix);
    const executable = try std.unicode.wtf16LeToWtf8Alloc(allocator, system_dir[0 .. length + suffix.len]);
    defer allocator.free(executable);
    var candidate = try launchUnverified(allocator, executable, null, 7);
    try std.testing.expect(candidate.process_handle != 0 and candidate.pid != 0);
    try std.testing.expect(!candidate.committed);
    candidate.deinit();
    try std.testing.expectEqual(@as(usize, 0), candidate.process_handle);
    if (Process.spawn(allocator, executable, null, 8, platform.monotonicMillis() + 300)) |unexpected| {
        var live = unexpected;
        live.deinit();
        return error.UnverifiedCandidateAccepted;
    } else |_| {}
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
    const command = try commandLine(allocator, "C:\\Program Files\\Onyx\\onyx-server.exe", 12, 24, 36, 48, "C:\\Onyx Data\\config\\live.toml");
    defer allocator.free(command);
    const utf8 = try std.unicode.wtf16LeToWtf8Alloc(allocator, command);
    defer allocator.free(utf8);
    try std.testing.expectEqualStrings("\"C:\\Program Files\\Onyx\\onyx-server.exe\" \"--helix-windows-successor-v1\" \"12\" \"24\" \"36\" \"48\" \"C:\\Onyx Data\\config\\live.toml\"", utf8);
    try std.testing.expectError(error.InvalidCandidate, commandLine(allocator, "C:\\Onyx\\server.exe", 1, 2, 3, 4, "bad\x00path"));
}
