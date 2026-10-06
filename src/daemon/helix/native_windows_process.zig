// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Windows native Helix candidate launch and capability negotiation. No live
//! socket, arena key, or state handle is sent before the actual child image
//! answers the exact capability challenge on its private control channel.
const std = @import("std");
const builtin = @import("builtin");
const platform = @import("../../substrate/platform.zig");
const control = @import("native_windows_control.zig");

pub const candidate_arg = "--helix-windows-successor-v16";
pub const capability = "onyx-native-helix-windows-v16;strict-capsules;hmac-control;indexed-sockets;encrypted-arena;account-wal-custody-v1;metrics-custody-v1;webhook-custody-v1;history-custody-v2;udp-custody-v1;media-custody-v1;active-webtransport-custody-v1;webpush-custody-v1;abuse-custody-v1;geo-custody-v1;mail-wal-custody-v2;policy-custody-v1;operator-custody-v1;account-flow-custody-v1;user-settings-custody-v1;memo-custody-v1;ocsp-custody-v1;acme-custody-v1;tls-material-custody-v1;wasm-custody-v1;inert-ready;commit-ack;release-before-iocp";
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
    defer closeOwned(&child_stdin);
    defer closeOwned(&child_stdout);
    defer closeOwned(&child_stderr);
    if (inherit_standard_streams) {
        inline for (.{ .{ std_input_handle, &child_stdin }, .{ std_output_handle, &child_stdout }, .{ std_error_handle, &child_stderr } }) |row| {
            const parent_handle = GetStdHandle(row[0]);
            if (parent_handle != 0 and parent_handle != std.math.maxInt(usize) and
                DuplicateHandle(own, parent_handle, own, row[1], 0, 1, duplicate_same_access) == 0)
                return error.DuplicateFailed;
        }
    }
    var child_handles = [_]usize{ pair.child_read, pair.child_write, child_parent, 0, 0, 0 };
    var child_handle_count: usize = 3;
    for ([_]usize{ child_stdin, child_stdout, child_stderr }) |handle| {
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
    const line = try commandLine(allocator, executable, pair.child_read, pair.child_write, child_parent, parent_pid, config);
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
    // cmd.exe writes to stdout for an unknown private flag. Keep it off Zig's
    // test-runner protocol pipe; production launch preserves standard streams.
    var candidate = try launchUnverified(allocator, executable, null, 7, false);
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
    try std.testing.expectEqualStrings("\"C:\\Program Files\\Onyx\\onyx-server.exe\" \"--helix-windows-successor-v16\" \"12\" \"24\" \"36\" \"48\" \"C:\\Onyx Data\\config\\live.toml\"", utf8);
    try std.testing.expectError(error.InvalidCandidate, commandLine(allocator, "C:\\Onyx\\server.exe", 1, 2, 3, 4, "bad\x00path"));
}

test "Windows Helix rejects previous custody capability during candidate negotiation" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var pair = try control.Pair.init();
    defer pair.deinit();
    const identity: control.Identity = .{ .generation = 9, .upgrade_id = @splat(4) };
    const key: control.Key = @splat(7);
    var parent = Process{ .endpoint = pair.takeParent(identity, key), .identity = identity };
    defer parent.endpoint.deinit();
    var child = pair.takeChild(identity, key);
    defer child.deinit();
    const previous_capability = "onyx-native-helix-windows-v15;strict-capsules;hmac-control;indexed-sockets;encrypted-arena;account-wal-custody-v1;metrics-custody-v1;webhook-custody-v1;history-custody-v2;udp-custody-v1;webpush-custody-v1;abuse-custody-v1;geo-custody-v1;mail-wal-custody-v2;policy-custody-v1;operator-custody-v1;account-flow-custody-v1;user-settings-custody-v1;memo-custody-v1;ocsp-custody-v1;acme-custody-v1;tls-material-custody-v1;wasm-custody-v1;inert-ready;commit-ack;release-before-iocp";
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
