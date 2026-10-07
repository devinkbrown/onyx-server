// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Stable Windows Service Control Manager host for the process-swapping daemon.
//! The SCM connection stays in this process while Helix replaces its worker.
//! An inherited manual-reset event requests cooperative stop; an inherited
//! pipe writer is the live-generation lease. Helix must explicitly carry both.
const std = @import("std");
const builtin = @import("builtin");
const console_stop = @import("windows_console_stop.zig");

pub const host_arg = "--windows-service";
pub const console_host_arg = "--windows-service-console-test";
pub const worker_arg = "--windows-service-worker-v1";

pub fn isServiceArg(first: []const u8) bool {
    return std.mem.eql(u8, first, host_arg);
}

pub fn isWorkerArg(first: []const u8) bool {
    return std.mem.eql(u8, first, worker_arg);
}

pub fn isConsoleHostArg(first: []const u8) bool {
    return std.mem.eql(u8, first, console_host_arg);
}

const service_name = [_:0]u16{ 'o', 'n', 'y', 'x', '-', 's', 'e', 'r', 'v', 'e', 'r' };
const service_win32_own_process: u32 = 0x10;
const service_stopped: u32 = 1;
const service_start_pending: u32 = 2;
const service_stop_pending: u32 = 3;
const service_running: u32 = 4;
const service_accept_stop: u32 = 1;
const service_accept_shutdown: u32 = 4;
const service_control_stop: u32 = 1;
const service_control_interrogate: u32 = 4;
const service_control_shutdown: u32 = 5;
const error_service_cannot_accept_ctrl: u32 = 1061;
const error_call_not_implemented: u32 = 120;
const error_broken_pipe: u32 = 109;
const wait_object_0: u32 = 0;
const wait_timeout: u32 = 258;
const infinite: u32 = 0xffff_ffff;
const handle_flag_inherit: u32 = 1;
const file_type_pipe: u32 = 3;
const duplicate_same_access: u32 = 2;
const std_error_handle: u32 = 0xffff_fff4;
const std_output_handle: u32 = 0xffff_fff5;
const std_input_handle: u32 = 0xffff_fff6;
const startf_use_std_handles: u32 = 0x0000_0100;
const proc_thread_attribute_handle_list: usize = 0x0002_0002;
const extended_startupinfo_present: u32 = 0x0008_0000;
const create_suspended: u32 = 0x0000_0004;
const create_no_window: u32 = 0x0800_0000;
const job_extended_limit_class: u32 = 9;
const job_limit_kill_on_close: u32 = 0x2000;

const ServiceStatus = extern struct {
    service_type: u32,
    current_state: u32,
    controls_accepted: u32,
    win32_exit_code: u32,
    service_specific_exit_code: u32,
    check_point: u32,
    wait_hint: u32,
};

const ServiceTableEntry = extern struct {
    name: ?[*:0]const u16,
    main: ?*const fn (u32, ?[*]const ?[*:0]u16) callconv(.winapi) void,
};

const SecurityAttributes = extern struct {
    length: u32,
    security_descriptor: ?*anyopaque,
    inherit_handle: i32,
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

const JobBasicLimit = extern struct {
    per_process_user_time: i64,
    per_job_user_time: i64,
    limit_flags: u32,
    minimum_working_set: usize,
    maximum_working_set: usize,
    active_process_limit: u32,
    affinity: usize,
    priority_class: u32,
    scheduling_class: u32,
};

const IoCounters = extern struct {
    read_operation: u64,
    write_operation: u64,
    other_operation: u64,
    read_transfer: u64,
    write_transfer: u64,
    other_transfer: u64,
};

const JobExtendedLimit = extern struct {
    basic: JobBasicLimit,
    io: IoCounters,
    process_memory: usize,
    job_memory: usize,
    peak_process: usize,
    peak_job: usize,
};

comptime {
    if (builtin.os.tag == .windows and @sizeOf(usize) == 8 and
        (@sizeOf(ServiceStatus) != 28 or @sizeOf(ProcessInformation) != 24 or
            @sizeOf(JobExtendedLimit) != 144))
        @compileError("Windows SCM or job ABI mismatch");
}

extern "advapi32" fn StartServiceCtrlDispatcherW(table: [*]const ServiceTableEntry) callconv(.winapi) i32;
extern "advapi32" fn RegisterServiceCtrlHandlerExW(name: [*:0]const u16, handler: *const fn (u32, u32, ?*anyopaque, ?*anyopaque) callconv(.winapi) u32, context: ?*anyopaque) callconv(.winapi) usize;
extern "advapi32" fn SetServiceStatus(handle: usize, status: *const ServiceStatus) callconv(.winapi) i32;
extern "kernel32" fn CreateEventW(attributes: ?*SecurityAttributes, manual_reset: i32, initial_state: i32, name: ?[*:0]const u16) callconv(.winapi) usize;
extern "kernel32" fn SetEvent(handle: usize) callconv(.winapi) i32;
extern "kernel32" fn CreatePipe(read: *usize, write: *usize, attributes: *SecurityAttributes, size: u32) callconv(.winapi) i32;
extern "kernel32" fn SetHandleInformation(handle: usize, mask: u32, flags: u32) callconv(.winapi) i32;
extern "kernel32" fn GetHandleInformation(handle: usize, flags: *u32) callconv(.winapi) i32;
extern "kernel32" fn GetFileType(handle: usize) callconv(.winapi) u32;
extern "kernel32" fn GetCurrentProcess() callconv(.winapi) usize;
extern "kernel32" fn GetStdHandle(which: u32) callconv(.winapi) usize;
extern "kernel32" fn DuplicateHandle(source_process: usize, source_handle: usize, target_process: usize, target_handle: *usize, access: u32, inherit: i32, options: u32) callconv(.winapi) i32;
extern "kernel32" fn InitializeProcThreadAttributeList(list: ?*anyopaque, count: u32, flags: u32, bytes: *usize) callconv(.winapi) i32;
extern "kernel32" fn UpdateProcThreadAttribute(list: *anyopaque, flags: u32, attribute: usize, value: *anyopaque, bytes: usize, previous: ?*anyopaque, returned: ?*usize) callconv(.winapi) i32;
extern "kernel32" fn DeleteProcThreadAttributeList(list: *anyopaque) callconv(.winapi) void;
extern "kernel32" fn CreateProcessW(application: [*:0]const u16, command_line: [*:0]u16, process_attributes: ?*anyopaque, thread_attributes: ?*anyopaque, inherit: i32, creation_flags: u32, environment: ?*anyopaque, cwd: ?[*:0]const u16, startup: *StartupInfoEx, information: *ProcessInformation) callconv(.winapi) i32;
extern "kernel32" fn ResumeThread(thread: usize) callconv(.winapi) u32;
extern "kernel32" fn TerminateProcess(process: usize, code: u32) callconv(.winapi) i32;
extern "kernel32" fn CreateJobObjectW(attributes: ?*SecurityAttributes, name: ?[*:0]const u16) callconv(.winapi) usize;
extern "kernel32" fn SetInformationJobObject(job: usize, class: u32, info: *const JobExtendedLimit, length: u32) callconv(.winapi) i32;
extern "kernel32" fn AssignProcessToJobObject(job: usize, process: usize) callconv(.winapi) i32;
extern "kernel32" fn TerminateJobObject(job: usize, code: u32) callconv(.winapi) i32;
extern "kernel32" fn WaitForSingleObject(handle: usize, ms: u32) callconv(.winapi) u32;
extern "kernel32" fn WaitForMultipleObjects(count: u32, handles: [*]const usize, wait_all: i32, ms: u32) callconv(.winapi) u32;
extern "kernel32" fn ReadFile(handle: usize, buffer: [*]u8, size: u32, read: *u32, overlapped: ?*anyopaque) callconv(.winapi) i32;
extern "kernel32" fn WriteFile(handle: usize, buffer: [*]const u8, size: u32, written: *u32, overlapped: ?*anyopaque) callconv(.winapi) i32;
extern "kernel32" fn GetLastError() callconv(.winapi) u32;
extern "kernel32" fn CloseHandle(handle: usize) callconv(.winapi) i32;

fn closeOwned(handle: *usize) void {
    if (handle.* != 0) _ = CloseHandle(handle.*);
    handle.* = 0;
}

fn canonicalHandle(text: []const u8) !usize {
    if (text.len == 0 or (text.len > 1 and text[0] == '0')) return error.InvalidWorkerHandle;
    for (text) |digit| if (digit < '0' or digit > '9') return error.InvalidWorkerHandle;
    const value = std.fmt.parseInt(usize, text, 10) catch return error.InvalidWorkerHandle;
    if (value == 0 or value == std.math.maxInt(usize)) return error.InvalidWorkerHandle;
    return value;
}

pub const HelixHandles = struct {
    stop_event: usize,
    lease_write: usize,
};

var active_worker: std.atomic.Value(usize) = .init(0);

/// Only call this while the daemon's run loop owns the activated WorkerHandles.
/// Its main frame outlives the Helix spawn callback and deactivates after join.
pub fn activeForHelix() ?HelixHandles {
    const address = active_worker.load(.acquire);
    if (address == 0) return null;
    const owner: *const WorkerHandles = @ptrFromInt(address);
    return .{ .stop_event = owner.stop_event, .lease_write = owner.lease_write };
}

/// One worker generation owns these inherited handles. A Helix candidate gets
/// stop and lease, never the cold-start ready event. That event belongs only to
/// the first worker and is signaled after all listeners have been prepared.
pub const WorkerHandles = struct {
    stop_event: usize,
    lease_write: usize,
    ready_event: usize = 0,
    active: bool = false,

    pub fn parse(stop_text: []const u8, lease_text: []const u8, ready_text: ?[]const u8) !WorkerHandles {
        if (comptime builtin.os.tag != .windows) return error.Unsupported;
        return init(try canonicalHandle(stop_text), try canonicalHandle(lease_text), if (ready_text) |text| try canonicalHandle(text) else 0);
    }

    /// The caller passes inherited handles and transfers their ownership here.
    pub fn init(stop_event: usize, lease_write: usize, ready_event: usize) !WorkerHandles {
        if (comptime builtin.os.tag != .windows) return error.Unsupported;
        if (stop_event == 0 or lease_write == 0 or stop_event == lease_write or
            (ready_event != 0 and (ready_event == stop_event or ready_event == lease_write)))
            return error.InvalidWorkerHandle;
        var flags: u32 = 0;
        if (GetHandleInformation(stop_event, &flags) == 0 or
            GetHandleInformation(lease_write, &flags) == 0 or
            (ready_event != 0 and GetHandleInformation(ready_event, &flags) == 0) or
            GetFileType(lease_write) != file_type_pipe)
            return error.InvalidWorkerHandle;
        const stop_state = WaitForSingleObject(stop_event, 0);
        if (stop_state != wait_object_0 and stop_state != wait_timeout) return error.InvalidWorkerHandle;
        if (ready_event != 0) {
            const ready_state = WaitForSingleObject(ready_event, 0);
            if (ready_state != wait_object_0 and ready_state != wait_timeout) return error.InvalidWorkerHandle;
        }
        return .{ .stop_event = stop_event, .lease_write = lease_write, .ready_event = ready_event };
    }

    pub fn activate(self: *WorkerHandles) !void {
        if (self.active or active_worker.cmpxchgStrong(0, @intFromPtr(self), .acq_rel, .acquire) != null)
            return error.AlreadyActive;
        self.active = true;
    }

    pub fn signalReady(self: *WorkerHandles) !void {
        if (self.ready_event == 0) return;
        if (SetEvent(self.ready_event) == 0) return error.ReadySignalFailed;
        closeOwned(&self.ready_event);
    }

    /// Write this only after graceful cleanup; EOF without a final byte is a
    /// crash or lost lease and is reported to SCM as a service failure.
    pub fn reportExit(self: *WorkerHandles, success: bool) !void {
        const byte = [_]u8{if (success) 0 else 1};
        var written: u32 = 0;
        if (WriteFile(self.lease_write, &byte, 1, &written, null) == 0 or written != 1)
            return error.ExitReportFailed;
    }

    pub fn deinit(self: *WorkerHandles) void {
        if (self.active) {
            _ = active_worker.cmpxchgStrong(@intFromPtr(self), 0, .acq_rel, .acquire);
            self.active = false;
        }
        closeOwned(&self.ready_event);
        closeOwned(&self.lease_write);
        closeOwned(&self.stop_event);
    }
};

/// The manual-reset stop event survives every Helix generation. Installation
/// follows COMMIT and full server setup, so a signaled event during handoff is
/// observed by the new serving generation as soon as it starts its run loop.
pub const StopGuard = struct {
    stop_event: usize,
    hook: console_stop.StopHook,
    cancel_event: usize = 0,
    thread: ?std.Thread = null,

    pub fn install(self: *StopGuard) !void {
        if (comptime builtin.os.tag != .windows) return error.Unsupported;
        if (self.thread != null or self.stop_event == 0) return error.AlreadyInstalled;
        self.cancel_event = CreateEventW(null, 1, 0, null);
        if (self.cancel_event == 0) return error.EventCreateFailed;
        errdefer closeOwned(&self.cancel_event);
        self.thread = try std.Thread.spawn(.{}, waitForStop, .{self});
    }

    fn waitForStop(self: *StopGuard) void {
        const handles = [_]usize{ self.cancel_event, self.stop_event };
        if (WaitForMultipleObjects(2, &handles, 0, infinite) == wait_object_0 + 1)
            self.hook.request(self.hook.context);
    }

    pub fn deinit(self: *StopGuard) void {
        if (self.thread) |thread| {
            _ = SetEvent(self.cancel_event);
            thread.join();
            self.thread = null;
        }
        closeOwned(&self.cancel_event);
    }
};

/// This host-side watchdog bounds STOP_PENDING without inventing checkpoint
/// progress. The daemon gets 120 seconds for cooperative worker cleanup. If it
/// does not release the lease, the host terminates the contained process tree.
const StopWatch = struct {
    stop_event: usize,
    job: usize,
    cancel_event: usize = 0,
    thread: ?std.Thread = null,
    timed_out: std.atomic.Value(bool) = .init(false),

    fn install(self: *StopWatch) !void {
        self.cancel_event = CreateEventW(null, 1, 0, null);
        if (self.cancel_event == 0) return error.EventCreateFailed;
        errdefer closeOwned(&self.cancel_event);
        self.thread = try std.Thread.spawn(.{}, watch, .{self});
    }

    fn watch(self: *StopWatch) void {
        const events = [_]usize{ self.cancel_event, self.stop_event };
        if (WaitForMultipleObjects(2, &events, 0, infinite) != wait_object_0 + 1) return;
        if (WaitForSingleObject(self.cancel_event, 120_000) == wait_timeout) {
            self.timed_out.store(true, .release);
            _ = TerminateJobObject(self.job, 1);
        }
    }

    fn deinit(self: *StopWatch) void {
        if (self.thread) |thread| {
            _ = SetEvent(self.cancel_event);
            thread.join();
            self.thread = null;
        }
        closeOwned(&self.cancel_event);
    }
};

const Host = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    config_path: []const u8,
    status_handle: usize = 0,
    stop_event: usize = 0,
    status_lock: std.atomic.Mutex = .unlocked,
    status_state: std.atomic.Value(u32) = .init(service_stopped),

    fn publish(self: *Host, state: u32, exit_code: u32, checkpoint: u32, wait_hint: u32) void {
        while (!self.status_lock.tryLock()) std.Thread.yield() catch {};
        defer self.status_lock.unlock();
        if (self.status_handle == 0 or self.status_state.load(.acquire) == service_stopped and state != service_start_pending) return;
        const status = ServiceStatus{
            .service_type = service_win32_own_process,
            .current_state = state,
            .controls_accepted = if (state == service_running) service_accept_stop | service_accept_shutdown else 0,
            .win32_exit_code = exit_code,
            .service_specific_exit_code = 0,
            .check_point = checkpoint,
            .wait_hint = wait_hint,
        };
        if (SetServiceStatus(self.status_handle, &status) != 0) self.status_state.store(state, .release);
    }

    fn supervise(self: *Host) !bool {
        if (self.stop_event == 0) {
            self.stop_event = CreateEventW(null, 1, 0, null);
            if (self.stop_event == 0) return error.EventCreateFailed;
        }
        const ready_event = CreateEventW(null, 1, 0, null);
        if (ready_event == 0) return error.EventCreateFailed;
        defer _ = CloseHandle(ready_event);

        var pipe_attributes = SecurityAttributes{ .length = @sizeOf(SecurityAttributes), .security_descriptor = null, .inherit_handle = 1 };
        var lease_read: usize = 0;
        var lease_write: usize = 0;
        if (CreatePipe(&lease_read, &lease_write, &pipe_attributes, 0) == 0) return error.PipeCreateFailed;
        defer closeOwned(&lease_read);
        defer closeOwned(&lease_write);
        if (SetHandleInformation(lease_read, handle_flag_inherit, 0) == 0) return error.HandleSetupFailed;

        var child_stop: usize = 0;
        var child_ready: usize = 0;
        const own = GetCurrentProcess();
        if (DuplicateHandle(own, self.stop_event, own, &child_stop, 0, 1, duplicate_same_access) == 0)
            return error.HandleSetupFailed;
        defer closeOwned(&child_stop);
        if (DuplicateHandle(own, ready_event, own, &child_ready, 0, 1, duplicate_same_access) == 0)
            return error.HandleSetupFailed;
        defer closeOwned(&child_ready);

        const job = CreateJobObjectW(null, null);
        if (job == 0) return error.JobCreateFailed;
        defer _ = CloseHandle(job);
        var limits = std.mem.zeroes(JobExtendedLimit);
        limits.basic.limit_flags = job_limit_kill_on_close;
        if (SetInformationJobObject(job, job_extended_limit_class, &limits, @sizeOf(JobExtendedLimit)) == 0)
            return error.JobSetupFailed;

        const executable = try std.process.executablePathAlloc(self.io, self.allocator);
        defer self.allocator.free(executable);
        const process = try spawnWorker(self.allocator, executable, self.config_path, child_stop, lease_write, child_ready, job);
        defer _ = CloseHandle(process);
        // The host must not retain the writer; EOF is the exact end of all
        // generations. The child received the writer before it was resumed.
        closeOwned(&lease_write);
        closeOwned(&child_stop);
        closeOwned(&child_ready);

        const start_handles = [_]usize{ ready_event, process };
        switch (WaitForMultipleObjects(2, &start_handles, 0, 120_000)) {
            wait_object_0 => {},
            wait_object_0 + 1 => return error.WorkerExitedBeforeReady,
            wait_timeout => return error.WorkerReadyTimeout,
            else => return error.WorkerReadyWaitFailed,
        }
        self.publish(service_running, 0, 0, 0);
        var stop_watch = StopWatch{ .stop_event = self.stop_event, .job = job };
        try stop_watch.install();
        defer stop_watch.deinit();
        var final_status: ?u8 = null;
        while (true) {
            var byte: [1]u8 = undefined;
            var got: u32 = 0;
            if (ReadFile(lease_read, &byte, 1, &got, null) == 0) {
                if (GetLastError() != error_broken_pipe) return error.LeaseReadFailed;
                break;
            }
            if (got == 0) break;
            if (final_status != null or byte[0] > 1) return error.InvalidExitReport;
            final_status = byte[0];
        }
        return final_status == 0 and !stop_watch.timed_out.load(.acquire);
    }
};

var active_host: std.atomic.Value(usize) = .init(0);

fn onControl(code: u32, _: u32, _: ?*anyopaque, raw: ?*anyopaque) callconv(.winapi) u32 {
    const host: *Host = @ptrCast(@alignCast(raw orelse return error_service_cannot_accept_ctrl));
    switch (code) {
        service_control_stop, service_control_shutdown => {
            const state = host.status_state.load(.acquire);
            if (state != service_running and state != service_stop_pending)
                return error_service_cannot_accept_ctrl;
            if (host.stop_event == 0 or SetEvent(host.stop_event) == 0) return error_service_cannot_accept_ctrl;
            host.publish(service_stop_pending, 0, 1, 130_000);
            return 0;
        },
        service_control_interrogate => return 0,
        else => return error_call_not_implemented,
    }
}

fn serviceMain(_: u32, _: ?[*]const ?[*:0]u16) callconv(.winapi) void {
    const address = active_host.load(.acquire);
    if (address == 0) return;
    const host: *Host = @ptrFromInt(address);
    host.status_handle = RegisterServiceCtrlHandlerExW(&service_name, onControl, host);
    if (host.status_handle == 0) return;
    host.publish(service_start_pending, 0, 1, 120_000);
    const graceful = host.supervise() catch |err| blk: {
        std.debug.print("onyx-server: Windows service host failed ({s})\n", .{@errorName(err)});
        break :blk false;
    };
    host.publish(service_stopped, if (graceful) 0 else 1, 0, 0);
}

/// Run from `--windows-service <absolute-config>` only. The SCM owns this
/// process; a foreground invocation fails when it cannot connect to SCM.
pub fn runHost(allocator: std.mem.Allocator, io: std.Io, config_path: []const u8) !void {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    if (config_path.len == 0 or !std.fs.path.isAbsolute(config_path) or
        std.mem.indexOfAny(u8, config_path, "\x00\r\n") != null)
        return error.InvalidConfigPath;
    var host = Host{ .allocator = allocator, .io = io, .config_path = config_path };
    if (active_host.cmpxchgStrong(0, @intFromPtr(&host), .acq_rel, .acquire) != null)
        return error.AlreadyRunning;
    defer {
        active_host.store(0, .release);
        closeOwned(&host.stop_event);
    }
    const table = [_]ServiceTableEntry{
        .{ .name = &service_name, .main = serviceMain },
        .{ .name = null, .main = null },
    };
    if (StartServiceCtrlDispatcherW(&table) == 0) return error.ServiceDispatcherFailed;
}

/// Non-SCM integration fixture. It uses the same job, worker, stop event and
/// lease as the production host, mapping Ctrl+C/Ctrl+Break to cooperative stop.
/// It never reports a service status and never substitutes for runHost.
pub fn runConsoleHost(allocator: std.mem.Allocator, io: std.Io, config_path: []const u8) !void {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    if (config_path.len == 0 or !std.fs.path.isAbsolute(config_path) or
        std.mem.indexOfAny(u8, config_path, "\x00\r\n") != null)
        return error.InvalidConfigPath;
    var host = Host{ .allocator = allocator, .io = io, .config_path = config_path };
    host.stop_event = CreateEventW(null, 1, 0, null);
    if (host.stop_event == 0) return error.EventCreateFailed;
    defer closeOwned(&host.stop_event);
    const StopContext = struct {
        fn request(raw: *anyopaque) void {
            const owner: *Host = @ptrCast(@alignCast(raw));
            _ = SetEvent(owner.stop_event);
        }
    };
    var guard = console_stop.Guard{ .hook = .{ .context = &host, .request = StopContext.request } };
    try guard.install();
    defer guard.deinit();
    if (!try host.supervise()) return error.WorkerFailed;
}

fn appendQuoted(allocator: std.mem.Allocator, output: *std.ArrayList(u8), arg: []const u8) !void {
    if (std.mem.indexOfScalar(u8, arg, 0) != null) return error.InvalidArgument;
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

fn workerCommandLine(allocator: std.mem.Allocator, executable: []const u8, config: []const u8, stop: usize, lease: usize, ready: usize) ![:0]u16 {
    var line: std.ArrayList(u8) = .empty;
    defer line.deinit(allocator);
    try appendQuoted(allocator, &line, executable);
    try line.append(allocator, ' ');
    try appendQuoted(allocator, &line, worker_arg);
    inline for (.{ stop, lease, ready }) |handle| {
        var buffer: [32]u8 = undefined;
        const decimal = try std.fmt.bufPrint(&buffer, "{d}", .{handle});
        try line.append(allocator, ' ');
        try appendQuoted(allocator, &line, decimal);
    }
    try line.append(allocator, ' ');
    try appendQuoted(allocator, &line, config);
    return try std.unicode.wtf8ToWtf16LeAllocZ(allocator, line.items);
}

fn spawnWorker(allocator: std.mem.Allocator, executable: []const u8, config: []const u8, stop: usize, lease: usize, ready: usize, job: usize) !usize {
    var child_stdin: usize = 0;
    var child_stdout: usize = 0;
    var child_stderr: usize = 0;
    defer closeOwned(&child_stdin);
    defer closeOwned(&child_stdout);
    defer closeOwned(&child_stderr);
    const own = GetCurrentProcess();
    inline for (.{ .{ std_input_handle, &child_stdin }, .{ std_output_handle, &child_stdout }, .{ std_error_handle, &child_stderr } }) |row| {
        const source = GetStdHandle(row[0]);
        if (source != 0 and source != std.math.maxInt(usize) and
            DuplicateHandle(own, source, own, row[1], 0, 1, duplicate_same_access) == 0)
            return error.StandardHandleFailed;
    }
    var handles = [_]usize{ stop, lease, ready, 0, 0, 0 };
    var handle_count: usize = 3;
    for ([_]usize{ child_stdin, child_stdout, child_stderr }) |handle| {
        if (handle == 0) continue;
        handles[handle_count] = handle;
        handle_count += 1;
    }
    var attribute_bytes: usize = 0;
    _ = InitializeProcThreadAttributeList(null, 1, 0, &attribute_bytes);
    if (attribute_bytes == 0 or attribute_bytes > 4096) return error.AttributeFailed;
    const words = try allocator.alloc(usize, try std.math.divCeil(usize, attribute_bytes, @sizeOf(usize)));
    defer allocator.free(words);
    const attributes: *anyopaque = @ptrCast(words.ptr);
    if (InitializeProcThreadAttributeList(attributes, 1, 0, &attribute_bytes) == 0) return error.AttributeFailed;
    defer DeleteProcThreadAttributeList(attributes);
    if (UpdateProcThreadAttribute(attributes, 0, proc_thread_attribute_handle_list, @ptrCast(&handles), handle_count * @sizeOf(usize), null, null) == 0)
        return error.AttributeFailed;

    const executable_w = try std.unicode.wtf8ToWtf16LeAllocZ(allocator, executable);
    defer allocator.free(executable_w);
    const config_dir = std.fs.path.dirname(config) orelse return error.InvalidConfigPath;
    const cwd_w = try std.unicode.wtf8ToWtf16LeAllocZ(allocator, config_dir);
    defer allocator.free(cwd_w);
    const line = try workerCommandLine(allocator, executable, config, stop, lease, ready);
    defer allocator.free(line);
    var startup = StartupInfoEx{ .startup = std.mem.zeroes(std.os.windows.STARTUPINFOW), .attributes = attributes };
    startup.startup.cb = @sizeOf(StartupInfoEx);
    if (handle_count > 3) {
        startup.startup.dwFlags |= startf_use_std_handles;
        startup.startup.hStdInput = @ptrFromInt(child_stdin);
        startup.startup.hStdOutput = @ptrFromInt(child_stdout);
        startup.startup.hStdError = @ptrFromInt(child_stderr);
    }
    var information: ProcessInformation = undefined;
    if (CreateProcessW(executable_w.ptr, line.ptr, null, null, 1, extended_startupinfo_present | create_suspended | create_no_window, null, cwd_w.ptr, &startup, &information) == 0)
        return error.ProcessCreateFailed;
    defer _ = CloseHandle(information.thread);
    errdefer {
        _ = TerminateProcess(information.process, 125);
        _ = WaitForSingleObject(information.process, infinite);
        _ = CloseHandle(information.process);
    }
    if (AssignProcessToJobObject(job, information.process) == 0) return error.JobAssignmentFailed;
    if (ResumeThread(information.thread) == std.math.maxInt(u32)) return error.ResumeFailed;
    return information.process;
}

test "SCM arguments and handle decimals are strict" {
    try std.testing.expect(isServiceArg(host_arg));
    try std.testing.expect(!isServiceArg(worker_arg));
    try std.testing.expect(isWorkerArg(worker_arg));
    try std.testing.expect(isConsoleHostArg(console_host_arg));
    try std.testing.expectEqual(@as(usize, 123), try canonicalHandle("123"));
    try std.testing.expectError(error.InvalidWorkerHandle, canonicalHandle("0"));
    try std.testing.expectError(error.InvalidWorkerHandle, canonicalHandle("01"));
    try std.testing.expectError(error.InvalidWorkerHandle, canonicalHandle("+1"));
    try std.testing.expectError(error.InvalidWorkerHandle, canonicalHandle("1x"));
}

test "SCM host refuses relative configuration before dispatcher registration" {
    if (comptime builtin.os.tag != .windows) return;
    try std.testing.expectError(error.InvalidConfigPath, runHost(std.testing.allocator, std.testing.io, "relative.toml"));
    try std.testing.expectError(error.InvalidConfigPath, runConsoleHost(std.testing.allocator, std.testing.io, "relative.toml"));
    try std.testing.expectError(error.InvalidWorkerHandle, WorkerHandles.init(0, 0, 0));
    var guard = StopGuard{ .stop_event = 0, .hook = .{ .context = undefined, .request = undefined } };
    try std.testing.expectError(error.AlreadyInstalled, guard.install());
}

test "SCM worker stop event and lease remain live until worker deinit" {
    if (comptime builtin.os.tag != .windows) return;
    const stop = CreateEventW(null, 1, 0, null);
    if (stop == 0) return error.EventCreateFailed;
    var pipe_attributes = SecurityAttributes{ .length = @sizeOf(SecurityAttributes), .security_descriptor = null, .inherit_handle = 0 };
    var read: usize = 0;
    var write: usize = 0;
    if (CreatePipe(&read, &write, &pipe_attributes, 0) == 0) {
        _ = CloseHandle(stop);
        return error.PipeCreateFailed;
    }
    defer closeOwned(&read);
    const callback_event = CreateEventW(null, 1, 0, null);
    if (callback_event == 0) {
        _ = CloseHandle(stop);
        _ = CloseHandle(write);
        return error.EventCreateFailed;
    }
    defer _ = CloseHandle(callback_event);
    var worker = try WorkerHandles.init(stop, write, 0);
    defer worker.deinit();
    try worker.activate();
    const helix = activeForHelix() orelse return error.MissingWorker;
    try std.testing.expectEqual(stop, helix.stop_event);
    try std.testing.expectEqual(write, helix.lease_write);
    const Callback = struct {
        fn request(raw: *anyopaque) void {
            const handle: *usize = @ptrCast(@alignCast(raw));
            _ = SetEvent(handle.*);
        }
    };
    var callback_context = callback_event;
    var guard = StopGuard{ .stop_event = worker.stop_event, .hook = .{ .context = &callback_context, .request = Callback.request } };
    try guard.install();
    defer guard.deinit();
    try std.testing.expect(SetEvent(stop) != 0);
    try std.testing.expectEqual(wait_object_0, WaitForSingleObject(callback_event, 5000));
    try worker.reportExit(true);
    var byte: [1]u8 = undefined;
    var got: u32 = 0;
    try std.testing.expect(ReadFile(read, &byte, 1, &got, null) != 0);
    try std.testing.expectEqual(@as(u32, 1), got);
    try std.testing.expectEqual(@as(u8, 0), byte[0]);
    guard.deinit();
    worker.deinit();
    try std.testing.expect(activeForHelix() == null);
    try std.testing.expect(ReadFile(read, &byte, 1, &got, null) == 0);
    try std.testing.expectEqual(error_broken_pipe, GetLastError());
}
