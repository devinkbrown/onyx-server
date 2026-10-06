// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Route Ctrl+C and Ctrl+Break through the daemon's cooperative stop path.
//! Windows invokes console handlers on another thread. The guard waits for
//! callbacks to finish before its borrowed stop context can be destroyed.
const std = @import("std");
const builtin = @import("builtin");

extern "kernel32" fn SetConsoleCtrlHandler(handler: *const fn (u32) callconv(.winapi) i32, add: i32) callconv(.winapi) i32;
extern "kernel32" fn Sleep(milliseconds: u32) callconv(.winapi) void;

pub const StopHook = struct {
    context: *anyopaque,
    request: *const fn (*anyopaque) void,
};

var active_guard: std.atomic.Value(usize) = .init(0);
var callbacks_in_flight: std.atomic.Value(u32) = .init(0);

fn onConsoleControl(code: u32) callconv(.winapi) i32 {
    if (code != 0 and code != 1) return 0;
    _ = callbacks_in_flight.fetchAdd(1, .acq_rel);
    defer _ = callbacks_in_flight.fetchSub(1, .acq_rel);
    const address = active_guard.load(.acquire);
    if (address == 0) return 0;
    const guard: *Guard = @ptrFromInt(address);
    guard.hook.request(guard.hook.context);
    return 1;
}

pub const Guard = struct {
    hook: StopHook,
    installed: bool = false,

    pub fn install(self: *Guard) !void {
        if (comptime builtin.os.tag != .windows) return error.Unsupported;
        if (self.installed or active_guard.cmpxchgStrong(0, @intFromPtr(self), .acq_rel, .acquire) != null)
            return error.AlreadyInstalled;
        if (SetConsoleCtrlHandler(onConsoleControl, 1) == 0) {
            active_guard.store(0, .release);
            return error.ConsoleHandlerFailed;
        }
        self.installed = true;
    }

    pub fn deinit(self: *Guard) void {
        if (comptime builtin.os.tag != .windows) return;
        if (!self.installed) return;
        active_guard.store(0, .release);
        _ = SetConsoleCtrlHandler(onConsoleControl, 0);
        while (callbacks_in_flight.load(.acquire) != 0) Sleep(1);
        self.installed = false;
    }
};
