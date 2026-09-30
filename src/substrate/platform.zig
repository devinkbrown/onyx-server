// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cross-platform OS primitives (CROSS-PLATFORM MANDATE, docs/dev/zig016-notes.md).
//!
//! Every OS-specific syscall the portable parts of the daemon need is funneled
//! through this one comptime `switch (builtin.os.tag)`, so the rest of the tree
//! never reaches for `std.os.linux.*` directly. Linux uses raw syscalls (no
//! libc); macOS/BSD use libc (`getentropy`, libc `clock_gettime`, `getpid`);
//! Windows uses ntdll/advapi32 externs. Linux-only fast paths (io_uring) live
//! elsewhere and are comptime-gated at their own use sites — never here.
const std = @import("std");
const builtin = @import("builtin");

const os_tag = builtin.os.tag;

/// Raised when the OS entropy source is unavailable or returns short.
pub const EntropyError = error{RandomSourceFailed};

// Windows system RNG (RtlGenRandom). std has no public wrapper, so declare the
// stable advapi32 alias ourselves. Returns 0 (FALSE) on failure.
extern "advapi32" fn SystemFunction036(buffer: [*]u8, length: u32) callconv(.winapi) u8;

// Windows wall clock (std's kernel32 binding lacks this); declare the extern.
extern "kernel32" fn GetSystemTimeAsFileTime(lpSystemTimeAsFileTime: *std.os.windows.FILETIME) callconv(.winapi) void;

/// Monotonic clock in milliseconds. Never wall-clock; safe for intervals and
/// timeouts across suspend. Sourced per-target so no `std.os.linux` leaks into
/// non-Linux builds.
pub fn monotonicMillis() i64 {
    switch (os_tag) {
        .linux => {
            var ts: std.os.linux.timespec = undefined;
            _ = std.os.linux.clock_gettime(std.os.linux.CLOCK.MONOTONIC, &ts);
            return tsToMillis(@intCast(ts.sec), @intCast(ts.nsec));
        },
        .windows => {
            var freq: i64 = 0;
            var cnt: i64 = 0;
            _ = std.os.windows.ntdll.RtlQueryPerformanceFrequency(&freq);
            _ = std.os.windows.ntdll.RtlQueryPerformanceCounter(&cnt);
            if (freq == 0) return 0;
            return @intCast(@divTrunc(@as(i128, cnt) * 1000, @as(i128, freq)));
        },
        else => {
            // macOS / *BSD via libc.
            var ts: std.c.timespec = undefined;
            _ = std.c.clock_gettime(std.posix.CLOCK.MONOTONIC, &ts);
            return tsToMillis(@intCast(ts.sec), @intCast(ts.nsec));
        },
    }
}

fn tsToMillis(sec: i64, nsec: i64) i64 {
    return sec * 1000 + @divTrunc(nsec, 1_000_000);
}

/// Wall-clock (Unix epoch) time in milliseconds. Use for timestamps a client
/// sees (server-time tags, TIME, signon, ban set-at); NOT for intervals.
pub fn realtimeMillis() i64 {
    return realtimeMillisChecked() orelse 0;
}

/// Checked Unix time for credential issuance and validation. A failed clock
/// read must not publish undefined timestamps or authenticate expired tokens.
pub fn realtimeMillisChecked() ?i64 {
    switch (os_tag) {
        .linux => {
            var ts: std.os.linux.timespec = undefined;
            if (std.os.linux.errno(std.os.linux.clock_gettime(std.os.linux.CLOCK.REALTIME, &ts)) != .SUCCESS) return null;
            return checkedUnixMillis(@intCast(ts.sec), @intCast(ts.nsec));
        },
        .windows => {
            // Windows FILETIME epoch is 1601; convert 100ns ticks to Unix ms.
            var ft: std.os.windows.FILETIME = undefined;
            GetSystemTimeAsFileTime(&ft);
            const ticks: u64 = (@as(u64, ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
            const unix_100ns: i128 = @as(i128, ticks) - 116_444_736_000_000_000;
            const millis = @divTrunc(unix_100ns, 10_000);
            if (millis < 0 or millis > std.math.maxInt(i64)) return null;
            return @intCast(millis);
        },
        else => {
            var ts: std.c.timespec = undefined;
            if (std.c.clock_gettime(std.posix.CLOCK.REALTIME, &ts) != 0) return null;
            return checkedUnixMillis(@intCast(ts.sec), @intCast(ts.nsec));
        },
    }
}

fn checkedUnixMillis(sec: i64, nsec: i64) ?i64 {
    if (sec < 0 or nsec < 0 or nsec >= 1_000_000_000) return null;
    const seconds_ms = std.math.mul(i64, sec, 1000) catch return null;
    return std.math.add(i64, seconds_ms, @divTrunc(nsec, 1_000_000)) catch null;
}

test "credential clock rejects malformed and overflowing Unix timestamps" {
    try std.testing.expectEqual(@as(?i64, 123456), checkedUnixMillis(123, 456_999_999));
    try std.testing.expect(checkedUnixMillis(-1, 0) == null);
    try std.testing.expect(checkedUnixMillis(1, -1) == null);
    try std.testing.expect(checkedUnixMillis(1, 1_000_000_000) == null);
    try std.testing.expect(checkedUnixMillis(std.math.maxInt(i64), 0) == null);
}

/// Process id, used for fork/snapshot detection in the RNG layer. Returns the
/// real pid on POSIX and the process id on Windows (where fork() does not
/// exist, so the value simply stays stable for the process lifetime).
pub fn currentPid() i32 {
    return switch (os_tag) {
        .linux => @intCast(std.os.linux.getpid()),
        // DWORD (u32) -> i32: @bitCast so a high pid can't trip the safe-build
        // @intCast overflow check (fork detection is moot on Windows anyway).
        .windows => @bitCast(std.os.windows.GetCurrentProcessId()),
        else => @intCast(std.c.getpid()),
    };
}

/// Fill `buf` from the OS CSPRNG. This is the slow root entropy source; hot
/// callers keep a per-instance DRBG and reseed from this.
pub fn fillOsEntropy(buf: []u8) EntropyError!void {
    switch (os_tag) {
        .linux => {
            var filled: usize = 0;
            while (filled < buf.len) {
                const rc = std.os.linux.getrandom(buf.ptr + filled, buf.len - filled, 0);
                switch (std.os.linux.errno(rc)) {
                    .SUCCESS => {
                        if (rc == 0) return EntropyError.RandomSourceFailed;
                        filled += rc;
                    },
                    .INTR => continue,
                    else => return EntropyError.RandomSourceFailed,
                }
            }
        },
        .windows => {
            var filled: usize = 0;
            while (filled < buf.len) {
                const want: u32 = @intCast(@min(buf.len - filled, @as(usize, std.math.maxInt(u32))));
                if (SystemFunction036(buf.ptr + filled, want) == 0) return EntropyError.RandomSourceFailed;
                filled += want;
            }
        },
        else => {
            // macOS / *BSD: arc4random_buf is the std-public CSPRNG (std.c
            // exposes it for these targets, unlike getentropy which is `{}`).
            // It always fills the whole buffer and cannot fail.
            std.c.arc4random_buf(buf.ptr, buf.len);
        },
    }
}

test "monotonic clock is non-negative and non-decreasing" {
    const a = monotonicMillis();
    const b = monotonicMillis();
    try std.testing.expect(a >= 0);
    try std.testing.expect(b >= a);
}

test "currentPid is stable within a process" {
    try std.testing.expectEqual(currentPid(), currentPid());
}

test "fillOsEntropy yields non-zero bytes" {
    var buf: [48]u8 = @splat(0);
    try fillOsEntropy(&buf);
    var any: bool = false;
    for (buf) |x| any = any or x != 0;
    try std.testing.expect(any);
}

test "realtime clock is a plausible Unix-epoch millisecond value" {
    const ms = realtimeMillis();
    // After 2020-01-01 and before year ~2100.
    try std.testing.expect(ms > 1_577_836_800_000);
    try std.testing.expect(ms < 4_102_444_800_000);
}
