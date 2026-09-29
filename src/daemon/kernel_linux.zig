// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Linux socket options the listener path actually sets.
//! TCP_FASTOPEN, TCP_USER_TIMEOUT, and SO_INCOMING_CPU are applied to the
//! listening socket. A missing option fails the bind; it is not reported as off.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;

/// Pending TFO handshakes the listener will accept. Set before listen.
pub const fastopen_queue: u32 = 256;
/// Unacked data abort, in milliseconds. Idle clients are not affected.
pub const user_timeout_ms: u32 = 30_000;

/// CPU index for SO_INCOMING_CPU. Shards spread across the machine's CPUs;
/// a one-CPU host stays on CPU 0.
pub fn shardIncomingCpu(shard_id: u12) u32 {
    const n = std.Thread.getCpuCount() catch 1;
    const cpus: usize = if (n == 0) 1 else n;
    return @intCast(@as(usize, shard_id) % cpus);
}

pub fn applyListenerOptions(fd: linux.fd_t) error{ PermissionDenied, Unexpected }!void {
    try setU32(fd, linux.IPPROTO.TCP, linux.TCP.FASTOPEN, fastopen_queue);
    try setU32(fd, linux.IPPROTO.TCP, linux.TCP.USER_TIMEOUT, user_timeout_ms);
    try setU32(fd, posix.SOL.SOCKET, linux.SO.INCOMING_CPU, 0);
}

pub fn setIncomingCpu(fd: linux.fd_t, cpu: u32) error{ PermissionDenied, Unexpected }!void {
    try setU32(fd, posix.SOL.SOCKET, linux.SO.INCOMING_CPU, cpu);
}

pub fn readU32Option(fd: linux.fd_t, level: i32, optname: u32) error{Unexpected}!u32 {
    var val: u32 = 0;
    var len: posix.socklen_t = @sizeOf(u32);
    const rc = linux.getsockopt(fd, level, optname, @ptrCast(&val), &len);
    if (posix.errno(rc) != .SUCCESS) return error.Unexpected;
    return val;
}

fn setU32(fd: linux.fd_t, level: i32, optname: u32, value: u32) error{ PermissionDenied, Unexpected }!void {
    var stored = value;
    const rc = linux.setsockopt(fd, level, optname, @ptrCast(&stored), @sizeOf(u32));
    switch (posix.errno(rc)) {
        .SUCCESS => return,
        .ACCES, .PERM => return error.PermissionDenied,
        else => return error.Unexpected,
    }
}
