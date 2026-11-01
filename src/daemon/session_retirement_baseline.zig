// SPDX-License-Identifier: AGPL-3.0-or-later

//! Offline Linux CLI witness for a trusted, quiesced retirement baseline.
//! The owner must freeze the issuer and provision a private 0500 directory
//! containing 0400 WAL/snapshot files before acquisition. Kernel read leases
//! reject existing writers and detect lease breaks; they do not prove issuer
//! quiescence, defend against a privileged/hostile owner, or prove the latest
//! state at publication. Never use this process-global signal owner at runtime.
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const Identity = @import("mesh_presence_lease.zig").Identity;

pub const Error = error{
    Unsupported,
    InvalidName,
    GuardAlreadyActive,
    SignalStateBusy,
    SignalFailed,
    FileNotFound,
    InsecureBaseline,
    ActiveWriter,
    LeaseBroken,
    SourceChanged,
    StatFailed,
    OpenFailed,
    LeaseFailed,
};

const supported = builtin.os.tag == .linux and @sizeOf(usize) == 8;
const name_max = 255;
// Zig's Linux ABI computes SIGRTMAX as NSIG-1 (64 on x86_64/aarch64).
// Use the ABI helper, not an assumed SIGRTMIN enum field or fixed bit index.
// std.Io.Threaded owns SIGIO for cancellation; neither this guard nor its
// cleanup changes SIGIO's handler, mask, or pending signals. A pre-existing
// owner of this RT signal causes acquisition to fail, never to steal it.
const lease_signal: linux.SIG = @fromBackingInt(@intCast(linux.sigrtmax()));
comptime {
    if (supported and (@backingInt(lease_signal) < linux.sigrtmin() or
        @backingInt(lease_signal) >= linux.NSIG or lease_signal == .IO))
        @compileError("retirement lease notification must be a separate valid Linux RT signal");
}
var active: std.atomic.Value(bool) = .init(false);
var broken: std.atomic.Value(bool) = .init(false);

fn onLeaseBreak(_: linux.SIG) callconv(.c) void {
    // No allocation, logging, file access, or non-lock-free operation here.
    broken.store(true, .release);
}

const Name = struct {
    bytes: [name_max + 1]u8 = @splat(0),
    len: usize = 0,

    fn init(value: []const u8) Error!Name {
        if (value.len == 0 or value.len > name_max or
            std.mem.eql(u8, value, ".") or std.mem.eql(u8, value, "..") or
            std.mem.indexOfAny(u8, value, "/\x00") != null) return error.InvalidName;
        var result: Name = .{ .len = value.len };
        @memcpy(result.bytes[0..value.len], value);
        return result;
    }

    fn z(self: *const Name) [*:0]const u8 {
        return self.bytes[0..self.len :0].ptr;
    }
};

const Metadata = struct {
    identity: Identity,
    mode: u16,
    uid: u32,
    gid: u32,
    links: u32,
    size: u64,
    mtime_sec: i64,
    mtime_nsec: u32,
    ctime_sec: i64,
    ctime_nsec: u32,
};

fn metadata(fd: linux.fd_t, name: [*:0]const u8, flags: u32) Error!Metadata {
    var stat: linux.Statx = std.mem.zeroes(linux.Statx);
    const wanted: linux.STATX = .{
        .TYPE = true,
        .MODE = true,
        .NLINK = true,
        .UID = true,
        .GID = true,
        .MTIME = true,
        .CTIME = true,
        .INO = true,
        .SIZE = true,
    };
    while (true) switch (linux.errno(linux.statx(fd, name, flags, wanted, &stat))) {
        .SUCCESS => break,
        .INTR => continue,
        .NOENT => return error.FileNotFound,
        .NOSYS, .OPNOTSUPP => return error.Unsupported,
        else => return error.StatFailed,
    };
    const mask: u32 = @bitCast(wanted);
    if (@as(u32, @bitCast(stat.mask)) & mask != mask) return error.StatFailed;
    return .{
        .identity = .{ .device = (@as(u64, stat.dev_major) << 32) | stat.dev_minor, .inode = stat.ino },
        .mode = stat.mode,
        .uid = stat.uid,
        .gid = stat.gid,
        .links = stat.nlink,
        .size = stat.size,
        .mtime_sec = stat.mtime.sec,
        .mtime_nsec = stat.mtime.nsec,
        .ctime_sec = stat.ctime.sec,
        .ctime_nsec = stat.ctime.nsec,
    };
}

fn heldMetadata(fd: linux.fd_t) Error!Metadata {
    return metadata(fd, "", linux.AT.EMPTY_PATH);
}

fn requirePrivate(value: Metadata, directory: bool) Error!void {
    const kind: u16 = if (directory) std.posix.S.IFDIR else std.posix.S.IFREG;
    const mode: u16 = if (directory) 0o500 else 0o400;
    if (value.mode & std.posix.S.IFMT != kind or value.mode & 0o7777 != mode or
        value.uid != linux.geteuid() or (!directory and value.links != 1))
        return error.InsecureBaseline;
}

fn openAt(parent: linux.fd_t, name: [*:0]const u8, directory: bool) Error!linux.fd_t {
    while (true) {
        const result = linux.openat(parent, name, .{
            .ACCMODE = .RDONLY,
            .CLOEXEC = true,
            .NOFOLLOW = true,
            .NONBLOCK = true,
            .DIRECTORY = directory,
        }, 0);
        switch (linux.errno(result)) {
            .SUCCESS => return @intCast(result),
            .INTR => continue,
            .NOENT => return error.FileNotFound,
            .LOOP, .NOTDIR => return error.InsecureBaseline,
            else => return error.OpenFailed,
        }
    }
}

fn acquireReadLease(fd: linux.fd_t) Error!void {
    const Operation = struct { command: i32, value: usize };
    for ([_]Operation{
        .{ .command = linux.F.SETSIG, .value = @backingInt(lease_signal) },
        .{ .command = linux.F.SETLEASE, .value = linux.F.RDLCK },
    }) |operation| {
        while (true) switch (linux.errno(linux.fcntl(fd, operation.command, operation.value))) {
            .SUCCESS => break,
            .INTR => continue,
            .AGAIN => return error.ActiveWriter,
            .INVAL, .NOSYS, .OPNOTSUPP => return error.Unsupported,
            else => return error.LeaseFailed,
        };
    }
}

fn requireLease(fd: linux.fd_t) Error!void {
    // Linux can fall back from queued RT notification to SIGIO when the RT
    // queue limit is reached. Threaded may consume that cancellation signal;
    // neither missed delivery nor a cleared sticky flag grants permission:
    // F_GETLEASE reports the target unlock immediately on a pending break and
    // remains unlocked after forced expiry. Never reacquire in assertStable.
    while (true) {
        const result = linux.fcntl(fd, linux.F.GETLEASE, 0);
        switch (linux.errno(result)) {
            .SUCCESS => if (result == linux.F.RDLCK) return else return error.LeaseBroken,
            .INTR => continue,
            else => return error.LeaseFailed,
        }
    }
}

fn leaseSignalSet() linux.sigset_t {
    var result = linux.sigemptyset();
    linux.sigaddset(&result, lease_signal);
    return result;
}

fn signalMask(operation: u32, set: *const linux.sigset_t, old: ?*linux.sigset_t) Error!void {
    if (linux.errno(linux.sigprocmask(operation, set, old)) != .SUCCESS) return error.SignalFailed;
}

fn pendingLeaseSignal() Error!bool {
    var pending = linux.sigemptyset();
    const rc = linux.syscall2(.rt_sigpending, @intFromPtr(&pending), @sizeOf(linux.sigset_t));
    if (linux.errno(rc) != .SUCCESS) return error.SignalFailed;
    return linux.sigismember(&pending, lease_signal);
}

fn drainLeaseSignal() Error!void {
    const set = leaseSignalSet();
    const zero: linux.timespec = .{ .sec = 0, .nsec = 0 };
    // Production cleanup closes leases before draining, so no further lease
    // notifications can be produced. Bound unrelated signal interference too.
    for (0..64) |_| {
        const rc = linux.syscall4(.rt_sigtimedwait, @intFromPtr(&set), 0, @intFromPtr(&zero), @sizeOf(linux.sigset_t));
        switch (linux.errno(rc)) {
            .SUCCESS => if (rc != @backingInt(lease_signal)) return error.SignalFailed,
            .INTR => continue,
            .AGAIN => return,
            else => return error.SignalFailed,
        }
    }
    return error.SignalStateBusy;
}

pub const Guard = struct {
    parent_fd: linux.fd_t = -1,
    directory_fd: linux.fd_t = -1,
    wal_fd: linux.fd_t = -1,
    snapshot_fd: linux.fd_t = -1,
    baseline_name: Name = .{},
    wal_name: Name = .{},
    snapshot_name: Name = .{},
    directory_metadata: Metadata = undefined,
    wal_metadata: Metadata = undefined,
    snapshot_metadata: Metadata = undefined,
    old_action: linux.Sigaction = undefined,
    old_mask: linux.sigset_t = undefined,
    owns_global: bool = false,
    saved_mask: bool = false,
    owns_handler: bool = false,
    ready: bool = false,

    /// Dedicated offline CLI only. The caller supplies a trusted parent handle
    /// and must neither copy this owning Guard nor modify its borrowed dir.
    /// Preparation and publication retain this guard; no method proves final
    /// issuer quiescence or closes the validation-to-publication race.
    pub fn acquire(io: std.Io, parent: std.Io.Dir, baseline_name: []const u8, wal_name: []const u8) Error!Guard {
        _ = io;
        if (comptime !supported) return error.Unsupported;
        var self: Guard = .{
            .baseline_name = try Name.init(baseline_name),
            .wal_name = try Name.init(wal_name),
        };
        if (wal_name.len > name_max - ".snap".len) return error.InvalidName;
        var snapshot: [name_max]u8 = undefined;
        @memcpy(snapshot[0..wal_name.len], wal_name);
        @memcpy(snapshot[wal_name.len..][0..".snap".len], ".snap");
        self.snapshot_name = try Name.init(snapshot[0 .. wal_name.len + ".snap".len]);
        if (active.cmpxchgStrong(false, true, .acq_rel, .acquire) != null) return error.GuardAlreadyActive;
        self.owns_global = true;
        errdefer self.deinit();

        // Block before examining/changing the disposition. Acquisition errors
        // preserve a pre-existing pending lease signal rather than consuming it.
        const set = leaseSignalSet();
        try signalMask(linux.SIG.BLOCK, &set, &self.old_mask);
        self.saved_mask = true;
        if (linux.sigismember(&self.old_mask, lease_signal) or try pendingLeaseSignal()) return error.SignalStateBusy;
        if (linux.errno(linux.sigaction(lease_signal, null, &self.old_action)) != .SUCCESS) return error.SignalFailed;
        if (self.old_action.handler.handler != linux.SIG.DFL) return error.SignalStateBusy;
        broken.store(false, .release);
        const action: linux.Sigaction = .{ .handler = .{ .handler = onLeaseBreak }, .mask = set, .flags = 0 };
        if (linux.errno(linux.sigaction(lease_signal, &action, null)) != .SUCCESS) return error.SignalFailed;
        self.owns_handler = true;

        // Open '.' to retain a parent even when the caller uses AT_FDCWD.
        self.parent_fd = try openAt(parent.handle, ".", true);
        self.directory_fd = try openAt(self.parent_fd, self.baseline_name.z(), true);
        self.directory_metadata = try heldMetadata(self.directory_fd);
        try requirePrivate(self.directory_metadata, true);
        self.wal_fd = try openAt(self.directory_fd, self.wal_name.z(), false);
        self.wal_metadata = try heldMetadata(self.wal_fd);
        try requirePrivate(self.wal_metadata, false);
        try acquireReadLease(self.wal_fd);
        self.snapshot_fd = openAt(self.directory_fd, self.snapshot_name.z(), false) catch |err| switch (err) {
            error.FileNotFound => -1,
            else => return err,
        };
        if (self.snapshot_fd >= 0) {
            self.snapshot_metadata = try heldMetadata(self.snapshot_fd);
            try requirePrivate(self.snapshot_metadata, false);
            try acquireReadLease(self.snapshot_fd);
        }
        self.ready = true;
        try self.assertStable();
        try signalMask(linux.SIG.SETMASK, &self.old_mask, null);
        return self;
    }

    /// Borrowed handle; valid only until deinit. Do not close or mutate it.
    pub fn directory(self: *const Guard) std.Io.Dir {
        std.debug.assert(self.ready and self.owns_global);
        return .{ .handle = self.directory_fd };
    }

    pub fn assertStable(self: *const Guard) Error!void {
        if (comptime !supported) return error.Unsupported;
        if (!self.ready or !self.owns_global) return error.SourceChanged;
        if (broken.load(.acquire) or try pendingLeaseSignal()) return error.LeaseBroken;
        try requireLease(self.wal_fd);
        if (self.snapshot_fd >= 0) try requireLease(self.snapshot_fd);
        const current_dir = try heldMetadata(self.directory_fd);
        try requirePrivate(current_dir, true);
        if (!std.meta.eql(current_dir, self.directory_metadata) or
            !std.meta.eql(try metadata(self.parent_fd, self.baseline_name.z(), linux.AT.SYMLINK_NOFOLLOW), self.directory_metadata))
            return error.SourceChanged;
        try self.checkFile(self.wal_fd, &self.wal_name, self.wal_metadata);
        if (self.snapshot_fd >= 0) {
            try self.checkFile(self.snapshot_fd, &self.snapshot_name, self.snapshot_metadata);
        } else {
            const appeared: ?Metadata = metadata(self.directory_fd, self.snapshot_name.z(), linux.AT.SYMLINK_NOFOLLOW) catch |err| switch (err) {
                error.FileNotFound => null,
                else => return err,
            };
            if (appeared != null) return error.SourceChanged;
        }
        if (broken.load(.acquire) or try pendingLeaseSignal()) return error.LeaseBroken;
        try requireLease(self.wal_fd);
        if (self.snapshot_fd >= 0) try requireLease(self.snapshot_fd);
    }

    fn checkFile(self: *const Guard, fd: linux.fd_t, name: *const Name, expected: Metadata) Error!void {
        const current = try heldMetadata(fd);
        try requirePrivate(current, false);
        if (!std.meta.eql(current, expected) or
            !std.meta.eql(try metadata(self.directory_fd, name.z(), linux.AT.SYMLINK_NOFOLLOW), expected))
            return error.SourceChanged;
    }

    /// Close leases while lease signal is blocked; drain only notifications owned by
    /// this guard before restoring the previous disposition and mask. Cleanup
    /// failure terminates the dedicated CLI rather than leaving unsafe signal
    /// state behind. No handler is ever installed in a daemon/test parent.
    pub fn deinit(self: *Guard) void {
        if (comptime !supported) return;
        if (!self.owns_global) return;
        if (self.saved_mask) {
            const set = leaseSignalSet();
            signalMask(linux.SIG.BLOCK, &set, null) catch linux.exit_group(1);
        }
        for ([_]*linux.fd_t{ &self.snapshot_fd, &self.wal_fd, &self.directory_fd, &self.parent_fd }) |fd| {
            if (fd.* >= 0) {
                // Last-close drops a lease even if explicit unlock fails.
                if (fd == &self.snapshot_fd or fd == &self.wal_fd) _ = linux.fcntl(fd.*, linux.F.SETLEASE, linux.F.UNLCK);
                _ = linux.close(fd.*);
                fd.* = -1;
            }
        }
        if (self.owns_handler) {
            drainLeaseSignal() catch linux.exit_group(1);
            if (linux.errno(linux.sigaction(lease_signal, &self.old_action, null)) != .SUCCESS) linux.exit_group(1);
            self.owns_handler = false;
        }
        if (self.saved_mask) {
            signalMask(linux.SIG.SETMASK, &self.old_mask, null) catch linux.exit_group(1);
            self.saved_mask = false;
        }
        self.ready = false;
        self.owns_global = false;
        active.store(false, .release);
    }
};

const Scenario = enum {
    absent_snapshot,
    present_snapshot,
    existing_writer,
    snapshot_writer_partial_cleanup,
    lease_break,
    lease_break_no_notification,
    stdio_sigio_coexistence,
    file_mode_changed,
    snapshot_appeared,
    snapshot_disappeared,
    wal_replaced,
    directory_replaced,
    hardlink,
    symlink,
    wrong_file_mode,
    wrong_directory_mode,
    conflicting_signal_handler,
    pending_signal,
    singleton,
};

var test_sigio_seen: std.atomic.Value(bool) = .init(false);

fn onTestSigio(_: linux.SIG) callconv(.c) void {
    test_sigio_seen.store(true, .release);
}

fn testOpen(parent: linux.fd_t, name: [*:0]const u8, flags: linux.O, mode: linux.mode_t) Error!linux.fd_t {
    const result = linux.openat(parent, name, flags, mode);
    if (linux.errno(result) != .SUCCESS) return error.OpenFailed;
    return @intCast(result);
}

fn createFixtureFile(parent: linux.fd_t, name: [*:0]const u8) Error!linux.fd_t {
    const fd = try testOpen(parent, name, .{ .ACCMODE = .RDWR, .CREAT = true, .EXCL = true, .CLOEXEC = true }, 0o400);
    errdefer _ = linux.close(fd);
    if (linux.write(fd, "baseline", 8) != 8 or linux.errno(linux.fchmod(fd, 0o400)) != .SUCCESS) return error.OpenFailed;
    return fd;
}

fn expectAcquireFailure(parent: std.Io.Dir, expected: Error) Error!void {
    var guard = Guard.acquire(undefined, parent, "baseline", "accounts.wal") catch |err| {
        if (err != expected) return err;
        // Partial acquisition must release singleton ownership and leave the
        // original signal disposition/mask intact in this isolated process.
        if (active.load(.acquire)) return error.SourceChanged;
        return;
    };
    guard.deinit();
    return error.SourceChanged;
}

/// Runs only after fork. No allocator or Io backend is touched in this child.
fn childScenario(parent: std.Io.Dir, scenario: Scenario) Error!void {
    // Normalize only the forked child's signal context. The parent runner may
    // have inherited its own mask/disposition from its execution environment.
    const set = leaseSignalSet();
    try signalMask(linux.SIG.BLOCK, &set, null);
    const default: linux.Sigaction = .{ .handler = .{ .handler = linux.SIG.DFL }, .mask = linux.sigemptyset(), .flags = 0 };
    if (linux.errno(linux.sigaction(lease_signal, &default, null)) != .SUCCESS) return error.SignalFailed;
    try drainLeaseSignal();
    try signalMask(linux.SIG.UNBLOCK, &set, null);
    if (linux.errno(linux.mkdirat(parent.handle, "baseline", 0o700)) != .SUCCESS) return error.OpenFailed;
    const dir = try openAt(parent.handle, "baseline", true);
    defer _ = linux.close(dir);
    defer _ = linux.fchmod(dir, 0o700);
    var writer = try createFixtureFile(dir, "accounts.wal");
    defer {
        if (writer >= 0) _ = linux.close(writer);
    }
    if (scenario != .existing_writer) {
        _ = linux.close(writer);
        writer = -1;
    }
    const has_snapshot = scenario == .present_snapshot or scenario == .snapshot_writer_partial_cleanup or scenario == .snapshot_disappeared;
    var snapshot_writer: linux.fd_t = -1;
    defer {
        if (snapshot_writer >= 0) _ = linux.close(snapshot_writer);
    }
    if (has_snapshot) {
        snapshot_writer = try createFixtureFile(dir, "accounts.wal.snap");
        if (scenario != .snapshot_writer_partial_cleanup) {
            _ = linux.close(snapshot_writer);
            snapshot_writer = -1;
        }
    }
    if (scenario == .hardlink and linux.errno(linux.linkat(dir, "accounts.wal", dir, "alias", 0)) != .SUCCESS) return error.OpenFailed;
    if (scenario == .symlink) {
        if (linux.errno(linux.renameat(dir, "accounts.wal", dir, "original")) != .SUCCESS or
            linux.errno(linux.symlinkat("original", dir, "accounts.wal")) != .SUCCESS) return error.OpenFailed;
    }
    if (scenario == .wrong_file_mode and linux.errno(linux.fchmodat(dir, "accounts.wal", 0o600)) != .SUCCESS) return error.OpenFailed;
    if (linux.errno(linux.fchmod(dir, if (scenario == .wrong_directory_mode) 0o700 else 0o500)) != .SUCCESS) return error.OpenFailed;

    switch (scenario) {
        .existing_writer => return expectAcquireFailure(parent, error.ActiveWriter),
        .snapshot_writer_partial_cleanup => {
            try expectAcquireFailure(parent, error.ActiveWriter);
            // A fresh nonblocking writer succeeds only if partial acquisition
            // released the earlier WAL lease, not merely singleton ownership.
            if (linux.errno(linux.fchmodat(dir, "accounts.wal", 0o600)) != .SUCCESS) return error.OpenFailed;
            const reopened = try testOpen(dir, "accounts.wal", .{ .ACCMODE = .WRONLY, .NONBLOCK = true, .CLOEXEC = true }, 0);
            _ = linux.close(reopened);
            if (linux.errno(linux.fchmodat(dir, "accounts.wal", 0o400)) != .SUCCESS) return error.OpenFailed;
            _ = linux.close(snapshot_writer);
            snapshot_writer = -1;
        },
        .hardlink, .symlink, .wrong_file_mode, .wrong_directory_mode => return expectAcquireFailure(parent, error.InsecureBaseline),
        .conflicting_signal_handler => {
            const ignored: linux.Sigaction = .{ .handler = .{ .handler = linux.SIG.IGN }, .mask = linux.sigemptyset(), .flags = 0 };
            var previous: linux.Sigaction = undefined;
            if (linux.errno(linux.sigaction(lease_signal, &ignored, &previous)) != .SUCCESS) return error.SignalFailed;
            defer _ = linux.sigaction(lease_signal, &previous, null);
            try expectAcquireFailure(parent, error.SignalStateBusy);
            var current: linux.Sigaction = undefined;
            if (linux.errno(linux.sigaction(lease_signal, null, &current)) != .SUCCESS or current.handler.handler != linux.SIG.IGN) return error.SignalFailed;
            return;
        },
        .pending_signal => {
            var original_mask: linux.sigset_t = undefined;
            try signalMask(linux.SIG.BLOCK, &set, &original_mask);
            defer signalMask(linux.SIG.SETMASK, &original_mask, null) catch linux.exit_group(30);
            if (linux.errno(linux.kill(linux.getpid(), lease_signal)) != .SUCCESS) return error.SignalFailed;
            try expectAcquireFailure(parent, error.SignalStateBusy);
            if (!try pendingLeaseSignal()) return error.SignalFailed;
            try drainLeaseSignal();
            return;
        },
        .stdio_sigio_coexistence => {
            // std.Io.Threaded already owns SIGIO in a native process.Init CLI.
            // Give this child an observable owner and a blocked pending SIGIO;
            // the guard must neither steal, consume nor unblock that signal.
            const action: linux.Sigaction = .{ .handler = .{ .handler = onTestSigio }, .mask = linux.sigemptyset(), .flags = 0 };
            var previous: linux.Sigaction = undefined;
            if (linux.errno(linux.sigaction(.IO, &action, &previous)) != .SUCCESS) return error.SignalFailed;
            defer _ = linux.sigaction(.IO, &previous, null);
            var io_set = linux.sigemptyset();
            linux.sigaddset(&io_set, .IO);
            var io_mask: linux.sigset_t = undefined;
            try signalMask(linux.SIG.BLOCK, &io_set, &io_mask);
            defer signalMask(linux.SIG.SETMASK, &io_mask, null) catch linux.exit_group(30);
            test_sigio_seen.store(false, .release);
            if (linux.errno(linux.kill(linux.getpid(), .IO)) != .SUCCESS) return error.SignalFailed;
            var guard = try Guard.acquire(undefined, parent, "baseline", "accounts.wal");
            defer guard.deinit();
            try guard.assertStable();
            guard.deinit();
            var current: linux.Sigaction = undefined;
            if (linux.errno(linux.sigaction(.IO, null, &current)) != .SUCCESS or current.handler.handler != onTestSigio) return error.SignalFailed;
            var pending = linux.sigemptyset();
            if (linux.errno(linux.syscall2(.rt_sigpending, @intFromPtr(&pending), @sizeOf(linux.sigset_t))) != .SUCCESS or
                !linux.sigismember(&pending, .IO)) return error.SignalFailed;
            var current_mask: linux.sigset_t = undefined;
            const empty_mask = linux.sigemptyset();
            try signalMask(linux.SIG.BLOCK, &empty_mask, &current_mask);
            if (!linux.sigismember(&current_mask, .IO) or test_sigio_seen.load(.acquire)) return error.SignalFailed;
            try signalMask(linux.SIG.UNBLOCK, &io_set, null);
            if (!test_sigio_seen.load(.acquire)) return error.SignalFailed;
            return;
        },
        else => {},
    }

    var prior_action: linux.Sigaction = undefined;
    if (linux.errno(linux.sigaction(lease_signal, null, &prior_action)) != .SUCCESS) return error.SignalFailed;
    var prior_mask: linux.sigset_t = undefined;
    const empty = linux.sigemptyset();
    try signalMask(linux.SIG.BLOCK, &empty, &prior_mask);
    var guard = try Guard.acquire(undefined, parent, "baseline", "accounts.wal");
    defer guard.deinit();
    try guard.assertStable();
    if (guard.directory().handle != guard.directory_fd) return error.SourceChanged;
    switch (scenario) {
        .lease_break, .lease_break_no_notification => {
            // Same trusted owner deliberately changes permissions to exercise
            // a real kernel lease break; this is not an adversarial-owner claim.
            if (linux.errno(linux.fchmodat(dir, "accounts.wal", 0o600)) != .SUCCESS) return error.OpenFailed;
            const opened = linux.openat(dir, "accounts.wal", .{ .ACCMODE = .WRONLY, .NONBLOCK = true, .CLOEXEC = true }, 0);
            if (linux.errno(opened) == .SUCCESS) {
                _ = linux.close(@intCast(opened));
                return error.LeaseFailed;
            }
            if (linux.errno(opened) != .AGAIN) return error.LeaseFailed;
            if (scenario == .lease_break_no_notification) {
                // Exercise the fallback witness independently of notification:
                // discard RT delivery and clear the sticky flag only in this
                // isolated test. The real kernel break must still be refused.
                const notification_set = leaseSignalSet();
                try signalMask(linux.SIG.BLOCK, &notification_set, null);
                try drainLeaseSignal();
                broken.store(false, .release);
                if (try pendingLeaseSignal()) return error.SignalFailed;
            } else if (!broken.load(.acquire) and !try pendingLeaseSignal()) {
                return error.SignalFailed;
            }
            guard.assertStable() catch |err| {
                if (err != error.LeaseBroken) return err;
                guard.deinit();
                // Drain/restore must make a second, unrelated acquisition safe.
                if (linux.errno(linux.fchmodat(dir, "accounts.wal", 0o400)) != .SUCCESS) return error.OpenFailed;
                var retry = try Guard.acquire(undefined, parent, "baseline", "accounts.wal");
                defer retry.deinit();
                return retry.assertStable();
            };
            return error.LeaseFailed;
        },
        .file_mode_changed => {
            if (linux.errno(linux.fchmodat(dir, "accounts.wal", 0o600)) != .SUCCESS) return error.OpenFailed;
        },
        .snapshot_appeared, .snapshot_disappeared, .wal_replaced => {
            if (linux.errno(linux.fchmod(dir, 0o700)) != .SUCCESS) return error.OpenFailed;
            if (scenario == .snapshot_appeared) {
                const fd = try createFixtureFile(dir, "accounts.wal.snap");
                _ = linux.close(fd);
            } else if (scenario == .snapshot_disappeared) {
                if (linux.errno(linux.unlinkat(dir, "accounts.wal.snap", 0)) != .SUCCESS) return error.OpenFailed;
            } else {
                if (linux.errno(linux.renameat(dir, "accounts.wal", dir, "moved.wal")) != .SUCCESS) return error.OpenFailed;
                const fd = try createFixtureFile(dir, "accounts.wal");
                _ = linux.close(fd);
            }
            if (linux.errno(linux.fchmod(dir, 0o500)) != .SUCCESS) return error.OpenFailed;
        },
        .directory_replaced => {
            if (linux.errno(linux.renameat(parent.handle, "baseline", parent.handle, "moved")) != .SUCCESS or
                linux.errno(linux.mkdirat(parent.handle, "baseline", 0o700)) != .SUCCESS) return error.OpenFailed;
        },
        .singleton => {
            var second = Guard.acquire(undefined, parent, "baseline", "accounts.wal") catch |err| {
                if (err != error.GuardAlreadyActive) return err;
                return;
            };
            second.deinit();
            return error.SourceChanged;
        },
        else => {},
    }
    const changed = scenario == .file_mode_changed or scenario == .snapshot_appeared or
        scenario == .snapshot_disappeared or scenario == .wal_replaced or scenario == .directory_replaced;
    guard.assertStable() catch |err| {
        if (changed and (err == error.SourceChanged or err == error.InsecureBaseline)) return;
        return err;
    };
    if (changed) return error.SourceChanged;
    guard.deinit();
    var restored: linux.Sigaction = undefined;
    if (linux.errno(linux.sigaction(lease_signal, null, &restored)) != .SUCCESS or restored.handler.handler != prior_action.handler.handler) return error.SignalFailed;
    var restored_mask: linux.sigset_t = undefined;
    try signalMask(linux.SIG.BLOCK, &empty, &restored_mask);
    if (!std.meta.eql(prior_mask, restored_mask) or try pendingLeaseSignal()) return error.SignalFailed;
}

test "retirement baseline names reject traversal and reserve snapshot suffix" {
    for ([_][]const u8{ "", ".", "..", "a/b", "a\x00b" }) |name|
        try std.testing.expectError(error.InvalidName, Name.init(name));
    _ = try Name.init("accounts.wal");
    const too_long: [name_max + 1]u8 = @splat('a');
    try std.testing.expectError(error.InvalidName, Name.init(&too_long));
}

test "retirement baseline isolated kernel leases signals namespace and partial cleanup" {
    if (comptime !supported) return error.SkipZigTest;
    // Signal state changes occur only in raw-fork children. Their syscall-only
    // bodies cannot acquire locks inherited from the test runner's Io threads.
    for (std.enums.values(Scenario)) |scenario| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        defer {
            // A killed/timed-out child cannot run its permission-restoring
            // defer. Restore only these fixture-owned dirs before tmp cleanup.
            for ([_][*:0]const u8{ "baseline", "moved" }) |name| {
                const fd = openAt(tmp.dir.handle, name, true) catch continue;
                _ = linux.fchmod(fd, 0o700);
                _ = linux.close(fd);
            }
        }
        const child = linux.fork();
        if (linux.errno(child) != .SUCCESS) return error.TestUnexpectedResult;
        if (child == 0) {
            childScenario(tmp.dir, scenario) catch |err| linux.exit_group(if (err == error.Unsupported) 77 else 1);
            linux.exit_group(0);
        }
        const pid: linux.pid_t = @intCast(child);
        var status: i32 = 0;
        var complete = false;
        // Five seconds of bounded nonblocking waits. Kill and reap a stuck
        // child so broken signal cleanup cannot hang the main test runner.
        for (0..500) |_| {
            const waited = linux.waitpid(pid, &status, linux.W.NOHANG);
            if (linux.errno(waited) == .INTR) continue;
            if (linux.errno(waited) != .SUCCESS) return error.TestUnexpectedResult;
            if (waited == child) {
                complete = true;
                break;
            }
            const delay: linux.timespec = .{ .sec = 0, .nsec = 10_000_000 };
            _ = linux.nanosleep(&delay, null);
        }
        if (!complete) {
            _ = linux.kill(pid, .KILL);
            _ = linux.waitpid(pid, &status, 0);
            return error.TestUnexpectedResult;
        }
        if (status == 77 << 8) return error.SkipZigTest;
        if (status != 0) std.debug.print("retirement baseline child scenario={s} status={d}\n", .{ @tagName(scenario), status });
        try std.testing.expectEqual(@as(i32, 0), status);
    }
}
