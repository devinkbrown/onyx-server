// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regression tests retained from the mail sender implementation.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const smtp_client = @import("../../proto/smtp_client.zig");
const os_runtime = @import("../os_runtime.zig");
const platform = @import("../../substrate/platform.zig");
const store_mod = @import("../store.zig");
const testing = std.testing;
const Config = @import("config.zig").Config;
const Sender = @import("core.zig").Sender;

const MailJournalFault = struct {
    mode: enum { failed_write, synced_then_error },
    original_write: *const fn (?*anyopaque, std.Io.File, []const u8, []const []const u8, usize, u64) std.Io.File.WritePositionalError!usize,
    original_sync: *const fn (?*anyopaque, std.Io.File) std.Io.File.SyncError!void,
    attempts: usize = 0,
    synced: usize = 0,
    observed_connect_failure: bool = false,
    attempted_fd: ?posix.fd_t = null,
    reached: ?*std.Io.Event = null,
    proceed: ?*std.Io.Event = null,

    fn write(userdata: ?*anyopaque, file: std.Io.File, header: []const u8, data: []const []const u8, splat: usize, offset: u64) std.Io.File.WritePositionalError!usize {
        const fault = mail_journal_fault.?;
        var is_failure = std.mem.indexOf(u8, header, "mailfail:1") != null;
        for (data) |bytes| is_failure = is_failure or std.mem.indexOf(u8, bytes, "mailfail:1") != null;
        if (is_failure) {
            fault.attempts += 1;
            fault.attempted_fd = file.handle;
            fault.observed_connect_failure = std.mem.indexOf(u8, header, "ConnectFailed") != null;
            for (data) |bytes| fault.observed_connect_failure = fault.observed_connect_failure or std.mem.indexOf(u8, bytes, "ConnectFailed") != null;
            if (fault.reached) |event| event.set(std.testing.io);
            if (fault.proceed) |event| event.waitUncancelable(std.testing.io);
            if (fault.mode == .failed_write) return error.NoSpaceLeft;
        }
        return fault.original_write(userdata, file, header, data, splat, offset);
    }

    fn sync(userdata: ?*anyopaque, file: std.Io.File) std.Io.File.SyncError!void {
        const fault = mail_journal_fault.?;
        try fault.original_sync(userdata, file);
        if (fault.mode == .synced_then_error and fault.attempted_fd == file.handle) {
            // The actual backend sync succeeded. Returning an error afterwards
            // creates a genuine ambiguous caller receipt, not a guessed row.
            fault.synced += 1;
            return error.InputOutput;
        }
    }
};
threadlocal var mail_journal_fault: ?*MailJournalFault = null;

fn mailJournalFailureCausal(mode: @FieldType(MailJournalFault, "mode")) !void {
    // Test-only helper: raw-fd socket() has no libc-free Windows mapping yet.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var vtable = std.testing.io.vtable.*;
    var fault: MailJournalFault = .{ .mode = mode, .original_write = vtable.fileWritePositional, .original_sync = vtable.fileSync };
    mail_journal_fault = &fault;
    defer mail_journal_fault = null;
    vtable.fileWritePositional = MailJournalFault.write;
    vtable.fileSync = MailJournalFault.sync;
    const faulty_io: std.Io = .{ .userdata = std.testing.io.userdata, .vtable = &vtable };

    // Reserve an actual owned, bound but NON-listening loopback TCP socket.
    // This proves ConnectFailed without relying on port1 or another service.
    const sys = posix.system;
    const opened = sys.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, posix.IPPROTO.TCP);
    if (posix.errno(opened) != .SUCCESS) return error.TestUnexpectedResult;
    const fd: posix.fd_t = @intCast(opened);
    defer _ = sys.close(fd);
    var address: posix.sockaddr.in = .{ .port = 0, .addr = std.mem.nativeToBig(u32, 0x7F00_0001) };
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.bind(fd, @ptrCast(&address), @sizeOf(@TypeOf(address)))));
    var size: posix.socklen_t = @sizeOf(@TypeOf(address));
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.getsockname(fd, @ptrCast(&address), &size)));
    try std.testing.expectEqual(@as(posix.socklen_t, @sizeOf(@TypeOf(address))), size);
    const port = std.mem.bigToNative(u16, address.port);
    try std.testing.expect(port != 0);
    var sender = try Sender.init(a, .{
        .relay_host = "127.0.0.1",
        .relay_port = port,
        .ehlo_domain = "fixture.invalid",
        .from = "sender@fixture.invalid",
        .failure_wal = "pending.wal",
        .failure_io = faulty_io,
        .failure_dir = tmp.dir,
    });
    defer sender.deinit();
    const result = sender.settle("recipient@fixture.invalid", "retained subject", "accepted secret body");
    // Both cases reach the actual original recordFailure -> OroStore.put path.
    try std.testing.expectEqual(@as(usize, 1), fault.attempts);
    try std.testing.expectEqual(@as(usize, if (mode == .synced_then_error) 1 else 0), fault.synced);
    try std.testing.expect(fault.observed_connect_failure);
    try std.testing.expectEqual(@as(u64, 1), sender.failure_seq);
    var cold = try store_mod.OroStore.openReadOnlyWithConfig(a, std.testing.io, tmp.dir, "pending.wal", .{});
    defer cold.deinit();
    const row = cold.get(.props, "mailfail:1");
    if (mode == .failed_write) {
        try std.testing.expect(row == null);
    } else {
        const bytes = row orelse return error.TestUnexpectedResult;
        try std.testing.expect(std.mem.indexOf(u8, bytes, "recipient@fixture.invalid") != null);
        try std.testing.expect(std.mem.indexOf(u8, bytes, "ConnectFailed") != null);
    }
    std.debug.print("mail failure custody causal mode={s} attempts={d} actual_syncs={d} cold_row={any}\n", .{ @tagName(mode), fault.attempts, fault.synced, row != null });
    // The OLD API wrongly reports success and frees the accepted job in BOTH
    // cases. The repaired owner must retain a pending outcome and report it.
    try std.testing.expectError(error.FailureJournalPending, result);
}

fn pendingMailCaptureSweep(allocator: std.mem.Allocator, sender: *Sender) !void {
    var captured = try sender.captureUnstarted(allocator, 1024 * 1024);
    defer captured.deinit();
    const pending = captured.pending_failure orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("accepted secret body", pending.job.body);
    try std.testing.expectEqualStrings("retained subject", pending.job.subject);
    try std.testing.expectEqualStrings("ConnectFailed", pending.name());
    try std.testing.expectEqual(@as(u64, 1), pending.sequence);
}

fn mailPendingCustodyRepair(mode: @FieldType(MailJournalFault, "mode")) !void {
    // Test-only helper: raw-fd socket() has no libc-free Windows mapping yet.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var vtable = std.testing.io.vtable.*;
    var fault: MailJournalFault = .{ .mode = mode, .original_write = vtable.fileWritePositional, .original_sync = vtable.fileSync };
    mail_journal_fault = &fault;
    defer mail_journal_fault = null;
    vtable.fileWritePositional = MailJournalFault.write;
    vtable.fileSync = MailJournalFault.sync;
    const faulty_io: std.Io = .{ .userdata = std.testing.io.userdata, .vtable = &vtable };
    const sys = posix.system;
    const opened = sys.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, posix.IPPROTO.TCP);
    if (posix.errno(opened) != .SUCCESS) return error.TestUnexpectedResult;
    const fd: posix.fd_t = @intCast(opened);
    defer _ = sys.close(fd);
    var address: posix.sockaddr.in = .{ .port = 0, .addr = std.mem.nativeToBig(u32, 0x7F00_0001) };
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.bind(fd, @ptrCast(&address), @sizeOf(@TypeOf(address)))));
    var size: posix.socklen_t = @sizeOf(@TypeOf(address));
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.getsockname(fd, @ptrCast(&address), &size)));
    const config: Config = .{
        .relay_host = "127.0.0.1",
        .relay_port = std.mem.bigToNative(u16, address.port),
        .ehlo_domain = "fixture.invalid",
        .from = "sender@fixture.invalid",
        .failure_wal = "pending.wal",
        .failure_io = faulty_io,
        .failure_dir = tmp.dir,
    };
    var sender = try Sender.init(a, config);
    defer sender.deinit();
    try std.testing.expectError(error.FailureJournalPending, sender.settle("recipient@fixture.invalid", "retained subject", "accepted secret body"));
    try std.testing.expect(fault.observed_connect_failure);
    try std.testing.expectEqual(@as(usize, 1), fault.attempts);
    const original = sender.pending_failure.?.message.job;
    try std.testing.expectEqualStrings("accepted secret body", original.body);
    try std.testing.expectEqualStrings("ConnectFailed", sender.pending_failure.?.message.name());
    const fence = try sender.fenceProducers();
    try std.testing.expectError(error.FailureJournalPending, sender.requireSettled(fence));
    sender.enqueue("blocked", "blocked", "blocked");
    try std.testing.expectEqual(@as(usize, 0), sender.job_count);
    try std.testing.checkAllAllocationFailures(a, pendingMailCaptureSweep, .{&sender});
    var snapshot = try sender.captureUnstarted(a, 1024 * 1024);
    defer snapshot.deinit();
    try std.testing.expectEqual(@as(u64, 1), snapshot.failure_seq);
    var n: usize = 0;
    while (true) : (n += 1) {
        var failing = std.testing.FailingAllocator.init(a, .{});
        var restored = try Sender.init(failing.allocator(), config);
        defer restored.deinit();
        restored.enqueue("old@fixture.invalid", "OLD subject", "OLD secret");
        const old = restored.jobs[0];
        restored.failure_seq = 9;
        failing.fail_index = failing.alloc_index + n;
        restored.restoreSnapshot(&snapshot, 1024 * 1024) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expectEqual(@as(usize, 1), restored.job_count);
            try std.testing.expectEqual(@as(u64, 9), restored.failure_seq);
            try std.testing.expect(restored.pending_failure == null);
            try std.testing.expectEqual(@intFromPtr(old.body.ptr), @intFromPtr(restored.jobs[0].body.ptr));
            try std.testing.expectEqualStrings("OLD secret", restored.jobs[0].body);
            failing.fail_index = std.math.maxInt(usize);
            try restored.restoreSnapshot(&snapshot, 1024 * 1024);
            try std.testing.expectEqualStrings("accepted secret body", restored.pending_failure.?.message.job.body);
            continue;
        };
        try std.testing.expect(n > 0);
        const restored_fence = try restored.fenceProducers();
        try std.testing.expectError(error.FailureJournalPending, restored.requireSettled(restored_fence));
        // DTO alone cannot invent original descriptor/lease custody.
        try std.testing.expectError(error.FailureJournalPending, restored.reconcilePendingFailure(restored_fence));
        break;
    }
    try std.testing.expectEqual(@intFromPtr(original.body.ptr), @intFromPtr(sender.pending_failure.?.message.job.body.ptr));
    try std.testing.expectEqual(@as(u64, 1), sender.failure_seq);
    // Stop the test-only sync error after the independently observed ambiguity.
    // No new SMTP invocation or WAL append is allowed during reconciliation.
    fault.attempted_fd = null;
    if (mode == .failed_write) {
        try std.testing.expectError(error.FailureJournalPending, sender.reconcilePendingFailure(fence));
        try std.testing.expectEqual(@intFromPtr(original.body.ptr), @intFromPtr(sender.pending_failure.?.message.job.body.ptr));
    } else {
        try sender.reconcilePendingFailure(fence);
        try std.testing.expect(sender.pending_failure == null);
        try sender.requireSettled(fence);
    }
    try std.testing.expectEqual(@as(usize, 1), fault.attempts);
    try std.testing.expectEqual(@as(u64, 1), sender.failure_seq);
}

test "Windows mail ambiguous private WAL append replays its retained handle" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "mail", .default_dir);
    try os_runtime.protectEmptyDirectoryWindows(io, tmp.dir, "mail");

    var vtable = io.vtable.*;
    var fault: MailJournalFault = .{ .mode = .synced_then_error, .original_write = vtable.fileWritePositional, .original_sync = vtable.fileSync };
    mail_journal_fault = &fault;
    defer mail_journal_fault = null;
    vtable.fileWritePositional = MailJournalFault.write;
    vtable.fileSync = MailJournalFault.sync;
    const faulty_io: std.Io = .{ .userdata = io.userdata, .vtable = &vtable };
    var sender = try Sender.init(allocator, .{
        .relay_host = "203.0.113.5",
        .relay_port = 587,
        .ehlo_domain = "onyx.test",
        .from = "onyx@example.test",
        .user = "submit",
        .pass = "secret",
        .failure_wal = "mail/pending.wal",
        .failure_io = faulty_io,
        .failure_dir = tmp.dir,
        .private_failure_windows = true,
    });
    defer sender.deinit();
    try std.testing.expectError(error.FailureJournalPending, sender.settle("user@example.test", "verification", "retained secret code"));
    try std.testing.expectEqual(@as(usize, 1), fault.attempts);
    try std.testing.expectEqual(@as(usize, 1), fault.synced);
    try std.testing.expect(sender.pending_failure != null);
    try std.testing.expect(sender.pending_failure.?.cut != null);
    const fence = try sender.fenceProducers();
    defer sender.resumeProducers(fence) catch {};
    try std.testing.expectError(error.FailureJournalPending, sender.requireSettled(fence));

    // The caller saw a sync error after the backend actually persisted the row.
    // Remove the injected error, replay the exact held descriptor, and prove
    // the original outcome settles without another SMTP attempt or WAL append.
    fault.mode = .failed_write;
    try sender.reconcilePendingFailure(fence);
    try sender.requireSettled(fence);
    try std.testing.expect(sender.pending_failure == null);
    try std.testing.expectEqual(@as(usize, 1), fault.attempts);
    var store = try store_mod.OroStore.openPrivateWindowsWithConfig(allocator, io, tmp.dir, "mail/pending.wal", .{});
    defer store.deinit();
    const row = store.get(.props, "mailfail:1") orelse return error.TestUnexpectedResult;
    try std.testing.expect(std.mem.indexOf(u8, row, "UnverifiedAuthRelay") != null);
    try std.testing.expect(std.mem.indexOf(u8, row, "user@example.test") != null);
}

test "companion failure custody causal actual mail WAL write error cannot report settled" {
    try mailJournalFailureCausal(.failed_write);
}

test "companion failure custody causal actual mail synced append ambiguity cannot report settled" {
    try mailJournalFailureCausal(.synced_then_error);
}

test "companion failure custody mail absent append retains full job through every capture and restore OOM" {
    try mailPendingCustodyRepair(.failed_write);
}

test "companion failure custody mail synced ambiguity resolves exact held row without SMTP redelivery" {
    try mailPendingCustodyRepair(.synced_then_error);
}

test "companion failure custody mail source fence observes actual in-flight append before pending publication" {
    // Raw-fd socket() has no libc-free Windows mapping yet.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    const Context = struct {
        sender: *Sender,
        fault: *MailJournalFault,
        failure: ?anyerror = null,
        fn run(self: *@This()) void {
            mail_journal_fault = self.fault;
            defer mail_journal_fault = null;
            self.sender.settle("accepted@fixture.invalid", "accepted subject", "accepted body") catch |err| {
                self.failure = err;
            };
        }
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const sys = posix.system;
    const opened = sys.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, posix.IPPROTO.TCP);
    if (posix.errno(opened) != .SUCCESS) return error.TestUnexpectedResult;
    const fd: posix.fd_t = @intCast(opened);
    defer _ = sys.close(fd);
    var address: posix.sockaddr.in = .{ .port = 0, .addr = std.mem.nativeToBig(u32, 0x7F00_0001) };
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.bind(fd, @ptrCast(&address), @sizeOf(@TypeOf(address)))));
    var size: posix.socklen_t = @sizeOf(@TypeOf(address));
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.getsockname(fd, @ptrCast(&address), &size)));
    var reached: std.Io.Event = .unset;
    var proceed: std.Io.Event = .unset;
    var vtable = std.testing.io.vtable.*;
    var fault: MailJournalFault = .{
        .mode = .failed_write,
        .original_write = vtable.fileWritePositional,
        .original_sync = vtable.fileSync,
        .reached = &reached,
        .proceed = &proceed,
    };
    vtable.fileWritePositional = MailJournalFault.write;
    vtable.fileSync = MailJournalFault.sync;
    const io: std.Io = .{ .userdata = std.testing.io.userdata, .vtable = &vtable };
    var sender = try Sender.init(std.testing.allocator, .{
        .relay_host = "127.0.0.1",
        .relay_port = std.mem.bigToNative(u16, address.port),
        .ehlo_domain = "fixture.invalid",
        .from = "sender@fixture.invalid",
        .failure_wal = "pending.wal",
        .failure_io = io,
        .failure_dir = tmp.dir,
    });
    defer sender.deinit();
    var ctx: Context = .{ .sender = &sender, .fault = &fault };
    const thread = try std.Thread.spawn(.{}, Context.run, .{&ctx});
    var joined = false;
    defer if (!joined) {
        proceed.set(std.testing.io);
        thread.join();
    };
    try reached.waitTimeout(std.testing.io, .{ .deadline = std.Io.Clock.Timestamp.fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(3) }) });
    const fence = try sender.fenceProducers();
    try std.testing.expectError(error.OperationActive, sender.requireSettled(fence));
    try std.testing.expectError(error.OperationActive, sender.captureUnstarted(std.testing.allocator, 1024 * 1024));
    sender.enqueue("refused", "refused", "refused");
    proceed.set(std.testing.io);
    thread.join();
    joined = true;
    try std.testing.expectEqual(error.FailureJournalPending, ctx.failure.?);
    try std.testing.expectEqual(@as(usize, 1), fault.attempts);
    try std.testing.expectEqual(@as(usize, 0), sender.job_count);
    try std.testing.expectEqualStrings("accepted body", sender.pending_failure.?.message.job.body);
    try std.testing.expectError(error.FailureJournalPending, sender.requireSettled(fence));
    try sender.resumeProducers(fence);
    const newer = try sender.fenceProducers();
    try std.testing.expectError(error.InvalidProducerFence, sender.requireSettled(fence));
    try std.testing.expectError(error.FailureJournalPending, sender.requireSettled(newer));
}

test "companion failure custody mail synchronous allocation failures precede accepted job and failure sequence" {
    // Same platform bound as above: `FileNotFound` never surfaces elsewhere.
    const mail_os = @import("builtin").os.tag;
    if (comptime mail_os != .linux and mail_os != .openbsd and mail_os != .freebsd) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    for (0..3) |index| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        var sender = try Sender.init(failing.allocator(), .{
            .relay_host = "must.not.resolve.invalid",
            .ehlo_domain = "fixture.invalid",
            .from = "sender@fixture.invalid",
            .failure_wal = "unused.wal",
            .failure_io = std.testing.io,
            .failure_dir = tmp.dir,
        });
        defer sender.deinit();
        failing.fail_index = failing.alloc_index + index;
        try std.testing.expectError(error.OutOfMemory, sender.settle("to", "subject", "body"));
        try std.testing.expectEqual(@as(u64, 0), sender.failure_seq);
        try std.testing.expectEqual(@as(usize, 0), sender.active_settles.load(.acquire));
        try std.testing.expect(sender.pending_failure == null);
        try std.testing.expectError(error.FileNotFound, store_mod.openColdExisting(std.testing.io, tmp.dir, "unused.wal", .read_only));
        // A retry reaches the source admission path, with no consumed identity.
        failing.fail_index = std.math.maxInt(usize);
        sender.enqueue("retry", "retry", "retry");
        try std.testing.expectEqual(@as(usize, 1), sender.job_count);
        try std.testing.expectEqualStrings("retry", sender.jobs[sender.job_head].body);
    }
}
