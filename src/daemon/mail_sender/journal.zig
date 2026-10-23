// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact failure-journal identity, transcript, and retained-file checks.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const smtp_client = @import("../../proto/smtp_client.zig");
const os_runtime = @import("../os_runtime.zig");
const store_mod = @import("../store.zig");
const journal_custody = @import("../mesh_presence_lease.zig");
const FailedMessage = @import("model.zig").FailedMessage;
const FileCut = @import("model.zig").FileCut;
const JournalCut = @import("model.zig").JournalCut;
const PrivateFileCut = @import("model.zig").PrivateFileCut;

pub fn failureValue(buffer: []u8, message: *const FailedMessage) ![]const u8 {
    return std.fmt.bufPrint(buffer, "{s} {s}", .{ message.name(), message.job.to[0..@min(message.job.to.len, 80)] });
}

pub fn captureFileCut(file: std.Io.File, io: std.Io) !FileCut {
    const before = try file.stat(io);
    if (before.kind != .file) return error.NotRegular;
    // Windows FileIndex is unique within one filesystem. The mail WAL and its
    // snapshot are resolved as basenames from one retained private directory
    // HANDLE, and the WAL itself remains open with no sharing.
    const identity: journal_custody.Identity = if (comptime builtin.os.tag == .windows)
        .{ .device = 0, .inode = @intCast(before.inode) }
    else
        try journal_custody.statRegular(file.handle);
    const size = before.size;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [4096]u8 = undefined;
    var offset: u64 = 0;
    while (offset < size) {
        const len: usize = @intCast(@min(size - offset, buffer.len));
        if (try file.readPositionalAll(io, buffer[0..len], offset) != len) return error.JournalCustodyMismatch;
        hash.update(buffer[0..len]);
        offset += len;
    }
    if (comptime builtin.os.tag == .windows) {
        const after = try file.stat(io);
        if (after.kind != .file or after.inode != before.inode or after.size != size) return error.JournalCustodyMismatch;
    } else {
        const after = try journal_custody.statRegular(file.handle);
        if (identity.device != after.device or identity.inode != after.inode or (try file.stat(io)).size != size) return error.JournalCustodyMismatch;
    }
    return .{ .identity = identity, .length = size, .digest = hash.finalResult() };
}

pub fn fileCutEqual(a: FileCut, b: FileCut) bool {
    return a.identity.device == b.identity.device and a.identity.inode == b.identity.inode and a.length == b.length and std.mem.eql(u8, &a.digest, &b.digest);
}

const private_file_id_info_class: i32 = 18;

const max_private_cut_bytes: u64 = 512 * 1024 * 1024;
extern "kernel32" fn GetFileInformationByHandleEx(handle: usize, class: i32, info: *anyopaque, size: u32) callconv(.winapi) i32;

pub fn privateFileIdentity(handle: usize) !store_mod.WindowsFileIdInfo {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    var info: store_mod.WindowsFileIdInfo = undefined;
    if (GetFileInformationByHandleEx(handle, private_file_id_info_class, &info, @sizeOf(@TypeOf(info))) == 0)
        return error.JournalCustodyMismatch;
    return info;
}

pub fn privateNameDigest(name: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(name, &digest, .{});
    return digest;
}

pub fn privateSnapshotName(name: []const u8, buffer: *[512]u8) ![]const u8 {
    return std.fmt.bufPrint(buffer, "{s}.snap", .{name});
}

pub fn privateFileCut(file: std.Io.File, io: std.Io) !PrivateFileCut {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    const identity = try privateFileIdentity(@intFromPtr(file.handle));
    const stat = try file.stat(io);
    if (stat.kind != .file or stat.size > max_private_cut_bytes) return error.JournalCustodyMismatch;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [4096]u8 = undefined;
    var offset: u64 = 0;
    while (offset < stat.size) {
        const len: usize = @intCast(@min(stat.size - offset, buffer.len));
        if (try file.readPositionalAll(io, buffer[0..len], offset) != len) return error.JournalCustodyMismatch;
        hash.update(buffer[0..len]);
        offset += len;
    }
    const after = try file.stat(io);
    if (after.kind != .file or after.size != stat.size or
        !std.meta.eql(identity, try privateFileIdentity(@intFromPtr(file.handle)))) return error.JournalCustodyMismatch;
    return .{ .identity = identity, .length = stat.size, .digest = hash.finalResult() };
}

pub fn privateFileCutEqual(a: PrivateFileCut, b: PrivateFileCut) bool {
    return std.meta.eql(a.identity, b.identity) and a.length == b.length and std.mem.eql(u8, &a.digest, &b.digest);
}

fn captureSnapshotCut(journal: *store_mod.OroStore) !?FileCut {
    if (comptime builtin.os.tag == .windows) {
        if (!journal.private_windows_files) return error.InsecureFailureJournal;
        const file = os_runtime.openExistingPrivateWindows(journal.dir, journal.snapshot_path, .verify_only) catch |err| {
            if (err == error.FileNotFound) return null;
            return err;
        };
        defer file.close(journal.io);
        return try captureFileCut(file, journal.io);
    }
    // `openColdExisting` only supports linux/openbsd/freebsd; elsewhere it
    // returns `Unsupported` (never `FileNotFound`), so compare instead of
    // switching — a `FileNotFound` prong does not compile on those targets.
    const file = store_mod.openColdExisting(journal.io, journal.dir, journal.snapshot_path, .read_only) catch |err| {
        if (err == error.FileNotFound) return null;
        return err;
    };
    defer file.close(journal.io);
    return try captureFileCut(file, journal.io);
}

pub fn captureJournalCut(journal: *store_mod.OroStore) !JournalCut {
    return .{ .wal = try captureFileCut(journal.wal_file orelse return error.FailureJournalPending, journal.io), .snapshot = try captureSnapshotCut(journal) };
}

pub fn requireJournalCut(journal: *store_mod.OroStore, expected: JournalCut) !void {
    const held = try captureJournalCut(journal);
    if (!fileCutEqual(held.wal, expected.wal)) return error.JournalCustodyMismatch;
    if (expected.snapshot) |snapshot| {
        if (!fileCutEqual(held.snapshot orelse return error.JournalCustodyMismatch, snapshot)) return error.JournalCustodyMismatch;
    } else if (held.snapshot != null) return error.JournalCustodyMismatch;
    if (comptime builtin.os.tag == .windows) {
        if (!journal.private_windows_files) return error.InsecureFailureJournal;
        return;
    }
    const file = try store_mod.openColdExisting(journal.io, journal.dir, journal.wal_path, .read_only);
    defer file.close(journal.io);
    if (!fileCutEqual(try captureFileCut(file, journal.io), expected.wal)) return error.JournalCustodyMismatch;
}
