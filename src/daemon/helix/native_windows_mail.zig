// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Windows Helix custody for settled SMTP queue and failure sequence. Pending
//! WAL ambiguity cannot be cloned: the original held journal descriptor must
//! stay with the predecessor, so source capture refuses it before COMMIT.
const std = @import("std");
const builtin = @import("builtin");
const mail = @import("../mail_sender.zig");
const runtime_pause = @import("../runtime_pause.zig");

const magic = "HXMA";
const version: u16 = 2;
const header_len: usize = 256;
const job_header_len: usize = 12;
pub const max_capture_bytes: usize = 4 * 1024 * 1024;
pub const max_checkpoint_bytes: usize = max_capture_bytes + header_len + mail.max_queued_jobs * job_header_len;
pub const Error = std.mem.Allocator.Error || error{ InvalidSnapshot, ConfigMismatch, TooLarge, PendingFailure };

comptime {
    if (mail.max_queued_jobs > std.math.maxInt(u16) or max_checkpoint_bytes > std.math.maxInt(u32))
        @compileError("Windows mail checkpoint exceeds its wire bounds");
}

pub fn isCheckpoint(bytes: []const u8) bool {
    return bytes.len >= magic.len and std.mem.eql(u8, bytes[0..magic.len], magic);
}

fn writeIdentity(out: []u8, id: @import("../store.zig").WindowsFileIdInfo) void {
    std.mem.writeInt(u64, out[0..8], id.volume_serial, .big);
    @memcpy(out[8..24], &id.file_id);
}
fn readIdentity(bytes: []const u8) @import("../store.zig").WindowsFileIdInfo {
    return .{ .volume_serial = std.mem.readInt(u64, bytes[0..8], .big), .file_id = bytes[8..24].* };
}
fn writeFileCut(out: []u8, cut: mail.PrivateFileCut) void {
    writeIdentity(out[0..24], cut.identity);
    std.mem.writeInt(u64, out[24..32], cut.length, .big);
    @memcpy(out[32..64], &cut.digest);
}
fn readFileCut(bytes: []const u8) mail.PrivateFileCut {
    return .{ .identity = readIdentity(bytes[0..24]), .length = std.mem.readInt(u64, bytes[24..32], .big), .digest = bytes[32..64].* };
}
fn writeWalCut(bytes: []u8, cut: ?mail.PrivateWalCut) void {
    if (cut) |value| {
        bytes[64] = 1;
        bytes[65] = @intFromBool(value.snapshot != null);
        writeIdentity(bytes[72..96], value.parent);
        @memcpy(bytes[96..128], &value.name_digest);
        writeFileCut(bytes[128..192], value.wal);
        if (value.snapshot) |snapshot| writeFileCut(bytes[192..256], snapshot);
    }
}
fn readWalCut(bytes: []const u8) ?mail.PrivateWalCut {
    if (bytes[64] == 0) return null;
    return .{ .parent = readIdentity(bytes[72..96]), .name_digest = bytes[96..128].*, .wal = readFileCut(bytes[128..192]), .snapshot = if (bytes[65] == 1) readFileCut(bytes[192..256]) else null };
}

const Header = struct { jobs: usize, execution: mail.Execution, failure_seq: u64, config_digest: [32]u8 };

fn header(bytes: []const u8) error{InvalidSnapshot}!Header {
    if (bytes.len < header_len or bytes.len > max_checkpoint_bytes or !isCheckpoint(bytes) or
        std.mem.readInt(u16, bytes[4..6], .big) != version or
        !std.mem.allEqual(u8, bytes[6..8], 0) or bytes[11] != 0 or
        std.mem.readInt(u32, bytes[52..56], .big) != bytes.len or
        !std.mem.allEqual(u8, bytes[56..64], 0) or bytes[64] > 1 or bytes[65] > 1 or
        !std.mem.allEqual(u8, bytes[66..72], 0) or
        (bytes[64] == 0 and !std.mem.allEqual(u8, bytes[65..256], 0)) or
        (bytes[64] == 1 and bytes[65] != 1)) return error.InvalidSnapshot;
    const jobs: usize = std.mem.readInt(u16, bytes[8..10], .big);
    if (jobs > mail.max_queued_jobs or bytes.len < header_len + jobs * job_header_len) return error.InvalidSnapshot;
    const execution = std.enums.fromInt(mail.Execution, bytes[10]) orelse return error.InvalidSnapshot;
    return .{ .jobs = jobs, .execution = execution, .failure_seq = std.mem.readInt(u64, bytes[12..20], .big), .config_digest = bytes[20..52].* };
}

fn take(bytes: []const u8, pos: *usize, len: usize) error{InvalidSnapshot}![]const u8 {
    if (len > bytes.len - pos.*) return error.InvalidSnapshot;
    const slice = bytes[pos.*..][0..len];
    pos.* += len;
    return slice;
}

/// Allocation-free structural validation. Identical queued messages are valid
/// physical FIFO entries and are deliberately never collapsed.
pub fn validateCheckpoint(bytes: []const u8) error{InvalidSnapshot}!void {
    const h = try header(bytes);
    var pos: usize = header_len;
    for (0..h.jobs) |_| {
        const lengths = try take(bytes, &pos, job_header_len);
        const to_len: usize = std.mem.readInt(u32, lengths[0..4], .big);
        const subject_len: usize = std.mem.readInt(u32, lengths[4..8], .big);
        const body_len: usize = std.mem.readInt(u32, lengths[8..12], .big);
        _ = try take(bytes, &pos, to_len);
        _ = try take(bytes, &pos, subject_len);
        _ = try take(bytes, &pos, body_len);
    }
    if (pos != bytes.len) return error.InvalidSnapshot;
}

fn checkSnapshot(snapshot: *const mail.Snapshot, config: mail.Config) Error!void {
    if (snapshot.pending_failure != null or snapshot.journal_cut != null) return error.PendingFailure;
    snapshot.validate(config, max_capture_bytes) catch |err| switch (err) {
        error.ConfigMismatch => return error.ConfigMismatch,
        error.Capacity => return error.TooLarge,
        else => return error.InvalidSnapshot,
    };
}

fn addLen(total: *usize, len: usize) Error!void {
    total.* = std.math.add(usize, total.*, len) catch return error.TooLarge;
    if (total.* > max_checkpoint_bytes) return error.TooLarge;
}

pub fn freeEncoded(allocator: std.mem.Allocator, bytes: []u8) void {
    std.crypto.secureZero(u8, bytes);
    allocator.free(bytes);
}

/// Owns cleartext verification mail until the caller wipes it with freeEncoded.
pub fn encodeSnapshot(allocator: std.mem.Allocator, snapshot: *const mail.Snapshot, config: mail.Config, cut: ?mail.PrivateWalCut) Error![]u8 {
    try checkSnapshot(snapshot, config);
    if (comptime builtin.os.tag == .windows) {
        if (config.private_failure_windows != (cut != null)) return error.InvalidSnapshot;
    }
    if (cut) |value| if (value.snapshot == null) return error.InvalidSnapshot;
    var total: usize = header_len;
    for (snapshot.jobs) |job| {
        if (job.to.len > std.math.maxInt(u32) or job.subject.len > std.math.maxInt(u32) or
            job.body.len > std.math.maxInt(u32)) return error.TooLarge;
        try addLen(&total, job_header_len);
        try addLen(&total, job.to.len);
        try addLen(&total, job.subject.len);
        try addLen(&total, job.body.len);
    }
    const bytes = try allocator.alloc(u8, total);
    errdefer freeEncoded(allocator, bytes);
    @memset(bytes, 0);
    @memcpy(bytes[0..4], magic);
    std.mem.writeInt(u16, bytes[4..6], version, .big);
    std.mem.writeInt(u16, bytes[8..10], @intCast(snapshot.jobs.len), .big);
    bytes[10] = @intFromEnum(snapshot.execution);
    std.mem.writeInt(u64, bytes[12..20], snapshot.failure_seq, .big);
    @memcpy(bytes[20..52], &snapshot.config_digest);
    std.mem.writeInt(u32, bytes[52..56], @intCast(total), .big);
    writeWalCut(bytes, cut);
    var pos: usize = header_len;
    for (snapshot.jobs) |job| {
        std.mem.writeInt(u32, bytes[pos..][0..4], @intCast(job.to.len), .big);
        std.mem.writeInt(u32, bytes[pos + 4 ..][0..4], @intCast(job.subject.len), .big);
        std.mem.writeInt(u32, bytes[pos + 8 ..][0..4], @intCast(job.body.len), .big);
        pos += job_header_len;
        @memcpy(bytes[pos..][0..job.to.len], job.to);
        pos += job.to.len;
        @memcpy(bytes[pos..][0..job.subject.len], job.subject);
        pos += job.subject.len;
        @memcpy(bytes[pos..][0..job.body.len], job.body);
        pos += job.body.len;
    }
    std.debug.assert(pos == bytes.len);
    try validateCheckpoint(bytes);
    return bytes;
}

fn wipeBytes(allocator: std.mem.Allocator, bytes: []u8) void {
    std.crypto.secureZero(u8, bytes);
    allocator.free(bytes);
}
fn wipeJob(allocator: std.mem.Allocator, job: mail.QueuedMessage) void {
    wipeBytes(allocator, job.to);
    wipeBytes(allocator, job.subject);
    wipeBytes(allocator, job.body);
}

pub fn decodeSnapshot(allocator: std.mem.Allocator, bytes: []const u8, config: mail.Config) Error!mail.Snapshot {
    try validateCheckpoint(bytes);
    const h = try header(bytes);
    if (comptime builtin.os.tag == .windows) {
        if (config.private_failure_windows != (bytes[64] == 1)) return error.InvalidSnapshot;
    }
    const expected = mail.configDigest(config) catch return error.ConfigMismatch;
    if (!std.crypto.timing_safe.eql([32]u8, expected, h.config_digest)) return error.ConfigMismatch;
    const jobs = try allocator.alloc(mail.QueuedMessage, h.jobs);
    var copied: usize = 0;
    errdefer {
        for (jobs[0..copied]) |job| wipeJob(allocator, job);
        allocator.free(jobs);
    }
    var pos: usize = header_len;
    for (jobs) |*job| {
        const lengths = try take(bytes, &pos, job_header_len);
        const to_len: usize = std.mem.readInt(u32, lengths[0..4], .big);
        const subject_len: usize = std.mem.readInt(u32, lengths[4..8], .big);
        const body_len: usize = std.mem.readInt(u32, lengths[8..12], .big);
        const to = try allocator.dupe(u8, try take(bytes, &pos, to_len));
        errdefer wipeBytes(allocator, to);
        const subject = try allocator.dupe(u8, try take(bytes, &pos, subject_len));
        errdefer wipeBytes(allocator, subject);
        const body = try allocator.dupe(u8, try take(bytes, &pos, body_len));
        job.* = .{ .to = to, .subject = subject, .body = body };
        copied += 1;
    }
    std.debug.assert(pos == bytes.len);
    const snapshot: mail.Snapshot = .{ .allocator = allocator, .jobs = jobs, .failure_seq = h.failure_seq, .config_digest = h.config_digest, .execution = h.execution };
    try checkSnapshot(&snapshot, config);
    return snapshot;
}

/// Capture only after server's accepted-event cut has frozen producers and
/// the real source worker is paused or proven unstarted. A pending WAL outcome
/// aborts before a checkpoint is emitted; the source retains its held handle.
pub fn captureFrozenEncoded(allocator: std.mem.Allocator, owner: *mail.Sender, fence: runtime_pause.ProducerFence, token: ?runtime_pause.Token) ![]u8 {
    var snapshot = try owner.captureFrozen(allocator, fence, token, max_capture_bytes);
    defer snapshot.deinit();
    try checkSnapshot(&snapshot, owner.config);
    const cut: ?mail.PrivateWalCut = if (comptime builtin.os.tag == .windows) blk: {
        if (owner.config.private_failure_windows) break :blk try owner.capturePrivateWalCut(fence, token);
        break :blk null;
    } else null;
    return encodeSnapshot(allocator, &snapshot, owner.config, cut);
}

pub fn restoreEncoded(allocator: std.mem.Allocator, owner: *mail.Sender, bytes: []const u8) !void {
    var snapshot = try decodeSnapshot(allocator, bytes, owner.config);
    defer snapshot.deinit();
    var staged = false;
    errdefer if (staged) owner.releaseStagedWalCut();
    if (comptime builtin.os.tag == .windows) {
        if (readWalCut(bytes)) |cut| {
            try owner.stagePrivateWalCut(cut);
            staged = true;
        }
    }
    try owner.restoreSnapshot(&snapshot, max_capture_bytes);
}

pub fn restoreEncodedParked(allocator: std.mem.Allocator, owner: *mail.Sender, bytes: []const u8) !void {
    var snapshot = try decodeSnapshot(allocator, bytes, owner.config);
    defer snapshot.deinit();
    var staged = false;
    errdefer if (staged) owner.releaseStagedWalCut();
    if (comptime builtin.os.tag == .windows) {
        if (readWalCut(bytes)) |cut| {
            try owner.stagePrivateWalCut(cut);
            staged = true;
        }
    }
    try owner.restoreSnapshotParked(&snapshot, max_capture_bytes);
}

const test_config: mail.Config = .{
    .relay_host = "relay.fixture.invalid",
    .ehlo_domain = "node.fixture.invalid",
    .from = "noreply@fixture.invalid",
};

fn decodeAllocation(allocator: std.mem.Allocator, bytes: []const u8) !void {
    var snapshot = try decodeSnapshot(allocator, bytes, test_config);
    defer snapshot.deinit();
    try std.testing.expectEqualStrings("secret body 1", snapshot.jobs[0].body);
}

test "Windows MAIL checkpoint preserves FIFO failure sequence and refuses pending WAL ambiguity" {
    const allocator = std.testing.allocator;
    var source = try mail.Sender.init(allocator, test_config);
    defer source.deinit();
    source.enqueue("alice@fixture.invalid", "verification 1", "secret body 1");
    source.enqueue("alice@fixture.invalid", "verification 1", "secret body 1");
    source.enqueue("bob@fixture.invalid", "verification 2", "secret body 2");
    source.failure_seq = 42;
    const fence = try source.fenceProducers();
    defer source.resumeProducers(fence) catch unreachable;
    const bytes = try captureFrozenEncoded(allocator, &source, fence, null);
    defer freeEncoded(allocator, bytes);
    try validateCheckpoint(bytes);
    try std.testing.checkAllAllocationFailures(allocator, decodeAllocation, .{bytes});
    var snapshot = try decodeSnapshot(allocator, bytes, test_config);
    defer snapshot.deinit();
    try std.testing.expectEqual(@as(usize, 3), snapshot.jobs.len);
    try std.testing.expectEqual(@as(u64, 42), snapshot.failure_seq);
    try std.testing.expectEqualStrings("alice@fixture.invalid", snapshot.jobs[0].to);
    try std.testing.expectEqualStrings("alice@fixture.invalid", snapshot.jobs[1].to);
    try std.testing.expectEqualStrings("bob@fixture.invalid", snapshot.jobs[2].to);
    var changed = test_config;
    changed.relay_port += 1;
    try std.testing.expectError(error.ConfigMismatch, decodeSnapshot(allocator, bytes, changed));

    const bad = try allocator.dupe(u8, bytes);
    defer allocator.free(bad);
    std.mem.writeInt(u16, bad[8..10], @intCast(mail.max_queued_jobs + 1), .big);
    try std.testing.expectError(error.InvalidSnapshot, validateCheckpoint(bad));
    std.mem.writeInt(u16, bad[8..10], 3, .big);
    std.mem.writeInt(u32, bad[header_len..][0..4], std.math.maxInt(u32), .big);
    try std.testing.expectError(error.InvalidSnapshot, validateCheckpoint(bad));

    snapshot.pending_failure = .{ .job = .{
        .to = try allocator.dupe(u8, "retained@fixture.invalid"),
        .subject = try allocator.dupe(u8, "pending"),
        .body = try allocator.dupe(u8, "ambiguous WAL body"),
    }, .sequence = snapshot.failure_seq };
    try std.testing.expectError(error.PendingFailure, encodeSnapshot(allocator, &snapshot, test_config, null));
}

test "Windows MAIL checkpoint source fence and parked candidate preserve queue on refusal" {
    const allocator = std.testing.allocator;
    var source = try mail.Sender.init(allocator, test_config);
    defer source.deinit();
    source.enqueue("alice@fixture.invalid", "verification", "secret body 1");
    source.failure_seq = 27;
    const fence = try source.fenceProducers();
    defer source.resumeProducers(fence) catch unreachable;
    const bytes = try captureFrozenEncoded(allocator, &source, fence, null);
    defer freeEncoded(allocator, bytes);

    var candidate = try mail.Sender.init(allocator, test_config);
    try candidate.prepareColdResources(std.testing.io);
    const specs = [_]runtime_pause.start_gate.ParticipantSpec{.{ .kind = .mail, .instance = 0, .owner_identity = &candidate }};
    const gate = try runtime_pause.start_gate.create(allocator, std.testing.io, &specs);
    defer {
        candidate.requestStopAndWake();
        if (gate.view.inspect().phase == .preparing) gate.control.cancelAllAndJoin() else gate.control.joinAll();
        candidate.detachAfterJoined() catch unreachable;
        candidate.deinit();
        gate.control.destroyJoined();
    }
    try std.testing.expectError(error.NotPrepared, restoreEncodedParked(allocator, &candidate, bytes));
    try std.testing.expectEqual(@as(usize, 0), candidate.job_count);
    try candidate.prepareDormantWorker(gate.control, gate.view, try gate.view.slot(.mail, 0, &candidate));
    try gate.control.awaitAllParked(std.Io.Clock.Timestamp.fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
    try restoreEncodedParked(allocator, &candidate, bytes);
    try std.testing.expectEqual(@as(usize, 1), candidate.job_count);
    try std.testing.expectEqual(@as(u64, 27), candidate.failure_seq);
    const bad = try allocator.dupe(u8, bytes);
    defer allocator.free(bad);
    bad[11] = 1;
    try std.testing.expectError(error.InvalidSnapshot, restoreEncodedParked(allocator, &candidate, bad));
    try std.testing.expectEqual(@as(usize, 1), candidate.job_count);
    try candidate.requireParked();
}

test "Windows MAIL private WAL cut pins exact directory and file through candidate stage" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const os_runtime = @import("../os_runtime.zig");
    const store = @import("../store.zig");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try os_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    private.close(std.testing.io);
    const config = mail.Config{
        .relay_host = "relay.fixture.invalid",
        .ehlo_domain = "node.fixture.invalid",
        .from = "noreply@fixture.invalid",
        .failure_wal = "private/mail.wal",
        .failure_io = std.testing.io,
        .failure_dir = tmp.dir,
        .private_failure_windows = true,
    };
    var source = try mail.Sender.init(allocator, config);
    defer source.deinit();
    source.enqueue("alice@fixture.invalid", "verification", "secret body 1");
    const fence = try source.fenceProducers();
    defer source.resumeProducers(fence) catch unreachable;
    const bytes = try captureFrozenEncoded(allocator, &source, fence, null);
    defer freeEncoded(allocator, bytes);
    try std.testing.expectEqual(@as(u8, 1), bytes[64]);
    try std.testing.expectEqual(@as(u8, 1), bytes[65]);
    try std.testing.expectEqual(@as(u64, 0), std.mem.readInt(u64, bytes[152..160], .big));
    try std.testing.expectEqual(@as(u64, 0), std.mem.readInt(u64, bytes[216..224], .big));

    var candidate = try mail.Sender.init(allocator, config);
    defer candidate.deinit();
    try restoreEncoded(allocator, &candidate, bytes);
    try candidate.requireStagedWalCut();
    try std.testing.expectEqual(@as(usize, 1), candidate.job_count);
    try std.testing.expectError(error.FileBusy, os_runtime.openExistingPrivateWindows(source.private_failure_dir.?, "mail.wal", .verify_only));
    try std.testing.expectError(error.FileBusy, os_runtime.openExistingPrivateWindows(source.private_failure_dir.?, "mail.wal.snap", .verify_only));
    const altered = try allocator.dupe(u8, bytes);
    defer freeEncoded(allocator, altered);
    altered[136] ^= 1;
    candidate.releaseStagedWalCut();
    try std.testing.expectError(error.JournalCustodyMismatch, restoreEncoded(allocator, &candidate, altered));
    try std.testing.expectEqual(@as(usize, 1), candidate.job_count);
    altered[136] ^= 1;
    altered[200] ^= 1;
    try std.testing.expectError(error.JournalCustodyMismatch, restoreEncoded(allocator, &candidate, altered));
    altered[200] ^= 1;
    var changed_snapshot = try os_runtime.openExistingPrivateWindows(source.private_failure_dir.?, "mail.wal.snap", .remediate_read_write);
    try changed_snapshot.writePositionalAll(std.testing.io, "X", 0);
    try changed_snapshot.sync(std.testing.io);
    changed_snapshot.close(std.testing.io);
    try std.testing.expectError(error.JournalCustodyMismatch, candidate.stagePrivateWalCut(readWalCut(bytes).?));
    changed_snapshot = try os_runtime.openExistingPrivateWindows(source.private_failure_dir.?, "mail.wal.snap", .remediate_read_write);
    try changed_snapshot.setLength(std.testing.io, 0);
    try changed_snapshot.sync(std.testing.io);
    changed_snapshot.close(std.testing.io);
    try candidate.stagePrivateWalCut(readWalCut(bytes).?);
    try candidate.requireStagedWalCut();
    candidate.releaseStagedWalCut();
    // A zero-length private WAL is an ordinary OroStore input: it receives its
    // epoch when the next real failure opens the store, not at upgrade preflight.
    var opened = try store.OroStore.openPrivateWindowsWithConfig(allocator, std.testing.io, source.private_failure_dir.?, "mail.wal", .{});
    defer opened.deinit();
    try opened.put(.props, "proof", "valid");
}
