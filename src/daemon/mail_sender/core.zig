// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Mail worker and failure-journal owner; lifecycle and publication stay together.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const smtp_client = @import("../../proto/smtp_client.zig");
const tls_client = @import("../../crypto/tls_client.zig");
const tls_client_failure = @import("../tls_client_failure.zig");
const os_runtime = @import("../os_runtime.zig");
const platform = @import("../../substrate/platform.zig");
const store_mod = @import("../store.zig");
const runtime_pause = @import("../runtime_pause.zig");
const testing = std.testing;

/// RFC 8701 GREASE stays on for this outbound TLS 1.3 client so peers that
/// mishandle unknown values are found early; GREASE ECH stays off because the
/// daemon holds no ECHConfig for these hosts (draft-ietf-tls-esni §6.2).
pub const outbound_grease = true;
pub const outbound_ech_grease = false;
const Config = @import("config.zig").Config;
const configDigest = @import("config.zig").configDigest;
const dormant_spawn_options = @import("limits.zig").dormant_spawn_options;
const job_capacity = @import("limits.zig").job_capacity;
const io_timeout_ms = @import("limits.zig").io_timeout_ms;
const max_message_len = @import("limits.zig").max_message_len;
const max_tls_record = @import("limits.zig").max_tls_record;
const max_smtp_iterations = @import("limits.zig").max_smtp_iterations;
const max_job_ms = @import("limits.zig").max_job_ms;
const Job = @import("model.zig").Job;
const FailedMessage = @import("model.zig").FailedMessage;
const PrivateWalCut = @import("model.zig").PrivateWalCut;
const PrivateWalStage = @import("model.zig").PrivateWalStage;
const PendingFailure = @import("model.zig").PendingFailure;
const ProducerFence = @import("model.zig").ProducerFence;
const Execution = @import("model.zig").Execution;
const cloneJob = @import("model.zig").cloneJob;
const jobBytes = @import("model.zig").jobBytes;
const buildMessage = @import("message.zig").buildMessage;
const wallClockSeconds = @import("message.zig").wallClockSeconds;
const sendTlsFatal = @import("tls_records.zig").sendTlsFatal;
const frameRecordLen = @import("tls_records.zig").frameRecordLen;
const consumePrefix = @import("tls_records.zig").consumePrefix;
const resolveRelayAddress = @import("resolution.zig").resolveRelayAddress;
const connectRelayAddress = @import("resolution.zig").connectRelayAddress;
const Socket = @import("native_io.zig").Socket;
const setRecvTimeout = @import("native_io.zig").setRecvTimeout;
const closeFd = @import("native_io.zig").closeFd;
const writeAll = @import("native_io.zig").writeAll;
const readSome = @import("native_io.zig").readSome;
const win = @import("windows_abi.zig").win;
const Snapshot = @import("checkpoint.zig").Snapshot;
const failureValue = @import("journal.zig").failureValue;
const captureFileCut = @import("journal.zig").captureFileCut;
const fileCutEqual = @import("journal.zig").fileCutEqual;
const privateFileIdentity = @import("journal.zig").privateFileIdentity;
const privateNameDigest = @import("journal.zig").privateNameDigest;
const privateSnapshotName = @import("journal.zig").privateSnapshotName;
const privateFileCut = @import("journal.zig").privateFileCut;
const privateFileCutEqual = @import("journal.zig").privateFileCutEqual;
const captureJournalCut = @import("journal.zig").captureJournalCut;
const requireJournalCut = @import("journal.zig").requireJournalCut;

pub const Sender = struct {
    allocator: std.mem.Allocator,
    config: Config,
    mutex: std.atomic.Mutex = .unlocked,
    stop_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    thread: ?std.Thread = null,
    runtime: runtime_pause.WorkerState = .{},
    active_settles: std.atomic.Value(usize) = .init(0),
    jobs: []Job,
    job_head: usize = 0,
    job_tail: usize = 0,
    job_count: usize = 0,
    failure_seq: u64 = 0,
    producers: runtime_pause.ProducerState = .{},
    pending_failure: ?PendingFailure = null,
    /// The Windows failure WAL always resolves beneath this retained private
    /// directory HANDLE, even if an ancestor pathname changes after boot.
    private_failure_dir: ?std.Io.Dir = null,
    private_wal_stage: ?PrivateWalStage = null,

    pub fn init(allocator: std.mem.Allocator, config: Config) !Sender {
        if ((config.failure_wal == null) != (config.failure_io == null)) return error.InvalidConfig;
        var private_dir: ?std.Io.Dir = null;
        if (comptime builtin.os.tag == .windows) {
            if (config.private_failure_windows) {
                const wal = config.failure_wal orelse return error.InvalidConfig;
                const io = config.failure_io orelse return error.InvalidConfig;
                private_dir = try os_runtime.openPrivateDirectoryWindows(io, config.failure_dir orelse std.Io.Dir.cwd(), std.fs.path.dirname(wal) orelse ".");
            }
        }
        errdefer if (private_dir) |dir| dir.close(config.failure_io.?);
        const jobs = try allocator.alloc(Job, job_capacity);
        return .{ .allocator = allocator, .config = config, .jobs = jobs, .private_failure_dir = private_dir };
    }

    pub fn prepareColdResources(self: *Sender, io: std.Io) !void {
        if (self.thread != null or self.runtime.view != null) return error.AlreadyStarted;
        if (comptime builtin.os.tag == .windows) {
            if (self.config.failure_wal != null and !self.config.private_failure_windows) return error.InsecureFailureJournal;
        }
        _ = try configDigest(self.config);
        try self.runtime.pause.bindIo(io);
    }
    pub fn validateDormantRegistration(self: *Sender, control: *runtime_pause.start_gate.Control, view: *const runtime_pause.start_gate.View, slot: runtime_pause.start_gate.Slot) !void {
        try self.runtime.validateRegistration(control, view, slot, .mail, 0, self, dormant_spawn_options);
    }
    pub fn prepareDormantWorker(self: *Sender, control: *runtime_pause.start_gate.Control, view: *const runtime_pause.start_gate.View, slot: runtime_pause.start_gate.Slot) !void {
        try self.runtime.validatePreparation(control, view, slot, .mail, 0, self, dormant_spawn_options);
        if (self.thread != null) return error.AlreadyStarted;
        if (self.config.relay_host.len == 0 or self.config.from.len == 0) return error.NotConfigured;
        if (comptime builtin.os.tag == .windows) {
            if (self.config.failure_wal != null and !self.config.private_failure_windows) return error.InsecureFailureJournal;
        }
        self.stop_flag.store(false, .release);
        try self.runtime.prepare(control, view, slot, .mail, 0, Sender, self, worker, dormant_spawn_options);
    }
    /// Signals this owner only. Runtime Control owns all actual joins.
    pub fn requestStopAndWake(self: *Sender) void {
        self.stop_flag.store(true, .release);
        self.runtime.wakeForStop();
    }
    pub fn detachAfterJoined(self: *Sender) !void {
        try self.runtime.detachAfterJoined();
    }
    pub fn requireParked(self: *Sender) !void {
        try self.runtime.requireParked();
    }
    pub fn requireActivated(self: *Sender) !void {
        if (self.stop_flag.load(.acquire)) return error.Stopped;
        try self.runtime.requireActivated();
    }
    pub fn requestPause(self: *Sender, epoch: u64) !runtime_pause.Token {
        return self.runtime.pause.request(epoch);
    }
    pub fn awaitPaused(self: *Sender, token: runtime_pause.Token, deadline: std.Io.Clock.Timestamp) !void {
        try self.runtime.pause.awaitPaused(token, deadline);
    }
    pub fn resumePaused(self: *Sender, token: runtime_pause.Token) !void {
        try self.runtime.pause.resumePaused(token);
    }
    fn requireCaptureCut(self: *Sender, token: ?runtime_pause.Token) !Execution {
        if (self.active_settles.load(.acquire) != 0) return error.OperationActive;
        if (token) |actual| {
            if (self.thread == null and self.runtime.view == null) return error.NotRunning;
            try self.runtime.pause.requirePaused(actual);
            return .paused;
        }
        if (self.thread != null or self.runtime.view != null) return error.NotQuiescent;
        return .unstarted;
    }
    pub fn capturePaused(self: *Sender, allocator: std.mem.Allocator, token: runtime_pause.Token, max_bytes: usize) !Snapshot {
        return self.captureCut(allocator, token, null, max_bytes);
    }
    pub fn captureUnstarted(self: *Sender, allocator: std.mem.Allocator, max_bytes: usize) !Snapshot {
        return self.captureCut(allocator, null, null, max_bytes);
    }
    /// Source-issued producer fence is rechecked under the exact data lock
    /// used for capture; no unlocked empty-queue observation grants custody.
    pub fn captureFrozen(self: *Sender, allocator: std.mem.Allocator, fence: runtime_pause.ProducerFence, token: ?runtime_pause.Token, max_bytes: usize) !Snapshot {
        try self.requireProducersFrozen(fence);
        return self.captureCut(allocator, token, fence, max_bytes);
    }
    fn captureCut(self: *Sender, allocator: std.mem.Allocator, token: ?runtime_pause.Token, fence: ?runtime_pause.ProducerFence, max_bytes: usize) !Snapshot {
        const execution = try self.requireCaptureCut(token);
        const digest = try configDigest(self.config);
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (fence) |proof| try self.producers.requireLocked(proof);
        _ = try self.requireCaptureCut(token);
        if (self.job_count > job_capacity) return error.InvalidState;
        var bytes = @sizeOf(Snapshot) + self.job_count * @sizeOf(Job);
        for (0..self.job_count) |i| {
            const job = self.jobs[(self.job_head + i) % job_capacity];
            bytes = std.math.add(usize, bytes, job.to.len) catch return error.Capacity;
            bytes = std.math.add(usize, bytes, job.subject.len) catch return error.Capacity;
            bytes = std.math.add(usize, bytes, job.body.len) catch return error.Capacity;
        }
        if (self.pending_failure) |pending| bytes = try jobBytes(bytes, pending.message.job);
        if (bytes > max_bytes) return error.Capacity;
        const jobs = try allocator.alloc(Job, self.job_count);
        errdefer allocator.free(jobs);
        var copied: usize = 0;
        errdefer for (jobs[0..copied]) |job| job.free(allocator);
        for (0..self.job_count) |i| {
            jobs[i] = try cloneJob(allocator, self.jobs[(self.job_head + i) % job_capacity]);
            copied += 1;
        }
        var failed: ?FailedMessage = null;
        if (self.pending_failure) |pending| {
            failed = pending.message;
            failed.?.job = try cloneJob(allocator, pending.message.job);
        }
        return .{ .allocator = allocator, .jobs = jobs, .failure_seq = self.failure_seq, .config_digest = digest, .execution = execution, .pending_failure = failed, .journal_cut = if (self.pending_failure) |pending| pending.cut else null };
    }
    /// All candidate bytes are allocated before replacing the accepted queue.
    /// Failure preserves the actual owner's sequence, payloads and FIFO.
    pub fn restoreSnapshot(self: *Sender, snapshot: *const Snapshot, max_bytes: usize) !void {
        try self.restoreSnapshotAt(snapshot, max_bytes, false);
    }
    /// Candidate's real mail worker must be parked behind the shared Gate.
    /// The original WAL descriptor cannot be reconstructed from a snapshot;
    /// Windows Helix callers reject pending_failure before using this method.
    pub fn restoreSnapshotParked(self: *Sender, snapshot: *const Snapshot, max_bytes: usize) !void {
        try self.restoreSnapshotAt(snapshot, max_bytes, true);
    }
    fn requireRestoreCut(self: *Sender, comptime parked: bool) !void {
        if (self.thread != null or self.runtime.pause.request_epoch != 0 or
            self.active_settles.load(.acquire) != 0 or self.stop_flag.load(.acquire)) return error.AlreadyStarted;
        if (parked) {
            try self.runtime.requireParked();
        } else if (self.runtime.view != null) return error.AlreadyStarted;
    }
    fn restoreSnapshotAt(self: *Sender, snapshot: *const Snapshot, max_bytes: usize, comptime parked: bool) !void {
        try self.requireRestoreCut(parked);
        try snapshot.validate(self.config, max_bytes);
        const candidate = try self.allocator.alloc(Job, snapshot.jobs.len);
        defer self.allocator.free(candidate);
        var copied: usize = 0;
        errdefer for (candidate[0..copied]) |job| job.free(self.allocator);
        for (snapshot.jobs, candidate) |job, *out| {
            out.* = try cloneJob(self.allocator, job);
            copied += 1;
        }
        var failed: ?PendingFailure = null;
        errdefer if (failed) |pending| pending.message.job.free(self.allocator);
        if (snapshot.pending_failure) |message| {
            // Clone before the pending value exists. Copying `message` first
            // would point `failed` at the snapshot's job, and an allocation
            // failure would free that snapshot out from under the caller.
            var owned = message;
            owned.job = try cloneJob(self.allocator, message.job);
            failed = .{ .message = owned, .cut = snapshot.journal_cut };
        }
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        try self.requireRestoreCut(parked);
        if (self.pending_failure) |pending| {
            pending.message.job.free(self.allocator);
            if (pending.journal) |journal| {
                journal.deinit();
                self.allocator.destroy(journal);
            }
        }
        self.pending_failure = failed;
        while (self.job_count != 0) {
            self.jobs[self.job_head].free(self.allocator);
            self.job_head = (self.job_head + 1) % job_capacity;
            self.job_count -= 1;
        }
        @memcpy(self.jobs[0..candidate.len], candidate);
        self.job_count = candidate.len;
        self.job_head = 0;
        self.job_tail = candidate.len % job_capacity;
        self.failure_seq = snapshot.failure_seq;
    }

    pub fn fenceProducers(self: *Sender) !ProducerFence {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.producers.freezeLocked();
    }
    pub fn requireProducersFrozen(self: *Sender, token: ProducerFence) !void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        try self.producers.requireLocked(token);
    }
    pub fn resumeProducers(self: *Sender, token: ProducerFence) !void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        try self.producers.resumeLocked(token);
    }
    /// Seals the exact private directory and journal files under the same
    /// source cut as the mail queue. A missing WAL is initialized as a private
    /// zero-length file only after proving there is no orphan snapshot; the
    /// normal OroStore open will write its epoch on the next failure.
    pub fn capturePrivateWalCut(self: *Sender, fence: ProducerFence, token: ?runtime_pause.Token) !PrivateWalCut {
        if (comptime builtin.os.tag != .windows) return error.Unsupported;
        if (!self.config.private_failure_windows) return error.InsecureFailureJournal;
        try self.requireProducersFrozen(fence);
        _ = try self.requireCaptureCut(token);
        lockSpin(&self.mutex);
        const unsettled = self.pending_failure != null or self.active_settles.load(.acquire) != 0;
        self.mutex.unlock();
        if (unsettled) return error.FailureJournalPending;
        const dir = self.private_failure_dir orelse return error.InsecureFailureJournal;
        const io = self.config.failure_io orelse return error.FailureJournalUnavailable;
        const name = std.fs.path.basename(self.config.failure_wal orelse return error.FailureJournalUnavailable);
        var snap_buf: [512]u8 = undefined;
        const snap_name = try privateSnapshotName(name, &snap_buf);
        const wal = os_runtime.openExistingPrivateWindows(dir, name, .verify_only) catch |err| blk: {
            if (err != error.FileNotFound) return err;
            // An orphan snapshot cannot be given a new WAL lineage here.
            const orphan = os_runtime.openExistingPrivateWindows(dir, snap_name, .verify_only) catch |snap_err| {
                if (snap_err != error.FileNotFound) return snap_err;
                break :blk try os_runtime.createPrivateExclusiveWindows(dir, name);
            };
            orphan.close(io);
            return error.JournalCustodyMismatch;
        };
        defer wal.close(io);
        const wal_cut = try privateFileCut(wal, io);
        // Store replay treats an empty snapshot as no records. Materializing
        // that private name lets the candidate hold both exact file objects
        // exclusively through COMMIT, including an initially absent snapshot.
        const snapshot_file = os_runtime.openExistingPrivateWindows(dir, snap_name, .verify_only) catch |err| blk: {
            if (err != error.FileNotFound) return err;
            break :blk try os_runtime.createPrivateExclusiveWindows(dir, snap_name);
        };
        defer snapshot_file.close(io);
        const snapshot_cut = try privateFileCut(snapshot_file, io);
        try self.requireProducersFrozen(fence);
        _ = try self.requireCaptureCut(token);
        return .{ .parent = try privateFileIdentity(@intFromPtr(dir.handle)), .name_digest = privateNameDigest(name), .wal = wal_cut, .snapshot = snapshot_cut };
    }

    /// Candidate-owned exclusive read handles keep the source WAL and optional
    /// snapshot from being renamed or replaced through COMMIT. All fallible
    /// checks finish before the stage is published into this Sender.
    pub fn stagePrivateWalCut(self: *Sender, expected: PrivateWalCut) !void {
        if (comptime builtin.os.tag != .windows) return error.Unsupported;
        if (!self.config.private_failure_windows or self.private_wal_stage != null) return error.InvalidState;
        const dir = self.private_failure_dir orelse return error.InsecureFailureJournal;
        const io = self.config.failure_io orelse return error.FailureJournalUnavailable;
        const name = std.fs.path.basename(self.config.failure_wal orelse return error.FailureJournalUnavailable);
        if (!std.meta.eql(expected.parent, try privateFileIdentity(@intFromPtr(dir.handle))) or
            !std.mem.eql(u8, &expected.name_digest, &privateNameDigest(name))) return error.JournalCustodyMismatch;
        const wal = try os_runtime.openExistingPrivateWindows(dir, name, .verify_only);
        errdefer wal.close(io);
        if (!privateFileCutEqual(expected.wal, try privateFileCut(wal, io))) return error.JournalCustodyMismatch;
        var snap_buf: [512]u8 = undefined;
        const snap_name = try privateSnapshotName(name, &snap_buf);
        const snapshot_file = try os_runtime.openExistingPrivateWindows(dir, snap_name, .verify_only);
        errdefer snapshot_file.close(io);
        const cut = expected.snapshot orelse return error.JournalCustodyMismatch;
        if (!privateFileCutEqual(cut, try privateFileCut(snapshot_file, io))) return error.JournalCustodyMismatch;
        self.private_wal_stage = .{ .expected = expected, .wal = wal, .snapshot = snapshot_file };
    }

    /// Call at the candidate's pre-COMMIT edge while the Gate is still parked.
    pub fn requireStagedWalCut(self: *Sender) !void {
        if (comptime builtin.os.tag != .windows) return error.Unsupported;
        const stage = self.private_wal_stage orelse return error.NotPrepared;
        const dir = self.private_failure_dir orelse return error.InsecureFailureJournal;
        const io = self.config.failure_io orelse return error.FailureJournalUnavailable;
        const name = std.fs.path.basename(self.config.failure_wal orelse return error.FailureJournalUnavailable);
        if (!std.meta.eql(stage.expected.parent, try privateFileIdentity(@intFromPtr(dir.handle))) or
            !std.mem.eql(u8, &stage.expected.name_digest, &privateNameDigest(name)) or
            !privateFileCutEqual(stage.expected.wal, try privateFileCut(stage.wal, io))) return error.JournalCustodyMismatch;
        const file = stage.snapshot orelse return error.JournalCustodyMismatch;
        const cut = stage.expected.snapshot orelse return error.JournalCustodyMismatch;
        if (!privateFileCutEqual(cut, try privateFileCut(file, io))) return error.JournalCustodyMismatch;
    }

    /// After authenticated COMMIT and before the Gate releases the mail worker.
    pub fn releaseStagedWalCut(self: *Sender) void {
        if (self.private_wal_stage) |stage| {
            const io = self.config.failure_io orelse unreachable;
            if (stage.snapshot) |file| file.close(io);
            stage.wal.close(io);
            self.private_wal_stage = null;
        }
    }
    /// Only this source can prove settlement under its producer fence. Pending
    /// failure custody includes failed AND ambiguous WAL outcomes.
    pub fn requireSettled(self: *Sender, token: ProducerFence) !void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        try self.producers.requireLocked(token);
        if (self.pending_failure != null) return error.FailureJournalPending;
        if (self.job_count != 0 or self.active_settles.load(.acquire) != 0) return error.OperationActive;
    }

    pub fn deinit(self: *Sender) void {
        self.runtime.requireDetached() catch @panic("managed worker must join and detach before deinit");
        self.stop();
        if (self.active_settles.load(.acquire) != 0) @panic("mail settlement caller must finish before source teardown");
        lockSpin(&self.mutex);
        while (self.job_count > 0) {
            const job = self.jobs[self.job_head];
            self.job_head = (self.job_head + 1) % job_capacity;
            self.job_count -= 1;
            job.free(self.allocator);
        }
        self.mutex.unlock();
        if (self.pending_failure) |*pending| {
            pending.message.job.free(self.allocator);
            if (pending.journal) |journal| {
                journal.deinit();
                self.allocator.destroy(journal);
            }
        }
        self.releaseStagedWalCut();
        if (self.private_failure_dir) |dir| dir.close(self.config.failure_io.?);
        self.allocator.free(self.jobs);
        self.* = undefined;
    }

    /// Spawn the worker. Inert (no thread) when relay/from is unconfigured;
    /// enqueued jobs then sit in the ring and are freed at deinit.
    pub fn start(self: *Sender) void {
        if (comptime builtin.os.tag == .windows) {
            if (self.config.failure_wal != null and !self.config.private_failure_windows) return;
        }
        if (self.thread != null or self.runtime.view != null) return;
        if (self.config.relay_host.len == 0 or self.config.from.len == 0) return;
        self.stop_flag.store(false, .release);
        self.thread = std.Thread.spawn(.{}, worker, .{self}) catch null;
    }

    /// Explicit startup for an enabled mail service. Windows requires a
    /// configured private failure journal before its worker can accept jobs.
    pub fn startChecked(self: *Sender) !void {
        if (self.thread != null or self.runtime.view != null) return error.AlreadyStarted;
        if (self.config.relay_host.len == 0 or self.config.from.len == 0) return error.NotConfigured;
        if (comptime builtin.os.tag == .windows) {
            const wal = self.config.failure_wal orelse return error.FailureJournalUnavailable;
            const io = self.config.failure_io orelse return error.FailureJournalUnavailable;
            if (!self.config.private_failure_windows) return error.InsecureFailureJournal;
            try os_runtime.requirePrivateDirectoryWindows(io, self.config.failure_dir orelse std.Io.Dir.cwd(), wal);
        }
        self.stop_flag.store(false, .release);
        errdefer self.stop_flag.store(true, .release);
        self.thread = try std.Thread.spawn(.{}, worker, .{self});
    }

    pub fn stop(self: *Sender) void {
        self.runtime.requireDetached() catch @panic("managed stop requires Runtime Control join and source detach");
        self.stop_flag.store(true, .release);
        self.runtime.wakeForStop();
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
    }

    /// Copy the strings into an owned job and push to the ring. Best-effort:
    /// silently drops on a full ring or alloc failure. Non-blocking; reactor-safe.
    pub fn enqueue(self: *Sender, to: []const u8, subject: []const u8, body: []const u8) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (self.producers.frozen or self.stop_flag.load(.acquire) or self.job_count >= job_capacity) return;
        const job = self.dupeJob(to, subject, body) orelse return;
        self.jobs[self.job_tail] = job;
        self.job_tail = (self.job_tail + 1) % job_capacity;
        self.job_count += 1;
    }

    /// Allocate the three owned copies; frees partial work and returns null on any
    /// alloc failure so the ring never holds a torn job. Caller holds the lock.
    fn dupeJob(self: *Sender, to: []const u8, subject: []const u8, body: []const u8) ?Job {
        const to_copy = self.allocator.dupe(u8, to) catch return null;
        const subject_copy = self.allocator.dupe(u8, subject) catch {
            std.crypto.secureZero(u8, to_copy);
            self.allocator.free(to_copy);
            return null;
        };
        const body_copy = self.allocator.dupe(u8, body) catch {
            std.crypto.secureZero(u8, to_copy);
            std.crypto.secureZero(u8, subject_copy);
            self.allocator.free(to_copy);
            self.allocator.free(subject_copy);
            return null;
        };
        return .{ .to = to_copy, .subject = subject_copy, .body = body_copy };
    }

    /// Pop the oldest job (mutex-guarded). Caller owns and must free it.
    fn takeJob(self: *Sender) ?Job {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (self.job_count == 0) return null;
        const job = self.jobs[self.job_head];
        self.job_head = (self.job_head + 1) % job_capacity;
        self.job_count -= 1;
        return job;
    }

    fn takeWorkerJob(self: *Sender) ?Job {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (self.pending_failure != null or self.active_settles.load(.acquire) != 0 or self.job_count == 0) return null;
        if (self.config.failure_wal != null and self.failure_seq == std.math.maxInt(u64)) return null;
        self.active_settles.store(1, .release);
        const job = self.jobs[self.job_head];
        self.job_head = (self.job_head + 1) % job_capacity;
        self.job_count -= 1;
        return job;
    }

    fn worker(self: *Sender) void {
        self.runtime.markEntered();
        defer self.runtime.markExited();
        while (!self.stop_flag.load(.acquire)) {
            self.runtime.pause.boundary();
            if (self.stop_flag.load(.acquire)) break;
            const job = self.takeWorkerJob() orelse {
                sleepMs(100); // low-rate work: poll for jobs, observe the stop flag
                continue;
            };
            defer self.active_settles.store(0, .release);
            self.finishJob(job) catch |err| {
                std.debug.assert(err == error.FailureJournalPending);
                // The entire failed job belongs to pending_failure, never
                // returned to the delivery queue or freed by this iteration.
            };
        }
    }

    /// Deliver one job. A failure is appended to the failure store when configured.
    pub fn settle(self: *Sender, to: []const u8, subject: []const u8, body: []const u8) !void {
        lockSpin(&self.mutex);
        if (self.producers.frozen or self.stop_flag.load(.acquire)) {
            self.mutex.unlock();
            return error.ProducersFrozen;
        }
        if (self.pending_failure != null) {
            self.mutex.unlock();
            return error.FailureJournalPending;
        }
        if (self.active_settles.load(.acquire) != 0) {
            self.mutex.unlock();
            return error.OperationActive;
        }
        if (self.config.failure_wal != null and self.failure_seq == std.math.maxInt(u64)) {
            self.mutex.unlock();
            return error.SequenceExhausted;
        }
        self.active_settles.store(1, .release);
        self.mutex.unlock();
        defer self.active_settles.store(0, .release);
        const job = self.dupeJob(to, subject, body) orelse return error.OutOfMemory;
        // finishJob takes complete ownership even on error.
        try self.finishJob(job);
    }

    fn finishJob(self: *Sender, job: Job) !void {
        self.deliver(job) catch |err| {
            if (self.config.failure_wal == null and self.config.failure_io == null) {
                // Explicit no-journal policy: terminal failed delivery, not a
                // claim that a durable journal write succeeded.
                job.free(self.allocator);
                return;
            }
            var pending: PendingFailure = .{ .message = .{ .job = job, .sequence = 0 } };
            const name = @errorName(err);
            if (name.len > pending.message.error_name.len) @panic("mail error identity exceeds stable name limit");
            @memcpy(pending.message.error_name[0..name.len], name);
            pending.message.error_len = @intCast(name.len);
            lockSpin(&self.mutex);
            if (self.failure_seq != std.math.maxInt(u64)) {
                self.failure_seq += 1;
                pending.message.sequence = self.failure_seq;
            }
            self.mutex.unlock();
            self.recordFailure(&pending) catch |journal_err| {
                if (comptime builtin.os.tag == .windows) std.debug.print("onyx-server: Windows mail failure journal rejected delivery error {s} ({s})\n", .{ name, @errorName(journal_err) });
                if (pending.journal) |journal| pending.cut = captureJournalCut(journal) catch null;
                lockSpin(&self.mutex);
                self.pending_failure = pending;
                self.mutex.unlock();
                return error.FailureJournalPending;
            };
            pending.message.job.free(self.allocator);
            if (pending.journal) |journal| {
                journal.deinit();
                self.allocator.destroy(journal);
            }
            return;
        };
        job.free(self.allocator);
    }

    fn recordFailure(self: *Sender, pending: *PendingFailure) !void {
        if (pending.message.sequence == 0) return error.SequenceExhausted;
        if (self.private_wal_stage != null) return error.StagedWalActive;
        const io = self.config.failure_io orelse return error.FailureJournalUnavailable;
        const wal = self.config.failure_wal orelse return error.FailureJournalUnavailable;
        const journal = try self.allocator.create(store_mod.OroStore);
        const opened = if (comptime builtin.os.tag == .windows) blk: {
            if (self.config.private_failure_windows)
                break :blk store_mod.OroStore.openPrivateWindowsWithConfig(self.allocator, io, self.private_failure_dir orelse return error.InsecureFailureJournal, std.fs.path.basename(wal), .{});
            break :blk store_mod.OroStore.open(self.allocator, io, self.config.failure_dir orelse std.Io.Dir.cwd(), wal);
        } else store_mod.OroStore.open(self.allocator, io, self.config.failure_dir orelse std.Io.Dir.cwd(), wal);
        journal.* = opened catch |err| {
            self.allocator.destroy(journal);
            return err;
        };
        pending.journal = journal;
        var key_buf: [48]u8 = undefined;
        const key = try std.fmt.bufPrint(&key_buf, "mailfail:{d}", .{pending.message.sequence});
        var val_buf: [220]u8 = undefined;
        const value = try failureValue(&val_buf, &pending.message);
        try journal.put(.props, key, value);
    }

    /// Resolve an already present EXACT failure row without another delivery or
    /// append. Strict same-file replay and the captured full transcript precede
    /// re-sync of the original owned descriptor. Missing/torn/changed rows and
    /// restored outcomes without actual descriptor custody remain fail-closed;
    /// they need a separately owned staged repair/adoption transaction.
    pub fn reconcilePendingFailure(self: *Sender, token: ProducerFence) !void {
        lockSpin(&self.mutex);
        self.producers.requireLocked(token) catch |err| {
            self.mutex.unlock();
            return err;
        };
        if (self.active_settles.load(.acquire) != 0) {
            self.mutex.unlock();
            return error.OperationActive;
        }
        const pending = if (self.pending_failure) |*value| value else {
            self.mutex.unlock();
            return;
        };
        self.active_settles.store(1, .release);
        self.mutex.unlock();
        defer self.active_settles.store(0, .release);
        const journal = pending.journal orelse return error.FailureJournalPending;
        const expected = pending.cut orelse return error.FailureJournalPending;
        try requireJournalCut(journal, expected);
        var key_buf: [48]u8 = undefined;
        const key = try std.fmt.bufPrint(&key_buf, "mailfail:{d}", .{pending.message.sequence});
        var val_buf: [220]u8 = undefined;
        const value = try failureValue(&val_buf, &pending.message);
        if (comptime builtin.os.tag == .windows) {
            const actual = try journal.replayHeldPrivateWindowsValueAlloc(self.allocator, .props, key) orelse return error.FailureJournalPending;
            defer {
                std.crypto.secureZero(u8, actual);
                self.allocator.free(actual);
            }
            if (!std.mem.eql(u8, actual, value)) return error.JournalCustodyMismatch;
            try requireJournalCut(journal, expected);
            try journal.wal_file.?.sync(journal.io);
            try requireJournalCut(journal, expected);
            lockSpin(&self.mutex);
            const resolved = self.pending_failure.?;
            self.pending_failure = null;
            self.mutex.unlock();
            resolved.message.job.free(self.allocator);
            journal.deinit();
            self.allocator.destroy(journal);
            return;
        }
        var replay = try store_mod.OroStore.openReadOnlyWithConfig(self.allocator, journal.io, journal.dir, journal.wal_path, .{});
        defer replay.deinit();
        if (!fileCutEqual(try captureFileCut(replay.wal_file orelse return error.FailureJournalPending, journal.io), expected.wal)) return error.JournalCustodyMismatch;
        const actual = replay.get(.props, key) orelse return error.FailureJournalPending;
        if (!std.mem.eql(u8, actual, value)) return error.JournalCustodyMismatch;
        try requireJournalCut(journal, expected);
        try journal.wal_file.?.sync(journal.io);
        try requireJournalCut(journal, expected);
        lockSpin(&self.mutex);
        const resolved = self.pending_failure.?;
        self.pending_failure = null;
        self.mutex.unlock();
        resolved.message.job.free(self.allocator);
        journal.deinit();
        self.allocator.destroy(journal);
    }

    /// Resolve, connect, and run the ESMTP conversation for one job (outside the lock).
    fn deliver(self: *Sender, job: Job) !void {
        const job_start = platform.monotonicMillis();
        if (comptime builtin.os.tag == .windows) {
            var startup: [408]u8 align(8) = @splat(0);
            if (win.WSAStartup(0x0202, &startup) != 0) return error.SocketUnavailable;
        }
        defer {
            if (comptime builtin.os.tag == .windows) _ = win.WSACleanup();
        }
        const addr = try resolveRelayAddress(self.config.relay_host, self.config.relay_port, io_timeout_ms);

        // Submission credentials must not cross an unverified session to a remote
        // relay. A non-empty trust store, or an explicit insecure opt-in, is required.
        const verified = self.config.trust_anchors.len != 0 or self.config.insecure_skip_verify;
        const fd = try connectRelayAddress(self.config.relay_host, self.config.relay_port, addr, io_timeout_ms, self.config.user != null, verified);
        defer closeFd(fd);
        try setRecvTimeout(fd, io_timeout_ms);

        var msg_buf: [max_message_len]u8 = undefined;
        const message = buildMessage(&msg_buf, self.config, job);

        const driver = try self.allocator.create(smtp_client.Driver);
        defer self.allocator.destroy(driver);
        driver.* = smtp_client.Driver.init(.{
            .ehlo_domain = self.config.ehlo_domain,
            .mail_from = self.config.from,
            .rcpt_to = job.to,
            .message = message,
            .auth_user = self.config.user,
            .auth_pass = self.config.pass,
            .use_starttls = self.config.starttls,
        });

        try self.converse(fd, driver, job_start);
    }

    /// Drive the SMTP state machine on a caller-owned socket, doing the TLS
    /// handshake when the driver asks (or up-front for implicit TLS on 465).
    /// `job_start` is the per-job wall-clock origin for the `max_job_ms` budget.
    fn converse(self: *Sender, fd: Socket, driver: *smtp_client.Driver, job_start: i64) !void {
        var tls: ?*tls_client.Client = null;
        defer if (tls) |tc| {
            tc.deinit();
            self.allocator.destroy(tc);
        };

        var read_buf: [max_tls_record]u8 = undefined;
        var pending: std.ArrayList(u8) = .empty;
        defer pending.deinit(self.allocator);

        // Implicit TLS (port 465): handshake before any plaintext is exchanged. H1:
        // fold the client's post-handshake buffer in first — the server commonly
        // coalesces its greeting with the final handshake flight on implicit TLS.
        if (!self.config.starttls) {
            const tc = try self.handshake(fd, job_start);
            tls = tc;
            try pending.appendSlice(self.allocator, tc.pendingBytes());
        }

        // The first feed consumes the server greeting; read it before looping.
        var action = driver.feed(try self.readChunk(fd, tls, &pending, &read_buf, job_start));

        var iterations: usize = 0;
        while (iterations < max_smtp_iterations) : (iterations += 1) {
            if (platform.monotonicMillis() - job_start > max_job_ms) return error.SmtpJobTimeout;
            switch (action) {
                .need_more => action = driver.feed(try self.readChunk(fd, tls, &pending, &read_buf, job_start)),
                .send => |bytes| {
                    try self.sendBytes(fd, tls, bytes);
                    action = driver.feed(try self.readChunk(fd, tls, &pending, &read_buf, job_start));
                },
                .start_tls => {
                    const tc = try self.handshake(fd, job_start);
                    tls = tc;
                    // Drop any pre-TLS plaintext, then seed with the post-handshake
                    // buffer (H1: the server may coalesce its greeting after STARTTLS).
                    pending.clearRetainingCapacity();
                    try pending.appendSlice(self.allocator, tc.pendingBytes());
                    action = driver.feed(null);
                },
                .done => return,
                .fail => return error.SmtpFailed,
            }
        }
        return error.SmtpTimeout;
    }

    /// Next plaintext SMTP chunk: a raw read, or the decrypted payload of the next
    /// framed TLS record. Buffers undecrypted record bytes in `pending`. `job_start`
    /// is the per-job origin so a stalled relay can't exceed the `max_job_ms` budget.
    fn readChunk(
        self: *Sender,
        fd: Socket,
        tls: ?*tls_client.Client,
        pending: *std.ArrayList(u8),
        read_buf: *[max_tls_record]u8,
        job_start: i64,
    ) ![]const u8 {
        const tc = tls orelse {
            const n = try readSome(fd, read_buf);
            if (platform.monotonicMillis() - job_start > max_job_ms) return error.SmtpJobTimeout;
            return read_buf[0..n];
        };
        while (true) {
            if (frameRecordLen(pending.items)) |rec_len| {
                const rec = pending.items[0..rec_len];
                const read = tc.decryptApp(rec) catch |err| {
                    sendTlsFatal(fd, tc, err);
                    return err;
                };
                defer switch (read) {
                    .application_data => |pt| self.allocator.free(pt),
                    .control => {},
                };
                // Complete a queued KeyUpdate response before further reads or
                // SMTP writes use the successor traffic epoch.
                if (try tc.takePendingSend()) |reply| {
                    defer self.allocator.free(reply);
                    try writeAll(fd, reply);
                }
                consumePrefix(pending, rec_len);
                switch (read) {
                    .application_data => |pt| {
                        // M1: never silently truncate a reply. The decrypted record
                        // must fit the chunk buffer; an over-large record is a fault.
                        if (pt.len > read_buf.len) return error.SmtpReplyTooLarge;
                        @memcpy(read_buf[0..pt.len], pt);
                        return read_buf[0..pt.len];
                    },
                    .control => continue,
                }
            }
            const n = try readSome(fd, read_buf);
            if (platform.monotonicMillis() - job_start > max_job_ms) return error.SmtpJobTimeout;
            try pending.appendSlice(self.allocator, read_buf[0..n]);
        }
    }

    /// Write SMTP command bytes, TLS-encrypting when a session is active.
    fn sendBytes(self: *Sender, fd: Socket, tls: ?*tls_client.Client, bytes: []const u8) !void {
        const tc = tls orelse return writeAll(fd, bytes);
        const record = try tc.encrypt(bytes);
        defer self.allocator.free(record);
        try writeAll(fd, record);
    }

    /// TLS 1.3 handshake on `fd`, returning a heap-allocated connected client.
    /// Cert verification uses `trust_anchors`. It is skipped only when
    /// `insecure_skip_verify` is set.
    fn handshake(self: *Sender, fd: Socket, job_start: i64) !*tls_client.Client {
        const tc = try self.allocator.create(tls_client.Client);
        errdefer self.allocator.destroy(tc);
        tc.* = try tls_client.Client.init(self.allocator, .{
            .server_name = self.config.relay_host,
            .trust_anchors = self.config.trust_anchors,
            .now_unix_seconds = wallClockSeconds(),
            .grease = outbound_grease,
            .ech_grease = outbound_ech_grease,
        });
        errdefer tc.deinit();
        if (self.config.insecure_skip_verify) tc.disableServerCertVerification();

        const hello = try tc.start();
        defer self.allocator.free(hello);
        try writeAll(fd, hello);

        var read_buf: [max_tls_record]u8 = undefined;
        while (!tc.handshakeDone()) {
            if (platform.monotonicMillis() - job_start > max_job_ms) return error.SmtpJobTimeout;
            const n = try readSome(fd, &read_buf);
            switch (tc.feed(read_buf[0..n]) catch |err| {
                sendTlsFatal(fd, tc, err);
                return err;
            }) {
                .need_more => {},
                .bytes_to_send => |out| {
                    defer self.allocator.free(out);
                    try writeAll(fd, out);
                },
            }
        }
        return tc;
    }
};

fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.Thread.yield() catch {};
}

fn sleepMs(ms: u32) void {
    if (comptime builtin.os.tag == .windows) return os_runtime.sleepMillis(ms);
    if (comptime @import("builtin").os.tag != .linux) {
        @import("../os_runtime.zig").sleepMillis(ms);
        return;
    }
    var req = linux.timespec{ .sec = @divTrunc(ms, 1000), .nsec = @as(isize, ms % 1000) * 1_000_000 };
    _ = linux.nanosleep(&req, null);
}

fn smtpPendingControlAllocationProof(failing: std.mem.Allocator) !void {
    // Unix-socketpair proof; no `socketpair` on Windows.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    const a = testing.allocator;
    const runtime = @import("../os_runtime.zig");
    const network = @import("../native_network.zig");
    const peer = try tls_client_failure.TestPeer.init(a);
    defer peer.deinit();
    var sockets: [2]posix.fd_t = undefined;
    try testing.expectEqual(posix.E.SUCCESS, posix.errno(posix.system.socketpair(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0, &sockets)));
    defer for (sockets) |fd| runtime.close(fd);
    for (sockets) |fd| try network.setTimeout(fd, 1000);
    const update = try peer.server.initiateKeyUpdate(true);
    defer a.free(update);
    try testing.expectEqual(tls_client.AppRead.control, try peer.client.decryptApp(update));
    const response = try peer.server.encrypt("250 OK\r\n");
    defer a.free(response);
    var pending: std.ArrayList(u8) = .empty;
    defer pending.deinit(a);
    try pending.appendSlice(a, response);
    // Prior control ciphertext is still owed when this call receives app data.
    // Failure to allocate its owned reply must also release the decrypted data.
    peer.client.allocator = failing;
    var sender = try Sender.init(failing, testConfig());
    defer sender.deinit();
    var read_buffer: [max_tls_record]u8 = undefined;
    const chunk = try sender.readChunk(sockets[0], &peer.client, &pending, &read_buffer, platform.monotonicMillis());
    try testing.expectEqualStrings("250 OK\r\n", chunk);
    try testing.expect((try peer.client.takePendingSend()) == null);
}

pub fn testConfig() Config {
    return .{ .relay_host = "mail.example.test", .ehlo_domain = "mx.example.test", .from = "noreply@example.test" };
}

test "enqueue copies the three strings; the ring holds the owned copy" {
    var s = try Sender.init(testing.allocator, testConfig());
    defer s.deinit();

    s.enqueue("rcpt@example.test", "Verify your account", "Your code is 123456");
    try testing.expectEqual(@as(usize, 1), s.job_count);

    // Inspect the ring directly (test-only): copies must equal the inputs.
    const job = s.jobs[s.job_head];
    try testing.expectEqualStrings("rcpt@example.test", job.to);
    try testing.expectEqualStrings("Verify your account", job.subject);
    try testing.expectEqualStrings("Your code is 123456", job.body);

    // Pop it and confirm the popped copy still equals the inputs.
    const popped = s.takeJob().?;
    defer popped.free(testing.allocator);
    try testing.expectEqual(@as(usize, 0), s.job_count);
    try testing.expectEqualStrings("rcpt@example.test", popped.to);
    try testing.expectEqualStrings("Your code is 123456", popped.body);
}

test "TLS client fatal transport: SMTP read path drains real KeyUpdate before reply" {
    // Unix-socketpair proof; no `socketpair` on Windows.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    const a = testing.allocator;
    const runtime = @import("../os_runtime.zig");
    const network = @import("../native_network.zig");
    const peer = try tls_client_failure.TestPeer.init(a);
    defer peer.deinit();
    var sender = try Sender.init(a, testConfig());
    defer sender.deinit();
    var sockets: [2]posix.fd_t = undefined;
    try testing.expectEqual(posix.E.SUCCESS, posix.errno(posix.system.socketpair(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0, &sockets)));
    defer for (sockets) |fd| runtime.close(fd);
    for (sockets) |fd| try network.setTimeout(fd, 1000);
    const update = try peer.server.initiateKeyUpdate(true);
    defer a.free(update);
    const response = try peer.server.encrypt("250 OK\r\n");
    defer a.free(response);
    try writeAll(sockets[1], update);
    try writeAll(sockets[1], response);
    var pending: std.ArrayList(u8) = .empty;
    defer pending.deinit(a);
    var read_buffer: [max_tls_record]u8 = undefined;
    const chunk = try sender.readChunk(sockets[0], &peer.client, &pending, &read_buffer, platform.monotonicMillis());
    try testing.expectEqualStrings("250 OK\r\n", chunk);
    try testing.expect((try peer.client.takePendingSend()) == null);
    var returned: [128]u8 = undefined;
    try tls_client_failure.testReadExact(sockets[1], returned[0..5]);
    const n = 5 + @as(usize, std.mem.readInt(u16, returned[3..5], .big));
    try testing.expect(n <= returned.len);
    try tls_client_failure.testReadExact(sockets[1], returned[5..n]);
    const decoded = try peer.server.decrypt(returned[0..n]);
    defer a.free(decoded);
    try testing.expectEqual(@as(usize, 0), decoded.len);
    try testing.expectEqual(@as(u64, 0), peer.server.app_read_seq);
    // Subsequent SMTP commands use the new TX epoch only after the reply.
    try sender.sendBytes(sockets[0], &peer.client, "NOOP\r\n");
    try tls_client_failure.testReadExact(sockets[1], returned[0..5]);
    const command_len = 5 + @as(usize, std.mem.readInt(u16, returned[3..5], .big));
    try testing.expect(command_len <= returned.len);
    try tls_client_failure.testReadExact(sockets[1], returned[5..command_len]);
    const command = try peer.server.decrypt(returned[0..command_len]);
    defer a.free(command);
    try testing.expectEqualStrings("NOOP\r\n", command);
}

test "TLS client fatal transport: SMTP pending control allocation failures release plaintext" {
    // This proof drives a Unix socketpair. The Windows mail transport remains
    // excluded until it has a native socket fixture and implementation.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    // The real peers hold allocations from before the failure interval. Keep
    // their ownership intact and let the test allocator detect actual leaks;
    // aggregate FailingAllocator byte counters include those earlier frees.
    for (0..64) |index| {
        var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = index });
        smtpPendingControlAllocationProof(failing.allocator()) catch |err| {
            try testing.expectEqual(error.OutOfMemory, err);
            try testing.expect(failing.has_induced_failure);
            continue;
        };
        try testing.expect(!failing.has_induced_failure);
        try testing.expect(index > 0);
        return;
    }
    return error.TestUnexpectedResult;
}

test "companion failure custody mail exhausted reservation preserves accepted queue before worker or synchronous IO" {
    // `openColdExisting` only supports linux/openbsd/freebsd; elsewhere it
    // returns `Unsupported`, so the `FileNotFound` assertion below cannot run.
    const mail_os = @import("builtin").os.tag;
    if (comptime mail_os != .linux and mail_os != .openbsd and mail_os != .freebsd) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var fail = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var sender = try Sender.init(fail.allocator(), .{
        .relay_host = "unreachable.invalid",
        .ehlo_domain = "fixture.invalid",
        .from = "sender@fixture.invalid",
        .failure_wal = "unused.wal",
        .failure_io = std.testing.io,
        .failure_dir = tmp.dir,
    });
    defer sender.deinit();
    sender.enqueue("accepted@fixture.invalid", "accepted", "accepted secret");
    const old = sender.jobs[0];
    const allocated = fail.alloc_index;
    sender.failure_seq = std.math.maxInt(u64);
    fail.fail_index = allocated;
    try std.testing.expectError(error.SequenceExhausted, sender.settle("new", "new", "new"));
    try std.testing.expect(sender.takeWorkerJob() == null);
    try std.testing.expectEqual(allocated, fail.alloc_index);
    try std.testing.expectEqual(@as(usize, 1), sender.job_count);
    try std.testing.expectEqual(@intFromPtr(old.body.ptr), @intFromPtr(sender.jobs[0].body.ptr));
    try std.testing.expectEqualStrings("accepted secret", sender.jobs[0].body);
    const fence = try sender.fenceProducers();
    try std.testing.expectError(error.OperationActive, sender.requireSettled(fence));
    try std.testing.expectError(error.FileNotFound, store_mod.openColdExisting(std.testing.io, tmp.dir, "unused.wal", .read_only));
}

test "outbound TLS client keeps RFC 8701 GREASE on and GREASE ECH off" {
    try std.testing.expect(outbound_grease);
    try std.testing.expect(!outbound_ech_grease);
    var tc = try tls_client.Client.init(std.testing.allocator, .{ .server_name = "example.test", .trust_anchors = &.{}, .grease = outbound_grease, .ech_grease = outbound_ech_grease });
    defer tc.deinit();
    try std.testing.expect(tc.grease != null);
    try std.testing.expect(!tc.ech_grease);
}
