// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Background SMTP-submission mail sender.
//!
//! Account-verification and password-reset codes must leave the reactor hot
//! path: a full TCP + TLS + ESMTP conversation can take seconds. Callers
//! `enqueue` a short message (mutex-guarded, non-blocking, drop-on-overflow) and
//! a dedicated worker thread delivers it through a configured submission relay.
//! Structural twin of `rdns.zig` (fixed job ring + worker + start/stop +
//! `lockSpin`/`sleepMs`, inert when unconfigured); the worker drives
//! `proto/smtp_client` over a real socket instead of doing a DNS lookup.
//! A resolve/connect/TLS/SMTP failure is written to the failure store when one
//! is configured. Live mail stays off unless the operator enables it. All
//! network I/O happens OUTSIDE the lock.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const net = std.Io.net;

const smtp_client = @import("../proto/smtp_client.zig");
const tls_client = @import("../crypto/tls_client.zig");
const tls_client_failure = @import("tls_client_failure.zig");
const http_fetch = @import("http_fetch.zig");
const platform = @import("../substrate/platform.zig");
const store_mod = @import("store.zig");
pub const runtime_pause = @import("runtime_pause.zig");
pub const dormant_spawn_options: std.Thread.SpawnConfig = .{};

const job_capacity: usize = 64; // bounded ring; enqueue drops past this
const io_timeout_ms: u31 = 15000; // per-job connect + recv/send timeout
const max_message_len: usize = 16 * 1024; // assembled RFC 5322 message cap
const max_body_len: usize = 12 * 1024; // body truncated to fit under the cap
const max_tls_record: usize = 16 * 1024 + 512; // largest framed TLS record
const max_smtp_iterations: usize = 256; // loop bound so a bad relay can't hang us
const max_job_ms: i64 = 60_000; // hard per-job wall-clock budget (H2: bounds total time)

/// Submission parameters; all slices are borrowed (owned by the daemon config).
pub const Config = struct {
    relay_host: []const u8,
    relay_port: u16 = 587,
    starttls: bool = true,
    /// Skip relay certificate verification. AUTH over a remote relay is refused
    /// unless this is set or `trust_anchors` is non-empty.
    insecure_skip_verify: bool = false,
    /// DER trust anchors for the relay certificate. Empty means a remote AUTH
    /// session is not verified.
    trust_anchors: []const []const u8 = &.{},
    ehlo_domain: []const u8,
    from: []const u8,
    user: ?[]const u8 = null,
    pass: ?[]const u8 = null,
    /// OroStore WAL that receives one props row per failed delivery.
    failure_wal: ?[]const u8 = null,
    failure_io: ?std.Io = null,
    failure_dir: ?std.Io.Dir = null,
};

/// One queued message; the three strings are allocator-owned copies.
const Job = struct {
    to: []u8,
    subject: []u8,
    body: []u8,

    fn free(self: Job, allocator: std.mem.Allocator) void {
        std.crypto.secureZero(u8, self.to);
        std.crypto.secureZero(u8, self.subject);
        std.crypto.secureZero(u8, self.body);
        allocator.free(self.to);
        allocator.free(self.subject);
        allocator.free(self.body);
    }
};

const journal_custody = @import("mesh_presence_lease.zig");

/// Stable error names are carried as checked bytes, never compiler anyerror
/// ordinals. A pending outcome owns the original whole job until resolution.
pub const FailedMessage = struct {
    job: Job,
    sequence: u64,
    error_name: [128]u8 = @splat(0),
    error_len: u8 = 0,
    fn name(self: *const FailedMessage) []const u8 {
        return self.error_name[0..self.error_len];
    }
    fn validate(self: *const FailedMessage, sequence: u64) !void {
        if (self.sequence == 0 or self.sequence != sequence or self.error_len == 0 or self.error_len > self.error_name.len) return error.InvalidState;
        for (self.name()) |c| if (!std.ascii.isAlphanumeric(c) and c != '_') return error.InvalidState;
        for (self.error_name[self.error_len..]) |c| if (c != 0) return error.InvalidState;
    }
};
pub const FileCut = struct { identity: journal_custody.Identity, length: u64, digest: [32]u8 };
pub const JournalCut = struct { wal: FileCut, snapshot: ?FileCut };
const PendingFailure = struct {
    message: FailedMessage,
    journal: ?*store_mod.OroStore = null,
    cut: ?JournalCut = null,
};
pub const ProducerFence = runtime_pause.ProducerFence;

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

    pub fn init(allocator: std.mem.Allocator, config: Config) !Sender {
        if ((config.failure_wal == null) != (config.failure_io == null)) return error.InvalidConfig;
        const jobs = try allocator.alloc(Job, job_capacity);
        return .{ .allocator = allocator, .config = config, .jobs = jobs };
    }

    pub fn prepareColdResources(self: *Sender, io: std.Io) !void {
        if (self.thread != null or self.runtime.view != null) return error.AlreadyStarted;
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
        if (self.thread != null or self.runtime.view != null or self.runtime.pause.request_epoch != 0 or
            self.active_settles.load(.acquire) != 0) return error.AlreadyStarted;
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
        if (snapshot.pending_failure) |message| {
            failed = .{ .message = message, .cut = snapshot.journal_cut };
            failed.?.message.job = try cloneJob(self.allocator, message.job);
        }
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
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
        self.allocator.free(self.jobs);
        self.* = undefined;
    }

    /// Spawn the worker. Inert (no thread) when relay/from is unconfigured;
    /// enqueued jobs then sit in the ring and are freed at deinit.
    pub fn start(self: *Sender) void {
        if (comptime @import("builtin").os.tag == .windows) return;
        if (self.thread != null or self.runtime.view != null) return;
        if (self.config.relay_host.len == 0 or self.config.from.len == 0) return;
        self.stop_flag.store(false, .release);
        self.thread = std.Thread.spawn(.{}, worker, .{self}) catch null;
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
            self.recordFailure(&pending) catch {
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
        const io = self.config.failure_io orelse return error.FailureJournalUnavailable;
        const wal = self.config.failure_wal orelse return error.FailureJournalUnavailable;
        const journal = try self.allocator.create(store_mod.OroStore);
        journal.* = store_mod.OroStore.open(self.allocator, io, self.config.failure_dir orelse std.Io.Dir.cwd(), wal) catch |err| {
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
        var replay = try store_mod.OroStore.openReadOnlyWithConfig(self.allocator, journal.io, journal.dir, journal.wal_path, .{});
        defer replay.deinit();
        if (!fileCutEqual(try captureFileCut(replay.wal_file orelse return error.FailureJournalPending, journal.io), expected.wal)) return error.JournalCustodyMismatch;
        var key_buf: [48]u8 = undefined;
        const key = try std.fmt.bufPrint(&key_buf, "mailfail:{d}", .{pending.message.sequence});
        var val_buf: [220]u8 = undefined;
        const value = try failureValue(&val_buf, &pending.message);
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
        const addr = try http_fetch.resolveHostA(self.config.relay_host, self.config.relay_port, io_timeout_ms);

        // Submission credentials must not cross an unverified session to a remote
        // relay. A non-empty trust store, or an explicit insecure opt-in, is required.
        const verified = self.config.trust_anchors.len != 0 or self.config.insecure_skip_verify;
        if (self.config.user != null and !isLoopback(addr) and !verified)
            return error.UnverifiedAuthRelay;

        // Apply the AUTH policy before the platform transport gate. IP literal
        // relays resolve on Windows, so a remote unverified relay is refused
        // with the same durable reason even while SMTP sockets are unavailable.
        if (comptime @import("builtin").os.tag == .windows) return error.SocketUnavailable;

        const fd = try connectAddr(addr, io_timeout_ms);
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
    fn converse(self: *Sender, fd: linux.fd_t, driver: *smtp_client.Driver, job_start: i64) !void {
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
            const tc = try self.handshake(fd);
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
                    const tc = try self.handshake(fd);
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
        fd: linux.fd_t,
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
                    tls_client_failure.sendFatal(fd, tc, err);
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
    fn sendBytes(self: *Sender, fd: linux.fd_t, tls: ?*tls_client.Client, bytes: []const u8) !void {
        const tc = tls orelse return writeAll(fd, bytes);
        const record = try tc.encrypt(bytes);
        defer self.allocator.free(record);
        try writeAll(fd, record);
    }

    /// TLS 1.3 handshake on `fd`, returning a heap-allocated connected client.
    /// Cert verification uses `trust_anchors`. It is skipped only when
    /// `insecure_skip_verify` is set.
    fn handshake(self: *Sender, fd: linux.fd_t) !*tls_client.Client {
        const tc = try self.allocator.create(tls_client.Client);
        errdefer self.allocator.destroy(tc);
        tc.* = try tls_client.Client.init(self.allocator, .{
            .server_name = self.config.relay_host,
            .trust_anchors = self.config.trust_anchors,
            .now_unix_seconds = wallClockSeconds(),
        });
        errdefer tc.deinit();
        if (self.config.insecure_skip_verify) tc.skipServerCertVerifyForTest();

        const hello = try tc.start();
        defer self.allocator.free(hello);
        try writeAll(fd, hello);

        var read_buf: [max_tls_record]u8 = undefined;
        while (!tc.handshakeDone()) {
            const n = try readSome(fd, &read_buf);
            switch (tc.feed(read_buf[0..n]) catch |err| {
                tls_client_failure.sendFatal(fd, tc, err);
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

/// Assemble the RFC 5322 message into `out`; body truncated to `max_body_len`.
/// Returns an empty slice if any header field carries a CR/LF (M2: defensive
/// header-injection guard — a caller treats an empty build as "skip enqueue").
fn buildMessage(out: *[max_message_len]u8, config: Config, job: Job) []const u8 {
    if (hasCrlf(job.to) or hasCrlf(config.from) or hasCrlf(job.subject)) return out[0..0];
    const body = job.body[0..@min(job.body.len, max_body_len)];
    // The Date is a fixed, syntactically-valid stub; the relay stamps its own
    // Received date, so a wall-clock-to-civil-time conversion is not worth it.
    return std.fmt.bufPrint(
        out,
        "From: <{s}>\r\nTo: <{s}>\r\nSubject: {s}\r\n" ++
            "Date: Thu, 01 Jan 1970 00:00:00 +0000\r\nMessage-ID: <{d}@{s}>\r\n" ++
            "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{s}",
        .{
            config.from,                                    job.to,             job.subject,
            @as(u64, @bitCast(platform.monotonicMillis())), config.ehlo_domain, body,
        },
    ) catch out[0..0];
}

fn wallClockSeconds() i64 {
    if (comptime @import("builtin").os.tag != .linux) return @divTrunc(platform.realtimeMillis(), 1000);
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(linux.CLOCK.REALTIME, &ts);
    return @intCast(ts.sec);
}

/// True if `s` carries a raw CR or LF — the bytes an attacker would use to splice
/// extra SMTP/RFC 5322 headers. Used to reject header injection in `buildMessage`.
fn hasCrlf(s: []const u8) bool {
    return std.mem.indexOfScalar(u8, s, '\r') != null or std.mem.indexOfScalar(u8, s, '\n') != null;
}

test "DST GAP-D7 configured relay with a trust store records a durable delivery failure" {
    std.debug.print("GAP-D7 branch=configured relay with a non-empty trust store records a durable delivery failure; empty trust still refuses remote AUTH; live mail stays off\n", .{});
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const anchors = [_][]const u8{"anchor"};
    var sender = try Sender.init(allocator, .{
        .relay_host = "127.0.0.1",
        .relay_port = 1,
        .ehlo_domain = "onyx.test",
        .from = "onyx@example.test",
        .trust_anchors = &anchors,
        .failure_wal = "mailfail.wal",
        .failure_io = io,
        .failure_dir = tmp.dir,
    });
    defer sender.deinit();
    try std.testing.expect(sender.config.trust_anchors.len != 0);
    try sender.settle("d7@example.test", "verify", "code");

    var opened = try store_mod.OroStore.open(allocator, io, tmp.dir, "mailfail.wal");
    defer opened.deinit();
    const row = opened.get(.props, "mailfail:1") orelse return error.TestUnexpectedResult;
    try std.testing.expect(std.mem.indexOf(u8, row, "d7@example.test") != null);
    try std.testing.expect(std.mem.indexOf(u8, row, "ConnectFailed") != null or std.mem.indexOf(u8, row, "SocketUnavailable") != null);

    var refused = try Sender.init(allocator, .{
        .relay_host = "203.0.113.5",
        .relay_port = 587,
        .ehlo_domain = "onyx.test",
        .from = "onyx@example.test",
        .user = "submit",
        .pass = "secret",
        .failure_wal = "mailfail-auth.wal",
        .failure_io = io,
        .failure_dir = tmp.dir,
    });
    defer refused.deinit();
    try std.testing.expect(refused.config.trust_anchors.len == 0);
    try refused.settle("d7@example.test", "verify", "code");
    var auth_store = try store_mod.OroStore.open(allocator, io, tmp.dir, "mailfail-auth.wal");
    defer auth_store.deinit();
    const auth_row = auth_store.get(.props, "mailfail:1") orelse return error.TestUnexpectedResult;
    try std.testing.expect(std.mem.indexOf(u8, auth_row, "UnverifiedAuthRelay") != null);
}

/// True if `addr` is a loopback address (IPv4 127.0.0.0/8 or IPv6 ::1). Used to
/// decide whether AUTH over an unverified TLS session is acceptable.
fn isLoopback(addr: net.IpAddress) bool {
    return switch (addr) {
        .ip4 => |x| x.bytes[0] == 127,
        .ip6 => |x| std.mem.eql(u8, &x.bytes, &(@as([15]u8, @splat(0)) ++ [_]u8{1})),
    };
}

// ---- TLS record framing (mirrors http_fetch) --------------------------------

fn frameRecordLen(buf: []const u8) ?usize {
    if (buf.len < 5) return null;
    const len = (@as(usize, buf[3]) << 8) | @as(usize, buf[4]);
    const total = 5 + len;
    if (buf.len < total) return null;
    return total;
}

fn consumePrefix(list: *std.ArrayList(u8), n: usize) void {
    const rem = list.items.len - n;
    std.mem.copyForwards(u8, list.items[0..rem], list.items[n..]);
    list.shrinkRetainingCapacity(rem);
}

// ---- raw socket helpers (mirror http_fetch) ---------------------------------
// `resolveHostA` only ever yields an IPv4 address, so (like http_fetch's own
// `connectAddr`) the v6 case is unreachable and treated as a connect failure.

const SocketError = error{ SocketUnavailable, ConnectFailed, ConnectTimeout, ConnectionClosed, RecvTimeout };

fn connectAddr(addr: net.IpAddress, timeout_ms: u31) SocketError!linux.fd_t {
    if (comptime @import("builtin").os.tag == .windows) return error.SocketUnavailable;
    if (comptime @import("builtin").os.tag == .openbsd) return @import("native_network.zig").connect(addr, timeout_ms);
    const a4 = switch (addr) {
        .ip4 => |x| x,
        .ip6 => return error.ConnectFailed,
    };
    const fd = try socketTcpNonblock();
    errdefer closeFd(fd);
    var sa = linux.sockaddr.in{ .port = std.mem.nativeToBig(u16, a4.port), .addr = @bitCast(a4.bytes) };
    switch (posix.errno(linux.connect(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in)))) {
        .SUCCESS => {},
        .INPROGRESS, .INTR => try waitWritable(fd, timeout_ms),
        else => return error.ConnectFailed,
    }
    var err_val: i32 = 0;
    var err_len: linux.socklen_t = @sizeOf(i32);
    if (posix.errno(linux.getsockopt(fd, posix.SOL.SOCKET, posix.SO.ERROR, @ptrCast(&err_val), &err_len)) != .SUCCESS)
        return error.ConnectFailed;
    if (err_val != 0) return error.ConnectFailed;
    setBlocking(fd);
    return fd;
}

fn waitWritable(fd: linux.fd_t, timeout_ms: u31) SocketError!void {
    // Use linux.pollfd/POLL (not posix.*): these pair with the raw linux.poll
    // syscall and posix.* is the libc/ws2_32 struct on non-Linux (build-time only).
    var pfd = [_]linux.pollfd{.{ .fd = fd, .events = linux.POLL.OUT, .revents = 0 }};
    const rc = linux.poll(&pfd, 1, timeout_ms);
    if (posix.errno(rc) != .SUCCESS) return error.ConnectFailed;
    if (rc == 0) return error.ConnectTimeout;
    if (pfd[0].revents & (linux.POLL.ERR | linux.POLL.HUP) != 0) return error.ConnectFailed;
}

fn socketTcpNonblock() SocketError!linux.fd_t {
    const rc = linux.socket(posix.AF.INET, linux.SOCK.STREAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC, linux.IPPROTO.TCP);
    return switch (posix.errno(rc)) {
        .SUCCESS => @intCast(rc),
        else => error.SocketUnavailable,
    };
}

fn setBlocking(fd: linux.fd_t) void {
    const flags = linux.fcntl(fd, linux.F.GETFL, 0);
    _ = linux.fcntl(fd, linux.F.SETFL, flags & ~@as(usize, linux.SOCK.NONBLOCK));
}

fn setRecvTimeout(fd: linux.fd_t, timeout_ms: u31) SocketError!void {
    if (comptime @import("builtin").os.tag == .openbsd) return @import("native_network.zig").setTimeout(fd, timeout_ms);
    const tv = linux.timeval{ .sec = @divTrunc(timeout_ms, 1000), .usec = @as(i64, @intCast(timeout_ms % 1000)) * 1000 };
    _ = linux.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, @ptrCast(&tv), @sizeOf(linux.timeval));
    _ = linux.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDTIMEO, @ptrCast(&tv), @sizeOf(linux.timeval));
}

fn closeFd(fd: linux.fd_t) void {
    if (comptime @import("builtin").os.tag == .windows) return;
    if (comptime @import("builtin").os.tag != .linux) return @import("os_runtime.zig").close(fd);
    _ = linux.close(fd);
}

fn writeAll(fd: linux.fd_t, bytes: []const u8) SocketError!void {
    if (comptime @import("builtin").os.tag == .openbsd) return @import("native_network.zig").writeAll(fd, bytes);
    var off: usize = 0;
    while (off < bytes.len) {
        const rc = linux.write(fd, bytes[off..].ptr, bytes.len - off);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                const n: usize = @intCast(rc);
                if (n == 0) return error.ConnectionClosed;
                off += n;
            },
            .INTR => {},
            .AGAIN => return error.RecvTimeout,
            else => return error.ConnectionClosed,
        }
    }
}

fn readSome(fd: linux.fd_t, buf: []u8) SocketError!usize {
    if (comptime @import("builtin").os.tag == .openbsd) return @import("native_network.zig").readSome(fd, buf);
    while (true) {
        const rc = linux.read(fd, buf.ptr, buf.len);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                const n: usize = @intCast(rc);
                if (n == 0) return error.ConnectionClosed;
                return n;
            },
            .INTR => continue,
            .AGAIN => return error.RecvTimeout,
            else => return error.ConnectionClosed,
        }
    }
}

fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.Thread.yield() catch {};
}

fn sleepMs(ms: u32) void {
    if (comptime @import("builtin").os.tag == .windows) return;
    if (comptime @import("builtin").os.tag != .linux) {
        @import("os_runtime.zig").sleepMillis(ms);
        return;
    }
    var req = linux.timespec{ .sec = @divTrunc(ms, 1000), .nsec = @as(isize, ms % 1000) * 1_000_000 };
    _ = linux.nanosleep(&req, null);
}

// ---- tests (pure mechanics only; the network path needs a live relay) -------

const testing = std.testing;

fn testConfig() Config {
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

test "the ring is bounded: overflow is dropped without crashing" {
    var s = try Sender.init(testing.allocator, testConfig());
    defer s.deinit();

    var i: usize = 0;
    while (i < job_capacity + 32) : (i += 1) {
        s.enqueue("rcpt@example.test", "subject", "body");
    }
    try testing.expectEqual(job_capacity, s.job_count);
}

test "deinit frees queued (un-sent) jobs with no leak" {
    var s = try Sender.init(testing.allocator, testConfig());
    s.enqueue("a@example.test", "s1", "b1");
    s.enqueue("b@example.test", "s2", "b2");
    s.enqueue("c@example.test", "s3", "b3");
    try testing.expectEqual(@as(usize, 3), s.job_count);
    // deinit must free the three queued jobs + the ring (testing.allocator
    // asserts no leak on teardown).
    s.deinit();
}

test "buildMessage emits well-formed headers and truncates an over-long body" {
    var buf: [max_message_len]u8 = undefined;
    var long_body: [max_body_len + 4096]u8 = undefined;
    @memset(&long_body, 'x');
    const job = Job{
        .to = @constCast("rcpt@example.test"),
        .subject = @constCast("Reset code"),
        .body = &long_body,
    };
    const msg = buildMessage(&buf, testConfig(), job);
    try testing.expect(std.mem.indexOf(u8, msg, "From: <noreply@example.test>\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, msg, "To: <rcpt@example.test>\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, msg, "Subject: Reset code\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, msg, "\r\n\r\n") != null); // header/body separator
    // The body was truncated to at most max_body_len bytes.
    const sep = std.mem.indexOf(u8, msg, "\r\n\r\n").? + 4;
    try testing.expect(msg.len - sep <= max_body_len);
}

test "buildMessage refuses a CRLF in a header field (header-injection guard)" {
    var buf: [max_message_len]u8 = undefined;
    // A `to` carrying a CRLF would otherwise splice an attacker-controlled header.
    const job = Job{
        .to = @constCast("rcpt@example.test\r\nBcc: victim@example.test"),
        .subject = @constCast("Reset code"),
        .body = @constCast("body"),
    };
    const msg = buildMessage(&buf, testConfig(), job);
    try testing.expectEqual(@as(usize, 0), msg.len);

    // A bare LF in the subject is likewise rejected.
    const job2 = Job{
        .to = @constCast("rcpt@example.test"),
        .subject = @constCast("Reset\ncode"),
        .body = @constCast("body"),
    };
    try testing.expectEqual(@as(usize, 0), buildMessage(&buf, testConfig(), job2).len);
}

test "isLoopback detects 127.0.0.0/8 and ::1, rejects public addresses" {
    try testing.expect(isLoopback(.{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 587 } }));
    try testing.expect(isLoopback(.{ .ip4 = .{ .bytes = .{ 127, 5, 9, 200 }, .port = 587 } }));
    try testing.expect(!isLoopback(.{ .ip4 = .{ .bytes = .{ 93, 184, 216, 34 }, .port = 587 } }));

    const v6_loop = @as([15]u8, @splat(0)) ++ [_]u8{1};
    try testing.expect(isLoopback(.{ .ip6 = .{ .bytes = v6_loop, .port = 587 } }));
    const v6_pub = [_]u8{ 0x20, 0x01 } ++ @as([13]u8, @splat(0)) ++ [_]u8{1};
    try testing.expect(!isLoopback(.{ .ip6 = .{ .bytes = v6_pub, .port = 587 } }));
}

test "TLS client fatal transport: mail_sender socket writer preserves control custody" {
    // Unix-socketpair proof; no `socketpair` on Windows.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    try tls_client_failure.testFatalTransportProof(true, writeAll);
}

test "TLS client fatal transport: SMTP read path drains real KeyUpdate before reply" {
    // Unix-socketpair proof; no `socketpair` on Windows.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    const a = testing.allocator;
    const runtime = @import("os_runtime.zig");
    const network = @import("native_network.zig");
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

fn smtpPendingControlAllocationProof(failing: std.mem.Allocator) !void {
    // Unix-socketpair proof; no `socketpair` on Windows.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    const a = testing.allocator;
    const runtime = @import("os_runtime.zig");
    const network = @import("native_network.zig");
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

pub const Execution = enum(u8) { unstarted, paused };
pub const QueuedMessage = Job;
pub const Snapshot = struct {
    allocator: std.mem.Allocator,
    jobs: []QueuedMessage,
    failure_seq: u64,
    config_digest: [32]u8,
    execution: Execution,
    pending_failure: ?FailedMessage = null,
    journal_cut: ?JournalCut = null,
    pub fn deinit(self: *Snapshot) void {
        for (self.jobs) |job| job.free(self.allocator);
        if (self.pending_failure) |message| message.job.free(self.allocator);
        self.allocator.free(self.jobs);
        self.* = undefined;
    }
    pub fn validate(self: *const Snapshot, config: Config, max_bytes: usize) !void {
        if (self.jobs.len > job_capacity) return error.InvalidState;
        if (!std.mem.eql(u8, &self.config_digest, &try configDigest(config))) return error.ConfigMismatch;
        var bytes = @sizeOf(Snapshot) + self.jobs.len * @sizeOf(Job);
        for (self.jobs) |job| {
            bytes = std.math.add(usize, bytes, job.to.len) catch return error.Capacity;
            bytes = std.math.add(usize, bytes, job.subject.len) catch return error.Capacity;
            bytes = std.math.add(usize, bytes, job.body.len) catch return error.Capacity;
        }
        if (self.pending_failure) |message| {
            try message.validate(self.failure_seq);
            if (config.failure_wal == null) return error.InvalidState;
            bytes = try jobBytes(bytes, message.job);
        } else if (self.journal_cut != null) return error.InvalidState;
        if (bytes > max_bytes) return error.Capacity;
    }
};
fn cloneJob(allocator: std.mem.Allocator, job: Job) !Job {
    const to = try allocator.dupe(u8, job.to);
    errdefer {
        std.crypto.secureZero(u8, to);
        allocator.free(to);
    }
    const subject = try allocator.dupe(u8, job.subject);
    errdefer {
        std.crypto.secureZero(u8, subject);
        allocator.free(subject);
    }
    const body = try allocator.dupe(u8, job.body);
    return .{ .to = to, .subject = subject, .body = body };
}
fn jobBytes(initial: usize, job: Job) !usize {
    var bytes = std.math.add(usize, initial, @sizeOf(Job)) catch return error.Capacity;
    bytes = std.math.add(usize, bytes, job.to.len) catch return error.Capacity;
    bytes = std.math.add(usize, bytes, job.subject.len) catch return error.Capacity;
    return std.math.add(usize, bytes, job.body.len) catch return error.Capacity;
}
fn failureValue(buffer: []u8, message: *const FailedMessage) ![]const u8 {
    return std.fmt.bufPrint(buffer, "{s} {s}", .{ message.name(), message.job.to[0..@min(message.job.to.len, 80)] });
}
fn captureFileCut(file: std.Io.File, io: std.Io) !FileCut {
    if (comptime @import("builtin").os.tag == .windows) return error.Unsupported;
    const identity = try journal_custody.statRegular(file.handle);
    const size = (try file.stat(io)).size;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [4096]u8 = undefined;
    var offset: u64 = 0;
    while (offset < size) {
        const len: usize = @intCast(@min(size - offset, buffer.len));
        if (try file.readPositionalAll(io, buffer[0..len], offset) != len) return error.JournalCustodyMismatch;
        hash.update(buffer[0..len]);
        offset += len;
    }
    const after = try journal_custody.statRegular(file.handle);
    if (identity.device != after.device or identity.inode != after.inode or (try file.stat(io)).size != size) return error.JournalCustodyMismatch;
    return .{ .identity = identity, .length = size, .digest = hash.finalResult() };
}
fn fileCutEqual(a: FileCut, b: FileCut) bool {
    return a.identity.device == b.identity.device and a.identity.inode == b.identity.inode and a.length == b.length and std.mem.eql(u8, &a.digest, &b.digest);
}
fn captureSnapshotCut(journal: *store_mod.OroStore) !?FileCut {
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
fn captureJournalCut(journal: *store_mod.OroStore) !JournalCut {
    return .{ .wal = try captureFileCut(journal.wal_file orelse return error.FailureJournalPending, journal.io), .snapshot = try captureSnapshotCut(journal) };
}
fn requireJournalCut(journal: *store_mod.OroStore, expected: JournalCut) !void {
    const held = try captureJournalCut(journal);
    if (!fileCutEqual(held.wal, expected.wal)) return error.JournalCustodyMismatch;
    if (expected.snapshot) |snapshot| {
        if (!fileCutEqual(held.snapshot orelse return error.JournalCustodyMismatch, snapshot)) return error.JournalCustodyMismatch;
    } else if (held.snapshot != null) return error.JournalCustodyMismatch;
    const file = try store_mod.openColdExisting(journal.io, journal.dir, journal.wal_path, .read_only);
    defer file.close(journal.io);
    if (!fileCutEqual(try captureFileCut(file, journal.io), expected.wal)) return error.JournalCustodyMismatch;
}

/// Commits configured value fields. The actual failure-store Io/Dir lineage is
/// separately held by the whole owner; these presence tags do not prove custody.
pub fn configDigest(config: Config) ![32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("onyx/companion/mail-config/v1");
    try runtime_pause.hashBytes(&hash, config.relay_host);
    var numbers: [2]u8 = undefined;
    std.mem.writeInt(u16, &numbers, config.relay_port, .big);
    hash.update(&numbers);
    hash.update(&.{ @intFromBool(config.starttls), @intFromBool(config.insecure_skip_verify) });
    const count = std.math.cast(u32, config.trust_anchors.len) orelse return error.Capacity;
    var prefix: [4]u8 = undefined;
    std.mem.writeInt(u32, &prefix, count, .big);
    hash.update(&prefix);
    for (config.trust_anchors) |anchor| try runtime_pause.hashBytes(&hash, anchor);
    try runtime_pause.hashBytes(&hash, config.ehlo_domain);
    try runtime_pause.hashBytes(&hash, config.from);
    try runtime_pause.hashOptional(&hash, config.user);
    try runtime_pause.hashOptional(&hash, config.pass);
    try runtime_pause.hashOptional(&hash, config.failure_wal);
    hash.update(&.{ @intFromBool(config.failure_io != null), @intFromBool(config.failure_dir != null) });
    return hash.finalResult();
}

fn pausedMailCaptureAllocation(allocator: std.mem.Allocator, sender: *Sender, token: runtime_pause.Token) !void {
    var snapshot = try sender.capturePaused(allocator, token, 1024 * 1024);
    defer snapshot.deinit();
    try std.testing.expectEqual(@as(usize, 2), snapshot.jobs.len);
    try std.testing.expectEqualStrings("verification secret", snapshot.jobs[0].body);
    try std.testing.expectEqual(@as(u64, 1337), snapshot.failure_seq);
}

test "companion runtime mail retained FIFO sequence secret custody and every restore OOM" {
    const config: Config = .{ .relay_host = "relay.invalid", .ehlo_domain = "test.invalid", .from = "sender@test.invalid" };
    var sender = try Sender.init(std.testing.allocator, config);
    try sender.prepareColdResources(std.testing.io);
    const specs = [_]runtime_pause.start_gate.ParticipantSpec{.{ .kind = .mail, .instance = 0, .owner_identity = &sender }};
    const gate = runtime_pause.start_gate.create(std.testing.allocator, std.testing.io, &specs) catch |err| {
        sender.deinit();
        return err;
    };
    defer {
        sender.requestStopAndWake();
        if (gate.view.inspect().phase == .preparing) gate.control.cancelAllAndJoin() else gate.control.joinAll();
        sender.detachAfterJoined() catch unreachable;
        sender.deinit();
        gate.control.destroyJoined();
    }
    const input = try std.testing.allocator.dupe(u8, "verification secret");
    sender.enqueue("first@test.invalid", "verify", input);
    std.testing.allocator.free(input);
    sender.enqueue("second@test.invalid", "reset", "reset secret");
    sender.failure_seq = 1337;
    const token = try sender.requestPause(1);
    try sender.prepareDormantWorker(gate.control, gate.view, try gate.view.slot(.mail, 0, &sender));
    try gate.control.awaitAllParked(std.Io.Clock.Timestamp.fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
    try std.testing.expectEqual(@as(usize, 2), sender.job_count);
    gate.control.releaseAll();
    try sender.awaitPaused(token, std.Io.Clock.Timestamp.fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
    try std.testing.checkAllAllocationFailures(std.testing.allocator, pausedMailCaptureAllocation, .{ &sender, token });
    var snapshot = try sender.capturePaused(std.testing.allocator, token, 1024 * 1024);
    defer snapshot.deinit();
    var n: usize = 0;
    while (true) : (n += 1) {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        var restored = try Sender.init(failing.allocator(), config);
        defer restored.deinit();
        restored.enqueue("old@test.invalid", "old", "accepted OLD secret");
        try std.testing.expectEqual(@as(usize, 1), restored.job_count);
        restored.failure_seq = 19;
        const old = restored.jobs[0];
        failing.fail_index = failing.alloc_index + n;
        restored.restoreSnapshot(&snapshot, 1024 * 1024) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expectEqual(@as(usize, 1), restored.job_count);
            try std.testing.expectEqual(@as(u64, 19), restored.failure_seq);
            try std.testing.expectEqual(@intFromPtr(old.body.ptr), @intFromPtr(restored.jobs[0].body.ptr));
            try std.testing.expectEqualStrings("accepted OLD secret", restored.jobs[0].body);
            failing.fail_index = std.math.maxInt(usize);
            try restored.restoreSnapshot(&snapshot, 1024 * 1024);
            try std.testing.expectEqual(@as(usize, 2), restored.job_count);
            try std.testing.expectEqualStrings("verification secret", restored.jobs[0].body);
            continue;
        };
        try std.testing.expectEqual(@as(usize, 7), n);
        try std.testing.expectEqual(@as(u64, 1337), restored.failure_seq);
        try std.testing.expectEqualStrings("reset secret", restored.jobs[1].body);
        break;
    }
    snapshot.config_digest[0] ^= 1;
    var refused = try Sender.init(std.testing.allocator, config);
    defer refused.deinit();
    try std.testing.expectError(error.ConfigMismatch, refused.restoreSnapshot(&snapshot, 1024 * 1024));
    try std.testing.expectEqual(@as(usize, 0), refused.job_count);
    snapshot.config_digest[0] ^= 1;
    try std.testing.expectError(error.Capacity, sender.capturePaused(std.testing.allocator, token, 1));
    // A real synchronous caller is part of the same source operation census.
    sender.active_settles.store(1, .release);
    try std.testing.expectError(error.OperationActive, sender.capturePaused(std.testing.allocator, token, 1024 * 1024));
    sender.active_settles.store(0, .release);
    try std.testing.expectEqual(@as(usize, 2), sender.job_count);
}

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

test "companion failure custody causal actual mail WAL write error cannot report settled" {
    try mailJournalFailureCausal(.failed_write);
}

test "companion failure custody causal actual mail synced append ambiguity cannot report settled" {
    try mailJournalFailureCausal(.synced_then_error);
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

test "companion failure custody mail absent append retains full job through every capture and restore OOM" {
    try mailPendingCustodyRepair(.failed_write);
}

test "companion failure custody mail synced ambiguity resolves exact held row without SMTP redelivery" {
    try mailPendingCustodyRepair(.synced_then_error);
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
