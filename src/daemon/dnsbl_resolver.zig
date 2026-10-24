// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Background DNS blocklist (DNSBL) resolver.
//!
//! The accept hot path must never block on DNS (a blocklist probe across
//! several zones can take seconds), so client IPs are *enqueued* here and
//! checked on a dedicated worker thread via `proto/dns.zig`. The reactor reads
//! the cached verdict back — at registration time — to decide whether to reject
//! or annotate a listed connection. Best-effort: any miss, timeout, or
//! NXDOMAIN leaves the entry resolved-not-listed and the caller treats the
//! client as clean. Mutex-guarded fixed cache + job ring, mirroring the
//! established `rdns` background-resolver pattern.

const std = @import("std");
const dns = @import("../proto/dns.zig");
const dns_engine = @import("../proto/dns/query_engine.zig");
const DnsDeadline = @import("../proto/dns/deadline.zig").Deadline;
const dnsbl = @import("dnsbl.zig");
const platform = @import("../substrate/platform.zig");
pub const runtime_pause = @import("runtime_pause.zig");
pub const dormant_spawn_options: std.Thread.SpawnConfig = .{};
const checkpoint = @import("dnsbl_snapshot.zig");

// The DNSBL worker test uses a real loopback UDP nameserver. Keep its socket
// declarations local to the fixture; production DNS transport is in proto/dns.
const test_win = struct {
    const invalid_socket = std.math.maxInt(usize);
    const SockAddr4 = extern struct {
        family: u16,
        port: u16,
        addr: [4]u8,
        zero: [8]u8 = @splat(0),
    };
    extern "ws2_32" fn WSAStartup(version_requested: u16, data: *anyopaque) callconv(.winapi) i32;
    extern "ws2_32" fn WSACleanup() callconv(.winapi) i32;
    extern "ws2_32" fn WSASocketW(family: i32, socket_type: i32, protocol: i32, protocol_info: ?*anyopaque, group: u32, flags: u32) callconv(.winapi) usize;
    extern "ws2_32" fn closesocket(socket: usize) callconv(.winapi) i32;
    extern "ws2_32" fn bind(socket: usize, address: *const SockAddr4, address_len: i32) callconv(.winapi) i32;
    extern "ws2_32" fn getsockname(socket: usize, address: *SockAddr4, address_len: *i32) callconv(.winapi) i32;
    extern "ws2_32" fn setsockopt(socket: usize, level: i32, option: i32, value: *const anyopaque, length: i32) callconv(.winapi) i32;
    extern "ws2_32" fn recvfrom(socket: usize, bytes: [*]u8, length: i32, flags: i32, from: *SockAddr4, from_length: *i32) callconv(.winapi) i32;
    extern "ws2_32" fn sendto(socket: usize, bytes: [*]const u8, length: i32, flags: i32, to: *const SockAddr4, to_length: i32) callconv(.winapi) i32;
};

/// Maximum number of blocklist zones probed per client IP.
pub const max_zones = checkpoint.max_zones;
pub const cache_slots = checkpoint.cache_slots;
pub const job_capacity = checkpoint.job_capacity;
/// Re-check an IP at most this often (blocklist state changes slowly).
const entry_ttl_ms: i64 = 30 * 60 * 1000;

pub const State = checkpoint.State;
pub const Verdict = checkpoint.Verdict;
pub const CacheEntry = checkpoint.CacheEntry;
pub const Execution = checkpoint.Execution;
pub const Snapshot = checkpoint.Snapshot;
pub const configDigest = checkpoint.configDigest;
pub const validateZones = checkpoint.validateZones;

const Entry = struct {
    key: dns.Address = .{ .ipv4 = .{ 0, 0, 0, 0 } },
    has_key: bool = false,
    state: State = .empty,
    /// Meaningful only when `state == .ready`.
    verdict: Verdict = .{ .listed = false },
    resolved_ms: i64 = 0,
    /// Runtime custody of an accepted queued/active job, independently of a
    /// synchronous ready result. Reconstructed from the FIFO after restore.
    work_reserved: bool = false,
};

const Job = struct { ip: dns.Address };

pub const Resolver = struct {
    allocator: std.mem.Allocator,
    cfg: dns.ResolverConfig,
    zones: [max_zones][]u8 = undefined,
    zone_count: usize = 0,
    mutex: std.atomic.Mutex = .unlocked,
    producers: runtime_pause.ProducerState = .{},
    stop_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    thread: ?std.Thread = null,
    runtime: runtime_pause.WorkerState = .{},
    entries: []Entry,
    jobs: [job_capacity]Job = undefined,
    job_head: usize = 0,
    job_tail: usize = 0,
    job_count: usize = 0,
    /// Protected by mutex; a dequeued job is still accepted work.
    active_job: ?Job = null,
    /// Bounded background recovery of historical pending rows without a job.
    recovery_cursor: usize = 0,

    pub fn init(allocator: std.mem.Allocator, zones: []const []const u8) !Resolver {
        try validateZones(zones);
        const entries = try allocator.alloc(Entry, cache_slots);
        errdefer allocator.free(entries);
        for (entries) |*e| e.* = .{};

        var self = Resolver{
            .allocator = allocator,
            .cfg = dns.systemResolverConfig(),
            .entries = entries,
        };
        errdefer for (self.zones[0..self.zone_count]) |z| allocator.free(z);
        for (zones) |zone| {
            self.zones[self.zone_count] = try allocator.dupe(u8, zone);
            self.zone_count += 1;
        }
        return self;
    }

    pub fn initConfigured(allocator: std.mem.Allocator, io: std.Io, cfg: dns.ResolverConfig, zones: []const []const u8) !Resolver {
        _ = try configDigest(cfg, zones);
        const entries = try allocator.alloc(Entry, cache_slots);
        errdefer allocator.free(entries);
        for (entries) |*e| e.* = .{};
        var self: Resolver = .{ .allocator = allocator, .cfg = cfg, .entries = entries };
        errdefer for (self.zones[0..self.zone_count]) |zone| allocator.free(zone);
        for (zones) |zone| {
            self.zones[self.zone_count] = try allocator.dupe(u8, zone);
            self.zone_count += 1;
        }
        try self.runtime.pause.bindIo(io);
        return self;
    }
    pub fn prepareColdResources(self: *Resolver, io: std.Io) !void {
        if (self.thread != null or self.runtime.view != null or self.runtime.entered.load(.acquire) or self.runtime.exited.load(.acquire)) return error.AlreadyStarted;
        _ = try configDigest(self.cfg, self.zones[0..self.zone_count]);
        try self.runtime.pause.prepareIo(io);
    }
    pub fn validateDormantRegistration(self: *Resolver, control: *runtime_pause.start_gate.Control, view: *const runtime_pause.start_gate.View, slot: runtime_pause.start_gate.Slot) !void {
        try self.runtime.validateRegistration(control, view, slot, .dnsbl, 0, self, dormant_spawn_options);
    }
    pub fn prepareDormantWorker(self: *Resolver, control: *runtime_pause.start_gate.Control, view: *const runtime_pause.start_gate.View, slot: runtime_pause.start_gate.Slot) !void {
        try self.runtime.validatePreparation(control, view, slot, .dnsbl, 0, self, dormant_spawn_options);
        if (self.thread != null) return error.AlreadyStarted;
        if (self.cfg.nameserver_count == 0 or self.zone_count == 0) return error.NotConfigured;
        self.stop_flag.store(false, .release);
        try self.runtime.prepare(control, view, slot, .dnsbl, 0, Resolver, self, worker, dormant_spawn_options);
    }
    /// Signals this owner only. Runtime Control owns all actual joins.
    pub fn requestStopAndWake(self: *Resolver) void {
        self.stop_flag.store(true, .release);
        self.runtime.wakeForStop();
    }
    pub fn detachAfterJoined(self: *Resolver) !void {
        try self.runtime.detachAfterJoined();
    }
    pub fn requireParked(self: *Resolver) !void {
        try self.runtime.requireParked();
    }
    pub fn requireActivated(self: *Resolver) !void {
        if (self.stop_flag.load(.acquire)) return error.Stopped;
        try self.runtime.requireActivated();
    }
    pub fn fenceProducers(self: *Resolver) !runtime_pause.ProducerFence {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.producers.freezeLocked();
    }
    pub fn requireProducersFrozen(self: *Resolver, fence: runtime_pause.ProducerFence) !void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        try self.producers.requireLocked(fence);
    }
    pub fn resumeProducers(self: *Resolver, fence: runtime_pause.ProducerFence) !void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        try self.producers.resumeLocked(fence);
    }
    pub fn inspectFrozen(self: *Resolver, fence: runtime_pause.ProducerFence, token: ?runtime_pause.Token) !struct { execution: Execution, queued: usize } {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        try self.producers.requireLocked(fence);
        if (self.active_job != null) return error.NotQuiescent;
        return .{ .execution = try self.requireCaptureCut(token), .queued = self.job_count };
    }
    pub fn requestPause(self: *Resolver, epoch: u64) !runtime_pause.Token {
        return self.runtime.pause.request(epoch);
    }
    pub fn awaitPaused(self: *Resolver, token: runtime_pause.Token, deadline: std.Io.Clock.Timestamp) !void {
        try self.runtime.pause.awaitPaused(token, deadline);
    }
    pub fn resumePaused(self: *Resolver, token: runtime_pause.Token) !void {
        try self.runtime.pause.resumePaused(token);
    }

    pub fn capturePaused(self: *Resolver, allocator: std.mem.Allocator, token: runtime_pause.Token, max_bytes: usize) !Snapshot {
        return self.captureCut(allocator, token, null, max_bytes);
    }
    /// A real unstarted owner can retain accepted cache/FIFO state. The caller
    /// holds whole-runtime producer/lifecycle exclusion; no worker arrival is
    /// fabricated and this refuses an existing legacy or Gate-owned worker.
    pub fn captureUnstarted(self: *Resolver, allocator: std.mem.Allocator, max_bytes: usize) !Snapshot {
        return self.captureCut(allocator, null, null, max_bytes);
    }
    fn requireCaptureCut(self: *Resolver, token: ?runtime_pause.Token) !Execution {
        if (token) |actual| {
            if (self.thread == null and self.runtime.view == null) return error.NotRunning;
            try self.runtime.pause.requirePaused(actual);
            return .paused;
        }
        if (self.thread != null or self.runtime.view != null) return error.NotQuiescent;
        return .unstarted;
    }
    /// Source-issued producer fence is rechecked under the exact data lock
    /// used for capture; no unlocked empty-queue observation grants custody.
    pub fn captureFrozen(self: *Resolver, allocator: std.mem.Allocator, fence: runtime_pause.ProducerFence, token: ?runtime_pause.Token, max_bytes: usize) !Snapshot {
        try self.requireProducersFrozen(fence);
        return self.captureCut(allocator, token, fence, max_bytes);
    }
    fn captureCut(self: *Resolver, allocator: std.mem.Allocator, token: ?runtime_pause.Token, fence: ?runtime_pause.ProducerFence, max_bytes: usize) !Snapshot {
        const execution = try self.requireCaptureCut(token);
        {
            lockSpin(&self.mutex);
            defer self.mutex.unlock();
            if (self.active_job != null) return error.NotQuiescent;
        }
        // Zones/configuration are immutable for the actual owner's lifetime.
        const digest = try configDigest(self.cfg, self.zones[0..self.zone_count]);
        var bytes = @sizeOf(Snapshot) + cache_slots * @sizeOf(CacheEntry) + job_capacity * @sizeOf(dns.Address) + self.zone_count * @sizeOf([]u8);
        for (self.zones[0..self.zone_count]) |zone| bytes = std.math.add(usize, bytes, zone.len) catch return error.Capacity;
        if (bytes > max_bytes) return error.Capacity;
        const entries = try allocator.alloc(CacheEntry, cache_slots);
        errdefer allocator.free(entries);
        const jobs = try allocator.alloc(dns.Address, job_capacity);
        errdefer allocator.free(jobs);
        const zones = try allocator.alloc([]u8, self.zone_count);
        errdefer allocator.free(zones);
        var copied: usize = 0;
        errdefer for (zones[0..copied]) |zone| allocator.free(zone);
        for (self.zones[0..self.zone_count], zones) |zone, *out| {
            out.* = try allocator.dupe(u8, zone);
            copied += 1;
        }
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (fence) |proof| try self.producers.requireLocked(proof);
        _ = try self.requireCaptureCut(token);
        if (self.active_job != null) return error.NotQuiescent;
        if (self.entries.len != cache_slots or self.job_count > job_capacity) return error.InvalidState;
        for (self.entries, entries) |entry, *out| out.* = .{ .key = entry.key, .has_key = entry.has_key, .state = entry.state, .verdict = entry.verdict, .resolved_ms = entry.resolved_ms };
        for (0..self.job_count) |i| jobs[i] = self.jobs[(self.job_head + i) % job_capacity].ip;
        const result: Snapshot = .{ .allocator = allocator, .entries = entries, .jobs = jobs, .job_count = self.job_count, .execution = execution, .zones = zones, .config_digest = digest, .captured_monotonic_ms = platform.monotonicMillis() };
        try result.validate(self.cfg, self.zones[0..self.zone_count]);
        return result;
    }
    pub fn restoreSnapshot(self: *Resolver, snapshot: *const Snapshot) !void {
        if (self.thread != null or self.runtime.view != null or self.runtime.pause.request_epoch != 0) return error.AlreadyStarted;
        try snapshot.validate(self.cfg, self.zones[0..self.zone_count]);
        try self.publishSnapshot(snapshot);
    }

    /// The successor can prepare its actual DNSBL worker under the Windows
    /// Gate before decoding. Prove that owner is still parked on both sides of
    /// validation, then publish the already allocated carry without failure.
    pub fn restoreSnapshotParked(self: *Resolver, snapshot: *const Snapshot) !void {
        if (self.thread != null or self.runtime.pause.request_epoch != 0) return error.AlreadyStarted;
        try self.requireParked();
        try snapshot.validate(self.cfg, self.zones[0..self.zone_count]);
        try self.requireParked();
        try self.publishSnapshot(snapshot);
    }

    fn publishSnapshot(self: *Resolver, snapshot: *const Snapshot) !void {
        if (self.active_job != null) return error.NotQuiescent;
        if (self.entries.len != cache_slots) return error.InvalidState;
        for (snapshot.entries, self.entries) |entry, *out| out.* = .{ .key = entry.key, .has_key = entry.has_key, .state = entry.state, .verdict = entry.verdict, .resolved_ms = entry.resolved_ms };
        for (snapshot.jobs[0..snapshot.job_count], 0..) |ip, i| {
            self.jobs[i] = .{ .ip = ip };
            // This cold restore walk derives runtime custody only. Keep every
            // cache row and FIFO record exactly as carried, including ready
            // rows with queued work and historical orphan pending entries.
            if (self.find(ip)) |entry| entry.work_reserved = true;
        }
        self.recovery_cursor = 0;
        self.job_head = 0;
        self.job_count = snapshot.job_count;
        self.job_tail = snapshot.job_count % job_capacity;
    }

    pub fn deinit(self: *Resolver) void {
        self.runtime.requireDetached() catch @panic("managed worker must join and detach before deinit");
        self.stop();
        for (self.zones[0..self.zone_count]) |z| self.allocator.free(z);
        self.allocator.free(self.entries);
        self.* = undefined;
    }

    /// Spawn the resolver thread. Inert (no thread) when no nameservers are
    /// configured or no zones are set; requests then simply never become ready
    /// and callers treat every client as not-listed.
    pub fn start(self: *Resolver) void {
        self.startChecked() catch {};
    }

    /// Strict startup for an explicitly configured blocklist. The daemon must
    /// not advertise DNSBL enforcement if DNS discovery or thread creation
    /// left it inert.
    pub fn startChecked(self: *Resolver) !void {
        if (self.thread != null or self.runtime.view != null) return error.AlreadyStarted;
        if (self.cfg.nameserver_count == 0) return error.NoNameservers;
        if (self.zone_count == 0) return error.NoZones;
        self.stop_flag.store(false, .release);
        errdefer self.stop_flag.store(true, .release);
        self.thread = try std.Thread.spawn(.{}, worker, .{self});
    }

    pub fn stop(self: *Resolver) void {
        self.runtime.requireDetached() catch @panic("managed stop requires Runtime Control join and source detach");
        self.stop_flag.store(true, .release);
        self.runtime.wakeForStop();
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
    }

    // ---- reactor-side API (mutex-guarded, never blocks on the network) -------

    /// Ensure `ip` is being checked. No-op if a fresh entry already exists or a
    /// job is already queued. Non-blocking.
    pub fn request(self: *Resolver, ip: dns.Address) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const now = platform.monotonicMillis();
        if (self.find(ip)) |e| {
            if (e.state == .pending and e.work_reserved) return;
            if (e.state == .ready and (now - e.resolved_ms) < entry_ttl_ms) return;
        }
        self.enqueueLocked(ip);
    }

    /// Record a resolved verdict in the cache without a probe. The worker
    /// writes the same slot after DNS; this is the synchronous form so a
    /// caller that already holds a verdict can make `lookup` answer. Existing
    /// queued/active work retains custody of the row and may later replace this
    /// verdict with its own completion; remember does not cancel that work.
    pub fn remember(self: *Resolver, ip: dns.Address, verdict: Verdict) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (self.producers.frozen or self.stop_flag.load(.acquire)) return;
        const e = self.reserve(ip) orelse return;
        e.verdict = verdict;
        e.state = .ready;
        e.resolved_ms = platform.monotonicMillis();
    }

    /// Cached verdict for `ip`, or null when not yet resolved (pending/absent).
    /// A resolved not-listed result is a real answer (`.listed == false`), not a
    /// miss. Never blocks.
    pub fn lookup(self: *Resolver, ip: dns.Address) ?Verdict {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const e = self.find(ip) orelse return null;
        if (e.state != .ready) return null;
        return e.verdict;
    }

    // ---- internals -----------------------------------------------------------

    fn find(self: *Resolver, ip: dns.Address) ?*Entry {
        for (self.entries) |*e| {
            if (e.has_key and addrEql(e.key, ip)) return e;
        }
        return null;
    }

    /// Find or claim a slot for `ip`. Pending rows and accepted work remain
    /// pinned, including ready results supplied while a job is outstanding.
    /// Caller holds the mutex.
    fn reserve(self: *Resolver, ip: dns.Address) ?*Entry {
        if (self.find(ip)) |e| return e;
        const e = self.victim() orelse return null;
        e.* = .{};
        e.key = ip;
        e.has_key = true;
        e.state = .pending;
        return e;
    }

    fn victim(self: *Resolver) ?*Entry {
        var oldest: ?*Entry = null;
        for (self.entries) |*e| {
            if (!e.has_key or e.state == .empty) return e;
            if (e.state == .pending or e.work_reserved) continue;
            if (oldest == null or e.resolved_ms < oldest.?.resolved_ms) oldest = e;
        }
        return oldest;
    }

    /// Caller holds the mutex.
    fn enqueueLocked(self: *Resolver, ip: dns.Address) void {
        if (self.producers.frozen or self.stop_flag.load(.acquire)) return;
        if (self.job_count >= job_capacity) return;
        if (self.active_job) |active| if (addrEql(active.ip, ip)) return;
        var i: usize = 0;
        var idx = self.job_head;
        while (i < self.job_count) : (i += 1) {
            if (addrEql(self.jobs[idx].ip, ip)) return; // already queued
            idx = (idx + 1) % job_capacity;
        }
        // Publish pending only after queue admission is certain. A refused
        // request must remain retryable and must not evict a cache entry.
        const entry = self.reserve(ip) orelse return;
        self.appendJobLocked(entry, ip);
    }

    fn appendJobLocked(self: *Resolver, entry: *Entry, ip: dns.Address) void {
        std.debug.assert(self.job_count < job_capacity and !entry.work_reserved);
        entry.* = .{ .key = ip, .has_key = true, .state = .pending, .work_reserved = true };
        self.jobs[self.job_tail] = .{ .ip = ip };
        self.job_tail = (self.job_tail + 1) % job_capacity;
        self.job_count += 1;
    }

    /// A v1 snapshot may contain pending rows without queued work. Repair only
    /// unowned rows, behind the accepted FIFO, without an unbounded admission
    /// scan on the reactor. Full/frozen queues retain them for a later boundary.
    fn recoverPendingLocked(self: *Resolver) void {
        if (self.producers.frozen or self.stop_flag.load(.acquire) or self.job_count == job_capacity) return;
        const entry = self.orphanCandidateLocked() orelse return;
        self.appendJobLocked(entry, entry.key);
    }

    fn orphanCandidateLocked(self: *Resolver) ?*Entry {
        for (0..@min(self.entries.len, 64)) |_| {
            const entry = &self.entries[self.recovery_cursor];
            self.recovery_cursor = (self.recovery_cursor + 1) % self.entries.len;
            if (!entry.has_key or entry.state != .pending or entry.work_reserved) continue;
            if (self.active_job) |active| if (addrEql(active.ip, entry.key)) continue;
            return entry;
        }
        return null;
    }

    /// A historical FIFO head can lack a cache row while every row is pending.
    /// Appending repairs behind that head would deadlock. Finish one existing
    /// orphan obligation first, without changing any FIFO item or cursor. Its
    /// completed row becomes reclaimable by the original head on the next turn.
    fn claimBlockingRepairLocked(self: *Resolver) ?Job {
        if (self.producers.frozen or self.stop_flag.load(.acquire)) return null;
        const entry = self.orphanCandidateLocked() orelse return null;
        const job = Job{ .ip = entry.key };
        entry.work_reserved = true;
        self.active_job = job;
        return job;
    }

    fn takeJob(self: *Resolver) ?Job {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (self.active_job != null or self.stop_flag.load(.acquire)) return null;
        const was_empty = self.job_count == 0;
        if (was_empty) self.recoverPendingLocked();
        if (self.job_count == 0) return null;
        const job = self.jobs[self.job_head];
        // Reserve before attempting normal recovery so that a rowless blocked
        // head cannot pin its last available orphan behind itself in the FIFO.
        const entry = self.reserve(job.ip) orelse return self.claimBlockingRepairLocked();
        entry.work_reserved = true;
        if (!was_empty) self.recoverPendingLocked();
        self.active_job = job;
        self.job_head = (self.job_head + 1) % job_capacity;
        self.job_count -= 1;
        return job;
    }

    fn completeJob(self: *Resolver, job: Job, verdict: Verdict) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        std.debug.assert(self.active_job != null and addrEql(self.active_job.?.ip, job.ip));
        const entry = self.find(job.ip) orelse unreachable;
        std.debug.assert(entry.work_reserved);
        entry.verdict = verdict;
        entry.resolved_ms = platform.monotonicMillis();
        entry.state = .ready;
        entry.work_reserved = false;
        self.active_job = null;
    }

    fn worker(self: *Resolver) void {
        self.runtime.markEntered();
        defer self.runtime.markExited();
        while (!self.stop_flag.load(.acquire)) {
            self.runtime.pause.boundary();
            if (self.stop_flag.load(.acquire)) break;
            const job = self.takeJob() orelse {
                sleepMs(100); // low-rate work: poll for jobs, observe the stop flag
                continue;
            };
            // DNS I/O happens OUTSIDE the lock (it can block for seconds).
            const verdict = self.probe(job.ip);

            self.completeJob(job, verdict);
        }
    }

    /// Probe every configured zone for `ip`, stopping at the first listing. Run
    /// outside the mutex. Any per-zone error (NXDOMAIN, no data, timeout) means
    /// "not listed by that zone" and the scan continues. All zones share one
    /// deadline of at most five seconds. Each receives an equal share of the
    /// remaining time, so earlier silence cannot consume every later zone's
    /// opportunity; quick replies leave their unused time to the remaining zones.
    fn probe(self: *const Resolver, ip: dns.Address) Verdict {
        const deadline = DnsDeadline.after(dns_engine.defaultBudget(&self.cfg));
        var query_cfg = self.cfg;
        if (comptime @import("builtin").os.tag == .windows) {
            // Preserve the existing per-attempt limit and stop boundary for
            // a single-zone Windows probe as well as the whole-scan deadline.
            query_cfg.timeout_ms = @min(query_cfg.timeout_ms, 1000);
            query_cfg.attempts = @min(query_cfg.attempts, 1);
        }
        for (self.zones[0..self.zone_count], 0..) |zone, index| {
            if (self.stop_flag.load(.acquire)) break;
            const remaining = deadline.remaining() catch break;
            const zones_left: u32 = @intCast(self.zone_count - index);
            const zone_deadline = deadline.slice(@max(1, remaining / zones_left)) catch break;
            var name_buf: [dns.max_domain_text_len]u8 = undefined;
            const name = switch (ip) {
                .ipv4 => |b| dnsbl.reverseNameV4(b, zone, &name_buf),
                .ipv6 => |b| dnsbl.reverseNameV6(b, zone, &name_buf),
            } catch continue;

            const result = dns_engine.resolveUntil(&query_cfg, name, .a, zone_deadline) catch continue;
            if (result.outcome != .positive) continue;

            var a_records: [8][4]u8 = undefined;
            var n: usize = 0;
            for (result.addressSlice()[0..@min(8, result.address_count)]) |ans| switch (ans) {
                .ipv4 => |b| {
                    a_records[n] = b;
                    n += 1;
                },
                .ipv6 => {},
            };
            const listing = dnsbl.classify(a_records[0..n]);
            if (listing.listed) return .{ .listed = true, .code = listing.code };
        }
        return .{ .listed = false };
    }
};

fn addrEql(a: dns.Address, b: dns.Address) bool {
    return checkpoint.addressEql(a, b);
}

fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.Thread.yield() catch {};
}

fn sleepMs(ms: u32) void {
    if (comptime @import("builtin").os.tag != .linux) {
        @import("os_runtime.zig").sleepMillis(ms);
        return;
    }
    const linux = std.os.linux;
    var req = linux.timespec{ .sec = @divTrunc(ms, 1000), .nsec = @as(isize, ms % 1000) * 1_000_000 };
    _ = linux.nanosleep(&req, null);
}

test "request enqueues; lookup misses until a verdict is stored" {
    var r = try Resolver.init(std.testing.allocator, &.{"zen.example.org"});
    defer r.deinit();

    const ip = dns.Address{ .ipv4 = .{ 192, 0, 2, 1 } };
    r.request(ip); // enqueues a pending entry; no worker thread started
    try std.testing.expect(r.lookup(ip) == null); // pending → miss

    // Simulate the worker storing a listed verdict.
    {
        lockSpin(&r.mutex);
        const e = r.reserve(ip) orelse return error.TestUnexpectedResult;
        e.verdict = .{ .listed = true, .code = 2 };
        e.state = .ready;
        r.mutex.unlock();
    }
    const hit = r.lookup(ip).?;
    try std.testing.expect(hit.listed);
    try std.testing.expectEqual(@as(u8, 2), hit.code);

    // A resolved not-listed verdict for another IP is a real answer, not null.
    const clean = dns.Address{ .ipv4 = .{ 198, 51, 100, 9 } };
    {
        lockSpin(&r.mutex);
        const e = r.reserve(clean) orelse return error.TestUnexpectedResult;
        e.verdict = .{ .listed = false };
        e.state = .ready;
        r.mutex.unlock();
    }
    try std.testing.expect(!r.lookup(clean).?.listed);
}

test "request de-dupes and the job ring stays bounded" {
    var r = try Resolver.init(std.testing.allocator, &.{ "zen.example.org", "bl.example.net" });
    defer r.deinit();
    const ip = dns.Address{ .ipv4 = .{ 203, 0, 113, 5 } };
    r.request(ip);
    r.request(ip);
    r.request(ip);
    try std.testing.expectEqual(@as(usize, 1), r.job_count);
}

test "DNSBL strict startup refuses missing nameservers and zones" {
    var missing_nameservers = try Resolver.initConfigured(std.testing.allocator, std.testing.io, .{}, &.{"dnsbl.test"});
    defer missing_nameservers.deinit();
    try std.testing.expectError(error.NoNameservers, missing_nameservers.startChecked());
    try std.testing.expect(missing_nameservers.thread == null);

    var cfg: dns.ResolverConfig = .{};
    cfg.addNameserver(.{ .ipv4 = .{ 127, 0, 0, 1 } });
    var missing_zones = try Resolver.initConfigured(std.testing.allocator, std.testing.io, cfg, &.{});
    defer missing_zones.deinit();
    try std.testing.expectError(error.NoZones, missing_zones.startChecked());
    try std.testing.expect(missing_zones.thread == null);
}

test "DNSBL rejects invalid zones before starting a worker" {
    try std.testing.expectError(error.InvalidName, validateZones(&.{"bad zone.test"}));
    const too_many = [_][]const u8{ "a.test", "b.test", "c.test", "d.test", "e.test", "f.test", "g.test", "h.test", "i.test" };
    try std.testing.expectError(error.TooManyZones, validateZones(&too_many));
    var too_long: [190]u8 = @splat('a');
    too_long[63] = '.';
    too_long[127] = '.';
    const long_zones = [_][]const u8{too_long[0..]};
    try std.testing.expectError(error.NameTooLong, validateZones(&long_zones));
}

test "Windows DNSBL worker resolves listed and clean addresses and stops during a silent query" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;

    var startup: [408]u8 align(8) = @splat(0);
    try std.testing.expectEqual(@as(i32, 0), test_win.WSAStartup(0x0202, &startup));
    defer _ = test_win.WSACleanup();
    const socket = test_win.WSASocketW(2, 2, 17, null, 0, 1);
    try std.testing.expect(socket != test_win.invalid_socket);
    defer _ = test_win.closesocket(socket);
    var bind_addr = test_win.SockAddr4{ .family = 2, .port = 0, .addr = .{ 127, 0, 0, 1 } };
    try std.testing.expectEqual(@as(i32, 0), test_win.bind(socket, &bind_addr, @sizeOf(test_win.SockAddr4)));
    var addr_len: i32 = @sizeOf(test_win.SockAddr4);
    try std.testing.expectEqual(@as(i32, 0), test_win.getsockname(socket, &bind_addr, &addr_len));
    const receive_timeout_ms: u32 = 2000;
    try std.testing.expectEqual(@as(i32, 0), test_win.setsockopt(socket, 0xffff, 0x1006, &receive_timeout_ms, @sizeOf(u32)));

    const Responder = struct {
        socket: usize,
        queries: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
        valid: std.atomic.Value(bool) = std.atomic.Value(bool).init(true),

        fn run(self: *@This()) void {
            for (0..3) |index| {
                var query_buf: [dns.max_message_len]u8 = undefined;
                var peer: test_win.SockAddr4 = undefined;
                var peer_len: i32 = @sizeOf(test_win.SockAddr4);
                const got = test_win.recvfrom(self.socket, &query_buf, @intCast(query_buf.len), 0, &peer, &peer_len);
                if (got <= 0) return;
                const parsed = dns.parseMessage(1, 0, query_buf[0..@intCast(got)]) catch {
                    self.valid.store(false, .release);
                    return;
                };
                if (parsed.question_count != 1 or parsed.questions[0].qtype != .a) {
                    self.valid.store(false, .release);
                    return;
                }
                const q = dns.Query{ .name = parsed.questions[0].name.slice(), .qtype = .a };
                var expected_buf: [dns.max_domain_text_len]u8 = undefined;
                const expected = dnsbl.reverseNameV4(.{ 203, 0, 113, @intCast(5 + index) }, "dnsbl.test", &expected_buf) catch unreachable;
                if (!std.mem.eql(u8, q.name, expected)) {
                    self.valid.store(false, .release);
                    return;
                }
                _ = self.queries.fetchAdd(1, .acq_rel);
                if (index == 2) return; // Hold the final lookup until its UDP timeout.
                const answer = dns.Answer{ .name = q.name, .rr_type = .a, .ttl = 30, .data = .{ .a = .{ 127, 0, 0, 7 } } };
                const answers: []const dns.Answer = if (index == 0) &.{answer} else &.{};
                var response_buf: [dns.max_message_len]u8 = undefined;
                const response = dns.encodeMessage(&response_buf, .{
                    .id = parsed.header.id,
                    .response = true,
                    .questions = &.{q},
                    .answers = answers,
                    .rcode = if (index == 0) 0 else 3,
                }) catch {
                    self.valid.store(false, .release);
                    return;
                };
                if (test_win.sendto(self.socket, response.ptr, @intCast(response.len), 0, &peer, peer_len) != @as(i32, @intCast(response.len))) {
                    self.valid.store(false, .release);
                    return;
                }
            }
        }
    };
    var responder: Responder = .{ .socket = socket };
    const responder_thread = try std.Thread.spawn(.{}, Responder.run, .{&responder});
    defer responder_thread.join();

    // Intentionally use a long caller timeout: the worker must enforce its
    // Windows stop bound while this final query receives no answer.
    var cfg: dns.ResolverConfig = .{ .port = std.mem.bigToNative(u16, bind_addr.port), .timeout_ms = 4000, .attempts = 3 };
    cfg.addNameserver(.{ .ipv4 = .{ 127, 0, 0, 1 } });
    var resolver = try Resolver.initConfigured(std.testing.allocator, std.testing.io, cfg, &.{"dnsbl.test"});
    defer resolver.deinit();
    try resolver.startChecked();
    try std.testing.expect(resolver.thread != null);

    const listed: dns.Address = .{ .ipv4 = .{ 203, 0, 113, 5 } };
    const clean: dns.Address = .{ .ipv4 = .{ 203, 0, 113, 6 } };
    resolver.request(listed);
    resolver.request(clean);
    const ready_deadline = platform.monotonicMillis() + 4000;
    while (platform.monotonicMillis() < ready_deadline and (resolver.lookup(listed) == null or resolver.lookup(clean) == null)) sleepMs(10);
    try std.testing.expect(resolver.lookup(listed) != null);
    try std.testing.expectEqual(Verdict{ .listed = true, .code = 7 }, resolver.lookup(listed).?);
    try std.testing.expectEqual(Verdict{ .listed = false }, resolver.lookup(clean).?);

    resolver.request(.{ .ipv4 = .{ 203, 0, 113, 7 } });
    const query_deadline = platform.monotonicMillis() + 2000;
    while (platform.monotonicMillis() < query_deadline and responder.queries.load(.acquire) < 3) sleepMs(10);
    try std.testing.expectEqual(@as(u32, 3), responder.queries.load(.acquire));
    const stop_start = platform.monotonicMillis();
    resolver.stop();
    try std.testing.expect(platform.monotonicMillis() - stop_start < 2500);
    try std.testing.expect(resolver.runtime.entered.load(.acquire));
    try std.testing.expect(resolver.runtime.exited.load(.acquire));
    try std.testing.expect(responder.valid.load(.acquire));
}

fn pausedDnsblCaptureAllocation(allocator: std.mem.Allocator, resolver: *Resolver, token: runtime_pause.Token) !void {
    var snapshot = try resolver.capturePaused(allocator, token, 1024 * 1024);
    defer snapshot.deinit();
    try std.testing.expectEqual(@as(usize, 2), snapshot.job_count);
    try std.testing.expectEqual(@as(usize, 2), snapshot.zones.len);
}

test "companion runtime dnsbl retained pause preserves ready queued state zones and OOM" {
    var cfg: dns.ResolverConfig = .{};
    cfg.addNameserver(.{ .ipv4 = .{ 192, 0, 2, 53 } });
    const zones = [_][]const u8{ "one.invalid", "two.invalid" };
    var resolver = try Resolver.initConfigured(std.testing.allocator, std.testing.io, cfg, &zones);
    const specs = [_]runtime_pause.start_gate.ParticipantSpec{.{ .kind = .dnsbl, .instance = 0, .owner_identity = &resolver }};
    const gate = runtime_pause.start_gate.create(std.testing.allocator, std.testing.io, &specs) catch |err| {
        resolver.deinit();
        return err;
    };
    defer {
        resolver.requestStopAndWake();
        if (gate.view.inspect().phase == .preparing) gate.control.cancelAllAndJoin() else gate.control.joinAll();
        resolver.detachAfterJoined() catch unreachable;
        resolver.deinit();
        gate.control.destroyJoined();
    }
    const a: dns.Address = .{ .ipv4 = .{ 192, 0, 2, 1 } };
    const b: dns.Address = .{ .ipv4 = .{ 192, 0, 2, 2 } };
    resolver.request(a);
    resolver.request(b);
    resolver.remember(a, .{ .listed = true, .code = 7 });
    const token = try resolver.requestPause(1);
    try resolver.prepareDormantWorker(gate.control, gate.view, try gate.view.slot(.dnsbl, 0, &resolver));
    try gate.control.awaitAllParked(std.Io.Clock.Timestamp.fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
    gate.control.releaseAll();
    try resolver.awaitPaused(token, std.Io.Clock.Timestamp.fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
    try std.testing.checkAllAllocationFailures(std.testing.allocator, pausedDnsblCaptureAllocation, .{ &resolver, token });
    var snapshot = try resolver.capturePaused(std.testing.allocator, token, 1024 * 1024);
    defer snapshot.deinit();
    var restored = try Resolver.initConfigured(std.testing.allocator, std.testing.io, cfg, &zones);
    defer restored.deinit();
    try restored.restoreSnapshot(&snapshot);
    try std.testing.expectEqual(@as(usize, 2), restored.job_count);
    try std.testing.expectEqual(@as(u8, 7), restored.entries[0].verdict.code);
    try std.testing.expect(restored.entries[0].verdict.listed);
    try std.testing.expect(addrEql(a, restored.jobs[0].ip));
    const original = snapshot.jobs[1];
    snapshot.jobs[1] = snapshot.jobs[0];
    try std.testing.expectError(error.InvalidState, restored.restoreSnapshot(&snapshot));
    snapshot.jobs[1] = original;
    snapshot.zones[0][0] ^= 1;
    try std.testing.expectError(error.ConfigMismatch, restored.restoreSnapshot(&snapshot));
    snapshot.zones[0][0] ^= 1;
    try std.testing.expectEqual(@as(usize, 2), resolver.job_count);
}

test "companion cold Io preparation DNSBL configured and legacy owners confirm exact source" {
    var cfg: dns.ResolverConfig = .{};
    cfg.addNameserver(.{ .ipv4 = .{ 127, 0, 0, 1 } });
    const zones = [_][]const u8{"fixture.invalid"};
    var configured = try Resolver.initConfigured(std.testing.allocator, std.testing.io, cfg, &zones);
    defer configured.deinit();
    try configured.prepareColdResources(std.testing.io);
    try configured.prepareColdResources(std.testing.io);
    var different_vtable = std.testing.io.vtable.*;
    const wrong: std.Io = .{ .userdata = std.testing.io.userdata, .vtable = &different_vtable };
    try std.testing.expectError(error.IoMismatch, configured.prepareColdResources(wrong));
    configured.start();
    try std.testing.expect(configured.thread != null);
    try std.testing.expectError(error.AlreadyStarted, configured.prepareColdResources(std.testing.io));
    configured.stop();
    try std.testing.expect(configured.runtime.entered.load(.acquire));
    try std.testing.expect(configured.runtime.exited.load(.acquire));
    try std.testing.expectError(error.AlreadyStarted, configured.prepareColdResources(std.testing.io));
    var legacy = try Resolver.init(std.testing.allocator, &zones);
    defer legacy.deinit();
    try legacy.prepareColdResources(std.testing.io);
    try legacy.prepareColdResources(std.testing.io);
    const token = try legacy.requestPause(1);
    try std.testing.expectError(error.Busy, legacy.prepareColdResources(std.testing.io));
    try legacy.resumePaused(token);
    try std.testing.expectError(error.Busy, legacy.prepareColdResources(std.testing.io));
}

test "companion runtime producer fence DNSBL preserves accepted cache and FIFO across resume" {
    const zones = [_][]const u8{"fixture.invalid"};
    var resolver = try Resolver.initConfigured(std.testing.allocator, std.testing.io, .{}, &zones);
    defer resolver.deinit();
    const accepted: dns.Address = .{ .ipv4 = .{ 192, 0, 2, 31 } };
    const refused: dns.Address = .{ .ipv4 = .{ 192, 0, 2, 32 } };
    resolver.request(accepted);
    const fence = try resolver.fenceProducers();
    resolver.request(refused);
    resolver.remember(accepted, .{ .listed = true, .code = 7 });
    try std.testing.expect(resolver.lookup(accepted) == null);
    try std.testing.expect(resolver.find(refused) == null);
    var snapshot = try resolver.captureFrozen(std.testing.allocator, fence, null, 1024 * 1024);
    defer snapshot.deinit();
    try std.testing.expectEqual(@as(usize, 1), snapshot.job_count);
    try std.testing.expect(addrEql(accepted, snapshot.jobs[0]));
    try resolver.resumeProducers(fence);
    resolver.remember(accepted, .{ .listed = true, .code = 7 });
    try std.testing.expectEqual(@as(u8, 7), resolver.lookup(accepted).?.code);
    const next = try resolver.fenceProducers();
    try std.testing.expectError(error.InvalidProducerFence, resolver.resumeProducers(fence));
    try resolver.requireProducersFrozen(next);
}

test "DNS worker full queue does not strand an unaccepted address" {
    var resolver = try Resolver.init(std.testing.allocator, &.{"dnsbl.test"});
    defer resolver.deinit();
    for (0..job_capacity) |i| {
        resolver.request(.{ .ipv4 = .{ 192, 0, @intCast(i / 256), @intCast(i % 256) } });
    }
    const overflow: dns.Address = .{ .ipv4 = .{ 198, 51, 100, 7 } };
    resolver.request(overflow);
    try std.testing.expectEqual(job_capacity, resolver.job_count);
    try std.testing.expect(resolver.find(overflow) == null);
    const first = resolver.takeJob() orelse return error.TestUnexpectedResult;
    resolver.request(overflow);
    try std.testing.expectEqual(job_capacity, resolver.job_count);
    try std.testing.expectEqual(State.pending, resolver.find(overflow).?.state);
    resolver.completeJob(first, .{ .listed = false });
    var occurrences: usize = 0;
    while (resolver.takeJob()) |job| {
        if (addrEql(job.ip, overflow)) occurrences += 1;
        resolver.completeJob(job, .{ .listed = false });
    }
    try std.testing.expectEqual(@as(usize, 1), occurrences);
}

test "DNS worker refresh stays pending after dequeue and preserves checkpoint validity" {
    var resolver = try Resolver.init(std.testing.allocator, &.{"dnsbl.test"});
    defer resolver.deinit();
    const ip: dns.Address = .{ .ipv4 = .{ 203, 0, 113, 7 } };
    const entry = resolver.reserve(ip) orelse return error.TestUnexpectedResult;
    entry.state = .ready;
    entry.resolved_ms = 0;
    entry.verdict = .{ .listed = true, .code = 2 };
    // Exercise admission directly so the test does not depend on host uptime.
    resolver.enqueueLocked(ip);
    try std.testing.expectEqual(State.pending, entry.state);
    var snapshot = try resolver.captureUnstarted(std.testing.allocator, 1024 * 1024);
    defer snapshot.deinit();
    try snapshot.validate(resolver.cfg, resolver.zones[0..resolver.zone_count]);
    const active = resolver.takeJob() orelse return error.TestUnexpectedResult;
    resolver.request(ip);
    try std.testing.expectEqual(@as(usize, 0), resolver.job_count);
    resolver.completeJob(active, .{ .listed = false });
}

test "DNS worker cache pressure preserves an in-flight pending address" {
    var resolver = try Resolver.init(std.testing.allocator, &.{"dnsbl.test"});
    defer resolver.deinit();
    for (resolver.entries, 0..) |*entry, i| {
        entry.* = .{ .key = .{ .ipv4 = .{ 192, 168, @intCast(i / 256), @intCast(i % 256) } }, .has_key = true, .state = .ready, .resolved_ms = @intCast(i + 1) };
    }
    const first: dns.Address = .{ .ipv4 = .{ 203, 0, 113, 1 } };
    const second: dns.Address = .{ .ipv4 = .{ 203, 0, 113, 2 } };
    resolver.request(first);
    const active = resolver.takeJob() orelse return error.TestUnexpectedResult;
    resolver.request(second);
    const retained = resolver.find(first) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(State.pending, retained.state);
    resolver.request(first);
    try std.testing.expectEqual(@as(usize, 1), resolver.job_count);
    try std.testing.expect(resolver.takeJob() == null);
    resolver.completeJob(active, .{ .listed = false });
    const next = resolver.takeJob() orelse return error.TestUnexpectedResult;
    try std.testing.expect(addrEql(second, next.ip));
    resolver.completeJob(next, .{ .listed = false });
}

test "DNS worker refuses admission when every cache entry is pending" {
    var resolver = try Resolver.init(std.testing.allocator, &.{"dnsbl.test"});
    defer resolver.deinit();
    for (resolver.entries, 0..) |*entry, i| {
        entry.* = .{ .key = .{ .ipv4 = .{ 192, 168, @intCast(i / 256), @intCast(i % 256) } }, .has_key = true, .state = .pending };
    }
    const incoming: dns.Address = .{ .ipv4 = .{ 203, 0, 113, 7 } };
    resolver.request(incoming);
    try std.testing.expectEqual(@as(usize, 0), resolver.job_count);
    try std.testing.expect(resolver.find(incoming) == null);
    for (resolver.entries, 0..) |entry, i| {
        const expected: dns.Address = .{ .ipv4 = .{ 192, 168, @intCast(i / 256), @intCast(i % 256) } };
        try std.testing.expect(addrEql(expected, entry.key));
        try std.testing.expectEqual(State.pending, entry.state);
    }
    // A synchronous verdict must not displace somebody else's accepted job.
    resolver.remember(incoming, .{ .listed = true, .code = 2 });
    try std.testing.expect(resolver.lookup(incoming) == null);
    try std.testing.expectEqual(@as(usize, 0), resolver.job_count);
    // Once a completed entry is available, the same request is retryable.
    resolver.entries[0].state = .ready;
    resolver.request(incoming);
    try std.testing.expectEqual(@as(usize, 1), resolver.job_count);
    try std.testing.expectEqual(State.pending, resolver.find(incoming).?.state);
}

test "DNSBL remembered ready results retain queued and active custody through restore and completion" {
    var source = try Resolver.initConfigured(std.testing.allocator, std.testing.io, .{}, &.{"dnsbl.test"});
    defer source.deinit();
    for (source.entries, 0..) |*entry, index| {
        entry.* = .{ .key = .{ .ipv4 = .{ 192, 168, @intCast(index / 256), @intCast(index % 256) } }, .has_key = true, .state = .ready, .resolved_ms = 1 };
    }
    const remembered: dns.Address = .{ .ipv4 = .{ 203, 0, 113, 1 } };
    const second: dns.Address = .{ .ipv4 = .{ 203, 0, 113, 2 } };
    const third: dns.Address = .{ .ipv4 = .{ 203, 0, 113, 3 } };
    source.request(remembered);
    source.remember(remembered, .{ .listed = true, .code = 7 });
    source.find(remembered).?.resolved_ms = 0; // would be the oldest unpinned victim
    source.request(second);
    try std.testing.expectEqual(@as(u8, 7), source.lookup(remembered).?.code);
    var snapshot = try source.captureUnstarted(std.testing.allocator, 1024 * 1024);
    defer snapshot.deinit();
    var resolver = try Resolver.initConfigured(std.testing.allocator, std.testing.io, .{}, &.{"dnsbl.test"});
    defer resolver.deinit();
    try resolver.restoreSnapshot(&snapshot);
    try std.testing.expect(resolver.find(remembered).?.work_reserved);
    try std.testing.expectEqual(@as(u8, 7), resolver.lookup(remembered).?.code);
    resolver.request(third);
    try std.testing.expectEqual(@as(u8, 7), resolver.lookup(remembered).?.code);
    const first = resolver.takeJob() orelse return error.TestUnexpectedResult;
    try std.testing.expect(addrEql(remembered, first.ip));
    resolver.remember(remembered, .{ .listed = true, .code = 9 });
    resolver.find(remembered).?.resolved_ms = 0;
    resolver.request(.{ .ipv4 = .{ 203, 0, 113, 4 } });
    try std.testing.expectEqual(@as(u8, 9), resolver.lookup(remembered).?.code);
    try std.testing.expect(resolver.find(remembered).?.work_reserved);
    resolver.completeJob(first, .{ .listed = true, .code = 2 });
    try std.testing.expectEqual(@as(u8, 2), resolver.lookup(remembered).?.code);
    try std.testing.expect(!resolver.find(remembered).?.work_reserved);
    try std.testing.expect(resolver.active_job == null);
    try std.testing.expectEqual(@as(usize, 3), resolver.job_count);
    for ([_]dns.Address{ second, third, .{ .ipv4 = .{ 203, 0, 113, 4 } } }) |expected| {
        const job = resolver.takeJob() orelse return error.TestUnexpectedResult;
        try std.testing.expect(addrEql(expected, job.ip));
        resolver.completeJob(job, .{ .listed = false });
    }
}

test "DNS worker restores and requeues historical orphan pending rows behind accepted FIFO" {
    var source = try Resolver.initConfigured(std.testing.allocator, std.testing.io, .{}, &.{"dnsbl.test"});
    defer source.deinit();
    const orphan: dns.Address = .{ .ipv4 = .{ 192, 0, 2, 1 } };
    const queued: dns.Address = .{ .ipv4 = .{ 192, 0, 2, 2 } };
    _ = source.reserve(orphan) orelse return error.TestUnexpectedResult;
    source.request(queued);
    var snapshot = try source.captureUnstarted(std.testing.allocator, 1024 * 1024);
    defer snapshot.deinit();
    var resolver = try Resolver.initConfigured(std.testing.allocator, std.testing.io, .{}, &.{"dnsbl.test"});
    defer resolver.deinit();
    try resolver.restoreSnapshot(&snapshot);
    try std.testing.expect(!resolver.find(orphan).?.work_reserved);
    try std.testing.expect(resolver.find(queued).?.work_reserved);
    resolver.request(orphan);
    resolver.request(orphan);
    try std.testing.expectEqual(@as(usize, 2), resolver.job_count);
    const first = resolver.takeJob() orelse return error.TestUnexpectedResult;
    try std.testing.expect(addrEql(queued, first.ip));
    resolver.request(queued);
    try std.testing.expectEqual(@as(usize, 1), resolver.job_count);
    resolver.completeJob(first, .{ .listed = false });
    const second = resolver.takeJob() orelse return error.TestUnexpectedResult;
    try std.testing.expect(addrEql(orphan, second.ip));
    resolver.completeJob(second, .{ .listed = false });
    try std.testing.expect(resolver.active_job == null);
    try std.testing.expectEqual(@as(usize, 0), resolver.job_count);
    try std.testing.expectEqual(State.ready, resolver.find(orphan).?.state);
}

test "DNS worker background orphan scan is bounded and appends at most one repair" {
    var resolver = try Resolver.initConfigured(std.testing.allocator, std.testing.io, .{}, &.{"dnsbl.test"});
    defer resolver.deinit();
    const orphan_a: dns.Address = .{ .ipv4 = .{ 192, 0, 2, 10 } };
    const orphan_b: dns.Address = .{ .ipv4 = .{ 192, 0, 2, 11 } };
    resolver.entries[64] = .{ .key = orphan_a, .has_key = true, .state = .pending };
    resolver.entries[65] = .{ .key = orphan_b, .has_key = true, .state = .pending };
    resolver.recoverPendingLocked();
    try std.testing.expectEqual(@as(usize, 0), resolver.job_count);
    try std.testing.expectEqual(@as(usize, 64), resolver.recovery_cursor);
    resolver.recoverPendingLocked();
    try std.testing.expectEqual(@as(usize, 1), resolver.job_count);
    try std.testing.expectEqual(@as(usize, 65), resolver.recovery_cursor);
    resolver.recoverPendingLocked();
    try std.testing.expectEqual(@as(usize, 2), resolver.job_count);
    try std.testing.expectEqual(@as(usize, 66), resolver.recovery_cursor);
    resolver.recovery_cursor = 64;
    resolver.recoverPendingLocked();
    try std.testing.expectEqual(@as(usize, 2), resolver.job_count);
    const first = resolver.takeJob() orelse return error.TestUnexpectedResult;
    try std.testing.expect(addrEql(orphan_a, first.ip));
    resolver.completeJob(first, .{ .listed = false });
    const second = resolver.takeJob() orelse return error.TestUnexpectedResult;
    try std.testing.expect(addrEql(orphan_b, second.ip));
    resolver.completeJob(second, .{ .listed = false });
}

test "DNS worker orphan recovery leaves a full or frozen FIFO unchanged and retries later" {
    var resolver = try Resolver.initConfigured(std.testing.allocator, std.testing.io, .{}, &.{"dnsbl.test"});
    defer resolver.deinit();
    for (0..job_capacity) |index| resolver.request(.{ .ipv4 = .{ 192, 0, 0, @intCast(index) } });
    const orphan: dns.Address = .{ .ipv4 = .{ 198, 51, 100, 1 } };
    const entry = resolver.reserve(orphan) orelse return error.TestUnexpectedResult;
    const before_head = resolver.job_head;
    const before_tail = resolver.job_tail;
    const before_cursor = resolver.recovery_cursor;
    resolver.request(orphan);
    resolver.recoverPendingLocked();
    try std.testing.expectEqual(job_capacity, resolver.job_count);
    try std.testing.expectEqual(before_head, resolver.job_head);
    try std.testing.expectEqual(before_tail, resolver.job_tail);
    try std.testing.expectEqual(before_cursor, resolver.recovery_cursor);
    try std.testing.expect(!entry.work_reserved and entry.state == .pending);
    for (0..job_capacity) |index| {
        const expected: dns.Address = .{ .ipv4 = .{ 192, 0, 0, @intCast(index) } };
        try std.testing.expect(addrEql(expected, resolver.jobs[(resolver.job_head + index) % job_capacity].ip));
    }
    const first = resolver.takeJob() orelse return error.TestUnexpectedResult;
    const fence = try resolver.fenceProducers();
    resolver.request(orphan);
    resolver.recoverPendingLocked();
    try std.testing.expectEqual(job_capacity - 1, resolver.job_count);
    try std.testing.expect(!entry.work_reserved);
    try resolver.resumeProducers(fence);
    resolver.request(orphan);
    try std.testing.expectEqual(job_capacity, resolver.job_count);
    try std.testing.expect(entry.work_reserved);
    resolver.completeJob(first, .{ .listed = false });
    var count: usize = 0;
    var repairs: usize = 0;
    while (resolver.takeJob()) |job| {
        if (addrEql(orphan, job.ip)) {
            repairs += 1;
            try std.testing.expectEqual(job_capacity - 1, count);
        }
        resolver.completeJob(job, .{ .listed = false });
        count += 1;
    }
    try std.testing.expectEqual(job_capacity, count);
    try std.testing.expectEqual(@as(usize, 1), repairs);
}

test "DNS worker active job refuses capture and restore until completion after stop" {
    var resolver = try Resolver.initConfigured(std.testing.allocator, std.testing.io, .{}, &.{"dnsbl.test"});
    defer resolver.deinit();
    const ip: dns.Address = .{ .ipv4 = .{ 192, 0, 2, 20 } };
    const queued: dns.Address = .{ .ipv4 = .{ 192, 0, 2, 21 } };
    resolver.request(ip);
    resolver.request(queued);
    var prior = try resolver.captureUnstarted(std.testing.allocator, 1024 * 1024);
    defer prior.deinit();
    const first = resolver.takeJob() orelse return error.TestUnexpectedResult;
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.NotQuiescent, resolver.captureUnstarted(failing.allocator(), 1024 * 1024));
    try std.testing.expectEqual(@as(usize, 0), failing.alloc_index);
    try std.testing.expectError(error.NotQuiescent, resolver.restoreSnapshot(&prior));
    try std.testing.expectEqual(@as(usize, 1), resolver.job_count);
    const fence = try resolver.fenceProducers();
    try std.testing.expectError(error.NotQuiescent, resolver.inspectFrozen(fence, null));
    try std.testing.expectError(error.NotQuiescent, resolver.captureFrozen(failing.allocator(), fence, null, 1024 * 1024));
    resolver.requestStopAndWake();
    try std.testing.expect(resolver.takeJob() == null);
    resolver.completeJob(first, .{ .listed = false });
    try std.testing.expect(resolver.active_job == null);
    try std.testing.expect(!resolver.find(ip).?.work_reserved);
    try std.testing.expectEqual(State.ready, resolver.find(ip).?.state);
    var completed = try resolver.captureFrozen(std.testing.allocator, fence, null, 1024 * 1024);
    defer completed.deinit();
    try std.testing.expectEqual(@as(usize, 1), completed.job_count);
    try std.testing.expect(addrEql(queued, completed.jobs[0]));
}

test "DNS worker completes an orphan to unblock a rowless legacy FIFO head without reordering" {
    var resolver = try Resolver.initConfigured(std.testing.allocator, std.testing.io, .{}, &.{"dnsbl.test"});
    defer resolver.deinit();
    for (resolver.entries, 0..) |*entry, index| {
        entry.* = .{ .key = .{ .ipv4 = .{ 192, 168, @intCast(index / 256), @intCast(index % 256) } }, .has_key = true, .state = .pending };
    }
    for (&resolver.jobs, 0..) |*job, index| job.* = .{ .ip = .{ .ipv4 = .{ 198, 51, 100, @intCast(index) } } };
    resolver.job_count = job_capacity;
    var before = try resolver.captureUnstarted(std.testing.allocator, 1024 * 1024);
    defer before.deinit();
    const repair = resolver.takeJob() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 0), resolver.job_head);
    try std.testing.expectEqual(@as(usize, 0), resolver.job_tail);
    try std.testing.expectEqual(job_capacity, resolver.job_count);
    for (before.jobs[0..before.job_count], 0..) |ip, index| {
        try std.testing.expect(addrEql(ip, resolver.jobs[index].ip));
        try std.testing.expect(!addrEql(ip, repair.ip));
    }
    try std.testing.expect(addrEql(repair.ip, resolver.active_job.?.ip));
    try std.testing.expect(resolver.find(repair.ip).?.work_reserved);
    resolver.request(repair.ip);
    try std.testing.expect(resolver.takeJob() == null);
    try std.testing.expectEqual(job_capacity, resolver.job_count);
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.NotQuiescent, resolver.captureUnstarted(failing.allocator(), 1024 * 1024));
    try std.testing.expectEqual(@as(usize, 0), failing.alloc_index);
    resolver.completeJob(repair, .{ .listed = false });
    try std.testing.expect(resolver.active_job == null);
    try std.testing.expectEqual(State.ready, resolver.find(repair.ip).?.state);
    try std.testing.expect(!resolver.find(repair.ip).?.work_reserved);
    // Production completion, without direct cache mutation, frees the original
    // FIFO head's reservation. Existing FIFO order and remaining work survive.
    const job = resolver.takeJob() orelse return error.TestUnexpectedResult;
    try std.testing.expect(addrEql(before.jobs[0], job.ip));
    try std.testing.expectEqual(@as(usize, 1), resolver.job_head);
    try std.testing.expectEqual(job_capacity - 1, resolver.job_count);
    resolver.completeJob(job, .{ .listed = false });
    var after = try resolver.captureUnstarted(std.testing.allocator, 1024 * 1024);
    defer after.deinit();
    try std.testing.expectEqualDeep(before.jobs[1..before.job_count], after.jobs[0..after.job_count]);
}

test "DNS worker budget bounds all eight silent DNSBL zones to five seconds" {
    const fixture = @import("../proto/dns/test_server.zig");
    var server = try fixture.Server.init(false, .valid);
    defer server.deinit();
    const zones = [_][]const u8{ "zero.test", "one.test", "two.test", "three.test", "four.test", "five.test", "six.test", "seven.test" };
    var names: [max_zones][dns.max_domain_text_len]u8 = undefined;
    var steps: [max_zones]fixture.Step = undefined;
    const ip: dns.Address = .{ .ipv4 = .{ 203, 0, 113, 7 } };
    for (zones, 0..) |zone, index| steps[index] = .{
        .name = try dnsbl.reverseNameV4(ip.ipv4, zone, &names[index]),
        .qtype = .a,
        .reply = .silent,
    };
    server.script = &steps;
    server.fixture_timeout_ms = 5000;
    try server.start();
    var cfg = server.resolverConfig();
    cfg.timeout_ms = std.math.maxInt(u32);
    cfg.attempts = 255;
    var resolver = try Resolver.initConfigured(std.testing.allocator, std.testing.io, cfg, &zones);
    defer resolver.deinit();
    resolver.request(ip);
    const started = platform.monotonicMillis();
    try resolver.startChecked();
    while (platform.monotonicMillis() - started < 6500 and resolver.lookup(ip) == null) sleepMs(5);
    const elapsed = platform.monotonicMillis() - started;
    const verdict = resolver.lookup(ip) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(Verdict{ .listed = false }, verdict);
    try std.testing.expect(elapsed >= 4500 and elapsed < 6500);
    resolver.stop();
    try server.join();
    try std.testing.expectEqual(max_zones, server.udp_queries);
    try std.testing.expectEqual(@as(usize, 0), resolver.job_count);
    try std.testing.expect(resolver.active_job == null);
    const entry = resolver.find(ip) orelse return error.TestUnexpectedResult;
    try std.testing.expect(!entry.work_reserved);
    try std.testing.expect(entry.resolved_ms >= started and entry.resolved_ms <= started + elapsed);
}

test "DNS worker budget gives the final DNSBL zone a listing opportunity after earlier silence" {
    const fixture = @import("../proto/dns/test_server.zig");
    var server = try fixture.Server.init(false, .valid);
    defer server.deinit();
    const zones = [_][]const u8{ "zero.test", "one.test", "two.test", "three.test", "four.test", "five.test", "six.test", "seven.test" };
    var names: [max_zones][dns.max_domain_text_len]u8 = undefined;
    var steps: [max_zones]fixture.Step = undefined;
    const ip: dns.Address = .{ .ipv4 = .{ 203, 0, 113, 7 } };
    for (zones, 0..) |zone, index| steps[index] = .{
        .name = try dnsbl.reverseNameV4(ip.ipv4, zone, &names[index]),
        .qtype = .a,
        .reply = if (index == max_zones - 1) .{ .address = .{ .ipv4 = .{ 127, 0, 0, 7 } } } else .silent,
    };
    server.script = &steps;
    try server.start();
    var cfg = server.resolverConfig();
    cfg.timeout_ms = 800;
    var resolver = try Resolver.initConfigured(std.testing.allocator, std.testing.io, cfg, &zones);
    defer resolver.deinit();
    resolver.request(ip);
    const started = platform.monotonicMillis();
    try resolver.startChecked();
    while (platform.monotonicMillis() - started < 1800 and resolver.lookup(ip) == null) sleepMs(5);
    const elapsed = platform.monotonicMillis() - started;
    try std.testing.expectEqual(Verdict{ .listed = true, .code = 7 }, resolver.lookup(ip) orelse return error.TestUnexpectedResult);
    try std.testing.expect(elapsed >= 500 and elapsed < 1800);
    resolver.stop();
    try server.join();
    try std.testing.expectEqual(max_zones, server.udp_queries);
}
