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
const dnsbl = @import("dnsbl.zig");
const platform = @import("../substrate/platform.zig");
pub const runtime_pause = @import("runtime_pause.zig");
pub const dormant_spawn_options: std.Thread.SpawnConfig = .{};
const rdns = @import("rdns.zig");

/// Maximum number of blocklist zones probed per client IP.
pub const max_zones: usize = 8;

/// A resolved blocklist verdict for one client IP.
pub const Verdict = struct {
    /// True when at least one configured zone listed the IP.
    listed: bool,
    /// Return code (last octet of the listing answer) of the first hit; 0 when
    /// not listed.
    code: u8 = 0,
};

pub const cache_slots: usize = 1024;
pub const job_capacity: usize = 256;
/// Re-check an IP at most this often (blocklist state changes slowly).
const entry_ttl_ms: i64 = 30 * 60 * 1000;

pub const State = enum(u8) { empty, pending, ready };

const Entry = struct {
    key: dns.Address = .{ .ipv4 = .{ 0, 0, 0, 0 } },
    has_key: bool = false,
    state: State = .empty,
    /// Meaningful only when `state == .ready`.
    verdict: Verdict = .{ .listed = false },
    resolved_ms: i64 = 0,
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

    pub fn init(allocator: std.mem.Allocator, zones: []const []const u8) !Resolver {
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
            if (self.zone_count >= max_zones) break;
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
        if (self.entries.len != cache_slots) return error.InvalidState;
        for (snapshot.entries, self.entries) |entry, *out| out.* = .{ .key = entry.key, .has_key = entry.has_key, .state = entry.state, .verdict = entry.verdict, .resolved_ms = entry.resolved_ms };
        for (snapshot.jobs[0..snapshot.job_count], 0..) |ip, i| self.jobs[i] = .{ .ip = ip };
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
        if (comptime @import("builtin").os.tag == .windows) return;
        if (self.thread != null or self.runtime.view != null) return;
        if (self.cfg.nameserver_count == 0 or self.zone_count == 0) return;
        self.stop_flag.store(false, .release);
        self.thread = std.Thread.spawn(.{}, worker, .{self}) catch null;
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
            if (e.state == .pending) return;
            if (e.state == .ready and (now - e.resolved_ms) < entry_ttl_ms) return;
        }
        self.enqueueLocked(ip);
    }

    /// Record a resolved verdict in the cache without a probe. The worker
    /// writes the same slot after DNS; this is the synchronous form so a
    /// caller that already holds a verdict can make `lookup` answer.
    pub fn remember(self: *Resolver, ip: dns.Address, verdict: Verdict) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (self.producers.frozen or self.stop_flag.load(.acquire)) return;
        const e = self.reserve(ip);
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

    /// Find or claim a slot for `ip`, marking it pending. Caller holds the mutex.
    fn reserve(self: *Resolver, ip: dns.Address) *Entry {
        if (self.find(ip)) |e| return e;
        const e = self.victim();
        e.* = .{};
        e.key = ip;
        e.has_key = true;
        e.state = .pending;
        return e;
    }

    fn victim(self: *Resolver) *Entry {
        var oldest: *Entry = &self.entries[0];
        for (self.entries) |*e| {
            if (!e.has_key or e.state == .empty) return e;
            if (e.resolved_ms < oldest.resolved_ms) oldest = e;
        }
        return oldest;
    }

    /// Caller holds the mutex.
    fn enqueueLocked(self: *Resolver, ip: dns.Address) void {
        if (self.producers.frozen or self.stop_flag.load(.acquire)) return;
        _ = self.reserve(ip); // mark pending so repeat requests don't pile up
        if (self.job_count >= job_capacity) return;
        var i: usize = 0;
        var idx = self.job_head;
        while (i < self.job_count) : (i += 1) {
            if (addrEql(self.jobs[idx].ip, ip)) return; // already queued
            idx = (idx + 1) % job_capacity;
        }
        self.jobs[self.job_tail] = .{ .ip = ip };
        self.job_tail = (self.job_tail + 1) % job_capacity;
        self.job_count += 1;
    }

    fn takeJob(self: *Resolver) ?Job {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (self.job_count == 0) return null;
        const job = self.jobs[self.job_head];
        self.job_head = (self.job_head + 1) % job_capacity;
        self.job_count -= 1;
        return job;
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

            lockSpin(&self.mutex);
            const e = self.reserve(job.ip);
            e.verdict = verdict;
            e.resolved_ms = platform.monotonicMillis();
            e.state = .ready;
            self.mutex.unlock();
        }
    }

    /// Probe every configured zone for `ip`, stopping at the first listing. Run
    /// outside the mutex. Any per-zone error (NXDOMAIN, no data, timeout) means
    /// "not listed by that zone" and the scan continues.
    fn probe(self: *const Resolver, ip: dns.Address) Verdict {
        for (self.zones[0..self.zone_count]) |zone| {
            var name_buf: [dns.max_domain_text_len]u8 = undefined;
            const name = switch (ip) {
                .ipv4 => |b| dnsbl.reverseNameV4(b, zone, &name_buf),
                .ipv6 => |b| dnsbl.reverseNameV6(b, zone, &name_buf),
            } catch continue;

            var addr_buf: [8]dns.Address = undefined;
            const answers = dns.resolveForward(&self.cfg, name, false, &addr_buf) catch continue;

            var a_records: [8][4]u8 = undefined;
            var n: usize = 0;
            for (answers) |ans| switch (ans) {
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

pub const CacheEntry = struct {
    key: dns.Address = .{ .ipv4 = .{ 0, 0, 0, 0 } },
    has_key: bool = false,
    state: State = .empty,
    verdict: Verdict = .{ .listed = false },
    resolved_ms: i64 = 0,
};
pub const Execution = enum(u8) { unstarted, paused };
pub const Snapshot = struct {
    allocator: std.mem.Allocator,
    entries: []CacheEntry,
    jobs: []dns.Address,
    job_count: usize,
    zones: [][]u8,
    config_digest: [32]u8,
    captured_monotonic_ms: i64,
    execution: Execution,
    pub fn deinit(self: *Snapshot) void {
        for (self.zones) |zone| self.allocator.free(zone);
        self.allocator.free(self.zones);
        self.allocator.free(self.jobs);
        self.allocator.free(self.entries);
        self.* = undefined;
    }
    pub fn validate(self: *const Snapshot, cfg: dns.ResolverConfig, zones: []const []const u8) !void {
        if (self.entries.len != cache_slots or self.jobs.len != job_capacity or self.job_count > job_capacity or self.zones.len != zones.len) return error.InvalidState;
        if (!std.mem.eql(u8, &self.config_digest, &try configDigest(cfg, zones))) return error.ConfigMismatch;
        for (self.zones, zones) |carried, actual| if (!std.mem.eql(u8, carried, actual)) return error.ConfigMismatch;
        for (self.entries, 0..) |entry, i| {
            if (!entry.has_key and (entry.state != .empty or entry.verdict.listed or entry.verdict.code != 0 or
                entry.resolved_ms != 0 or !addrEql(entry.key, .{ .ipv4 = .{ 0, 0, 0, 0 } }))) return error.InvalidState;
            if (entry.has_key and entry.state == .empty) return error.InvalidState;
            if (entry.has_key) for (self.entries[0..i]) |prior| {
                if (prior.has_key and addrEql(prior.key, entry.key)) return error.InvalidState;
            };
        }
        for (self.jobs[0..self.job_count], 0..) |ip, i| for (self.jobs[0..i]) |prior| {
            if (addrEql(ip, prior)) return error.InvalidState;
        };
    }
};
pub fn configDigest(cfg: dns.ResolverConfig, zones: []const []const u8) ![32]u8 {
    if (zones.len > max_zones) return error.InvalidState;
    const dns_digest = try rdns.resolverConfigDigest(cfg);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("onyx/companion/dnsbl-config/v1");
    hash.update(&dns_digest);
    hash.update(&.{@intCast(zones.len)});
    for (zones) |zone| {
        const len = std.math.cast(u32, zone.len) orelse return error.Capacity;
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, len, .big);
        hash.update(&bytes);
        hash.update(zone);
    }
    return hash.finalResult();
}

fn addrEql(a: dns.Address, b: dns.Address) bool {
    return switch (a) {
        .ipv4 => |x| switch (b) {
            .ipv4 => |y| std.mem.eql(u8, &x, &y),
            else => false,
        },
        .ipv6 => |x| switch (b) {
            .ipv6 => |y| std.mem.eql(u8, &x, &y),
            else => false,
        },
    };
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
        const e = r.reserve(ip);
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
        const e = r.reserve(clean);
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
    // Resolver worker threads never start on Windows (see `start`); the
    // lifecycle below cannot proceed there.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
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
