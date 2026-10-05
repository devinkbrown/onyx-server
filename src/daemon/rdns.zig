// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Background forward-confirmed reverse-DNS resolver.
//!
//! The accept hot path must never block on DNS (a PTR lookup plus its forward
//! confirmation can take seconds), so client IPs are *enqueued* here and
//! resolved on a dedicated worker thread via `proto/dns.zig` (FCrDNS). The
//! reactor reads the confirmed hostname back — at registration time — to present
//! a cloaked HOSTNAME instead of a cloaked IP. Best-effort: any miss, timeout,
//! or unconfirmed PTR leaves the entry resolved-but-nameless and the caller
//! falls back to the IP cloak. Mutex-guarded fixed cache + job ring, mirroring
//! the established `geo_services` background-fetcher pattern.

const std = @import("std");
const builtin = @import("builtin");
const dns = @import("../proto/dns.zig");
const platform = @import("../substrate/platform.zig");
pub const runtime_pause = @import("runtime_pause.zig");
pub const dormant_spawn_options: std.Thread.SpawnConfig = .{};

pub const max_host_len: usize = dns.max_domain_text_len;

pub const cache_slots: usize = 1024;
pub const job_capacity: usize = 256;
/// Re-resolve an IP at most this often (a host's PTR rarely changes).
const entry_ttl_ms: i64 = 30 * 60 * 1000;

pub const State = enum(u8) { empty, pending, ready };

const Entry = struct {
    key: dns.Address = .{ .ipv4 = .{ 0, 0, 0, 0 } },
    has_key: bool = false,
    state: State = .empty,
    host_buf: [max_host_len]u8 = undefined,
    /// 0 when ready-but-unconfirmed (no usable hostname → caller uses the IP).
    host_len: usize = 0,
    resolved_ms: i64 = 0,
};

const Job = struct { ip: dns.Address };

pub const Resolver = struct {
    allocator: std.mem.Allocator,
    cfg: dns.ResolverConfig,
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

    pub fn init(allocator: std.mem.Allocator) !Resolver {
        const entries = try allocator.alloc(Entry, cache_slots);
        for (entries) |*e| e.* = .{};
        return .{
            .allocator = allocator,
            .cfg = dns.systemResolverConfig(),
            .entries = entries,
        };
    }

    /// Caller supplies the actual configured DNS cut. No worker or network I/O.
    pub fn initConfigured(allocator: std.mem.Allocator, io: std.Io, cfg: dns.ResolverConfig) !Resolver {
        _ = try resolverConfigDigest(cfg);
        const entries = try allocator.alloc(Entry, cache_slots);
        errdefer allocator.free(entries);
        for (entries) |*e| e.* = .{};
        var self: Resolver = .{ .allocator = allocator, .cfg = cfg, .entries = entries };
        try self.runtime.pause.bindIo(io);
        return self;
    }

    pub fn prepareColdResources(self: *Resolver, io: std.Io) !void {
        if (self.thread != null or self.runtime.view != null or self.runtime.entered.load(.acquire) or self.runtime.exited.load(.acquire)) return error.AlreadyStarted;
        _ = try resolverConfigDigest(self.cfg);
        try self.runtime.pause.prepareIo(io);
    }

    pub fn validateDormantRegistration(self: *Resolver, control: *runtime_pause.start_gate.Control, view: *const runtime_pause.start_gate.View, slot: runtime_pause.start_gate.Slot) !void {
        try self.runtime.validateRegistration(control, view, slot, .rdns, 0, self, dormant_spawn_options);
    }
    pub fn prepareDormantWorker(self: *Resolver, control: *runtime_pause.start_gate.Control, view: *const runtime_pause.start_gate.View, slot: runtime_pause.start_gate.Slot) !void {
        try self.runtime.validatePreparation(control, view, slot, .rdns, 0, self, dormant_spawn_options);
        if (self.thread != null) return error.AlreadyStarted;
        if (self.cfg.nameserver_count == 0) return error.NotConfigured;
        self.stop_flag.store(false, .release);
        try self.runtime.prepare(control, view, slot, .rdns, 0, Resolver, self, worker, dormant_spawn_options);
    }
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

    /// Worker pause plus the caller's actual producer freeze is required. Cache
    /// slots keep their physical order, including nameless and pending records.
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
        const required = std.math.add(usize, @sizeOf(Snapshot), cache_slots * @sizeOf(CacheEntry) + job_capacity * @sizeOf(dns.Address)) catch return error.Capacity;
        if (required > max_bytes) return error.Capacity;
        const entries = try allocator.alloc(CacheEntry, cache_slots);
        errdefer allocator.free(entries);
        const jobs = try allocator.alloc(dns.Address, job_capacity);
        errdefer allocator.free(jobs);
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (fence) |proof| try self.producers.requireLocked(proof);
        _ = try self.requireCaptureCut(token);
        if (self.entries.len != cache_slots or self.job_count > job_capacity) return error.InvalidState;
        for (self.entries, entries) |entry, *out| {
            if (entry.host_len > max_host_len) return error.InvalidState;
            out.* = .{ .key = entry.key, .has_key = entry.has_key, .state = entry.state, .host_len = @intCast(entry.host_len), .resolved_ms = entry.resolved_ms };
            @memcpy(out.host[0..entry.host_len], entry.host_buf[0..entry.host_len]);
        }
        for (0..self.job_count) |i| jobs[i] = self.jobs[(self.job_head + i) % job_capacity].ip;
        const result: Snapshot = .{ .allocator = allocator, .entries = entries, .jobs = jobs, .job_count = self.job_count, .execution = execution, .config_digest = try resolverConfigDigest(self.cfg), .captured_monotonic_ms = platform.monotonicMillis() };
        try result.validate(self.cfg);
        return result;
    }

    /// Validate the complete candidate BEFORE changing any source state. No
    /// allocation and no fallback to an empty queue on malformed carry.
    pub fn restoreSnapshot(self: *Resolver, snapshot: *const Snapshot) !void {
        if (self.thread != null or self.runtime.view != null or self.runtime.pause.request_epoch != 0) return error.AlreadyStarted;
        try self.restoreValidatedSnapshot(snapshot);
    }

    /// A Windows successor may prepare its real worker under the runtime Gate
    /// before decoding the inherited state. The worker cannot enter its body
    /// until COMMIT releases that Gate, so the same allocation-free restore is
    /// safe after verifying the actual parked owner on both sides of validation.
    pub fn restoreSnapshotParked(self: *Resolver, snapshot: *const Snapshot) !void {
        if (self.thread != null or self.runtime.pause.request_epoch != 0) return error.AlreadyStarted;
        try self.requireParked();
        try snapshot.validate(self.cfg);
        try self.requireParked();
        try self.publishSnapshot(snapshot);
    }

    fn restoreValidatedSnapshot(self: *Resolver, snapshot: *const Snapshot) !void {
        try snapshot.validate(self.cfg);
        try self.publishSnapshot(snapshot);
    }

    fn publishSnapshot(self: *Resolver, snapshot: *const Snapshot) !void {
        if (self.entries.len != cache_slots) return error.InvalidState;
        for (snapshot.entries, self.entries) |entry, *out| {
            out.* = .{ .key = entry.key, .has_key = entry.has_key, .state = entry.state, .host_len = entry.host_len, .resolved_ms = entry.resolved_ms };
            @memcpy(out.host_buf[0..entry.host_len], entry.host[0..entry.host_len]);
        }
        for (snapshot.jobs[0..snapshot.job_count], 0..) |ip, i| self.jobs[i] = .{ .ip = ip };
        self.job_head = 0;
        self.job_count = snapshot.job_count;
        self.job_tail = snapshot.job_count % job_capacity;
    }

    pub fn deinit(self: *Resolver) void {
        self.runtime.requireDetached() catch @panic("managed worker must join and detach before deinit");
        self.stop();
        self.allocator.free(self.entries);
        self.* = undefined;
    }

    /// Spawn the resolver thread. Inert (no thread) when no nameservers are
    /// configured; requests then simply never become ready and callers keep the
    /// IP cloak.
    pub fn start(self: *Resolver) void {
        if (self.thread != null or self.runtime.view != null) return;
        if (self.cfg.nameserver_count == 0) return;
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

    /// Ensure `ip` is being resolved. No-op if a fresh entry already exists or a
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

    /// Confirmed hostname for `ip`, copied into `out`, or null when not yet
    /// resolved or there is no forward-confirmed PTR. Never blocks.
    pub fn lookup(self: *Resolver, ip: dns.Address, out: []u8) ?[]const u8 {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const e = self.find(ip) orelse return null;
        if (e.state != .ready or e.host_len == 0) return null;
        const n = @min(e.host_len, out.len);
        @memcpy(out[0..n], e.host_buf[0..n]);
        return out[0..n];
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
            var name_buf: [max_host_len]u8 = undefined;
            const confirmed = dns.resolveConfirmed(&self.cfg, job.ip, &name_buf);

            lockSpin(&self.mutex);
            const e = self.reserve(job.ip);
            if (confirmed) |name| {
                const n = @min(name.len, e.host_buf.len);
                @memcpy(e.host_buf[0..n], name[0..n]);
                e.host_len = n;
            } else {
                e.host_len = 0; // resolved, but no forward-confirmed hostname
            }
            e.resolved_ms = platform.monotonicMillis();
            e.state = .ready;
            self.mutex.unlock();
        }
    }
};

pub const CacheEntry = struct {
    key: dns.Address = .{ .ipv4 = .{ 0, 0, 0, 0 } },
    has_key: bool = false,
    state: State = .empty,
    host: [max_host_len]u8 = @splat(0),
    host_len: u16 = 0,
    resolved_ms: i64 = 0,
};
pub const Execution = enum(u8) { unstarted, paused };
pub const Snapshot = struct {
    allocator: std.mem.Allocator,
    entries: []CacheEntry,
    /// Backing is exactly job_capacity; only job_count records are initialized.
    jobs: []dns.Address,
    job_count: usize,
    config_digest: [32]u8,
    captured_monotonic_ms: i64,
    execution: Execution,
    pub fn deinit(self: *Snapshot) void {
        self.allocator.free(self.entries);
        self.allocator.free(self.jobs);
        self.* = undefined;
    }
    pub fn validate(self: *const Snapshot, cfg: dns.ResolverConfig) !void {
        if (self.entries.len != cache_slots or self.jobs.len != job_capacity or self.job_count > job_capacity) return error.InvalidState;
        if (self.captured_monotonic_ms < 0) return error.InvalidState;
        if (!std.mem.eql(u8, &self.config_digest, &try resolverConfigDigest(cfg))) return error.ConfigMismatch;
        for (self.entries, 0..) |entry, i| {
            if (entry.host_len > max_host_len) return error.InvalidState;
            if (!std.mem.allEqual(u8, entry.host[entry.host_len..], 0)) return error.InvalidState;
            if (!entry.has_key and (entry.state != .empty or entry.host_len != 0 or entry.resolved_ms != 0 or
                !addrEql(entry.key, .{ .ipv4 = .{ 0, 0, 0, 0 } }))) return error.InvalidState;
            if (entry.has_key and entry.state == .empty) return error.InvalidState;
            if (entry.state != .ready and entry.host_len != 0) return error.InvalidState;
            if (entry.state == .ready and (entry.resolved_ms < 0 or entry.resolved_ms > self.captured_monotonic_ms)) return error.InvalidState;
            if (entry.host_len != 0 and !validConfirmedHost(entry.host[0..entry.host_len])) return error.InvalidState;
            if (entry.has_key) for (self.entries[0..i]) |prior| {
                if (prior.has_key and addrEql(prior.key, entry.key)) return error.InvalidState;
            };
        }
        for (self.jobs[0..self.job_count], 0..) |ip, i| for (self.jobs[0..i]) |prior| {
            if (addrEql(ip, prior)) return error.InvalidState;
        };
    }
};

/// The DNS decoder accepts only these label bytes before writing a confirmed
/// PTR name. Apply the same check to restored cache text before WHOIS can emit it.
pub fn validConfirmedHost(host: []const u8) bool {
    var label_len: usize = 0;
    for (host) |ch| {
        if (ch == '.') {
            if (label_len == 0 or label_len > 63) return false;
            label_len = 0;
        } else switch (ch) {
            'a'...'z', 'A'...'Z', '0'...'9', '-', '_' => label_len += 1,
            else => return false,
        }
    }
    return label_len != 0 and label_len <= 63;
}

/// Hash only initialized configured fields; do not hash union padding or unused
/// nameserver tails. DNSBL uses the same exact DNS context commitment.
pub fn resolverConfigDigest(cfg: dns.ResolverConfig) ![32]u8 {
    if (cfg.nameserver_count > dns.max_nameservers) return error.InvalidState;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("onyx/companion/dns-config/v2");
    hash.update(&.{@intCast(cfg.nameserver_count)});
    for (cfg.nameservers[0..cfg.nameserver_count], cfg.nameserver_scope_ids[0..cfg.nameserver_count]) |address, scope_id| {
        hashAddress(&hash, address);
        var scope_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &scope_bytes, scope_id, .big);
        hash.update(&scope_bytes);
    }
    var numbers: [7]u8 = undefined;
    std.mem.writeInt(u16, numbers[0..2], cfg.port, .big);
    std.mem.writeInt(u32, numbers[2..6], cfg.timeout_ms, .big);
    numbers[6] = cfg.attempts;
    hash.update(&numbers);
    return hash.finalResult();
}
pub fn hashAddress(hash: *std.crypto.hash.sha2.Sha256, address: dns.Address) void {
    switch (address) {
        .ipv4 => |bytes| {
            hash.update(&.{4});
            hash.update(&bytes);
        },
        .ipv6 => |bytes| {
            hash.update(&.{6});
            hash.update(&bytes);
        },
    }
}

test "rDNS config digest commits scoped IPv6 nameserver identity" {
    var cfg: dns.ResolverConfig = .{};
    cfg.addNameserver(.{ .ipv6 = .{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } });
    const first = try resolverConfigDigest(cfg);
    cfg.nameserver_scope_ids[0] = 17;
    const scoped = try resolverConfigDigest(cfg);
    try std.testing.expect(!std.mem.eql(u8, &first, &scoped));
    cfg.nameserver_scope_ids[0] = 0;
    try std.testing.expectEqualSlices(u8, &first, &try resolverConfigDigest(cfg));
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

/// Idle wait for the resolver worker. Linux `nanosleep` is syscall 35, which
/// is a different call on FreeBSD, so the BSD thread uses libc.
fn sleepMs(ms: u32) void {
    switch (builtin.os.tag) {
        .linux => {
            const linux = std.os.linux;
            var req = linux.timespec{ .sec = @divTrunc(ms, 1000), .nsec = @as(isize, ms % 1000) * 1_000_000 };
            _ = linux.nanosleep(&req, null);
        },
        .windows => {
            const ntdll = struct {
                extern "ntdll" fn NtDelayExecution(alertable: u8, interval: *const i64) callconv(.winapi) i32;
            };
            var ticks: i64 = -@as(i64, ms) * 10_000;
            _ = ntdll.NtDelayExecution(0, &ticks);
        },
        else => {
            var req = std.c.timespec{
                .sec = @intCast(ms / 1000),
                .nsec = @intCast((ms % 1000) * 1_000_000),
            };
            _ = std.c.nanosleep(&req, null);
        },
    }
}

test "resolver idle wait returns" {
    sleepMs(1);
}

test "request enqueues; lookup misses until a confirmed result is stored" {
    var r = try Resolver.init(std.testing.allocator);
    defer r.deinit();

    const ip = dns.Address{ .ipv4 = .{ 192, 0, 2, 1 } };
    r.request(ip); // enqueues a pending entry; no worker thread started
    var buf: [256]u8 = undefined;
    try std.testing.expect(r.lookup(ip, &buf) == null); // pending → miss

    // Simulate the worker storing a resolved-but-unconfirmed result.
    {
        lockSpin(&r.mutex);
        const e = r.reserve(ip);
        e.host_len = 0;
        e.state = .ready;
        r.mutex.unlock();
    }
    try std.testing.expect(r.lookup(ip, &buf) == null); // ready, no hostname → miss

    // Simulate a confirmed result.
    {
        lockSpin(&r.mutex);
        const e = r.reserve(ip);
        const name = "host.example.com";
        @memcpy(e.host_buf[0..name.len], name);
        e.host_len = name.len;
        e.state = .ready;
        r.mutex.unlock();
    }
    try std.testing.expectEqualStrings("host.example.com", r.lookup(ip, &buf).?);
}

test "request de-dupes and the job ring stays bounded" {
    var r = try Resolver.init(std.testing.allocator);
    defer r.deinit();
    const ip = dns.Address{ .ipv4 = .{ 203, 0, 113, 5 } };
    r.request(ip);
    r.request(ip);
    r.request(ip);
    try std.testing.expectEqual(@as(usize, 1), r.job_count);
}

fn pausedCaptureAllocation(allocator: std.mem.Allocator, resolver: *Resolver, token: runtime_pause.Token) !void {
    var snapshot = try resolver.capturePaused(allocator, token, 1024 * 1024);
    defer snapshot.deinit();
    try std.testing.expectEqual(@as(usize, 2), snapshot.job_count);
    try std.testing.expectEqual(State.pending, snapshot.entries[0].state);
    try std.testing.expectEqual(State.ready, snapshot.entries[1].state);
}

test "companion runtime rdns real gated pause preserves full cache FIFO and OOM retry" {
    var cfg: dns.ResolverConfig = .{};
    cfg.addNameserver(.{ .ipv4 = .{ 192, 0, 2, 53 } });
    var resolver = try Resolver.initConfigured(std.testing.allocator, std.testing.io, cfg);
    const specs = [_]runtime_pause.start_gate.ParticipantSpec{.{ .kind = .rdns, .instance = 0, .owner_identity = &resolver }};
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
    const b: dns.Address = .{ .ipv6 = @splat(7) };
    resolver.request(a);
    resolver.request(b);
    // Actual ready-but-nameless cache plus queued job is legal source state.
    resolver.entries[1].state = .ready;
    resolver.entries[1].resolved_ms = 123;
    const token = try resolver.requestPause(1);
    try resolver.prepareDormantWorker(gate.control, gate.view, try gate.view.slot(.rdns, 0, &resolver));
    try gate.control.awaitAllParked(std.Io.Clock.Timestamp.fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
    try resolver.requireParked();
    try std.testing.expectEqual(@as(usize, 2), resolver.job_count);
    gate.control.releaseAll();
    try resolver.awaitPaused(token, std.Io.Clock.Timestamp.fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
    try std.testing.checkAllAllocationFailures(std.testing.allocator, pausedCaptureAllocation, .{ &resolver, token });
    var snapshot = try resolver.capturePaused(std.testing.allocator, token, 1024 * 1024);
    defer snapshot.deinit();
    var restored = try Resolver.initConfigured(std.testing.allocator, std.testing.io, cfg);
    defer restored.deinit();
    try restored.restoreSnapshot(&snapshot);
    try std.testing.expectEqual(@as(usize, 2), restored.job_count);
    try std.testing.expect(addrEql(a, restored.jobs[0].ip));
    try std.testing.expect(addrEql(b, restored.jobs[1].ip));
    try std.testing.expectEqual(@as(i64, 123), restored.entries[1].resolved_ms);
    const original = snapshot.entries[1];
    snapshot.entries[1] = snapshot.entries[0];
    try std.testing.expectError(error.InvalidState, restored.restoreSnapshot(&snapshot));
    try std.testing.expectEqual(@as(i64, 123), restored.entries[1].resolved_ms);
    snapshot.entries[1] = original;
    snapshot.config_digest[0] ^= 1;
    try std.testing.expectError(error.ConfigMismatch, restored.restoreSnapshot(&snapshot));
    snapshot.config_digest[0] ^= 1;
    try std.testing.expectError(error.Capacity, resolver.capturePaused(std.testing.allocator, token, 1));
    try std.testing.expectEqual(@as(usize, 2), resolver.job_count);
    // Stop wakes the actual same paused worker; no DNS operation was started.
}

test "companion runtime rdns truly unstarted retains queued cache without fake arrival" {
    var resolver = try Resolver.initConfigured(std.testing.allocator, std.testing.io, .{});
    defer resolver.deinit();
    resolver.request(.{ .ipv4 = .{ 192, 0, 2, 11 } });
    var snapshot = try resolver.captureUnstarted(std.testing.allocator, 1024 * 1024);
    defer snapshot.deinit();
    try std.testing.expectEqual(Execution.unstarted, snapshot.execution);
    try std.testing.expectEqual(@as(usize, 1), snapshot.job_count);
    try std.testing.expectEqual(State.pending, snapshot.entries[0].state);
    const token = try resolver.requestPause(1);
    try std.testing.expectError(error.NotRunning, resolver.capturePaused(std.testing.allocator, token, 1024 * 1024));
    try std.testing.expectError(error.Timeout, resolver.awaitPaused(token, std.Io.Clock.Timestamp.now(std.testing.io, .awake)));
    try resolver.resumePaused(token);
}

test "companion cold Io preparation RDNS configured and legacy owners confirm exact source" {
    var cfg: dns.ResolverConfig = .{};
    cfg.addNameserver(.{ .ipv4 = .{ 127, 0, 0, 1 } });
    var configured = try Resolver.initConfigured(std.testing.allocator, std.testing.io, cfg);
    defer configured.deinit();
    try configured.prepareColdResources(std.testing.io);
    try configured.prepareColdResources(std.testing.io);
    var different_vtable = std.testing.io.vtable.*;
    const wrong: std.Io = .{ .userdata = std.testing.io.userdata, .vtable = &different_vtable };
    try std.testing.expectError(error.IoMismatch, configured.prepareColdResources(wrong));
    configured.start();
    try std.testing.expect(configured.thread != null);
    try std.testing.expectError(error.AlreadyStarted, configured.prepareColdResources(std.testing.io));
    configured.stop(); // Actual body entered/exited and actual thread joined.
    try std.testing.expect(configured.runtime.entered.load(.acquire));
    try std.testing.expect(configured.runtime.exited.load(.acquire));
    try std.testing.expectError(error.AlreadyStarted, configured.prepareColdResources(std.testing.io));
    var legacy = try Resolver.init(std.testing.allocator);
    defer legacy.deinit();
    try legacy.prepareColdResources(std.testing.io);
    try legacy.prepareColdResources(std.testing.io);
    const token = try legacy.requestPause(1);
    try std.testing.expectError(error.Busy, legacy.prepareColdResources(std.testing.io));
    try legacy.resumePaused(token);
    try std.testing.expectError(error.Busy, legacy.prepareColdResources(std.testing.io));
}

test "companion runtime producer fence RDNS preserves accepted queue and rejects stale capture before allocation" {
    var resolver = try Resolver.initConfigured(std.testing.allocator, std.testing.io, .{});
    defer resolver.deinit();
    const accepted: dns.Address = .{ .ipv4 = .{ 192, 0, 2, 21 } };
    const refused: dns.Address = .{ .ipv4 = .{ 192, 0, 2, 22 } };
    resolver.request(accepted);
    const fence = try resolver.fenceProducers();
    resolver.request(refused);
    const cut = try resolver.inspectFrozen(fence, null);
    try std.testing.expectEqual(Execution.unstarted, cut.execution);
    try std.testing.expectEqual(@as(usize, 1), cut.queued);
    try std.testing.expect(resolver.find(refused) == null);
    var snapshot = try resolver.captureFrozen(std.testing.allocator, fence, null, 1024 * 1024);
    defer snapshot.deinit();
    try std.testing.expectEqual(@as(usize, 1), snapshot.job_count);
    try std.testing.expect(addrEql(accepted, snapshot.jobs[0]));
    try resolver.resumeProducers(fence);
    resolver.request(refused);
    const next = try resolver.fenceProducers();
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.InvalidProducerFence, resolver.captureFrozen(failing.allocator(), fence, null, 1024 * 1024));
    try std.testing.expectEqual(@as(usize, 0), failing.alloc_index);
    try std.testing.expectEqual(@as(usize, 2), (try resolver.inspectFrozen(next, null)).queued);
}
