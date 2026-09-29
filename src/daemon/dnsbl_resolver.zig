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

const cache_slots: usize = 1024;
const job_capacity: usize = 256;
/// Re-check an IP at most this often (blocklist state changes slowly).
const entry_ttl_ms: i64 = 30 * 60 * 1000;

const State = enum(u8) { empty, pending, ready };

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
    stop_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    thread: ?std.Thread = null,
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

    pub fn deinit(self: *Resolver) void {
        self.stop();
        for (self.zones[0..self.zone_count]) |z| self.allocator.free(z);
        self.allocator.free(self.entries);
        self.* = undefined;
    }

    /// Spawn the resolver thread. Inert (no thread) when no nameservers are
    /// configured or no zones are set; requests then simply never become ready
    /// and callers treat every client as not-listed.
    pub fn start(self: *Resolver) void {
        if (self.thread != null) return;
        if (self.cfg.nameserver_count == 0 or self.zone_count == 0) return;
        self.stop_flag.store(false, .release);
        self.thread = std.Thread.spawn(.{}, worker, .{self}) catch null;
    }

    pub fn stop(self: *Resolver) void {
        self.stop_flag.store(true, .release);
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
        while (!self.stop_flag.load(.acquire)) {
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
