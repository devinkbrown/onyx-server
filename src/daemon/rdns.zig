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

pub const max_host_len: usize = dns.max_domain_text_len;

const cache_slots: usize = 1024;
const job_capacity: usize = 256;
/// Re-resolve an IP at most this often (a host's PTR rarely changes).
const entry_ttl_ms: i64 = 30 * 60 * 1000;

const State = enum(u8) { empty, pending, ready };

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
    stop_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    thread: ?std.Thread = null,
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

    pub fn deinit(self: *Resolver) void {
        self.stop();
        self.allocator.free(self.entries);
        self.* = undefined;
    }

    /// Spawn the resolver thread. Inert (no thread) when no nameservers are
    /// configured; requests then simply never become ready and callers keep the
    /// IP cloak.
    pub fn start(self: *Resolver) void {
        if (self.thread != null) return;
        if (self.cfg.nameserver_count == 0) return;
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
