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
const http_fetch = @import("http_fetch.zig");
const platform = @import("../substrate/platform.zig");
const store_mod = @import("store.zig");

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
        allocator.free(self.to);
        allocator.free(self.subject);
        allocator.free(self.body);
    }
};

pub const Sender = struct {
    allocator: std.mem.Allocator,
    config: Config,
    mutex: std.atomic.Mutex = .unlocked,
    stop_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    thread: ?std.Thread = null,
    jobs: []Job,
    job_head: usize = 0,
    job_tail: usize = 0,
    job_count: usize = 0,
    failure_seq: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, config: Config) !Sender {
        const jobs = try allocator.alloc(Job, job_capacity);
        return .{ .allocator = allocator, .config = config, .jobs = jobs };
    }

    pub fn deinit(self: *Sender) void {
        self.stop();
        lockSpin(&self.mutex);
        while (self.job_count > 0) {
            const job = self.jobs[self.job_head];
            self.job_head = (self.job_head + 1) % job_capacity;
            self.job_count -= 1;
            job.free(self.allocator);
        }
        self.mutex.unlock();
        self.allocator.free(self.jobs);
        self.* = undefined;
    }

    /// Spawn the worker. Inert (no thread) when relay/from is unconfigured;
    /// enqueued jobs then sit in the ring and are freed at deinit.
    pub fn start(self: *Sender) void {
        if (comptime @import("builtin").os.tag == .windows) return;
        if (self.thread != null) return;
        if (self.config.relay_host.len == 0 or self.config.from.len == 0) return;
        self.stop_flag.store(false, .release);
        self.thread = std.Thread.spawn(.{}, worker, .{self}) catch null;
    }

    pub fn stop(self: *Sender) void {
        self.stop_flag.store(true, .release);
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
        if (self.job_count >= job_capacity) return;
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
            self.allocator.free(to_copy);
            return null;
        };
        const body_copy = self.allocator.dupe(u8, body) catch {
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

    fn worker(self: *Sender) void {
        while (!self.stop_flag.load(.acquire)) {
            const job = self.takeJob() orelse {
                sleepMs(100); // low-rate work: poll for jobs, observe the stop flag
                continue;
            };
            defer job.free(self.allocator);
            self.finishJob(job);
        }
    }

    /// Deliver one job. A failure is appended to the failure store when configured.
    pub fn settle(self: *Sender, to: []const u8, subject: []const u8, body: []const u8) !void {
        const job = self.dupeJob(to, subject, body) orelse return error.OutOfMemory;
        defer job.free(self.allocator);
        self.finishJob(job);
    }

    fn finishJob(self: *Sender, job: Job) void {
        self.deliver(job) catch |err| {
            self.recordFailure(job, err) catch {};
        };
    }

    fn recordFailure(self: *Sender, job: Job, err: anyerror) !void {
        const io = self.config.failure_io orelse return;
        const wal = self.config.failure_wal orelse return;
        const dir = self.config.failure_dir orelse std.Io.Dir.cwd();
        if (self.failure_seq == std.math.maxInt(u64)) return error.SequenceExhausted;
        self.failure_seq += 1;
        var store = try store_mod.OroStore.open(self.allocator, io, dir, wal);
        defer store.deinit();
        var key_buf: [48]u8 = undefined;
        const key = std.fmt.bufPrint(&key_buf, "mailfail:{d}", .{self.failure_seq}) catch return error.NoSpaceLeft;
        var val_buf: [180]u8 = undefined;
        const to = job.to[0..@min(job.to.len, 80)];
        const value = std.fmt.bufPrint(&val_buf, "{s} {s}", .{ @errorName(err), to }) catch return error.NoSpaceLeft;
        try store.put(.props, key, value);
    }

    /// Resolve, connect, and run the ESMTP conversation for one job (outside the lock).
    fn deliver(self: *Sender, job: Job) !void {
        if (comptime @import("builtin").os.tag == .windows) return error.SocketUnavailable;
        const job_start = platform.monotonicMillis();
        const addr = try http_fetch.resolveHostA(self.config.relay_host, self.config.relay_port, io_timeout_ms);

        // Submission credentials must not cross an unverified session to a remote
        // relay. A non-empty trust store, or an explicit insecure opt-in, is required.
        const verified = self.config.trust_anchors.len != 0 or self.config.insecure_skip_verify;
        if (self.config.user != null and !isLoopback(addr) and !verified)
            return error.UnverifiedAuthRelay;

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
                const read = try tc.decryptApp(rec);
                consumePrefix(pending, rec_len);
                switch (read) {
                    .application_data => |pt| {
                        defer self.allocator.free(pt);
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
            switch (try tc.feed(read_buf[0..n])) {
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
