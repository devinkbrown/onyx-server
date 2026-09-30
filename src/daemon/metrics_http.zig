// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Live Prometheus `/metrics` HTTP endpoint.
//!
//! Two pieces, mirroring the loopback ACME challenge listener
//! (see [acme_http01_listener] / [acme_http01_server]):
//!
//!  * `MetricsSnapshot` — a mutex-guarded owned `[]u8` holding the latest
//!    Prometheus exposition text. The server refreshes it on its existing stats
//!    cadence (alongside `publishStatsFiles`); the listener thread only ever
//!    READS it under the mutex. The handler never touches live `Stats`.
//!
//!  * `MetricsServer` — a standalone, threaded, loopback HTTP/1.1 listener that
//!    serves the snapshot for `GET /metrics` (404/405 otherwise). It is
//!    read-only, bounds the request size, and applies a per-connection read
//!    timeout, exactly like the challenge listener.
//!
//! The bind address defaults to loopback `127.0.0.1` (security: metrics are not
//! exposed publicly by default). A non-loopback bind is opt-in via config.
//!
//! On hot-upgrade the thread is torn down and re-created on the new process — no
//! fd migration is needed for a stateless scrape endpoint.

const std = @import("std");
const builtin = @import("builtin");

const sys = std.posix.system;
const posix = std.posix;

comptime {
    if (@bitSizeOf(usize) != 64) @compileError("metrics_http requires a 64-bit target");
}

/// Prometheus text format version served in the Content-Type header.
pub const content_type = "text/plain; version=0.0.4; charset=utf-8";

/// Max request bytes read per connection (a scrape GET is tiny).
const max_request: usize = 8 * 1024;
/// Fixed scratch for the status line + headers (the body is streamed separately).
const max_header: usize = 512;

/// Default TCP accept backlog for the metrics listener.
pub const default_listen_backlog: u31 = 16;
/// Default accept-poll wake interval (ms) so the loop re-checks the stop flag.
pub const default_accept_poll_ms: u32 = 250;
/// Default per-connection read timeout (seconds) guarding against slow clients.
pub const default_conn_read_timeout_sec: u32 = 5;

/// Loopback address `127.0.0.1` in host byte order (the secure default bind).
pub const loopback_addr: u32 = 0x7f00_0001;

pub const ListenerError = error{
    SocketUnavailable,
    BindFailed,
    ListenFailed,
    AddrLookupFailed,
    TimeoutSetupFailed,
};

// ---------------------------------------------------------------------------
// Snapshot: the only state shared between the daemon and the listener thread.
// ---------------------------------------------------------------------------

/// A mutex-guarded owned copy of the latest Prometheus exposition text.
///
/// The daemon calls `set` on its stats cadence; the listener thread calls
/// `copyInto` to serve. Both take the mutex; neither touches live counters.
pub const MetricsSnapshot = struct {
    allocator: std.mem.Allocator,
    /// Latest rendered Prometheus text (owned). Empty until the first refresh.
    text: []u8 = &.{},
    /// Guards `text` across the daemon refresh and the listener reads.
    mutex: std.atomic.Mutex = .unlocked,

    pub fn init(allocator: std.mem.Allocator) MetricsSnapshot {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *MetricsSnapshot) void {
        lockSpin(&self.mutex);
        if (self.text.len != 0) self.allocator.free(self.text);
        self.text = &.{};
        self.mutex.unlock();
        self.* = undefined;
    }

    /// Replace the stored text with an owned copy of `new_text`. The previous
    /// buffer is freed under the mutex. On allocation failure the prior snapshot
    /// is left intact (a scrape returns stale-but-valid data rather than empty).
    pub fn set(self: *MetricsSnapshot, new_text: []const u8) std.mem.Allocator.Error!void {
        const owned = try self.allocator.dupe(u8, new_text);
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (self.text.len != 0) self.allocator.free(self.text);
        self.text = owned;
    }

    /// Copy the current snapshot into `out`, returning the slice written. If the
    /// snapshot does not fit, returns `error.NoSpaceLeft` (callers size `out` to
    /// the connection buffer). A never-refreshed snapshot copies zero bytes.
    pub fn copyInto(self: *MetricsSnapshot, out: []u8) error{NoSpaceLeft}![]const u8 {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (self.text.len > out.len) return error.NoSpaceLeft;
        @memcpy(out[0..self.text.len], self.text);
        return out[0..self.text.len];
    }

    /// Current snapshot byte length (for tests / introspection).
    pub fn len(self: *MetricsSnapshot) usize {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.text.len;
    }
};

// ---------------------------------------------------------------------------
// Pure request handling (unit-testable, no sockets).
// ---------------------------------------------------------------------------

/// Outcome of parsing a request line, before consulting the snapshot.
const Routed = enum { ok, not_found, method_not_allowed };

/// Classify the HTTP request line: `GET /metrics` → ok, a non-GET method on
/// `/metrics` → 405, anything else → 404. Only the request line is inspected.
fn route(request_bytes: []const u8) Routed {
    const line_end = std.mem.indexOfScalar(u8, request_bytes, '\n') orelse request_bytes.len;
    var line = request_bytes[0..line_end];
    if (line.len > 0 and line[line.len - 1] == '\r') line = line[0 .. line.len - 1];

    const first_space = std.mem.indexOfScalar(u8, line, ' ') orelse return .not_found;
    const method = line[0..first_space];

    const rest = line[first_space + 1 ..];
    const second_space = std.mem.indexOfScalar(u8, rest, ' ') orelse return .not_found;
    const target = rest[0..second_space];

    // Accept `/metrics` exactly, or with a query string (`/metrics?foo=bar`).
    const is_metrics = std.mem.eql(u8, target, "/metrics") or
        std.mem.startsWith(u8, target, "/metrics?");
    if (!is_metrics) return .not_found;

    if (!std.mem.eql(u8, method, "GET")) return .method_not_allowed;
    return .ok;
}

/// Write a full HTTP/1.1 response (status line + headers + body) into `out`,
/// reading the metrics body from `snapshot` only for a 200. Returns the slice
/// written. The body for `GET /metrics` is the live snapshot; error responses
/// carry a tiny plain-text body.
pub fn handleRequest(
    snapshot: *MetricsSnapshot,
    request_bytes: []const u8,
    out: []u8,
) error{NoSpaceLeft}![]const u8 {
    switch (route(request_bytes)) {
        .ok => return writeMetricsResponse(snapshot, out),
        .not_found => return writeSimpleResponse(out, "404 Not Found", "not found\n"),
        .method_not_allowed => return writeSimpleResponse(out, "405 Method Not Allowed", "method not allowed\n"),
    }
}

/// 200 OK with the Prometheus content type and the snapshot body copied inline.
fn writeMetricsResponse(snapshot: *MetricsSnapshot, out: []u8) error{NoSpaceLeft}![]const u8 {
    // The header length depends on the body length, so render the snapshot into
    // the tail of `out` first, then prefix the header. We hold the snapshot
    // mutex only for the copy (inside copyInto).
    var header_buf: [max_header]u8 = undefined;
    // Probe the snapshot length to size the header without holding the lock long.
    const body_len = snapshot.len();
    const header = std.fmt.bufPrint(
        &header_buf,
        "HTTP/1.1 200 OK\r\nContent-Type: {s}\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n",
        .{ content_type, body_len },
    ) catch return error.NoSpaceLeft;

    if (out.len < header.len) return error.NoSpaceLeft;
    @memcpy(out[0..header.len], header);

    // Copy the live snapshot into the body region. If it grew between the length
    // probe and here, copyInto reports NoSpaceLeft against the remaining buffer.
    const body = try snapshot.copyInto(out[header.len..]);
    return out[0 .. header.len + body.len];
}

/// A small fixed-body response (used for 404/405).
fn writeSimpleResponse(out: []u8, status: []const u8, body: []const u8) error{NoSpaceLeft}![]const u8 {
    const header = std.fmt.bufPrint(
        out,
        "HTTP/1.1 {s}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n",
        .{ status, body.len },
    ) catch return error.NoSpaceLeft;
    if (out.len - header.len < body.len) return error.NoSpaceLeft;
    @memcpy(out[header.len .. header.len + body.len], body);
    return out[0 .. header.len + body.len];
}

// ---------------------------------------------------------------------------
// Threaded loopback listener.
// ---------------------------------------------------------------------------

/// Operational tunables for the metrics listener. Unlike the ACME listener, the
/// bind address IS configurable (defaulting to loopback) so an operator can bind
/// a private interface for a remote Prometheus — but it stays loopback by default.
pub const Config = struct {
    /// TCP accept backlog.
    listen_backlog: u31 = default_listen_backlog,
    /// Accept-poll wake interval in milliseconds.
    accept_poll_ms: u32 = default_accept_poll_ms,
    /// Per-connection read timeout in seconds.
    conn_read_timeout_sec: u32 = default_conn_read_timeout_sec,
    /// Bind address (host byte order). Defaults to loopback `127.0.0.1`.
    bind_addr: u32 = loopback_addr,
};

pub const MetricsServer = struct {
    snapshot: *MetricsSnapshot,
    listen_fd: sys.fd_t,
    port: u16,
    thread: ?std.Thread = null,
    stop_flag: std.atomic.Value(bool) = .{ .raw = false },
    /// Per-connection read timeout (seconds); read by the accept loop.
    conn_read_timeout_sec: u32 = default_conn_read_timeout_sec,

    /// Bind `<addr>:port` (use port 0 for an ephemeral port) with default
    /// loopback bind + default tunables. No thread runs yet; call `spawn`.
    pub fn init(snapshot: *MetricsSnapshot, port: u16) ListenerError!MetricsServer {
        return initWithConfig(snapshot, port, .{});
    }

    /// Like `init`, but with explicit tunables (including a non-loopback bind).
    /// The returned value must live at a stable address for the thread's lifetime.
    pub fn initWithConfig(snapshot: *MetricsSnapshot, port: u16, config: Config) ListenerError!MetricsServer {
        const fd = try socketTcp();
        errdefer closeFd(fd);

        var yes: u32 = 1;
        _ = sys.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&yes), @sizeOf(u32));

        var addr = sys.sockaddr.in{
            .port = std.mem.nativeToBig(u16, port),
            .addr = std.mem.nativeToBig(u32, config.bind_addr),
        };
        if (posix.errno(sys.bind(fd, @ptrCast(&addr), @sizeOf(sys.sockaddr.in))) != .SUCCESS)
            return error.BindFailed;
        if (posix.errno(sys.listen(fd, config.listen_backlog)) != .SUCCESS)
            return error.ListenFailed;
        if (comptime builtin.os.tag != .linux) {
            @import("os_runtime.zig").setNonblocking(fd) catch return error.ListenFailed;
        }

        // Receive timeout so a blocked accept4 wakes periodically to re-check the
        // stop flag (closing the listener from another thread does NOT reliably
        // wake accept4).
        const poll_ms = if (builtin.os.tag == .linux) config.accept_poll_ms else @max(config.accept_poll_ms, 1);
        const tv = sys.timeval{
            .sec = @intCast(poll_ms / 1000),
            .usec = @intCast((poll_ms % 1000) * 1000),
        };
        const timeout_rc = sys.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(sys.timeval));
        if (comptime builtin.os.tag != .linux) {
            if (posix.errno(timeout_rc) != .SUCCESS) return error.TimeoutSetupFailed;
        }

        return .{
            .snapshot = snapshot,
            .listen_fd = fd,
            .port = try boundPort(fd),
            .conn_read_timeout_sec = if (builtin.os.tag == .linux) config.conn_read_timeout_sec else @max(config.conn_read_timeout_sec, 1),
        };
    }

    /// Spawn the background accept loop.
    pub fn spawn(self: *MetricsServer) std.Thread.SpawnError!void {
        self.thread = try std.Thread.spawn(.{}, acceptLoop, .{self});
    }

    /// Signal stop, unblock the accept loop by closing the listener, and join.
    pub fn shutdown(self: *MetricsServer) void {
        self.stop_flag.store(true, .release);
        if (comptime builtin.os.tag == .linux) closeFd(self.listen_fd);
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
        if (comptime builtin.os.tag != .linux) closeFd(self.listen_fd);
        self.listen_fd = -1;
    }

    fn acceptLoop(self: *MetricsServer) void {
        while (!self.stop_flag.load(.acquire)) {
            const rc = acceptSocket(self.listen_fd);
            switch (posix.errno(rc)) {
                .SUCCESS => self.serveConn(@intCast(rc)),
                .AGAIN, .INTR, .CONNABORTED => continue, // timeout/interrupt: re-check stop flag
                else => return, // listener closed (shutdown) or fatal: exit thread
            }
        }
    }

    fn serveConn(self: *MetricsServer, fd: sys.fd_t) void {
        defer closeFd(fd);
        // Accepted sockets do not inherit the listener's timeout; cap the read so
        // a silent/slow client cannot stall the single-threaded accept loop.
        const tv = sys.timeval{ .sec = @intCast(self.conn_read_timeout_sec), .usec = 0 };
        const timeout_rc = sys.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(sys.timeval));
        if (comptime builtin.os.tag != .linux) {
            if (posix.errno(timeout_rc) != .SUCCESS or posix.errno(sys.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&tv), @sizeOf(sys.timeval))) != .SUCCESS) return;
        }

        var req_buf: [max_request]u8 = undefined;
        const rc = sys.read(fd, &req_buf, req_buf.len);
        if (posix.errno(rc) != .SUCCESS) return;
        const n: usize = @intCast(rc);
        if (n == 0) return;

        // Response buffer: header + the full Prometheus body. Sized generously so
        // a large metrics page still fits; an oversize body yields NoSpaceLeft and
        // the connection simply closes (Prometheus retries).
        var resp_buf: [256 * 1024]u8 = undefined;
        const resp = handleRequest(self.snapshot, req_buf[0..n], &resp_buf) catch return;
        writeAll(fd, resp);
    }
};

// ---------------------------------------------------------------------------
// Low-level helpers (raw linux syscalls), mirroring acme_http01_listener.
// ---------------------------------------------------------------------------

/// Blocking acquire on the tryLock-only `std.atomic.Mutex`. Contention is
/// near-zero (a periodic refresh vs. occasional scrapes), so a yielding spin is
/// fine.
fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.Thread.yield() catch {};
}

// BSD accept timeout is explicit: listener SO_RCVTIMEO is configuration,
// poll bounds the wait, and nonblocking accept cannot hang after stale readiness.
fn acceptSocket(fd: posix.fd_t) if (builtin.os.tag == .linux) usize else c_int {
    if (comptime builtin.os.tag == .linux) return sys.accept4(fd, null, null, posix.SOCK.CLOEXEC);
    var tv: sys.timeval = undefined;
    var len: posix.socklen_t = @sizeOf(@TypeOf(tv));
    if (sys.getsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, @ptrCast(&tv), &len) != 0) return -1;
    const millis = @max(@as(i64, 1), tv.sec * 1000 + @divTrunc(tv.usec, 1000));
    var pollfds = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.IN, .revents = 0 }};
    const rc = sys.poll(&pollfds, 1, @intCast(@min(millis, std.math.maxInt(c_int))));
    if (rc < 0) return -1;
    if (rc == 0) {
        sys._errno().* = @intFromEnum(posix.E.AGAIN);
        return -1;
    }
    const accepted = sys.accept4(fd, null, null, posix.SOCK.CLOEXEC);
    if (accepted < 0) return -1;
    // BSD may inherit listener nonblocking state. Request readers use a
    // verified SO_RCVTIMEO on a blocking accepted socket.
    const old = sys.fcntl(accepted, posix.F.GETFL, @as(c_int, 0));
    if (old >= 0) {
        var flags: posix.O = @bitCast(@as(u32, @intCast(old)));
        flags.NONBLOCK = false;
        if (sys.fcntl(accepted, posix.F.SETFL, @as(usize, @as(u32, @bitCast(flags)))) == 0) return accepted;
    }
    const saved = sys._errno().*;
    _ = sys.close(accepted);
    sys._errno().* = saved;
    return -1;
}

fn socketTcp() ListenerError!sys.fd_t {
    const rc = sys.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, posix.IPPROTO.TCP);
    return switch (posix.errno(rc)) {
        .SUCCESS => @intCast(rc),
        else => error.SocketUnavailable,
    };
}

fn boundPort(fd: sys.fd_t) ListenerError!u16 {
    var storage: posix.sockaddr.storage = undefined;
    var slen: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
    if (posix.errno(sys.getsockname(fd, @ptrCast(&storage), &slen)) != .SUCCESS)
        return error.AddrLookupFailed;
    const a: *const sys.sockaddr.in = @ptrCast(@alignCast(&storage));
    return std.mem.bigToNative(u16, a.port);
}

fn closeFd(fd: sys.fd_t) void {
    _ = sys.close(fd);
}

fn writeAll(fd: sys.fd_t, bytes: []const u8) void {
    var off: usize = 0;
    while (off < bytes.len) {
        const rc = if (comptime builtin.os.tag == .linux) sys.write(fd, bytes[off..].ptr, bytes.len - off) else sys.send(fd, bytes[off..].ptr, bytes.len - off, posix.MSG.NOSIGNAL);
        if (posix.errno(rc) != .SUCCESS) return;
        if (rc == 0) return;
        off += @intCast(rc);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "MetricsSnapshot set/copyInto round-trips owned text" {
    var snap = MetricsSnapshot.init(testing.allocator);
    defer snap.deinit();

    try testing.expectEqual(@as(usize, 0), snap.len());

    try snap.set("onyx_connections_total 7\n");
    try testing.expectEqual(@as(usize, 25), snap.len());

    var buf: [128]u8 = undefined;
    const got = try snap.copyInto(&buf);
    try testing.expectEqualStrings("onyx_connections_total 7\n", got);
}

test "MetricsSnapshot set replaces and frees the prior buffer" {
    var snap = MetricsSnapshot.init(testing.allocator);
    defer snap.deinit();

    try snap.set("first");
    try snap.set("second-longer");

    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("second-longer", try snap.copyInto(&buf));
}

test "MetricsSnapshot copyInto reports NoSpaceLeft when body exceeds buffer" {
    var snap = MetricsSnapshot.init(testing.allocator);
    defer snap.deinit();
    try snap.set("0123456789");

    var buf: [4]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, snap.copyInto(&buf));
}

test "handleRequest serves the snapshot for GET /metrics with the prom content type" {
    var snap = MetricsSnapshot.init(testing.allocator);
    defer snap.deinit();
    try snap.set("# TYPE onyx_connections_total counter\nonyx_connections_total 3\n");

    var out: [1024]u8 = undefined;
    const resp = try handleRequest(&snap, "GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n", &out);

    try testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 200 OK\r\n"));
    try testing.expect(std.mem.containsAtLeast(u8, resp, 1, "Content-Type: " ++ content_type ++ "\r\n"));
    try testing.expect(std.mem.containsAtLeast(u8, resp, 1, "Content-Length: 63\r\n"));
    try testing.expect(std.mem.endsWith(u8, resp, "\r\n\r\n# TYPE onyx_connections_total counter\nonyx_connections_total 3\n"));
}

test "handleRequest accepts a query string on /metrics" {
    var snap = MetricsSnapshot.init(testing.allocator);
    defer snap.deinit();
    try snap.set("onyx_up 1\n");

    var out: [512]u8 = undefined;
    const resp = try handleRequest(&snap, "GET /metrics?collect[]=all HTTP/1.1\r\n\r\n", &out);
    try testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 200 OK\r\n"));
    try testing.expect(std.mem.endsWith(u8, resp, "\r\n\r\nonyx_up 1\n"));
}

test "handleRequest returns 404 for other paths" {
    var snap = MetricsSnapshot.init(testing.allocator);
    defer snap.deinit();
    try snap.set("onyx_up 1\n");

    var out: [512]u8 = undefined;
    const root = try handleRequest(&snap, "GET / HTTP/1.1\r\n\r\n", &out);
    const other = try handleRequest(&snap, "GET /metricsxyz HTTP/1.1\r\n\r\n", &out);

    try testing.expect(std.mem.startsWith(u8, root, "HTTP/1.1 404 Not Found\r\n"));
    try testing.expect(std.mem.startsWith(u8, other, "HTTP/1.1 404 Not Found\r\n"));
}

test "handleRequest returns 405 for non-GET on /metrics" {
    var snap = MetricsSnapshot.init(testing.allocator);
    defer snap.deinit();
    try snap.set("onyx_up 1\n");

    var out: [512]u8 = undefined;
    const post = try handleRequest(&snap, "POST /metrics HTTP/1.1\r\n\r\n", &out);
    try testing.expect(std.mem.startsWith(u8, post, "HTTP/1.1 405 Method Not Allowed\r\n"));
}

test "handleRequest serves a never-refreshed (empty) snapshot as a 200 with zero body" {
    var snap = MetricsSnapshot.init(testing.allocator);
    defer snap.deinit();

    var out: [512]u8 = undefined;
    const resp = try handleRequest(&snap, "GET /metrics HTTP/1.1\r\n\r\n", &out);
    try testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 200 OK\r\n"));
    try testing.expect(std.mem.containsAtLeast(u8, resp, 1, "Content-Length: 0\r\n"));
    try testing.expect(std.mem.endsWith(u8, resp, "\r\n\r\n"));
}

test "MetricsServer serves the snapshot over loopback" {
    if (builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
    const allocator = testing.allocator;
    var snap = MetricsSnapshot.init(allocator);
    defer snap.deinit();
    try snap.set("onyx_metrics_probe 1\n");

    var server = try MetricsServer.init(&snap, 0);
    try server.spawn();
    defer server.shutdown();

    const cfd = try socketTcp();
    defer closeFd(cfd);
    var addr = sys.sockaddr.in{
        .port = std.mem.nativeToBig(u16, server.port),
        .addr = std.mem.nativeToBig(u32, loopback_addr),
    };
    try testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.connect(cfd, @ptrCast(&addr), @sizeOf(sys.sockaddr.in))));

    writeAll(cfd, "GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n");

    var buf: [1024]u8 = undefined;
    const rc = sys.read(cfd, &buf, buf.len);
    try testing.expectEqual(posix.E.SUCCESS, posix.errno(rc));
    const got = buf[0..@intCast(rc)];
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200 OK\r\n"));
    try testing.expect(std.mem.containsAtLeast(u8, got, 1, "Content-Type: " ++ content_type ++ "\r\n"));
    try testing.expect(std.mem.endsWith(u8, got, "\r\n\r\nonyx_metrics_probe 1\n"));
}

test "initWithConfig honors a custom backlog and read timeout" {
    if (builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
    var snap = MetricsSnapshot.init(testing.allocator);
    defer snap.deinit();

    var server = try MetricsServer.initWithConfig(&snap, 0, .{
        .listen_backlog = 32,
        .accept_poll_ms = 100,
        .conn_read_timeout_sec = 3,
    });
    defer server.shutdown();
    try server.spawn();

    try testing.expectEqual(@as(u32, 3), server.conn_read_timeout_sec);
}

test {
    testing.refAllDecls(@This());
}
