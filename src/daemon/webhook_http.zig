// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Threaded plaintext HTTP listener for Discord-compatible incoming webhooks.
//!
//! Mirrors `metrics_http.zig`: a standalone, loopback-by-default HTTP/1.1
//! accept loop on its own thread. It NEVER touches reactor-owned connection
//! state — it only (a) verifies a presented token against the shared
//! `WebhookStore` (constant-time), (b) rate-limits, (c) parses + sanitises the
//! Discord JSON body, and (d) hands a fully-scrubbed `PendingPost` to the owning
//! reactor through a `PostSink` (which enqueues + wakes). The reactor performs
//! the actual channel fan-out on-thread.
//!
//! Responses use Discord-shaped status codes:
//!   204 success · 400 bad payload · 401 bad token · 404 unknown id ·
//!   405 wrong method · 411 missing Content-Length · 413 too large ·
//!   429 rate-limited (+ `Retry-After`).
//!
//! TLS is intentionally out of scope: front this listener with a reverse proxy
//! (nginx/Caddy) that terminates HTTPS and forwards to the configured loopback
//! port, exactly as an operator already does for the `/metrics` endpoint.

const std = @import("std");
const builtin = @import("builtin");

const sys = std.posix.system;
const posix = std.posix;

const webhook = @import("webhook.zig");
const webhook_render = @import("webhook_render.zig");
const runtime_pause = @import("runtime_pause.zig");
pub const dormant_spawn_options: std.Thread.SpawnConfig = .{};
const metrics_http = @import("metrics_http.zig");

comptime {
    if (@bitSizeOf(usize) != 64) @compileError("webhook_http requires a 64-bit target");
}

/// Absolute ceiling on a request body, independent of the (smaller) configured
/// cap. Sizes the connection read buffer; a declared/actual body beyond the
/// configured cap yields 413 well before this.
pub const max_body_hard: usize = 64 * 1024;
/// Scratch reserved for the request line + headers.
pub const max_header: usize = 4 * 1024;
/// JSON parse arena size (fixed, on the connection stack). Bounded work: the
/// body is already ≤ the configured cap. Exhaustion → 400 (fail-closed).
pub const json_scratch: usize = 256 * 1024;

pub const default_listen_backlog: u31 = 16;
pub const default_accept_poll_ms: u32 = 250;
pub const default_conn_read_timeout_sec: u32 = 5;
const accept_retry_initial_ms: u32 = 1;
const accept_retry_max_ms: u32 = 64;

/// Loopback `127.0.0.1` in host byte order (the secure default bind).
pub const loopback_addr: u32 = 0x7f00_0001;

pub const ListenerError = error{
    SocketUnavailable,
    BindFailed,
    ListenFailed,
    AddrLookupFailed,
    TimeoutSetupFailed,
    InvalidListener,
};

/// Handler tunables (validation limits + rate policy).
pub const HandlerConfig = struct {
    /// Max request-body bytes accepted before answering 413.
    max_body: usize = 8 * 1024,
    /// Per-webhook token-bucket rate policy.
    rate: webhook.RateConfig = .{},
    /// `Retry-After` (seconds) returned when the reactor post queue is full.
    busy_retry_after: u32 = 1,
};

// ---------------------------------------------------------------------------
// Pure request handling (unit-testable, no sockets)
// ---------------------------------------------------------------------------

/// Handle one fully-read HTTP request. Writes a complete HTTP/1.1 response into
/// `out` and returns the slice written. On a validated post it fills a
/// `PendingPost` and offers it to `sink`; a full queue yields 429. `allocator`
/// backs only the transient JSON parse tree.
pub fn handleRequest(
    store: *webhook.WebhookStore,
    sink: webhook.PostSink,
    cfg: HandlerConfig,
    allocator: std.mem.Allocator,
    request_bytes: []const u8,
    now_ms: i64,
    out: []u8,
) error{NoSpaceLeft}![]const u8 {
    // --- Request line ---------------------------------------------------
    const head_end = std.mem.indexOf(u8, request_bytes, "\r\n\r\n") orelse
        return writeSimple(out, "400 Bad Request", "bad request\n", null);
    const line_end = std.mem.indexOfScalar(u8, request_bytes, '\n') orelse
        return writeSimple(out, "400 Bad Request", "bad request\n", null);
    var line = request_bytes[0..line_end];
    if (line.len > 0 and line[line.len - 1] == '\r') line = line[0 .. line.len - 1];

    const sp1 = std.mem.indexOfScalar(u8, line, ' ') orelse
        return writeSimple(out, "400 Bad Request", "bad request\n", null);
    const method = line[0..sp1];
    const after = line[sp1 + 1 ..];
    const sp2 = std.mem.indexOfScalar(u8, after, ' ') orelse
        return writeSimple(out, "400 Bad Request", "bad request\n", null);
    const target = after[0..sp2];

    // --- Route (POST /api/webhooks/<id>/<token>) ------------------------
    const parsed_target = webhook.parseTarget(target) orelse
        return writeSimple(out, "404 Not Found", "unknown webhook\n", null);
    if (!std.mem.eql(u8, method, "POST"))
        return writeSimple(out, "405 Method Not Allowed", "method not allowed\n", null);

    // --- Body length gate -----------------------------------------------
    // A POST body MUST declare a valid Content-Length. Rejecting fast with 411
    // (rather than falling back to "read the body until the peer closes or the
    // read timeout fires") closes an unauthenticated slow-read DoS on the
    // single-threaded accept loop: a body-bearing request with no length header
    // otherwise pins the one-connection-at-a-time serveConn loop for the whole
    // RCVTIMEO window. A buffering reverse proxy always supplies Content-Length.
    const headers = request_bytes[0..head_end];
    const body = request_bytes[head_end + 4 ..];
    const declared = contentLength(headers) orelse
        return writeSimple(out, "411 Length Required", "length required\n", null);
    if (declared > cfg.max_body)
        return writeSimple(out, "413 Payload Too Large", "payload too large\n", null);
    // Honour exactly the declared body length (a client may pipeline; we never
    // read past the declared body).
    const body_slice = body[0..@min(declared, body.len)];
    if (declared > body_slice.len)
        return writeSimple(out, "400 Bad Request", "truncated body\n", null);

    // --- Token verification (constant-time) + rate limit ----------------
    var resolved: webhook.Resolved = .{};
    const vr = store.verify(parsed_target.id, parsed_target.token, now_ms, cfg.rate, &resolved);
    switch (vr.status) {
        .not_found => return writeSimple(out, "404 Not Found", "unknown webhook\n", null),
        .bad_token => return writeSimple(out, "401 Unauthorized", "invalid token\n", null),
        .rate_limited => return writeSimple(out, "429 Too Many Requests", "rate limited\n", vr.retry_after_sec),
        .ok => {},
    }

    // --- Render (fail-closed on hostile / empty JSON) -------------------
    var post: webhook.PendingPost = .{};
    post.setChannel(resolved.channel());
    webhook_render.render(allocator, body_slice, resolved.name(), &post) catch |e| switch (e) {
        error.BadJson => return writeSimple(out, "400 Bad Request", "invalid payload\n", null),
        error.EmptyPayload => return writeSimple(out, "400 Bad Request", "empty payload\n", null),
    };

    // --- Hand off to the reactor ----------------------------------------
    if (!sink.tryPost(&post))
        return writeSimple(out, "429 Too Many Requests", "server busy\n", cfg.busy_retry_after);

    // 204 No Content: success, no body (Discord's success code).
    const resp = std.fmt.bufPrint(out, "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n", .{}) catch
        return error.NoSpaceLeft;
    return resp;
}

/// Parse a `Content-Length` header value from the header block (case-insensitive
/// key). Returns null if absent or unparseable.
fn contentLength(headers: []const u8) ?usize {
    var it = std.mem.splitSequence(u8, headers, "\r\n");
    while (it.next()) |h| {
        const colon = std.mem.indexOfScalar(u8, h, ':') orelse continue;
        const key = std.mem.trim(u8, h[0..colon], " ");
        if (!std.ascii.eqlIgnoreCase(key, "content-length")) continue;
        const val = std.mem.trim(u8, h[colon + 1 ..], " \t");
        return std.fmt.parseInt(usize, val, 10) catch null;
    }
    return null;
}

/// A small fixed-body response (all non-204 outcomes). When `retry_after` is
/// set, a `Retry-After` header is included (429).
fn writeSimple(out: []u8, status: []const u8, body: []const u8, retry_after: ?u32) error{NoSpaceLeft}![]const u8 {
    const header = if (retry_after) |ra|
        std.fmt.bufPrint(
            out,
            "HTTP/1.1 {s}\r\nContent-Type: text/plain; charset=utf-8\r\nRetry-After: {d}\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n",
            .{ status, ra, body.len },
        ) catch return error.NoSpaceLeft
    else
        std.fmt.bufPrint(
            out,
            "HTTP/1.1 {s}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n",
            .{ status, body.len },
        ) catch return error.NoSpaceLeft;
    if (out.len - header.len < body.len) return error.NoSpaceLeft;
    @memcpy(out[header.len .. header.len + body.len], body);
    return out[0 .. header.len + body.len];
}

// ---------------------------------------------------------------------------
// Threaded loopback listener
// ---------------------------------------------------------------------------

pub const Config = struct {
    listen_backlog: u31 = default_listen_backlog,
    accept_poll_ms: u32 = default_accept_poll_ms,
    conn_read_timeout_sec: u32 = default_conn_read_timeout_sec,
    bind_addr: u32 = loopback_addr,
    handler: HandlerConfig = .{},
};

pub const WebhookServer = struct {
    store: *webhook.WebhookStore,
    sink: webhook.PostSink,
    handler: HandlerConfig,
    listen_fd: sys.fd_t,
    port: u16,
    /// Serializes the control-plane lifecycle. The accept thread never takes
    /// this mutex; it observes only stop_flag and the listener fd, whose final
    /// invalidation happens after join. Concurrent pause/resume/shutdown callers
    /// therefore linearize without two of them spawning or joining one handle.
    lifecycle_mutex: std.atomic.Mutex = .unlocked,
    thread: ?std.Thread = null,
    runtime: runtime_pause.WorkerState = .{},
    config: Config = .{},
    stop_flag: std.atomic.Value(bool) = .{ .raw = false },
    conn_read_timeout_sec: u32 = default_conn_read_timeout_sec,

    /// Bind `<addr>:port` (port 0 = ephemeral). No thread runs yet; call `spawn`.
    /// The returned value must live at a stable address for the thread's life.
    pub fn init(
        store: *webhook.WebhookStore,
        sink: webhook.PostSink,
        port: u16,
        config: Config,
    ) ListenerError!WebhookServer {
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
        @import("os_runtime.zig").setNonblocking(fd) catch return error.ListenFailed;

        // A finite accept timeout is also the pause barrier's wake-up clock.
        // Clamp a configured zero to one millisecond: on Linux a zero timeval
        // disables SO_RCVTIMEO and could otherwise make pause() wait forever on
        // an idle listener.
        const accept_poll_ms = normalizedConfig(config).accept_poll_ms;
        if (!installReceiveTimeoutMs(fd, accept_poll_ms)) return error.TimeoutSetupFailed;

        return .{
            .store = store,
            .sink = sink,
            .handler = config.handler,
            .config = normalizedConfig(config),
            .listen_fd = fd,
            .port = try boundPort(fd),
            // A zero timeval disables SO_RCVTIMEO. The listener lifecycle needs
            // every accepted request to remain join-bounded, so retain at least
            // a one-second read timeout even for a zero-valued config.
            .conn_read_timeout_sec = @max(config.conn_read_timeout_sec, 1),
        };
    }

    pub const ResumeError = std.Thread.SpawnError || error{ ListenerClosed, SharedGateOwned };

    /// Start the listener thread for the first time. Kept as the boot-facing
    /// name; lifecycle restarts use resumeServing() to make the retained-FD contract
    /// explicit.
    pub fn spawn(self: *WebhookServer) ResumeError!void {
        try self.resumeServing();
    }

    /// Stop accepting and wait for any already-accepted request to finish, but
    /// retain the bound listener fd. Once this returns no HTTP thread can call
    /// the sink until resumeServing(), making it an exact producer barrier for Helix.
    /// TCP handshakes may remain queued in the kernel backlog while paused; no
    /// request from them is parsed or acknowledged until the thread resumes.
    pub fn pause(self: *WebhookServer) void {
        self.runtime.requireDetached() catch @panic("managed stop requires Runtime Control join and source detach");
        lockLifecycle(&self.lifecycle_mutex);
        defer self.lifecycle_mutex.unlock();
        self.stop_flag.store(true, .release);
        self.runtime.wakeForStop();
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
    }

    /// Resume a paused listener on the same fd and therefore the same bound
    /// address/port. Repeated resume calls while already running are harmless.
    pub fn resumeServing(self: *WebhookServer) ResumeError!void {
        lockLifecycle(&self.lifecycle_mutex);
        defer self.lifecycle_mutex.unlock();
        if (self.runtime.view != null) return error.SharedGateOwned;
        if (self.thread != null) return;
        if (self.listen_fd < 0) return error.ListenerClosed;
        self.stop_flag.store(false, .release);
        self.thread = std.Thread.spawn(.{}, acceptLoop, .{self}) catch |err| {
            // Preserve the paused invariant when a thread cannot be created so
            // the caller may retry resumeServing() without reopening the listener.
            self.stop_flag.store(true, .release);
            return err;
        };
    }

    /// Final teardown retains the listener until the one producer has joined.
    /// Main must cancel/join a pending shared Gate before freeing any context.
    pub fn shutdown(self: *WebhookServer) void {
        self.runtime.requireDetached() catch @panic("managed stop requires Runtime Control join and source detach");
        lockLifecycle(&self.lifecycle_mutex);
        defer self.lifecycle_mutex.unlock();
        self.stop_flag.store(true, .release);
        self.runtime.wakeForStop();
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
        if (self.listen_fd >= 0) closeFd(self.listen_fd);
        self.listen_fd = -1;
    }

    pub fn prepareColdResources(self: *WebhookServer, io: std.Io) !void {
        if (self.thread != null or self.runtime.view != null) return error.AlreadyStarted;
        try validateEndpoint(try metrics_http.observeListener(self.listen_fd), self.port, self.config);
        try self.runtime.pause.bindIo(io);
    }
    pub fn validateDormantRegistration(self: *WebhookServer, control: *runtime_pause.start_gate.Control, view: *const runtime_pause.start_gate.View, slot: runtime_pause.start_gate.Slot) !void {
        try self.runtime.validateRegistration(control, view, slot, .webhook, 0, self, dormant_spawn_options);
    }
    pub fn prepareDormantWorker(self: *WebhookServer, control: *runtime_pause.start_gate.Control, view: *const runtime_pause.start_gate.View, slot: runtime_pause.start_gate.Slot) !void {
        try self.runtime.validatePreparation(control, view, slot, .webhook, 0, self, dormant_spawn_options);
        if (self.thread != null) return error.AlreadyStarted;
        try validateEndpoint(try metrics_http.observeListener(self.listen_fd), self.port, self.config);
        self.stop_flag.store(false, .release);
        try self.runtime.prepare(control, view, slot, .webhook, 0, WebhookServer, self, acceptLoop, dormant_spawn_options);
    }
    /// Signals this owner only. Runtime Control owns all actual joins.
    pub fn requestStopAndWake(self: *WebhookServer) void {
        self.stop_flag.store(true, .release);
        self.runtime.wakeForStop();
    }
    pub fn detachAfterJoined(self: *WebhookServer) !void {
        try self.runtime.detachAfterJoined();
    }
    pub fn requireParked(self: *WebhookServer) !void {
        try self.runtime.requireParked();
    }
    pub fn requireActivated(self: *WebhookServer) !void {
        if (self.stop_flag.load(.acquire)) return error.Stopped;
        try self.runtime.requireActivated();
    }
    pub fn requestPause(self: *WebhookServer, epoch: u64) !runtime_pause.Token {
        return self.runtime.pause.request(epoch);
    }
    pub fn awaitPaused(self: *WebhookServer, token: runtime_pause.Token, deadline: std.Io.Clock.Timestamp) !void {
        try self.runtime.pause.awaitPaused(token, deadline);
    }
    pub fn resumePaused(self: *WebhookServer, token: runtime_pause.Token) !void {
        try self.runtime.pause.resumePaused(token);
    }
    pub fn capturePaused(self: *WebhookServer, token: runtime_pause.Token) !Snapshot {
        if (self.thread == null and self.runtime.view == null) return error.NotRunning;
        try self.runtime.pause.requirePaused(token);
        return self.captureCut(.paused);
    }
    pub fn captureUnstarted(self: *WebhookServer) !Snapshot {
        if (self.thread != null or self.runtime.view != null) return error.NotQuiescent;
        return self.captureCut(.unstarted);
    }
    fn captureCut(self: *WebhookServer, execution: Execution) !Snapshot {
        const observed = try metrics_http.observeListener(self.listen_fd);
        try validateEndpoint(observed, self.port, self.config);
        return .{ .listener = observed, .config = self.config, .execution = execution };
    }
    /// Consumes the received duplicate on entry. The caller separately owns the
    /// exact WebhookStore (bindings/rate state) and accepted reactor post queue.
    /// Neither borrowed callback nor store pointers are serialized in this row.
    pub fn initInherited(store: *webhook.WebhookStore, sink: webhook.PostSink, fd: sys.fd_t, carry: *const Snapshot, config: Config) !WebhookServer {
        errdefer closeFd(fd);
        try carry.validate(config);
        const observed = try metrics_http.observeListener(fd);
        if (!std.meta.eql(observed, carry.listener)) return error.ListenerMismatch;
        return .{ .store = store, .sink = sink, .listen_fd = fd, .port = observed.port, .handler = carry.config.handler, .config = carry.config, .conn_read_timeout_sec = carry.config.conn_read_timeout_sec };
    }

    fn acceptLoop(self: *WebhookServer) void {
        self.runtime.markEntered();
        defer self.runtime.markExited();
        var retry_ms: u32 = accept_retry_initial_ms;
        while (!self.stop_flag.load(.acquire)) {
            self.runtime.pause.boundary();
            if (self.stop_flag.load(.acquire)) break;
            const rc = acceptSocket(self.listen_fd);
            const err = posix.errno(rc);
            switch (err) {
                .SUCCESS => {
                    retry_ms = accept_retry_initial_ms;
                    self.serveConn(@intCast(rc));
                },
                .AGAIN, .INTR, .CONNABORTED => continue,
                else => if (isTransientAcceptResourceError(err)) {
                    self.waitAcceptRetry(retry_ms);
                    retry_ms = nextAcceptRetryMs(retry_ms);
                    continue;
                } else return,
            }
        }
    }

    /// Resource exhaustion is process-wide and usually transient. Keep the
    /// endpoint alive without a hot spin, but poll the lifecycle stop latch each
    /// millisecond so pause()/shutdown() remain promptly joinable.
    fn waitAcceptRetry(self: *WebhookServer, delay_ms: u32) void {
        var elapsed: u32 = 0;
        while (elapsed < delay_ms and !self.stop_flag.load(.acquire)) : (elapsed += 1) {
            var req = sys.timespec{ .sec = 0, .nsec = std.time.ns_per_ms };
            _ = sys.nanosleep(&req, null);
        }
    }

    fn serveConn(self: *WebhookServer, fd: sys.fd_t) void {
        defer closeFd(fd);
        const deadline = @import("../substrate/platform.zig").monotonicMillis() + @as(i64, self.conn_read_timeout_sec) * 1000;
        // Never enter the blocking request reader without a verified finite
        // timeout: pause() joins this thread and must not be hostage to a peer
        // holding a partial request open.
        if (!installReceiveTimeoutSec(fd, self.conn_read_timeout_sec)) return;

        // Read request headers + body (bounded). The read loop stops once the
        // full declared body is present, the buffer fills, or the socket idles.
        var req_buf: [max_header + max_body_hard]u8 = undefined;
        const n = readRequestUntil(fd, &req_buf, self.handler.max_body, &self.stop_flag, deadline) orelse return;
        if (n == 0) return;

        var scratch: [json_scratch]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&scratch);

        var resp_buf: [1024]u8 = undefined;
        const now_ms = @import("../substrate/platform.zig").monotonicMillis();
        const resp = handleRequest(
            self.store,
            self.sink,
            self.handler,
            fba.allocator(),
            req_buf[0..n],
            now_ms,
            &resp_buf,
        ) catch return;
        _ = metrics_http.writeUntil(fd, resp, &self.stop_flag, deadline);
    }
};

/// Read a full HTTP request (headers + declared body) into `buf`. Returns the
/// byte count, or null on read error before any bytes. Stops early once the
/// declared `Content-Length` body is complete so a keep-alive-less client that
/// leaves the socket open does not stall the loop for the whole read timeout.
/// A request with no `Content-Length` completes at the header boundary (its
/// body, if any, is never awaited — `handleRequest` answers such a POST 411),
/// which is what keeps a length-less slow body from pinning the accept loop.
fn readRequest(fd: sys.fd_t, buf: []u8, max_body: usize, stop: *const std.atomic.Value(bool), timeout_sec: u32) ?usize {
    return readRequestUntil(fd, buf, max_body, stop, @import("../substrate/platform.zig").monotonicMillis() + @as(i64, @intCast(@max(timeout_sec, 1))) * 1000);
}
fn readRequestUntil(fd: sys.fd_t, buf: []u8, max_body: usize, stop: *const std.atomic.Value(bool), deadline: i64) ?usize {
    const clock = @import("../substrate/platform.zig");
    var total: usize = 0;
    var header_end: ?usize = null;
    var need: ?usize = null; // total bytes required once headers are parsed
    while (total < buf.len) {
        if (stop.load(.acquire)) return null;
        const remaining = deadline - clock.monotonicMillis();
        if (remaining <= 0) return null;
        var pollfds = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.IN, .revents = 0 }};
        const ready = sys.poll(&pollfds, 1, @intCast(@min(remaining, 50)));
        switch (posix.errno(ready)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return null,
        }
        if (ready == 0) continue;
        // Never block after a readiness snapshot; re-check stop/deadline on
        // every idle wake and every fragment, even under a continuously active peer.
        const rc = sys.recvfrom(fd, buf[total..].ptr, buf.len - total, posix.MSG.DONTWAIT, null, null);
        switch (posix.errno(rc)) {
            .SUCCESS => {},
            .INTR, .AGAIN => continue,
            else => return if (total == 0) null else total,
        }
        const got: usize = @intCast(rc);
        if (got == 0) break; // peer closed
        total += got;

        if (header_end == null) {
            if (std.mem.indexOf(u8, buf[0..total], "\r\n\r\n")) |he| {
                header_end = he;
                const clen = contentLength(buf[0..he]) orelse 0;
                // Stop reading at most one byte past the configured cap: a body
                // declared larger than `max_body` is a guaranteed 413, so there is
                // no reason to slurp the whole (possibly 64 KiB) declared payload.
                const wanted = @min(clen, max_body + 1);
                need = he + 4 + wanted;
            }
        }
        if (need) |req| {
            if (total >= req) break; // full request (or the cap+1) in hand
        }
    }
    return total;
}

// ---------------------------------------------------------------------------
// Low-level helpers (raw linux syscalls), mirroring metrics_http.zig
// ---------------------------------------------------------------------------

fn lockLifecycle(mutex: *std.atomic.Mutex) void {
    while (!mutex.tryLock()) std.Thread.yield() catch {};
}

fn installReceiveTimeout(fd: sys.fd_t, tv: sys.timeval) bool {
    if (posix.errno(sys.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(sys.timeval))) != .SUCCESS) return false;
    if (posix.errno(sys.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&tv), @sizeOf(sys.timeval))) != .SUCCESS) return false;
    return true;
}

fn installReceiveTimeoutMs(fd: sys.fd_t, timeout_ms: u32) bool {
    const finite_ms = @max(timeout_ms, 1);
    return installReceiveTimeout(fd, .{
        .sec = @intCast(finite_ms / 1000),
        .usec = @intCast((finite_ms % 1000) * 1000),
    });
}

fn installReceiveTimeoutSec(fd: sys.fd_t, timeout_sec: u32) bool {
    return installReceiveTimeout(fd, .{
        .sec = @intCast(@max(timeout_sec, 1)),
        .usec = 0,
    });
}

fn isTransientAcceptResourceError(err: posix.E) bool {
    return switch (err) {
        .MFILE, .NFILE, .NOBUFS, .NOMEM => true,
        else => false,
    };
}

fn nextAcceptRetryMs(current_ms: u32) u32 {
    if (current_ms >= accept_retry_max_ms) return accept_retry_max_ms;
    return @min(current_ms * 2, accept_retry_max_ms);
}

// BSD accept timeout is explicit: listener SO_RCVTIMEO is configuration,
// poll bounds the wait, and nonblocking accept cannot hang after stale readiness.
fn acceptSocket(fd: posix.fd_t) if (builtin.os.tag == .linux) usize else c_int {
    var tv: sys.timeval = undefined;
    var len: posix.socklen_t = @sizeOf(@TypeOf(tv));
    if (posix.errno(sys.getsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, @ptrCast(&tv), &len)) != .SUCCESS) return acceptFailure(.INVAL);
    const millis = @max(@as(i64, 1), tv.sec * 1000 + @divTrunc(tv.usec, 1000));
    var pollfds = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.IN, .revents = 0 }};
    const rc = sys.poll(&pollfds, 1, @intCast(@min(millis, std.math.maxInt(c_int))));
    if (posix.errno(rc) != .SUCCESS) return acceptFailure(posix.errno(rc));
    if (rc == 0) return acceptFailure(.AGAIN);
    const accepted = sys.accept4(fd, null, null, posix.SOCK.CLOEXEC);
    if (posix.errno(accepted) != .SUCCESS) return acceptFailure(posix.errno(accepted));
    if (comptime builtin.os.tag == .linux) return accepted;
    if (comptime builtin.os.tag != .linux) {
        // Only the newly accepted socket changes mode; never an inherited listener.
        const old = sys.fcntl(accepted, posix.F.GETFL, @as(c_int, 0));
        if (old >= 0) {
            var flags: posix.O = @bitCast(@as(u32, @intCast(old)));
            flags.NONBLOCK = false;
            if (sys.fcntl(accepted, posix.F.SETFL, @as(if (@import("builtin").os.tag == .linux) usize else c_int, @intCast(@as(u32, @bitCast(flags))))) == 0) return accepted;
        }
        const saved = sys._errno().*;
        _ = sys.close(accepted);
        sys._errno().* = saved;
        return -1;
    } else unreachable;
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

/// A test sink that records the last post and can be forced to reject (full).
const RecordingSink = struct {
    got: ?webhook.PendingPost = null,
    accept: bool = true,

    fn submit(ctx: *anyopaque, post: *const webhook.PendingPost) bool {
        const self: *RecordingSink = @ptrCast(@alignCast(ctx));
        if (!self.accept) return false;
        self.got = post.*;
        return true;
    }

    fn sink(self: *RecordingSink) webhook.PostSink {
        return .{ .ctx = self, .submit = submit };
    }
};

/// Thread-safe sink for listener lifecycle tests. Counting, rather than
/// retaining a borrowed post, lets the test prove a queued connection is
/// handled exactly once across a pause/resume boundary without a data race.
const CountingSink = struct {
    count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    fn submit(ctx: *anyopaque, post: *const webhook.PendingPost) bool {
        _ = post;
        const self: *CountingSink = @ptrCast(@alignCast(ctx));
        _ = self.count.fetchAdd(1, .acq_rel);
        return true;
    }

    fn sink(self: *CountingSink) webhook.PostSink {
        return .{ .ctx = self, .submit = submit };
    }
};

const LifecycleRaceAction = enum { pause, resume_serving };

const LifecycleRaceCtx = struct {
    server: *WebhookServer,
    action: LifecycleRaceAction,
    ready: *std.atomic.Value(u32),
    go: *std.atomic.Value(bool),
    failed: *std.atomic.Value(bool),

    fn run(self: *LifecycleRaceCtx) void {
        _ = self.ready.fetchAdd(1, .acq_rel);
        while (!self.go.load(.acquire)) std.Thread.yield() catch {};
        switch (self.action) {
            .pause => self.server.pause(),
            .resume_serving => self.server.resumeServing() catch self.failed.store(true, .release),
        }
    }
};

fn seed(store: *webhook.WebhookStore) webhook.Credentials {
    const idm: [webhook.id_bytes]u8 = @splat(0xAB);
    const tkm: [webhook.token_bytes]u8 = @splat(0xCD);
    return store.create("#alerts", "hook", "op", 0, 0, .{}, idm, tkm) catch unreachable;
}

fn buildRequest(buf: []u8, id: []const u8, token: []const u8, body: []const u8) []const u8 {
    return std.fmt.bufPrint(
        buf,
        "POST /api/webhooks/{s}/{s} HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}",
        .{ id, token, body.len, body },
    ) catch unreachable;
}

/// Like `buildRequest`, but deliberately omits the `Content-Length` header — a
/// body-bearing POST that must be rejected fast (411) rather than awaited.
fn buildRequestNoLen(buf: []u8, id: []const u8, token: []const u8, body: []const u8) []const u8 {
    return std.fmt.bufPrint(
        buf,
        "POST /api/webhooks/{s}/{s} HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\r\n{s}",
        .{ id, token, body },
    ) catch unreachable;
}

fn connectLoopback(port: u16) !sys.fd_t {
    const fd = try socketTcp();
    errdefer closeFd(fd);
    var addr = sys.sockaddr.in{
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, loopback_addr),
    };
    if (posix.errno(sys.connect(fd, @ptrCast(&addr), @sizeOf(sys.sockaddr.in))) != .SUCCESS)
        return error.ConnectFailed;
    // Bound a broken lifecycle test rather than leaving the test runner blocked
    // forever waiting for a listener thread that did not resume.
    const tv = sys.timeval{ .sec = 2, .usec = 0 };
    _ = sys.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(sys.timeval));
    return fd;
}

fn expectNoContent(fd: sys.fd_t) !void {
    var buf: [512]u8 = undefined;
    const rc = sys.read(fd, &buf, buf.len);
    if (posix.errno(rc) != .SUCCESS) return error.ResponseReadFailed;
    const got = buf[0..@intCast(rc)];
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 204 No Content\r\n"));
}

fn testSleepMs(ms: u64) void {
    var req = sys.timespec{
        .sec = @intCast(ms / 1000),
        .nsec = @intCast((ms % 1000) * std.time.ns_per_ms),
    };
    _ = sys.nanosleep(&req, null);
}

test "handleRequest returns 204 and enqueues a post on a valid request" {
    var store = webhook.WebhookStore.init();
    const creds = seed(&store);
    var rec = RecordingSink{};

    var reqbuf: [512]u8 = undefined;
    const req = buildRequest(&reqbuf, &creds.id, &creds.token, "{\"content\":\"hi\"}");

    var out: [1024]u8 = undefined;
    const resp = try handleRequest(&store, rec.sink(), .{}, testing.allocator, req, 0, &out);
    try testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 204 No Content\r\n"));
    try testing.expect(rec.got != null);
    try testing.expectEqualStrings("#alerts", rec.got.?.channel());
    try testing.expectEqualStrings("hi", rec.got.?.body());
}

test "handleRequest 404 for unknown id, 401 for bad token" {
    var store = webhook.WebhookStore.init();
    const creds = seed(&store);
    var rec = RecordingSink{};

    var reqbuf: [512]u8 = undefined;
    var out: [1024]u8 = undefined;

    var unknown: [webhook.id_hex_len]u8 = @splat('0');
    const r404 = try handleRequest(&store, rec.sink(), .{}, testing.allocator, buildRequest(&reqbuf, &unknown, &creds.token, "{\"content\":\"x\"}"), 0, &out);
    try testing.expect(std.mem.startsWith(u8, r404, "HTTP/1.1 404 Not Found\r\n"));

    const r401 = try handleRequest(&store, rec.sink(), .{}, testing.allocator, buildRequest(&reqbuf, &creds.id, "wrongtoken", "{\"content\":\"x\"}"), 0, &out);
    try testing.expect(std.mem.startsWith(u8, r401, "HTTP/1.1 401 Unauthorized\r\n"));
    // Neither error posted anything.
    try testing.expect(rec.got == null);
}

test "handleRequest 400 for bad JSON and empty payload" {
    var store = webhook.WebhookStore.init();
    const creds = seed(&store);
    var rec = RecordingSink{};
    var reqbuf: [512]u8 = undefined;
    var out: [1024]u8 = undefined;

    const bad = try handleRequest(&store, rec.sink(), .{}, testing.allocator, buildRequest(&reqbuf, &creds.id, &creds.token, "not json"), 0, &out);
    try testing.expect(std.mem.startsWith(u8, bad, "HTTP/1.1 400 Bad Request\r\n"));

    const empty = try handleRequest(&store, rec.sink(), .{}, testing.allocator, buildRequest(&reqbuf, &creds.id, &creds.token, "{}"), 0, &out);
    try testing.expect(std.mem.startsWith(u8, empty, "HTTP/1.1 400 Bad Request\r\n"));
}

test "handleRequest 411 when a POST body has no Content-Length" {
    // Regression for the unauthenticated slow-read DoS: a body-bearing POST with
    // no Content-Length header must fail fast (411) instead of being accepted or
    // stalling the accept loop until the read timeout fires. Pre-fix this
    // returned 204 (the body was silently honoured via a length fallback).
    var store = webhook.WebhookStore.init();
    const creds = seed(&store);
    var rec = RecordingSink{};
    var reqbuf: [512]u8 = undefined;
    var out: [1024]u8 = undefined;

    const req = buildRequestNoLen(&reqbuf, &creds.id, &creds.token, "{\"content\":\"hi\"}");
    const resp = try handleRequest(&store, rec.sink(), .{}, testing.allocator, req, 0, &out);
    try testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 411 Length Required\r\n"));
    // The 411 short-circuits before token verify / render — nothing enqueued.
    try testing.expect(rec.got == null);
}

test "handleRequest 411 rejects an unparseable Content-Length on a POST body" {
    // A syntactically invalid length is treated as "no valid Content-Length".
    var store = webhook.WebhookStore.init();
    const creds = seed(&store);
    var rec = RecordingSink{};
    var reqbuf: [512]u8 = undefined;
    var out: [1024]u8 = undefined;
    const req = std.fmt.bufPrint(
        &reqbuf,
        "POST /api/webhooks/{s}/{s} HTTP/1.1\r\nHost: x\r\nContent-Length: notanumber\r\n\r\n{{\"content\":\"x\"}}",
        .{ creds.id, creds.token },
    ) catch unreachable;
    const resp = try handleRequest(&store, rec.sink(), .{}, testing.allocator, req, 0, &out);
    try testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 411 Length Required\r\n"));
    try testing.expect(rec.got == null);
}

test "handleRequest still returns 204 for a well-formed POST with Content-Length" {
    // No regression: the length-present happy path reaches the handler and posts.
    var store = webhook.WebhookStore.init();
    const creds = seed(&store);
    var rec = RecordingSink{};
    var reqbuf: [512]u8 = undefined;
    var out: [1024]u8 = undefined;
    const req = buildRequest(&reqbuf, &creds.id, &creds.token, "{\"content\":\"ok\"}");
    const resp = try handleRequest(&store, rec.sink(), .{}, testing.allocator, req, 0, &out);
    try testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 204 No Content\r\n"));
    try testing.expect(rec.got != null);
    try testing.expectEqualStrings("ok", rec.got.?.body());
}

test "handleRequest 405 for a bodiless non-POST is not masked by the 411 gate" {
    // A GET carries no body and no Content-Length; it must still be answered 405
    // (wrong method), never 411 — the length gate is POST-only and sits after
    // the method check.
    var store = webhook.WebhookStore.init();
    const creds = seed(&store);
    var rec = RecordingSink{};
    var out: [1024]u8 = undefined;
    var reqbuf: [512]u8 = undefined;
    const req = std.fmt.bufPrint(&reqbuf, "GET /api/webhooks/{s}/{s} HTTP/1.1\r\nHost: x\r\n\r\n", .{ creds.id, creds.token }) catch unreachable;
    const resp = try handleRequest(&store, rec.sink(), .{}, testing.allocator, req, 0, &out);
    try testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 405 Method Not Allowed\r\n"));
}

test "handleRequest 405 for a non-POST method on a valid webhook path" {
    var store = webhook.WebhookStore.init();
    const creds = seed(&store);
    var rec = RecordingSink{};
    var out: [1024]u8 = undefined;
    var reqbuf: [512]u8 = undefined;
    const req = std.fmt.bufPrint(&reqbuf, "GET /api/webhooks/{s}/{s} HTTP/1.1\r\nHost: x\r\n\r\n", .{ creds.id, creds.token }) catch unreachable;
    const resp = try handleRequest(&store, rec.sink(), .{}, testing.allocator, req, 0, &out);
    try testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 405 Method Not Allowed\r\n"));
}

test "handleRequest 413 when the declared body exceeds the cap" {
    var store = webhook.WebhookStore.init();
    const creds = seed(&store);
    var rec = RecordingSink{};
    var out: [1024]u8 = undefined;
    var reqbuf: [512]u8 = undefined;
    // Declare a huge Content-Length with a tiny cap.
    const req = std.fmt.bufPrint(&reqbuf, "POST /api/webhooks/{s}/{s} HTTP/1.1\r\nContent-Length: 99999\r\n\r\n{{}}", .{ creds.id, creds.token }) catch unreachable;
    const resp = try handleRequest(&store, rec.sink(), .{ .max_body = 16 }, testing.allocator, req, 0, &out);
    try testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 413 Payload Too Large\r\n"));
}

test "handleRequest 429 with Retry-After when rate limited" {
    var store = webhook.WebhookStore.init();
    const idm: [webhook.id_bytes]u8 = @splat(1);
    const tkm: [webhook.token_bytes]u8 = @splat(2);
    const creds = try store.create("#c", "h", "o", 0, 0, .{ .per_min = 60, .burst = 1 }, idm, tkm);
    var rec = RecordingSink{};
    const cfg = HandlerConfig{ .rate = .{ .per_min = 60, .burst = 1 } };
    var reqbuf: [512]u8 = undefined;
    var out: [1024]u8 = undefined;

    // First succeeds.
    _ = try handleRequest(&store, rec.sink(), cfg, testing.allocator, buildRequest(&reqbuf, &creds.id, &creds.token, "{\"content\":\"a\"}"), 0, &out);
    // Second within the same instant → 429 + Retry-After.
    const limited = try handleRequest(&store, rec.sink(), cfg, testing.allocator, buildRequest(&reqbuf, &creds.id, &creds.token, "{\"content\":\"b\"}"), 0, &out);
    try testing.expect(std.mem.startsWith(u8, limited, "HTTP/1.1 429 Too Many Requests\r\n"));
    try testing.expect(std.mem.containsAtLeast(u8, limited, 1, "Retry-After: "));
}

test "handleRequest 429 server busy when the sink is full" {
    var store = webhook.WebhookStore.init();
    const creds = seed(&store);
    var rec = RecordingSink{ .accept = false };
    var reqbuf: [512]u8 = undefined;
    var out: [1024]u8 = undefined;
    const resp = try handleRequest(&store, rec.sink(), .{}, testing.allocator, buildRequest(&reqbuf, &creds.id, &creds.token, "{\"content\":\"x\"}"), 0, &out);
    try testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 429 Too Many Requests\r\n"));
}

test "contentLength parses case-insensitively" {
    try testing.expectEqual(@as(?usize, 42), contentLength("Host: x\r\ncontent-length: 42\r\nX: y"));
    try testing.expectEqual(@as(?usize, 7), contentLength("CONTENT-LENGTH:7"));
    try testing.expectEqual(@as(?usize, null), contentLength("Host: x"));
}

test "WebhookServer installs finite lifecycle timeouts even when configured zero" {
    if (builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
    var store = webhook.WebhookStore.init();
    var rec = RecordingSink{};
    var server = try WebhookServer.init(&store, rec.sink(), 0, .{
        .accept_poll_ms = 0,
        .conn_read_timeout_sec = 0,
    });
    defer server.shutdown();

    try testing.expectEqual(@as(u32, 1), server.conn_read_timeout_sec);
    var tv: sys.timeval = undefined;
    var tv_len: posix.socklen_t = @sizeOf(sys.timeval);
    const rc = sys.getsockopt(
        server.listen_fd,
        posix.SOL.SOCKET,
        posix.SO.RCVTIMEO,
        @ptrCast(&tv),
        &tv_len,
    );
    try testing.expectEqual(posix.E.SUCCESS, posix.errno(rc));
    try testing.expect(tv.sec != 0 or tv.usec != 0);
    try testing.expect(!installReceiveTimeoutSec(-1, 1));
}

test "WebhookServer transient accept errors use bounded exponential backoff" {
    try testing.expect(isTransientAcceptResourceError(.MFILE));
    try testing.expect(isTransientAcceptResourceError(.NFILE));
    try testing.expect(isTransientAcceptResourceError(.NOBUFS));
    try testing.expect(isTransientAcceptResourceError(.NOMEM));
    try testing.expect(!isTransientAcceptResourceError(.BADF));

    var delay = accept_retry_initial_ms;
    try testing.expectEqual(@as(u32, 1), delay);
    delay = nextAcceptRetryMs(delay);
    try testing.expectEqual(@as(u32, 2), delay);
    delay = nextAcceptRetryMs(delay);
    try testing.expectEqual(@as(u32, 4), delay);
    while (delay < accept_retry_max_ms) delay = nextAcceptRetryMs(delay);
    try testing.expectEqual(accept_retry_max_ms, delay);
    try testing.expectEqual(accept_retry_max_ms, nextAcceptRetryMs(delay));
}

test "WebhookServer serves a POST over loopback and enqueues a post" {
    if (builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
    var store = webhook.WebhookStore.init();
    const creds = seed(&store);
    var rec = RecordingSink{};

    var server = try WebhookServer.init(&store, rec.sink(), 0, .{});
    try server.spawn();
    defer server.shutdown();

    const cfd = try socketTcp();
    defer closeFd(cfd);
    var addr = sys.sockaddr.in{
        .port = std.mem.nativeToBig(u16, server.port),
        .addr = std.mem.nativeToBig(u32, loopback_addr),
    };
    try testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.connect(cfd, @ptrCast(&addr), @sizeOf(sys.sockaddr.in))));

    var reqbuf: [512]u8 = undefined;
    const req = buildRequest(&reqbuf, &creds.id, &creds.token, "{\"content\":\"loop\"}");
    writeAll(cfd, req);

    var buf: [512]u8 = undefined;
    const rc = sys.read(cfd, &buf, buf.len);
    try testing.expectEqual(posix.E.SUCCESS, posix.errno(rc));
    const got = buf[0..@intCast(rc)];
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 204 No Content\r\n"));

    // The post reached the sink (poll briefly for the accept-loop thread).
    var tries: usize = 0;
    while (rec.got == null and tries < 1000) : (tries += 1) std.Thread.yield() catch {};
    try testing.expect(rec.got != null);
    try testing.expectEqualStrings("loop", rec.got.?.body());
}

test "WebhookServer pause and resume retain the port and handle each POST once" {
    if (builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
    var store = webhook.WebhookStore.init();
    const creds = seed(&store);
    var counted = CountingSink{};

    var server = try WebhookServer.init(&store, counted.sink(), 0, .{
        .accept_poll_ms = 10,
        .conn_read_timeout_sec = 1,
    });
    try server.spawn();
    defer server.shutdown();

    const original_fd = server.listen_fd;
    const original_port = server.port;

    // Establish one ordinary delivery before the first lifecycle boundary.
    var reqbuf: [512]u8 = undefined;
    const first = buildRequest(&reqbuf, &creds.id, &creds.token, "{\"content\":\"first\"}");
    const first_fd = try connectLoopback(original_port);
    writeAll(first_fd, first);
    try expectNoContent(first_fd);
    closeFd(first_fd);
    try testing.expectEqual(@as(u32, 1), counted.count.load(.acquire));

    // pause() joins the only producer thread but retains the exact listening
    // socket. A request may complete its TCP handshake into the kernel backlog,
    // yet it cannot reach the sink while the listener is paused.
    server.pause();
    try testing.expect(server.thread == null);
    try testing.expectEqual(original_fd, server.listen_fd);
    try testing.expectEqual(original_port, server.port);
    try testing.expectEqual(original_port, try boundPort(server.listen_fd));

    const queued_fd = try connectLoopback(original_port);
    const queued = buildRequest(&reqbuf, &creds.id, &creds.token, "{\"content\":\"queued\"}");
    writeAll(queued_fd, queued);
    try testing.expectEqual(@as(u32, 1), counted.count.load(.acquire));

    try server.resumeServing();
    try testing.expect(server.thread != null);
    try testing.expectEqual(original_fd, server.listen_fd);
    try testing.expectEqual(original_port, server.port);
    try expectNoContent(queued_fd);
    closeFd(queued_fd);
    try testing.expectEqual(@as(u32, 2), counted.count.load(.acquire));

    // A second complete cycle must neither replay either closed connection nor
    // allocate a replacement listener. A fresh POST remains serviceable once.
    server.pause();
    try testing.expectEqual(@as(u32, 2), counted.count.load(.acquire));
    try server.resumeServing();
    const third_fd = try connectLoopback(original_port);
    const third = buildRequest(&reqbuf, &creds.id, &creds.token, "{\"content\":\"third\"}");
    writeAll(third_fd, third);
    try expectNoContent(third_fd);
    closeFd(third_fd);
    try testing.expectEqual(@as(u32, 3), counted.count.load(.acquire));

    // Final teardown closes once and is safe to repeat; a closed listener is
    // deliberately not resumable.
    server.shutdown();
    server.shutdown();
    try testing.expectEqual(@as(sys.fd_t, -1), server.listen_fd);
    try testing.expectError(error.ListenerClosed, server.resumeServing());
}

test "WebhookServer concurrent pause and resume never leave a duplicate producer" {
    if (builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
    var store = webhook.WebhookStore.init();
    const creds = seed(&store);
    var counted = CountingSink{};

    var server = try WebhookServer.init(&store, counted.sink(), 0, .{
        .accept_poll_ms = 5,
        .conn_read_timeout_sec = 1,
        .handler = .{ .rate = .{ .per_min = 60_000, .burst = 100 } },
    });
    try server.spawn();
    defer server.shutdown();
    const original_fd = server.listen_fd;
    const original_port = server.port;

    var delivered: u32 = 0;
    for (0..32) |_| {
        var ready = std.atomic.Value(u32).init(0);
        var go = std.atomic.Value(bool).init(false);
        var failed = std.atomic.Value(bool).init(false);
        var contexts = [_]LifecycleRaceCtx{
            .{ .server = &server, .action = .resume_serving, .ready = &ready, .go = &go, .failed = &failed },
            .{ .server = &server, .action = .pause, .ready = &ready, .go = &go, .failed = &failed },
            .{ .server = &server, .action = .resume_serving, .ready = &ready, .go = &go, .failed = &failed },
        };
        var controllers: [contexts.len]std.Thread = undefined;
        for (&controllers, &contexts) |*thread, *ctx| {
            thread.* = try std.Thread.spawn(.{}, LifecycleRaceCtx.run, .{ctx});
        }
        while (ready.load(.acquire) != contexts.len) std.Thread.yield() catch {};
        go.store(true, .release);
        for (controllers) |thread| thread.join();
        try testing.expect(!failed.load(.acquire));

        // Establish a final paused linearization point. If concurrent resume
        // callers spawned two accept loops and overwrote one handle, pause would
        // join only the recorded thread and the orphan would consume this POST.
        server.pause();
        try testing.expect(server.thread == null);
        try testing.expectEqual(original_fd, server.listen_fd);
        try testing.expectEqual(original_port, server.port);

        var reqbuf: [512]u8 = undefined;
        const req = buildRequest(&reqbuf, &creds.id, &creds.token, "{\"content\":\"race\"}");
        const fd = try connectLoopback(original_port);
        writeAll(fd, req);
        testSleepMs(10);
        try testing.expectEqual(delivered, counted.count.load(.acquire));

        try server.resumeServing();
        try expectNoContent(fd);
        closeFd(fd);
        delivered += 1;
        try testing.expectEqual(delivered, counted.count.load(.acquire));
    }
    server.pause();
}

test "WebhookServer answers 411 promptly for a length-less POST body over loopback" {
    if (builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
    var store = webhook.WebhookStore.init();
    const creds = seed(&store);
    var rec = RecordingSink{};

    var server = try WebhookServer.init(&store, rec.sink(), 0, .{});
    try server.spawn();
    defer server.shutdown();

    const cfd = try socketTcp();
    defer closeFd(cfd);
    var addr = sys.sockaddr.in{
        .port = std.mem.nativeToBig(u16, server.port),
        .addr = std.mem.nativeToBig(u32, loopback_addr),
    };
    try testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.connect(cfd, @ptrCast(&addr), @sizeOf(sys.sockaddr.in))));

    // A complete header block, a JSON body, and NO Content-Length. Pre-fix the
    // server would honour the fallback body (204); it now short-circuits 411
    // without waiting for the read timeout.
    var reqbuf: [512]u8 = undefined;
    const req = buildRequestNoLen(&reqbuf, &creds.id, &creds.token, "{\"content\":\"nolen\"}");
    writeAll(cfd, req);

    var buf: [512]u8 = undefined;
    const rc = sys.read(cfd, &buf, buf.len);
    try testing.expectEqual(posix.E.SUCCESS, posix.errno(rc));
    const got = buf[0..@intCast(rc)];
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 411 Length Required\r\n"));

    // Nothing was enqueued for the reactor.
    try testing.expect(rec.got == null);
}

test {
    testing.refAllDecls(@This());
}

test "WebhookServer pause and whole request deadline stop an active dribble before publication" {
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
    for ([_]bool{ true, false }) |pause_now| {
        var store = webhook.WebhookStore.init();
        var counted = CountingSink{};
        var server = try WebhookServer.init(&store, counted.sink(), 0, .{ .accept_poll_ms = 10, .conn_read_timeout_sec = 1 });
        try server.spawn();
        defer server.shutdown();
        const fd = try connectLoopback(server.port);
        defer closeFd(fd);
        writeAll(fd, "POST /webhook/incomplete HTTP/1.1\r\nContent-Length: 65536\r\n\r\n");
        const Dribble = struct {
            fd: posix.fd_t,
            stop: std.atomic.Value(bool) = .init(false),
            writes: std.atomic.Value(u32) = .init(0),
            fn run(self: *@This()) void {
                while (!self.stop.load(.acquire)) {
                    const rc = sys.sendto(self.fd, "x", 1, posix.MSG.NOSIGNAL | posix.MSG.DONTWAIT, null, 0);
                    if (posix.errno(rc) != .SUCCESS) return;
                    _ = self.writes.fetchAdd(1, .release);
                    testSleepMs(10);
                }
            }
        };
        var dribble = Dribble{ .fd = fd };
        const thread = try std.Thread.spawn(.{}, Dribble.run, .{&dribble});
        defer {
            dribble.stop.store(true, .release);
            thread.join();
        }
        for (0..100) |_| {
            if (dribble.writes.load(.acquire) >= 5) break;
            testSleepMs(10);
        }
        try testing.expect(dribble.writes.load(.acquire) >= 5);
        const clock = @import("../substrate/platform.zig");
        const before = clock.monotonicMillis();
        if (pause_now) server.pause();
        if (pause_now) try testing.expect(clock.monotonicMillis() - before < 1000);
        try testing.expectEqual(@as(u32, 0), counted.count.load(.acquire));
        // EOF or reset proves this was an accepted request, not a vacuous backlog
        // connection. The listener remains bound for a later resume.
        var byte: [1]u8 = undefined;
        const ended = sys.recvfrom(fd, &byte, byte.len, 0, null, null);
        try testing.expect(ended == 0 or posix.errno(ended) == .CONNRESET);
        try testing.expect(clock.monotonicMillis() - before < 1500);
        if (!pause_now) server.pause();
        try testing.expect(server.thread == null);
        try testing.expectEqual(@as(u32, 0), counted.count.load(.acquire));
        try testing.expect(server.listen_fd >= 0);
    }
}

fn acceptFailure(err: posix.E) if (builtin.os.tag == .linux) usize else c_int {
    if (comptime builtin.os.tag == .linux) return @bitCast(-@as(isize, @intFromEnum(err))) else {
        sys._errno().* = @intFromEnum(err);
        return -1;
    }
}

pub const Execution = enum(u8) { unstarted = 0, paused = 1 };
pub const Snapshot = struct {
    listener: metrics_http.ListenerObservation,
    config: Config,
    execution: Execution,
    pub fn validate(self: *const Snapshot, config: Config) !void {
        if (!std.meta.eql(self.config, normalizedConfig(config))) return error.ConfigMismatch;
        if (self.config.handler.max_body > max_body_hard) return error.InvalidSnapshot;
        try validateEndpoint(self.listener, self.listener.port, self.config);
    }
};
fn normalizedConfig(config: Config) Config {
    var result = config;
    result.accept_poll_ms = @min(@max(result.accept_poll_ms, 1), std.math.maxInt(c_int));
    result.conn_read_timeout_sec = @max(result.conn_read_timeout_sec, 1);
    return result;
}
fn validateEndpoint(observed: metrics_http.ListenerObservation, port: u16, config: Config) !void {
    var address: [16]u8 = @splat(0);
    std.mem.writeInt(u32, address[0..4], config.bind_addr, .big);
    if (observed.family != posix.AF.INET or port == 0 or observed.port != port or
        observed.scope_id != 0 or observed.flow_info != 0 or !std.mem.eql(u8, &observed.address, &address)) return error.ListenerMismatch;
    // Linux rounds sub-tick SO_RCVTIMEO upward; matching the held observation is
    // authoritative, with this finite configured lower bound and one tick slack.
    const wanted = @as(u64, normalizedConfig(config).accept_poll_ms) * 1000;
    if (observed.recv_timeout_us < wanted or observed.recv_timeout_us - wanted > 10_000) return error.ListenerMismatch;
}

fn duplicateListenerForTest(fd: posix.fd_t) !posix.fd_t {
    const rc = sys.fcntl(fd, (if (@import("builtin").os.tag == .openbsd) @as(c_int, 10) else std.posix.F.DUPFD_CLOEXEC), @as(if (@import("builtin").os.tag == .linux) usize else c_int, 0));
    if (posix.errno(rc) != .SUCCESS) return error.TestUnexpectedResult;
    return @intCast(rc);
}

test "companion runtime webhook gated retained worker preserves backlog and exact listener" {
    // getsockopt/setsockopt have no libc-free Windows mapping yet.
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    var store = webhook.WebhookStore.init();
    const creds = seed(&store);
    var counted = CountingSink{};
    const config: Config = .{ .accept_poll_ms = 10, .conn_read_timeout_sec = 1 };
    var server = try WebhookServer.init(&store, counted.sink(), 0, config);
    try server.prepareColdResources(std.testing.io);
    const specs = [_]runtime_pause.start_gate.ParticipantSpec{.{ .kind = .webhook, .instance = 0, .owner_identity = &server }};
    const gate = runtime_pause.start_gate.create(std.testing.allocator, std.testing.io, &specs) catch |err| {
        server.shutdown();
        return err;
    };
    defer {
        server.requestStopAndWake();
        if (gate.view.inspect().phase == .preparing) gate.control.cancelAllAndJoin() else gate.control.joinAll();
        server.detachAfterJoined() catch unreachable;
        server.shutdown();
        gate.control.destroyJoined();
    }
    const first_pause = try server.requestPause(1);
    try server.prepareDormantWorker(gate.control, gate.view, try gate.view.slot(.webhook, 0, &server));
    try gate.control.awaitAllParked(std.Io.Clock.Timestamp.fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
    try std.testing.expect(server.thread == null);
    gate.control.releaseAll();
    try server.awaitPaused(first_pause, std.Io.Clock.Timestamp.fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
    try server.requireActivated();
    const observed = try metrics_http.observeListener(server.listen_fd);
    var carry = try server.capturePaused(first_pause);
    const queued_fd = try connectLoopback(server.port);
    defer closeFd(queued_fd);
    var request: [512]u8 = undefined;
    writeAll(queued_fd, buildRequest(&request, &creds.id, &creds.token, "{\"content\":\"retained\"}"));
    try std.testing.expectEqual(@as(u32, 0), counted.count.load(.acquire));
    var adopted = try WebhookServer.initInherited(&store, counted.sink(), try duplicateListenerForTest(server.listen_fd), &carry, config);
    adopted.shutdown();
    try std.testing.expectEqualDeep(observed, try metrics_http.observeListener(server.listen_fd));
    const rejected = try duplicateListenerForTest(server.listen_fd);
    carry.listener.inode ^= 1;
    try std.testing.expectError(error.ListenerMismatch, WebhookServer.initInherited(&store, counted.sink(), rejected, &carry, config));
    carry.listener.inode ^= 1;
    try std.testing.expect(posix.errno(sys.fcntl(rejected, posix.F.GETFD, @as(if (@import("builtin").os.tag == .linux) usize else c_int, 0))) != .SUCCESS);
    var wrong_config = config;
    wrong_config.handler.rate.burst += 1;
    try std.testing.expectError(error.ConfigMismatch, carry.validate(wrong_config));
    try server.resumePaused(first_pause);
    try expectNoContent(queued_fd);
    try std.testing.expectEqual(@as(u32, 1), counted.count.load(.acquire));
    const second_pause = try server.requestPause(2);
    try server.awaitPaused(second_pause, std.Io.Clock.Timestamp.fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
    try std.testing.expectError(error.InvalidToken, server.resumePaused(first_pause));
    try std.testing.expectEqualDeep(observed, (try server.capturePaused(second_pause)).listener);
    // Gate still owns exactly the original worker; neither rollback nor a new
    // pause epoch respawns it. The borrowed sink has published the one post.
    try std.testing.expectEqual(@as(usize, 1), gate.view.inspect().spawned);
    try std.testing.expectEqual(@as(u32, 1), counted.count.load(.acquire));
}
