// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Loopback HTTP-01 challenge listener.
//!
//! Binds `127.0.0.1:<port>` and serves ACME challenge responses from a shared
//! `TokenStore` (see [acme_http01_server]) on a background thread, so the
//! blocking issuance driver (see [acme_runner]) can run concurrently while the
//! CA validates the challenge.
//!
//! Deployment (per the chosen rollout): nginx on the live box proxies
//! `/.well-known/acme-challenge/` to this loopback port — the public site keeps
//! serving everything else. This listener never binds a public interface.

const std = @import("std");
const builtin = @import("builtin");

const http01 = @import("acme_http01_server.zig");
const toml = @import("../proto/toml.zig");

const sys = std.posix.system;
const posix = std.posix;

comptime {
    if (@bitSizeOf(usize) != 64) @compileError("acme_http01_listener requires a 64-bit target");
}

pub const ListenerError = error{
    SocketUnavailable,
    BindFailed,
    ListenFailed,
    AddrLookupFailed,
    TimeoutSetupFailed,
};

/// Max request bytes read per connection (a challenge GET is tiny).
const max_request: usize = 8 * 1024;
/// Max response bytes (status line + headers + key authorization).
const max_response: usize = 4 * 1024;

/// Default TCP accept backlog for the challenge listener.
pub const default_listen_backlog: u31 = 16;
/// Default accept-poll wake interval (ms) so the loop re-checks the stop flag.
pub const default_accept_poll_ms: u32 = 250;
/// Default per-connection read timeout (seconds) guarding against slow clients.
pub const default_conn_read_timeout_sec: u32 = 5;

/// Operational tunables for the loopback HTTP-01 listener. The bind address is
/// NOT configurable: it is a security invariant that this listener only ever
/// binds 127.0.0.1 (nginx proxies the public challenge path to it).
pub const Config = struct {
    /// TCP accept backlog.
    listen_backlog: u31 = default_listen_backlog,
    /// Accept-poll wake interval in milliseconds.
    accept_poll_ms: u32 = default_accept_poll_ms,
    /// Per-connection read timeout in seconds.
    conn_read_timeout_sec: u32 = default_conn_read_timeout_sec,

    /// Overlay `[acme]` config keys onto a Config, leaving absent keys at their
    /// current value. `http01_bind_address` is intentionally NOT honored: the
    /// loopback bind is a security invariant.
    pub fn applyToml(self: *Config, doc: *const toml.Document) void {
        if (doc.getUint("acme.http01_listen_backlog")) |v| {
            if (v >= 1 and v <= std.math.maxInt(u31)) self.listen_backlog = @intCast(v);
        }
        if (doc.getString("acme.http01_accept_poll")) |s| {
            if (parseDurationMs(s)) |v| {
                if (v >= 50 and v <= 5000) self.accept_poll_ms = v;
            } else |_| {}
        }
        if (doc.getString("acme.http01_conn_read_timeout")) |s| {
            if (parseDurationMs(s)) |v| {
                if (v >= 1000 and v <= 60_000 and v % 1000 == 0) self.conn_read_timeout_sec = v / 1000;
            } else |_| {}
        }
    }
};

pub const ChallengeServer = struct {
    store: *http01.TokenStore,
    listen_fd: sys.fd_t,
    port: u16,
    thread: ?std.Thread = null,
    stop_flag: std.atomic.Value(bool) = .{ .raw = false },
    /// Per-connection read timeout (seconds); read by the accept loop.
    conn_read_timeout_sec: u32 = default_conn_read_timeout_sec,

    /// Bind `127.0.0.1:port` (use port 0 for an ephemeral port) and start
    /// listening with default tunables. No thread is running yet; call `spawn`.
    pub fn init(store: *http01.TokenStore, port: u16) ListenerError!ChallengeServer {
        return initWithConfig(store, port, .{});
    }

    /// Like `init`, but with explicit operational tunables. The bind address is
    /// always 127.0.0.1 (security invariant); only timeouts/backlog are tunable.
    /// The returned value must live at a stable address for the thread's lifetime.
    pub fn initWithConfig(store: *http01.TokenStore, port: u16, config: Config) ListenerError!ChallengeServer {
        const fd = try socketTcp();
        errdefer closeFd(fd);
        // socketTcp already reports SocketUnavailable on Windows; stop
        // analysis here so the libc-linked calls below are never instantiated.
        if (comptime builtin.os.tag == .windows) return error.SocketUnavailable;

        var yes: u32 = 1;
        _ = sys.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&yes), @sizeOf(u32));

        var addr = sys.sockaddr.in{
            .port = std.mem.nativeToBig(u16, port),
            .addr = std.mem.nativeToBig(u32, 0x7f00_0001), // 127.0.0.1 (invariant)
        };
        if (posix.errno(sys.bind(fd, @ptrCast(&addr), @sizeOf(sys.sockaddr.in))) != .SUCCESS)
            return error.BindFailed;
        if (posix.errno(sys.listen(fd, config.listen_backlog)) != .SUCCESS)
            return error.ListenFailed;
        const current_flags = sys.fcntl(fd, posix.F.GETFL, @as(if (builtin.os.tag == .linux) usize else c_int, 0));
        if (posix.errno(current_flags) != .SUCCESS) return error.ListenFailed;
        var owned_flags: posix.O = @bitCast(@as(u32, @intCast(current_flags)));
        owned_flags.NONBLOCK = true;
        const flag_arg: if (builtin.os.tag == .linux) usize else c_int = @intCast(@as(u32, @bitCast(owned_flags)));
        if (posix.errno(sys.fcntl(fd, posix.F.SETFL, flag_arg)) != .SUCCESS) return error.ListenFailed;

        // Receive timeout so a blocked accept4 wakes periodically to re-check the
        // stop flag. Closing the listener from another thread does NOT reliably
        // wake accept4, so this poll is how shutdown actually terminates.
        const poll_ms = @min(@max(config.accept_poll_ms, 1), std.math.maxInt(c_int));
        const tv = sys.timeval{
            .sec = @intCast(poll_ms / 1000),
            .usec = @intCast((poll_ms % 1000) * 1000),
        };
        const timeout_rc = sys.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(sys.timeval));
        if (posix.errno(timeout_rc) != .SUCCESS) return error.TimeoutSetupFailed;

        return .{
            .store = store,
            .listen_fd = fd,
            .port = try boundPort(fd),
            .conn_read_timeout_sec = @max(config.conn_read_timeout_sec, 1),
        };
    }

    /// Spawn the background accept loop.
    pub fn spawn(self: *ChallengeServer) std.Thread.SpawnError!void {
        self.thread = try std.Thread.spawn(.{}, acceptLoop, .{self});
    }

    /// Stop and join while the numeric listener FD still denotes this owner.
    /// Poll/read/write operations are finite and stop-aware; close follows join.
    pub fn shutdown(self: *ChallengeServer) void {
        self.stop_flag.store(true, .release);
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
        // This listener never opens on Windows (`socketTcp` refuses and the
        // portable server stays plaintext-only); gate at comptime so
        // `refAllDecls` test builds compile. Byte-identical elsewhere.
        if (comptime builtin.os.tag != .windows) {
            if (self.listen_fd >= 0) closeFd(self.listen_fd);
            self.listen_fd = -1;
        }
    }

    fn acceptLoop(self: *ChallengeServer) void {
        // Linux-only accept loop (`accept4`/`SOCK_CLOEXEC`). Gate at comptime so
        // foreign-target test builds compile; byte-identical on Linux.
        if (comptime builtin.os.tag == .linux or builtin.os.tag == .openbsd) {
            while (!self.stop_flag.load(.acquire)) {
                const rc = acceptSocket(self.listen_fd);
                switch (posix.errno(rc)) {
                    .SUCCESS => self.serveConn(@intCast(rc)),
                    .AGAIN, .INTR, .CONNABORTED => continue, // timeout/interrupt: re-check stop flag
                    else => return, // listener closed (shutdown) or fatal: exit thread
                }
            }
        }
    }

    fn serveConn(self: *ChallengeServer, fd: sys.fd_t) void {
        defer closeFd(fd);
        // Accepted sockets do not inherit the listener's timeout; cap the read so a
        // silent/slow client cannot stall the single-threaded accept loop.
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

        var resp_buf: [max_response]u8 = undefined;
        const resp = http01.handleRequest(self.store, req_buf[0..n], &resp_buf) catch return;
        writeAll(fd, resp);
    }
};

// ---------------------------------------------------------------------------
// Low-level helpers (raw linux syscalls)
// ---------------------------------------------------------------------------

// BSD accept timeout is explicit: listener SO_RCVTIMEO is configuration,
// poll bounds the wait, and nonblocking accept cannot hang after stale readiness.
fn acceptSocket(fd: posix.fd_t) if (builtin.os.tag == .linux) usize else c_int {
    var tv: sys.timeval = undefined;
    var len: posix.socklen_t = @sizeOf(@TypeOf(tv));
    const timeout = sys.getsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, @ptrCast(&tv), &len);
    if (posix.errno(timeout) != .SUCCESS or len != @sizeOf(@TypeOf(tv))) return acceptAgain();
    const millis = @max(@as(i64, 1), tv.sec * 1000 + @divTrunc(tv.usec, 1000));
    var pollfds = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.IN, .revents = 0 }};
    const rc = sys.poll(&pollfds, 1, @intCast(@min(millis, std.math.maxInt(c_int))));
    if (posix.errno(rc) != .SUCCESS or rc == 0) return acceptAgain();
    const accepted = sys.accept4(fd, null, null, posix.SOCK.CLOEXEC);
    if (posix.errno(accepted) != .SUCCESS) return accepted;
    if (comptime builtin.os.tag == .linux) return accepted;
    if (comptime builtin.os.tag != .linux) {
        // BSD may inherit listener nonblocking state. Request readers use a
        // verified SO_RCVTIMEO on a blocking accepted socket.
        const old = sys.fcntl(accepted, posix.F.GETFL, @as(c_int, 0));
        if (old >= 0) {
            var flags: posix.O = @bitCast(@as(u32, @intCast(old)));
            flags.NONBLOCK = false;
            if (sys.fcntl(accepted, posix.F.SETFL, @as(c_int, @intCast(@as(u32, @bitCast(flags))))) == 0) return accepted;
        }
        const saved = sys._errno().*;
        _ = sys.close(accepted);
        sys._errno().* = saved;
        return -1;
    }
}

fn acceptAgain() if (builtin.os.tag == .linux) usize else c_int {
    if (comptime builtin.os.tag == .linux) return @bitCast(-@as(isize, @intFromEnum(posix.E.AGAIN)));
    sys._errno().* = @intFromEnum(posix.E.AGAIN);
    return -1;
}

fn socketTcp() ListenerError!sys.fd_t {
    // Linux-only (`SOCK_CLOEXEC`); force-referenced by `refAllDecls` in the test
    // build, so gate the body at comptime. Byte-identical on Linux.
    if (comptime builtin.os.tag == .linux or builtin.os.tag == .openbsd) {
        const rc = sys.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, posix.IPPROTO.TCP);
        return switch (posix.errno(rc)) {
            .SUCCESS => @intCast(rc),
            else => error.SocketUnavailable,
        };
    } else return error.SocketUnavailable;
}

fn boundPort(fd: sys.fd_t) ListenerError!u16 {
    var storage: posix.sockaddr.storage = undefined;
    var len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
    if (posix.errno(sys.getsockname(fd, @ptrCast(&storage), &len)) != .SUCCESS)
        return error.AddrLookupFailed;
    const a: *const sys.sockaddr.in = @ptrCast(@alignCast(&storage));
    return std.mem.bigToNative(u16, a.port);
}

fn closeFd(fd: sys.fd_t) void {
    // No libc-linked close on Windows; unreachable there (see gate above).
    if (comptime builtin.os.tag == .windows) return;
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

fn parseDurationMs(text: []const u8) !u32 {
    const units = [_]struct { suffix: []const u8, scale: u32 }{
        .{ .suffix = "ms", .scale = 1 },
        .{ .suffix = "s", .scale = 1000 },
        .{ .suffix = "m", .scale = 60_000 },
    };
    for (units) |unit| {
        if (std.mem.endsWith(u8, text, unit.suffix)) {
            const digits = text[0 .. text.len - unit.suffix.len];
            const n = try std.fmt.parseInt(u32, digits, 10);
            if (n == 0 or n > std.math.maxInt(u32) / unit.scale) return error.Overflow;
            return n * unit.scale;
        }
    }
    return error.InvalidDuration;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "ChallengeServer serves a stored token over loopback" {
    if (builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var store = http01.TokenStore.init(allocator);
    defer store.deinit();
    try store.put("tok_AZ09-test", "tok_AZ09-test.thumb");

    var server = try ChallengeServer.init(&store, 0);
    try server.spawn();
    defer server.shutdown();

    // Connect a client to the ephemeral loopback port and request the token.
    const cfd = try socketTcp();
    defer closeFd(cfd);
    var addr = sys.sockaddr.in{
        .port = std.mem.nativeToBig(u16, server.port),
        .addr = std.mem.nativeToBig(u32, 0x7f00_0001),
    };
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.connect(cfd, @ptrCast(&addr), @sizeOf(sys.sockaddr.in))));

    const req = "GET /.well-known/acme-challenge/tok_AZ09-test HTTP/1.1\r\nHost: x\r\n\r\n";
    writeAll(cfd, req);

    var buf: [512]u8 = undefined;
    const rc = sys.read(cfd, &buf, buf.len);
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(rc));
    const got = buf[0..@intCast(rc)];
    try std.testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.endsWith(u8, got, "\r\n\r\ntok_AZ09-test.thumb"));
}

test "ChallengeServer returns 404 for unknown token" {
    if (builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var store = http01.TokenStore.init(allocator);
    defer store.deinit();

    var server = try ChallengeServer.init(&store, 0);
    try server.spawn();
    defer server.shutdown();

    const cfd = try socketTcp();
    defer closeFd(cfd);
    var addr = sys.sockaddr.in{
        .port = std.mem.nativeToBig(u16, server.port),
        .addr = std.mem.nativeToBig(u32, 0x7f00_0001),
    };
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.connect(cfd, @ptrCast(&addr), @sizeOf(sys.sockaddr.in))));

    writeAll(cfd, "GET /.well-known/acme-challenge/nope HTTP/1.1\r\n\r\n");
    var buf: [512]u8 = undefined;
    const rc = sys.read(cfd, &buf, buf.len);
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(rc));
    try std.testing.expect(std.mem.startsWith(u8, buf[0..@intCast(rc)], "HTTP/1.1 404 Not Found\r\n"));
}

test "Config.applyToml overlays listener tunables and skips bind address" {
    const allocator = std.testing.allocator;
    const src =
        \\[acme]
        \\http01_listen_backlog = 64
        \\http01_accept_poll = "500ms"
        \\http01_conn_read_timeout = "10s"
        \\http01_bind_address = "0.0.0.0"
    ;
    var doc = try toml.parse(allocator, src);
    defer doc.deinit(allocator);

    var cfg: Config = .{};
    cfg.applyToml(&doc);

    try std.testing.expectEqual(@as(u31, 64), cfg.listen_backlog);
    try std.testing.expectEqual(@as(u32, 500), cfg.accept_poll_ms);
    try std.testing.expectEqual(@as(u32, 10), cfg.conn_read_timeout_sec);
    // bind address is a security invariant: never read from config.
}

test "Config.applyToml leaves defaults when keys absent" {
    const allocator = std.testing.allocator;
    var doc = try toml.parse(allocator, "[server]\nname = \"mz\"\n");
    defer doc.deinit(allocator);

    var cfg: Config = .{};
    cfg.applyToml(&doc);

    try std.testing.expectEqual(default_listen_backlog, cfg.listen_backlog);
    try std.testing.expectEqual(default_accept_poll_ms, cfg.accept_poll_ms);
    try std.testing.expectEqual(default_conn_read_timeout_sec, cfg.conn_read_timeout_sec);
}

test "initWithConfig honors a custom backlog and read timeout" {
    if (builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var store = http01.TokenStore.init(allocator);
    defer store.deinit();

    var server = try ChallengeServer.initWithConfig(&store, 0, .{
        .listen_backlog = 32,
        .accept_poll_ms = 100,
        .conn_read_timeout_sec = 3,
    });
    defer server.shutdown();
    try server.spawn();

    try std.testing.expectEqual(@as(u32, 3), server.conn_read_timeout_sec);
}

test {
    std.testing.refAllDecls(@This());
}
