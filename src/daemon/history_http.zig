// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Loopback read of history the account can already see via CHATHISTORY.
//! A non-loopback bind is refused before any socket is created. The only
//! route is GET /history over TLS 1.3. This is not an admin API.

const std = @import("std");
pub const runtime_pause = @import("runtime_pause.zig");
pub const dormant_spawn_options: std.Thread.SpawnConfig = .{};
const metrics_http = @import("metrics_http.zig");
const builtin = @import("builtin");
const linux = std.os.linux;
const sys = if (builtin.os.tag == .openbsd) std.posix.system else linux;
const Socket = if (builtin.os.tag == .windows) usize else linux.fd_t;
// Pollfd element type must match `sys` above: libc's on OpenBSD,
// Linux's everywhere else (`posix.pollfd` differs from it on macOS).
// Both branches resolve on every target, so this container-level `if`
// stays valid cross-platform. Windows uses WSAPoll through the Winsock path.
const sys_pollfd = if (builtin.os.tag == .openbsd) posix.pollfd else linux.pollfd;
const runtime = @import("os_runtime.zig");
const native_network = @import("native_network.zig");
const platform = @import("../substrate/platform.zig");
const posix = std.posix;
const tls_record = @import("../crypto/tls_record.zig");
const tls_server = @import("../crypto/tls_server.zig");
const managed_ocsp = @import("ocsp_staple.zig");
const ocsp = @import("../crypto/ocsp.zig");
const native_windows_socket = @import("helix/native_windows_socket.zig");

const win = struct {
    const invalid_socket = std.math.maxInt(usize);
    const af_inet: i32 = 2;
    const af_inet6: i32 = 23;
    const sock_stream: i32 = 1;
    const ipproto_tcp: i32 = 6;
    const ipproto_ipv6: i32 = 41;
    const sol_socket: i32 = 0xffff;
    const so_type: i32 = 0x1008;
    const so_acceptconn: i32 = 0x0002;
    const so_rcvtimeo: i32 = 0x1006;
    const so_sndtimeo: i32 = 0x1005;
    const so_exclusiveaddruse: i32 = -5;
    const ipv6_v6only: i32 = 27;
    const tcp_nodelay: i32 = 1;
    const fionbio: u32 = 0x8004667e;
    const pollin: i16 = 0x0300;
    const pollout: i16 = 0x0010;
    const interrupted: i32 = 10004;
    const would_block: i32 = 10035;
    const connection_aborted: i32 = 10053;

    const SockAddr4 = extern struct {
        family: u16,
        port: u16,
        addr: u32,
        zero: [8]u8 = @splat(0),
    };
    const SockAddr6 = extern struct {
        family: u16,
        port: u16,
        flowinfo: u32 = 0,
        addr: [16]u8,
        scope_id: u32 = 0,
    };
    const PollFd = extern struct { fd: usize, events: i16, revents: i16 = 0 };
    comptime {
        if (@sizeOf(SockAddr4) != 16 or @sizeOf(SockAddr6) != 28 or @sizeOf(PollFd) != 16)
            @compileError("history HTTP Winsock ABI layout mismatch");
    }

    extern "ws2_32" fn WSAStartup(version_requested: u16, data: *anyopaque) callconv(.winapi) i32;
    extern "ws2_32" fn WSACleanup() callconv(.winapi) i32;
    extern "ws2_32" fn WSAGetLastError() callconv(.winapi) i32;
    extern "ws2_32" fn WSASocketW(family: i32, kind: i32, protocol: i32, info: ?*anyopaque, group: u32, flags: u32) callconv(.winapi) usize;
    extern "ws2_32" fn closesocket(socket: usize) callconv(.winapi) i32;
    extern "ws2_32" fn bind(socket: usize, addr: *const anyopaque, length: i32) callconv(.winapi) i32;
    extern "ws2_32" fn connect(socket: usize, addr: *const anyopaque, length: i32) callconv(.winapi) i32;
    extern "ws2_32" fn listen(socket: usize, backlog: i32) callconv(.winapi) i32;
    extern "ws2_32" fn getsockname(socket: usize, addr: *anyopaque, length: *i32) callconv(.winapi) i32;
    extern "ws2_32" fn accept(socket: usize, addr: ?*anyopaque, length: ?*i32) callconv(.winapi) usize;
    extern "ws2_32" fn ioctlsocket(socket: usize, command: u32, value: *u32) callconv(.winapi) i32;
    extern "ws2_32" fn getsockopt(socket: usize, level: i32, option: i32, value: *anyopaque, length: *i32) callconv(.winapi) i32;
    extern "ws2_32" fn setsockopt(socket: usize, level: i32, option: i32, value: *const anyopaque, length: i32) callconv(.winapi) i32;
    extern "ws2_32" fn WSAPoll(fds: [*]PollFd, count: u32, timeout_ms: i32) callconv(.winapi) i32;
    extern "ws2_32" fn recv(socket: usize, bytes: [*]u8, length: i32, flags: i32) callconv(.winapi) i32;
    extern "ws2_32" fn send(socket: usize, bytes: [*]const u8, length: i32, flags: i32) callconv(.winapi) i32;
};

pub const loopback_v4 = "127.0.0.1";
pub const loopback_v6 = "::1";

pub fn bindAllowed(addr: []const u8) bool {
    return std.mem.eql(u8, addr, loopback_v4) or std.mem.eql(u8, addr, loopback_v6);
}

/// Empty config means loopback. Any other address must itself be loopback.
pub fn listenAddr(configured: []const u8) error{PublicBind}![]const u8 {
    if (configured.len == 0) return loopback_v4;
    if (!bindAllowed(configured)) return error.PublicBind;
    return configured;
}

pub const Reader = struct {
    ptr: *anyopaque,
    readFn: *const fn (ptr: *anyopaque, account: []const u8, target: []const u8, out: []u8) error{Denied}!usize,
};

pub fn handleRequest(request: []const u8, reader: Reader, body_buf: []u8, out: []u8) []const u8 {
    const line_end = std.mem.indexOf(u8, request, "\r\n") orelse return writeResponse(400, "bad request\n", out);
    const line = request[0..line_end];
    if (!std.ascii.startsWithIgnoreCase(line, "GET ")) return writeResponse(405, "method\n", out);
    const rest = line["GET ".len..];
    const sp = std.mem.indexOfScalar(u8, rest, ' ') orelse return writeResponse(400, "bad request\n", out);
    const target_uri = rest[0..sp];
    if (!std.mem.startsWith(u8, target_uri, "/history")) return writeResponse(404, "not found\n", out);
    const qmark = std.mem.indexOfScalar(u8, target_uri, '?') orelse return writeResponse(400, "target required\n", out);
    const query = target_uri[qmark + 1 ..];
    const raw_target = queryParam(query, "target") orelse return writeResponse(400, "target required\n", out);
    var target_buf: [256]u8 = undefined;
    const target = decodeQuery(raw_target, &target_buf) orelse return writeResponse(400, "bad target\n", out);
    if (target.len == 0) return writeResponse(400, "target required\n", out);
    const auth = headerValue(request, "Authorization") orelse return writeResponse(401, "account required\n", out);
    const prefix = "Bearer ";
    if (auth.len <= prefix.len or !std.ascii.startsWithIgnoreCase(auth, prefix)) return writeResponse(401, "account required\n", out);
    const account = std.mem.trim(u8, auth[prefix.len..], " ");
    if (account.len == 0 or account.len > 64) return writeResponse(401, "account required\n", out);
    const n = reader.readFn(reader.ptr, account, target, body_buf) catch return writeResponse(403, "denied\n", out);
    return writeResponse(200, body_buf[0..n], out);
}

fn queryParam(query: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |part| {
        if (std.mem.startsWith(u8, part, name) and part.len > name.len and part[name.len] == '=') {
            return part[name.len + 1 ..];
        }
    }
    return null;
}

fn headerValue(request: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, request, '\n');
    _ = it.next();
    while (it.next()) |raw| {
        const line = std.mem.trim(u8, raw, "\r");
        if (line.len == 0) break;
        if (line.len <= name.len or line[name.len] != ':') continue;
        if (!std.ascii.eqlIgnoreCase(line[0..name.len], name)) continue;
        return std.mem.trim(u8, line[name.len + 1 ..], " \t");
    }
    return null;
}

fn decodeQuery(src: []const u8, dest: []u8) ?[]const u8 {
    var n: usize = 0;
    var i: usize = 0;
    while (i < src.len) {
        if (n >= dest.len) return null;
        if (src[i] == '%' and i + 2 < src.len) {
            const byte = std.fmt.parseInt(u8, src[i + 1 .. i + 3], 16) catch return null;
            dest[n] = byte;
            n += 1;
            i += 3;
            continue;
        }
        dest[n] = if (src[i] == '+') ' ' else src[i];
        n += 1;
        i += 1;
    }
    return dest[0..n];
}

fn writeResponse(status: u16, body: []const u8, out: []u8) []const u8 {
    const reason = switch (status) {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        else => "Error",
    };
    return std.fmt.bufPrint(out, "HTTP/1.1 {d} {s}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ status, reason, body.len, body }) catch "HTTP/1.1 500 Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
}

pub const BindError = error{
    PublicBind,
    SocketUnavailable,
    BindFailed,
    ListenFailed,
    AddrLookupFailed,
    TimeoutSetupFailed,
};

/// TLS 1.3 listener for GET /history. `open` refuses a public address before
/// it creates a socket. Call `spawn` to accept; `shutdown` joins that thread.
pub const HttpsListener = struct {
    allocator: std.mem.Allocator,
    listen_fd: Socket,
    listen_open: bool = false,
    winsock_started: bool = false,
    v6: bool = false,
    port: u16,
    thread: ?std.Thread = null,
    runtime_worker: runtime_pause.WorkerState = .{},
    stop_flag: std.atomic.Value(bool) = .{ .raw = false },
    tls_config: tls_server.Config,
    reader: Reader,
    request_deadline: i64 = 0,

    pub fn open(
        allocator: std.mem.Allocator,
        configured: []const u8,
        port: u16,
        tls_config: tls_server.Config,
        reader: Reader,
    ) BindError!HttpsListener {
        const spec = try listenAddr(configured);
        const v6 = std.mem.eql(u8, spec, loopback_v6);
        if (comptime builtin.os.tag == .windows) return openWindows(allocator, v6, port, tls_config, reader);
        const fd = if (v6) try socketTcp6() else try socketTcp4();
        errdefer closeFd(fd);

        var yes: u32 = 1;
        _ = sys.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&yes), @sizeOf(u32));
        if (v6) {
            var bytes: [16]u8 = @splat(0);
            bytes[15] = 1;
            var addr = posix.sockaddr.in6{
                .port = std.mem.nativeToBig(u16, port),
                .flowinfo = 0,
                .addr = bytes,
                .scope_id = 0,
            };
            if (posix.errno(sys.bind(fd, @ptrCast(&addr), @sizeOf(posix.sockaddr.in6))) != .SUCCESS)
                return error.BindFailed;
        } else {
            var addr = sys.sockaddr.in{
                .port = std.mem.nativeToBig(u16, port),
                .addr = std.mem.nativeToBig(u32, 0x7f00_0001),
            };
            if (posix.errno(sys.bind(fd, @ptrCast(&addr), @sizeOf(sys.sockaddr.in))) != .SUCCESS)
                return error.BindFailed;
        }
        if (posix.errno(sys.listen(fd, 16)) != .SUCCESS) return error.ListenFailed;

        runtime.setNonblocking(fd) catch return error.SocketUnavailable;
        const tv = sys.timeval{ .sec = 0, .usec = 200_000 };
        if (posix.errno(sys.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(sys.timeval))) != .SUCCESS) return error.TimeoutSetupFailed;
        return .{
            .allocator = allocator,
            .listen_fd = fd,
            .listen_open = true,
            .v6 = v6,
            .port = try boundPort(fd, v6),
            .tls_config = tls_config,
            .reader = reader,
        };
    }

    fn openWindows(allocator: std.mem.Allocator, v6: bool, port: u16, tls_config: tls_server.Config, reader: Reader) BindError!HttpsListener {
        if (comptime builtin.os.tag != .windows) return error.SocketUnavailable;
        var startup: [408]u8 align(8) = @splat(0);
        if (win.WSAStartup(0x0202, &startup) != 0) return error.SocketUnavailable;
        errdefer _ = win.WSACleanup();
        const fd = win.WSASocketW(if (v6) win.af_inet6 else win.af_inet, win.sock_stream, win.ipproto_tcp, null, 0, 1);
        if (fd == win.invalid_socket) return error.SocketUnavailable;
        errdefer closeFd(fd);
        const yes: i32 = 1;
        if (win.setsockopt(fd, win.sol_socket, win.so_exclusiveaddruse, &yes, @sizeOf(i32)) != 0)
            return error.SocketUnavailable;
        if (v6) {
            if (win.setsockopt(fd, win.ipproto_ipv6, win.ipv6_v6only, &yes, @sizeOf(i32)) != 0)
                return error.SocketUnavailable;
            var address = win.SockAddr6{ .family = @intCast(win.af_inet6), .port = std.mem.nativeToBig(u16, port), .addr = @splat(0) };
            address.addr[15] = 1;
            if (win.bind(fd, &address, @sizeOf(win.SockAddr6)) != 0) return error.BindFailed;
        } else {
            const address = win.SockAddr4{ .family = @intCast(win.af_inet), .port = std.mem.nativeToBig(u16, port), .addr = std.mem.nativeToBig(u32, 0x7f00_0001) };
            if (win.bind(fd, &address, @sizeOf(win.SockAddr4)) != 0) return error.BindFailed;
        }
        if (win.listen(fd, 16) != 0) return error.ListenFailed;
        var nonblocking: u32 = 1;
        if (win.ioctlsocket(fd, win.fionbio, &nonblocking) != 0) return error.SocketUnavailable;
        const timeout_ms: u32 = 200;
        if (win.setsockopt(fd, win.sol_socket, win.so_rcvtimeo, &timeout_ms, @sizeOf(u32)) != 0)
            return error.TimeoutSetupFailed;
        return .{
            .allocator = allocator,
            .listen_fd = fd,
            .listen_open = true,
            .winsock_started = true,
            .v6 = v6,
            .port = try boundPort(fd, v6),
            .tls_config = tls_config,
            .reader = reader,
        };
    }

    pub fn spawn(self: *HttpsListener) std.Thread.SpawnError!void {
        if (self.thread != null or self.runtime_worker.view != null) return error.SystemResources;
        self.thread = try std.Thread.spawn(.{}, acceptLoop, .{self});
    }

    pub fn shutdown(self: *HttpsListener) void {
        self.runtime_worker.requireDetached() catch @panic("managed stop requires Runtime Control join and source detach");
        self.stop_flag.store(true, .release);
        self.runtime_worker.wakeForStop();
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }
        if (self.listen_open) {
            self.listen_open = false;
            closeFd(self.listen_fd);
        }
        if (comptime builtin.os.tag == .windows) {
            if (self.winsock_started) {
                self.winsock_started = false;
                _ = win.WSACleanup();
            }
        }
    }

    pub fn prepareColdResources(self: *HttpsListener, io: std.Io) !void {
        if (self.thread != null or self.runtime_worker.view != null) return error.AlreadyStarted;
        try validateEndpoint(try observeHistoryListener(self.listen_fd, self.v6), self.v6, self.port);
        // Actual TLS constructor validation/allocation precedes worker readiness.
        var check = try tls_server.Server.init(self.allocator, self.tls_config);
        defer check.deinit();
        try self.runtime_worker.pause.bindIo(io);
    }
    pub fn validateDormantRegistration(self: *HttpsListener, control: *runtime_pause.start_gate.Control, view: *const runtime_pause.start_gate.View, slot: runtime_pause.start_gate.Slot) !void {
        try self.runtime_worker.validateRegistration(control, view, slot, .history, @intFromBool(self.v6), self, dormant_spawn_options);
    }
    pub fn prepareDormantWorker(self: *HttpsListener, control: *runtime_pause.start_gate.Control, view: *const runtime_pause.start_gate.View, slot: runtime_pause.start_gate.Slot) !void {
        try self.runtime_worker.validatePreparation(control, view, slot, .history, @intFromBool(self.v6), self, dormant_spawn_options);
        if (self.thread != null) return error.AlreadyStarted;
        try validateEndpoint(try observeHistoryListener(self.listen_fd, self.v6), self.v6, self.port);
        self.stop_flag.store(false, .release);
        try self.runtime_worker.prepare(control, view, slot, .history, @intFromBool(self.v6), HttpsListener, self, acceptLoop, dormant_spawn_options);
    }
    /// Signals this owner only. Runtime Control owns all actual joins.
    pub fn requestStopAndWake(self: *HttpsListener) void {
        self.stop_flag.store(true, .release);
        self.runtime_worker.wakeForStop();
    }
    pub fn detachAfterJoined(self: *HttpsListener) !void {
        try self.runtime_worker.detachAfterJoined();
    }
    pub fn requireParked(self: *HttpsListener) !void {
        try self.runtime_worker.requireParked();
    }
    pub fn requireActivated(self: *HttpsListener) !void {
        if (self.stop_flag.load(.acquire)) return error.Stopped;
        try self.runtime_worker.requireActivated();
    }
    pub fn requestPause(self: *HttpsListener, epoch: u64) !runtime_pause.Token {
        return self.runtime_worker.pause.request(epoch);
    }
    pub fn awaitPaused(self: *HttpsListener, token: runtime_pause.Token, deadline: std.Io.Clock.Timestamp) !void {
        try self.runtime_worker.pause.awaitPaused(token, deadline);
    }
    pub fn resumePaused(self: *HttpsListener, token: runtime_pause.Token) !void {
        try self.runtime_worker.pause.resumePaused(token);
    }
    pub fn capturePaused(self: *HttpsListener, token: runtime_pause.Token) !Snapshot {
        if (self.thread == null and self.runtime_worker.view == null) return error.NotRunning;
        try self.runtime_worker.pause.requirePaused(token);
        return self.captureCut(.paused);
    }
    pub fn captureUnstarted(self: *HttpsListener) !Snapshot {
        if (self.thread != null or self.runtime_worker.view != null) return error.NotQuiescent;
        return self.captureCut(.unstarted);
    }
    fn captureCut(self: *HttpsListener, execution: Execution) !Snapshot {
        // Shared anti-replay state requires its own source-owned carried graph;
        // a pointer or an empty replacement cannot prove 0-RTT continuity.
        if (self.tls_config.max_early_data_size != 0) return error.ActiveTlsContinuityUnsupported;
        const observed = try observeHistoryListener(self.listen_fd, self.v6);
        try validateEndpoint(observed, self.v6, self.port);
        return .{ .listener = observed, .tls_digest = try tlsConfigDigest(self.tls_config), .execution = execution };
    }
    /// Consumes received FD on entry; validation is read-only/close-only.
    /// `tls_config` and Reader are real whole-owner reconstructed references,
    /// never pointers decoded from this row. Server's reader authorization and
    /// TLS material custody must remain live through the final worker join.
    pub fn initInherited(allocator: std.mem.Allocator, configured: []const u8, fd: Socket, carry: *const Snapshot, tls_config: tls_server.Config, reader: Reader) !HttpsListener {
        errdefer closeFd(fd);
        // A raw SOCKET value does not prove custody across Windows processes.
        // Cross-process duplication must arrive with its authenticated manifest.
        if (comptime builtin.os.tag == .windows) return error.Unsupported;
        const spec = try listenAddr(configured);
        const v6 = std.mem.eql(u8, spec, loopback_v6);
        try carry.validate(v6, tls_config);
        const observed = try observeHistoryListener(fd, v6);
        if (!std.meta.eql(observed, carry.listener)) return error.ListenerMismatch;
        return .{ .allocator = allocator, .listen_fd = fd, .listen_open = true, .v6 = v6, .port = observed.port, .tls_config = tls_config, .reader = reader };
    }

    /// Import a one-use socket transfer delivered by the authenticated Helix
    /// control path, which must bind it to `carry`. The imported SOCKET number
    /// changes, so validate every other captured listener field and TLS policy.
    pub fn initTransferred(allocator: std.mem.Allocator, configured: []const u8, transfer: *native_windows_socket.Transfer, carry: *const Snapshot, tls_config: tls_server.Config, reader: Reader) !HttpsListener {
        if (comptime builtin.os.tag != .windows) return error.Unsupported;
        var startup: [408]u8 align(8) = @splat(0);
        if (win.WSAStartup(0x0202, &startup) != 0) return error.SocketUnavailable;
        errdefer _ = win.WSACleanup();
        const fd = try transfer.import();
        errdefer closeFd(fd);
        const spec = try listenAddr(configured);
        const v6 = std.mem.eql(u8, spec, loopback_v6);
        try carry.validate(v6, tls_config);
        const observed = try observeHistoryListener(fd, v6);
        if (!transferredListenerMatches(carry.listener, observed)) return error.ListenerMismatch;
        return .{
            .allocator = allocator,
            .listen_fd = fd,
            .listen_open = true,
            .winsock_started = true,
            .v6 = v6,
            .port = observed.port,
            .tls_config = tls_config,
            .reader = reader,
        };
    }

    fn acceptLoop(self: *HttpsListener) void {
        self.runtime_worker.markEntered();
        defer self.runtime_worker.markExited();
        if (comptime builtin.os.tag == .windows) return self.acceptLoopWindows();
        while (!self.stop_flag.load(.acquire)) {
            self.runtime_worker.pause.boundary();
            if (self.stop_flag.load(.acquire)) break;
            {
                var polls = [_]sys_pollfd{.{ .fd = self.listen_fd, .events = posix.POLL.IN, .revents = 0 }};
                const ready = sys.poll(&polls, 1, 50);
                if (posix.errno(ready) == .INTR) continue;
                if (posix.errno(ready) != .SUCCESS) return;
                if (ready == 0) continue;
                if ((polls[0].revents & posix.POLL.IN) == 0) return;
                if (self.stop_flag.load(.acquire)) return;
            }
            const rc = sys.accept4(self.listen_fd, null, null, posix.SOCK.CLOEXEC);
            switch (posix.errno(rc)) {
                .SUCCESS => self.serveConn(@intCast(rc)),
                .AGAIN, .INTR, .CONNABORTED => continue,
                else => return,
            }
        }
    }

    fn acceptLoopWindows(self: *HttpsListener) void {
        if (comptime builtin.os.tag != .windows) return;
        while (!self.stop_flag.load(.acquire)) {
            self.runtime_worker.pause.boundary();
            if (self.stop_flag.load(.acquire)) break;
            const ready = pollWindows(self.listen_fd, false, 50) orelse return;
            if (!ready or self.stop_flag.load(.acquire)) continue;
            const fd = win.accept(self.listen_fd, null, null);
            if (fd == win.invalid_socket) {
                switch (win.WSAGetLastError()) {
                    win.interrupted, win.would_block, win.connection_aborted => continue,
                    else => return,
                }
            }
            var nonblocking: u32 = 1;
            if (win.ioctlsocket(fd, win.fionbio, &nonblocking) != 0) {
                closeFd(fd);
                return;
            }
            self.serveConn(fd);
        }
    }

    fn serveConn(self: *HttpsListener, fd: Socket) void {
        defer closeFd(fd);
        const on: u32 = 1;
        if (comptime builtin.os.tag == .windows) {
            _ = win.setsockopt(fd, win.ipproto_tcp, win.tcp_nodelay, &on, @sizeOf(u32));
            const timeout_ms: u32 = 5000;
            if (win.setsockopt(fd, win.sol_socket, win.so_rcvtimeo, &timeout_ms, @sizeOf(u32)) != 0 or
                win.setsockopt(fd, win.sol_socket, win.so_sndtimeo, &timeout_ms, @sizeOf(u32)) != 0) return;
        } else {
            _ = sys.setsockopt(fd, sys.IPPROTO.TCP, if (comptime builtin.os.tag == .openbsd) @as(u32, 1) else linux.TCP.NODELAY, std.mem.asBytes(&on), @sizeOf(u32));
            // This is a new accepted FD, never the inherited shared listener.
            native_network.setBlocking(fd) catch return;
            native_network.setTimeout(fd, 5000) catch return;
        }
        self.request_deadline = platform.monotonicMillis() + 5000;

        var tls_config = self.tls_config;
        if (tls_config.ocsp_staple.len != 0 and !managed_ocsp.stapleServableForChain(
            tls_config.ocsp_staple,
            tls_config.cert_chain,
            @divFloor(platform.realtimeMillis(), 1000),
            ocsp.default_staple_skew_seconds,
        )) tls_config.ocsp_staple = &.{};
        var tls = tls_server.Server.init(self.allocator, tls_config) catch return;
        defer tls.deinit();
        var raw: std.ArrayList(u8) = .empty;
        defer raw.deinit(self.allocator);

        var flights: usize = 0;
        while (!tls.handshakeDone()) {
            flights += 1;
            if (flights > 32) return;
            const rec = self.readRecord(fd, &raw) catch return;
            defer self.allocator.free(rec);
            switch (tls.feed(rec) catch return) {
                .need_more => {},
                .bytes_to_send => |b| {
                    defer self.allocator.free(b);
                    if (!self.writeConn(fd, b)) return;
                },
            }
        }
        const pending = tls.takePendingSend() catch return;
        if (pending) |extra| {
            defer self.allocator.free(extra);
            if (!self.writeConn(fd, extra)) return;
        }

        var plain: std.ArrayList(u8) = .empty;
        defer plain.deinit(self.allocator);
        var apps: usize = 0;
        while (std.mem.indexOf(u8, plain.items, "\r\n\r\n") == null) {
            apps += 1;
            if (apps > 8 or plain.items.len > 8192) return;
            const rec = self.readRecord(fd, &raw) catch return;
            defer self.allocator.free(rec);
            const pt = tls.decrypt(rec) catch return;
            defer self.allocator.free(pt);
            plain.appendSlice(self.allocator, pt) catch return;
        }

        var body: [4096]u8 = undefined;
        var out: [8192]u8 = undefined;
        if (self.stop_flag.load(.acquire) or platform.monotonicMillis() >= self.request_deadline) return;
        const resp = handleRequest(plain.items, self.reader, &body, &out);
        const sealed = tls.encrypt(resp) catch return;
        defer self.allocator.free(sealed);
        _ = self.writeConn(fd, sealed);
    }

    fn writeConn(self: *HttpsListener, fd: Socket, bytes: []const u8) bool {
        if (comptime builtin.os.tag == .windows) {
            var offset: usize = 0;
            while (offset < bytes.len) {
                const remaining = self.request_deadline - platform.monotonicMillis();
                if (self.stop_flag.load(.acquire) or remaining <= 0) return false;
                if (!(pollWindows(fd, true, @intCast(@min(remaining, 50))) orelse return false)) continue;
                const n = win.send(fd, bytes[offset..].ptr, @intCast(@min(bytes.len - offset, std.math.maxInt(i32))), 0);
                if (n > 0) {
                    offset += @intCast(n);
                } else if (n == 0) {
                    return false;
                } else switch (win.WSAGetLastError()) {
                    win.interrupted, win.would_block => continue,
                    else => return false,
                }
            }
            return true;
        }
        var offset: usize = 0;
        while (offset < bytes.len) {
            const remaining = self.request_deadline - platform.monotonicMillis();
            if (self.stop_flag.load(.acquire) or remaining <= 0) return false;
            const rc = sys.sendto(fd, bytes[offset..].ptr, bytes.len - offset, posix.MSG.DONTWAIT | posix.MSG.NOSIGNAL, null, 0);
            switch (posix.errno(rc)) {
                .SUCCESS => {
                    if (rc == 0) return false;
                    offset += @intCast(rc);
                },
                .INTR => continue,
                .AGAIN => {
                    var polls = [_]sys_pollfd{.{ .fd = fd, .events = posix.POLL.OUT, .revents = 0 }};
                    const ready = sys.poll(&polls, 1, @intCast(@min(remaining, 50)));
                    if (posix.errno(ready) == .INTR) continue;
                    if (posix.errno(ready) != .SUCCESS or polls[0].revents & (posix.POLL.ERR | posix.POLL.HUP | posix.POLL.NVAL) != 0) return false;
                },
                else => return false,
            }
        }
        return true;
    }

    fn readRecord(self: *HttpsListener, fd: Socket, raw: *std.ArrayList(u8)) ![]u8 {
        var scratch: [4096]u8 = undefined;
        while (true) {
            if (self.stop_flag.load(.acquire) or platform.monotonicMillis() >= self.request_deadline) return error.Closed;
            if (try framedRecordLen(raw.items)) |n| {
                const rec = try self.allocator.dupe(u8, raw.items[0..n]);
                dropPrefix(raw, n);
                return rec;
            }
            if (raw.items.len > 64 * 1024) return error.Closed;
            if (comptime builtin.os.tag == .windows) {
                if (!(pollWindows(fd, false, 50) orelse return error.Closed)) continue;
                const received = win.recv(fd, &scratch, @intCast(scratch.len), 0);
                if (received > 0) {
                    try raw.appendSlice(self.allocator, scratch[0..@intCast(received)]);
                    continue;
                }
                if (received == 0) return error.Closed;
                switch (win.WSAGetLastError()) {
                    win.interrupted, win.would_block => continue,
                    else => return error.Closed,
                }
            }
            const rc = blk: {
                if (self.stop_flag.load(.acquire) or platform.monotonicMillis() >= self.request_deadline) return error.Closed;
                var polls = [_]sys_pollfd{.{ .fd = fd, .events = posix.POLL.IN, .revents = 0 }};
                const ready = sys.poll(&polls, 1, 50);
                if (posix.errno(ready) == .INTR) continue;
                if (posix.errno(ready) != .SUCCESS) return error.Closed;
                if (ready == 0) continue;
                if ((polls[0].revents & posix.POLL.IN) == 0) return error.Closed;
                break :blk sys.recvfrom(fd, &scratch, scratch.len, posix.MSG.DONTWAIT, null, null);
            };
            switch (posix.errno(rc)) {
                .SUCCESS => {
                    const n: usize = @intCast(rc);
                    if (n == 0) return error.Closed;
                    try raw.appendSlice(self.allocator, scratch[0..n]);
                },
                .INTR, .AGAIN => continue,
                else => return error.Closed,
            }
        }
    }
};

fn framedRecordLen(buf: []const u8) error{Oversized}!?usize {
    if (buf.len < tls_record.record_header_len) return null;
    const body = std.mem.readInt(u16, buf[3..5], .big);
    if (body > tls_record.max_ciphertext_len) return error.Oversized;
    const total = tls_record.record_header_len + @as(usize, body);
    if (buf.len < total) return null;
    return total;
}

fn dropPrefix(list: *std.ArrayList(u8), n: usize) void {
    const rest = list.items.len - n;
    std.mem.copyForwards(u8, list.items[0..rest], list.items[n..]);
    list.shrinkRetainingCapacity(rest);
}

/// A bounded readiness probe; no Winsock call may hold the worker beyond its
/// shutdown or per-request deadline. The socket remains nonblocking throughout.
fn pollWindows(fd: Socket, writable: bool, timeout_ms: u32) ?bool {
    if (comptime builtin.os.tag != .windows) return null;
    const event = if (writable) win.pollout else win.pollin;
    var polls = [_]win.PollFd{.{ .fd = fd, .events = event }};
    const rc = win.WSAPoll(&polls, 1, @intCast(@min(timeout_ms, std.math.maxInt(i32))));
    if (rc < 0) return null;
    if (rc == 0) return false;
    if (polls[0].revents & event == 0) return null;
    return true;
}

fn socketTcp4() BindError!Socket {
    const rc = sys.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, sys.IPPROTO.TCP);
    return switch (posix.errno(rc)) {
        .SUCCESS => @intCast(rc),
        else => error.SocketUnavailable,
    };
}

fn socketTcp6() BindError!Socket {
    const rc = sys.socket(posix.AF.INET6, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, sys.IPPROTO.TCP);
    return switch (posix.errno(rc)) {
        .SUCCESS => @intCast(rc),
        else => error.SocketUnavailable,
    };
}

fn boundPort(fd: Socket, v6: bool) BindError!u16 {
    if (comptime builtin.os.tag == .windows) {
        if (v6) {
            var address: win.SockAddr6 = undefined;
            var len: i32 = @sizeOf(win.SockAddr6);
            if (win.getsockname(fd, &address, &len) != 0 or len != @sizeOf(win.SockAddr6) or address.family != @as(u16, @intCast(win.af_inet6)))
                return error.AddrLookupFailed;
            return std.mem.bigToNative(u16, address.port);
        }
        var address: win.SockAddr4 = undefined;
        var len: i32 = @sizeOf(win.SockAddr4);
        if (win.getsockname(fd, &address, &len) != 0 or len != @sizeOf(win.SockAddr4) or address.family != @as(u16, @intCast(win.af_inet)))
            return error.AddrLookupFailed;
        return std.mem.bigToNative(u16, address.port);
    }
    if (v6) {
        var storage: posix.sockaddr.in6 = undefined;
        var slen: posix.socklen_t = @sizeOf(posix.sockaddr.in6);
        if (posix.errno(sys.getsockname(fd, @ptrCast(&storage), &slen)) != .SUCCESS)
            return error.AddrLookupFailed;
        return std.mem.bigToNative(u16, storage.port);
    }
    var storage: posix.sockaddr.storage = undefined;
    var slen: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
    if (posix.errno(sys.getsockname(fd, @ptrCast(&storage), &slen)) != .SUCCESS)
        return error.AddrLookupFailed;
    const a: *const sys.sockaddr.in = @ptrCast(@alignCast(&storage));
    return std.mem.bigToNative(u16, a.port);
}

fn closeFd(fd: Socket) void {
    // Ownership is one reference. shutdown would mutate an inherited shared
    // listener and destroy the predecessor's serving/backlog on rollback.
    if (comptime builtin.os.tag == .windows) {
        if (fd != win.invalid_socket) _ = win.closesocket(fd);
    } else {
        _ = sys.close(fd);
    }
}

fn writeAll(fd: Socket, bytes: []const u8) bool {
    if (comptime builtin.os.tag == .windows) {
        var offset: usize = 0;
        while (offset < bytes.len) {
            const n = win.send(fd, bytes[offset..].ptr, @intCast(@min(bytes.len - offset, std.math.maxInt(i32))), 0);
            if (n <= 0) return false;
            offset += @intCast(n);
        }
        return true;
    }
    if (comptime builtin.os.tag == .openbsd) {
        native_network.writeAll(fd, bytes) catch return false;
        return true;
    }
    var off: usize = 0;
    while (off < bytes.len) {
        const rc = sys.write(fd, bytes[off..].ptr, bytes.len - off);
        if (posix.errno(rc) != .SUCCESS) return false;
        const n: usize = @intCast(rc);
        if (n == 0) return false;
        off += n;
    }
    return true;
}

test "GAP-P12 loopback is the only history bind and other paths are not an admin API" {
    try std.testing.expect(bindAllowed("127.0.0.1"));
    try std.testing.expect(bindAllowed("::1"));
    try std.testing.expectError(error.PublicBind, listenAddr("0.0.0.0"));
    const addr = try listenAddr("");
    try std.testing.expectEqualStrings("127.0.0.1", addr);

    const reader = Reader{ .ptr = undefined, .readFn = refuseAll };
    var body: [64]u8 = undefined;
    var out: [512]u8 = undefined;
    const missing = handleRequest("GET /admin HTTP/1.1\r\n\r\n", reader, &body, &out);
    try std.testing.expect(std.mem.indexOf(u8, missing, " 404 ") != null);
    const posted = handleRequest("POST /history?target=%23room HTTP/1.1\r\nAuthorization: Bearer member\r\n\r\n", reader, &body, &out);
    try std.testing.expect(std.mem.indexOf(u8, posted, " 405 ") != null);
}

fn refuseAll(_: *anyopaque, _: []const u8, _: []const u8, _: []u8) error{Denied}!usize {
    return error.Denied;
}

test "GAP-P12 a public history bind is refused and loopback sockets listen" {
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .openbsd and builtin.os.tag != .windows) return error.SkipZigTest;
    const empty: []const []const u8 = &.{};
    const reader = Reader{ .ptr = undefined, .readFn = refuseAll };
    const cfg = tls_server.Config{ .cert_chain = empty };
    try std.testing.expectError(error.PublicBind, HttpsListener.open(std.testing.allocator, "0.0.0.0", 0, cfg, reader));
    var v4 = try HttpsListener.open(std.testing.allocator, "", 0, cfg, reader);
    defer v4.shutdown();
    try std.testing.expect(v4.port != 0);
    var v6 = try HttpsListener.open(std.testing.allocator, "::1", 0, cfg, reader);
    defer v6.shutdown();
    try std.testing.expect(v6.port != 0);
}

const NativeHistoryFixture = struct {
    certificate: [1024]u8 = undefined,
    chain: [1][]const u8 = undefined,
    key: std.crypto.sign.Ed25519.KeyPair = undefined,
    calls: std.atomic.Value(usize) = .init(0),

    fn init(self: *NativeHistoryFixture) !void {
        self.key = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x12)));
        self.chain[0] = try @import("../proto/x509_selfsign.zig").buildSelfSigned(&self.certificate, .{
            .common_name = "history.test",
            .not_before = 1_704_067_200,
            .not_after = 4_102_444_800,
            .serial = &.{0x12},
            .key_pair = self.key,
            .dns_names = &.{"history.test"},
            .is_ca = true,
        });
    }

    fn open(self: *NativeHistoryFixture, host: []const u8) !HttpsListener {
        return HttpsListener.open(std.testing.allocator, host, 0, .{
            .cert_chain = &self.chain,
            .signing_key = self.key,
        }, .{ .ptr = self, .readFn = read });
    }

    fn read(ptr: *anyopaque, account: []const u8, target: []const u8, out: []u8) error{Denied}!usize {
        const self: *NativeHistoryFixture = @ptrCast(@alignCast(ptr));
        _ = self.calls.fetchAdd(1, .release);
        if (!std.mem.eql(u8, account, "member") or !std.mem.eql(u8, target, "#room")) return error.Denied;
        const body = "visible history line\n";
        @memcpy(out[0..body.len], body);
        return body.len;
    }
};

fn connectWindowsHistory(host: []const u8, port: u16) !Socket {
    if (comptime builtin.os.tag != .windows) return error.SocketUnavailable;
    const v6 = std.mem.eql(u8, host, loopback_v6);
    if (!v6 and !std.mem.eql(u8, host, loopback_v4)) return error.InvalidAddress;
    var startup: [408]u8 align(8) = @splat(0);
    if (win.WSAStartup(0x0202, &startup) != 0) return error.SocketUnavailable;
    errdefer _ = win.WSACleanup();
    const fd = win.WSASocketW(if (v6) win.af_inet6 else win.af_inet, win.sock_stream, win.ipproto_tcp, null, 0, 1);
    if (fd == win.invalid_socket) return error.SocketUnavailable;
    errdefer closeFd(fd);
    const timeout_ms: u32 = 1500;
    if (win.setsockopt(fd, win.sol_socket, win.so_rcvtimeo, &timeout_ms, @sizeOf(u32)) != 0 or
        win.setsockopt(fd, win.sol_socket, win.so_sndtimeo, &timeout_ms, @sizeOf(u32)) != 0)
        return error.SocketUnavailable;
    if (v6) {
        var address = win.SockAddr6{ .family = @intCast(win.af_inet6), .port = std.mem.nativeToBig(u16, port), .addr = @splat(0) };
        address.addr[15] = 1;
        if (win.connect(fd, &address, @sizeOf(win.SockAddr6)) != 0) return error.ConnectFailed;
    } else {
        const address = win.SockAddr4{ .family = @intCast(win.af_inet), .port = std.mem.nativeToBig(u16, port), .addr = std.mem.nativeToBig(u32, 0x7f00_0001) };
        if (win.connect(fd, &address, @sizeOf(win.SockAddr4)) != 0) return error.ConnectFailed;
    }
    return fd;
}

fn clientWrite(fd: Socket, bytes: []const u8) !void {
    if (comptime builtin.os.tag == .windows) {
        if (!writeAll(fd, bytes)) return error.ConnectionClosed;
    } else try native_network.writeAll(fd, bytes);
}

fn clientRead(fd: Socket, bytes: []u8) !usize {
    if (comptime builtin.os.tag == .windows) {
        const n = win.recv(fd, bytes.ptr, @intCast(@min(bytes.len, std.math.maxInt(i32))), 0);
        if (n <= 0) return error.ConnectionClosed;
        return @intCast(n);
    }
    return native_network.readSome(fd, bytes);
}

const NativeHistoryClient = struct {
    fd: Socket,
    tls: @import("../crypto/tls_client.zig").Client,
    winsock_started: bool = false,

    fn connect(host: []const u8, port: u16, chain: []const []const u8) !NativeHistoryClient {
        const fd = if (comptime builtin.os.tag == .windows)
            try connectWindowsHistory(host, port)
        else blk: {
            const address = try std.Io.net.IpAddress.parse(host, port);
            break :blk try native_network.connect(address, 1500);
        };
        errdefer {
            closeFd(fd);
            if (comptime builtin.os.tag == .windows) _ = win.WSACleanup();
        }
        var tls = try @import("../crypto/tls_client.zig").Client.init(std.testing.allocator, .{
            .server_name = "history.test",
            .trust_anchors = chain,
        });
        errdefer tls.deinit();
        const hello = try tls.start();
        defer std.testing.allocator.free(hello);
        try clientWrite(fd, hello);
        var scratch: [8192]u8 = undefined;
        for (0..32) |_| {
            if (tls.handshakeDone()) return .{ .fd = fd, .tls = tls, .winsock_started = builtin.os.tag == .windows };
            const n = try clientRead(fd, &scratch);
            switch (try tls.feed(scratch[0..n])) {
                .need_more => {},
                .bytes_to_send => |flight| {
                    defer std.testing.allocator.free(flight);
                    try clientWrite(fd, flight);
                },
            }
        }
        return error.TestUnexpectedResult;
    }

    fn deinit(self: *NativeHistoryClient) void {
        self.tls.deinit();
        closeFd(self.fd);
        if (comptime builtin.os.tag == .windows) {
            if (self.winsock_started) _ = win.WSACleanup();
        }
    }

    fn get(self: *NativeHistoryClient, account: []const u8, out: []u8) ![]const u8 {
        var request: [256]u8 = undefined;
        const text = try std.fmt.bufPrint(&request, "GET /history?target=%23room HTTP/1.1\r\nHost: history.test\r\nAuthorization: Bearer {s}\r\n\r\n", .{account});
        const sealed = try self.tls.encrypt(text);
        defer std.testing.allocator.free(sealed);
        try clientWrite(self.fd, sealed);
        var raw: std.ArrayList(u8) = .empty;
        defer raw.deinit(std.testing.allocator);
        var used: usize = 0;
        var scratch: [8192]u8 = undefined;
        for (0..32) |_| {
            const n = try clientRead(self.fd, &scratch);
            try raw.appendSlice(std.testing.allocator, scratch[0..n]);
            while (try framedRecordLen(raw.items)) |length| {
                switch (try self.tls.decryptApp(raw.items[0..length])) {
                    .control => {},
                    .application_data => |plaintext| {
                        defer std.testing.allocator.free(plaintext);
                        if (plaintext.len > out.len - used) return error.TestUnexpectedResult;
                        @memcpy(out[used..][0..plaintext.len], plaintext);
                        used += plaintext.len;
                    },
                }
                dropPrefix(&raw, length);
            }
            if (std.mem.indexOf(u8, out[0..used], "\r\n\r\n")) |header_end| {
                const prefix = "Content-Length: ";
                const start = (std.mem.indexOf(u8, out[0..header_end], prefix) orelse return error.TestUnexpectedResult) + prefix.len;
                const end = start + (std.mem.indexOf(u8, out[start..header_end], "\r\n") orelse header_end - start);
                const body_length = try std.fmt.parseInt(usize, out[start..end], 10);
                if (used == header_end + 4 + body_length) return out[0..used];
            }
        }
        return error.TestUnexpectedResult;
    }
};

test "history native HTTPS: real IPv4 and IPv6 TLS GET returns authorized body and denies outsider" {
    if (comptime builtin.os.tag != .openbsd and builtin.os.tag != .windows) return error.SkipZigTest;
    for ([_][]const u8{ loopback_v4, loopback_v6 }) |host| {
        var fixture: NativeHistoryFixture = .{};
        try fixture.init();
        var listener = try fixture.open(host);
        defer listener.shutdown();
        try listener.spawn();
        var out: [2048]u8 = undefined;
        {
            var client = try NativeHistoryClient.connect(host, listener.port, &fixture.chain);
            defer client.deinit();
            const response = try client.get("member", &out);
            try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 200 OK\r\n"));
            try std.testing.expect(std.mem.endsWith(u8, response, "\r\n\r\nvisible history line\n"));
        }
        {
            var client = try NativeHistoryClient.connect(host, listener.port, &fixture.chain);
            defer client.deinit();
            const response = try client.get("outsider", &out);
            try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 403 Forbidden\r\n"));
            try std.testing.expect(std.mem.indexOf(u8, response, "visible history line") == null);
        }
        try std.testing.expectEqual(@as(usize, 2), fixture.calls.load(.acquire));
    }
}

fn nativeHistoryDribble(fd: i32, bytes: []const u8, sent: *std.atomic.Value(usize), stop: *std.atomic.Value(bool)) void {
    for (bytes, 0..) |_, offset| {
        if (stop.load(.acquire)) return;
        const rc = sys.send(fd, bytes[offset..].ptr, 1, posix.MSG.NOSIGNAL | posix.MSG.DONTWAIT);
        if (posix.errno(rc) != .SUCCESS or rc != 1) return;
        sent.store(offset + 1, .release);
        runtime.sleepMillis(20);
    }
}

test "history native HTTPS: accepted stalled and dribbling TLS clients cannot hold shutdown" {
    if (comptime builtin.os.tag != .openbsd) return;
    for ([_]bool{ false, true }) |dribble| {
        var fixture: NativeHistoryFixture = .{};
        try fixture.init();
        var listener = try fixture.open(loopback_v4);
        defer listener.shutdown();
        try listener.spawn();
        // Receiving the verified server flight proves this peer was accepted.
        var client = try NativeHistoryClient.connect(loopback_v4, listener.port, &fixture.chain);
        defer client.deinit();
        const sealed = try client.tls.encrypt("GET /history?target=%23room HTTP/1.1\r\nAuthorization: Bearer member\r\n\r\n");
        defer std.testing.allocator.free(sealed);
        var sent: std.atomic.Value(usize) = .init(0);
        var stop: std.atomic.Value(bool) = .init(false);
        var thread: ?std.Thread = null;
        defer {
            stop.store(true, .release);
            if (thread) |t| t.join();
        }
        if (dribble) {
            thread = try std.Thread.spawn(.{}, nativeHistoryDribble, .{ client.fd, sealed, &sent, &stop });
            const deadline = platform.monotonicMillis() + 1000;
            while (sent.load(.acquire) < 3 and platform.monotonicMillis() < deadline) runtime.sleepMillis(5);
            try std.testing.expect(sent.load(.acquire) >= 3);
        }
        const before = platform.monotonicMillis();
        listener.shutdown();
        try std.testing.expect(platform.monotonicMillis() - before < 1000);
        try std.testing.expectEqual(@as(usize, 0), fixture.calls.load(.acquire));
        stop.store(true, .release);
        if (thread) |t| {
            t.join();
            thread = null;
        }
        // Joining the listener closes its accepted socket, but peer-side FIN
        // delivery can lag that close. Require EOF/reset within a fixed bound;
        // a response byte is still an immediate failure.
        const close_deadline = platform.monotonicMillis() + 1000;
        while (true) {
            var byte: [1]u8 = undefined;
            const rc = sys.recv(client.fd, &byte, 1, posix.MSG.DONTWAIT);
            switch (posix.errno(rc)) {
                .SUCCESS => {
                    try std.testing.expectEqual(@as(isize, 0), rc);
                    break;
                },
                .CONNRESET => break,
                .AGAIN, .INTR => {
                    try std.testing.expect(platform.monotonicMillis() < close_deadline);
                    runtime.sleepMillis(5);
                },
                else => return error.TestUnexpectedResult,
            }
        }
    }
}

pub const Execution = enum(u8) { unstarted = 0, paused = 1 };
pub const Snapshot = struct {
    listener: metrics_http.ListenerObservation,
    tls_digest: [32]u8,
    execution: Execution,
    pub fn validate(self: *const Snapshot, v6: bool, config: tls_server.Config) !void {
        if (config.max_early_data_size != 0) return error.ActiveTlsContinuityUnsupported;
        try validateEndpoint(self.listener, v6, self.listener.port);
        if (!std.mem.eql(u8, &self.tls_digest, &try tlsConfigDigest(config))) return error.ConfigMismatch;
    }
};

fn observeHistoryListener(fd: Socket, v6: bool) !metrics_http.ListenerObservation {
    if (comptime builtin.os.tag != .windows) return metrics_http.observeListener(fd);
    if (fd == win.invalid_socket) return error.InvalidListener;
    var kind: i32 = 0;
    var len: i32 = @sizeOf(i32);
    if (win.getsockopt(fd, win.sol_socket, win.so_type, &kind, &len) != 0 or len != @sizeOf(i32) or kind != win.sock_stream)
        return error.InvalidListener;
    var accepting: i32 = 0;
    len = @sizeOf(i32);
    if (win.getsockopt(fd, win.sol_socket, win.so_acceptconn, &accepting, &len) != 0 or len != @sizeOf(i32) or accepting == 0)
        return error.InvalidListener;
    var timeout_ms: u32 = 0;
    len = @sizeOf(u32);
    if (win.getsockopt(fd, win.sol_socket, win.so_rcvtimeo, &timeout_ms, &len) != 0 or len != @sizeOf(u32) or timeout_ms != 200)
        return error.InvalidListener;
    var address: [16]u8 = @splat(0);
    var port: u16 = 0;
    var family: u16 = 0;
    var scope: u32 = 0;
    var flow: u32 = 0;
    if (v6) {
        var socket_addr: win.SockAddr6 = undefined;
        len = @sizeOf(win.SockAddr6);
        if (win.getsockname(fd, &socket_addr, &len) != 0 or len != @sizeOf(win.SockAddr6)) return error.InvalidListener;
        family = socket_addr.family;
        port = std.mem.bigToNative(u16, socket_addr.port);
        address = socket_addr.addr;
        scope = socket_addr.scope_id;
        flow = socket_addr.flowinfo;
    } else {
        var socket_addr: win.SockAddr4 = undefined;
        len = @sizeOf(win.SockAddr4);
        if (win.getsockname(fd, &socket_addr, &len) != 0 or len != @sizeOf(win.SockAddr4)) return error.InvalidListener;
        family = socket_addr.family;
        port = std.mem.bigToNative(u16, socket_addr.port);
        std.mem.writeInt(u32, address[0..4], std.mem.bigToNative(u32, socket_addr.addr), .big);
    }
    // Same-process identity only. A transferred duplicate gets a new SOCKET
    // number; the authenticated transfer supplies cross-process custody.
    return .{
        .device = 0,
        .inode = fd,
        .family = family,
        .address = address,
        .port = port,
        .scope_id = scope,
        .flow_info = flow,
        .recv_timeout_us = @as(u64, timeout_ms) * 1000,
    };
}

fn transferredListenerMatches(captured: metrics_http.ListenerObservation, observed: metrics_http.ListenerObservation) bool {
    if (comptime builtin.os.tag != .windows) return false;
    var canonical = observed;
    canonical.inode = captured.inode;
    return captured.device == 0 and captured.inode != @as(u64, win.invalid_socket) and std.meta.eql(captured, canonical);
}

test "history native Windows shutdown bounds a connected idle TLS client" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var fixture: NativeHistoryFixture = .{};
    try fixture.init();
    var listener = try fixture.open(loopback_v4);
    defer listener.shutdown();
    try listener.spawn();
    var client = try NativeHistoryClient.connect(loopback_v4, listener.port, &fixture.chain);
    defer client.deinit();
    const before = platform.monotonicMillis();
    listener.shutdown();
    try std.testing.expect(platform.monotonicMillis() - before < 1000);
    try std.testing.expectEqual(@as(usize, 0), fixture.calls.load(.acquire));
}

test "history native Windows capture checks loopback TLS and refuses raw inherited socket" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var fixture: NativeHistoryFixture = .{};
    try fixture.init();
    var listener = try fixture.open(loopback_v6);
    defer listener.shutdown();
    const snap = try listener.captureUnstarted();
    try snap.validate(true, listener.tls_config);
    var changed = listener.tls_config;
    changed.receive_record_size_limit -= 1;
    try std.testing.expectError(error.ConfigMismatch, snap.validate(true, changed));
    changed = listener.tls_config;
    changed.max_early_data_size = 32;
    try std.testing.expectError(error.ActiveTlsContinuityUnsupported, snap.validate(true, changed));
    const foreign = win.WSASocketW(win.af_inet6, win.sock_stream, win.ipproto_tcp, null, 0, 1);
    if (foreign == win.invalid_socket) return error.SocketUnavailable;
    try std.testing.expectError(error.Unsupported, HttpsListener.initInherited(std.testing.allocator, loopback_v6, foreign, &snap, listener.tls_config, listener.reader));
}

test "history native Windows transferred listener validates TLS and serves after predecessor shutdown" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    for ([_][]const u8{ loopback_v4, loopback_v6 }) |host| {
        var fixture: NativeHistoryFixture = .{};
        try fixture.init();
        var source = try fixture.open(host);
        var source_open = true;
        defer if (source_open) source.shutdown();
        const carry = try source.captureUnstarted();
        const original = try observeHistoryListener(source.listen_fd, source.v6);

        var wrong_config = source.tls_config;
        wrong_config.receive_record_size_limit -= 1;
        var rejected_config = try native_windows_socket.duplicateForProcess(source.listen_fd, std.os.windows.GetCurrentProcessId());
        try std.testing.expectError(error.ConfigMismatch, HttpsListener.initTransferred(std.testing.allocator, host, &rejected_config, &carry, wrong_config, source.reader));
        try std.testing.expect(rejected_config.consumed);
        try std.testing.expectEqualDeep(original, try observeHistoryListener(source.listen_fd, source.v6));

        var rejected_public = try native_windows_socket.duplicateForProcess(source.listen_fd, std.os.windows.GetCurrentProcessId());
        try std.testing.expectError(error.PublicBind, HttpsListener.initTransferred(std.testing.allocator, "0.0.0.0", &rejected_public, &carry, source.tls_config, source.reader));
        try std.testing.expect(rejected_public.consumed);
        try std.testing.expectEqualDeep(original, try observeHistoryListener(source.listen_fd, source.v6));

        var other = try fixture.open(host);
        defer other.shutdown();
        var rejected_endpoint = try native_windows_socket.duplicateForProcess(other.listen_fd, std.os.windows.GetCurrentProcessId());
        try std.testing.expectError(error.ListenerMismatch, HttpsListener.initTransferred(std.testing.allocator, host, &rejected_endpoint, &carry, source.tls_config, source.reader));
        try std.testing.expect(rejected_endpoint.consumed);
        try std.testing.expectEqualDeep(original, try observeHistoryListener(source.listen_fd, source.v6));

        var transfer = try native_windows_socket.duplicateForProcess(source.listen_fd, std.os.windows.GetCurrentProcessId());
        var adopted = try HttpsListener.initTransferred(std.testing.allocator, host, &transfer, &carry, source.tls_config, source.reader);
        defer adopted.shutdown();
        try std.testing.expect(transfer.consumed);
        try std.testing.expect(adopted.winsock_started);
        try std.testing.expect(adopted.listen_fd != source.listen_fd);
        source.shutdown();
        source_open = false;
        try adopted.spawn();

        var client = try NativeHistoryClient.connect(host, adopted.port, &fixture.chain);
        defer client.deinit();
        var out: [2048]u8 = undefined;
        const response = try client.get("member", &out);
        try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 200 OK\r\n"));
        try std.testing.expect(std.mem.endsWith(u8, response, "\r\n\r\nvisible history line\n"));
        try std.testing.expectEqual(@as(usize, 1), fixture.calls.load(.acquire));
    }
}

fn validateEndpoint(observed: metrics_http.ListenerObservation, v6: bool, port: u16) !void {
    var expected: [16]u8 = @splat(0);
    if (v6) expected[15] = 1 else std.mem.writeInt(u32, expected[0..4], 0x7f000001, .big);
    if (observed.family != @as(u16, if (v6) posix.AF.INET6 else posix.AF.INET) or observed.port != port or port == 0 or
        observed.scope_id != 0 or observed.flow_info != 0 or !std.mem.eql(u8, &observed.address, &expected) or
        observed.recv_timeout_us < 200_000 or observed.recv_timeout_us > 210_000) return error.ListenerMismatch;
}
/// Complete material/policy pin, with replay-guard presence only. Its actual
/// mutable graph is not hashed without its owner; active 0-RTT carry refuses.
pub fn tlsConfigDigest(config: tls_server.Config) ![32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("onyx/companion/history/tls-config/1");
    inline for (@typeInfo(tls_server.Config).@"struct".field_names) |name| {
        if (comptime std.mem.eql(u8, name, "replay_guard")) {
            try runtime_pause.hashConfigValue(&hash, config.replay_guard != null);
        } else try hashTlsValue(&hash, @field(config, name));
    }
    return hash.finalResult();
}
fn hashTlsValue(hash: *std.crypto.hash.sha2.Sha256, value: anytype) !void {
    const T = @TypeOf(value);
    switch (@typeInfo(T)) {
        .pointer => |p| {
            if (p.size != .slice) @compileError("TLS pin refuses raw pointers");
            if (p.child == u8) return runtime_pause.hashBytes(hash, value);
            try runtime_pause.hashConfigValue(hash, std.math.cast(u32, value.len) orelse return error.Capacity);
            for (value) |inner| try hashTlsValue(hash, inner);
        },
        .array => for (value) |inner| try hashTlsValue(hash, inner),
        .optional => {
            try runtime_pause.hashConfigValue(hash, value != null);
            if (value) |inner| try hashTlsValue(hash, inner);
        },
        .@"struct" => |info| inline for (info.field_names) |name| try hashTlsValue(hash, @field(value, name)),
        .@"union" => |info| {
            const tag = std.meta.activeTag(value);
            try runtime_pause.hashConfigValue(hash, @intFromEnum(tag));
            inline for (info.field_names) |name| if (tag == @field(info.tag_type.?, name)) try hashTlsValue(hash, @field(value, name));
        },
        else => try runtime_pause.hashConfigValue(hash, value),
    }
}

test "companion runtime history retained IPv4 IPv6 listener TLS pins and read-only adoption" {
    // Live listeners plus dormant-worker adoption: linux/openbsd only (see above).
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
    for ([_][]const u8{ loopback_v4, loopback_v6 }) |host| {
        var fixture: NativeHistoryFixture = .{};
        try fixture.init();
        var listener = try fixture.open(host);
        try listener.prepareColdResources(std.testing.io);
        const specs = [_]runtime_pause.start_gate.ParticipantSpec{.{ .kind = .history, .instance = @intFromBool(listener.v6), .owner_identity = &listener }};
        const gate = runtime_pause.start_gate.create(std.testing.allocator, std.testing.io, &specs) catch |err| {
            listener.shutdown();
            return err;
        };
        defer {
            listener.requestStopAndWake();
            if (gate.view.inspect().phase == .preparing) gate.control.cancelAllAndJoin() else gate.control.joinAll();
            listener.detachAfterJoined() catch unreachable;
            listener.shutdown();
            gate.control.destroyJoined();
        }
        const token = try listener.requestPause(1);
        try listener.prepareDormantWorker(gate.control, gate.view, try gate.view.slot(.history, @intFromBool(listener.v6), &listener));
        try gate.control.awaitAllParked(std.Io.Clock.Timestamp.fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
        gate.control.releaseAll();
        try listener.awaitPaused(token, std.Io.Clock.Timestamp.fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
        try listener.requireActivated();
        var carry = try listener.capturePaused(token);
        const original = try metrics_http.observeListener(listener.listen_fd);
        const rc = sys.fcntl(listener.listen_fd, (if (@import("builtin").os.tag == .openbsd) @as(c_int, 10) else std.posix.F.DUPFD_CLOEXEC), @as(if (@import("builtin").os.tag == .linux) usize else c_int, 0));
        try std.testing.expect(posix.errno(rc) == .SUCCESS);
        var adopted = try HttpsListener.initInherited(std.testing.allocator, host, @intCast(rc), &carry, listener.tls_config, listener.reader);
        adopted.shutdown();
        try std.testing.expectEqualDeep(original, try metrics_http.observeListener(listener.listen_fd));
        const rejected = sys.fcntl(listener.listen_fd, (if (@import("builtin").os.tag == .openbsd) @as(c_int, 10) else std.posix.F.DUPFD_CLOEXEC), @as(if (@import("builtin").os.tag == .linux) usize else c_int, 0));
        try std.testing.expect(posix.errno(rejected) == .SUCCESS);
        carry.listener.inode ^= 1;
        try std.testing.expectError(error.ListenerMismatch, HttpsListener.initInherited(std.testing.allocator, host, @intCast(rejected), &carry, listener.tls_config, listener.reader));
        carry.listener.inode ^= 1;
        try std.testing.expect(posix.errno(sys.fcntl(@intCast(rejected), posix.F.GETFD, @as(if (@import("builtin").os.tag == .linux) usize else c_int, 0))) != .SUCCESS);
        var changed = listener.tls_config;
        changed.receive_record_size_limit -= 1;
        try std.testing.expectError(error.ConfigMismatch, carry.validate(listener.v6, changed));
        changed = listener.tls_config;
        changed.max_early_data_size = 32;
        try std.testing.expectError(error.ActiveTlsContinuityUnsupported, carry.validate(listener.v6, changed));
        try std.testing.expectEqual(@as(usize, 0), fixture.calls.load(.acquire));
        try listener.resumePaused(token);
        {
            var client = try NativeHistoryClient.connect(host, listener.port, &fixture.chain);
            defer client.deinit();
            var out: [2048]u8 = undefined;
            const response = try client.get("member", &out);
            try std.testing.expect(std.mem.endsWith(u8, response, "visible history line\n"));
        }
        const next = try listener.requestPause(2);
        try listener.awaitPaused(next, std.Io.Clock.Timestamp.fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
        try std.testing.expectEqual(@as(usize, 1), fixture.calls.load(.acquire));
        try std.testing.expectEqual(@as(usize, 1), gate.view.inspect().spawned);
    }
}
