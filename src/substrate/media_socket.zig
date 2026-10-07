// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Live UDP media socket for the SFU transport plane (IPv4).
//!
//! A blocking `SOCK_DGRAM` socket that the media plane reads in a loop (on its
//! own thread; see the daemon wiring). Each datagram is demultiplexed: STUN
//! binding requests are answered via `MediaTransport.handleStunBinding` (ICE
//! connectivity checks that bind the peer's address); RTP is relayed by the SFU
//! (a later step). Kept deliberately separate from the io_uring TCP loop — media
//! I/O is hot and self-contained, so a dedicated UDP socket is simpler and does
//! not perturb the client/S2S event loop.
const std = @import("std");
const builtin = @import("builtin");
const sys = std.posix.system;
const posix = std.posix;
const ice = @import("../proto/ice.zig");
const media_transport = @import("media_transport.zig");
const windows_udp = @import("../daemon/helix/native_windows_udp_socket.zig");
pub const SocketHandle = if (builtin.os.tag == .windows) usize else sys.fd_t;
const Socket = SocketHandle;

const win = struct {
    const invalid_socket = std.math.maxInt(usize);
    const af_inet: i32 = 2;
    const sock_dgram: i32 = 2;
    const ipproto_udp: i32 = 17;
    const sol_socket: i32 = 0xffff;
    const so_type: i32 = 0x1008;
    const so_exclusiveaddruse: i32 = ~@as(i32, 0x0004);
    const wsa_flag_no_handle_inherit: u32 = 0x80;
    const fionbio: u32 = 0x8004667e;
    const would_block: i32 = 10035;
    const SockAddr4 = extern struct {
        family: u16,
        port: u16,
        addr: [4]u8,
        zero: [8]u8 = @splat(0),
    };
    const FdSet = extern struct { count: u32, sockets: [64]usize };
    const Timeval = extern struct { seconds: i32, microseconds: i32 };
    comptime {
        if (@sizeOf(SockAddr4) != 16 or @sizeOf(FdSet) != 520 or @sizeOf(Timeval) != 8)
            @compileError("Windows media socket ABI shape changed");
    }
    extern "ws2_32" fn WSAStartup(version_requested: u16, data: *anyopaque) callconv(.winapi) i32;
    extern "ws2_32" fn WSACleanup() callconv(.winapi) i32;
    extern "ws2_32" fn WSAGetLastError() callconv(.winapi) i32;
    extern "ws2_32" fn WSASocketW(family: i32, socket_type: i32, protocol: i32, protocol_info: ?*anyopaque, group: u32, flags: u32) callconv(.winapi) usize;
    extern "ws2_32" fn closesocket(socket: usize) callconv(.winapi) i32;
    extern "ws2_32" fn ioctlsocket(socket: usize, command: u32, value: *u32) callconv(.winapi) i32;
    extern "ws2_32" fn bind(socket: usize, address: *const SockAddr4, address_len: i32) callconv(.winapi) i32;
    extern "ws2_32" fn getsockname(socket: usize, address: *SockAddr4, address_len: *i32) callconv(.winapi) i32;
    extern "ws2_32" fn getsockopt(socket: usize, level: i32, option: i32, value: *anyopaque, length: *i32) callconv(.winapi) i32;
    extern "ws2_32" fn setsockopt(socket: usize, level: i32, option: i32, value: *const anyopaque, length: i32) callconv(.winapi) i32;
    extern "ws2_32" fn select(ignored_nfds: i32, readfds: ?*FdSet, writefds: ?*FdSet, exceptfds: ?*FdSet, timeout: *Timeval) callconv(.winapi) i32;
    extern "ws2_32" fn sendto(socket: usize, bytes: [*]const u8, length: i32, flags: i32, address: *const SockAddr4, address_len: i32) callconv(.winapi) i32;
    extern "ws2_32" fn recvfrom(socket: usize, bytes: [*]u8, length: i32, flags: i32, address: *SockAddr4, address_len: *i32) callconv(.winapi) i32;
};

pub const TransportAddress = ice.TransportAddress;
pub const MediaTransport = media_transport.MediaTransport;
pub const max_datagram: usize = 64 * 1024;

/// 127.0.0.1 in network byte order, for loopback binds/tests.
pub const loopback_be: u32 = nativeToBigU32(0x7f00_0001);
/// 0.0.0.0 (all interfaces).
pub const any_be: u32 = 0;

fn nativeToBigU32(v: u32) u32 {
    return std.mem.nativeToBig(u32, v);
}

pub const Error = error{ SocketUnavailable, BindFailed, AddrLookupFailed };
pub const SendDisposition = enum { sent, would_block, socket_error, invalid_destination };

pub const MediaSocket = struct {
    fd: Socket,
    recv_timeout_ms: u32 = 250,

    /// Create and bind a UDP socket. `bind_addr_be` is an IPv4 address already in
    /// network byte order (use `loopback_be` / `any_be`); `port` 0 = ephemeral.
    pub fn bind(bind_addr_be: u32, port: u16) Error!MediaSocket {
        if (comptime builtin.os.tag == .windows) {
            var startup: [408]u8 align(8) = @splat(0);
            if (win.WSAStartup(0x0202, &startup) != 0) return error.SocketUnavailable;
            errdefer _ = win.WSACleanup();
            const socket = win.WSASocketW(win.af_inet, win.sock_dgram, win.ipproto_udp, null, 0, 1 | win.wsa_flag_no_handle_inherit);
            if (socket == win.invalid_socket) return error.SocketUnavailable;
            errdefer _ = win.closesocket(socket);
            const exclusive: i32 = 1;
            if (win.setsockopt(socket, win.sol_socket, win.so_exclusiveaddruse, &exclusive, @sizeOf(i32)) != 0)
                return error.SocketUnavailable;
            const address = win.SockAddr4{ .family = win.af_inet, .port = std.mem.nativeToBig(u16, port), .addr = @bitCast(bind_addr_be) };
            if (win.bind(socket, &address, @sizeOf(win.SockAddr4)) != 0) return error.BindFailed;
            var nonblocking: u32 = 1;
            if (win.ioctlsocket(socket, win.fionbio, &nonblocking) != 0) return error.SocketUnavailable;
            return .{ .fd = socket };
        }
        // Use each target's native socket ABI. Linux retains its blocking UDP
        // path; OpenBSD uses nonblocking reads after finite readiness polls.
        if (comptime builtin.os.tag == .linux or builtin.os.tag == .openbsd) {
            const rc = sys.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK, posix.IPPROTO.UDP);
            if (posix.errno(rc) != .SUCCESS) return error.SocketUnavailable;
            const fd: sys.fd_t = @intCast(rc);
            errdefer _ = sys.close(fd);

            var addr = sys.sockaddr.in{ .port = std.mem.nativeToBig(u16, port), .addr = bind_addr_be };
            if (posix.errno(sys.bind(fd, @ptrCast(&addr), @sizeOf(sys.sockaddr.in))) != .SUCCESS)
                return error.BindFailed;
            return .{ .fd = fd };
        } else return error.SocketUnavailable;
    }

    pub fn deinit(self: *MediaSocket) void {
        if (comptime builtin.os.tag == .windows) {
            _ = win.closesocket(self.fd);
            _ = win.WSACleanup();
            self.* = undefined;
            return;
        }
        _ = sys.close(self.fd);
        self.* = undefined;
    }

    /// The bound local UDP port (host byte order).
    pub fn localPort(self: *const MediaSocket) Error!u16 {
        if (comptime builtin.os.tag == .windows) {
            var address: win.SockAddr4 = undefined;
            var length: i32 = @sizeOf(win.SockAddr4);
            if (win.getsockname(self.fd, &address, &length) != 0 or length != @sizeOf(win.SockAddr4) or address.family != win.af_inet)
                return error.AddrLookupFailed;
            return std.mem.bigToNative(u16, address.port);
        }
        var storage: posix.sockaddr.storage = undefined;
        var len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
        if (posix.errno(sys.getsockname(self.fd, @ptrCast(&storage), &len)) != .SUCCESS)
            return error.AddrLookupFailed;
        const a: *const sys.sockaddr.in = @ptrCast(@alignCast(&storage));
        return std.mem.bigToNative(u16, a.port);
    }

    /// Bound a blocking recv with a timeout so the pump loop can re-check a stop
    /// flag (and tests never hang).
    pub fn setRecvTimeoutMs(self: *MediaSocket, ms: u32) void {
        // Source-owned local poll policy, never mutation of shared socket state.
        self.recv_timeout_ms = @min(@max(ms, 1), std.math.maxInt(c_int));
    }

    /// Zero-timeout readiness check for packet-denial fixtures. A broken socket
    /// must fail the oracle instead of looking like an absent datagram.
    pub fn testOnlyReadableNow(self: *const MediaSocket) error{PollFailed}!bool {
        if (!builtin.is_test) @compileError("test-only UDP readiness oracle");
        if (comptime builtin.os.tag == .windows) {
            var readable = win.FdSet{ .count = 1, .sockets = undefined };
            readable.sockets[0] = self.fd;
            var timeout = win.Timeval{ .seconds = 0, .microseconds = 0 };
            const ready = win.select(0, &readable, null, null, &timeout);
            if (ready < 0) return error.PollFailed;
            return ready > 0;
        }
        var pfd = [_]posix.pollfd{.{ .fd = self.fd, .events = posix.POLL.IN, .revents = 0 }};
        const ready = sys.poll(&pfd, 1, 0);
        if (ready < 0 or (ready > 0 and pfd[0].revents & posix.POLL.IN == 0)) return error.PollFailed;
        return ready > 0;
    }

    pub fn capture(self: *const MediaSocket) !Snapshot {
        var result = try observeSocket(self.fd);
        result.recv_timeout_ms = self.recv_timeout_ms;
        try result.validate();
        return result;
    }
    /// Consumes one authenticated received duplicate on entry. Kernel identity
    /// is a read-only observation; actual OFD lineage is joined by the manifest.
    pub fn initInherited(fd: posix.fd_t, snapshot: *const Snapshot) !MediaSocket {
        // Endpoint observation is not proof of a transferred Winsock socket.
        if (comptime builtin.os.tag == .windows) return error.UnverifiableSocketIdentity;
        errdefer _ = sys.close(fd);
        try snapshot.validate();
        var actual = try observeSocket(fd);
        actual.recv_timeout_ms = snapshot.recv_timeout_ms;
        if (!std.meta.eql(actual, snapshot.*)) return error.SocketMismatch;
        return .{ .fd = fd, .recv_timeout_ms = snapshot.recv_timeout_ms };
    }

    /// Adopt an authenticated, PID-scoped Winsock UDP duplicate. The record is
    /// consumed on entry, including refusal, and the imported handle is closed
    /// on any mismatch. Only the real duplicate proves lineage; matching a
    /// rebound endpoint or a process-local socket value is insufficient.
    pub fn initTransferred(transfer: *windows_udp.Transfer, snapshot: *const Snapshot) !MediaSocket {
        if (comptime builtin.os.tag != .windows) return error.UnverifiableSocketIdentity;
        var startup: [408]u8 align(8) = @splat(0);
        if (win.WSAStartup(0x0202, &startup) != 0) return error.SocketUnavailable;
        errdefer _ = win.WSACleanup();
        const socket = try transfer.import();
        errdefer _ = win.closesocket(socket);
        try snapshot.validate();
        if (snapshot.inode != 0 or snapshot.device != transfer.source_socket)
            return error.SocketMismatch;
        var actual = try observeSocket(socket);
        actual.device = snapshot.device;
        actual.recv_timeout_ms = snapshot.recv_timeout_ms;
        if (!std.meta.eql(actual, snapshot.*)) return error.SocketMismatch;
        return .{ .fd = socket, .recv_timeout_ms = snapshot.recv_timeout_ms };
    }

    /// Send `bytes` to an IPv4 destination. Non-IPv4 addresses are dropped.
    pub fn sendTo(self: *MediaSocket, dest: TransportAddress, bytes: []const u8) void {
        if (comptime builtin.os.tag == .windows) {
            _ = self.trySendTo(dest, bytes);
            return;
        }
        if (dest.ip_len != 4) return;
        var sa = sys.sockaddr.in{
            .port = std.mem.nativeToBig(u16, dest.port),
            .addr = @bitCast(dest.ip[0..4].*),
        };
        _ = sys.sendto(self.fd, bytes.ptr, bytes.len, posix.MSG.DONTWAIT, @ptrCast(&sa), @sizeOf(sys.sockaddr.in));
    }

    /// Source-owned nonblocking datagram attempt with explicit terminal outcome.
    /// UDP has no partial-write retry; a short result is a socket failure.
    pub fn trySendTo(self: *MediaSocket, dest: TransportAddress, bytes: []const u8) SendDisposition {
        if (comptime builtin.os.tag == .windows) {
            if (dest.ip_len != 4 or dest.port == 0 or bytes.len > std.math.maxInt(i32)) return .invalid_destination;
            const address = win.SockAddr4{ .family = win.af_inet, .port = std.mem.nativeToBig(u16, dest.port), .addr = dest.ip[0..4].* };
            const sent = win.sendto(self.fd, bytes.ptr, @intCast(bytes.len), 0, &address, @sizeOf(win.SockAddr4));
            if (sent >= 0) return if (@as(usize, @intCast(sent)) == bytes.len) .sent else .socket_error;
            return if (win.WSAGetLastError() == win.would_block) .would_block else .socket_error;
        }
        if (dest.ip_len != 4 or dest.port == 0) return .invalid_destination;
        var address = sys.sockaddr.in{ .port = std.mem.nativeToBig(u16, dest.port), .addr = @bitCast(dest.ip[0..4].*) };
        const rc = sys.sendto(self.fd, bytes.ptr, bytes.len, posix.MSG.DONTWAIT, @ptrCast(&address), @sizeOf(sys.sockaddr.in));
        return switch (posix.errno(rc)) {
            .SUCCESS => if (@as(usize, @intCast(rc)) == bytes.len) .sent else .socket_error,
            .AGAIN => .would_block,
            else => .socket_error,
        };
    }

    pub const Received = struct { data: []u8, from: TransportAddress };

    /// Receive one datagram into `buf`. Returns null on timeout/error/non-IPv4.
    pub fn recvFrom(self: *MediaSocket, buf: []u8) ?Received {
        if (comptime builtin.os.tag == .windows) {
            var readable = win.FdSet{ .count = 1, .sockets = undefined };
            readable.sockets[0] = self.fd;
            const finite_ms = @min(@max(self.recv_timeout_ms, 1), 60_000);
            const seconds: i32 = @intCast(finite_ms / 1000);
            const remainder_ms: u32 = finite_ms % 1000;
            const microseconds: i32 = @intCast(remainder_ms * 1000);
            var timeout = win.Timeval{ .seconds = seconds, .microseconds = microseconds };
            if (win.select(0, &readable, null, null, &timeout) <= 0) return null;
            var address: win.SockAddr4 = undefined;
            var length: i32 = @sizeOf(win.SockAddr4);
            const received = win.recvfrom(self.fd, buf.ptr, @intCast(@min(buf.len, std.math.maxInt(i32))), 0, &address, &length);
            if (received < 0 or length != @sizeOf(win.SockAddr4) or address.family != win.af_inet) return null;
            const from = TransportAddress.fromBytes(&address.addr, std.mem.bigToNative(u16, address.port)) catch return null;
            return .{ .data = buf[0..@intCast(received)], .from = from };
        }
        {
            var pfd = [_]posix.pollfd{.{ .fd = self.fd, .events = posix.POLL.IN, .revents = 0 }};
            const ready = sys.poll(&pfd, 1, @intCast(@min(self.recv_timeout_ms, std.math.maxInt(c_int))));
            if (ready <= 0 or pfd[0].revents & posix.POLL.IN == 0) return null;
        }
        var sa: sys.sockaddr.in = undefined;
        var slen: posix.socklen_t = @sizeOf(sys.sockaddr.in);
        const rc = sys.recvfrom(self.fd, buf.ptr, buf.len, posix.MSG.DONTWAIT, @ptrCast(&sa), &slen);
        if (posix.errno(rc) != .SUCCESS) return null;
        const n: usize = @intCast(rc);
        if (slen != @sizeOf(sys.sockaddr.in) or sa.family != posix.AF.INET or n > buf.len) return null;
        const ip4: [4]u8 = @bitCast(sa.addr);
        const from = TransportAddress.fromBytes(&ip4, std.mem.bigToNative(u16, sa.port)) catch return null;
        return .{ .data = buf[0..n], .from = from };
    }

    /// Whether a datagram's first byte marks it as STUN (top two bits zero) vs
    /// RTP/RTCP (version 2 → 0x80+). RFC 5764 §5.1.2 demultiplexing rule.
    pub fn isStun(first: u8) bool {
        return (first & 0xC0) == 0;
    }

    /// Send a plain STUN binding request to `server` and return the reflexive
    /// (public) address it reports in XOR-MAPPED-ADDRESS — the server's own
    /// server-reflexive candidate. `txid` is the caller-supplied transaction id
    /// (use random bytes). Returns null on timeout / malformed / no address.
    /// Must be called before the pump thread owns the socket (e.g. at boot).
    pub fn queryReflexive(self: *MediaSocket, server: TransportAddress, txid: [12]u8, allocator: std.mem.Allocator) ?TransportAddress {
        const req = stun.buildBindingRequest(allocator, txid, .{ .fingerprint = true }) catch return null;
        defer allocator.free(req);
        self.sendTo(server, req);

        var buf: [max_datagram]u8 = undefined;
        const got = self.recvFrom(&buf) orelse return null;
        var msg = stun.decode(allocator, got.data) catch return null;
        defer msg.deinit(allocator);
        if (msg.typ != .binding_success_response) return null;
        for (msg.attributes) |a| {
            const addr: ?stun.Address = switch (a) {
                .xor_mapped_address => |v| v,
                .mapped_address => |v| v,
                else => null,
            };
            if (addr) |sa| return switch (sa) {
                .ipv4 => |v| TransportAddress.fromBytes(&v.ip, v.port) catch null,
                .ipv6 => |v| TransportAddress.fromBytes(&v.ip, v.port) catch null,
            };
        }
        return null;
    }

    /// Read and process one datagram: STUN binding requests are answered (binding
    /// the peer address); RTP is left for the SFU relay step. Returns true if a
    /// datagram was read, false on timeout/idle. `buf` is scratch for the read.
    pub fn pumpOnce(
        self: *MediaSocket,
        transport: *MediaTransport,
        allocator: std.mem.Allocator,
        buf: []u8,
    ) bool {
        const got = self.recvFrom(buf) orelse return false;
        if (got.data.len == 0) return true;
        if (isStun(got.data[0])) {
            const resp = transport.handleStunBinding(allocator, got.data, got.from) catch return true;
            if (resp) |r| {
                defer allocator.free(r);
                self.sendTo(got.from, r);
            }
        }
        return true;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const stun = @import("../proto/stun.zig");

test "Windows MediaSocket binds, sends and receives IPv4 UDP with bounded idle poll" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var server = try MediaSocket.bind(loopback_be, 0);
    defer server.deinit();
    var peer = try MediaSocket.bind(loopback_be, 0);
    defer peer.deinit();
    const port = try server.localPort();
    try testing.expect(port != 0);
    const observed = try server.capture();
    try testing.expectEqual(@as(u64, @intCast(server.fd)), observed.device);
    try testing.expectEqual(@as(u64, 0), observed.inode);
    try testing.expectEqual(port, observed.port);
    const destination = try TransportAddress.fromBytes(&.{ 127, 0, 0, 1 }, port);
    try testing.expectEqual(SendDisposition.sent, peer.trySendTo(destination, "cadence"));
    var buf: [64]u8 = undefined;
    const got = server.recvFrom(&buf) orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("cadence", got.data);
    try testing.expectEqual(@as(u16, try peer.localPort()), got.from.port);
    try testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, got.from.bytes());
    server.setRecvTimeoutMs(50);
    const before = @import("platform.zig").monotonicMillis();
    try testing.expect(server.recvFrom(&buf) == null);
    try testing.expect(@import("platform.zig").monotonicMillis() - before < 1000);
}

test "Windows UDP custody MediaSocket imports a real duplicate without changing source custody" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var old = try MediaSocket.bind(loopback_be, 0);
    defer old.deinit();
    old.setRecvTimeoutMs(43);
    const carry = try old.capture();
    var transfer = try windows_udp.duplicateForProcess(old.fd, std.os.windows.GetCurrentProcessId());
    var adopted = try MediaSocket.initTransferred(&transfer, &carry);
    defer adopted.deinit();
    try testing.expect(transfer.consumed);
    try testing.expect(old.fd != adopted.fd);
    try testing.expectEqual(carry.port, try adopted.localPort());
    try testing.expectEqual(carry.recv_timeout_ms, adopted.recv_timeout_ms);
    try testing.expectEqualDeep(carry, try old.capture());

    var peer = try MediaSocket.bind(loopback_be, 0);
    defer peer.deinit();
    const destination = try TransportAddress.fromBytes(&.{ 127, 0, 0, 1 }, carry.port);
    try testing.expectEqual(SendDisposition.sent, peer.trySendTo(destination, "adopted"));
    var buf: [64]u8 = undefined;
    const first = adopted.recvFrom(&buf) orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("adopted", first.data);
    try testing.expectEqual(SendDisposition.sent, peer.trySendTo(destination, "source"));
    const second = old.recvFrom(&buf) orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("source", second.data);
    try testing.expectError(error.AlreadyConsumed, transfer.import());

    var stale = carry;
    stale.port = if (stale.port == 65535) 65534 else stale.port + 1;
    var rejected = try windows_udp.duplicateForProcess(old.fd, std.os.windows.GetCurrentProcessId());
    try testing.expectError(error.SocketMismatch, MediaSocket.initTransferred(&rejected, &stale));
    try testing.expect(rejected.consumed);
    var substitute = try windows_udp.duplicateForProcess(peer.fd, std.os.windows.GetCurrentProcessId());
    try testing.expectError(error.SocketMismatch, MediaSocket.initTransferred(&substitute, &carry));
    try testing.expect(substitute.consumed);
    try testing.expectEqualDeep(carry, try old.capture());
}

test "loopback STUN binding round-trip binds the peer and answers" {
    var prng = std.Random.DefaultPrng.init(0xc0ffee);
    var mt = MediaTransport.init(testing.allocator);
    defer mt.deinit();
    const ep = try mt.allocate("#c", "alice", prng.random());
    const ufrag = ep.ufrag;
    const pwd = ep.pwd;

    var server = try MediaSocket.bind(loopback_be, 0);
    defer server.deinit();
    server.setRecvTimeoutMs(2000);
    const sport = try server.localPort();

    var client = try MediaSocket.bind(loopback_be, 0);
    defer client.deinit();
    client.setRecvTimeoutMs(2000);

    // Client sends a STUN binding request to the server's media port.
    var user_buf: [media_transport.ufrag_len + 6]u8 = undefined;
    const user = std.fmt.bufPrint(&user_buf, "{s}:peer", .{ufrag[0..]}) catch unreachable;
    const tx: stun.TransactionId = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
    const req = try stun.buildBindingRequest(testing.allocator, tx, .{
        .username = user,
        .integrity_key = pwd[0..],
        .fingerprint = true,
    });
    defer testing.allocator.free(req);
    const server_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, sport);
    client.sendTo(server_addr, req);

    // Server processes the datagram: authenticates, binds, replies.
    var sbuf: [max_datagram]u8 = undefined;
    try testing.expect(server.pumpOnce(&mt, testing.allocator, &sbuf));
    try testing.expect(mt.get("#c", "alice").?.connected());

    // Client receives a verifiable binding success response.
    var cbuf: [max_datagram]u8 = undefined;
    const got = client.recvFrom(&cbuf) orelse return error.TestUnexpectedResult;
    var decoded = try stun.decode(testing.allocator, got.data);
    defer decoded.deinit(testing.allocator);
    try testing.expectEqual(stun.MessageType.binding_success_response, decoded.typ);
    try testing.expect(try stun.verifyMessageIntegrity(got.data, pwd[0..]));
}

fn reflectorThread(sock: *MediaSocket) void {
    var fba_buf: [4096]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&fba_buf);
    const a = fba.allocator();
    var buf: [max_datagram]u8 = undefined;
    const got = sock.recvFrom(&buf) orelse return;
    var msg = stun.decode(a, got.data) catch return;
    defer msg.deinit(a);
    if (msg.typ != .binding_request) return;
    const mapped = stun.Address{ .ipv4 = .{ .ip = got.from.ip[0..4].*, .port = got.from.port } };
    const resp = stun.buildBindingSuccessResponse(a, msg.transaction_id, .{
        .xor_mapped_address = mapped,
        .fingerprint = true,
    }) catch return;
    sock.sendTo(got.from, resp);
}

test "queryReflexive learns the reflexive address from a STUN server" {
    var server = try MediaSocket.bind(loopback_be, 0);
    defer server.deinit();
    server.setRecvTimeoutMs(2000);
    const sport = try server.localPort();

    var client = try MediaSocket.bind(loopback_be, 0);
    defer client.deinit();
    client.setRecvTimeoutMs(2000);
    const cport = try client.localPort();

    const t = try std.Thread.spawn(.{}, reflectorThread, .{&server});
    defer t.join();

    const server_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, sport);
    const refl = client.queryReflexive(server_addr, .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 }, testing.allocator) orelse
        return error.TestUnexpectedResult;
    // The reflector reports back what it saw: the client's own loopback ip:port.
    try testing.expectEqual(cport, refl.port);
    try testing.expectEqualSlices(u8, &[_]u8{ 127, 0, 0, 1 }, refl.bytes());
}

test "isStun demultiplexes STUN from RTP" {
    try testing.expect(MediaSocket.isStun(0x00)); // STUN binding request type hi byte
    try testing.expect(!MediaSocket.isStun(0x80)); // RTP version 2
    try testing.expect(!MediaSocket.isStun(0x90)); // RTP with extension
}

pub const Snapshot = struct {
    device: u64,
    inode: u64,
    address_be: u32,
    port: u16,
    recv_timeout_ms: u32,
    pub fn validate(self: *const Snapshot) !void {
        if (self.port == 0 or self.recv_timeout_ms == 0 or self.recv_timeout_ms > std.math.maxInt(c_int)) return error.InvalidSocket;
    }
};
fn identityBits(value: anytype) u64 {
    return @intCast(@as(@Int(.unsigned, @bitSizeOf(@TypeOf(value))), @bitCast(value)));
}
fn observeSocket(fd: Socket) !Snapshot {
    if (comptime builtin.os.tag == .windows) {
        var socket_type: i32 = 0;
        var length: i32 = @sizeOf(i32);
        if (win.getsockopt(fd, win.sol_socket, win.so_type, &socket_type, &length) != 0 or
            length != @sizeOf(i32) or socket_type != win.sock_dgram) return error.InvalidSocket;
        var address: win.SockAddr4 = undefined;
        length = @sizeOf(win.SockAddr4);
        if (win.getsockname(fd, &address, &length) != 0 or length != @sizeOf(win.SockAddr4) or
            address.family != win.af_inet) return error.InvalidSocket;
        const result = Snapshot{
            // A process-local SOCKET value catches substitution during cold
            // startup. Zero inode explicitly denies inherited-socket custody.
            .device = @intCast(fd),
            .inode = 0,
            .address_be = @bitCast(address.addr),
            .port = std.mem.bigToNative(u16, address.port),
            .recv_timeout_ms = 250,
        };
        try result.validate();
        return result;
    }
    var typ: u32 = 0;
    var len: posix.socklen_t = @sizeOf(u32);
    if (posix.errno(sys.getsockopt(fd, posix.SOL.SOCKET, posix.SO.TYPE, @ptrCast(&typ), &len)) != .SUCCESS or len != @sizeOf(u32) or typ != posix.SOCK.DGRAM) return error.InvalidSocket;
    const raw = sys.fcntl(fd, posix.F.GETFL, @as(if (@import("builtin").os.tag == .linux) usize else c_int, 0));
    if (posix.errno(raw) != .SUCCESS or !@as(posix.O, @bitCast(@as(u32, @intCast(raw)))).NONBLOCK) return error.InvalidSocket;
    const flags = sys.fcntl(fd, posix.F.GETFD, @as(if (@import("builtin").os.tag == .linux) usize else c_int, 0));
    if (posix.errno(flags) != .SUCCESS or (flags & posix.FD_CLOEXEC) == 0) return error.InvalidSocket;
    var address: posix.sockaddr.storage = undefined;
    len = @sizeOf(posix.sockaddr.storage);
    if (posix.errno(sys.getsockname(fd, @ptrCast(&address), &len)) != .SUCCESS or address.family != posix.AF.INET or len != @sizeOf(posix.sockaddr.in)) return error.InvalidSocket;
    const addr: *const posix.sockaddr.in = @ptrCast(@alignCast(&address));
    var result: Snapshot = .{ .device = 0, .inode = 0, .address_be = addr.addr, .port = std.mem.bigToNative(u16, addr.port), .recv_timeout_ms = 250 };
    if (comptime builtin.os.tag == .linux) {
        var st: std.os.linux.Statx = std.mem.zeroes(std.os.linux.Statx);
        if (posix.errno(std.os.linux.statx(fd, "", std.os.linux.AT.EMPTY_PATH, .{ .TYPE = true, .INO = true }, &st)) != .SUCCESS or !st.mask.TYPE or !st.mask.INO or (st.mode & posix.S.IFMT) != posix.S.IFSOCK) return error.InvalidSocket;
        result.device = (@as(u64, st.dev_major) << 32) | st.dev_minor;
        result.inode = st.ino;
    } else {
        var st: posix.Stat = undefined;
        if (posix.errno(sys.fstat(fd, &st)) != .SUCCESS or (st.mode & posix.S.IFMT) != posix.S.IFSOCK) return error.InvalidSocket;
        result.device = identityBits(st.dev);
        result.inode = identityBits(st.ino);
    }
    try result.validate();
    return result;
}

test "companion runtime media socket inherited UDP custody is validation-only" {
    // Loopback UDP via posix poll/sendto has no Winsock mapping yet.
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    var old = try MediaSocket.bind(loopback_be, 0);
    defer old.deinit();
    old.setRecvTimeoutMs(17);
    var carry = try old.capture();
    const flags = sys.fcntl(old.fd, posix.F.GETFL, @as(if (@import("builtin").os.tag == .linux) usize else c_int, 0));
    const duplicate = sys.fcntl(old.fd, (if (@import("builtin").os.tag == .openbsd) @as(c_int, 10) else std.posix.F.DUPFD_CLOEXEC), @as(if (@import("builtin").os.tag == .linux) usize else c_int, 0));
    try testing.expect(posix.errno(duplicate) == .SUCCESS);
    var adopted = try MediaSocket.initInherited(@intCast(duplicate), &carry);
    try testing.expectEqual(@as(u32, 17), adopted.recv_timeout_ms);
    adopted.deinit();
    try testing.expectEqual(flags, sys.fcntl(old.fd, posix.F.GETFL, @as(if (@import("builtin").os.tag == .linux) usize else c_int, 0)));
    try testing.expectEqualDeep(carry, try old.capture());
    const rejected = sys.fcntl(old.fd, (if (@import("builtin").os.tag == .openbsd) @as(c_int, 10) else std.posix.F.DUPFD_CLOEXEC), @as(if (@import("builtin").os.tag == .linux) usize else c_int, 0));
    try testing.expect(posix.errno(rejected) == .SUCCESS);
    carry.inode ^= 1;
    try testing.expectError(error.SocketMismatch, MediaSocket.initInherited(@intCast(rejected), &carry));
    carry.inode ^= 1;
    try testing.expect(posix.errno(sys.fcntl(@intCast(rejected), posix.F.GETFD, @as(if (@import("builtin").os.tag == .linux) usize else c_int, 0))) != .SUCCESS);
    try testing.expectEqualDeep(carry, try old.capture());
    var client = try MediaSocket.bind(loopback_be, 0);
    defer client.deinit();
    const destination = try TransportAddress.fromBytes(&.{ 127, 0, 0, 1 }, carry.port);
    client.sendTo(destination, "queued datagram");
    var bytes: [128]u8 = undefined;
    const received = old.recvFrom(&bytes) orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("queued datagram", received.data);
}
