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

pub const MediaSocket = struct {
    fd: sys.fd_t,
    recv_timeout_ms: u32 = 250,

    /// Create and bind a UDP socket. `bind_addr_be` is an IPv4 address already in
    /// network byte order (use `loopback_be` / `any_be`); `port` 0 = ephemeral.
    pub fn bind(bind_addr_be: u32, port: u16) Error!MediaSocket {
        // Use each target's native socket ABI. Linux retains its blocking UDP
        // path; OpenBSD uses nonblocking reads after finite readiness polls.
        if (comptime builtin.os.tag == .linux or builtin.os.tag == .openbsd) {
            const rc = sys.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC | (if (builtin.os.tag == .linux) @as(u32, 0) else posix.SOCK.NONBLOCK), posix.IPPROTO.UDP);
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
        // No Winsock mapping yet (mirrors dualstack_udp.zig); unreachable:
        // bind() already reports SocketUnavailable on Windows.
        if (comptime builtin.os.tag == .windows) return;
        _ = sys.close(self.fd);
        self.* = undefined;
    }

    /// The bound local UDP port (host byte order).
    pub fn localPort(self: *const MediaSocket) Error!u16 {
        // No Winsock mapping yet (mirrors dualstack_udp.zig); unreachable:
        // bind() already reports SocketUnavailable on Windows.
        if (comptime builtin.os.tag == .windows) return error.AddrLookupFailed;
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
        if (comptime builtin.os.tag != .linux) {
            self.recv_timeout_ms = @max(ms, 1);
            return;
        }
        const tv = sys.timeval{ .sec = @intCast(ms / 1000), .usec = @intCast((ms % 1000) * 1000) };
        _ = sys.setsockopt(self.fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(sys.timeval));
    }

    /// Send `bytes` to an IPv4 destination. Non-IPv4 addresses are dropped.
    pub fn sendTo(self: *MediaSocket, dest: TransportAddress, bytes: []const u8) void {
        // No Winsock mapping yet (mirrors dualstack_udp.zig); unreachable:
        // bind() already reports SocketUnavailable on Windows.
        if (comptime builtin.os.tag == .windows) return;
        if (dest.ip_len != 4) return;
        var sa = sys.sockaddr.in{
            .port = std.mem.nativeToBig(u16, dest.port),
            .addr = @bitCast(dest.ip[0..4].*),
        };
        _ = sys.sendto(self.fd, bytes.ptr, bytes.len, 0, @ptrCast(&sa), @sizeOf(sys.sockaddr.in));
    }

    pub const Received = struct { data: []u8, from: TransportAddress };

    /// Receive one datagram into `buf`. Returns null on timeout/error/non-IPv4.
    pub fn recvFrom(self: *MediaSocket, buf: []u8) ?Received {
        // No Winsock mapping yet (mirrors dualstack_udp.zig); unreachable:
        // bind() already reports SocketUnavailable on Windows.
        if (comptime builtin.os.tag == .windows) return null;
        if (comptime builtin.os.tag != .linux) {
            var pfd = [_]posix.pollfd{.{ .fd = self.fd, .events = posix.POLL.IN, .revents = 0 }};
            const ready = sys.poll(&pfd, 1, @intCast(@min(self.recv_timeout_ms, std.math.maxInt(c_int))));
            if (ready <= 0 or pfd[0].revents & posix.POLL.IN == 0) return null;
        }
        var sa: sys.sockaddr.in = undefined;
        var slen: posix.socklen_t = @sizeOf(sys.sockaddr.in);
        const rc = sys.recvfrom(self.fd, buf.ptr, buf.len, 0, @ptrCast(&sa), &slen);
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

test "loopback STUN binding round-trip binds the peer and answers" {
    // Loopback UDP via posix poll/sendto has no Winsock mapping yet.
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
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
    // Loopback UDP via posix poll/sendto has no Winsock mapping yet.
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
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
