// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! IPv4/IPv6 UDP sockets for the WebTransport listener.
//!
//! Linux uses one nonblocking `AF_INET6` socket with `IPV6_V6ONLY=0`; IPv4
//! peers arrive as mapped addresses. OpenBSD uses native IPv4 and IPv6 sockets
//! sharing one port, with finite readiness polls and fair dispatch. This mirrors the
//! shape of `MediaSocket` (`bind` / `deinit` / `localPort` / `setRecvTimeoutMs` /
//! `recvFrom` / `sendTo`) so the listener can swap one for the other, but it is a
//! SEPARATE socket: the media plane keeps its proven IPv4-only `MediaSocket`.
//!
//! Address mapping (`sockaddr_in6` ⇄ `TransportAddress`)
//! ----------------------------------------------------
//!   * `recvFrom`: an IPv4-mapped source (`::ffff:0:0/96`) is surfaced as a
//!     4-byte ipv4 `TransportAddress` (so PROXY-protocol carry + logging see the
//!     REAL v4 address, not a v6 wrapper); any other source is surfaced as a
//!     16-byte ipv6 `TransportAddress`.
//!   * `sendTo`: a v4 `TransportAddress` is re-wrapped as a v4-mapped
//!     `::ffff:a.b.c.d`; a v6 `TransportAddress` is copied verbatim. Either way
//!     the kernel routes it correctly over the single dual-stack socket.
//!   * `scope_id`/`flowinfo` are 0 (loopback + global unicast; this listener does
//!     not address link-local scopes).
//!
//! Bounds: a malformed/oversized datagram cannot panic — `recvFrom` clamps the
//! read to `buf.len` and only ever returns the actually-received prefix; the
//! address conversion is fixed-width and total over any 16-byte input.
const std = @import("std");
const builtin = @import("builtin");
const sys = if (builtin.os.tag == .windows) std.os.linux else std.posix.system;
const posix = std.posix;
const ice = @import("../proto/ice.zig");

pub const TransportAddress = ice.TransportAddress;

/// The 12-byte `::ffff:` prefix that marks an IPv4-mapped IPv6 address
/// (RFC 4291 §2.5.5.2): 80 zero bits followed by 16 one bits.
const v4mapped_prefix = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

pub const Error = error{ SocketUnavailable, BindFailed, AddrLookupFailed };

/// IPV6_V6ONLY option name for the native-pair path. `std.posix.system.IPV6`
/// is `void` on macOS, where only the libc headers carry it
/// (`std.c.IPV6.V6ONLY` = 27, matching the BSDs); Linux uses 26 via
/// `std.os.linux.IPV6` in `bind` above and never calls this.
fn ipv6V6Only() comptime_int {
    // IPV6_V6ONLY is 27 on macOS (XNU in6.h) and the BSDs, 26 on Linux
    // (which never calls this: `bind` uses `std.os.linux.IPV6` directly).
    // Neither `std.posix.system.IPV6` nor `std.c.IPV6` covers Apple targets in
    // Zig 0.17 (both are `void` there), so the macOS value is spelled out.
    // `comptime_int` keeps the original implicit coercion to each libc's
    // `setsockopt`/`getsockopt` option-name parameter type.
    if (builtin.os.tag == .macos) return 27;
    return sys.IPV6.V6ONLY;
}

pub const DualStackUdpSocket = struct {
    fd: sys.fd_t,
    ipv4_fd: sys.fd_t = -1,
    primary_ipv4: bool = false,
    recv_timeout_ms: u32 = 250,
    prefer_ipv4: bool = false,

    /// Open a dual-stack UDP socket and bind it. `bind_addr` selects the local
    /// address to bind:
    ///   * `.any` → `[::]` (all interfaces, both families) — the normal server bind.
    ///   * `.loopback_v6` → `[::1]` (IPv6 loopback only) — for tests.
    ///   * `.v4_mapped` → bind a configured IPv4 address as `::ffff:a.b.c.d` so a
    ///     v4-only operator config still works over the dual-stack socket.
    /// `port` 0 = ephemeral. Linux receives mapped IPv4 on the IPv6 socket;
    /// OpenBSD publishes a socket pair transactionally for `.any`.
    pub fn bind(bind_addr: BindAddr, port: u16) Error!DualStackUdpSocket {
        if (comptime builtin.os.tag == .windows) return error.SocketUnavailable;
        if (comptime builtin.os.tag != .linux) return bindNative(bind_addr, port);
        const rc = sys.socket(posix.AF.INET6, sys.SOCK.DGRAM | sys.SOCK.CLOEXEC | sys.SOCK.NONBLOCK, sys.IPPROTO.UDP);
        if (posix.errno(rc) != .SUCCESS) return error.SocketUnavailable;
        const fd: sys.fd_t = @intCast(rc);
        errdefer _ = sys.close(fd);

        // IPV6_V6ONLY=0: one socket serves both IPv6 and IPv4 (mapped) peers.
        const v6only: c_int = 0;
        if (posix.errno(sys.setsockopt(
            fd,
            sys.SOL.IPV6,
            sys.IPV6.V6ONLY,
            std.mem.asBytes(&v6only),
            @sizeOf(c_int),
        )) != .SUCCESS) return error.BindFailed;

        var addr = sys.sockaddr.in6{
            .port = std.mem.nativeToBig(u16, port),
            .flowinfo = 0,
            .addr = bind_addr.toBytes(),
            .scope_id = 0,
        };
        if (posix.errno(sys.bind(fd, @ptrCast(&addr), @sizeOf(sys.sockaddr.in6))) != .SUCCESS)
            return error.BindFailed;
        return .{ .fd = fd };
    }

    fn bindNative(bind_addr: BindAddr, port: u16) Error!DualStackUdpSocket {
        const flags = posix.SOCK.DGRAM | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK;
        if (bind_addr == .v4_mapped) {
            const raw_fd = sys.socket(posix.AF.INET, flags, posix.IPPROTO.UDP);
            if (posix.errno(raw_fd) != .SUCCESS) return error.SocketUnavailable;
            const fd: posix.fd_t = @intCast(raw_fd);
            errdefer _ = sys.close(fd);
            var addr = sys.sockaddr.in{ .port = std.mem.nativeToBig(u16, port), .addr = @bitCast(bind_addr.v4_mapped) };
            if (posix.errno(sys.bind(fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr)))) != .SUCCESS) return error.BindFailed;
            return .{ .fd = fd, .primary_ipv4 = true };
        }
        // OpenBSD deliberately has no IPv4-mapped IPv6 sockets. Bind a native
        // socket per family at one port; each attempt publishes both or neither.
        for (0..16) |_| {
            const raw_fd = sys.socket(posix.AF.INET6, flags, posix.IPPROTO.UDP);
            if (posix.errno(raw_fd) != .SUCCESS) return error.SocketUnavailable;
            const fd: posix.fd_t = @intCast(raw_fd);
            var owner = DualStackUdpSocket{ .fd = fd };
            errdefer owner.deinit();
            const one: c_int = 1;
            if (posix.errno(sys.setsockopt(fd, posix.IPPROTO.IPV6, ipv6V6Only(), std.mem.asBytes(&one), @sizeOf(c_int))) != .SUCCESS) return error.BindFailed;
            var addr = sys.sockaddr.in6{ .port = std.mem.nativeToBig(u16, port), .flowinfo = 0, .addr = bind_addr.toBytes(), .scope_id = 0 };
            if (posix.errno(sys.bind(fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr)))) != .SUCCESS) return error.BindFailed;
            if (bind_addr == .loopback_v6) return owner;
            const chosen = try owner.localPort();
            const raw_fd4 = sys.socket(posix.AF.INET, flags, posix.IPPROTO.UDP);
            if (posix.errno(raw_fd4) != .SUCCESS) return error.SocketUnavailable;
            const fd4: posix.fd_t = @intCast(raw_fd4);
            owner.ipv4_fd = fd4;
            var addr4 = sys.sockaddr.in{ .port = std.mem.nativeToBig(u16, chosen), .addr = 0 };
            const bound = sys.bind(fd4, @ptrCast(&addr4), @sizeOf(@TypeOf(addr4)));
            if (posix.errno(bound) == .SUCCESS) return owner;
            if (port != 0 or posix.errno(bound) != .ADDRINUSE) return error.BindFailed;
            owner.deinit();
        }
        return error.BindFailed;
    }

    /// Which local address to bind the dual-stack socket to.
    pub const BindAddr = union(enum) {
        /// `[::]` — all interfaces, both families (the production server bind).
        any,
        /// `[::1]` — IPv6 loopback only (tests).
        loopback_v6,
        /// A configured IPv4 bind address, bound as `::ffff:a.b.c.d` so a
        /// v4-only operator config still binds on the dual-stack socket.
        v4_mapped: [4]u8,

        fn toBytes(self: BindAddr) [16]u8 {
            return switch (self) {
                .any => @as([16]u8, @splat(0)), // ::
                .loopback_v6 => blk: {
                    var a = @as([16]u8, @splat(0));
                    a[15] = 1; // ::1
                    break :blk a;
                },
                .v4_mapped => |v4| blk: {
                    var a = @as([16]u8, @splat(0));
                    @memcpy(a[0..12], &v4mapped_prefix);
                    @memcpy(a[12..16], &v4);
                    break :blk a;
                },
            };
        }
    };

    pub fn deinit(self: *DualStackUdpSocket) void {
        if (comptime builtin.os.tag == .windows) {
            self.* = undefined;
            return;
        }
        _ = sys.close(self.fd);
        if (self.ipv4_fd >= 0) _ = sys.close(self.ipv4_fd);
        self.* = undefined;
    }

    /// The bound local UDP port (host byte order).
    pub fn localPort(self: *const DualStackUdpSocket) Error!u16 {
        if (comptime builtin.os.tag == .windows) return error.AddrLookupFailed;
        if (self.primary_ipv4) {
            var sa4: sys.sockaddr.in = undefined;
            var len4: posix.socklen_t = @sizeOf(@TypeOf(sa4));
            if (posix.errno(sys.getsockname(self.fd, @ptrCast(&sa4), &len4)) != .SUCCESS) return error.AddrLookupFailed;
            if (len4 != @sizeOf(@TypeOf(sa4)) or sa4.family != posix.AF.INET) return error.AddrLookupFailed;
            return std.mem.bigToNative(u16, sa4.port);
        }
        var sa: sys.sockaddr.in6 = undefined;
        var len: posix.socklen_t = @sizeOf(sys.sockaddr.in6);
        if (posix.errno(sys.getsockname(self.fd, @ptrCast(&sa), &len)) != .SUCCESS)
            return error.AddrLookupFailed;
        if (len != @sizeOf(@TypeOf(sa)) or sa.family != posix.AF.INET6) return error.AddrLookupFailed;
        return std.mem.bigToNative(u16, sa.port);
    }

    /// Bound a blocking recv with a timeout so the pump loop can re-check a stop
    /// flag (and tests never hang).
    pub fn setRecvTimeoutMs(self: *DualStackUdpSocket, ms: u32) void {
        self.recv_timeout_ms = @min(@max(ms, 1), std.math.maxInt(c_int));
    }

    pub fn capture(self: *const DualStackUdpSocket) !Snapshot {
        var carry: Snapshot = .{ .primary = try observeDatagram(self.fd), .ipv4 = null, .primary_ipv4 = self.primary_ipv4, .recv_timeout_ms = self.recv_timeout_ms, .prefer_ipv4 = self.prefer_ipv4 };
        if (self.ipv4_fd >= 0) {
            if (self.ipv4_fd == self.fd) return error.InvalidSocket;
            carry.ipv4 = try observeDatagram(self.ipv4_fd);
        }
        try carry.validate();
        return carry;
    }
    /// Takes both transferred references on entry, including refusal. It never
    /// binds, sets flags/options, reads or shuts down a shared open description.
    pub fn initInherited(fd: posix.fd_t, ipv4_fd: ?posix.fd_t, carry: *const Snapshot) !DualStackUdpSocket {
        errdefer {
            _ = sys.close(fd);
            if (ipv4_fd) |other| if (other != fd) {
                _ = sys.close(other);
            };
        }
        try carry.validate();
        if ((ipv4_fd != null) != (carry.ipv4 != null) or (ipv4_fd != null and ipv4_fd.? == fd)) return error.InvalidSocket;
        const actual = try observeDatagram(fd);
        if (!std.meta.eql(actual, carry.primary)) return error.SocketMismatch;
        if (ipv4_fd) |other| {
            if (!std.meta.eql(try observeDatagram(other), carry.ipv4.?)) return error.SocketMismatch;
        }
        // OpenBSD socket fstat reports no device/inode identity. A cold
        // source-owned observation is useful, but cannot authenticate an
        // inherited open description. Keep adoption closed until a genuine
        // source-custody bridge supplies that proof.
        if (actual.inode == 0 or (carry.ipv4 != null and carry.ipv4.?.inode == 0)) return error.UnverifiableSocketIdentity;
        return .{ .fd = fd, .ipv4_fd = ipv4_fd orelse -1, .primary_ipv4 = carry.primary_ipv4, .recv_timeout_ms = carry.recv_timeout_ms, .prefer_ipv4 = carry.prefer_ipv4 };
    }

    /// Send `bytes` to `dest`. A v4 `TransportAddress` is re-wrapped as a
    /// v4-mapped `::ffff:a.b.c.d`; a v6 one is copied verbatim. A `TransportAddress`
    /// with an unexpected `ip_len` (neither 4 nor 16) is dropped.
    pub fn sendTo(self: *DualStackUdpSocket, dest: TransportAddress, bytes: []const u8) void {
        if (comptime builtin.os.tag == .windows) return;
        if (dest.ip_len == 4 and (self.primary_ipv4 or self.ipv4_fd >= 0)) {
            const fd = if (self.primary_ipv4) self.fd else self.ipv4_fd;
            const sa4 = sys.sockaddr.in{ .port = std.mem.nativeToBig(u16, dest.port), .addr = @bitCast(dest.ip[0..4].*) };
            _ = sys.sendto(fd, bytes.ptr, bytes.len, posix.MSG.DONTWAIT, @ptrCast(&sa4), @sizeOf(@TypeOf(sa4)));
            return;
        }
        if (self.primary_ipv4 or (comptime builtin.os.tag != .linux) and dest.ip_len != 16) return;
        const sa = toSockaddrIn6(dest) orelse return;
        _ = sys.sendto(self.fd, bytes.ptr, bytes.len, posix.MSG.DONTWAIT, @ptrCast(&sa), @sizeOf(sys.sockaddr.in6));
    }

    pub const Received = struct { data: []u8, from: TransportAddress };

    /// Receive one datagram into `buf`. Returns null on timeout/error. The source
    /// `sockaddr_in6` is converted to a `TransportAddress`: an IPv4-mapped source
    /// becomes a 4-byte ipv4 address, anything else a 16-byte ipv6 address.
    pub fn recvFrom(self: *DualStackUdpSocket, buf: []u8) ?Received {
        if (comptime builtin.os.tag == .windows) return null;
        return self.recvNative(buf);
    }
    fn recvNative(self: *DualStackUdpSocket, buf: []u8) ?Received {
        var fds = [_]posix.pollfd{
            .{ .fd = self.fd, .events = posix.POLL.IN, .revents = 0 },
            .{ .fd = self.ipv4_fd, .events = posix.POLL.IN, .revents = 0 },
        };
        const ready = sys.poll(&fds, fds.len, @intCast(@min(self.recv_timeout_ms, std.math.maxInt(c_int))));
        if (ready <= 0) return null;
        for (0..2) |offset| {
            const idx = (offset + @as(usize, @intFromBool(self.prefer_ipv4))) % 2;
            if (fds[idx].fd < 0 or fds[idx].revents & posix.POLL.IN == 0) continue;
            var sa: posix.sockaddr.storage = undefined;
            var len: posix.socklen_t = @sizeOf(@TypeOf(sa));
            const rc = sys.recvfrom(fds[idx].fd, buf.ptr, buf.len, posix.MSG.DONTWAIT, @ptrCast(&sa), &len);
            if (posix.errno(rc) != .SUCCESS) continue;
            const n: usize = @intCast(rc);
            if (n > buf.len) return null;
            const from = if (sa.family == posix.AF.INET and len == @sizeOf(sys.sockaddr.in)) blk: {
                const v4: *const sys.sockaddr.in = @ptrCast(@alignCast(&sa));
                const bytes: [4]u8 = @bitCast(v4.addr);
                break :blk TransportAddress.fromBytes(&bytes, std.mem.bigToNative(u16, v4.port)) catch return null;
            } else if (sa.family == posix.AF.INET6 and len == @sizeOf(sys.sockaddr.in6))
                fromSockaddrIn6(@ptrCast(@alignCast(&sa))) catch return null
            else
                return null;
            self.prefer_ipv4 = idx == 0;
            return .{ .data = buf[0..n], .from = from };
        }
        return null;
    }
};

// ---------------------------------------------------------------------------
// sockaddr_in6 ⇄ TransportAddress mapping (pure; unit-tested without a socket)
// ---------------------------------------------------------------------------

/// True if `addr16` is an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`).
pub fn isV4Mapped(addr16: [16]u8) bool {
    return std.mem.eql(u8, addr16[0..12], &v4mapped_prefix);
}

/// Convert a source `sockaddr_in6` to a `TransportAddress`. An IPv4-mapped
/// source is surfaced as a 4-byte ipv4 address (so the REAL v4 address reaches
/// PROXY-protocol + logging); otherwise a 16-byte ipv6 address. Total over any
/// 16-byte address (the only failure path is the unreachable >16-byte case).
pub fn fromSockaddrIn6(sa: *const sys.sockaddr.in6) ice.IceError!TransportAddress {
    const port = std.mem.bigToNative(u16, sa.port);
    if (isV4Mapped(sa.addr)) {
        return TransportAddress.fromBytes(sa.addr[12..16], port);
    }
    return TransportAddress.fromBytes(&sa.addr, port);
}

/// Convert a `TransportAddress` to a `sockaddr_in6` for sending over the
/// dual-stack socket. A v4 address (`ip_len == 4`) is re-wrapped as a v4-mapped
/// `::ffff:a.b.c.d`; a v6 address (`ip_len == 16`) is copied verbatim. Returns
/// null for an unexpected `ip_len` (neither 4 nor 16) so a malformed address is
/// dropped rather than sent to a garbage destination.
pub fn toSockaddrIn6(addr: TransportAddress) ?sys.sockaddr.in6 {
    var out = sys.sockaddr.in6{
        .port = std.mem.nativeToBig(u16, addr.port),
        .flowinfo = 0,
        .addr = @as([16]u8, @splat(0)),
        .scope_id = 0,
    };
    switch (addr.ip_len) {
        4 => {
            @memcpy(out.addr[0..12], &v4mapped_prefix);
            @memcpy(out.addr[12..16], addr.ip[0..4]);
        },
        16 => @memcpy(&out.addr, addr.ip[0..16]),
        else => return null,
    }
    return out;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "isV4Mapped recognises ::ffff:0:0/96 and rejects native v6" {
    var mapped = @as([16]u8, @splat(0));
    @memcpy(mapped[0..12], &v4mapped_prefix);
    mapped[12..16].* = [_]u8{ 192, 0, 2, 7 };
    try testing.expect(isV4Mapped(mapped));

    // ::1 (loopback) is NOT v4-mapped.
    var v6 = @as([16]u8, @splat(0));
    v6[15] = 1;
    try testing.expect(!isV4Mapped(v6));

    // A global-unicast v6 address is not v4-mapped.
    const g = [_]u8{ 0x20, 0x01, 0x0d, 0xb8 } ++ @as([11]u8, @splat(0)) ++ [_]u8{1};
    try testing.expect(!isV4Mapped(g));
}

test "round-trip: a v4-mapped sockaddr_in6 surfaces as an ipv4 TransportAddress and back" {
    // Build a v4-mapped sockaddr_in6 for 203.0.113.9:4433.
    var sa = sys.sockaddr.in6{
        .port = std.mem.nativeToBig(u16, 4433),
        .flowinfo = 0,
        .addr = @as([16]u8, @splat(0)),
        .scope_id = 0,
    };
    @memcpy(sa.addr[0..12], &v4mapped_prefix);
    sa.addr[12..16].* = [_]u8{ 203, 0, 113, 9 };

    // recv path: surfaced as a 4-byte ipv4 address (NOT a v6 wrapper).
    const ta = try fromSockaddrIn6(&sa);
    try testing.expectEqual(@as(u8, 4), ta.ip_len);
    try testing.expectEqual(@as(u16, 4433), ta.port);
    try testing.expectEqualSlices(u8, &[_]u8{ 203, 0, 113, 9 }, ta.bytes());

    // send path: the ipv4 address re-wraps to the identical v4-mapped sockaddr.
    const back = toSockaddrIn6(ta) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(sa.port, back.port);
    try testing.expectEqual(@as(u32, 0), back.scope_id);
    try testing.expectEqual(@as(u32, 0), back.flowinfo);
    try testing.expectEqualSlices(u8, &sa.addr, &back.addr);
    try testing.expect(isV4Mapped(back.addr));
}

test "round-trip: a native v6 sockaddr_in6 surfaces as an ipv6 TransportAddress and back" {
    const v6 = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42 };
    var sa = sys.sockaddr.in6{
        .port = std.mem.nativeToBig(u16, 51820),
        .flowinfo = 0,
        .addr = v6,
        .scope_id = 0,
    };

    const ta = try fromSockaddrIn6(&sa);
    try testing.expectEqual(@as(u8, 16), ta.ip_len);
    try testing.expectEqual(@as(u16, 51820), ta.port);
    try testing.expectEqualSlices(u8, &v6, ta.bytes());

    const back = toSockaddrIn6(ta) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(sa.port, back.port);
    try testing.expectEqualSlices(u8, &v6, &back.addr);
    try testing.expect(!isV4Mapped(back.addr));
}

test "round-trip: ::1 loopback surfaces as a 16-byte ipv6 TransportAddress" {
    var v6 = @as([16]u8, @splat(0));
    v6[15] = 1;
    var sa = sys.sockaddr.in6{
        .port = std.mem.nativeToBig(u16, 9000),
        .flowinfo = 0,
        .addr = v6,
        .scope_id = 0,
    };
    const ta = try fromSockaddrIn6(&sa);
    try testing.expectEqual(@as(u8, 16), ta.ip_len);
    try testing.expectEqualSlices(u8, &v6, ta.bytes());
    const back = toSockaddrIn6(ta) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, &v6, &back.addr);
}

test "toSockaddrIn6 drops a TransportAddress with an unexpected ip_len" {
    var bad: TransportAddress = .{};
    bad.ip_len = 7; // neither 4 nor 16
    try testing.expect(toSockaddrIn6(bad) == null);
}

test "dualstack socket: bind on [::], ephemeral port, clean shutdown, v4 receive" {
    // `bindNative` has no Windows support (`SOCK_CLOEXEC`); skip there.
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    // The server binds [::]:0 (dual-stack). An IPv4 loopback client must reach it
    // as a v4-mapped source surfaced as an ipv4 TransportAddress.
    var server = DualStackUdpSocket.bind(.any, 0) catch return error.SkipZigTest;
    defer server.deinit();
    server.setRecvTimeoutMs(2000);
    const sport = try server.localPort();
    try testing.expect(sport != 0);

    // --- IPv4 leg: send from a real 127.0.0.1 UDP socket. ---
    const c4_rc = sys.socket(posix.AF.INET, sys.SOCK.DGRAM | sys.SOCK.CLOEXEC, sys.IPPROTO.UDP);
    try testing.expectEqual(posix.E.SUCCESS, posix.errno(c4_rc));
    const c4: sys.fd_t = @intCast(c4_rc);
    defer _ = sys.close(c4);
    var c4_addr = sys.sockaddr.in{ .port = 0, .addr = std.mem.nativeToBig(u32, 0x7f00_0001) };
    try testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.bind(c4, @ptrCast(&c4_addr), @sizeOf(sys.sockaddr.in))));
    var c4_sa: sys.sockaddr.in = undefined;
    var c4_slen: posix.socklen_t = @sizeOf(sys.sockaddr.in);
    _ = sys.getsockname(c4, @ptrCast(&c4_sa), &c4_slen);
    const c4_port = std.mem.bigToNative(u16, c4_sa.port);

    // 127.0.0.1:sport as a sockaddr_in (the v4 client addresses the v4 world).
    var dst4 = sys.sockaddr.in{
        .port = std.mem.nativeToBig(u16, sport),
        .addr = std.mem.nativeToBig(u32, 0x7f00_0001),
    };
    const payload4 = "v4-hello";
    _ = sys.sendto(c4, payload4, payload4.len, 0, @ptrCast(&dst4), @sizeOf(sys.sockaddr.in));

    var buf: [64]u8 = undefined;
    const got4 = server.recvFrom(&buf) orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings(payload4, got4.data);
    // The v4 client surfaces as an IPV4 TransportAddress (real 127.0.0.1), not v6.
    try testing.expectEqual(@as(u8, 4), got4.from.ip_len);
    try testing.expectEqualSlices(u8, &[_]u8{ 127, 0, 0, 1 }, got4.from.bytes());
    try testing.expectEqual(c4_port, got4.from.port);

    // Reply via sendTo (ipv4 dest → v4-mapped over the dual-stack socket).
    server.sendTo(got4.from, "v4-reply");
    var rbuf: [64]u8 = undefined;
    // Bound the client recv so the test can't hang.
    const tv = sys.timeval{ .sec = 2, .usec = 0 };
    _ = sys.setsockopt(c4, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(sys.timeval));
    const rn4 = sys.recvfrom(c4, &rbuf, rbuf.len, 0, null, null);
    try testing.expectEqual(posix.E.SUCCESS, posix.errno(rn4));
    try testing.expectEqualStrings("v4-reply", rbuf[0..@intCast(rn4)]);
}

test "dualstack socket: IPv6 loopback receive (skips if no v6 loopback)" {
    // `bindNative` has no Windows support (`SOCK_CLOEXEC`); skip there.
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    var server = DualStackUdpSocket.bind(.any, 0) catch return error.SkipZigTest;
    defer server.deinit();
    server.setRecvTimeoutMs(2000);
    const sport = try server.localPort();

    // --- IPv6 leg: send from a real ::1 UDP socket. If the sandbox lacks IPv6
    // loopback, gracefully skip THIS leg only (the v4-over-v6-socket leg above
    // and the pure mapping tests still hold coverage). ---
    const c6_rc = sys.socket(posix.AF.INET6, sys.SOCK.DGRAM | sys.SOCK.CLOEXEC, sys.IPPROTO.UDP);
    if (posix.errno(c6_rc) != .SUCCESS) return error.SkipZigTest;
    const c6: sys.fd_t = @intCast(c6_rc);
    defer _ = sys.close(c6);
    var lo6 = @as([16]u8, @splat(0));
    lo6[15] = 1; // ::1
    var c6_bind = sys.sockaddr.in6{ .port = 0, .flowinfo = 0, .addr = lo6, .scope_id = 0 };
    if (posix.errno(sys.bind(c6, @ptrCast(&c6_bind), @sizeOf(sys.sockaddr.in6))) != .SUCCESS)
        return error.SkipZigTest;

    var dst6 = sys.sockaddr.in6{
        .port = std.mem.nativeToBig(u16, sport),
        .flowinfo = 0,
        .addr = lo6,
        .scope_id = 0,
    };
    const payload6 = "v6-hello";
    const sn = sys.sendto(c6, payload6, payload6.len, 0, @ptrCast(&dst6), @sizeOf(sys.sockaddr.in6));
    if (posix.errno(sn) != .SUCCESS) return error.SkipZigTest;

    var buf: [64]u8 = undefined;
    const got6 = server.recvFrom(&buf) orelse return error.SkipZigTest;
    try testing.expectEqualStrings(payload6, got6.data);
    // The v6 client surfaces as a 16-byte IPV6 TransportAddress (::1).
    try testing.expectEqual(@as(u8, 16), got6.from.ip_len);
    try testing.expectEqualSlices(u8, &lo6, got6.from.bytes());

    // Reply via sendTo (ipv6 dest copied verbatim).
    server.sendTo(got6.from, "v6-reply");
    const tv = sys.timeval{ .sec = 2, .usec = 0 };
    _ = sys.setsockopt(c6, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(sys.timeval));
    var rbuf: [64]u8 = undefined;
    const rn6 = sys.recvfrom(c6, &rbuf, rbuf.len, 0, null, null);
    if (posix.errno(rn6) != .SUCCESS) return error.SkipZigTest;
    try testing.expectEqualStrings("v6-reply", rbuf[0..@intCast(rn6)]);
}

test "dualstack socket: native paired families share a port and preserve both queued datagrams" {
    if (comptime builtin.os.tag != .openbsd) return;
    var server = try DualStackUdpSocket.bind(.any, 0);
    defer server.deinit();
    server.setRecvTimeoutMs(100);
    try testing.expect(server.ipv4_fd >= 0);
    var bound4: sys.sockaddr.in = undefined;
    var length: posix.socklen_t = @sizeOf(@TypeOf(bound4));
    try testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.getsockname(server.ipv4_fd, @ptrCast(&bound4), &length)));
    const port = try server.localPort();
    try testing.expectEqual(port, std.mem.bigToNative(u16, bound4.port));
    for ([_]sys.fd_t{ server.fd, server.ipv4_fd }) |fd| {
        const descriptor_flags = sys.fcntl(fd, posix.F.GETFD, @as(c_int, 0));
        try testing.expectEqual(posix.E.SUCCESS, posix.errno(descriptor_flags));
        try testing.expect(descriptor_flags & posix.FD_CLOEXEC != 0);
        const status = sys.fcntl(fd, posix.F.GETFL, @as(c_int, 0));
        try testing.expectEqual(posix.E.SUCCESS, posix.errno(status));
        const options: posix.O = @bitCast(@as(u32, @intCast(status)));
        try testing.expect(options.NONBLOCK);
    }
    var client4 = try DualStackUdpSocket.bind(.{ .v4_mapped = .{ 127, 0, 0, 1 } }, 0);
    defer client4.deinit();
    client4.setRecvTimeoutMs(100);
    var client6 = try DualStackUdpSocket.bind(.loopback_v6, 0);
    defer client6.deinit();
    client6.setRecvTimeoutMs(100);
    var loopback6: [16]u8 = @splat(0);
    loopback6[15] = 1;
    client4.sendTo(try TransportAddress.fromBytes(&.{ 127, 0, 0, 1 }, port), "four");
    client6.sendTo(try TransportAddress.fromBytes(&loopback6, port), "six");
    var buf: [32]u8 = undefined;
    var seen4 = false;
    var seen6 = false;
    for (0..2) |_| {
        const got = server.recvFrom(&buf) orelse return error.TestUnexpectedResult;
        switch (got.from.ip_len) {
            4 => {
                try testing.expect(!seen4);
                try testing.expectEqualStrings("four", got.data);
                seen4 = true;
            },
            16 => {
                try testing.expect(!seen6);
                try testing.expectEqualStrings("six", got.data);
                seen6 = true;
            },
            else => return error.TestUnexpectedResult,
        }
        server.sendTo(got.from, got.data);
    }
    try testing.expect(seen4 and seen6);
    try testing.expectEqualStrings("four", (client4.recvFrom(&buf) orelse return error.TestUnexpectedResult).data);
    try testing.expectEqualStrings("six", (client6.recvFrom(&buf) orelse return error.TestUnexpectedResult).data);
    const before = @import("../substrate/platform.zig").monotonicMillis();
    try testing.expect(server.recvFrom(&buf) == null);
    const elapsed = @import("../substrate/platform.zig").monotonicMillis() - before;
    try testing.expect(elapsed >= 50 and elapsed < 1000);
}

/// Kernel observations only. Authenticated transfer and predecessor inventory
/// establish same-OFD lineage; equal socket metadata alone cannot prove it.
pub const DatagramObservation = struct {
    device: u64,
    inode: u64,
    family: u16,
    address: [16]u8,
    port: u16,
    scope_id: u32,
    flowinfo: u32,
    v6only: bool,
    pub fn validate(self: *const DatagramObservation) !void {
        if (self.port == 0 or (self.family != posix.AF.INET and self.family != posix.AF.INET6)) return error.InvalidSocket;
        if (self.family == posix.AF.INET) {
            for (self.address[4..]) |byte| if (byte != 0) return error.InvalidSocket;
            if (self.scope_id != 0 or self.flowinfo != 0 or self.v6only) return error.InvalidSocket;
        } else if (self.scope_id != 0 or self.flowinfo != 0) return error.InvalidSocket;
    }
};
/// Endpoint and descriptor observations, not an inherited-custody receipt.
/// A zero inode explicitly means that the platform supplies no socket identity.
pub const Snapshot = struct {
    primary: DatagramObservation,
    ipv4: ?DatagramObservation,
    primary_ipv4: bool,
    recv_timeout_ms: u32,
    prefer_ipv4: bool,
    pub fn validate(self: *const Snapshot) !void {
        try self.primary.validate();
        if (self.recv_timeout_ms == 0 or self.recv_timeout_ms > std.math.maxInt(c_int) or self.primary_ipv4 != (self.primary.family == posix.AF.INET)) return error.InvalidSocket;
        if (self.ipv4) |*other| {
            try other.validate();
            if (self.primary_ipv4 or !self.primary.v6only or other.family != posix.AF.INET or other.port != self.primary.port or (other.inode != 0 and other.device == self.primary.device and other.inode == self.primary.inode)) return error.InvalidSocket;
            // Only .any creates a native two-family pair.
            for (self.primary.address) |byte| if (byte != 0) return error.InvalidSocket;
            for (other.address) |byte| if (byte != 0) return error.InvalidSocket;
        }
    }
};
fn identityBits(value: anytype) u64 {
    return @intCast(@as(@Int(.unsigned, @bitSizeOf(@TypeOf(value))), @bitCast(value)));
}
fn observeDatagram(fd: posix.fd_t) !DatagramObservation {
    var typ: c_int = 0;
    var len: posix.socklen_t = @sizeOf(c_int);
    if (posix.errno(sys.getsockopt(fd, posix.SOL.SOCKET, posix.SO.TYPE, std.mem.asBytes(&typ), &len)) != .SUCCESS or len != @sizeOf(c_int) or typ != posix.SOCK.DGRAM) return error.InvalidSocket;
    const arg: if (builtin.os.tag == .linux) usize else c_int = 0;
    const flags = sys.fcntl(fd, posix.F.GETFL, arg);
    if (posix.errno(flags) != .SUCCESS or !@as(posix.O, @bitCast(@as(u32, @intCast(flags)))).NONBLOCK) return error.InvalidSocket;
    const fdflags = sys.fcntl(fd, posix.F.GETFD, arg);
    if (posix.errno(fdflags) != .SUCCESS or (fdflags & posix.FD_CLOEXEC) == 0) return error.InvalidSocket;
    var address: posix.sockaddr.storage = undefined;
    len = @sizeOf(@TypeOf(address));
    if (posix.errno(sys.getsockname(fd, @ptrCast(&address), &len)) != .SUCCESS) return error.InvalidSocket;
    var result: DatagramObservation = .{ .device = 0, .inode = 0, .family = address.family, .address = @splat(0), .port = 0, .scope_id = 0, .flowinfo = 0, .v6only = false };
    if (address.family == posix.AF.INET and len == @sizeOf(posix.sockaddr.in)) {
        const sa: *const posix.sockaddr.in = @ptrCast(@alignCast(&address));
        @memcpy(result.address[0..4], &@as([4]u8, @bitCast(sa.addr)));
        result.port = std.mem.bigToNative(u16, sa.port);
    } else if (address.family == posix.AF.INET6 and len == @sizeOf(posix.sockaddr.in6)) {
        const sa: *const posix.sockaddr.in6 = @ptrCast(@alignCast(&address));
        result.address = sa.addr;
        result.port = std.mem.bigToNative(u16, sa.port);
        result.scope_id = sa.scope_id;
        result.flowinfo = sa.flowinfo;
        var only: c_int = 0;
        len = @sizeOf(c_int);
        if (posix.errno(sys.getsockopt(fd, posix.IPPROTO.IPV6, ipv6V6Only(), std.mem.asBytes(&only), &len)) != .SUCCESS or len != @sizeOf(c_int) or (only != 0 and only != 1)) return error.InvalidSocket;
        result.v6only = only == 1;
    } else return error.InvalidSocket;
    if (comptime builtin.os.tag == .linux) {
        var stat: std.os.linux.Statx = std.mem.zeroes(std.os.linux.Statx);
        if (posix.errno(std.os.linux.statx(fd, "", std.os.linux.AT.EMPTY_PATH, .{ .TYPE = true, .INO = true }, &stat)) != .SUCCESS or !stat.mask.TYPE or !stat.mask.INO or (stat.mode & posix.S.IFMT) != posix.S.IFSOCK) return error.InvalidSocket;
        result.device = (@as(u64, stat.dev_major) << 32) | stat.dev_minor;
        result.inode = stat.ino;
    } else {
        var stat: posix.Stat = undefined;
        if (posix.errno(sys.fstat(fd, &stat)) != .SUCCESS or (stat.mode & posix.S.IFMT) != posix.S.IFSOCK) return error.InvalidSocket;
        result.device = identityBits(stat.dev);
        result.inode = identityBits(stat.ino);
    }
    try result.validate();
    return result;
}

test "companion runtime dualstack native pair exact inherited custody and live OLD traffic" {
    // Direct `bindNative`/`capture` use; no Windows support (`SOCK_CLOEXEC`).
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    // Exercise the native pair algorithm on Linux too, rather than relying on
    // the mapped one-FD implementation to stand in for native pair custody.
    var owner = try DualStackUdpSocket.bindNative(.any, 0);
    defer owner.deinit();
    owner.setRecvTimeoutMs(200);
    owner.prefer_ipv4 = true;
    var carry = try owner.capture();
    try std.testing.expect(carry.ipv4 != null);
    const arg: if (builtin.os.tag == .linux) usize else c_int = 0;
    const fd = sys.fcntl(owner.fd, (if (@import("builtin").os.tag == .openbsd) @as(c_int, 10) else std.posix.F.DUPFD_CLOEXEC), arg);
    try std.testing.expect(posix.errno(fd) == .SUCCESS);
    const fd4 = sys.fcntl(owner.ipv4_fd, (if (@import("builtin").os.tag == .openbsd) @as(c_int, 10) else std.posix.F.DUPFD_CLOEXEC), arg);
    if (posix.errno(fd4) != .SUCCESS) {
        _ = sys.close(@intCast(fd));
        return error.TestUnexpectedResult;
    }
    if (carry.primary.inode == 0 or carry.ipv4.?.inode == 0) {
        try std.testing.expectError(error.UnverifiableSocketIdentity, DualStackUdpSocket.initInherited(@intCast(fd), @intCast(fd4), &carry));
        try std.testing.expect(posix.errno(sys.fcntl(@intCast(fd), posix.F.GETFD, arg)) != .SUCCESS);
        try std.testing.expect(posix.errno(sys.fcntl(@intCast(fd4), posix.F.GETFD, arg)) != .SUCCESS);
    } else {
        var adopted = try DualStackUdpSocket.initInherited(@intCast(fd), @intCast(fd4), &carry);
        try std.testing.expect(adopted.prefer_ipv4);
        adopted.deinit();
    }
    try std.testing.expectEqualDeep(carry, try owner.capture());
    const bad = sys.fcntl(owner.fd, (if (@import("builtin").os.tag == .openbsd) @as(c_int, 10) else std.posix.F.DUPFD_CLOEXEC), arg);
    try std.testing.expect(posix.errno(bad) == .SUCCESS);
    const bad4 = sys.fcntl(owner.ipv4_fd, (if (@import("builtin").os.tag == .openbsd) @as(c_int, 10) else std.posix.F.DUPFD_CLOEXEC), arg);
    if (posix.errno(bad4) != .SUCCESS) {
        _ = sys.close(@intCast(bad));
        return error.TestUnexpectedResult;
    }
    carry.ipv4.?.inode ^= std.math.maxInt(u64);
    try std.testing.expectError(error.SocketMismatch, DualStackUdpSocket.initInherited(@intCast(bad), @intCast(bad4), &carry));
    try std.testing.expect(posix.errno(sys.fcntl(@intCast(bad), posix.F.GETFD, arg)) != .SUCCESS);
    try std.testing.expect(posix.errno(sys.fcntl(@intCast(bad4), posix.F.GETFD, arg)) != .SUCCESS);
    carry.ipv4.?.inode ^= std.math.maxInt(u64);
    var sender = try DualStackUdpSocket.bindNative(.any, 0);
    defer sender.deinit();
    sender.sendTo(try TransportAddress.fromBytes(&.{ 127, 0, 0, 1 }, carry.primary.port), "v4 alive");
    var address: [16]u8 = @splat(0);
    address[15] = 1;
    var buf: [64]u8 = undefined;
    const first = owner.recvFrom(&buf) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, "v4 alive", first.data);
    try std.testing.expectEqual(@as(u8, 4), first.from.ip_len);
    sender.sendTo(try TransportAddress.fromBytes(&address, carry.primary.port), "v6 alive");
    const second = owner.recvFrom(&buf) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, "v6 alive", second.data);
    try std.testing.expectEqual(@as(u8, 16), second.from.ip_len);
}

test "companion runtime native socket observation refuses a rebound endpoint as original custody" {
    // Direct `bindNative` use; no Windows support (`SOCK_CLOEXEC`).
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const loopback = DualStackUdpSocket.BindAddr{ .v4_mapped = .{ 127, 0, 0, 1 } };
    const carry = blk: {
        var original = try DualStackUdpSocket.bindNative(loopback, 0);
        defer original.deinit();
        break :blk try original.capture();
    };
    // The original description is gone. A newly bound socket can repeat every
    // endpoint observation, but must never acquire its predecessor's custody.
    var replacement = try DualStackUdpSocket.bindNative(loopback, carry.primary.port);
    defer replacement.deinit();
    const arg: if (builtin.os.tag == .linux) usize else c_int = 0;
    const fd = sys.fcntl(replacement.fd, (if (builtin.os.tag == .openbsd) @as(c_int, 10) else posix.F.DUPFD_CLOEXEC), arg);
    try std.testing.expect(posix.errno(fd) == .SUCCESS);
    try std.testing.expectError(if (carry.primary.inode == 0) error.UnverifiableSocketIdentity else error.SocketMismatch, DualStackUdpSocket.initInherited(@intCast(fd), null, &carry));
    try std.testing.expect(posix.errno(sys.fcntl(@intCast(fd), posix.F.GETFD, arg)) != .SUCCESS);
    try std.testing.expectEqual(carry.primary.port, try replacement.localPort());
}
