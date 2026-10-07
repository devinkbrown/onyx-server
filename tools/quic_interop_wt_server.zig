// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Standalone WebTransport interop test server for a REAL browser (Chromium).
//!
//! Where `quic_interop_server.zig` proves the QUIC + HTTP/3 path against
//! `curl --http3`, this binary proves the WebTransport-specific path against
//! Chrome's actual WebTransport API: Extended CONNECT (`:protocol=webtransport`),
//! WT bidi streams, and WT datagrams. curl cannot speak Extended CONNECT, so a
//! real browser is the only way to exercise this leg.
//!
//! Chrome's `serverCertificateHashes` lets a page connect to a self-signed
//! server WITHOUT a CA, but ONLY if the leaf cert is ECDSA P-256, its validity
//! window is <= 14 days, and the page is given the SHA-256 of the cert DER. So
//! this server mints exactly that cert (Ed25519 — the default interop cert —
//! would be rejected by Chrome's serverCertificateHashes path).
//!
//! Bridge target: the listener bridges the client's first WT bidi stream to a
//! TCP target on `127.0.0.1:<port>`, proxying raw bytes both ways. Two modes:
//!
//!   * DEFAULT (no `ONYX_WT_BRIDGE_PORT`): spawn a tiny in-process loopback TCP
//!     echo server and point the bridge at it, so bytes the browser writes on the
//!     WT bidi stream round-trip back byte-exact. This is the echo-interop lane
//!     (`tools/quic_interop_browser.{mjs,sh}`).
//!   * `ONYX_WT_BRIDGE_PORT=<P>` (env): point the bridge at an already-running
//!     TCP server on `127.0.0.1:<P>` instead of the in-process echo. The IRC
//!     interop lane (`tools/quic_interop_irc_browser.{mjs,sh}`) starts a REAL
//!     onyx IRC daemon on a plaintext loopback port and passes that port here,
//!     so the browser registers as a genuine IRC client. (An env var, not an
//!     argv flag: Zig 0.16 has no `std.os.argv`/arg iterator on the no-libc Linux
//!     target this harness builds for.)
//!
//! WT datagrams are echoed by the listener's `echo_wt_datagrams` interop mode
//! (received WT datagram -> re-queued back to the peer). In `ONYX_WT_BRIDGE_PORT`
//! (IRC) mode datagram echo is OFF — IRC rides the reliable bidi stream, and the
//! IRC harness never exercises the datagram leg.
//!
//! Output contract (read by `tools/quic_interop_browser.mjs`):
//!   * `PORT=<udp>\n`      — the bound UDP port (bind is 127.0.0.1 only).
//!   * `CERTHASH=<hex>\n`  — lowercase hex SHA-256 of the leaf cert DER.
//!   * `CERTHASHB64=<b64>\n`— standard base64 of the same 32-byte hash.
//!   Then it blocks until killed.

const std = @import("std");
const builtin = @import("builtin");
const onyx_server = @import("onyx_server");

const WebTransportListener = onyx_server.daemon.webtransport_listener.WebTransportListener;
const x509_selfsign = onyx_server.proto.x509_selfsign;
const ecdsa_p256 = onyx_server.crypto.ecdsa_p256;
const Sha256 = std.crypto.hash.sha2.Sha256;

const linux = std.os.linux;
const posix = std.posix;
const TcpSocket = if (builtin.os.tag == .windows) usize else linux.fd_t;

const win = struct {
    const invalid_socket = std.math.maxInt(usize);
    const SockAddr4 = extern struct {
        family: u16,
        port: u16,
        addr: [4]u8,
        zero: [8]u8 = @splat(0),
    };
    comptime {
        if (@sizeOf(SockAddr4) != 16) @compileError("Windows TCP socket ABI shape changed");
    }
    extern "ws2_32" fn WSAStartup(version: u16, data: *anyopaque) callconv(.winapi) i32;
    extern "ws2_32" fn WSACleanup() callconv(.winapi) i32;
    extern "ws2_32" fn WSAGetLastError() callconv(.winapi) i32;
    extern "ws2_32" fn WSASocketW(family: i32, kind: i32, protocol: i32, info: ?*anyopaque, group: u32, flags: u32) callconv(.winapi) usize;
    extern "ws2_32" fn closesocket(socket: usize) callconv(.winapi) i32;
    extern "ws2_32" fn setsockopt(socket: usize, level: i32, option: i32, value: *const anyopaque, len: i32) callconv(.winapi) i32;
    extern "ws2_32" fn bind(socket: usize, address: *const SockAddr4, len: i32) callconv(.winapi) i32;
    extern "ws2_32" fn listen(socket: usize, backlog: i32) callconv(.winapi) i32;
    extern "ws2_32" fn getsockname(socket: usize, address: *SockAddr4, len: *i32) callconv(.winapi) i32;
    extern "ws2_32" fn accept(socket: usize, address: ?*SockAddr4, len: ?*i32) callconv(.winapi) usize;
    extern "ws2_32" fn recv(socket: usize, bytes: [*]u8, len: i32, flags: i32) callconv(.winapi) i32;
    extern "ws2_32" fn send(socket: usize, bytes: [*]const u8, len: i32, flags: i32) callconv(.winapi) i32;
    extern "kernel32" fn Sleep(milliseconds: u32) callconv(.winapi) void;
    extern "kernel32" fn GetStdHandle(which: u32) callconv(.winapi) usize;
    extern "kernel32" fn WriteFile(handle: usize, bytes: [*]const u8, len: u32, written: *u32, overlapped: ?*anyopaque) callconv(.winapi) i32;
    extern "kernel32" fn GetEnvironmentVariableW(name: [*:0]const u16, value: [*]u16, size: u32) callconv(.winapi) u32;
};

/// Validity window for Chrome's serverCertificateHashes: must be <= 14 days
/// (~1209600 s). We use ~12 days and set not_before ~1h in the past for clock
/// skew, keeping the whole window comfortably under the cap.
const cert_skew_back_s: i64 = 3600;
const cert_validity_s: i64 = 12 * 24 * 3600;

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // --- 1. Mint a fresh ECDSA P-256 short-validity leaf cert. ---------------
    var seed: [ecdsa_p256.KeyPair.seed_length]u8 = undefined;
    try osEntropy(&seed);
    const kp = try ecdsa_p256.KeyPair.generateDeterministic(seed);

    const now: i64 = try wallClockSeconds();
    const not_before = now - cert_skew_back_s;
    const not_after = now + cert_validity_s;

    var cert_buf: [1024]u8 = undefined;
    const cert = try x509_selfsign.buildSelfSignedEcdsaP256(&cert_buf, .{
        .common_name = "localhost",
        .not_before = not_before,
        .not_after = not_after,
        .serial = &.{ 0x51, 0x9a },
        .key_pair = kp,
        .dns_names = &.{"localhost"},
        // 127.0.0.1 as an iPAddress SAN so the browser's hostname check passes.
        .ip_addresses = &.{&[_]u8{ 127, 0, 0, 1 }},
        .is_ca = false,
    });
    const cert_chain = [_][]const u8{cert};

    // SHA-256 over the cert DER — exactly what Chrome hashes for the
    // serverCertificateHashes match.
    var hash: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(cert, &hash, .{});

    // --- 2. Decide the WT bidi bridge target. --------------------------------
    // `--bridge-port <P>` / `ONYX_WT_BRIDGE_PORT` points the bridge at an
    // already-running TCP server on 127.0.0.1:<P> (the IRC daemon). Absent it, we
    // spawn the in-process echo server (default echo-interop lane).
    const bridge_port_opt = try bridgePortArg();
    const bridge_port = bridge_port_opt orelse try startTcpEchoServer(allocator);

    // --- 3. Stand up the real WebTransport listener. -------------------------
    var listener = WebTransportListener.init(allocator, .{
        .cert_chain = &cert_chain,
        .signing_key = .{ .ecdsa_p256 = kp },
    }, bridge_port);
    defer listener.deinit();
    // Interop datagram-echo: received WT datagrams are reflected to the peer.
    // Only meaningful for the in-process echo lane; the IRC bridge carries stream
    // bytes, not datagrams, so leave it off when bridging to a real target.
    listener.echo_wt_datagrams = (bridge_port_opt == null);

    // Bind 127.0.0.1 only (the browser connects to https://127.0.0.1:<port>).
    const loopback_be: u32 = std.mem.nativeToBig(u32, 0x7f00_0001);
    listener.start(loopback_be, 0) catch |err| {
        std.debug.print("quic_interop_wt_server: bind failed: {s}\n", .{@errorName(err)});
        return err;
    };

    // --- 4. Announce PORT + CERTHASH on stdout. ------------------------------
    var out_buf: [256]u8 = undefined;
    {
        const line = std.fmt.bufPrint(&out_buf, "PORT={d}\n", .{listener.port}) catch unreachable;
        writeAll(1, line);
    }
    {
        var hex_buf: [Sha256.digest_length * 2]u8 = undefined;
        const hex = std.fmt.bufPrint(&hex_buf, "{x}", .{&hash}) catch unreachable;
        const line = std.fmt.bufPrint(&out_buf, "CERTHASH={s}\n", .{hex}) catch unreachable;
        writeAll(1, line);
    }
    {
        const Enc = std.base64.standard.Encoder;
        var b64_buf: [Enc.calcSize(Sha256.digest_length)]u8 = undefined;
        const b64 = Enc.encode(&b64_buf, &hash);
        const line = std.fmt.bufPrint(&out_buf, "CERTHASHB64={s}\n", .{b64}) catch unreachable;
        writeAll(1, line);
    }

    // --- 5. Block forever; the harness kills us when done. -------------------
    while (true) {
        if (comptime builtin.os.tag == .windows) {
            win.Sleep(60_000);
        } else {
            var req = linux.timespec{ .sec = 60, .nsec = 0 };
            _ = linux.nanosleep(&req, &req);
        }
    }
}

// ---------------------------------------------------------------------------
// Loopback TCP echo server (bridge target)
// ---------------------------------------------------------------------------

/// Bind a TCP socket on 127.0.0.1:0, spawn a detached accept/echo loop, and
/// return the chosen port. Each accepted connection is echoed byte-for-byte
/// until the peer closes. Single-threaded per connection is fine: there is at
/// most one bridge per QUIC connection and the harness drives one session.
fn startTcpEchoServer(allocator: std.mem.Allocator) !u16 {
    if (comptime builtin.os.tag == .windows) {
        var startup: [408]u8 align(8) = @splat(0);
        if (win.WSAStartup(0x0202, &startup) != 0) return error.SocketFailed;
        errdefer _ = win.WSACleanup();
        const fd = win.WSASocketW(2, 1, 6, null, 0, 1);
        if (fd == win.invalid_socket) return error.SocketFailed;
        errdefer _ = win.closesocket(fd);
        const exclusive: i32 = 1;
        if (win.setsockopt(fd, 0xffff, ~@as(i32, 0x0004), &exclusive, @sizeOf(i32)) != 0) return error.SocketFailed;
        const addr = win.SockAddr4{ .family = 2, .port = 0, .addr = .{ 127, 0, 0, 1 } };
        if (win.bind(fd, &addr, @sizeOf(win.SockAddr4)) != 0) return error.BindFailed;
        if (win.listen(fd, 16) != 0) return error.ListenFailed;
        var bound: win.SockAddr4 = undefined;
        var slen: i32 = @sizeOf(win.SockAddr4);
        if (win.getsockname(fd, &bound, &slen) != 0 or slen != @sizeOf(win.SockAddr4)) return error.GetSockNameFailed;
        const t = try std.Thread.spawn(.{}, echoAcceptLoop, .{fd});
        t.detach();
        _ = allocator;
        return std.mem.bigToNative(u16, bound.port);
    }
    const rc = linux.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, linux.IPPROTO.TCP);
    if (posix.errno(rc) != .SUCCESS) return error.SocketFailed;
    const fd: linux.fd_t = @intCast(rc);

    const one: u32 = 1;
    _ = linux.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, @ptrCast(&one), @sizeOf(u32));

    var addr = linux.sockaddr.in{
        .port = 0, // ephemeral
        .addr = std.mem.nativeToBig(u32, 0x7f00_0001), // 127.0.0.1
    };
    if (posix.errno(linux.bind(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in))) != .SUCCESS) {
        _ = linux.close(fd);
        return error.BindFailed;
    }
    if (posix.errno(linux.listen(fd, 16)) != .SUCCESS) {
        _ = linux.close(fd);
        return error.ListenFailed;
    }

    // Read back the bound port.
    var bound: linux.sockaddr.in = undefined;
    var slen: posix.socklen_t = @sizeOf(linux.sockaddr.in);
    if (posix.errno(linux.getsockname(fd, @ptrCast(&bound), &slen)) != .SUCCESS) {
        _ = linux.close(fd);
        return error.GetSockNameFailed;
    }
    const port = std.mem.bigToNative(u16, bound.port);

    const t = try std.Thread.spawn(.{}, echoAcceptLoop, .{fd});
    t.detach();
    _ = allocator; // no per-thread allocation needed
    return port;
}

fn echoAcceptLoop(listen_fd: TcpSocket) void {
    while (true) {
        if (comptime builtin.os.tag == .windows) {
            const conn_fd = win.accept(listen_fd, null, null);
            if (conn_fd == win.invalid_socket) {
                win.Sleep(1);
                continue;
            }
            echoConnLoop(conn_fd);
            _ = win.closesocket(conn_fd);
            continue;
        }
        const arc = linux.accept(listen_fd, null, null);
        if (posix.errno(arc) != .SUCCESS) {
            // Transient accept error: yield and retry.
            var req = linux.timespec{ .sec = 0, .nsec = 1_000_000 };
            _ = linux.nanosleep(&req, &req);
            continue;
        }
        const conn_fd: linux.fd_t = @intCast(arc);
        echoConnLoop(conn_fd);
        _ = linux.close(conn_fd);
    }
}

fn echoConnLoop(fd: TcpSocket) void {
    var buf: [4096]u8 = undefined;
    while (true) {
        if (comptime builtin.os.tag == .windows) {
            const n = win.recv(fd, &buf, buf.len, 0);
            if (n < 0 and win.WSAGetLastError() == 10004) continue;
            if (n <= 0) return;
            if (!writeAllFd(fd, buf[0..@intCast(n)])) return;
            continue;
        }
        const rc = linux.read(fd, &buf, buf.len);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                const n: usize = @intCast(rc);
                if (n == 0) return; // peer closed
                if (!writeAllFd(fd, buf[0..n])) return;
            },
            .INTR => continue,
            else => return,
        }
    }
}

fn writeAllFd(fd: TcpSocket, bytes: []const u8) bool {
    var sent: usize = 0;
    while (sent < bytes.len) {
        if (comptime builtin.os.tag == .windows) {
            const n = win.send(fd, bytes[sent..].ptr, @intCast(@min(bytes.len - sent, std.math.maxInt(i32))), 0);
            if (n < 0 and win.WSAGetLastError() == 10004) continue;
            if (n <= 0) return false;
            sent += @intCast(n);
            continue;
        }
        const rc = linux.write(fd, bytes.ptr + sent, bytes.len - sent);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                const n: usize = @intCast(rc);
                if (n == 0) return false;
                sent += n;
            },
            .INTR => continue,
            else => return false,
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
// Small OS helpers
// ---------------------------------------------------------------------------

fn writeAll(fd: i32, bytes: []const u8) void {
    var sent: usize = 0;
    while (sent < bytes.len) {
        if (comptime builtin.os.tag == .windows) {
            const handle = win.GetStdHandle(if (fd == 2) @as(u32, @bitCast(@as(i32, -12))) else @as(u32, @bitCast(@as(i32, -11))));
            var written: u32 = 0;
            if (win.WriteFile(handle, bytes[sent..].ptr, @intCast(@min(bytes.len - sent, std.math.maxInt(u32))), &written, null) == 0 or written == 0) return;
            sent += written;
            continue;
        }
        const rc = std.os.linux.write(fd, bytes.ptr + sent, bytes.len - sent);
        const signed: isize = @bitCast(rc);
        if (signed <= 0) return;
        sent += rc;
    }
}

/// Wall-clock seconds since the Unix epoch, used to anchor cert validity.
fn wallClockSeconds() !i64 {
    if (comptime builtin.os.tag == .windows) {
        const millis = onyx_server.substrate.platform.realtimeMillisChecked() orelse return error.ClockUnavailable;
        return @divTrunc(millis, 1000);
    }
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(linux.CLOCK.REALTIME, &ts);
    return @intCast(ts.sec);
}

/// Resolve the optional bridge target port from the `ONYX_WT_BRIDGE_PORT`
/// environment variable; null means "use the in-process echo". The port must
/// parse as a non-zero u16. Zig 0.16 dropped `std.os.environ`/`getEnvVarOwned`
/// on a no-libc Linux target (this harness builds without libc), so we read the
/// raw `/proc/self/environ` blob (NUL-separated `KEY=VALUE` records) exactly as
/// `webtransport_listener.zig` does — no allocation, bounded buffer. Windows
/// reads the same variable through its native UTF-16 process environment.
fn bridgePortArg() !?u16 {
    if (comptime builtin.os.tag == .windows) {
        var wide: [256]u16 = undefined;
        const n = win.GetEnvironmentVariableW(std.unicode.utf8ToUtf16LeStringLiteral("ONYX_WT_BRIDGE_PORT"), &wide, wide.len);
        if (n == 0) return null;
        if (n >= wide.len) return error.InvalidBridgePort;
        var utf8: [wide.len * 3]u8 = undefined;
        const len = std.unicode.utf16LeToUtf8(&utf8, wide[0..n]) catch return error.InvalidBridgePort;
        return try parsePort(utf8[0..len]);
    }
    var buf: [16384]u8 = undefined;
    const env = readSelfEnviron(&buf) orelse return null;
    const key = "ONYX_WT_BRIDGE_PORT=";
    var it = std.mem.splitScalar(u8, env, 0);
    while (it.next()) |record| {
        if (std.mem.startsWith(u8, record, key)) {
            const val = record[key.len..];
            if (val.len == 0) return null;
            return try parsePort(val);
        }
    }
    return null;
}

/// Read `/proc/self/environ` into `buf` via raw syscalls; returns the populated
/// slice (NUL-separated records) or null on any read failure.
fn readSelfEnviron(buf: []u8) ?[]const u8 {
    const rc = linux.open("/proc/self/environ", .{ .ACCMODE = .RDONLY }, 0);
    const signed_fd: isize = @bitCast(rc);
    if (signed_fd < 0) return null;
    const fd: linux.fd_t = @intCast(rc);
    defer _ = linux.close(fd);

    var total: usize = 0;
    while (total < buf.len) {
        const n = linux.read(fd, buf[total..].ptr, buf.len - total);
        const sn: isize = @bitCast(n);
        if (sn <= 0) break;
        total += n;
    }
    return buf[0..total];
}

fn parsePort(s: []const u8) !u16 {
    const trimmed = std.mem.trim(u8, s, " \t\r\n");
    const port = std.fmt.parseInt(u16, trimmed, 10) catch return error.InvalidBridgePort;
    if (port == 0) return error.InvalidBridgePort;
    return port;
}

fn osEntropy(buf: []u8) !void {
    if (comptime builtin.os.tag == .windows) {
        onyx_server.substrate.platform.fillOsEntropy(buf) catch return error.Entropy;
        return;
    }
    var filled: usize = 0;
    while (filled < buf.len) {
        const rc = std.os.linux.getrandom(buf.ptr + filled, buf.len - filled, 0);
        const signed: isize = @bitCast(rc);
        if (signed < 0 or rc == 0) return error.Entropy;
        filled += rc;
    }
}
