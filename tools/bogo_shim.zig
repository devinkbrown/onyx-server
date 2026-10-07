// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Standalone BoGo shim — the onyx-side adapter that lets BoringSSL's
//! `ssl/test/runner` protocol-test suite ("BoGo") drive onyx's from-scratch
//! Yoroi TLS stack. Roadmap 0.3 (design: `docs/dev/tls-design/bogo.md`).
//!
//! Per test, BoGo stands up a Go TLS peer on a loopback TCP port and spawns this
//! shim with a `-flag [value]` argv describing the case. The shim always DIALS
//! `127.0.0.1:<-port>` (the TLS role is orthogonal to the TCP role), optionally
//! writes the runner's `-shim-id` as the first 8 bytes (LE) so the runner can
//! correlate the accept, then drives the chosen engine (`TlsConn` server /
//! `tls_client.Client`) over a read→feed→write pump, and after the handshake
//! echoes each application record back with every byte XOR 0xff until EOF.
//!
//! Exit-code contract (what BoGo reads):
//!   * 0  — handshake completed, expectations met, app-data echoed, clean close.
//!   * 89 — "unimplemented": any flag or case outside the scoped subset. With the
//!          runner's `-allow-unimplemented` these report as skipped, not failed.
//!   * 1  — an error: the shim prints the onyx error name to stderr (BoGo
//!          matches it via its `ErrorMap`) and, on a handshake failure, first
//!          synthesizes a fatal TLS alert record on the wire (via the engine's
//!          `takeAlert` / `alertRecordForError`) so the peer's `expectedLocalError`
//!          assertion sees a real alert instead of a bare RST.
//!
//! This tool is TEST-ONLY: it links against the shared `onyx_server` module but is
//! gated behind its own `zig build bogo-shim` step and is NOT part of the daemon
//! or `zig build test`. It adds only flag parsing, a socket pump, and the echo —
//! it changes no `src/crypto` or `src/daemon` production code, and reuses the
//! engines exactly as the daemon does (`TlsConn.onInbound`/`write`,
//! `Client.start`/`feed`/`encrypt`, `tls_certs.loadOrBootstrap`).
//!
//! SCOPED SUBSET (onyx is modern-only). Handled flags:
//!   -server, -port, -shim-id, -cert-file, -key-file, -min-version, -max-version,
//!   -expect-version, -curves (client: 23→P-256, 4588→X25519MLKEM768),
//!   -select-alpn (server), -expect-alpn (server).
//! Everything else — including TLS<1.2, DTLS, resumption (-resume-count), 0-RTT,
//! mTLS, HelloRetryRequest, -shim-writes-first/-shim-shuts-down, and every
//! -expect-*/-curves value not listed above — exits 89. See the roadmap 0.3 row
//! and the design doc for the full in/out-of-scope matrix; the external
//! BoringSSL `runner` harness (with a `-shim-config` DisabledTests/ErrorMap) is
//! the out-of-repo piece wired in a CI environment.

const std = @import("std");
const builtin = @import("builtin");
const onyx_server = @import("onyx_server");

const posix = std.posix;
const linux = std.os.linux;
const Socket = if (builtin.os.tag == .windows) usize else linux.fd_t;

const win = struct {
    const invalid_socket = std.math.maxInt(usize);
    const SockAddr4 = extern struct {
        family: u16,
        port: u16,
        addr: [4]u8,
        zero: [8]u8 = @splat(0),
    };
    const FdSet = extern struct { count: u32, sockets: [64]usize };
    const Timeval = extern struct { sec: i32, usec: i32 };
    comptime {
        if (@sizeOf(SockAddr4) != 16 or @sizeOf(FdSet) != 520 or @sizeOf(Timeval) != 8)
            @compileError("Windows socket ABI shape changed");
    }
    extern "ws2_32" fn WSAStartup(version: u16, data: *anyopaque) callconv(.winapi) i32;
    extern "ws2_32" fn WSACleanup() callconv(.winapi) i32;
    extern "ws2_32" fn WSASocketW(family: i32, kind: i32, protocol: i32, info: ?*anyopaque, group: u32, flags: u32) callconv(.winapi) usize;
    extern "ws2_32" fn closesocket(socket: usize) callconv(.winapi) i32;
    extern "ws2_32" fn connect(socket: usize, address: *const SockAddr4, len: i32) callconv(.winapi) i32;
    extern "ws2_32" fn bind(socket: usize, address: *const SockAddr4, len: i32) callconv(.winapi) i32;
    extern "ws2_32" fn listen(socket: usize, backlog: i32) callconv(.winapi) i32;
    extern "ws2_32" fn getsockname(socket: usize, address: *SockAddr4, len: *i32) callconv(.winapi) i32;
    extern "ws2_32" fn select(ignored: i32, read: ?*FdSet, write: ?*FdSet, except: ?*FdSet, timeout: *const Timeval) callconv(.winapi) i32;
    extern "ws2_32" fn accept(socket: usize, address: ?*SockAddr4, len: ?*i32) callconv(.winapi) usize;
    extern "ws2_32" fn setsockopt(socket: usize, level: i32, option: i32, value: *const anyopaque, len: i32) callconv(.winapi) i32;
    extern "ws2_32" fn recv(socket: usize, bytes: [*]u8, len: i32, flags: i32) callconv(.winapi) i32;
    extern "ws2_32" fn send(socket: usize, bytes: [*]const u8, len: i32, flags: i32) callconv(.winapi) i32;
    extern "kernel32" fn GetStdHandle(which: u32) callconv(.winapi) usize;
    extern "kernel32" fn WriteFile(handle: usize, bytes: [*]const u8, len: u32, written: *u32, overlapped: ?*anyopaque) callconv(.winapi) i32;
    extern "kernel32" fn GetEnvironmentVariableW(name: [*:0]const u16, value: [*]u16, size: u32) callconv(.winapi) u32;
};

const tls_conn = onyx_server.daemon.tls_conn;
const tls_certs = onyx_server.daemon.tls_certs;
const tls_server = onyx_server.crypto.tls_server;
const tls12_server = onyx_server.crypto.tls12_server;
const tls_client = onyx_server.crypto.tls_client;
const tls_record = onyx_server.crypto.tls_record;

const TlsConn = tls_conn.TlsConn;
const Client = tls_client.Client;

/// BoGo exit codes (design doc §1).
const exit_success: u8 = 0;
const exit_error: u8 = 1;
const exit_unimplemented: u8 = 89;

/// TLS wire version numbers, as BoGo passes them to `-min/-max/-expect-version`.
const version_tls12: u16 = 0x0303;
const version_tls13: u16 = 0x0304;

/// Named-group codepoints BoGo passes to `-curves` that this shim can reproduce
/// EXACTLY as a client offer (via the engine's single-group `offerOnly*` hooks).
const curve_secp256r1: u64 = 23;
const curve_x25519mlkem768: u64 = 4588; // 0x11ec

const max_read = 18 * 1024; // one TLS record (16 KiB + overhead) per syscall.

// ── Flags ───────────────────────────────────────────────────────────────────

const Curve = enum { p256, hybrid };

/// The scoped subset of BoGo shim flags this tool understands. Anything outside
/// it is signalled by `error.Unimplemented` from `parse` (⇒ exit 89).
pub const Flags = struct {
    server: bool = false,
    have_port: bool = false,
    port: u16 = 0,
    have_shim_id: bool = false,
    shim_id: u64 = 0,
    /// Borrowed from argv (stable for the process lifetime).
    cert_file: ?[]const u8 = null,
    key_file: ?[]const u8 = null,
    min_version: u16 = version_tls12,
    max_version: u16 = version_tls13,
    expect_version: ?u16 = null,
    /// Client key-exchange group constraint (server role rejects it).
    client_curve: ?Curve = null,
    /// Server ALPN protocol to offer/select (borrowed from argv).
    select_alpn: ?[]const u8 = null,
    /// Post-handshake ALPN assertion (server role only; borrowed from argv).
    expect_alpn: ?[]const u8 = null,

    pub const ParseError = error{
        /// Flag/case outside the scoped subset ⇒ exit 89.
        Unimplemented,
        /// Malformed invocation (missing value / bad integer / missing -port).
        Usage,
    };

    /// Parse `args` (argv, including argv[0]). Allocation-free: every retained
    /// slice borrows argv. The FIRST unknown or unsupported behavior-changing
    /// flag returns `error.Unimplemented` so BoGo skips (never silently
    /// mis-handles) an out-of-scope case.
    pub fn parse(args: []const []const u8) ParseError!Flags {
        var f: Flags = .{};
        var i: usize = 1;
        while (i < args.len) {
            const a = args[i];
            if (eql(a, "-server")) {
                f.server = true;
                i += 1;
            } else if (eql(a, "-port")) {
                f.port = try parseU16(try takeVal(args, &i));
                f.have_port = true;
            } else if (eql(a, "-shim-id")) {
                f.shim_id = std.fmt.parseInt(u64, try takeVal(args, &i), 10) catch return error.Usage;
                f.have_shim_id = true;
            } else if (eql(a, "-cert-file")) {
                f.cert_file = try takeVal(args, &i);
            } else if (eql(a, "-key-file")) {
                f.key_file = try takeVal(args, &i);
            } else if (eql(a, "-min-version")) {
                f.min_version = try parseU16(try takeVal(args, &i));
            } else if (eql(a, "-max-version")) {
                f.max_version = try parseU16(try takeVal(args, &i));
            } else if (eql(a, "-expect-version")) {
                f.expect_version = try parseU16(try takeVal(args, &i));
            } else if (eql(a, "-curves")) {
                if (f.client_curve != null) return error.Unimplemented; // single group only
                const id = std.fmt.parseInt(u64, try takeVal(args, &i), 10) catch return error.Usage;
                f.client_curve = switch (id) {
                    curve_secp256r1 => .p256,
                    curve_x25519mlkem768 => .hybrid,
                    else => return error.Unimplemented,
                };
            } else if (eql(a, "-select-alpn")) {
                f.select_alpn = try takeVal(args, &i);
            } else if (eql(a, "-expect-alpn")) {
                f.expect_alpn = try takeVal(args, &i);
            } else {
                // Unknown or out-of-scope flag: over-skipping (exit 89) is safe,
                // silently mis-handling is not.
                return error.Unimplemented;
            }
        }

        // Post-validation, encoding the modern-only + reachable-subset posture.
        if (!f.have_port) return error.Usage;
        if (f.min_version < version_tls12 or f.min_version > version_tls13) return error.Unimplemented;
        if (f.max_version < version_tls12 or f.max_version > version_tls13) return error.Unimplemented;
        if (f.min_version > f.max_version) return error.Usage;
        // A 1.2-only cap is unreachable: the shim client is TLS 1.3-only, and the
        // dual server has no 1.2-only constructor. (1.2 is reachable only as the
        // server auto-negotiating down for a 1.2-only ClientHello.)
        if (f.max_version < version_tls13) return error.Unimplemented;
        if (f.server and f.client_curve != null) return error.Unimplemented; // client-only
        if (!f.server and f.select_alpn != null) return error.Unimplemented; // server-only
        if (!f.server and f.expect_alpn != null) return error.Unimplemented; // asserted via server accessor
        return f;
    }

    fn takeVal(args: []const []const u8, i: *usize) ParseError![]const u8 {
        if (i.* + 1 >= args.len) return error.Usage;
        const v = args[i.* + 1];
        i.* += 2;
        return v;
    }

    fn parseU16(s: []const u8) ParseError!u16 {
        return std.fmt.parseInt(u16, s, 10) catch error.Usage;
    }

    fn eql(a: []const u8, b: []const u8) bool {
        return std.mem.eql(u8, a, b);
    }
};

// ── Entry point ───────────────────────────────────────────────────────────────

pub fn main(init: std.process.Init) void {
    ignoreSigpipe(); // a peer that closes before we write our alert must yield
    // EPIPE (a clean error/exit), not SIGPIPE (a signal death BoGo can't map).
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    const code = shimRun(gpa.allocator(), init);
    _ = gpa.deinit();
    std.process.exit(code);
}

/// Set SIGPIPE to ignore so a raw-socket write to a peer-closed fd returns EPIPE
/// instead of terminating the process (mirrors the daemon's own disposition).
fn ignoreSigpipe() void {
    if (comptime builtin.os.tag == .windows) return;
    const act = posix.Sigaction{
        .handler = .{ .handler = posix.SIG.IGN },
        .mask = posix.sigemptyset(),
        .flags = 0,
    };
    posix.sigaction(posix.SIG.PIPE, &act, null);
}

/// Do the whole run and return the BoGo exit code. All owned state is released
/// via `defer` before this returns, so `main` may `gpa.deinit()` for a leak
/// report on the normal path.
fn shimRun(alloc: std.mem.Allocator, init: std.process.Init) u8 {
    var it = std.process.Args.iterateAllocator(init.minimal.args, alloc) catch {
        errWrite("bogo_shim: args failed\n");
        return exit_error;
    };
    defer it.deinit();
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(alloc);
    while (it.next()) |a| argv.append(alloc, a) catch return exit_error;

    // Capability probe: the runner asks whether a separate handshaker binary is
    // supported (split-handshake / handoff tests). We do not implement a
    // handshaker, so answer "No" on stdout and exit cleanly — a non-zero exit
    // here aborts the WHOLE runner ("Error making split handshake tests").
    for (argv.items) |a| {
        if (std.mem.eql(u8, a, "-is-handshaker-supported")) {
            outWrite("No\n");
            return exit_success;
        }
    }

    const flags = Flags.parse(argv.items) catch |e| switch (e) {
        error.Unimplemented => return exit_unimplemented,
        error.Usage => {
            errWrite("bogo_shim: usage error\n");
            return exit_error;
        },
    };

    doConnection(alloc, init.io, flags) catch |e| {
        // BoGo matches this error name against its ErrorMap (expectedError).
        errWrite(@errorName(e));
        errWrite("\n");
        return exit_error;
    };
    return exit_success;
}

fn doConnection(alloc: std.mem.Allocator, io: std.Io, flags: Flags) !void {
    if (comptime builtin.os.tag == .windows) try socketStartup();
    defer socketCleanup();
    const fd = try tcpConnect(flags.port);
    defer socketClose(fd);

    if (flags.have_shim_id) {
        var idb: [8]u8 = undefined;
        std.mem.writeInt(u64, &idb, flags.shim_id, .little);
        try sockWriteAll(fd, &idb);
    }

    if (flags.server) {
        try runServerRole(alloc, io, fd, flags);
    } else {
        try runClientRole(alloc, fd, flags);
    }
}

// ── Server role (TlsConn: TLS 1.3 + hardened TLS 1.2) ─────────────────────────

fn runServerRole(alloc: std.mem.Allocator, io: std.Io, fd: Socket, flags: Flags) !void {
    // BoGo supplies PEM `-cert-file`/`-key-file`; with neither we bootstrap a
    // self-signed Ed25519 leaf (loopback-only, matches the daemon's own loader).
    var loaded = try tls_certs.loadOrBootstrap(alloc, io, .{
        .enabled = flags.cert_file == null and flags.key_file == null,
        .cert_path = flags.cert_file,
        .key_path = flags.key_file,
        .dns_name = "localhost",
    });
    defer loaded.deinit(alloc);

    // `-select-alpn` names the single protocol the server will select. The store
    // lives on this frame (outlives `conn`); its element borrows argv.
    var alpn_store: [1][]const u8 = undefined;
    var alpn: []const []const u8 = &.{};
    if (flags.select_alpn) |name| {
        alpn_store[0] = name;
        alpn = alpn_store[0..1];
    }

    const cfg13: tls_server.Config = .{
        .cert_chain = loaded.cert_chain,
        .signing_key = loaded.signing_key,
        .ecdsa_p256_signing_key = loaded.ecdsa_p256_signing_key,
        .rsa_signing_key = loaded.rsa_signing_key,
        .alpn_protocols = alpn,
    };
    // TLS 1.2 server auth is ECDSA/RSA only (no Ed25519 in the 1.2 engine); a
    // 1.2 ClientHello against an Ed25519-only leaf fails at engine construction.
    const cfg12: tls12_server.Config = .{
        .cert_chain = loaded.cert_chain,
        .ecdsa_p256_signing_key = loaded.ecdsa_p256_signing_key,
        .rsa_signing_key = loaded.rsa_signing_key,
        .alpn_protocols = alpn,
    };

    // Offer the dual (1.3 + hardened 1.2) engine only when the leaf key can
    // actually authenticate a 1.2 handshake (ECDSA/RSA — the 1.2 engine has no
    // Ed25519 path). Otherwise run 1.3-only: this both matches capability AND
    // avoids feeding `TlsConn.initDual` a keyless `cfg12`, whose lazy
    // `tls12_server.Server.init` would fail `NoSigningKey` on a 1.2 ClientHello
    // (e.g. a downgrade/negative test) and leave the engine union in a corrupt
    // half-constructed `.tls12` state. `-min-version 0x0304` also forces 1.3-only.
    const has_tls12_key = loaded.ecdsa_p256_signing_key != null or loaded.rsa_signing_key != null;
    var conn = if (flags.min_version >= version_tls13 or !has_tls12_key)
        try TlsConn.init(alloc, cfg13)
    else
        TlsConn.initDual(alloc, cfg13, cfg12);
    defer conn.deinit();

    driveServerHandshake(fd, &conn) catch |e| {
        // Emit the engine's fatal alert (plaintext pre-ServerHello, encrypted
        // after) so a real BoGo peer sees a diagnostic alert, not a bare RST.
        if (conn.takeAlert(e)) |rec| {
            defer alloc.free(rec);
            sockWriteAll(fd, rec) catch {};
        }
        return e;
    };

    try checkServerExpect(&conn, flags);
    try echoServer(alloc, fd, &conn);
}

fn driveServerHandshake(fd: Socket, conn: *TlsConn) !void {
    var buf: [max_read]u8 = undefined;
    while (!conn.handshakeDone()) {
        const n = try sockReadSome(fd, &buf);
        if (n == 0) return error.UnexpectedEof;
        const outcome = try conn.onInbound(buf[0..n]);
        if (outcome.handshake_bytes.len != 0) try sockWriteAll(fd, outcome.handshake_bytes);
    }
}

fn checkServerExpect(conn: *const TlsConn, flags: Flags) !void {
    if (flags.expect_version) |want| {
        const got: u16 = switch (conn.negotiatedVersion() orelse return error.HandshakeIncomplete) {
            .tls12 => version_tls12,
            .tls13 => version_tls13,
        };
        if (got != want) return error.VersionMismatch;
    }
    if (flags.expect_alpn) |want| {
        const got = conn.selectedAlpn() orelse return error.AlpnMismatch;
        if (!std.mem.eql(u8, got, want)) return error.AlpnMismatch;
    }
}

fn echoServer(alloc: std.mem.Allocator, fd: Socket, conn: *TlsConn) !void {
    var buf: [max_read]u8 = undefined;
    while (true) {
        const n = try sockReadSome(fd, &buf);
        if (n == 0) return; // clean TCP EOF ⇒ done (exit 0).
        const outcome = conn.onInbound(buf[0..n]) catch |e| {
            // A peer close_notify surfaces as a decrypt/parse error post-handshake
            // (the server engine collapses an inner alert to BadRecord); treat it
            // as an orderly end of the exchange rather than a shim failure.
            if (e == error.TlsAlert or e == error.BadRecord) return;
            return e;
        };
        if (outcome.plaintext.len != 0) {
            const xored = try alloc.dupe(u8, outcome.plaintext);
            defer alloc.free(xored);
            for (xored) |*b| b.* ^= 0xff;
            const ct = try conn.write(xored);
            try sockWriteAll(fd, ct);
        }
    }
}

// ── Client role (tls_client.Client: TLS 1.3) ──────────────────────────────────

fn runClientRole(alloc: std.mem.Allocator, fd: Socket, flags: Flags) !void {
    var client = try Client.init(alloc, .{
        .server_name = "localhost",
        .trust_anchors = &.{},
    });
    defer client.deinit();
    // Permissive server-cert handling is the shim default (matches bssl_shim's
    // custom-verify default; BoGo opts INTO verification with flags this subset
    // does not yet handle). The leaf key is still parsed and CertificateVerify
    // still checked.
    client.skipServerCertVerifyForTest();
    if (flags.client_curve) |c| switch (c) {
        .p256 => client.offerOnlyP256ForTest(),
        .hybrid => client.offerOnlyHybridForTest(),
    };

    driveClientHandshake(alloc, fd, &client) catch |e| {
        // Pre-connected client failures warrant a plaintext alert.
        if (tls_server.alertRecordForError(alloc, e)) |rec| {
            defer alloc.free(rec);
            sockWriteAll(fd, rec) catch {};
        }
        return e;
    };

    try checkClientExpect(&client, flags);
    try echoClient(alloc, fd, &client);
}

fn driveClientHandshake(alloc: std.mem.Allocator, fd: Socket, client: *Client) !void {
    const hello = try client.start();
    {
        defer alloc.free(hello);
        try sockWriteAll(fd, hello);
    }
    var buf: [max_read]u8 = undefined;
    while (!client.handshakeDone()) {
        const n = try sockReadSome(fd, &buf);
        if (n == 0) return error.UnexpectedEof;
        switch (try client.feed(buf[0..n])) {
            .need_more => {},
            .bytes_to_send => |b| {
                defer alloc.free(b);
                try sockWriteAll(fd, b);
            },
        }
    }
}

fn checkClientExpect(client: *const Client, flags: Flags) !void {
    if (flags.expect_version) |want| {
        // The shim client is TLS 1.3 only, so it can only satisfy an expectation
        // of 1.3; anything else is a genuine mismatch for this subset.
        if (want != version_tls13) return error.VersionMismatch;
        if (!client.handshakeDone()) return error.HandshakeIncomplete;
    }
}

fn echoClient(alloc: std.mem.Allocator, fd: Socket, client: *Client) !void {
    var acc: std.ArrayList(u8) = .empty;
    defer acc.deinit(alloc);
    var buf: [max_read]u8 = undefined;
    while (true) {
        const n = try sockReadSome(fd, &buf);
        if (n == 0) return;
        try acc.appendSlice(alloc, buf[0..n]);
        while (completeRecordLen(acc.items)) |wire_len| {
            const rd = client.decryptApp(acc.items[0..wire_len]) catch |e| {
                if (e == error.TlsAlert) return; // peer close_notify / alert.
                return e;
            };
            switch (rd) {
                .control => {
                    // Post-handshake NST/KeyUpdate: flush any queued reply.
                    if (try client.takePendingSend()) |reply| {
                        defer alloc.free(reply);
                        try sockWriteAll(fd, reply);
                    }
                },
                .application_data => |pt| {
                    defer alloc.free(pt);
                    for (pt) |*b| b.* ^= 0xff;
                    const ct = try client.encrypt(pt);
                    defer alloc.free(ct);
                    try sockWriteAll(fd, ct);
                },
            }
            consumePrefix(&acc, wire_len);
        }
    }
}

// ── Record framing (app-data phase; the engines frame handshake records) ──────

/// Length (header + body) of the complete TLS record at the front of `buf`, or
/// null if `buf` doesn't yet hold a whole record. Mirrors `TlsConn`'s private
/// helper — the client engine has no record-framing wrapper for app data.
fn completeRecordLen(buf: []const u8) ?usize {
    if (buf.len < tls_record.record_header_len) return null;
    const body_len = std.mem.readInt(u16, buf[3..5], .big);
    const wire_len = tls_record.record_header_len + @as(usize, body_len);
    if (buf.len < wire_len) return null;
    return wire_len;
}

/// Drop the first `n` bytes of `list`, sliding the remainder to the front
/// (capacity retained; no allocation).
fn consumePrefix(list: *std.ArrayList(u8), n: usize) void {
    const remaining = list.items.len - n;
    std.mem.copyForwards(u8, list.items[0..remaining], list.items[n..]);
    list.items.len = remaining;
}

// ── Raw socket helpers (the shim owns the socket, engines are pure) ───────────

fn socketStartup() !void {
    if (comptime builtin.os.tag == .windows) {
        var data: [408]u8 align(8) = @splat(0);
        if (win.WSAStartup(0x0202, &data) != 0) return error.SocketFailed;
    }
}

fn socketCleanup() void {
    if (comptime builtin.os.tag == .windows) _ = win.WSACleanup();
}

fn socketClose(fd: Socket) void {
    if (comptime builtin.os.tag == .windows) {
        _ = win.closesocket(fd);
    } else {
        _ = linux.close(fd);
    }
}

fn tcpConnect(port: u16) !Socket {
    if (comptime builtin.os.tag == .windows) {
        const fd = win.WSASocketW(2, 1, 6, null, 0, 1);
        if (fd == win.invalid_socket) return error.SocketFailed;
        errdefer socketClose(fd);
        const addr = win.SockAddr4{ .family = 2, .port = std.mem.nativeToBig(u16, port), .addr = .{ 127, 0, 0, 1 } };
        if (win.connect(fd, &addr, @sizeOf(win.SockAddr4)) != 0) return error.ConnectFailed;
        return fd;
    }
    const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM, 0);
    if (posix.errno(rc) != .SUCCESS) return error.SocketFailed;
    const fd: Socket = @intCast(rc);
    errdefer socketClose(fd);
    var addr: linux.sockaddr.in = .{
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, 0x7f00_0001), // 127.0.0.1
    };
    if (posix.errno(linux.connect(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in))) != .SUCCESS) {
        return error.ConnectFailed;
    }
    return fd;
}

fn sockWriteAll(fd: Socket, bytes: []const u8) !void {
    var off: usize = 0;
    while (off < bytes.len) {
        if (comptime builtin.os.tag == .windows) {
            const n = win.send(fd, bytes[off..].ptr, @intCast(@min(bytes.len - off, std.math.maxInt(i32))), 0);
            if (n <= 0) return error.WriteFailed;
            off += @intCast(n);
            continue;
        }
        const rc = linux.write(fd, bytes.ptr + off, bytes.len - off);
        const signed: isize = @bitCast(rc);
        if (signed <= 0) return error.WriteFailed;
        off += @intCast(rc);
    }
}

/// Read up to `buf.len` bytes; returns 0 on EOF.
fn sockReadSome(fd: Socket, buf: []u8) !usize {
    if (comptime builtin.os.tag == .windows) {
        const n = win.recv(fd, buf.ptr, @intCast(@min(buf.len, std.math.maxInt(i32))), 0);
        if (n < 0) return error.ReadFailed;
        return @intCast(n);
    }
    const rc = linux.read(fd, buf.ptr, buf.len);
    const signed: isize = @bitCast(rc);
    if (signed < 0) return error.ReadFailed;
    return @intCast(rc);
}

fn errWrite(bytes: []const u8) void {
    fdWrite(2, bytes);
}

fn outWrite(bytes: []const u8) void {
    fdWrite(1, bytes);
}

fn fdWrite(fd: Socket, bytes: []const u8) void {
    var off: usize = 0;
    while (off < bytes.len) {
        if (comptime builtin.os.tag == .windows) {
            const handle = win.GetStdHandle(if (fd == 2) @as(u32, @bitCast(@as(i32, -12))) else @as(u32, @bitCast(@as(i32, -11))));
            var written: u32 = 0;
            if (win.WriteFile(handle, bytes[off..].ptr, @intCast(@min(bytes.len - off, std.math.maxInt(u32))), &written, null) == 0 or written == 0) return;
            off += written;
            continue;
        }
        const rc = linux.write(fd, bytes.ptr + off, bytes.len - off);
        const signed: isize = @bitCast(rc);
        if (signed <= 0) return;
        off += @intCast(rc);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Self-driven proof (NOT part of `zig build test`; run via `zig build
// bogo-shim-test`, which builds+installs the shim and sets BOGO_SHIM_BIN).
//
// These spawn the REAL compiled shim as a subprocess and drive it with onyx's
// own loopback TLS engines standing in for BoringSSL's runner — proving the shim
// completes a handshake, XOR-echoes app data, and returns the BoGo-expected exit
// code (0 / 89 / nonzero) WITHOUT the external Go harness. The shim binary is
// built with full safety checks, so a memory-safety fault would trap and fail
// the exit-code assertion.
// ═══════════════════════════════════════════════════════════════════════════

const testing = std.testing;
const x509_selfsign = onyx_server.proto.x509_selfsign;
const Ed25519 = std.crypto.sign.Ed25519;

test "parse: valid server invocation" {
    const args = [_][]const u8{ "bogo_shim", "-server", "-port", "6680", "-shim-id", "42" };
    const f = try Flags.parse(&args);
    try testing.expect(f.server);
    try testing.expect(f.have_port);
    try testing.expectEqual(@as(u16, 6680), f.port);
    try testing.expect(f.have_shim_id);
    try testing.expectEqual(@as(u64, 42), f.shim_id);
    try testing.expectEqual(version_tls12, f.min_version);
    try testing.expectEqual(version_tls13, f.max_version);
}

test "parse: valid client invocation with curve + expect-version" {
    const args = [_][]const u8{ "bogo_shim", "-port", "1234", "-curves", "23", "-expect-version", "772" };
    const f = try Flags.parse(&args);
    try testing.expect(!f.server);
    try testing.expectEqual(Curve.p256, f.client_curve.?);
    try testing.expectEqual(version_tls13, f.expect_version.?);
}

test "parse: server ALPN select + expect" {
    const args = [_][]const u8{ "bogo_shim", "-server", "-port", "9", "-select-alpn", "h2", "-expect-alpn", "h2" };
    const f = try Flags.parse(&args);
    try testing.expectEqualStrings("h2", f.select_alpn.?);
    try testing.expectEqualStrings("h2", f.expect_alpn.?);
}

test "parse: unknown flag ⇒ Unimplemented (exit 89)" {
    const args = [_][]const u8{ "bogo_shim", "-port", "9", "-resume-count", "1" };
    try testing.expectError(error.Unimplemented, Flags.parse(&args));
}

test "parse: unsupported curve ⇒ Unimplemented" {
    const args = [_][]const u8{ "bogo_shim", "-port", "9", "-curves", "25" }; // secp521r1
    try testing.expectError(error.Unimplemented, Flags.parse(&args));
}

test "parse: 1.2-only cap is unreachable ⇒ Unimplemented" {
    const args = [_][]const u8{ "bogo_shim", "-port", "9", "-max-version", "771" };
    try testing.expectError(error.Unimplemented, Flags.parse(&args));
}

test "parse: server curve constraint ⇒ Unimplemented" {
    const args = [_][]const u8{ "bogo_shim", "-server", "-port", "9", "-curves", "23" };
    try testing.expectError(error.Unimplemented, Flags.parse(&args));
}

test "parse: client expect-alpn ⇒ Unimplemented" {
    const args = [_][]const u8{ "bogo_shim", "-port", "9", "-expect-alpn", "h2" };
    try testing.expectError(error.Unimplemented, Flags.parse(&args));
}

test "parse: missing -port ⇒ Usage" {
    const args = [_][]const u8{ "bogo_shim", "-server" };
    try testing.expectError(error.Usage, Flags.parse(&args));
}

test "parse: flag missing its value ⇒ Usage" {
    const args = [_][]const u8{ "bogo_shim", "-port" };
    try testing.expectError(error.Usage, Flags.parse(&args));
}

test "completeRecordLen: partial header, partial body, whole, multi" {
    try testing.expectEqual(@as(?usize, null), completeRecordLen(&[_]u8{ 0x17, 0x03 }));
    // header claims a 4-byte body but only 2 present.
    try testing.expectEqual(@as(?usize, null), completeRecordLen(&[_]u8{ 0x17, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb }));
    const whole = [_]u8{ 0x17, 0x03, 0x03, 0x00, 0x02, 0xaa, 0xbb };
    try testing.expectEqual(@as(?usize, 7), completeRecordLen(&whole));
    const multi = [_]u8{ 0x17, 0x03, 0x03, 0x00, 0x01, 0xaa, 0x17, 0x03, 0x03, 0x00, 0x01, 0xbb };
    try testing.expectEqual(@as(?usize, 6), completeRecordLen(&multi));
}

test "consumePrefix: slides the remainder to the front" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    try list.appendSlice(testing.allocator, &[_]u8{ 1, 2, 3, 4, 5 });
    consumePrefix(&list, 2);
    try testing.expectEqualSlices(u8, &[_]u8{ 3, 4, 5 }, list.items);
    consumePrefix(&list, 3);
    try testing.expectEqual(@as(usize, 0), list.items.len);
}

/// Absolute path to the built shim, injected as BOGO_SHIM_BIN by the
/// `bogo-shim-test` build step. Test blocks do not receive process Init, so read
/// `/proc/self/environ` on Linux and the native process environment on Windows.
/// The returned slice borrows `out`.
/// Absent ⇒ subprocess tests skip (the pure parse/framing tests still run).
fn shimBinPath(out: []u8) ?[]const u8 {
    if (comptime builtin.os.tag == .windows) {
        const name = std.unicode.utf8ToUtf16LeStringLiteral("BOGO_SHIM_BIN");
        var wide: [2048]u16 = undefined;
        const len = win.GetEnvironmentVariableW(name, &wide, wide.len);
        if (len == 0 or len >= wide.len) return null;
        const n = std.unicode.utf16LeToUtf8(out, wide[0..len]) catch return null;
        return out[0..n];
    }
    const rc = linux.open("/proc/self/environ", .{ .ACCMODE = .RDONLY }, 0);
    if (@as(isize, @bitCast(rc)) < 0) return null;
    const fd: Socket = @intCast(rc);
    defer _ = linux.close(fd);

    var block: [65536]u8 = undefined; // large enough for any realistic CI environ
    var total: usize = 0;
    while (total < block.len) {
        const r = linux.read(fd, block[total..].ptr, block.len - total);
        const s: isize = @bitCast(r);
        if (s <= 0) break;
        total += @intCast(r);
    }

    const prefix = "BOGO_SHIM_BIN=";
    var it = std.mem.splitScalar(u8, block[0..total], 0);
    while (it.next()) |kv| {
        if (std.mem.startsWith(u8, kv, prefix)) {
            const v = kv[prefix.len..];
            if (v.len == 0 or v.len > out.len) return null;
            @memcpy(out[0..v.len], v);
            return out[0..v.len];
        }
    }
    return null;
}

fn makeEd25519Leaf(out: []u8, kp: Ed25519.KeyPair) ![]const u8 {
    return x509_selfsign.buildSelfSigned(out, .{
        .common_name = "localhost",
        .not_before = 1_704_067_200, // 2024-01-01
        .not_after = 4_102_444_800, // 2100-01-01
        .serial = &.{ 0xb0, 0x60 },
        .key_pair = kp,
        .dns_names = &.{ "localhost", "127.0.0.1" },
        .is_ca = true,
    });
}

fn listenLoopback() !Socket {
    if (comptime builtin.os.tag == .windows) {
        try socketStartup();
        errdefer socketCleanup();
        const fd = win.WSASocketW(2, 1, 6, null, 0, 1);
        if (fd == win.invalid_socket) return error.SocketFailed;
        errdefer socketClose(fd);
        const addr = win.SockAddr4{ .family = 2, .port = 0, .addr = .{ 127, 0, 0, 1 } };
        if (win.bind(fd, &addr, @sizeOf(win.SockAddr4)) != 0) return error.BindFailed;
        if (win.listen(fd, 1) != 0) return error.ListenFailed;
        return fd;
    }
    const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM, 0);
    if (posix.errno(rc) != .SUCCESS) return error.SkipZigTest;
    const fd: Socket = @intCast(rc);
    errdefer _ = linux.close(fd);
    var addr: linux.sockaddr.in = .{ .port = 0, .addr = std.mem.nativeToBig(u32, 0x7f00_0001) };
    if (posix.errno(linux.bind(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in))) != .SUCCESS) return error.SkipZigTest;
    if (posix.errno(linux.listen(fd, 1)) != .SUCCESS) return error.SkipZigTest;
    return fd;
}

fn loopbackPort(listen_fd: Socket) !u16 {
    if (comptime builtin.os.tag == .windows) {
        var addr = win.SockAddr4{ .family = 2, .port = 0, .addr = .{ 127, 0, 0, 1 } };
        var len: i32 = @sizeOf(win.SockAddr4);
        if (win.getsockname(listen_fd, &addr, &len) != 0 or len != @sizeOf(win.SockAddr4)) return error.AddrLookupFailed;
        return std.mem.bigToNative(u16, addr.port);
    }
    var storage: posix.sockaddr.storage = undefined;
    var slen: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
    if (posix.errno(linux.getsockname(listen_fd, @ptrCast(&storage), &slen)) != .SUCCESS) return error.SkipZigTest;
    const in: *const linux.sockaddr.in = @ptrCast(@alignCast(&storage));
    return std.mem.bigToNative(u16, in.port);
}

fn acceptWithTimeout(listen_fd: Socket, timeout_ms: i32) !Socket {
    if (comptime builtin.os.tag == .windows) {
        var read = win.FdSet{ .count = 1, .sockets = @splat(0) };
        read.sockets[0] = listen_fd;
        const timeout = win.Timeval{ .sec = @divTrunc(timeout_ms, 1000), .usec = @rem(timeout_ms, 1000) * 1000 };
        if (win.select(0, &read, null, null, &timeout) != 1) return error.AcceptTimeout;
        const fd = win.accept(listen_fd, null, null);
        if (fd == win.invalid_socket) return error.AcceptFailed;
        return fd;
    }
    var pfd = [_]linux.pollfd{.{ .fd = listen_fd, .events = linux.POLL.IN, .revents = 0 }};
    const pr = linux.poll(&pfd, 1, timeout_ms);
    if (posix.errno(pr) != .SUCCESS or pr == 0) return error.AcceptTimeout;
    const rc = linux.accept4(listen_fd, null, null, 0);
    if (posix.errno(rc) != .SUCCESS) return error.AcceptFailed;
    return @intCast(rc);
}

/// Best-effort read timeout so a misbehaving shim can't hang the suite.
fn setReadTimeout(fd: Socket, ms: u32) void {
    if (comptime builtin.os.tag == .windows) {
        _ = win.setsockopt(fd, 0xffff, 0x1006, &ms, @sizeOf(u32));
        return;
    }
    const tv: linux.timeval = .{ .sec = @intCast(ms / 1000), .usec = @intCast((ms % 1000) * 1000) };
    _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(linux.timeval));
}

fn readExact(fd: Socket, buf: []u8) !void {
    var off: usize = 0;
    while (off < buf.len) {
        const n = try sockReadSome(fd, buf[off..]);
        if (n == 0) return error.UnexpectedEof;
        off += n;
    }
}

const probe_msg = "onyx-bogo-shim-probe";

/// Drive the accepted socket as a TLS 1.3 CLIENT peer (the shim is the server):
/// complete the handshake, send `probe_msg`, and assert the shim echoed it back
/// XOR 0xff. When `alpn` is set, offer it and require the shim to select it.
fn peerClientVerifyEcho(alloc: std.mem.Allocator, afd: Socket, alpn: []const []const u8) !void {
    var client = try Client.init(alloc, .{
        .server_name = "localhost",
        .trust_anchors = &.{},
        .alpn_protocols = alpn,
    });
    defer client.deinit();
    client.skipServerCertVerifyForTest();

    const ch = try client.start();
    {
        defer alloc.free(ch);
        try sockWriteAll(afd, ch);
    }
    var buf: [max_read]u8 = undefined;
    while (!client.handshakeDone()) {
        const n = try sockReadSome(afd, &buf);
        if (n == 0) return error.PeerEof;
        switch (try client.feed(buf[0..n])) {
            .need_more => {},
            .bytes_to_send => |b| {
                defer alloc.free(b);
                try sockWriteAll(afd, b);
            },
        }
    }

    const rec = try client.encrypt(probe_msg);
    {
        defer alloc.free(rec);
        try sockWriteAll(afd, rec);
    }
    try readXorEchoClient(alloc, afd, &client);
}

fn readXorEchoClient(alloc: std.mem.Allocator, afd: Socket, client: *Client) !void {
    var acc: std.ArrayList(u8) = .empty;
    defer acc.deinit(alloc);
    var got: [probe_msg.len]u8 = undefined;
    var gl: usize = 0;
    var buf: [max_read]u8 = undefined;
    while (gl < probe_msg.len) {
        const n = try sockReadSome(afd, &buf);
        if (n == 0) return error.PeerEof;
        try acc.appendSlice(alloc, buf[0..n]);
        while (completeRecordLen(acc.items)) |wire_len| {
            switch (try client.decryptApp(acc.items[0..wire_len])) {
                .control => {},
                .application_data => |pt| {
                    defer alloc.free(pt);
                    if (gl + pt.len > got.len) return error.EchoTooLong;
                    @memcpy(got[gl..][0..pt.len], pt);
                    gl += pt.len;
                },
            }
            consumePrefix(&acc, wire_len);
        }
    }
    for (probe_msg, 0..) |c, idx| try testing.expectEqual(c ^ @as(u8, 0xff), got[idx]);
}

/// Drive the accepted socket as a TLS 1.3 SERVER peer (the shim is the client):
/// complete the handshake, send `probe_msg`, and assert the XOR echo.
fn peerServerVerifyEcho(alloc: std.mem.Allocator, afd: Socket, cert_der: []const u8, kp: Ed25519.KeyPair) !void {
    var conn = try TlsConn.init(alloc, .{ .cert_chain = &.{cert_der}, .signing_key = kp });
    defer conn.deinit();

    var buf: [max_read]u8 = undefined;
    while (!conn.handshakeDone()) {
        const n = try sockReadSome(afd, &buf);
        if (n == 0) return error.PeerEof;
        const outcome = try conn.onInbound(buf[0..n]);
        if (outcome.handshake_bytes.len != 0) try sockWriteAll(afd, outcome.handshake_bytes);
    }

    const ct = try conn.write(probe_msg);
    try sockWriteAll(afd, ct);

    var got: [probe_msg.len]u8 = undefined;
    var gl: usize = 0;
    while (gl < probe_msg.len) {
        const n = try sockReadSome(afd, &buf);
        if (n == 0) return error.PeerEof;
        const outcome = try conn.onInbound(buf[0..n]);
        if (outcome.plaintext.len != 0) {
            if (gl + outcome.plaintext.len > got.len) return error.EchoTooLong;
            @memcpy(got[gl..][0..outcome.plaintext.len], outcome.plaintext);
            gl += outcome.plaintext.len;
        }
    }
    for (probe_msg, 0..) |c, idx| try testing.expectEqual(c ^ @as(u8, 0xff), got[idx]);
}

fn spawnShim(io: std.Io, argv: []const []const u8) !std.process.Child {
    if (comptime builtin.os.tag == .windows) {
        // Threaded.init's default environment is empty. Winsock's provider
        // loader needs SystemRoot to locate its DLLs in a spawned child.
        var wide: [1024]u16 = undefined;
        const len = win.GetEnvironmentVariableW(std.unicode.utf8ToUtf16LeStringLiteral("SystemRoot"), &wide, wide.len);
        if (len == 0 or len >= wide.len) return error.MissingSystemRoot;
        var root: [2048]u8 = undefined;
        const root_len = try std.unicode.utf16LeToUtf8(&root, wide[0..len]);
        var environ = std.process.Environ.Map.init(testing.allocator);
        defer environ.deinit();
        try environ.put("SystemRoot", root[0..root_len]);
        return std.process.spawn(io, .{
            .argv = argv,
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .ignore,
            .environ_map = &environ,
        });
    }
    return std.process.spawn(io, .{
        .argv = argv,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
}

fn expectExit(term: std.process.Child.Term, code: u8) !void {
    switch (term) {
        .exited => |c| try testing.expectEqual(code, c),
        else => return error.TestUnexpectedResult,
    }
}

test "subprocess: shim as TLS 1.3 server completes handshake, selects ALPN, echoes, exits 0" {
    if (builtin.os.tag != .linux and builtin.os.tag != .windows) return error.SkipZigTest;
    var pathbuf: [1024]u8 = undefined;
    const bin = shimBinPath(&pathbuf) orelse return error.SkipZigTest;
    const alloc = testing.allocator;

    const listen_fd = try listenLoopback();
    defer {
        socketClose(listen_fd);
        socketCleanup();
    }
    const port = try loopbackPort(listen_fd);

    var io_t = std.Io.Threaded.init(alloc, .{});
    defer io_t.deinit();
    const io = io_t.io();

    var port_buf: [8]u8 = undefined;
    const port_str = try std.fmt.bufPrint(&port_buf, "{d}", .{port});
    const argv = [_][]const u8{ bin, "-server", "-port", port_str, "-shim-id", "42", "-expect-version", "772", "-select-alpn", "h2", "-expect-alpn", "h2" };
    var child = try spawnShim(io, &argv);
    errdefer child.kill(io);

    const afd = try acceptWithTimeout(listen_fd, 5000);
    {
        errdefer socketClose(afd);
        setReadTimeout(afd, 5000);
        var idbuf: [8]u8 = undefined;
        try readExact(afd, &idbuf);
        try testing.expectEqual(@as(u64, 42), std.mem.readInt(u64, &idbuf, .little));
        try peerClientVerifyEcho(alloc, afd, &.{"h2"});
    }
    socketClose(afd); // TCP FIN ⇒ shim echo loop hits EOF ⇒ exits 0.

    try expectExit(try child.wait(io), 0);
}

test "subprocess: shim as TLS 1.3 client completes handshake, echoes, exits 0" {
    if (builtin.os.tag != .linux and builtin.os.tag != .windows) return error.SkipZigTest;
    var pathbuf: [1024]u8 = undefined;
    const bin = shimBinPath(&pathbuf) orelse return error.SkipZigTest;
    const alloc = testing.allocator;

    var cert_buf: [1024]u8 = undefined;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x51)));
    const cert_der = try makeEd25519Leaf(&cert_buf, kp);

    const listen_fd = try listenLoopback();
    defer {
        socketClose(listen_fd);
        socketCleanup();
    }
    const port = try loopbackPort(listen_fd);

    var io_t = std.Io.Threaded.init(alloc, .{});
    defer io_t.deinit();
    const io = io_t.io();

    var port_buf: [8]u8 = undefined;
    const port_str = try std.fmt.bufPrint(&port_buf, "{d}", .{port});
    const argv = [_][]const u8{ bin, "-port", port_str, "-shim-id", "77", "-expect-version", "772" };
    var child = try spawnShim(io, &argv);
    errdefer child.kill(io);

    const afd = try acceptWithTimeout(listen_fd, 5000);
    {
        errdefer socketClose(afd);
        setReadTimeout(afd, 5000);
        var idbuf: [8]u8 = undefined;
        try readExact(afd, &idbuf);
        try testing.expectEqual(@as(u64, 77), std.mem.readInt(u64, &idbuf, .little));
        try peerServerVerifyEcho(alloc, afd, cert_der, kp);
    }
    socketClose(afd);

    try expectExit(try child.wait(io), 0);
}

test "subprocess: shim client honors -curves 23 (secp256r1), exits 0" {
    if (builtin.os.tag != .linux and builtin.os.tag != .windows) return error.SkipZigTest;
    var pathbuf: [1024]u8 = undefined;
    const bin = shimBinPath(&pathbuf) orelse return error.SkipZigTest;
    const alloc = testing.allocator;

    var cert_buf: [1024]u8 = undefined;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x22)));
    const cert_der = try makeEd25519Leaf(&cert_buf, kp);

    const listen_fd = try listenLoopback();
    defer {
        socketClose(listen_fd);
        socketCleanup();
    }
    const port = try loopbackPort(listen_fd);

    var io_t = std.Io.Threaded.init(alloc, .{});
    defer io_t.deinit();
    const io = io_t.io();

    var port_buf: [8]u8 = undefined;
    const port_str = try std.fmt.bufPrint(&port_buf, "{d}", .{port});
    const argv = [_][]const u8{ bin, "-port", port_str, "-shim-id", "5", "-curves", "23" };
    var child = try spawnShim(io, &argv);
    errdefer child.kill(io);

    const afd = try acceptWithTimeout(listen_fd, 5000);
    {
        errdefer socketClose(afd);
        setReadTimeout(afd, 5000);
        var idbuf: [8]u8 = undefined;
        try readExact(afd, &idbuf);
        try peerServerVerifyEcho(alloc, afd, cert_der, kp);
    }
    socketClose(afd);

    try expectExit(try child.wait(io), 0);
}

test "subprocess: unimplemented flag ⇒ exit 89 (no dial)" {
    if (builtin.os.tag != .linux and builtin.os.tag != .windows) return error.SkipZigTest;
    var pathbuf: [1024]u8 = undefined;
    const bin = shimBinPath(&pathbuf) orelse return error.SkipZigTest;
    const alloc = testing.allocator;

    var io_t = std.Io.Threaded.init(alloc, .{});
    defer io_t.deinit();
    const io = io_t.io();

    const argv = [_][]const u8{ bin, "-port", "1", "-resume-count", "1" };
    var child = try spawnShim(io, &argv);
    errdefer child.kill(io);
    try expectExit(try child.wait(io), 89);
}

test "subprocess: malformed ClientHello ⇒ handshake failure, nonzero (not 89)" {
    if (builtin.os.tag != .linux and builtin.os.tag != .windows) return error.SkipZigTest;
    var pathbuf: [1024]u8 = undefined;
    const bin = shimBinPath(&pathbuf) orelse return error.SkipZigTest;
    const alloc = testing.allocator;

    const listen_fd = try listenLoopback();
    defer {
        socketClose(listen_fd);
        socketCleanup();
    }
    const port = try loopbackPort(listen_fd);

    var io_t = std.Io.Threaded.init(alloc, .{});
    defer io_t.deinit();
    const io = io_t.io();

    var port_buf: [8]u8 = undefined;
    const port_str = try std.fmt.bufPrint(&port_buf, "{d}", .{port});
    const argv = [_][]const u8{ bin, "-server", "-port", port_str, "-shim-id", "9" };
    var child = try spawnShim(io, &argv);
    errdefer child.kill(io);

    const afd = try acceptWithTimeout(listen_fd, 5000);
    {
        errdefer socketClose(afd);
        setReadTimeout(afd, 5000);
        var idbuf: [8]u8 = undefined;
        try readExact(afd, &idbuf);
        // A complete handshake record carrying a zero-length ClientHello body —
        // enough for the engine to parse and reject (decode error).
        const bad = [_]u8{ 0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00 };
        try sockWriteAll(afd, &bad);
    }
    socketClose(afd);

    switch (try child.wait(io)) {
        .exited => |c| {
            try testing.expect(c != 0);
            try testing.expect(c != exit_unimplemented);
        },
        else => return error.TestUnexpectedResult,
    }
}
