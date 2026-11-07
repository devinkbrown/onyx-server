// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! `armor s_server` — minimal TLS 1.3 echo server over the Armor `tls_server`
//! engine. It accepts connections one at a time, completes the handshake,
//! prints the negotiated session, and echoes every application-data byte back
//! until the client closes. Optional material mirrors the daemon's `[tls]`
//! knobs so operators can rehearse a deployment offline: an OCSP staple, an
//! ECH key (`armor ech-gen` output, loaded through `daemon/tls_ech_load.zig`),
//! and a delegated credential (`armor dc mint` output).
//!
//! Not the daemon reactor: no kTLS, no session tickets, no 0-RTT.

const std = @import("std");
const onyx_server = @import("onyx_server");
const common = @import("common.zig");
const transport = @import("tls_transport.zig");
const ech_gen_cmd = @import("ech_gen_cmd.zig");

const tls_server = onyx_server.crypto.tls_server;
const tls_certs = onyx_server.daemon.tls_certs;
const tls_ech_load = onyx_server.daemon.tls_ech_load;
const delegated_credential_cli = onyx_server.daemon.delegated_credential_cli;
const dc_mint = delegated_credential_cli.dc_mint;

const Allocator = std.mem.Allocator;
const Writer = common.Writer;
const net = std.Io.net;

pub const Options = struct {
    accept: ?[]const u8 = null,
    cert: ?[]const u8 = null,
    key: ?[]const u8 = null,
    alpn: ?[]const u8 = null,
    /// Stop after this many connections; 0 = serve forever.
    naccept: u32 = 0,
    status_file: ?[]const u8 = null,
    ech_config: ?[]const u8 = null,
    ech_key: ?[]const u8 = null,
    dc: ?[]const u8 = null,
    dc_key: ?[]const u8 = null,
    /// A client that has not finished the handshake within this many
    /// milliseconds is dropped, so one idle peer cannot stall this
    /// one-connection-at-a-time server.
    handshake_timeout_ms: u32 = default_handshake_timeout_ms,
};

pub const default_handshake_timeout_ms: u32 = 10_000;

/// Per-listener serving limits.
pub const Limits = struct {
    /// Stop after this many connections; 0 = serve forever.
    naccept: u32 = 0,
    handshake_timeout_ms: u32 = default_handshake_timeout_ms,
};

pub fn usage(w: *Writer) Writer.Error!void {
    try w.writeAll(
        \\usage: armor s_server -accept [host:]port -cert <chain.pem> -key <key.pem> [options]
        \\  -accept [host:]port   listen address (default host 0.0.0.0)
        \\  -cert <chain.pem>     leaf-first certificate chain (PEM or DER)
        \\  -key <key.pem>        leaf private key (Ed25519, P-256, or RSA)
        \\  -alpn p1,p2           ALPN protocols to select from, in preference order
        \\  -naccept <n>          exit after n connections (default: serve forever)
        \\  -status_file <der>    OCSP response to staple (RFC 6066 / RFC 8446 4.4.2.1)
        \\  -ech-config <file>    ECHConfigList from `armor ech-gen`  (with -ech-key)
        \\  -ech-key <file>       matching hex X25519 key file        (with -ech-config)
        \\  -dc <file>            delegated credential from `armor dc mint` (with -dc-key)
        \\  -dc-key <pem>         the delegated credential's private key
        \\
        \\TLS 1.3 echo server: every byte received is sent back.
        \\
    );
}

pub fn parseArgs(args: []const []const u8) common.Error!Options {
    var opts = Options{};
    var cur = common.ArgCursor{ .args = args };
    while (cur.next()) |a| {
        if (std.mem.eql(u8, a, "-accept")) {
            opts.accept = try cur.value();
        } else if (std.mem.eql(u8, a, "-cert")) {
            opts.cert = try cur.value();
        } else if (std.mem.eql(u8, a, "-key")) {
            opts.key = try cur.value();
        } else if (std.mem.eql(u8, a, "-alpn")) {
            opts.alpn = try cur.value();
        } else if (std.mem.eql(u8, a, "-naccept")) {
            opts.naccept = std.fmt.parseInt(u32, try cur.value(), 10) catch return error.Usage;
        } else if (std.mem.eql(u8, a, "-status_file")) {
            opts.status_file = try cur.value();
        } else if (std.mem.eql(u8, a, "-ech-config")) {
            opts.ech_config = try cur.value();
        } else if (std.mem.eql(u8, a, "-ech-key")) {
            opts.ech_key = try cur.value();
        } else if (std.mem.eql(u8, a, "-dc")) {
            opts.dc = try cur.value();
        } else if (std.mem.eql(u8, a, "-dc-key")) {
            opts.dc_key = try cur.value();
        } else {
            return error.Usage;
        }
    }
    if (opts.accept == null or opts.cert == null or opts.key == null) return error.Usage;
    if ((opts.ech_config == null) != (opts.ech_key == null)) return error.Usage;
    if ((opts.dc == null) != (opts.dc_key == null)) return error.Usage;
    return opts;
}

/// Parse `-accept`: a bare port binds 0.0.0.0, otherwise `host:port`.
pub fn listenAddress(spec: []const u8) !net.IpAddress {
    if (std.fmt.parseInt(u16, spec, 10)) |port| {
        return .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = port } };
    } else |_| {}
    const hp = try transport.splitHostPort(spec);
    return net.IpAddress.parse(hp.host, hp.port) catch error.BadEndpoint;
}

/// Everything loaded from disk for one `run`. Owns all of it.
const Material = struct {
    loaded: tls_certs.Loaded,
    staple: []u8 = &.{},
    ech: ?tls_ech_load.Loaded = null,
    dc_wire: []u8 = &.{},
    dc_key: ?tls_certs.Loaded = null,

    fn deinit(self: *Material, gpa: Allocator) void {
        self.loaded.deinit(gpa);
        gpa.free(self.staple);
        if (self.ech) |*e| e.deinit(gpa);
        gpa.free(self.dc_wire);
        if (self.dc_key) |*k| k.deinit(gpa);
    }
};

pub fn run(gpa: Allocator, io: std.Io, opts: Options, out: *Writer) !void {
    const addr = try listenAddress(opts.accept orelse return error.Usage);

    var m: Material = .{ .loaded = try tls_certs.loadOrBootstrap(gpa, io, .{
        .cert_path = opts.cert orelse return error.Usage,
        .key_path = opts.key orelse return error.Usage,
    }) };
    defer m.deinit(gpa);
    if (m.loaded.cert_chain.len == 0) return error.EmptyCertificateChain;

    if (opts.status_file) |p| m.staple = try common.readInput(gpa, io, p);
    if (opts.ech_config) |cfg_path| {
        var private_key = try ech_gen_cmd.readKeyFile(gpa, io, opts.ech_key.?);
        defer std.crypto.secureZero(u8, &private_key);
        m.ech = try tls_ech_load.load(gpa, io, &.{.{ .config_path = cfg_path, .private_key = private_key }});
    }
    if (opts.dc) |dc_path| {
        m.dc_wire = try std.Io.Dir.cwd().readFileAlloc(io, dc_path, gpa, .limited(delegated_credential_cli.max_dc_file_bytes));
        // Refuse to serve a DC that a client would reject (wrong leaf, expired,
        // over seven days, missing DelegationUsage) — fail at startup instead.
        _ = try delegated_credential_cli.validateChain(gpa, m.dc_wire, m.loaded.cert_chain, null);
        // tls_certs only reads the key half here; the chain is reused.
        m.dc_key = try tls_certs.loadOrBootstrap(gpa, io, .{ .cert_path = opts.cert.?, .key_path = opts.dc_key.? });
    }
    // tls_server.Server.init only compares key types; compare the actual
    // public keys so a wrong -key / -dc-key fails here, not per handshake.
    try checkKeys(&m);

    var alpn_storage: [transport.max_alpn][]const u8 = undefined;
    const alpn: []const []const u8 = if (opts.alpn) |text| try transport.splitAlpn(text, &alpn_storage) else &.{};

    var cfg: tls_server.Config = .{
        .cert_chain = m.loaded.cert_chain,
        .signing_key = m.loaded.signing_key,
        .ecdsa_p256_signing_key = m.loaded.ecdsa_p256_signing_key,
        .rsa_signing_key = m.loaded.rsa_signing_key,
        .alpn_protocols = alpn,
        .ocsp_staple = m.staple,
        .now_unix_seconds = common.wallClockSeconds(),
    };
    if (m.ech) |e| {
        cfg.ech_keys = e.keys;
        cfg.ech_retry_config_list = e.retry_config_list;
    }
    if (m.dc_key) |k| {
        cfg.delegated_credential = .{
            .wire = m.dc_wire,
            .private_key = if (k.ecdsa_p256_signing_key) |kp|
                .{ .ecdsa_p256 = kp }
            else if (k.signing_key) |kp|
                .{ .ed25519 = kp }
            else
                return error.UnsupportedAlgorithm,
        };
    }
    // Fail at startup on a key/cert or ECH key/config mismatch.
    {
        var probe = try tls_server.Server.init(gpa, cfg);
        probe.deinit();
    }

    var server = try addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    try out.print("ACCEPT {f}\n", .{server.socket.address});
    try out.flush();
    try serveListener(gpa, io, &server, cfg, .{ .naccept = opts.naccept, .handshake_timeout_ms = opts.handshake_timeout_ms }, out);
}

/// Prove the loaded private keys are the private halves of the certificate
/// SPKI and of the delegated credential's SPKI (same comparison `dc mint`
/// uses), not merely keys of the right type.
fn checkKeys(m: *const Material) !void {
    const leaf_key: dc_mint.LeafKey = if (m.loaded.ecdsa_p256_signing_key) |kp|
        .{ .ecdsa_p256 = kp }
    else if (m.loaded.signing_key) |kp|
        .{ .ed25519 = kp }
    else if (m.loaded.rsa_signing_key) |k|
        .{ .rsa = k }
    else
        return error.UnsupportedAlgorithm;
    try dc_mint.checkLeafKey(m.loaded.cert_chain[0], leaf_key);
    if (m.dc_key) |k| {
        const dc_key: dc_mint.DcPrivateKey = if (k.ecdsa_p256_signing_key) |kp|
            .{ .ecdsa_p256 = kp }
        else if (k.signing_key) |kp|
            .{ .ed25519 = kp }
        else
            return error.UnsupportedAlgorithm;
        try dc_mint.checkDcKey(m.dc_wire, dc_key);
    }
}

/// Accept and serve connections sequentially. A failed connection, and a
/// transient accept failure (fd exhaustion, a connection aborted before
/// accept), is logged and does not stop the server; `naccept == 0` serves
/// forever.
pub fn serveListener(gpa: Allocator, io: std.Io, server: *net.Server, cfg: tls_server.Config, limits: Limits, out: *Writer) !void {
    var served: u32 = 0;
    while (limits.naccept == 0 or served < limits.naccept) {
        const stream = server.accept(io) catch |err| switch (err) {
            error.ProcessFdQuotaExceeded,
            error.SystemFdQuotaExceeded,
            error.SystemResources,
            error.ConnectionAborted,
            error.BlockedByFirewall,
            error.ProtocolFailure,
            error.WouldBlock,
            => {
                try out.print("accept error: {s}\n", .{@errorName(err)});
                try out.flush();
                // Back off so fd exhaustion does not spin the CPU.
                try io.sleep(.fromMilliseconds(100), .awake);
                continue;
            },
            else => return err,
        };
        defer stream.close(io);
        served += 1;
        serveConnection(gpa, io, stream, cfg, limits.handshake_timeout_ms, out) catch |err| {
            try out.print("connection error: {s}\n", .{@errorName(err)});
        };
        try out.flush();
    }
}

/// Handshake one accepted stream and echo application data until EOF or an
/// alert (close_notify included). The handshake must complete within
/// `handshake_timeout_ms`; the echo phase has no idle limit.
pub fn serveConnection(gpa: Allocator, io: std.Io, stream: net.Stream, cfg: tls_server.Config, handshake_timeout_ms: u32, out: *Writer) !void {
    var engine = try tls_server.Server.init(gpa, cfg);
    defer engine.deinit();
    var rr: transport.RecordReader = .{};
    defer rr.deinit(gpa);

    const deadline = std.Io.Clock.awake.now(io).toMilliseconds() + @as(i64, handshake_timeout_ms);
    while (!engine.handshakeDone()) {
        const rec = try transport.readRecordBy(gpa, io, stream, &rr, deadline) orelse return error.ConnectionClosed;
        const result = engine.feed(rec) catch |err| {
            if (engine.takeAlert(err)) |alert| {
                defer gpa.free(alert);
                transport.sendAll(io, stream, alert) catch {};
            }
            return err;
        };
        switch (result) {
            .need_more => {},
            .bytes_to_send => |b| {
                defer gpa.free(b);
                try transport.sendAll(io, stream, b);
            },
        }
    }
    try flushPending(gpa, io, stream, &engine);
    try writeServerSession(&engine, out);
    try out.flush();

    var echoed: usize = 0;
    while (true) {
        const rec = try transport.readRecord(gpa, io, stream, &rr) orelse break;
        const plain = engine.decrypt(rec) catch |err| switch (err) {
            error.TlsAlert => break, // close_notify or a peer alert ends the echo
            else => {
                if (engine.takeAlert(err)) |alert| {
                    defer gpa.free(alert);
                    transport.sendAll(io, stream, alert) catch {};
                }
                return err;
            },
        };
        defer gpa.free(plain);
        try flushPending(gpa, io, stream, &engine);
        if (plain.len == 0) continue; // a consumed post-handshake control record
        const sealed = try engine.encrypt(plain);
        defer gpa.free(sealed);
        try transport.sendAll(io, stream, sealed);
        echoed += plain.len;
    }
    try out.print("DONE echoed {d} bytes\n", .{echoed});
}

fn flushPending(gpa: Allocator, io: std.Io, stream: net.Stream, engine: *tls_server.Server) !void {
    if (try engine.takePendingSend()) |b| {
        defer gpa.free(b);
        try transport.sendAll(io, stream, b);
    }
}

pub fn writeServerSession(engine: *const tls_server.Server, out: *Writer) !void {
    try out.writeAll("Protocol  : TLSv1.3\n");
    try out.print("Cipher    : {s}\n", .{engine.cipherName() orelse "(none)"});
    try out.print("Group     : {s}\n", .{transport.groupName(@backingInt(engine.selected_group))});
    try out.print("ALPN      : {s}\n", .{engine.selectedAlpn() orelse "(none)"});
    try out.print("ECH       : {s}\n", .{if (engine.ech_accepted) "accepted" else "not accepted"});
}

const testing = std.testing;

test "armorcli s_server parseArgs requires accept, cert, key and paired options" {
    try testing.expectError(error.Usage, parseArgs(&.{}));
    try testing.expectError(error.Usage, parseArgs(&.{ "-accept", "4433", "-cert", "c.pem" }));
    try testing.expectError(error.Usage, parseArgs(&.{ "-accept", "4433", "-cert", "c", "-key", "k", "-ech-config", "e" }));
    try testing.expectError(error.Usage, parseArgs(&.{ "-accept", "4433", "-cert", "c", "-key", "k", "-dc", "d" }));
    try testing.expectError(error.Usage, parseArgs(&.{ "-accept", "4433", "-cert", "c", "-key", "k", "-naccept", "x" }));
    const o = try parseArgs(&.{ "-accept", "127.0.0.1:4433", "-cert", "c", "-key", "k", "-alpn", "irc,h2", "-naccept", "1" });
    try testing.expectEqual(@as(u32, 1), o.naccept);
    var storage: [transport.max_alpn][]const u8 = undefined;
    const alpn = try transport.splitAlpn(o.alpn.?, &storage);
    try testing.expectEqual(@as(usize, 2), alpn.len);
    try testing.expectEqualStrings("h2", alpn[1]);
    try testing.expectError(error.Usage, transport.splitAlpn("a,,b", &storage));
    const a = try listenAddress("4433");
    try testing.expectEqual(@as(u16, 4433), a.getPort());
    const b = try listenAddress("127.0.0.1:0");
    try testing.expectEqual(@as(u16, 0), b.getPort());
}
