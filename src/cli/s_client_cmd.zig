// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! `armor s_client` — standalone TLS 1.3 client over the Armor `tls_client`
//! engine and a real TCP socket. It completes the handshake (full chain and
//! hostname verification against `-CAfile`, stapled-OCSP verification, optional
//! ECH and delegated credentials), prints the negotiated session, then relays
//! stdin to the server and the server's application data to stdout until either
//! side closes. Not the daemon reactor.
//!
//! The negotiated group, certificate chain and stapled OCSP response are read
//! back from the client's verified handshake transcript (`Client.transcript`:
//! ServerHello and Certificate exactly as authenticated by Finished, RFC 8446
//! §4.4.4). The engine has no accessors for them yet; see the integrator notes.
//!
//! On stdin EOF the client half-closes TCP (the engine cannot yet emit a
//! `close_notify`, RFC 8446 §6.1) and keeps reading until the server closes.

const std = @import("std");
const builtin = @import("builtin");
const onyx_server = @import("onyx_server");
const common = @import("common.zig");
const transport = @import("tls_transport.zig");
const x509_cmd = @import("x509_cmd.zig");

const tls_client = onyx_server.crypto.tls_client;
const tls_server = onyx_server.crypto.tls_server;
const x509 = onyx_server.crypto.x509;
const ocsp = onyx_server.crypto.ocsp;
const acme_cli = onyx_server.daemon.acme_cli;

const Allocator = std.mem.Allocator;
const Writer = common.Writer;
const net = std.Io.net;

pub const max_ech_file_bytes: usize = 64 * 1024;

pub const Input = union(enum) {
    /// Interactive: relay the process's stdin (poll(2) based; POSIX only).
    stdin,
    /// Send these bytes, half-close, and print the reply (tests, scripting).
    bytes: []const u8,
    /// Handshake and summary only (`-brief`).
    none,
};

pub const Options = struct {
    connect: ?[]const u8 = null,
    server_name: ?[]const u8 = null,
    name: ?[]const u8 = null,
    ca_file: []const u8 = "",
    alpn: ?[]const u8 = null,
    ech_file: ?[]const u8 = null,
    offer_dc: bool = false,
    /// On stdin EOF keep the connection open (no TCP half-close) and wait for
    /// the server to close, like `openssl s_client -ign_eof`.
    ign_eof: bool = false,
    input: Input = .stdin,
};

pub fn usage(w: *Writer) Writer.Error!void {
    try w.writeAll(
        \\usage: armor s_client -connect host:port -CAfile <bundle> [options]
        \\  -connect host:port  TCP peer
        \\  -servername <dns>   SNI (default: the connect host)
        \\  -name <dns>         hostname to verify (default: SNI)
        \\  -CAfile <bundle>    PEM trust anchors (required)
        \\  -alpn p1,p2         offer ALPN protocols, in preference order
        \\  -ech <file>         ECHConfigList (binary or base64) to encrypt the ClientHello;
        \\                      fails if no config is usable or the server rejects ECH
        \\  -dc                 offer delegated credentials (RFC 9345)
        \\  -ign_eof            on stdin EOF, wait for the server to close (no half-close)
        \\  -brief             print the session and exit (no stdin relay)
        \\
        \\Prints version, suite, group, ALPN, ECH, chain, and OCSP status, then
        \\relays stdin <-> server until either side closes.
        \\
    );
}

pub fn parseArgs(args: []const []const u8) common.Error!Options {
    var opts = Options{};
    var cur = common.ArgCursor{ .args = args };
    while (cur.next()) |a| {
        if (std.mem.eql(u8, a, "-connect")) {
            opts.connect = try cur.value();
        } else if (std.mem.eql(u8, a, "-servername")) {
            opts.server_name = try cur.value();
        } else if (std.mem.eql(u8, a, "-name")) {
            opts.name = try cur.value();
        } else if (std.mem.eql(u8, a, "-CAfile")) {
            opts.ca_file = try cur.value();
        } else if (std.mem.eql(u8, a, "-alpn")) {
            opts.alpn = try cur.value();
        } else if (std.mem.eql(u8, a, "-ech")) {
            opts.ech_file = try cur.value();
        } else if (std.mem.eql(u8, a, "-dc")) {
            opts.offer_dc = true;
        } else if (std.mem.eql(u8, a, "-ign_eof")) {
            opts.ign_eof = true;
        } else if (std.mem.eql(u8, a, "-brief")) {
            opts.input = .none;
        } else {
            return error.Usage;
        }
    }
    return opts;
}

pub fn run(gpa: Allocator, io: std.Io, opts: Options, out: *Writer) !void {
    const spec = opts.connect orelse return error.Usage;
    if (opts.ca_file.len == 0) return error.Usage;
    const hp = transport.splitHostPort(spec) catch return error.Usage;
    if (hp.port == 0) return error.Usage;
    // tls_client sends and verifies one name (RFC 6066 §3 SNI, RFC 6125
    // matching), so `-name` overrides `-servername`, which defaults to the
    // connect host.
    const verify_name = opts.name orelse opts.server_name orelse hp.host;

    const bundle_text = try common.readInput(gpa, io, opts.ca_file);
    defer gpa.free(bundle_text);
    var anchors = try acme_cli.loadTrustAnchors(gpa, bundle_text);
    defer {
        for (anchors.items) |a| gpa.free(a);
        anchors.deinit(gpa);
    }
    if (anchors.items.len == 0) return error.NoMatchingIssuer;
    const view = try gpa.alloc([]const u8, anchors.items.len);
    defer gpa.free(view);
    for (anchors.items, 0..) |a, i| view[i] = a;

    var alpn_storage: [transport.max_alpn][]const u8 = undefined;
    const alpn: []const []const u8 = if (opts.alpn) |text| try transport.splitAlpn(text, &alpn_storage) else &.{};

    const ech_list: ?[]u8 = if (opts.ech_file) |p| try readEchConfigList(gpa, io, p) else null;
    defer if (ech_list) |l| gpa.free(l);

    var client = try tls_client.Client.init(gpa, .{
        .server_name = verify_name,
        .trust_anchors = view,
        .alpn_protocols = alpn,
        .now_unix_seconds = common.wallClockSeconds(),
        .ech_config_list = ech_list,
    });
    defer client.deinit();
    if (opts.offer_dc) client.offerDelegatedCredentials();

    const stream = try transport.connect(io, hp.host, hp.port);
    defer stream.close(io);
    try out.print("CONNECTED {s}:{d}\n", .{ hp.host, hp.port });
    try out.flush();

    // One reader spans handshake and relay: records the server sent right
    // after its Finished (0.5-RTT data, RFC 8446 §4.4.4 / §2.3) may share a
    // TCP segment with the handshake flight and must not be dropped.
    var rr: transport.RecordReader = .{};
    defer rr.deinit(gpa);
    handshake(gpa, io, stream, &client, &rr, .{ .require_ech = ech_list != null }) catch |err| {
        switch (err) {
            error.EchNotUsable => try out.writeAll("ECH       : no usable ECHConfig in -ech file; ClientHello not sent\n"),
            error.EchRejected => try writeEchRejection(&client, out),
            else => {},
        }
        try out.flush();
        return err;
    };
    try writeSession(&client, out);
    try out.flush();

    switch (opts.input) {
        .none => {},
        .bytes => |b| try relayBytes(gpa, io, stream, &client, &rr, b, out),
        .stdin => try relayStdin(gpa, io, stream, &client, &rr, opts.ign_eof, out),
    }
}

pub const HandshakeOptions = struct {
    /// The caller supplied an ECHConfigList, so ECH is mandatory: a list with
    /// no usable config must not fall back to a cleartext inner SNI, and a
    /// server rejection must abort (RFC 9849 §6.1.6).
    require_ech: bool = false,
};

/// Drive the handshake over `stream`, one record at a time. On an engine
/// failure the matching fatal alert is sent before the error returns. Records
/// after the server Finished stay in `rr` for the caller.
///
/// With `require_ech`, fails with `error.EchNotUsable` before anything is
/// written when `tls_client` found no usable ECHConfig (it would otherwise
/// send an ordinary ClientHello carrying the real SNI), and with
/// `error.EchRejected` after sending an `ech_required` alert when the server
/// rejected ECH: then only the ECHConfig `public_name` was authenticated, so
/// the connection must not be used for the requested name (RFC 9849 §6.1.6).
pub fn handshake(gpa: Allocator, io: std.Io, stream: net.Stream, client: *tls_client.Client, rr: *transport.RecordReader, hs: HandshakeOptions) !void {
    {
        const hello = try client.start();
        defer gpa.free(hello);
        if (hs.require_ech and !client.echOffered()) return error.EchNotUsable;
        try transport.sendAll(io, stream, hello);
    }
    while (!client.handshakeDone()) {
        const rec = try transport.readRecord(gpa, io, stream, rr) orelse return error.ConnectionClosed;
        const result = client.feed(rec) catch |err| {
            if (client.takeAlert(err)) |alert| {
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
    // Whole records were fed one at a time, so the engine holds nothing back.
    if (client.pendingBytes().len != 0) return error.UnexpectedRecord;
    // RFC 9849 §6.1.6: after a rejection the handshake authenticated only the
    // outer public_name; the client MUST abort with ech_required.
    if (client.echOffered() and client.echAccepted() != true) {
        if (sealEchRequiredAlert(gpa, client)) |alert| {
            defer gpa.free(alert);
            transport.sendAll(io, stream, alert) catch {};
        } else |_| {}
        return error.EchRejected;
    }
}

/// RFC 9849 §11.2 AlertDescription ech_required.
pub const alert_ech_required: u8 = 121;

/// Seal a fatal `ech_required` alert under the client application traffic
/// keys (the client Finished has already been sent, RFC 8446 §7.1 / §5.2).
/// `tls_client.takeAlert` has no ech_required mapping, so this seals the one
/// record locally with the engine's current write keys and sequence number;
/// the connection is torn down right after, so the engine's own sequence
/// counter is advanced only for consistency.
pub fn sealEchRequiredAlert(gpa: Allocator, client: *tls_client.Client) ![]u8 {
    const tls_record = onyx_server.crypto.tls_record;
    const suite = client.selected_suite orelse return error.BadState;
    if (!client.handshakeDone()) return error.BadState;
    const seq = client.app_write_seq;
    if (seq == std.math.maxInt(u64)) return error.BadState;
    const body = [_]u8{ 2, alert_ech_required }; // fatal(2), RFC 8446 §6
    // TLSInnerPlaintext: content || ContentType.alert(21), no padding (§5.2).
    const inner = body ++ [_]u8{21};
    const keys = &client.client_app_keys;
    const tag_len: usize = 16;
    const out = try gpa.alloc(u8, tls_record.record_header_len + inner.len + tag_len);
    errdefer gpa.free(out);
    const aad = tls_record.makeAdditionalData(@intCast(inner.len + tag_len));
    @memcpy(out[0..tls_record.record_header_len], &aad);
    const nonce = tls_record.deriveNonce(keys.iv, seq);
    const ct = out[tls_record.record_header_len..][0..inner.len];
    var tag: [16]u8 = undefined;
    switch (suite) {
        .tls_aes_128_gcm_sha256 => {
            const A = std.crypto.aead.aes_gcm.Aes128Gcm;
            A.encrypt(ct, &tag, &inner, &aad, nonce, keys.key[0..A.key_length].*);
        },
        .tls_aes_256_gcm_sha384 => {
            const A = std.crypto.aead.aes_gcm.Aes256Gcm;
            A.encrypt(ct, &tag, &inner, &aad, nonce, keys.key[0..A.key_length].*);
        },
        .tls_chacha20_poly1305_sha256 => {
            const A = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
            A.encrypt(ct, &tag, &inner, &aad, nonce, keys.key[0..A.key_length].*);
        },
    }
    @memcpy(out[tls_record.record_header_len + inner.len ..], &tag);
    client.app_write_seq = seq + 1;
    return out;
}

/// Report an ECH rejection: the inner name was never authenticated, and the
/// server's retry_configs (authenticated by the public_name certificate,
/// RFC 9849 §6.1.6) are printed in the DNS HTTPS `ech=` base64 form for a
/// retry with `-ech`.
fn writeEchRejection(client: *const tls_client.Client, out: *Writer) !void {
    try out.writeAll("ECH       : rejected by server; aborted with ech_required (inner name not verified)\n");
    if (client.echRetryConfigs()) |rc| {
        try out.writeAll("retry_configs: ");
        try std.base64.standard.Encoder.encodeWriter(out, rc);
        try out.writeByte('\n');
    } else {
        try out.writeAll("retry_configs: (none)\n");
    }
}

const Step = enum { more, closed };

/// Decrypt one record and act on it.
fn onRecord(gpa: Allocator, io: std.Io, stream: net.Stream, client: *tls_client.Client, rec: []const u8, out: *Writer) !Step {
    const read = client.decryptApp(rec) catch |err| switch (err) {
        error.TlsAlert => {
            const alert = client.last_alert;
            if (alert) |al| {
                if (al.description == .close_notify) {
                    try out.writeAll("\nclosed by peer (close_notify)\n");
                    return .closed;
                }
                try out.print("\npeer alert: {s}\n", .{@tagName(al.description)});
            }
            return err;
        },
        else => {
            if (client.takeAlert(err)) |alert| {
                defer gpa.free(alert);
                transport.sendAll(io, stream, alert) catch {};
            }
            return err;
        },
    };
    switch (read) {
        .application_data => |pt| {
            defer gpa.free(pt);
            try out.writeAll(pt);
            try out.flush();
        },
        .control => {},
    }
    // A server KeyUpdate(update_requested) queues our KeyUpdate reply.
    if (try client.takePendingSend()) |reply| {
        defer gpa.free(reply);
        try transport.sendAll(io, stream, reply);
    }
    return .more;
}

/// Send `bytes`, half-close, and print everything until the server closes.
pub fn relayBytes(gpa: Allocator, io: std.Io, stream: net.Stream, client: *tls_client.Client, rr: *transport.RecordReader, bytes: []const u8, out: *Writer) !void {
    if (bytes.len != 0) {
        const sealed = try client.encrypt(bytes);
        defer gpa.free(sealed);
        try transport.sendAll(io, stream, sealed);
    }
    stream.shutdown(io, .send) catch {};
    while (try transport.readRecord(gpa, io, stream, rr)) |rec| {
        if (try onRecord(gpa, io, stream, client, rec, out) == .closed) return;
    }
}

/// Interactive relay: poll(2) over the socket and stdin.
pub fn relayStdin(gpa: Allocator, io: std.Io, stream: net.Stream, client: *tls_client.Client, rr: *transport.RecordReader, ign_eof: bool, out: *Writer) !void {
    if (comptime builtin.os.tag == .windows) return error.NotImplemented;
    const posix = std.posix;
    const stdin_fd = std.Io.File.stdin().handle;
    while (try rr.next()) |rec| {
        if (try onRecord(gpa, io, stream, client, rec, out) == .closed) return;
    }
    var fds = [_]posix.pollfd{
        .{ .fd = stream.socket.handle, .events = posix.POLL.IN, .revents = 0 },
        .{ .fd = stdin_fd, .events = posix.POLL.IN, .revents = 0 },
    };
    var nfds: usize = 2;
    var scratch: [16 * 1024]u8 = undefined;
    while (true) {
        _ = try posix.poll(fds[0..nfds], -1);
        if (fds[0].revents != 0) {
            const n = try transport.readSome(io, stream, &scratch);
            if (n == 0) {
                if (rr.hasPartial()) return error.TruncatedRecord;
                try out.writeAll("\nconnection closed by peer\n");
                return;
            }
            try rr.push(gpa, scratch[0..n]);
            while (try rr.next()) |rec| {
                if (try onRecord(gpa, io, stream, client, rec, out) == .closed) return;
            }
        }
        if (nfds == 2 and fds[1].revents != 0) {
            const n = posix.read(stdin_fd, &scratch) catch 0;
            if (n == 0) {
                if (!ign_eof) stream.shutdown(io, .send) catch {};
                nfds = 1;
            } else {
                const sealed = try client.encrypt(scratch[0..n]);
                defer gpa.free(sealed);
                try transport.sendAll(io, stream, sealed);
            }
        }
    }
}

/// Read an ECHConfigList file: raw bytes (2-byte length covering the rest) or
/// base64 text (the DNS HTTPS `ech=` form `armor ech-gen` prints).
pub fn readEchConfigList(gpa: Allocator, io: std.Io, path: []const u8) ![]u8 {
    const raw = try std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(max_ech_file_bytes));
    errdefer gpa.free(raw);
    if (raw.len >= 2 and @as(usize, std.mem.readInt(u16, raw[0..2], .big)) + 2 == raw.len) return raw;
    const text = std.mem.trim(u8, raw, " \t\r\n");
    const dec = std.base64.standard.Decoder;
    const n = dec.calcSizeForSlice(text) catch return error.BadEchConfigList;
    const list = try gpa.alloc(u8, n);
    errdefer gpa.free(list);
    dec.decode(list, text) catch return error.BadEchConfigList;
    if (list.len < 2 or @as(usize, std.mem.readInt(u16, list[0..2], .big)) + 2 != list.len) return error.BadEchConfigList;
    gpa.free(raw);
    return list;
}

/// Drive a ClientHello / server flight / client Finished exchange against an
/// in-memory `tls_server.Server` (no socket).
pub fn handshakeInMemory(
    gpa: Allocator,
    server: *tls_server.Server,
    client: *tls_client.Client,
) !void {
    const ch = try client.start();
    defer gpa.free(ch);
    const sflight = switch (try server.feed(ch)) {
        .bytes_to_send => |b| b,
        .need_more => return error.HandshakeIncomplete,
    };
    defer gpa.free(sflight);
    const cfin = switch (try client.feed(sflight)) {
        .bytes_to_send => |b| b,
        .need_more => return error.HandshakeIncomplete,
    };
    defer gpa.free(cfin);
    switch (try server.feed(cfin)) {
        .bytes_to_send => |b| gpa.free(b),
        .need_more => {},
    }
    if (!client.handshakeDone()) return error.HandshakeIncomplete;
}

/// What the verified transcript says about the server's flight.
pub const TranscriptInfo = struct {
    group: ?u16 = null,
    /// Body of the server Certificate message (RFC 8446 §4.4.2), if sent
    /// uncompressed.
    certificate: ?[]const u8 = null,
    compressed_certificate: bool = false,
};

/// Walk the handshake transcript (Handshake structs, RFC 8446 §4). The last
/// ServerHello wins, so a HelloRetryRequest (also type 2) is superseded.
pub fn scanTranscript(t: []const u8) TranscriptInfo {
    var info: TranscriptInfo = .{};
    var off: usize = 0;
    while (off + 4 <= t.len) {
        const typ = t[off];
        const len: usize = std.mem.readInt(u24, t[off + 1 ..][0..3], .big);
        if (off + 4 + len > t.len) break;
        const body = t[off + 4 ..][0..len];
        switch (typ) {
            2 => if (serverHelloGroup(body)) |g| {
                info.group = g;
            },
            11 => info.certificate = body,
            25 => info.compressed_certificate = true,
            else => {},
        }
        off += 4 + len;
    }
    return info;
}

/// key_share (51) group from a ServerHello body (RFC 8446 §4.1.3, §4.2.8).
fn serverHelloGroup(body: []const u8) ?u16 {
    var c: usize = 2 + 32; // legacy_version + random
    if (body.len < c + 1) return null;
    c += 1 + body[c]; // legacy_session_id_echo
    c += 2 + 1; // cipher_suite + legacy_compression_method
    if (body.len < c + 2) return null;
    const ext_len: usize = std.mem.readInt(u16, body[c..][0..2], .big);
    c += 2;
    if (body.len < c + ext_len) return null;
    const end = c + ext_len;
    while (c + 4 <= end) {
        const et = std.mem.readInt(u16, body[c..][0..2], .big);
        const el: usize = std.mem.readInt(u16, body[c + 2 ..][0..2], .big);
        c += 4;
        if (c + el > end) return null;
        if (et == 51 and el >= 2) return std.mem.readInt(u16, body[c..][0..2], .big);
        c += el;
    }
    return null;
}

/// Iterates a Certificate message body's CertificateEntry list.
pub const CertIterator = struct {
    list: []const u8,
    off: usize = 0,

    pub const Entry = struct { der: []const u8, ocsp_staple: ?[]const u8 };

    pub fn init(body: []const u8) ?CertIterator {
        if (body.len < 1) return null;
        const ctx_len = body[0];
        if (body.len < 1 + ctx_len + 3) return null;
        const p = 1 + ctx_len;
        const list_len: usize = std.mem.readInt(u24, body[p..][0..3], .big);
        if (body.len != p + 3 + list_len) return null;
        return .{ .list = body[p + 3 ..] };
    }

    pub fn next(self: *CertIterator) ?Entry {
        const l = self.list;
        if (self.off + 3 > l.len) return null;
        const der_len: usize = std.mem.readInt(u24, l[self.off..][0..3], .big);
        const der_start = self.off + 3;
        if (der_start + der_len + 2 > l.len) return null;
        const ext_len: usize = std.mem.readInt(u16, l[der_start + der_len ..][0..2], .big);
        const ext_start = der_start + der_len + 2;
        if (ext_start + ext_len > l.len) return null;
        self.off = ext_start + ext_len;
        return .{ .der = l[der_start..][0..der_len], .ocsp_staple = stapleFromExtensions(l[ext_start..][0..ext_len]) };
    }

    /// status_request (5) CertificateStatus: status_type ocsp(1) || uint24 len
    /// || OCSPResponse (RFC 8446 §4.4.2.1, RFC 6066 §8).
    fn stapleFromExtensions(ext: []const u8) ?[]const u8 {
        var c: usize = 0;
        while (c + 4 <= ext.len) {
            const et = std.mem.readInt(u16, ext[c..][0..2], .big);
            const el: usize = std.mem.readInt(u16, ext[c + 2 ..][0..2], .big);
            c += 4;
            if (c + el > ext.len) return null;
            if (et == 5 and el >= 4 and ext[c] == 1) {
                const rl: usize = std.mem.readInt(u24, ext[c + 1 ..][0..3], .big);
                if (4 + rl == el) return ext[c + 4 ..][0..rl];
                return null;
            }
            c += el;
        }
        return null;
    }
};

pub fn writeSession(client: *const tls_client.Client, out: *Writer) !void {
    const info = scanTranscript(client.transcript.items);
    try out.writeAll("Protocol  : TLSv1.3\n");
    try out.writeAll("Cipher    : ");
    if (client.selected_suite) |suite| {
        try out.writeAll(suiteIanaName(suite));
    } else {
        try out.writeAll("(none)");
    }
    try out.writeByte('\n');
    if (info.group) |g| {
        try out.print("Group     : {s} (0x{x:0>4})\n", .{ transport.groupName(g), g });
    } else {
        try out.writeAll("Group     : (unknown)\n");
    }
    try out.print("SNI       : {s}\n", .{client.server_name});
    try out.print("ALPN      : {s}\n", .{client.selected_alpn orelse "(none)"});
    try out.writeAll("ECH       : ");
    if (client.echAccepted()) |accepted| {
        try out.writeAll(if (accepted) "accepted\n" else "rejected (outer ClientHello used)\n");
        if (!accepted and client.echRetryConfigs() != null) try out.writeAll("            server sent retry_configs\n");
    } else {
        try out.writeAll("not offered\n");
    }
    if (client.offer_delegated_credential) {
        try out.print("Delegated : {s}\n", .{if (client.dc_verified_key != null) "used (CertificateVerify by DC key)" else "not presented"});
    }

    var leaf_serial: ?[]const u8 = null;
    var staple: ?[]const u8 = null;
    if (info.certificate) |body| {
        try out.writeAll("Certificate chain\n");
        if (CertIterator.init(body)) |it_init| {
            var it = it_init;
            var i: usize = 0;
            while (it.next()) |entry| : (i += 1) {
                const cert = x509.parse(entry.der) catch {
                    try out.print(" {d} <unparsable certificate>\n", .{i});
                    continue;
                };
                try out.print(" {d} s:", .{i});
                try x509_cmd.writeNameTlv(cert.subject_der, out);
                try out.writeAll("\n   i:");
                try x509_cmd.writeNameTlv(cert.issuer_der, out);
                try out.print("\n   v:{d} .. {d}\n", .{ cert.not_before.epoch_seconds, cert.not_after.epoch_seconds });
                if (i == 0) {
                    leaf_serial = cert.serial_der;
                    staple = entry.ocsp_staple;
                }
            }
        }
    } else if (info.compressed_certificate) {
        try out.writeAll("Certificate chain: (compressed, RFC 8879)\n");
    } else {
        try out.writeAll("Certificate chain: (none; PSK or raw public key)\n");
    }

    try out.writeAll("OCSP      : ");
    if (staple) |der| {
        // tls_client already authenticated this response against the issuer
        // and rejected a revoked or stale one, so only the status is reported.
        const status: ?ocsp.CertStatus = if (ocsp.parse(der)) |parsed|
            if (leaf_serial) |s| ocsp.statusForSerial(parsed, s) else null
        else |_|
            null;
        if (status) |s| {
            try out.print("{s} (stapled, verified)\n", .{@tagName(s)});
        } else {
            try out.writeAll("stapled (status not found)\n");
        }
    } else {
        try out.writeAll("no response sent\n");
    }
    try out.writeAll("Verify return code: 0 (ok)\n");
}

fn suiteIanaName(suite: anytype) []const u8 {
    return switch (suite) {
        .tls_aes_128_gcm_sha256 => "TLS_AES_128_GCM_SHA256",
        .tls_aes_256_gcm_sha384 => "TLS_AES_256_GCM_SHA384",
        .tls_chacha20_poly1305_sha256 => "TLS_CHACHA20_POLY1305_SHA256",
    };
}

// ===========================================================================
// Tests
// ===========================================================================

const testing = std.testing;
const x509_selfsign = onyx_server.proto.x509_selfsign;
const pem = onyx_server.proto.pem;
const s_server_cmd = @import("s_server_cmd.zig");
const ech_gen_cmd = @import("ech_gen_cmd.zig");
const Ed25519 = std.crypto.sign.Ed25519;

test "armorcli s_client parseArgs accepts connect, SNI, ALPN, ECH and DC flags" {
    try testing.expectError(error.Usage, parseArgs(&.{"-bogus"}));
    const opts = try parseArgs(&.{
        "-connect",    "irc.test:6697",
        "-servername", "irc.test",
        "-CAfile",     "ca.pem",
        "-alpn",       "irc,h2",
        "-ech",        "ech.bin",
        "-dc",         "-brief",
    });
    try testing.expectEqualStrings("irc.test:6697", opts.connect.?);
    try testing.expectEqualStrings("irc.test", opts.server_name.?);
    try testing.expectEqualStrings("ca.pem", opts.ca_file);
    try testing.expectEqualStrings("irc,h2", opts.alpn.?);
    try testing.expectEqualStrings("ech.bin", opts.ech_file.?);
    try testing.expect(opts.offer_dc);
    try testing.expect(opts.input == .none);
}

test "armorcli s_client loopback handshake prints suite, group, chain, and verify ok" {
    const gpa = testing.allocator;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x37)));
    var cert_buf: [1024]u8 = undefined;
    const der = try x509_selfsign.buildSelfSigned(&cert_buf, .{
        .common_name = "irc.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x12, 0x34 },
        .key_pair = kp,
        .dns_names = &.{"irc.test"},
        .is_ca = true,
    });

    var server = try tls_server.Server.init(gpa, .{ .cert_chain = &.{der}, .signing_key = kp });
    defer server.deinit();
    var client = try tls_client.Client.init(gpa, .{ .server_name = "irc.test", .trust_anchors = &.{der} });
    defer client.deinit();

    try handshakeInMemory(gpa, &server, &client);
    try testing.expect(client.handshakeDone());
    try testing.expect(server.handshakeDone());

    var aw = Writer.Allocating.init(gpa);
    defer aw.deinit();
    try writeSession(&client, &aw.writer);
    const w = aw.written();
    try testing.expect(std.mem.indexOf(u8, w, "Protocol  : TLSv1.3") != null);
    try testing.expect(std.mem.indexOf(u8, w, "TLS_") != null);
    try testing.expect(std.mem.indexOf(u8, w, "SNI       : irc.test") != null);
    try testing.expect(std.mem.indexOf(u8, w, "s:CN=irc.test") != null);
    try testing.expect(std.mem.indexOf(u8, w, "OCSP      : no response sent") != null);
    try testing.expect(std.mem.indexOf(u8, w, "Verify return code: 0 (ok)") != null);
    // The group printed is the one the server actually selected.
    var buf: [64]u8 = undefined;
    const line = try std.fmt.bufPrint(&buf, "Group     : {s}", .{transport.groupName(@backingInt(server.selected_group))});
    try testing.expect(std.mem.indexOf(u8, w, line) != null);
}

test "armorcli s_client scanTranscript skips truncated input and reads the last ServerHello" {
    try testing.expect(scanTranscript(&.{ 2, 0, 0, 9 }).group == null);
    // Minimal ServerHello: version, random, empty sid, suite, comp, ext(key_share 0x001d).
    var sh: [4 + 2 + 32 + 1 + 3 + 2 + 6]u8 = @splat(0);
    sh[0] = 2;
    std.mem.writeInt(u24, sh[1..4], sh.len - 4, .big);
    std.mem.writeInt(u16, sh[42..44], 6, .big);
    std.mem.writeInt(u16, sh[44..46], 51, .big);
    std.mem.writeInt(u16, sh[46..48], 2, .big);
    std.mem.writeInt(u16, sh[48..50], 0x11ec, .big);
    try testing.expectEqual(@as(?u16, 0x11ec), scanTranscript(&sh).group);
    try testing.expect(CertIterator.init(&.{ 0, 0, 0, 5 }) == null);
}

/// Mint a fixture cert + key on disk and return its pieces.
const Fixture = struct {
    kp: Ed25519.KeyPair,
    der: []const u8,
    cert_path: []u8,
    key_path: []u8,
    buf: [1024]u8 = undefined,

    fn deinit(self: *Fixture, gpa: Allocator) void {
        gpa.free(self.cert_path);
        gpa.free(self.key_path);
    }
};

fn writeFixture(gpa: Allocator, tmp: *std.testing.TmpDir, buf: *[1024]u8, seed: u8) !Fixture {
    return writeFixtureNames(gpa, tmp, buf, seed, &.{ "localhost", "cover.example" });
}

fn writeFixtureNames(gpa: Allocator, tmp: *std.testing.TmpDir, buf: *[1024]u8, seed: u8, dns_names: []const []const u8) !Fixture {
    const io = testing.io;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(seed)));
    const now = common.wallClockSeconds();
    const der = try x509_selfsign.buildSelfSigned(buf, .{
        .common_name = "localhost",
        .not_before = now - 3600,
        .not_after = now + 30 * 86400,
        .serial = &.{seed},
        .key_pair = kp,
        .dns_names = dns_names,
        .is_ca = true,
        .delegation_usage = true,
        .key_usage_digital_signature = true,
    });
    var pem_buf: [2048]u8 = undefined;
    try tmp.dir.writeFile(io, .{ .sub_path = "cert.pem", .data = try pem.encode(&pem_buf, "CERTIFICATE", der) });
    const key_der = @import("pkey_cmd.zig").ed25519Pkcs8Der(kp.secret_key.seed());
    try tmp.dir.writeFile(io, .{ .sub_path = "key.pem", .data = try pem.encode(&pem_buf, "PRIVATE KEY", &key_der) });
    return .{
        .kp = kp,
        .der = der,
        .cert_path = try std.fmt.allocPrint(gpa, ".zig-cache/tmp/{s}/cert.pem", .{tmp.sub_path}),
        .key_path = try std.fmt.allocPrint(gpa, ".zig-cache/tmp/{s}/key.pem", .{tmp.sub_path}),
    };
}

const ServerThread = struct {
    gpa: Allocator,
    listener: net.Server,
    cfg: tls_server.Config,
    log: Writer.Allocating,
    err: ?anyerror = null,
    handshake_timeout_ms: u32 = s_server_cmd.default_handshake_timeout_ms,

    fn main(self: *ServerThread) void {
        s_server_cmd.serveListener(self.gpa, testing.io, &self.listener, self.cfg, .{ .naccept = 1, .handshake_timeout_ms = self.handshake_timeout_ms }, &self.log.writer) catch |e| {
            self.err = e;
        };
    }
};

fn startServer(gpa: Allocator, st: *ServerThread, cfg: tls_server.Config) !std.Thread {
    const addr: net.IpAddress = .{ .ip4 = .loopback(0) };
    st.* = .{ .gpa = gpa, .listener = try addr.listen(testing.io, .{ .reuse_address = true }), .cfg = cfg, .log = .init(gpa) };
    return std.Thread.spawn(.{}, ServerThread.main, .{st});
}

test "armorcli s_client and s_server complete a real TCP handshake and echo" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [1024]u8 = undefined;
    var fx = try writeFixture(gpa, &tmp, &buf, 0x41);
    defer fx.deinit(gpa);

    var st: ServerThread = undefined;
    const thread = try startServer(gpa, &st, .{ .cert_chain = &.{fx.der}, .signing_key = fx.kp, .alpn_protocols = &.{"irc"} });
    defer {
        st.listener.deinit(io);
        st.log.deinit();
    }
    const port = st.listener.socket.address.getPort();
    var connect_buf: [32]u8 = undefined;
    const connect = try std.fmt.bufPrint(&connect_buf, "127.0.0.1:{d}", .{port});

    var aw = Writer.Allocating.init(gpa);
    defer aw.deinit();
    var opts = try parseArgs(&.{ "-connect", connect, "-servername", "localhost", "-CAfile", fx.cert_path, "-alpn", "h2,irc" });
    opts.input = .{ .bytes = "PING :armor\r\n" };
    try run(gpa, io, opts, &aw.writer);
    thread.join();
    if (st.err) |e| return e;

    const w = aw.written();
    try testing.expect(std.mem.indexOf(u8, w, "CONNECTED 127.0.0.1:") != null);
    try testing.expect(std.mem.indexOf(u8, w, "ALPN      : irc") != null);
    try testing.expect(std.mem.indexOf(u8, w, "s:CN=localhost") != null);
    try testing.expect(std.mem.indexOf(u8, w, "Verify return code: 0 (ok)") != null);
    try testing.expect(std.mem.endsWith(u8, w, "PING :armor\r\n"));
    try testing.expect(std.mem.indexOf(u8, st.log.written(), "DONE echoed 13 bytes") != null);
    try testing.expect(std.mem.indexOf(u8, st.log.written(), "ALPN      : irc") != null);
}

test "armorcli s_client rejects an untrusted server and the wrong name" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [1024]u8 = undefined;
    var fx = try writeFixture(gpa, &tmp, &buf, 0x42);
    defer fx.deinit(gpa);
    // A stranger CA bundle.
    var other_buf: [1024]u8 = undefined;
    const other_kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x43)));
    const other = try x509_selfsign.buildSelfSigned(&other_buf, .{
        .common_name = "other",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{0x43},
        .key_pair = other_kp,
        .is_ca = true,
    });
    var pem_buf: [2048]u8 = undefined;
    try tmp.dir.writeFile(io, .{ .sub_path = "other.pem", .data = try pem.encode(&pem_buf, "CERTIFICATE", other) });
    const other_path = try std.fmt.allocPrint(gpa, ".zig-cache/tmp/{s}/other.pem", .{tmp.sub_path});
    defer gpa.free(other_path);

    for ([_]struct { ca: []const u8, sni: []const u8 }{
        .{ .ca = other_path, .sni = "localhost" },
        .{ .ca = fx.cert_path, .sni = "wrong.example" },
    }) |case| {
        var st: ServerThread = undefined;
        const thread = try startServer(gpa, &st, .{ .cert_chain = &.{fx.der}, .signing_key = fx.kp });
        defer {
            st.listener.deinit(io);
            st.log.deinit();
        }
        var connect_buf: [32]u8 = undefined;
        const connect = try std.fmt.bufPrint(&connect_buf, "127.0.0.1:{d}", .{st.listener.socket.address.getPort()});
        var aw = Writer.Allocating.init(gpa);
        defer aw.deinit();
        const result = run(gpa, io, try parseArgs(&.{ "-connect", connect, "-servername", case.sni, "-CAfile", case.ca, "-brief" }), &aw.writer);
        thread.join();
        try testing.expect(std.meta.isError(result));
        try testing.expect(std.mem.indexOf(u8, aw.written(), "Verify return code") == null);
        try testing.expect(std.mem.indexOf(u8, st.log.written(), "connection error") != null);
    }
}

test "armorcli s_client -ech against s_server with ech-gen keys is accepted" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [1024]u8 = undefined;
    var fx = try writeFixture(gpa, &tmp, &buf, 0x44);
    defer fx.deinit(gpa);

    const cfg_path = try std.fmt.allocPrint(gpa, ".zig-cache/tmp/{s}/ech.bin", .{tmp.sub_path});
    defer gpa.free(cfg_path);
    const key_path = try std.fmt.allocPrint(gpa, ".zig-cache/tmp/{s}/ech.key", .{tmp.sub_path});
    defer gpa.free(key_path);
    var gen_out = Writer.Allocating.init(gpa);
    defer gen_out.deinit();
    try ech_gen_cmd.run(gpa, io, try ech_gen_cmd.parseArgs(&.{ "-public-name", "cover.example", "-config-out", cfg_path, "-key-out", key_path }), &gen_out.writer);

    var key = try ech_gen_cmd.readKeyFile(gpa, io, key_path);
    defer std.crypto.secureZero(u8, &key);
    var loaded = try onyx_server.daemon.tls_ech_load.load(gpa, io, &.{.{ .config_path = cfg_path, .private_key = key }});
    defer loaded.deinit(gpa);

    var st: ServerThread = undefined;
    const thread = try startServer(gpa, &st, .{
        .cert_chain = &.{fx.der},
        .signing_key = fx.kp,
        .ech_keys = loaded.keys,
        .ech_retry_config_list = loaded.retry_config_list,
    });
    defer {
        st.listener.deinit(io);
        st.log.deinit();
    }
    var connect_buf: [32]u8 = undefined;
    const connect = try std.fmt.bufPrint(&connect_buf, "127.0.0.1:{d}", .{st.listener.socket.address.getPort()});
    var aw = Writer.Allocating.init(gpa);
    defer aw.deinit();
    try run(gpa, io, try parseArgs(&.{ "-connect", connect, "-servername", "localhost", "-CAfile", fx.cert_path, "-ech", cfg_path, "-brief" }), &aw.writer);
    thread.join();
    if (st.err) |e| return e;
    try testing.expect(std.mem.indexOf(u8, aw.written(), "ECH       : accepted") != null);
    try testing.expect(std.mem.indexOf(u8, st.log.written(), "ECH       : accepted") != null);
}

test "armorcli s_client -ech aborts with ech_required when the server rejects ECH" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [1024]u8 = undefined;
    // The server holds only the cover certificate: a rejected handshake can
    // authenticate public_name, never the requested inner name.
    var fx = try writeFixtureNames(gpa, &tmp, &buf, 0x46, &.{"cover.example"});
    defer fx.deinit(gpa);

    var paths: [4][]u8 = undefined;
    for ([_][]const u8{ "client.bin", "client.key", "server.bin", "server.key" }, 0..) |n, i| {
        paths[i] = try std.fmt.allocPrint(gpa, ".zig-cache/tmp/{s}/{s}", .{ tmp.sub_path, n });
    }
    defer for (paths) |p| gpa.free(p);
    var gen_out = Writer.Allocating.init(gpa);
    defer gen_out.deinit();
    // Client config and server key come from two different ech-gen runs.
    try ech_gen_cmd.run(gpa, io, try ech_gen_cmd.parseArgs(&.{ "-public-name", "cover.example", "-config-out", paths[0], "-key-out", paths[1], "-config-id", "1" }), &gen_out.writer);
    try ech_gen_cmd.run(gpa, io, try ech_gen_cmd.parseArgs(&.{ "-public-name", "cover.example", "-config-out", paths[2], "-key-out", paths[3], "-config-id", "2" }), &gen_out.writer);

    var key = try ech_gen_cmd.readKeyFile(gpa, io, paths[3]);
    defer std.crypto.secureZero(u8, &key);
    var loaded = try onyx_server.daemon.tls_ech_load.load(gpa, io, &.{.{ .config_path = paths[2], .private_key = key }});
    defer loaded.deinit(gpa);

    var st: ServerThread = undefined;
    const thread = try startServer(gpa, &st, .{
        .cert_chain = &.{fx.der},
        .signing_key = fx.kp,
        .ech_keys = loaded.keys,
        .ech_retry_config_list = loaded.retry_config_list,
    });
    defer {
        st.listener.deinit(io);
        st.log.deinit();
    }
    var connect_buf: [32]u8 = undefined;
    const connect = try std.fmt.bufPrint(&connect_buf, "127.0.0.1:{d}", .{st.listener.socket.address.getPort()});
    var aw = Writer.Allocating.init(gpa);
    defer aw.deinit();
    var opts = try parseArgs(&.{ "-connect", connect, "-servername", "secret.example", "-CAfile", fx.cert_path, "-ech", paths[0] });
    opts.input = .{ .bytes = "PASSWORD hunter2" };
    const result = run(gpa, io, opts, &aw.writer);
    thread.join();
    if (st.err) |e| return e;

    try testing.expectError(error.EchRejected, result);
    const w = aw.written();
    try testing.expect(std.mem.indexOf(u8, w, "rejected by server; aborted with ech_required") != null);
    try testing.expect(std.mem.indexOf(u8, w, "Verify return code") == null);
    try testing.expect(std.mem.indexOf(u8, w, "SNI       :") == null);
    try testing.expect(std.mem.indexOf(u8, w, "hunter2") == null);
    // The server's retry_configs are reported for a retry.
    var b64_buf: [512]u8 = undefined;
    const b64 = std.base64.standard.Encoder.encode(&b64_buf, loaded.retry_config_list);
    try testing.expect(std.mem.indexOf(u8, w, b64) != null);
    // The server decrypted our alert (an alert ends the echo loop cleanly) and
    // received no application data.
    const log = st.log.written();
    try testing.expect(std.mem.indexOf(u8, log, "ECH       : not accepted") != null);
    try testing.expect(std.mem.indexOf(u8, log, "DONE echoed 0 bytes") != null);
}

test "armorcli s_client -ech with no usable config sends nothing" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [1024]u8 = undefined;
    var fx = try writeFixture(gpa, &tmp, &buf, 0x47);
    defer fx.deinit(gpa);
    // Passes the 2-byte length check but holds no parseable ECHConfig.
    try tmp.dir.writeFile(io, .{ .sub_path = "junk.bin", .data = &[_]u8{ 0x00, 0x03, 0xaa, 0xbb, 0xcc } });
    const junk_path = try std.fmt.allocPrint(gpa, ".zig-cache/tmp/{s}/junk.bin", .{tmp.sub_path});
    defer gpa.free(junk_path);

    var st: ServerThread = undefined;
    const thread = try startServer(gpa, &st, .{ .cert_chain = &.{fx.der}, .signing_key = fx.kp });
    defer {
        st.listener.deinit(io);
        st.log.deinit();
    }
    var connect_buf: [32]u8 = undefined;
    const connect = try std.fmt.bufPrint(&connect_buf, "127.0.0.1:{d}", .{st.listener.socket.address.getPort()});
    var aw = Writer.Allocating.init(gpa);
    defer aw.deinit();
    const result = run(gpa, io, try parseArgs(&.{ "-connect", connect, "-servername", "localhost", "-CAfile", fx.cert_path, "-ech", junk_path, "-brief" }), &aw.writer);
    thread.join();
    if (st.err) |e| return e;
    try testing.expectError(error.EchNotUsable, result);
    try testing.expect(std.mem.indexOf(u8, aw.written(), "ClientHello not sent") != null);
    // The server saw EOF before any record: no cleartext SNI left the client.
    try testing.expect(std.mem.indexOf(u8, st.log.written(), "connection error: ConnectionClosed") != null);
}

test "armorcli s_client -dc verifies a dc_mint credential served by s_server" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [1024]u8 = undefined;
    var fx = try writeFixture(gpa, &tmp, &buf, 0x45);
    defer fx.deinit(gpa);
    const dc_mint = onyx_server.daemon.delegated_credential_cli.dc_mint;
    var minted = try dc_mint.mint(gpa, io, .{
        .leaf_der = fx.der,
        .leaf_key = .{ .ed25519 = fx.kp },
        .now_unix = common.wallClockSeconds(),
        .lifetime_seconds = 3600,
    });
    defer minted.deinit(gpa);

    var st: ServerThread = undefined;
    const thread = try startServer(gpa, &st, .{
        .cert_chain = &.{fx.der},
        .signing_key = fx.kp,
        .delegated_credential = minted.serverCredential(),
    });
    defer {
        st.listener.deinit(io);
        st.log.deinit();
    }
    var connect_buf: [32]u8 = undefined;
    const connect = try std.fmt.bufPrint(&connect_buf, "127.0.0.1:{d}", .{st.listener.socket.address.getPort()});
    var aw = Writer.Allocating.init(gpa);
    defer aw.deinit();
    try run(gpa, io, try parseArgs(&.{ "-connect", connect, "-servername", "localhost", "-CAfile", fx.cert_path, "-dc", "-brief" }), &aw.writer);
    thread.join();
    if (st.err) |e| return e;
    try testing.expect(std.mem.indexOf(u8, aw.written(), "Delegated : used") != null);
}

test "armorcli s_server refuses a -key or -dc-key of the right type that does not match" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp_a = testing.tmpDir(.{});
    defer tmp_a.cleanup();
    var tmp_b = testing.tmpDir(.{});
    defer tmp_b.cleanup();
    var buf_a: [1024]u8 = undefined;
    var fx = try writeFixture(gpa, &tmp_a, &buf_a, 0x48);
    defer fx.deinit(gpa);
    var buf_b: [1024]u8 = undefined;
    var wrong = try writeFixture(gpa, &tmp_b, &buf_b, 0x49); // another Ed25519 key
    defer wrong.deinit(gpa);
    var aw = Writer.Allocating.init(gpa);
    defer aw.deinit();

    try testing.expectError(error.LeafKeyMismatch, s_server_cmd.run(gpa, io, try s_server_cmd.parseArgs(&.{
        "-accept", "127.0.0.1:0", "-cert", fx.cert_path, "-key", wrong.key_path, "-naccept", "1",
    }), &aw.writer));

    // An Ed25519 DC served with a different Ed25519 -dc-key.
    const dc_mint = onyx_server.daemon.delegated_credential_cli.dc_mint;
    var minted = try dc_mint.mint(gpa, io, .{
        .leaf_der = fx.der,
        .leaf_key = .{ .ed25519 = fx.kp },
        .dc_algorithm = .ed25519,
        .now_unix = common.wallClockSeconds(),
        .lifetime_seconds = 3600,
    });
    defer minted.deinit(gpa);
    try tmp_a.dir.writeFile(io, .{ .sub_path = "dc.bin", .data = minted.wire });
    const dc_path = try std.fmt.allocPrint(gpa, ".zig-cache/tmp/{s}/dc.bin", .{tmp_a.sub_path});
    defer gpa.free(dc_path);
    try testing.expectError(error.DcKeyMismatch, s_server_cmd.run(gpa, io, try s_server_cmd.parseArgs(&.{
        "-accept", "127.0.0.1:0", "-cert",   fx.cert_path,   "-key", fx.key_path,
        "-dc",     dc_path,       "-dc-key", wrong.key_path,
    }), &aw.writer));
    // Nothing was ever listening.
    try testing.expect(std.mem.indexOf(u8, aw.written(), "ACCEPT") == null);
}

test "armorcli s_server drops a client that never finishes the handshake" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [1024]u8 = undefined;
    var fx = try writeFixture(gpa, &tmp, &buf, 0x4a);
    defer fx.deinit(gpa);

    var st: ServerThread = undefined;
    const addr: net.IpAddress = .{ .ip4 = .loopback(0) };
    st = .{
        .gpa = gpa,
        .listener = try addr.listen(io, .{ .reuse_address = true }),
        .cfg = .{ .cert_chain = &.{fx.der}, .signing_key = fx.kp },
        .log = .init(gpa),
        .handshake_timeout_ms = 200,
    };
    defer {
        st.listener.deinit(io);
        st.log.deinit();
    }
    const thread = try std.Thread.spawn(.{}, ServerThread.main, .{&st});
    // Connect and stay silent; the server must give up on its own.
    const idle = try transport.connect(io, "127.0.0.1", st.listener.socket.address.getPort());
    defer idle.close(io);
    thread.join();
    if (st.err) |e| return e;
    try testing.expect(std.mem.indexOf(u8, st.log.written(), "connection error: HandshakeTimeout") != null);
}

test "armorcli s_client reads ECHConfigList files as binary or base64 and rejects garbage" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const list = [_]u8{ 0x00, 0x03, 0xaa, 0xbb, 0xcc };
    try tmp.dir.writeFile(io, .{ .sub_path = "bin", .data = &list });
    try tmp.dir.writeFile(io, .{ .sub_path = "b64", .data = "AAOqu8w=\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "bad", .data = "AAQ=" }); // length says 4, has 0
    const names = [_][]const u8{ "bin", "b64", "bad" };
    var paths: [3][]u8 = undefined;
    for (names, 0..) |n, i| paths[i] = try std.fmt.allocPrint(gpa, ".zig-cache/tmp/{s}/{s}", .{ tmp.sub_path, n });
    defer for (paths) |p| gpa.free(p);
    for (paths[0..2]) |p| {
        const got = try readEchConfigList(gpa, io, p);
        defer gpa.free(got);
        try testing.expectEqualSlices(u8, &list, got);
    }
    try testing.expectError(error.BadEchConfigList, readEchConfigList(gpa, io, paths[2]));
}

test "armorcli s_client live path still requires -connect and -CAfile" {
    try testing.expectError(error.Usage, run(testing.allocator, std.testing.io, .{}, undefined));
    try testing.expectError(error.Usage, run(
        testing.allocator,
        std.testing.io,
        .{ .connect = "127.0.0.1:1" },
        undefined,
    ));
    try testing.expectError(error.Usage, run(
        testing.allocator,
        std.testing.io,
        .{ .connect = "noport", .ca_file = "x" },
        undefined,
    ));
}
