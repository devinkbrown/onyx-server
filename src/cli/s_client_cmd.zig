// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! `armor s_client` — standalone TLS client over the Armor `tls_client`
//! substrate. Not the daemon reactor. The first increment completes a
//! loopback handshake against `tls_server` and prints the negotiated
//! session. A live `-connect host:port` socket loop is the remaining AX-2
//! piece (same Client, different transport).

const std = @import("std");
const onyx_server = @import("onyx_server");
const common = @import("common.zig");

const tls_client = onyx_server.crypto.tls_client;
const tls_server = onyx_server.crypto.tls_server;
const acme_cli = onyx_server.daemon.acme_cli;

const Allocator = std.mem.Allocator;
const Writer = common.Writer;

pub const Options = struct {
    connect: ?[]const u8 = null,
    server_name: ?[]const u8 = null,
    name: ?[]const u8 = null,
    ca_file: []const u8 = "",
    alpn: ?[]const u8 = null,
};

pub fn usage(w: *Writer) Writer.Error!void {
    try w.writeAll(
        \\usage: armor s_client -connect host:port [options]
        \\  -connect host:port  TCP peer (required for the live path)
        \\  -servername <dns>   SNI (default: the connect host)
        \\  -name <dns>         hostname to verify (default: SNI)
        \\  -CAfile <bundle>    PEM trust anchors (required for the live path)
        \\  -alpn <proto>       offer a single ALPN protocol
        \\
        \\Standalone Armor TLS client — not the daemon reactor.
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
        } else {
            return error.Usage;
        }
    }
    return opts;
}

pub fn run(gpa: Allocator, io: std.Io, opts: Options, out: *Writer) !void {
    const spec = opts.connect orelse return error.Usage;
    if (opts.ca_file.len == 0) return error.Usage;
    const host = hostOf(spec) orelse return error.Usage;
    const sni = opts.server_name orelse host;

    const bundle_text = try common.readInput(gpa, io, opts.ca_file);
    defer gpa.free(bundle_text);
    var anchors = try acme_cli.loadTrustAnchors(gpa, bundle_text);
    defer {
        for (anchors.items) |a| gpa.free(a);
        anchors.deinit(gpa);
    }
    if (anchors.items.len == 0) return error.NoMatchingIssuer;

    var view: [8][]const u8 = undefined;
    if (anchors.items.len > view.len) return error.Usage;
    for (anchors.items, 0..) |a, i| view[i] = a;

    var alpn_storage: [1][]const u8 = undefined;
    const alpn: []const []const u8 = if (opts.alpn) |p| blk: {
        alpn_storage[0] = p;
        break :blk alpn_storage[0..1];
    } else &.{};

    var client = try tls_client.Client.init(gpa, .{
        .server_name = sni,
        .trust_anchors = view[0..anchors.items.len],
        .alpn_protocols = alpn,
        .now_unix_seconds = common.wallClockSeconds(),
    });
    defer client.deinit();

    _ = out;
    return error.NotImplemented;
}

/// Drive a ClientHello / server flight / client Finished exchange against an
/// in-memory `tls_server.Server`. This is the AX-2 loopback proof; it does
/// not touch a socket or `server.zig`.
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
    _ = try server.feed(cfin);
    if (!client.handshakeDone()) return error.HandshakeIncomplete;
}

pub fn writeSession(client: *const tls_client.Client, out: *Writer) !void {
    try out.writeAll("Protocol  : TLSv1.3\n");
    try out.writeAll("Cipher    : ");
    if (client.selected_suite) |suite| {
        try out.writeAll(suiteIanaName(suite));
    } else {
        try out.writeAll("(none)");
    }
    try out.writeByte('\n');
    try out.print("SNI       : {s}\n", .{client.server_name});
    try out.writeAll("ALPN      : ");
    if (client.selected_alpn) |alpn| {
        try out.writeAll(alpn);
    } else {
        try out.writeAll("(none)");
    }
    try out.writeByte('\n');
    try out.writeAll("Verify return code: 0 (ok)\n");
}

fn hostOf(spec: []const u8) ?[]const u8 {
    const colon = std.mem.lastIndexOfScalar(u8, spec, ':') orelse return null;
    if (colon == 0 or colon + 1 >= spec.len) return null;
    return spec[0..colon];
}

fn suiteIanaName(suite: anytype) []const u8 {
    return switch (suite) {
        .tls_aes_128_gcm_sha256 => "TLS_AES_128_GCM_SHA256",
        .tls_aes_256_gcm_sha384 => "TLS_AES_256_GCM_SHA384",
        .tls_chacha20_poly1305_sha256 => "TLS_CHACHA20_POLY1305_SHA256",
    };
}

const testing = std.testing;
const x509_selfsign = onyx_server.proto.x509_selfsign;
const Ed25519 = std.crypto.sign.Ed25519;

test "armorcli s_client parseArgs accepts connect and SNI flags" {
    try testing.expectError(error.Usage, parseArgs(&.{"-bogus"}));
    const opts = try parseArgs(&.{
        "-connect",    "irc.test:6697",
        "-servername", "irc.test",
        "-CAfile",     "ca.pem",
        "-alpn",       "irc",
    });
    try testing.expectEqualStrings("irc.test:6697", opts.connect.?);
    try testing.expectEqualStrings("irc.test", opts.server_name.?);
    try testing.expectEqualStrings("ca.pem", opts.ca_file);
    try testing.expectEqualStrings("irc", opts.alpn.?);
}

test "armorcli s_client loopback handshake prints suite, SNI, and verify ok" {
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
    try testing.expect(std.mem.indexOf(u8, aw.written(), "Protocol  : TLSv1.3") != null);
    try testing.expect(std.mem.indexOf(u8, aw.written(), "TLS_AES_128_GCM_SHA256") != null);
    try testing.expect(std.mem.indexOf(u8, aw.written(), "SNI       : irc.test") != null);
    try testing.expect(std.mem.indexOf(u8, aw.written(), "Verify return code: 0 (ok)") != null);
}

test "armorcli s_client live path still requires -connect and -CAfile" {
    try testing.expectError(error.Usage, run(testing.allocator, std.testing.io, .{}, undefined));
    try testing.expectError(error.Usage, run(
        testing.allocator,
        std.testing.io,
        .{ .connect = "127.0.0.1:1" },
        undefined,
    ));
}
