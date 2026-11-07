// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! `armor ocsp` — display and verify a stapled OCSP response (RFC 6960), or
//! fetch one online with `-fetch`.
//!
//! All parse / signature / staple-servable decisions are substrate calls
//! (`src/crypto/ocsp.zig`). `-fetch` builds the RFC 6960 §4.1 OCSPRequest for
//! the leaf (CertID from the issuer Name and key, SHA-1 per RFC 5019 §2.1.1),
//! POSTs it (RFC 6960 Appendix A.1) through the daemon's `http_fetch` client to
//! the leaf's AIA id-ad-ocsp URL (RFC 5280 §4.2.2.1) or `-url`, and then fails
//! closed unless the response is signed by the issuer or an issuer-delegated
//! responder (RFC 6960 §4.2.2.2), names this exact CertID, says `good`, and is
//! current (thisUpdate/nextUpdate, RFC 6960 §4.2.2.1).

const std = @import("std");
const onyx_server = @import("onyx_server");
const common = @import("common.zig");

const ocsp = onyx_server.crypto.ocsp;
const x509 = onyx_server.crypto.x509;
const pem = onyx_server.proto.pem;
const acme_cli = onyx_server.daemon.acme_cli;
const http_fetch = onyx_server.daemon.http_fetch;
const ocsp_staple = onyx_server.daemon.ocsp_staple;
const tls_certs = onyx_server.daemon.tls_certs;

const Allocator = std.mem.Allocator;
const Writer = common.Writer;

pub const pem_label = "OCSP RESPONSE";

pub const Options = struct {
    in_path: []const u8 = "-",
    inform: common.Form = .auto,
    text: bool = false,
    noout: bool = false,
    verify: bool = false,
    ca_file: []const u8 = "",
    serial: ?[]const u8 = null,
    at_epoch: ?i64 = null,
    /// `-fetch` mode: query the responder for `cert`.
    fetch: bool = false,
    cert: ?[]const u8 = null,
    issuer: ?[]const u8 = null,
    url: ?[]const u8 = null,
    out_path: ?[]const u8 = null,
    timeout_ms: u31 = 10_000,
};

/// Largest OCSP response `-fetch` accepts (the daemon stapler uses the same).
pub const max_fetch_response_bytes: usize = 64 * 1024;

pub fn usage(w: *Writer) Writer.Error!void {
    try w.writeAll(
        \\usage: armor ocsp [-in <path>] [options]
        \\  -in <path>        OCSP response PEM/DER (default stdin)
        \\  -inform pem|der   force the input encoding (default: auto-detect)
        \\  -text             dump status, responder, serials, this/nextUpdate
        \\  -noout            suppress the response PEM reprint
        \\  -verify           authenticate the response (requires -CAfile)
        \\  -CAfile <bundle>  PEM trust anchors used as issuer / delegating CA
        \\  -serial <hex>     require that serial to be staple-servable (good + current)
        \\  -at <epoch>       evaluate freshness at this Unix time (default: now)
        \\
        \\       armor ocsp -fetch -cert <leaf|chain.pem> [-issuer <ca.pem>] [-url <uri>]
        \\                  [-CAfile <bundle>] [-out <resp.der>] [-at <epoch>] [-text]
        \\  -fetch            POST an OCSPRequest for -cert to its responder and verify
        \\  -cert <pem>       leaf (or leaf-first chain; chain[1] is the default issuer)
        \\  -issuer <pem>     issuing CA certificate
        \\  -url <uri>        responder URL (default: the leaf's AIA OCSP URL)
        \\  -CAfile <bundle>  with -fetch: trust anchors for an https:// responder
        \\  -out <file>       save the verified DER response (for s_server -status_file)
        \\
        \\Fail-closed on bad signature, unknown, revoked, or stale.
        \\
    );
}

pub fn parseArgs(args: []const []const u8) common.Error!Options {
    var opts = Options{};
    var cur = common.ArgCursor{ .args = args };
    while (cur.next()) |a| {
        if (std.mem.eql(u8, a, "-in")) {
            opts.in_path = try cur.value();
        } else if (std.mem.eql(u8, a, "-inform")) {
            opts.inform = try common.Form.parse(try cur.value());
        } else if (std.mem.eql(u8, a, "-text")) {
            opts.text = true;
        } else if (std.mem.eql(u8, a, "-noout")) {
            opts.noout = true;
        } else if (std.mem.eql(u8, a, "-verify")) {
            opts.verify = true;
        } else if (std.mem.eql(u8, a, "-CAfile")) {
            opts.ca_file = try cur.value();
        } else if (std.mem.eql(u8, a, "-serial")) {
            opts.serial = try cur.value();
        } else if (std.mem.eql(u8, a, "-at")) {
            opts.at_epoch = std.fmt.parseInt(i64, try cur.value(), 10) catch return error.Usage;
        } else if (std.mem.eql(u8, a, "-fetch")) {
            opts.fetch = true;
        } else if (std.mem.eql(u8, a, "-cert")) {
            opts.cert = try cur.value();
        } else if (std.mem.eql(u8, a, "-issuer")) {
            opts.issuer = try cur.value();
        } else if (std.mem.eql(u8, a, "-url")) {
            opts.url = try cur.value();
        } else if (std.mem.eql(u8, a, "-out")) {
            opts.out_path = try cur.value();
        } else if (a.len > 0 and a[0] == '-' and a.len > 1) {
            return error.Usage;
        } else {
            opts.in_path = a;
        }
    }
    if (opts.fetch) {
        // -fetch always verifies against the issuer; -verify/-serial belong to
        // the file mode.
        if (opts.cert == null or opts.verify or opts.serial != null) return error.Usage;
        return opts;
    }
    if (opts.cert != null or opts.issuer != null or opts.url != null or opts.out_path != null) return error.Usage;
    if (opts.verify and opts.ca_file.len == 0) return error.Usage;
    if (opts.serial != null and !opts.verify) return error.Usage;
    return opts;
}

pub fn run(gpa: Allocator, io: std.Io, opts: Options, out: *Writer) !void {
    if (opts.fetch) return runFetch(gpa, io, opts, out);
    const text = try common.readInput(gpa, io, opts.in_path);
    defer gpa.free(text);
    const der = try common.loadDer(gpa, text, pem_label, opts.inform);
    defer gpa.free(der);
    try runOnDer(gpa, io, opts, der, out);
}

pub fn runOnDer(gpa: Allocator, io: std.Io, opts: Options, der: []const u8, out: *Writer) !void {
    const parsed = try ocsp.parse(der);

    if (opts.text) try dumpText(&parsed, out);

    if (opts.verify) {
        const bundle_text = try common.readInput(gpa, io, opts.ca_file);
        defer gpa.free(bundle_text);
        var anchors = try acme_cli.loadTrustAnchors(gpa, bundle_text);
        defer {
            for (anchors.items) |a| gpa.free(a);
            anchors.deinit(gpa);
        }
        try authenticate(gpa, opts, parsed, der, anchors.items, out);
    }

    if (!opts.noout) {
        const buf = try gpa.alloc(u8, pem.encodedLen(pem_label, der.len));
        defer gpa.free(buf);
        try out.writeAll(try pem.encode(buf, pem_label, der));
    }
}

/// `-fetch`: build, send, and verify an OCSP request for the leaf.
pub fn runFetch(gpa: Allocator, io: std.Io, opts: Options, out: *Writer) !void {
    const chain = try tls_certs.loadCertChain(gpa, io, opts.cert orelse return error.Usage);
    defer {
        for (chain) |der| gpa.free(der);
        gpa.free(chain);
    }
    if (chain.len == 0) return error.EmptyCertificateChain;
    const issuer_chain: ?[][]const u8 = if (opts.issuer) |p| try tls_certs.loadCertChain(gpa, io, p) else null;
    defer if (issuer_chain) |ic| {
        for (ic) |der| gpa.free(der);
        gpa.free(ic);
    };
    const issuer_der: []const u8 = if (issuer_chain) |ic| blk: {
        if (ic.len == 0) return error.EmptyCertificateChain;
        break :blk ic[0];
    } else if (chain.len > 1) chain[1] else return error.Usage;

    const leaf = try x509.parse(chain[0]);
    const issuer = try x509.parse(issuer_der);
    // RFC 6960 §4.1.1: the CertID names the leaf's issuer; refuse to ask about
    // a pairing the responder could only answer `unknown` for.
    if (!std.mem.eql(u8, leaf.issuer_der, issuer.subject_der)) return error.IssuerMismatch;

    const url_text = opts.url orelse leaf.aia_ocsp_url;
    if (url_text.len == 0) return error.NoOcspUrl;
    const url = try http_fetch.parseUrl(url_text);

    var anchors: std.ArrayList([]u8) = .empty;
    defer {
        for (anchors.items) |a| gpa.free(a);
        anchors.deinit(gpa);
    }
    if (opts.ca_file.len != 0) {
        const bundle_text = try common.readInput(gpa, io, opts.ca_file);
        defer gpa.free(bundle_text);
        anchors = try acme_cli.loadTrustAnchors(gpa, bundle_text);
    }
    if (url.tls and anchors.items.len == 0) return error.Usage; // https needs -CAfile
    const view = try gpa.alloc([]const u8, anchors.items.len);
    defer gpa.free(view);
    for (anchors.items, 0..) |a, i| view[i] = a;

    const request = try ocsp.buildRequestForCerts(gpa, leaf, issuer);
    defer gpa.free(request);
    const http_resp = try http_fetch.post(gpa, url, "application/ocsp-request", request, .{
        .trust_anchors = view,
        .connect_timeout_ms = opts.timeout_ms,
        .recv_timeout_ms = opts.timeout_ms,
        .max_response_bytes = max_fetch_response_bytes,
    });
    defer gpa.free(http_resp);
    const der = ocsp_staple.extractOcspBody(http_resp) orelse return error.BadOcspResponse;

    try out.print("Responder: {s}\n", .{url_text});
    const parsed = try ocsp.parse(der);
    if (opts.text) try dumpText(&parsed, out);
    const now = opts.at_epoch orelse common.wallClockSeconds();
    try verifyFetched(parsed, der, leaf, issuer, now, out);
    if (opts.out_path) |p| try common.writePublicFile(io, std.Io.Dir.cwd(), p, der);
}

/// Fail-closed verdict on a fetched response for exactly (`leaf`, `issuer`).
pub fn verifyFetched(parsed: ocsp.Parsed, der: []const u8, leaf: x509.Certificate, issuer: x509.Certificate, now: i64, out: *Writer) !void {
    if (!ocsp.verifyResponseSignatureWithChain(parsed, issuer.spki_der, now)) return error.BadSignature;
    const identity: ocsp.CertIdInput = .{
        .issuer_name_der = issuer.subject_der,
        .issuer_key_bytes = issuer.subject_public_key,
        .serial_der = leaf.serial_der,
    };
    const single = ocsp.singleForCertId(parsed, identity) orelse return error.NoMatchingResponse;
    try out.print("Cert Status: {s}\n", .{@tagName(single.cert_status)});
    switch (single.cert_status) {
        .good => {},
        .revoked => return error.Revoked,
        .unknown => return error.UnknownStatus,
    }
    if (!ocsp.isStapleServableForCertId(der, issuer.spki_der, identity, now, ocsp.default_staple_skew_seconds)) {
        return error.Stale;
    }
    try out.writeAll("Response verifies: OK\n");
}

/// Authenticate `parsed` against already-decoded CA DERs. Tests drive this
/// directly so they do not need a temp file.
pub fn authenticate(
    gpa: Allocator,
    opts: Options,
    parsed: ocsp.Parsed,
    der: []const u8,
    anchors: []const []const u8,
    out: *Writer,
) !void {
    if (anchors.len == 0) return error.NoMatchingIssuer;
    const now = opts.at_epoch orelse common.wallClockSeconds();
    const issuer_spki = findVerifyingIssuer(anchors, parsed, now) orelse return error.BadSignature;

    if (opts.serial) |hex| {
        const serial = try common.parseHexSerial(gpa, hex);
        defer gpa.free(serial);
        if (!ocsp.isStapleServable(der, issuer_spki, serial, now, 0)) {
            return stapleFailure(parsed, serial);
        }
        try out.writeAll("serial ");
        try common.writeHex(out, serial);
        try out.writeAll(": staple servable\n");
        return;
    }
    try assertAllGoodAndCurrent(&parsed, now);
    try out.writeAll("Response verifies: OK\n");
}

fn findVerifyingIssuer(anchors: []const []const u8, parsed: ocsp.Parsed, now: i64) ?[]const u8 {
    for (anchors) |anchor| {
        const cert = x509.parse(anchor) catch continue;
        if (ocsp.verifyResponseSignatureWithChain(parsed, cert.spki_der, now)) return cert.spki_der;
    }
    return null;
}

fn stapleFailure(parsed: ocsp.Parsed, serial: []const u8) anyerror {
    const status = ocsp.statusForSerial(parsed, serial) orelse return error.UnknownStatus;
    return switch (status) {
        .revoked => error.Revoked,
        .unknown => error.UnknownStatus,
        .good => error.Stale,
    };
}

fn assertAllGoodAndCurrent(parsed: *const ocsp.Parsed, now: i64) !void {
    if (parsed.response_status != .successful) return error.UnknownStatus;
    if (parsed.response_count == 0) return error.UnknownStatus;
    var i: usize = 0;
    while (i < parsed.response_count) : (i += 1) {
        const single = parsed.responses[i];
        switch (single.cert_status) {
            .good => {},
            .revoked => return error.Revoked,
            .unknown => return error.UnknownStatus,
        }
        const next_bytes = single.next_update orelse return error.Stale;
        const this_epoch = x509.generalizedTimeToEpoch(single.this_update) catch return error.Stale;
        const next_epoch = x509.generalizedTimeToEpoch(next_bytes) catch return error.Stale;
        if (next_epoch <= this_epoch) return error.Stale;
        if (now < this_epoch) return error.Stale;
        if (now >= next_epoch) return error.Stale;
    }
}

fn dumpText(parsed: *const ocsp.Parsed, out: *Writer) !void {
    try out.writeAll("OCSP Response:\n");
    try out.print("  Status: {s}\n", .{@tagName(parsed.response_status)});
    try out.writeAll("  Responder: ");
    switch (parsed.responder_id_kind) {
        .none => try out.writeAll("none\n"),
        .by_name => {
            try out.writeAll("byName ");
            try common.writeColonHex(out, parsed.responder_id_value);
            try out.writeByte('\n');
        },
        .by_key => {
            try out.writeAll("byKey ");
            try common.writeColonHex(out, parsed.responder_id_value);
            try out.writeByte('\n');
        },
    }
    try out.print("  Responses: {d}\n", .{parsed.response_count});
    var i: usize = 0;
    while (i < parsed.response_count) : (i += 1) {
        const single = parsed.responses[i];
        try out.writeAll("    Serial: ");
        try common.writeHex(out, single.serial);
        try out.writeByte('\n');
        try out.print("    Cert Status: {s}\n", .{@tagName(single.cert_status)});
        try out.print("    This Update: {s}\n", .{single.this_update});
        if (single.next_update) |nu| {
            try out.print("    Next Update: {s}\n", .{nu});
        } else {
            try out.writeAll("    Next Update: <absent>\n");
        }
    }
}

const testing = std.testing;
const x509_selfsign = onyx_server.proto.x509_selfsign;
const Ed25519 = std.crypto.sign.Ed25519;

/// Mid-window instant for the mint fixture (thisUpdate 2026-01-02, nextUpdate 2026-02-02).
const fixture_now: i64 = 1_768_000_000;

fn mintCaAndGoodResponse(gpa: Allocator) !struct { ca_der: []u8, response: []u8, kp: Ed25519.KeyPair } {
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x5A)));
    var ca_buf: [2048]u8 = undefined;
    const ca_view = try x509_selfsign.buildSelfSigned(&ca_buf, .{
        .common_name = "armorcli ocsp ca",
        .not_before = fixture_now - 1000,
        .not_after = fixture_now + 100_000,
        .serial = &.{0x01},
        .key_pair = kp,
        .dns_names = &.{"ocsp-ca.test"},
        .is_ca = true,
    });
    const response = try ocsp.testSignedOcspResponse(gpa, kp, &[_]u8{0x44}, .good, "20260202030405Z");
    errdefer gpa.free(response);
    return .{ .ca_der = try gpa.dupe(u8, ca_view), .response = response, .kp = kp };
}

test "armorcli ocsp -text dumps a successful basic response" {
    const gpa = testing.allocator;
    const minted = try mintCaAndGoodResponse(gpa);
    defer gpa.free(minted.ca_der);
    defer gpa.free(minted.response);

    var aw = Writer.Allocating.init(gpa);
    defer aw.deinit();
    try runOnDer(gpa, std.testing.io, .{ .text = true, .noout = true }, minted.response, &aw.writer);
    try testing.expect(std.mem.indexOf(u8, aw.written(), "Status: successful") != null);
    try testing.expect(std.mem.indexOf(u8, aw.written(), "Serial: 44") != null);
    try testing.expect(std.mem.indexOf(u8, aw.written(), "Cert Status: good") != null);
    try testing.expect(std.mem.indexOf(u8, aw.written(), "This Update: 20260102030405Z") != null);
}

test "armorcli ocsp -verify accepts the issuing CA and rejects a stranger" {
    const gpa = testing.allocator;
    const minted = try mintCaAndGoodResponse(gpa);
    defer gpa.free(minted.ca_der);
    defer gpa.free(minted.response);

    const other_kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x11)));
    var other_buf: [2048]u8 = undefined;
    const other_der = try x509_selfsign.buildSelfSigned(&other_buf, .{
        .common_name = "stranger",
        .not_before = fixture_now - 1000,
        .not_after = fixture_now + 100_000,
        .serial = &.{0x02},
        .key_pair = other_kp,
        .dns_names = &.{"other.test"},
        .is_ca = true,
    });

    const parsed = try ocsp.parse(minted.response);
    var aw = Writer.Allocating.init(gpa);
    defer aw.deinit();
    try authenticate(gpa, .{ .at_epoch = fixture_now }, parsed, minted.response, &.{minted.ca_der}, &aw.writer);
    try testing.expect(std.mem.indexOf(u8, aw.written(), "Response verifies: OK") != null);

    aw.clearRetainingCapacity();
    try testing.expectError(error.BadSignature, authenticate(
        gpa,
        .{ .at_epoch = fixture_now },
        parsed,
        minted.response,
        &.{other_der},
        &aw.writer,
    ));
}

test "armorcli ocsp -verify -serial is fail-closed on revoked, unknown, and stale" {
    const gpa = testing.allocator;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x5A)));
    var ca_buf: [2048]u8 = undefined;
    const ca_der = try x509_selfsign.buildSelfSigned(&ca_buf, .{
        .common_name = "armorcli ocsp ca",
        .not_before = fixture_now - 1000,
        .not_after = fixture_now + 100_000,
        .serial = &.{0x01},
        .key_pair = kp,
        .dns_names = &.{"ocsp-ca.test"},
        .is_ca = true,
    });

    const good = try ocsp.testSignedOcspResponse(gpa, kp, &[_]u8{0x44}, .good, "20260202030405Z");
    defer gpa.free(good);
    const revoked = try ocsp.testSignedOcspResponse(gpa, kp, &[_]u8{0x44}, .revoked, "20260202030405Z");
    defer gpa.free(revoked);

    const good_parsed = try ocsp.parse(good);
    const revoked_parsed = try ocsp.parse(revoked);

    var aw = Writer.Allocating.init(gpa);
    defer aw.deinit();
    try authenticate(gpa, .{ .serial = "44", .at_epoch = fixture_now }, good_parsed, good, &.{ca_der}, &aw.writer);
    try testing.expect(std.mem.indexOf(u8, aw.written(), "staple servable") != null);

    try testing.expectError(error.Revoked, authenticate(
        gpa,
        .{ .serial = "44", .at_epoch = fixture_now },
        revoked_parsed,
        revoked,
        &.{ca_der},
        &aw.writer,
    ));
    try testing.expectError(error.UnknownStatus, authenticate(
        gpa,
        .{ .serial = "99", .at_epoch = fixture_now },
        good_parsed,
        good,
        &.{ca_der},
        &aw.writer,
    ));
    try testing.expectError(error.Stale, authenticate(
        gpa,
        .{ .serial = "44", .at_epoch = 1_900_000_000 },
        good_parsed,
        good,
        &.{ca_der},
        &aw.writer,
    ));
}

test "armorcli ocsp parseArgs requires -CAfile for -verify and -verify for -serial" {
    try testing.expectError(error.Usage, parseArgs(&.{"-verify"}));
    try testing.expectError(error.Usage, parseArgs(&.{ "-serial", "44" }));
    const opts = try parseArgs(&.{ "-verify", "-CAfile", "ca.pem", "-serial", "44", "-text", "-noout" });
    try testing.expect(opts.verify);
    try testing.expectEqualStrings("ca.pem", opts.ca_file);
    try testing.expectEqualStrings("44", opts.serial.?);
    try testing.expect(opts.text);
    try testing.expect(opts.noout);
}

test "armorcli ocsp rejects empty and truncated DER" {
    const gpa = testing.allocator;
    var aw = Writer.Allocating.init(gpa);
    defer aw.deinit();
    try testing.expectError(error.EmptyInput, runOnDer(gpa, std.testing.io, .{ .noout = true }, &.{}, &aw.writer));
    try testing.expectError(error.Truncated, runOnDer(
        gpa,
        std.testing.io,
        .{ .noout = true },
        &[_]u8{ 0x30, 0x10, 0x0A },
        &aw.writer,
    ));
}

test "armorcli ocsp -fetch parseArgs keeps fetch and file modes apart" {
    try testing.expectError(error.Usage, parseArgs(&.{"-fetch"}));
    try testing.expectError(error.Usage, parseArgs(&.{ "-fetch", "-cert", "c", "-verify", "-CAfile", "x" }));
    try testing.expectError(error.Usage, parseArgs(&.{ "-cert", "c" }));
    const o = try parseArgs(&.{ "-fetch", "-cert", "leaf.pem", "-issuer", "ca.pem", "-url", "http://ocsp.test/", "-out", "r.der" });
    try testing.expect(o.fetch);
    try testing.expectEqualStrings("ca.pem", o.issuer.?);
}

/// One-shot plain-HTTP OCSP responder: reads a complete POST, checks the
/// content type and that the body is the expected OCSPRequest, replies `der`.
const Responder = struct {
    listener: std.Io.net.Server,
    expect_request: []const u8,
    der: []const u8,
    request_ok: bool = false,

    fn main(self: *Responder) void {
        self.serve() catch {};
    }

    fn serve(self: *Responder) !void {
        const io = testing.io;
        const stream = try self.listener.accept(io);
        defer stream.close(io);
        var buf: [8192]u8 = undefined;
        var len: usize = 0;
        while (true) {
            var bufs = [_][]u8{buf[len..]};
            const n = (try stream.readWithControl(io, &bufs, &.{})).data_len;
            if (n == 0) return error.EndOfStream;
            len += n;
            const head_end = std.mem.indexOf(u8, buf[0..len], "\r\n\r\n") orelse continue;
            const body = buf[head_end + 4 .. len];
            if (body.len < self.expect_request.len) continue;
            const head = buf[0..head_end];
            self.request_ok = std.mem.startsWith(u8, head, "POST ") and
                std.mem.indexOf(u8, head, "Content-Type: application/ocsp-request") != null and
                std.mem.eql(u8, body, self.expect_request);
            break;
        }
        var w = stream.writer(io, &.{});
        try w.interface.print("HTTP/1.1 200 OK\r\nContent-Type: application/ocsp-response\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{self.der.len});
        try w.interface.writeAll(self.der);
        try w.interface.flush();
    }
};

fn fetchFixture(gpa: Allocator, tmp: *std.testing.TmpDir, port: u16) !struct { kp: Ed25519.KeyPair, der: []u8, path: []u8 } {
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x5B)));
    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/ocsp", .{port});
    var cert_buf: [2048]u8 = undefined;
    const der = try x509_selfsign.buildSelfSigned(&cert_buf, .{
        .common_name = "armorcli ocsp fetch",
        .not_before = fixture_now - 1000,
        .not_after = fixture_now + 100_000,
        .serial = &.{0x46},
        .key_pair = kp,
        .is_ca = true,
        .ocsp_url = url,
    });
    var pem_buf: [4096]u8 = undefined;
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "leaf.pem", .data = try pem.encode(&pem_buf, "CERTIFICATE", der) });
    return .{ .kp = kp, .der = try gpa.dupe(u8, der), .path = try std.fmt.allocPrint(gpa, ".zig-cache/tmp/{s}/leaf.pem", .{tmp.sub_path}) };
}

fn runFetchAgainst(gpa: Allocator, status: ocsp.CertStatus, out: *Writer) !bool {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var responder = Responder{ .listener = try addr.listen(io, .{ .reuse_address = true }), .expect_request = &.{}, .der = &.{} };
    defer responder.listener.deinit(io);
    const fx = try fetchFixture(gpa, &tmp, responder.listener.socket.address.getPort());
    defer gpa.free(fx.der);
    defer gpa.free(fx.path);

    // Self-issued fixture: the leaf is its own issuer, as in the daemon's
    // stapler tests.
    const cert = try x509.parse(fx.der);
    const request = try ocsp.buildRequestForCerts(gpa, cert, cert);
    defer gpa.free(request);
    const response = try ocsp.testSignedOcspResponseForCertId(gpa, fx.kp, .{
        .issuer_name_der = cert.subject_der,
        .issuer_key_bytes = cert.subject_public_key,
        .serial_der = cert.serial_der,
    }, status, "20260202030405Z");
    defer gpa.free(response);
    responder.expect_request = request;
    responder.der = response;

    const out_path = try std.fmt.allocPrint(gpa, ".zig-cache/tmp/{s}/resp.der", .{tmp.sub_path});
    defer gpa.free(out_path);
    const thread = try std.Thread.spawn(.{}, Responder.main, .{&responder});
    var opts = try parseArgs(&.{ "-fetch", "-cert", fx.path, "-issuer", fx.path, "-out", out_path });
    opts.at_epoch = fixture_now;
    opts.timeout_ms = 5000;
    const result = runFetch(gpa, io, opts, out);
    thread.join();
    try testing.expect(responder.request_ok);
    try result;
    const saved = try tmp.dir.readFileAlloc(io, "resp.der", gpa, .limited(max_fetch_response_bytes));
    defer gpa.free(saved);
    return std.mem.eql(u8, saved, response);
}

test "armorcli ocsp -fetch posts the CertID request and verifies a good response" {
    const gpa = testing.allocator;
    var aw = Writer.Allocating.init(gpa);
    defer aw.deinit();
    try testing.expect(try runFetchAgainst(gpa, .good, &aw.writer));
    try testing.expect(std.mem.indexOf(u8, aw.written(), "Cert Status: good") != null);
    try testing.expect(std.mem.indexOf(u8, aw.written(), "Response verifies: OK") != null);
}

test "armorcli ocsp -fetch fails closed on a revoked response and saves nothing" {
    const gpa = testing.allocator;
    var aw = Writer.Allocating.init(gpa);
    defer aw.deinit();
    try testing.expectError(error.Revoked, runFetchAgainst(gpa, .revoked, &aw.writer));
    try testing.expect(std.mem.indexOf(u8, aw.written(), "Response verifies: OK") == null);
}

test "armorcli ocsp verifyFetched rejects a stranger signature and a stale window" {
    const gpa = testing.allocator;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x5C)));
    const other = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x5D)));
    var cert_buf: [2048]u8 = undefined;
    const der = try x509_selfsign.buildSelfSigned(&cert_buf, .{
        .common_name = "armorcli ocsp verify",
        .not_before = fixture_now - 1000,
        .not_after = fixture_now + 100_000,
        .serial = &.{0x47},
        .key_pair = kp,
        .is_ca = true,
    });
    const cert = try x509.parse(der);
    const identity: ocsp.CertIdInput = .{ .issuer_name_der = cert.subject_der, .issuer_key_bytes = cert.subject_public_key, .serial_der = cert.serial_der };
    var aw = Writer.Allocating.init(gpa);
    defer aw.deinit();

    const forged = try ocsp.testSignedOcspResponseForCertId(gpa, other, identity, .good, "20260202030405Z");
    defer gpa.free(forged);
    try testing.expectError(error.BadSignature, verifyFetched(try ocsp.parse(forged), forged, cert, cert, fixture_now, &aw.writer));

    const good = try ocsp.testSignedOcspResponseForCertId(gpa, kp, identity, .good, "20260202030405Z");
    defer gpa.free(good);
    try testing.expectError(error.Stale, verifyFetched(try ocsp.parse(good), good, cert, cert, 1_900_000_000, &aw.writer));
    try verifyFetched(try ocsp.parse(good), good, cert, cert, fixture_now, &aw.writer);
}
