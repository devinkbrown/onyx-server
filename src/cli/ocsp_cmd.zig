// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! `armor ocsp` — display and verify a stapled OCSP response (RFC 6960).
//!
//! All parse / signature / staple-servable decisions are substrate calls
//! (`src/crypto/ocsp.zig`). This file only formats and loads files. There is
//! no HTTP fetch here — daemon `ocsp_staple.zig` owns that loop.

const std = @import("std");
const onyx_server = @import("onyx_server");
const common = @import("common.zig");

const ocsp = onyx_server.crypto.ocsp;
const x509 = onyx_server.crypto.x509;
const pem = onyx_server.proto.pem;
const acme_cli = onyx_server.daemon.acme_cli;

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
};

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
        \\No HTTP fetch. Fail-closed on bad signature, unknown, revoked, or stale.
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
        } else if (a.len > 0 and a[0] == '-' and a.len > 1) {
            return error.Usage;
        } else {
            opts.in_path = a;
        }
    }
    if (opts.verify and opts.ca_file.len == 0) return error.Usage;
    if (opts.serial != null and !opts.verify) return error.Usage;
    return opts;
}

pub fn run(gpa: Allocator, io: std.Io, opts: Options, out: *Writer) !void {
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
