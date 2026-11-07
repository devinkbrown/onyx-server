// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! `armor dc` — RFC 9345 delegated credentials.
//!
//!   armor dc mint     -cert <chain> -key <leaf key> -out <dc.bin> -dc-key-out <pem> -valid <dur>
//!   armor dc inspect  -in <dc.bin> [-cert <chain>] [-at <unix>]
//!   armor dc validate -in <dc.bin> -cert <chain> [-at <unix>]
//!
//! Minting is `crypto/dc_mint.zig`; checking is the daemon's
//! `delegated_credential_cli.validateChain`, the same RFC 9345 §4.1.3 checks
//! the TLS client applies. A freshly minted DC is re-validated before anything
//! is written, so `mint` can never emit a credential a client would reject.
//! The leaf must carry the DelegationUsage extension (RFC 9345 §4.2); without
//! it `mint` fails with `DelegationUsageMissing`.

const std = @import("std");
const onyx_server = @import("onyx_server");
const common = @import("common.zig");
const pkey_cmd = @import("pkey_cmd.zig");

const delegated_credential_cli = onyx_server.daemon.delegated_credential_cli;
const dc_mint = delegated_credential_cli.dc_mint;
const tls_certs = onyx_server.daemon.tls_certs;
const pem = onyx_server.proto.pem;
const ecdsa_p256 = onyx_server.crypto.ecdsa_p256;

const Allocator = std.mem.Allocator;
const Writer = common.Writer;

pub const Command = enum { mint, inspect, validate };

pub const Options = struct {
    command: Command,
    cert: ?[]const u8 = null,
    key: ?[]const u8 = null,
    in_path: ?[]const u8 = null,
    out_path: ?[]const u8 = null,
    dc_key_out: ?[]const u8 = null,
    valid_seconds: u32 = 0,
    dc_algorithm: dc_mint.DcAlgorithm = .ecdsa_p256,
    at: ?i64 = null,
};

pub fn usage(w: *Writer) Writer.Error!void {
    try w.writeAll(
        \\usage: armor dc mint -cert <chain.pem> -key <leaf-key.pem> -out <dc.bin>
        \\                     -dc-key-out <dc-key.pem> -valid <dur> [-dc-alg ecdsa-p256|ed25519]
        \\       armor dc inspect  -in <dc.bin> [-cert <chain.pem>] [-at <unix>]
        \\       armor dc validate -in <dc.bin> -cert <chain.pem> [-at <unix>]
        \\  -valid <dur>   lifetime from now: <n>[s|m|h|d], at most 7d (RFC 9345 4.1.3)
        \\  -dc-alg        delegated key type (default ecdsa-p256)
        \\
        \\The leaf certificate must carry the DelegationUsage extension (RFC 9345 4.2).
        \\The DC private key is written mode 0600; the DC wire file is the raw
        \\DelegatedCredential structure (`s_server -dc`, `onyx-server delegated-credential`).
        \\
    );
}

/// Parse `<n>[s|m|h|d]` to seconds; zero or more than seven days is a usage error.
pub fn parseDuration(text: []const u8) common.Error!u32 {
    if (text.len == 0) return error.Usage;
    const unit: u64 = switch (text[text.len - 1]) {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        'd' => 86400,
        '0'...'9' => 0,
        else => return error.Usage,
    };
    const digits = if (unit == 0) text else text[0 .. text.len - 1];
    const n = std.fmt.parseInt(u64, digits, 10) catch return error.Usage;
    const secs = std.math.mul(u64, n, if (unit == 0) 1 else unit) catch return error.Usage;
    if (secs == 0 or secs > dc_mint.max_lifetime_seconds) return error.Usage;
    return @intCast(secs);
}

pub fn parseArgs(args: []const []const u8) common.Error!Options {
    if (args.len == 0) return error.Usage;
    var opts = Options{ .command = std.meta.stringToEnum(Command, args[0]) orelse return error.Usage };
    var cur = common.ArgCursor{ .args = args[1..] };
    while (cur.next()) |a| {
        if (std.mem.eql(u8, a, "-cert")) {
            opts.cert = try cur.value();
        } else if (std.mem.eql(u8, a, "-key")) {
            opts.key = try cur.value();
        } else if (std.mem.eql(u8, a, "-in")) {
            opts.in_path = try cur.value();
        } else if (std.mem.eql(u8, a, "-out")) {
            opts.out_path = try cur.value();
        } else if (std.mem.eql(u8, a, "-dc-key-out")) {
            opts.dc_key_out = try cur.value();
        } else if (std.mem.eql(u8, a, "-valid")) {
            opts.valid_seconds = try parseDuration(try cur.value());
        } else if (std.mem.eql(u8, a, "-dc-alg")) {
            const v = try cur.value();
            opts.dc_algorithm = if (std.mem.eql(u8, v, "ecdsa-p256"))
                .ecdsa_p256
            else if (std.mem.eql(u8, v, "ed25519"))
                .ed25519
            else
                return error.Usage;
        } else if (std.mem.eql(u8, a, "-at")) {
            opts.at = std.fmt.parseInt(i64, try cur.value(), 10) catch return error.Usage;
        } else {
            return error.Usage;
        }
    }
    switch (opts.command) {
        .mint => {
            if (opts.cert == null or opts.key == null or opts.out_path == null or
                opts.dc_key_out == null or opts.valid_seconds == 0) return error.Usage;
            if (std.mem.eql(u8, opts.out_path.?, opts.dc_key_out.?)) return error.Usage;
        },
        .inspect => if (opts.in_path == null) return error.Usage,
        .validate => if (opts.in_path == null or opts.cert == null) return error.Usage,
    }
    return opts;
}

pub fn run(gpa: Allocator, io: std.Io, opts: Options, out: *Writer) !void {
    switch (opts.command) {
        .mint => return runMint(gpa, io, opts, out),
        .inspect, .validate => {
            const wire = try std.Io.Dir.cwd().readFileAlloc(io, opts.in_path.?, gpa, .limited(delegated_credential_cli.max_dc_file_bytes));
            defer gpa.free(wire);
            const v = try delegated_credential_cli.validate(gpa, io, wire, opts.cert, opts.at);
            try writeValidation(v, out);
        },
    }
}

fn runMint(gpa: Allocator, io: std.Io, opts: Options, out: *Writer) !void {
    var leaf = try tls_certs.loadOrBootstrap(gpa, io, .{ .cert_path = opts.cert.?, .key_path = opts.key.? });
    defer leaf.deinit(gpa);
    if (leaf.cert_chain.len == 0) return error.EmptyCertificateChain;
    const leaf_key: dc_mint.LeafKey = if (leaf.rsa_signing_key) |k|
        .{ .rsa = k }
    else if (leaf.ecdsa_p256_signing_key) |k|
        .{ .ecdsa_p256 = k }
    else if (leaf.signing_key) |k|
        .{ .ed25519 = k }
    else
        return error.UnsupportedAlgorithm;

    const now = opts.at orelse common.wallClockSeconds();
    var minted = try dc_mint.mint(gpa, io, .{
        .leaf_der = leaf.cert_chain[0],
        .leaf_key = leaf_key,
        .dc_algorithm = opts.dc_algorithm,
        .now_unix = now,
        .lifetime_seconds = opts.valid_seconds,
    });
    defer minted.deinit(gpa);

    // Self-check with the validator the daemon and client logic share.
    const v = try delegated_credential_cli.validateChain(gpa, minted.wire, leaf.cert_chain, now);

    var pem_buf: [512]u8 = undefined;
    defer std.crypto.secureZero(u8, &pem_buf);
    const key_pem = try dcKeyPem(&pem_buf, &minted.private_key);
    try common.writeKeyFile(io, std.Io.Dir.cwd(), opts.dc_key_out.?, key_pem);
    try common.writePublicFile(io, std.Io.Dir.cwd(), opts.out_path.?, minted.wire);

    try out.print("minted delegated credential -> {s} (key -> {s})\n", .{ opts.out_path.?, opts.dc_key_out.? });
    try writeValidation(v, out);
}

/// PEM for the delegated private key, in the forms `tls_certs` loads:
/// SEC1 `EC PRIVATE KEY` (RFC 5915) or PKCS#8 `PRIVATE KEY` for Ed25519
/// (RFC 8410 §7).
fn dcKeyPem(buf: []u8, key: *const dc_mint.DcPrivateKey) ![]const u8 {
    switch (key.*) {
        .ecdsa_p256 => |*kp| {
            var der = pkey_cmd.ecPrivateKeyDer(kp);
            defer std.crypto.secureZero(u8, &der);
            return pem.encode(buf, "EC PRIVATE KEY", &der);
        },
        .ed25519 => |kp| {
            var seed = kp.secret_key.seed();
            defer std.crypto.secureZero(u8, &seed);
            var der = pkey_cmd.ed25519Pkcs8Der(seed);
            defer std.crypto.secureZero(u8, &der);
            return pem.encode(buf, "PRIVATE KEY", &der);
        },
    }
}

pub fn writeValidation(v: delegated_credential_cli.Validation, out: *Writer) !void {
    const dc = v.dc;
    const name = delegated_credential_cli.schemeName;
    try out.print("valid_time              : {d}\n", .{dc.valid_time});
    try out.print("dc_cert_verify_algorithm: 0x{x:0>4} ({s})\n", .{ dc.dc_cert_verify_algorithm, name(dc.dc_cert_verify_algorithm) });
    try out.print("algorithm               : 0x{x:0>4} ({s})\n", .{ dc.algorithm, name(dc.algorithm) });
    try out.print("spki_len                : {d}\n", .{dc.spki.len});
    try out.print("signature_len           : {d}\n", .{dc.signature.len});
    if (v.cert_checked) {
        try out.print("expiry_unix             : {d}\n", .{v.expiry_unix});
        try out.writeAll("leaf_signature          : valid\n");
        try out.writeAll("delegated credential: OK\n");
    } else {
        try out.writeAll("leaf_signature          : not checked (no -cert)\n");
    }
}

const testing = std.testing;
const x509_selfsign = onyx_server.proto.x509_selfsign;
const Ed25519 = std.crypto.sign.Ed25519;

test "armorcli dc parseDuration caps at seven days" {
    try testing.expectEqual(@as(u32, 90), try parseDuration("90"));
    try testing.expectEqual(@as(u32, 90), try parseDuration("90s"));
    try testing.expectEqual(@as(u32, 7200), try parseDuration("2h"));
    try testing.expectEqual(@as(u32, 604800), try parseDuration("7d"));
    try testing.expectError(error.Usage, parseDuration("8d"));
    try testing.expectError(error.Usage, parseDuration("604801"));
    try testing.expectError(error.Usage, parseDuration("0h"));
    try testing.expectError(error.Usage, parseDuration("h"));
    try testing.expectError(error.Usage, parseDuration("1w"));
    try testing.expectError(error.Usage, parseDuration("99999999999999999999d"));
}

test "armorcli dc parseArgs requires every mint input" {
    try testing.expectError(error.Usage, parseArgs(&.{}));
    try testing.expectError(error.Usage, parseArgs(&.{"forge"}));
    try testing.expectError(error.Usage, parseArgs(&.{ "mint", "-cert", "c", "-key", "k", "-out", "o", "-dc-key-out", "d" }));
    try testing.expectError(error.Usage, parseArgs(&.{ "mint", "-cert", "c", "-key", "k", "-out", "o", "-dc-key-out", "o", "-valid", "1h" }));
    try testing.expectError(error.Usage, parseArgs(&.{ "validate", "-in", "x" }));
    const m = try parseArgs(&.{ "mint", "-cert", "c", "-key", "k", "-out", "o", "-dc-key-out", "d", "-valid", "1d", "-dc-alg", "ed25519" });
    try testing.expectEqual(@as(u32, 86400), m.valid_seconds);
    try testing.expectEqual(dc_mint.DcAlgorithm.ed25519, m.dc_algorithm);
}

/// Write a leaf cert + Ed25519 PKCS#8 key into `tmp`; returns owned paths.
fn writeLeafFixture(gpa: Allocator, tmp: *std.testing.TmpDir, delegation: bool, not_before: i64) !struct { cert: []u8, key: []u8 } {
    const io = testing.io;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x71)));
    var cert_buf: [1024]u8 = undefined;
    const der = try x509_selfsign.buildSelfSigned(&cert_buf, .{
        .common_name = "dc.example.test",
        .not_before = not_before,
        .not_after = not_before + 90 * 86400,
        .serial = &.{0x71},
        .key_pair = kp,
        .dns_names = &.{"dc.example.test"},
        .delegation_usage = delegation,
        .key_usage_digital_signature = true,
        .is_ca = true,
    });
    var pem_buf: [2048]u8 = undefined;
    try tmp.dir.writeFile(io, .{ .sub_path = "leaf.pem", .data = try pem.encode(&pem_buf, "CERTIFICATE", der) });
    const key_der = pkey_cmd.ed25519Pkcs8Der(kp.secret_key.seed());
    try tmp.dir.writeFile(io, .{ .sub_path = "leaf.key", .data = try pem.encode(&pem_buf, "PRIVATE KEY", &key_der) });
    return .{
        .cert = try std.fmt.allocPrint(gpa, ".zig-cache/tmp/{s}/leaf.pem", .{tmp.sub_path}),
        .key = try std.fmt.allocPrint(gpa, ".zig-cache/tmp/{s}/leaf.key", .{tmp.sub_path}),
    };
}

test "armorcli dc mint output validates with the existing validator and loads as a TLS DC" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const now = common.wallClockSeconds();
    const fx = try writeLeafFixture(gpa, &tmp, true, now - 3600);
    defer gpa.free(fx.cert);
    defer gpa.free(fx.key);
    const out_path = try std.fmt.allocPrint(gpa, ".zig-cache/tmp/{s}/dc.bin", .{tmp.sub_path});
    defer gpa.free(out_path);
    const key_out = try std.fmt.allocPrint(gpa, ".zig-cache/tmp/{s}/dc.key", .{tmp.sub_path});
    defer gpa.free(key_out);

    var aw = Writer.Allocating.init(gpa);
    defer aw.deinit();
    try run(gpa, io, try parseArgs(&.{ "mint", "-cert", fx.cert, "-key", fx.key, "-out", out_path, "-dc-key-out", key_out, "-valid", "12h" }), &aw.writer);
    try testing.expect(std.mem.indexOf(u8, aw.written(), "delegated credential: OK") != null);

    // `dc validate` and the daemon's validate() accept it.
    aw.clearRetainingCapacity();
    try run(gpa, io, try parseArgs(&.{ "validate", "-in", out_path, "-cert", fx.cert }), &aw.writer);
    try testing.expect(std.mem.indexOf(u8, aw.written(), "ecdsa_secp256r1_sha256") != null);
    const wire = try tmp.dir.readFileAlloc(io, "dc.bin", gpa, .limited(4096));
    defer gpa.free(wire);
    const v = try delegated_credential_cli.validate(gpa, io, wire, fx.cert, now);
    try testing.expectEqual(now + 12 * 3600, v.expiry_unix);

    if (@import("builtin").os.tag == .linux) {
        const st = try tmp.dir.statFile(io, "dc.key", .{});
        try testing.expectEqual(@as(std.posix.mode_t, 0), st.permissions.toMode() & 0o077);
    }

    // The DC key loads and the TLS server accepts the pair as its DC.
    var dc_key = try tls_certs.loadOrBootstrap(gpa, io, .{ .cert_path = fx.cert, .key_path = key_out });
    defer dc_key.deinit(gpa);
    var leaf = try tls_certs.loadOrBootstrap(gpa, io, .{ .cert_path = fx.cert, .key_path = fx.key });
    defer leaf.deinit(gpa);
    const tls_server = onyx_server.crypto.tls_server;
    var server = try tls_server.Server.init(gpa, .{
        .cert_chain = leaf.cert_chain,
        .signing_key = leaf.signing_key,
        .delegated_credential = .{ .wire = wire, .private_key = .{ .ecdsa_p256 = dc_key.ecdsa_p256_signing_key.? } },
    });
    server.deinit();
}

test "armorcli dc mint fails clearly without DelegationUsage" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const fx = try writeLeafFixture(gpa, &tmp, false, common.wallClockSeconds() - 60);
    defer gpa.free(fx.cert);
    defer gpa.free(fx.key);
    var aw = Writer.Allocating.init(gpa);
    defer aw.deinit();
    try testing.expectError(error.DelegationUsageMissing, run(gpa, io, try parseArgs(&.{ "mint", "-cert", fx.cert, "-key", fx.key, "-out", "never.bin", "-dc-key-out", "never.key", "-valid", "1h" }), &aw.writer));
    // Nothing was written.
    try testing.expectError(error.FileNotFound, std.Io.Dir.cwd().statFile(io, "never.key", .{}));
}
