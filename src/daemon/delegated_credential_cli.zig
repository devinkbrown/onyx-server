// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Out-of-band delegated credential inspection/validation tooling.
//!
//! This intentionally does not mint delegated credentials: production minting
//! needs private-key loading, DC private-key output, and rotation policy.  The
//! command here validates ready-made RFC 9345 wire bytes with the same codec and
//! signature primitives the TLS stack already consumes.

// This leaf stays inside the onyx_server module. A second `@import("onyx_server")`
// from the executable would put the same file in both modules, which Zig rejects.
const std = @import("std");
const dlog = @import("dlog.zig");
const tls_certs = @import("tls_certs.zig");
const delegated_credential = @import("../proto/delegated_credential.zig");
const tls_signature_scheme = @import("../proto/tls_signature_scheme.zig");
const ecdsa_p256 = @import("../crypto/ecdsa_p256.zig");
const rsa_verify = @import("../crypto/rsa_verify.zig");
const x509 = @import("../crypto/x509.zig");
const platform = @import("../substrate/platform.zig");
const x509_selfsign = @import("../proto/x509_selfsign.zig");
const pem = @import("../proto/pem.zig");

const Ed25519 = std.crypto.sign.Ed25519;

const max_dc_file_bytes: usize = 256 * 1024;

pub const Options = struct {
    command: Command = .inspect,
    dc_path: []const u8,
    cert_path: ?[]const u8 = null,
    now_unix: ?i64 = null,
};

pub const Command = enum {
    inspect,
    validate,
};

pub const Validation = struct {
    dc: delegated_credential.Parsed,
    cert_checked: bool = false,
    leaf_not_before: i64 = 0,
    leaf_not_after: i64 = 0,
    expiry_unix: i64 = 0,
};

pub const Error = error{
    MissingArgument,
    UnknownArgument,
    NoCertificate,
    EmptyCertificateChain,
    DelegationUsageMissing,
    DigitalSignatureKeyUsageMissing,
    NoClock,
    Expired,
    LifetimeTooLong,
    OutlivesCertificate,
    UnsupportedSignatureScheme,
    UnsupportedPublicKey,
    BadSignature,
} ||
    std.fmt.ParseIntError ||
    std.Io.Dir.ReadFileAllocError ||
    std.mem.Allocator.Error ||
    delegated_credential.Error ||
    tls_certs.Error ||
    x509.Error ||
    ecdsa_p256.DerError;

pub fn usage() void {
    dlog.log(
        \\usage: onyx-server delegated-credential inspect --dc <wire> [--cert <chain.pem>] [--time <unix>]
        \\       onyx-server delegated-credential validate --dc <wire> --cert <chain.pem> [--time <unix>]
        \\  --dc <path>      raw DelegatedCredential extension data
        \\  --cert <path>    PEM/DER leaf or chain whose leaf signed the DC
        \\  --time <unix>    validation time; default is current wall clock
        \\
    , .{});
}

pub fn parseArgs(args: []const []const u8) Error!?Options {
    if (args.len == 0) return null;
    const command: Command = if (std.mem.eql(u8, args[0], "inspect"))
        .inspect
    else if (std.mem.eql(u8, args[0], "validate"))
        .validate
    else
        return error.UnknownArgument;

    var dc_path: ?[]const u8 = null;
    var cert_path: ?[]const u8 = null;
    var now_unix: ?i64 = null;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--dc") and i + 1 < args.len) {
            i += 1;
            dc_path = args[i];
        } else if (std.mem.eql(u8, a, "--cert") and i + 1 < args.len) {
            i += 1;
            cert_path = args[i];
        } else if (std.mem.eql(u8, a, "--time") and i + 1 < args.len) {
            i += 1;
            now_unix = try std.fmt.parseInt(i64, args[i], 10);
        } else {
            return error.UnknownArgument;
        }
    }

    const dc = dc_path orelse return error.MissingArgument;
    if (command == .validate and cert_path == null) return error.NoCertificate;
    return .{
        .command = command,
        .dc_path = dc,
        .cert_path = cert_path,
        .now_unix = now_unix,
    };
}

pub fn run(allocator: std.mem.Allocator, io: std.Io, opts: Options) !bool {
    const dc_wire = try std.Io.Dir.cwd().readFileAlloc(io, opts.dc_path, allocator, .limited(max_dc_file_bytes));
    defer allocator.free(dc_wire);

    const validation = validate(allocator, io, dc_wire, opts.cert_path, opts.now_unix) catch |err| {
        dlog.log("delegated-credential: INVALID ({s})\n", .{@errorName(err)});
        return false;
    };
    printValidation(validation);
    return true;
}

pub fn validate(
    allocator: std.mem.Allocator,
    io: std.Io,
    dc_wire: []const u8,
    cert_path: ?[]const u8,
    now_override: ?i64,
) Error!Validation {
    const dc = try delegated_credential.parse(dc_wire);
    var result = Validation{ .dc = dc };
    const path = cert_path orelse return result;

    const chain = try tls_certs.loadCertChain(allocator, io, path);
    defer {
        for (chain) |der| allocator.free(der);
        allocator.free(chain);
    }
    if (chain.len == 0) return error.EmptyCertificateChain;
    const leaf_der = chain[0];
    const leaf = try x509.parse(leaf_der);
    if (!leaf.delegation_usage) return error.DelegationUsageMissing;
    if (!leaf.key_usage_digital_signature) return error.DigitalSignatureKeyUsageMissing;

    const now = now_override orelse @divTrunc(platform.realtimeMillis(), 1000);
    const expiry = leaf.not_before.epoch_seconds + @as(i64, dc.valid_time);
    if (now > expiry) return error.Expired;
    if (expiry > now + @as(i64, delegated_credential.max_valid_time_seconds)) {
        return error.LifetimeTooLong;
    }
    if (expiry >= leaf.not_after.epoch_seconds) return error.OutlivesCertificate;

    const msg_len = delegated_credential.signedMessageLen(leaf_der.len, dc.signed_portion.len);
    const msg = try allocator.alloc(u8, msg_len);
    defer allocator.free(msg);
    const signed = try delegated_credential.writeSignedMessage(msg, leaf_der, dc.signed_portion);
    try verifySignatureScheme(
        try x509.extractPublicKey(leaf.spki_der),
        tls_signature_scheme.SignatureScheme.fromInt(dc.algorithm),
        signed,
        dc.signature,
    );

    result.cert_checked = true;
    result.leaf_not_before = leaf.not_before.epoch_seconds;
    result.leaf_not_after = leaf.not_after.epoch_seconds;
    result.expiry_unix = expiry;
    return result;
}

fn verifySignatureScheme(
    key: x509.SubjectPublicKey,
    scheme: tls_signature_scheme.SignatureScheme,
    msg: []const u8,
    sig: []const u8,
) Error!void {
    switch (scheme) {
        .ed25519 => {
            const raw = switch (key) {
                .ed25519 => |pk| pk,
                else => return error.UnsupportedPublicKey,
            };
            if (raw.len != Ed25519.PublicKey.encoded_length or sig.len != Ed25519.Signature.encoded_length) {
                return error.BadSignature;
            }
            const pk = Ed25519.PublicKey.fromBytes(raw[0..Ed25519.PublicKey.encoded_length].*) catch return error.BadSignature;
            const fixed = Ed25519.Signature.fromBytes(sig[0..Ed25519.Signature.encoded_length].*);
            fixed.verify(msg, pk) catch return error.BadSignature;
        },
        .ecdsa_secp256r1_sha256 => {
            const sec1 = switch (key) {
                .ecdsa_p256 => |pk| pk,
                else => return error.UnsupportedPublicKey,
            };
            const pk = ecdsa_p256.parsePublicKeySec1(sec1) catch return error.BadSignature;
            const decoded = try ecdsa_p256.signatureFromDer(sig);
            if (!ecdsa_p256.verify(decoded, msg, pk)) return error.BadSignature;
        },
        .rsa_pss_rsae_sha256 => {
            const rsa = switch (key) {
                .rsa => |pk| pk,
                else => return error.UnsupportedPublicKey,
            };
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(msg, &digest, .{});
            const pub_key = rsa_verify.PublicKey{ .n = rsa.modulus, .e = rsa.exponent };
            if (!rsa_verify.verifyPss(pub_key, .sha256, &digest, sig, 32)) return error.BadSignature;
        },
        else => return error.UnsupportedSignatureScheme,
    }
}

fn printValidation(validation: Validation) void {
    const dc = validation.dc;
    dlog.log("delegated-credential: OK\n", .{});
    dlog.log("  valid_time: {d}\n", .{dc.valid_time});
    dlog.log("  dc_cert_verify_algorithm: 0x{x:0>4} ({s})\n", .{ dc.dc_cert_verify_algorithm, schemeName(dc.dc_cert_verify_algorithm) });
    dlog.log("  algorithm: 0x{x:0>4} ({s})\n", .{ dc.algorithm, schemeName(dc.algorithm) });
    dlog.log("  spki_len: {d}\n", .{dc.spki.len});
    dlog.log("  signature_len: {d}\n", .{dc.signature.len});
    if (validation.cert_checked) {
        dlog.log("  leaf_not_before: {d}\n", .{validation.leaf_not_before});
        dlog.log("  leaf_not_after: {d}\n", .{validation.leaf_not_after});
        dlog.log("  expiry_unix: {d}\n", .{validation.expiry_unix});
        dlog.log("  leaf_signature: valid\n", .{});
    } else {
        dlog.log("  leaf_signature: not checked (no --cert)\n", .{});
    }
}

fn schemeName(raw: u16) []const u8 {
    return switch (tls_signature_scheme.SignatureScheme.fromInt(raw)) {
        .ed25519 => "ed25519",
        .ecdsa_secp256r1_sha256 => "ecdsa_secp256r1_sha256",
        .ecdsa_secp384r1_sha384 => "ecdsa_secp384r1_sha384",
        .rsa_pss_rsae_sha256 => "rsa_pss_rsae_sha256",
        .rsa_pkcs1_sha256 => "rsa_pkcs1_sha256",
        else => "unknown",
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "delegated credential CLI parseArgs" {
    try testing.expectError(error.UnknownArgument, parseArgs(&.{"bogus"}));
    try testing.expectError(error.MissingArgument, parseArgs(&.{"inspect"}));
    try testing.expectError(error.NoCertificate, parseArgs(&.{ "validate", "--dc", "dc.bin" }));

    const inspect = (try parseArgs(&.{ "inspect", "--dc", "dc.bin" })).?;
    try testing.expectEqual(Command.inspect, inspect.command);
    try testing.expectEqualStrings("dc.bin", inspect.dc_path);
    try testing.expect(inspect.cert_path == null);

    const validate_args = (try parseArgs(&.{ "validate", "--dc", "dc.bin", "--cert", "leaf.pem", "--time", "1700000000" })).?;
    try testing.expectEqual(Command.validate, validate_args.command);
    try testing.expectEqualStrings("leaf.pem", validate_args.cert_path.?);
    try testing.expectEqual(@as(i64, 1_700_000_000), validate_args.now_unix.?);
}

test "delegated credential CLI validates leaf signature and lifetime" {
    const allocator = testing.allocator;
    const leaf_kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x51)));
    const dc_kp = ecdsa_p256.KeyPair.generate(testing.io);
    const not_before: i64 = 1_704_067_200;
    const not_after: i64 = not_before + 30 * 24 * 3600;
    const now = not_before + 3600;

    var leaf_buf: [1024]u8 = undefined;
    const leaf = try x509_selfsign.buildSelfSigned(&leaf_buf, .{
        .common_name = "dc.example.test",
        .not_before = not_before,
        .not_after = not_after,
        .serial = &.{ 0x44, 0x43 },
        .key_pair = leaf_kp,
        .delegation_usage = true,
        .key_usage_digital_signature = true,
    });

    var spki_buf: [p256_spki_prefix.len + ecdsa_p256.sec1_uncompressed_length]u8 = undefined;
    const dc_spki = p256Spki(&spki_buf, dc_kp);
    const valid_time: u32 = @intCast(now + 24 * 3600 - not_before);
    var dc_wire_buf: [512]u8 = undefined;
    const dc_wire = try mintEd25519LeafDc(&dc_wire_buf, leaf, dc_spki, valid_time, leaf_kp);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pem_buf: [2048]u8 = undefined;
    const encoded = try pem.encode(&pem_buf, "CERTIFICATE", leaf);
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "leaf.pem", .data = encoded });
    const cert_path = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/leaf.pem", .{tmp.sub_path});
    defer allocator.free(cert_path);

    const ok = try validate(allocator, testing.io, dc_wire, cert_path, now);
    try testing.expect(ok.cert_checked);
    try testing.expectEqual(@as(i64, now + 24 * 3600), ok.expiry_unix);

    var tampered: [512]u8 = undefined;
    @memcpy(tampered[0..dc_wire.len], dc_wire);
    tampered[dc_wire.len - 1] ^= 0x01;
    try testing.expectError(error.BadSignature, validate(allocator, testing.io, tampered[0..dc_wire.len], cert_path, now));
}

const p256_spki_prefix = [_]u8{
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
    0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
};

fn p256Spki(out: *[p256_spki_prefix.len + ecdsa_p256.sec1_uncompressed_length]u8, kp: ecdsa_p256.KeyPair) []const u8 {
    @memcpy(out[0..p256_spki_prefix.len], &p256_spki_prefix);
    const sec1 = kp.public_key.toUncompressedSec1();
    @memcpy(out[p256_spki_prefix.len..], &sec1);
    return out[0..];
}

fn mintEd25519LeafDc(
    out: []u8,
    leaf_der: []const u8,
    dc_spki: []const u8,
    valid_time: u32,
    leaf_kp: Ed25519.KeyPair,
) ![]const u8 {
    const cred: delegated_credential.Credential = .{
        .valid_time = valid_time,
        .dc_cert_verify_algorithm = tls_signature_scheme.SignatureScheme.ecdsa_secp256r1_sha256.toInt(),
        .spki = dc_spki,
    };
    var portion_buf: [256]u8 = undefined;
    const portion = try delegated_credential.writeSignedPortion(&portion_buf, cred, tls_signature_scheme.SignatureScheme.ed25519.toInt());
    var msg_buf: [2048]u8 = undefined;
    const msg = try delegated_credential.writeSignedMessage(&msg_buf, leaf_der, portion);
    const sig = (try leaf_kp.sign(msg, null)).toBytes();
    return delegated_credential.serialize(out, cred, tls_signature_scheme.SignatureScheme.ed25519.toInt(), &sig);
}
