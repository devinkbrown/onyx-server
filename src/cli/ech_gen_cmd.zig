// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! `armor ech-gen` — generate an Encrypted Client Hello key: a fresh X25519
//! HPKE key pair, the single-entry `ECHConfigList` that publishes it, and an
//! owner-only (0600) private-key file. The output is exactly what the daemon's
//! `[[tls.ech_keys]]` loader (`daemon/tls_ech_load.zig`) consumes:
//!
//!     [[tls.ech_keys]]
//!     config_path = "<config-out>"          # raw ECHConfigList bytes
//!     private_key = "@file:<key-out>"       # 64 hex chars (whitespace trimmed)
//!
//! Wire format (draft-ietf-tls-esni-22 §4, version 0xfe0d):
//!
//!     ECHConfigList  = uint16 length || ECHConfig
//!     ECHConfig      = uint16 version(0xfe0d) || uint16 length || contents
//!     contents       = uint8 config_id || uint16 kem_id || opaque public_key<1..2^16-1>
//!                      || HpkeSymmetricCipherSuite cipher_suites<4..2^16-4>
//!                      || uint8 maximum_name_length || opaque public_name<1..255>
//!                      || ECHConfigExtension extensions<0..2^16-1>
//!
//! KEM is DHKEM(X25519, HKDF-SHA256) (0x0020, RFC 9180 §7.1). Only the
//! `{HKDF-SHA256, ChaCha20-Poly1305}` suite is advertised because it is the one
//! suite the Armor server opens (`tls_server.zig` rejects a config without it);
//! advertising a suite the server cannot open would make clients that pick it
//! fall back to the outer ClientHello. The base64 form printed on success is
//! the value for a DNS HTTPS/SVCB `ech=` SvcParam (RFC 9460 + draft-ietf-tls-
//! svcb-ech).

const std = @import("std");
const onyx_server = @import("onyx_server");
const common = @import("common.zig");

const hpke = onyx_server.crypto.hpke;
const ech_seal = onyx_server.crypto.ech_seal;
const ech_config = onyx_server.proto.ech_config;

const Allocator = std.mem.Allocator;
const Writer = common.Writer;

pub const Options = struct {
    public_name: ?[]const u8 = null,
    config_out: ?[]const u8 = null,
    key_out: ?[]const u8 = null,
    config_id: ?u8 = null,
    max_name_len: u8 = 0,
};

/// Largest key file `readKeyFile` accepts (64 hex chars plus whitespace).
pub const max_key_file_bytes: usize = 1024;

pub fn usage(w: *Writer) Writer.Error!void {
    try w.writeAll(
        \\usage: armor ech-gen -public-name <dns> -config-out <file> -key-out <file> [options]
        \\  -public-name <dns>   cover name placed in the outer ClientHello SNI
        \\  -config-out <file>   write the ECHConfigList (binary) here
        \\  -key-out <file>      write the X25519 private key (hex, mode 0600) here
        \\  -config-id <0-255>   config_id (default: random)
        \\  -max-name-len <n>    maximum_name_length hint (default 0 = unknown)
        \\
        \\Output loads as [[tls.ech_keys]] config_path / private_key = "@file:<key-out>".
        \\
    );
}

pub fn parseArgs(args: []const []const u8) common.Error!Options {
    var opts = Options{};
    var cur = common.ArgCursor{ .args = args };
    while (cur.next()) |a| {
        if (std.mem.eql(u8, a, "-public-name")) {
            opts.public_name = try cur.value();
        } else if (std.mem.eql(u8, a, "-config-out")) {
            opts.config_out = try cur.value();
        } else if (std.mem.eql(u8, a, "-key-out")) {
            opts.key_out = try cur.value();
        } else if (std.mem.eql(u8, a, "-config-id")) {
            opts.config_id = std.fmt.parseInt(u8, try cur.value(), 10) catch return error.Usage;
        } else if (std.mem.eql(u8, a, "-max-name-len")) {
            opts.max_name_len = std.fmt.parseInt(u8, try cur.value(), 10) catch return error.Usage;
        } else {
            return error.Usage;
        }
    }
    const name = opts.public_name orelse return error.Usage;
    if (!ech_config.isValidPublicName(name)) return error.Usage;
    if (opts.config_out == null or opts.key_out == null) return error.Usage;
    if (std.mem.eql(u8, opts.config_out.?, opts.key_out.?)) return error.Usage;
    return opts;
}

/// Upper bound on a generated list: 2 + 4 + 1 + 2 + 2 + 32 + 2 + 4 + 1 + 1 + 255 + 2.
pub const max_list_len: usize = 308;

/// Serialize a single-entry ECHConfigList into `out` (see module header).
pub fn buildConfigList(
    out: *[max_list_len]u8,
    config_id: u8,
    public_key: *const [hpke.public_key_len]u8,
    public_name: []const u8,
    max_name_len: u8,
) error{InvalidPublicName}![]const u8 {
    if (!ech_config.isValidPublicName(public_name) or public_name.len > 255) return error.InvalidPublicName;
    var n: usize = 6; // list length(2) + version(2) + contents length(2)
    out[n] = config_id;
    n += 1;
    std.mem.writeInt(u16, out[n..][0..2], ech_seal.kem_id, .big);
    n += 2;
    std.mem.writeInt(u16, out[n..][0..2], public_key.len, .big);
    n += 2;
    @memcpy(out[n..][0..public_key.len], public_key);
    n += public_key.len;
    std.mem.writeInt(u16, out[n..][0..2], 4, .big); // one {kdf, aead} pair
    n += 2;
    std.mem.writeInt(u16, out[n..][0..2], ech_seal.kdf_id, .big);
    n += 2;
    std.mem.writeInt(u16, out[n..][0..2], ech_seal.aead_id, .big);
    n += 2;
    out[n] = max_name_len;
    n += 1;
    out[n] = @intCast(public_name.len);
    n += 1;
    @memcpy(out[n..][0..public_name.len], public_name);
    n += public_name.len;
    std.mem.writeInt(u16, out[n..][0..2], 0, .big); // no extensions
    n += 2;
    std.mem.writeInt(u16, out[0..2], @intCast(n - 2), .big);
    std.mem.writeInt(u16, out[2..4], ech_config.version_draft13, .big);
    std.mem.writeInt(u16, out[4..6], @intCast(n - 6), .big);
    return out[0..n];
}

/// Read a hex X25519 private-key file written by `ech-gen` (the same format
/// `[[tls.ech_keys]] private_key = "@file:..."` accepts).
pub fn readKeyFile(gpa: Allocator, io: std.Io, path: []const u8) ![hpke.secret_key_len]u8 {
    const raw = try std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(max_key_file_bytes));
    defer {
        std.crypto.secureZero(u8, raw);
        gpa.free(raw);
    }
    const hex = std.mem.trim(u8, raw, " \t\r\n");
    var key: [hpke.secret_key_len]u8 = undefined;
    if (hex.len != key.len * 2) return error.BadEchKeyFile;
    _ = std.fmt.hexToBytes(&key, hex) catch return error.BadEchKeyFile;
    return key;
}

pub fn run(gpa: Allocator, io: std.Io, opts: Options, out: *Writer) !void {
    _ = gpa;
    const name = opts.public_name orelse return error.Usage;
    const config_out = opts.config_out orelse return error.Usage;
    const key_out = opts.key_out orelse return error.Usage;

    var kp = hpke.KeyPair.generate(io);
    defer kp.wipe();
    const config_id = opts.config_id orelse blk: {
        var b: [1]u8 = undefined;
        io.random(&b);
        break :blk b[0];
    };
    var list_buf: [max_list_len]u8 = undefined;
    const list = try buildConfigList(&list_buf, config_id, &kp.public_key, name, opts.max_name_len);

    var hex_buf: [hpke.secret_key_len * 2 + 1]u8 = undefined;
    defer std.crypto.secureZero(u8, &hex_buf);
    const hex = std.fmt.bytesToHex(kp.secret_key, .lower);
    @memcpy(hex_buf[0..hex.len], &hex);
    hex_buf[hex.len] = '\n';

    // Key first: a config without its key is useless, a stray key is harmless.
    try common.writeKeyFile(io, std.Io.Dir.cwd(), key_out, &hex_buf);
    try common.writePublicFile(io, std.Io.Dir.cwd(), config_out, list);

    var b64_buf: [std.base64.standard.Encoder.calcSize(max_list_len)]u8 = undefined;
    const b64 = std.base64.standard.Encoder.encode(&b64_buf, list);
    try out.print("config_id  : {d}\n", .{config_id});
    try out.print("public_name: {s}\n", .{name});
    try out.writeAll("suite      : DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305\n");
    try out.print("ECHConfigList (base64, DNS HTTPS ech=): {s}\n\n", .{b64});
    try out.print("[[tls.ech_keys]]\nconfig_path = \"{s}\"\nprivate_key = \"@file:{s}\"\n", .{ config_out, key_out });
}

const testing = std.testing;
const builtin = @import("builtin");

test "armorcli ech-gen parseArgs validates public name and outputs" {
    try testing.expectError(error.Usage, parseArgs(&.{}));
    try testing.expectError(error.Usage, parseArgs(&.{ "-public-name", "cover.example", "-config-out", "a" }));
    try testing.expectError(error.Usage, parseArgs(&.{ "-public-name", "10.0.0.1", "-config-out", "a", "-key-out", "b" }));
    try testing.expectError(error.Usage, parseArgs(&.{ "-public-name", "cover.example", "-config-out", "a", "-key-out", "a" }));
    try testing.expectError(error.Usage, parseArgs(&.{ "-public-name", "cover.example", "-config-out", "a", "-key-out", "b", "-config-id", "256" }));
    const o = try parseArgs(&.{ "-public-name", "cover.example", "-config-out", "a", "-key-out", "b", "-config-id", "9" });
    try testing.expectEqual(@as(?u8, 9), o.config_id);
}

test "armorcli ech-gen config list parses with the ECH config codec" {
    const kp = try hpke.KeyPair.generateDeterministic(@as([32]u8, @splat(0x21)));
    var buf: [max_list_len]u8 = undefined;
    const list = try buildConfigList(&buf, 42, &kp.public_key, "cover.example", 0);
    var it = try ech_config.List.init(list);
    const entry = (try it.next()).?;
    try testing.expect((try it.next()) == null);
    const cfg = try ech_config.parse(entry);
    try testing.expectEqual(@as(u8, 42), cfg.config_id);
    try testing.expectEqual(ech_seal.kem_id, cfg.kem_id);
    try testing.expectEqualSlices(u8, &kp.public_key, cfg.public_key);
    try testing.expectEqualStrings("cover.example", cfg.public_name);
    try testing.expect(cfg.supportsSuite(ech_seal.kdf_id, ech_seal.aead_id));
    try testing.expect(!(try cfg.hasUnsupportedMandatoryExtension()));
    try testing.expectError(error.InvalidPublicName, buildConfigList(&buf, 1, &kp.public_key, "bad..name", 0));
}

test "armorcli ech-gen output loads through tls_ech_load and the TLS server" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg_path = try std.fmt.allocPrint(gpa, ".zig-cache/tmp/{s}/ech.bin", .{tmp.sub_path});
    defer gpa.free(cfg_path);
    const key_path = try std.fmt.allocPrint(gpa, ".zig-cache/tmp/{s}/ech.key", .{tmp.sub_path});
    defer gpa.free(key_path);

    var aw = Writer.Allocating.init(gpa);
    defer aw.deinit();
    try run(gpa, io, try parseArgs(&.{ "-public-name", "cover.example", "-config-out", cfg_path, "-key-out", key_path, "-config-id", "7" }), &aw.writer);
    try testing.expect(std.mem.indexOf(u8, aw.written(), "[[tls.ech_keys]]") != null);
    try testing.expect(std.mem.indexOf(u8, aw.written(), "@file:") != null);

    if (builtin.os.tag == .linux) {
        const st = try tmp.dir.statFile(io, "ech.key", .{});
        try testing.expectEqual(@as(std.posix.mode_t, 0), st.permissions.toMode() & 0o077);
    }

    var key = try readKeyFile(gpa, io, key_path);
    defer std.crypto.secureZero(u8, &key);
    const tls_ech_load = onyx_server.daemon.tls_ech_load;
    var loaded = try tls_ech_load.load(gpa, io, &.{.{ .config_path = cfg_path, .private_key = key }});
    defer loaded.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), loaded.keys.len);
    try testing.expectEqualSlices(u8, loaded.configs[0], loaded.retry_config_list);

    // tls_server.Server.init verifies the private key matches the config's
    // public key and that the config carries the suite it opens.
    const tls_server = onyx_server.crypto.tls_server;
    const x509_selfsign = onyx_server.proto.x509_selfsign;
    const Ed25519 = std.crypto.sign.Ed25519;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x22)));
    var cert_buf: [1024]u8 = undefined;
    const der = try x509_selfsign.buildSelfSigned(&cert_buf, .{
        .common_name = "cover.example",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{0x22},
        .key_pair = kp,
        .dns_names = &.{"cover.example"},
        .is_ca = true,
    });
    var server = try tls_server.Server.init(gpa, .{ .cert_chain = &.{der}, .signing_key = kp, .ech_keys = loaded.keys });
    server.deinit();

    // A wrong key is refused by the engine.
    var wrong = loaded.keys[0];
    wrong.private_key[1] ^= 1; // byte 0 low bits are clamped away (RFC 7748 §5)
    try testing.expectError(error.BadEchConfig, tls_server.Server.init(gpa, .{ .cert_chain = &.{der}, .signing_key = kp, .ech_keys = &.{wrong} }));
}
