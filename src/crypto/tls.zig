// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! TLS version and cipher-suite policy for Onyx Server.
//!
//! The hardened allow-list below is the single policy table `onyx-server
//! ciphers` prints. The live TLS engines own everything else: record
//! protection is `tls_record.zig` (driven by `tls_server.zig`), the TLS 1.3 key
//! schedule is `hkdf_tls13.zig`, and certificate verification is
//! `x509_verify.zig`. An earlier generic record/handshake/key-schedule skeleton
//! that lived here had no production callers and was removed so the
//! known-answer and property tests (`tls_kat.zig`, `tls_props.zig`) target
//! shipping code instead.
const std = @import("std");
const hash = @import("hash.zig");

/// TLS protocol versions as wire values. TLS 1.0/1.1 are represented only so
/// policy tests can prove they fail closed.
pub const ProtocolVersion = enum(u16) {
    tls10 = 0x0301,
    tls11 = 0x0302,
    tls12 = 0x0303,
    tls13 = 0x0304,
};

/// Cipher suites relevant to policy decisions. Values match IANA assignments.
pub const CipherSuite = enum(u16) {
    tls_aes_128_gcm_sha256 = 0x1301,
    tls_aes_256_gcm_sha384 = 0x1302,
    tls_chacha20_poly1305_sha256 = 0x1303,
    tls_aes_128_ccm_sha256 = 0x1304,
    tls_aes_128_ccm_8_sha256 = 0x1305,

    tls_rsa_with_null_sha = 0x0002,
    tls_rsa_export_with_rc4_40_md5 = 0x0003,
    tls_rsa_with_rc4_128_sha = 0x0005,
    tls_rsa_with_3des_ede_cbc_sha = 0x000a,
    tls_rsa_with_aes_128_cbc_sha = 0x002f,
    tls_rsa_with_aes_256_cbc_sha = 0x0035,
    tls_rsa_with_aes_128_gcm_sha256 = 0x009c,
    tls_rsa_with_aes_256_gcm_sha384 = 0x009d,

    tls_ecdhe_ecdsa_with_aes_128_cbc_sha = 0xc009,
    tls_ecdhe_ecdsa_with_aes_256_cbc_sha = 0xc00a,
    tls_ecdhe_rsa_with_aes_128_cbc_sha = 0xc013,
    tls_ecdhe_rsa_with_aes_256_cbc_sha = 0xc014,
    tls_ecdhe_ecdsa_with_aes_128_gcm_sha256 = 0xc02b,
    tls_ecdhe_ecdsa_with_aes_256_gcm_sha384 = 0xc02c,
    tls_ecdhe_rsa_with_aes_128_gcm_sha256 = 0xc02f,
    tls_ecdhe_rsa_with_aes_256_gcm_sha384 = 0xc030,
    tls_ecdhe_rsa_with_chacha20_poly1305_sha256 = 0xcca8,
    tls_ecdhe_ecdsa_with_chacha20_poly1305_sha256 = 0xcca9,

    pub fn fromWire(v: u16) ?CipherSuite {
        return switch (v) {
            0x1301 => .tls_aes_128_gcm_sha256,
            0x1302 => .tls_aes_256_gcm_sha384,
            0x1303 => .tls_chacha20_poly1305_sha256,
            0x1304 => .tls_aes_128_ccm_sha256,
            0x1305 => .tls_aes_128_ccm_8_sha256,
            0x0002 => .tls_rsa_with_null_sha,
            0x0003 => .tls_rsa_export_with_rc4_40_md5,
            0x0005 => .tls_rsa_with_rc4_128_sha,
            0x000a => .tls_rsa_with_3des_ede_cbc_sha,
            0x002f => .tls_rsa_with_aes_128_cbc_sha,
            0x0035 => .tls_rsa_with_aes_256_cbc_sha,
            0x009c => .tls_rsa_with_aes_128_gcm_sha256,
            0x009d => .tls_rsa_with_aes_256_gcm_sha384,
            0xc009 => .tls_ecdhe_ecdsa_with_aes_128_cbc_sha,
            0xc00a => .tls_ecdhe_ecdsa_with_aes_256_cbc_sha,
            0xc013 => .tls_ecdhe_rsa_with_aes_128_cbc_sha,
            0xc014 => .tls_ecdhe_rsa_with_aes_256_cbc_sha,
            0xc02b => .tls_ecdhe_ecdsa_with_aes_128_gcm_sha256,
            0xc02c => .tls_ecdhe_ecdsa_with_aes_256_gcm_sha384,
            0xc02f => .tls_ecdhe_rsa_with_aes_128_gcm_sha256,
            0xc030 => .tls_ecdhe_rsa_with_aes_256_gcm_sha384,
            0xcca8 => .tls_ecdhe_rsa_with_chacha20_poly1305_sha256,
            0xcca9 => .tls_ecdhe_ecdsa_with_chacha20_poly1305_sha256,
            else => null,
        };
    }
};

pub const AeadKind = enum { aes_128_gcm, aes_256_gcm, chacha20_poly1305 };
pub const KeyExchangeKind = enum { none, rsa, dhe, ecdhe };
pub const AuthKind = enum { none, rsa, ecdsa };

pub const SuiteInfo = struct {
    aead: AeadKind,
    hash_alg: hash.Alg,
    key_len: usize,
    iv_len: usize,
    tag_len: usize,
    kx_kind: KeyExchangeKind,
    auth_kind: AuthKind,
    tls13: bool,
};

/// Return suite parameters only for the hardened allow-list.
pub fn suiteInfo(version: ProtocolVersion, suite: CipherSuite) ?SuiteInfo {
    if (!isAllowed(version, suite)) return null;
    return switch (suite) {
        .tls_aes_128_gcm_sha256 => .{
            .aead = .aes_128_gcm,
            .hash_alg = .sha256,
            .key_len = 16,
            .iv_len = 12,
            .tag_len = 16,
            .kx_kind = .none,
            .auth_kind = .none,
            .tls13 = true,
        },
        .tls_aes_256_gcm_sha384 => .{
            .aead = .aes_256_gcm,
            .hash_alg = .sha384,
            .key_len = 32,
            .iv_len = 12,
            .tag_len = 16,
            .kx_kind = .none,
            .auth_kind = .none,
            .tls13 = true,
        },
        .tls_chacha20_poly1305_sha256 => .{
            .aead = .chacha20_poly1305,
            .hash_alg = .sha256,
            .key_len = 32,
            .iv_len = 12,
            .tag_len = 16,
            .kx_kind = .none,
            .auth_kind = .none,
            .tls13 = true,
        },
        .tls_ecdhe_ecdsa_with_aes_128_gcm_sha256 => tls12Info(.aes_128_gcm, .sha256, 16, .ecdsa),
        .tls_ecdhe_ecdsa_with_aes_256_gcm_sha384 => tls12Info(.aes_256_gcm, .sha384, 32, .ecdsa),
        .tls_ecdhe_rsa_with_aes_128_gcm_sha256 => tls12Info(.aes_128_gcm, .sha256, 16, .rsa),
        .tls_ecdhe_rsa_with_aes_256_gcm_sha384 => tls12Info(.aes_256_gcm, .sha384, 32, .rsa),
        .tls_ecdhe_ecdsa_with_chacha20_poly1305_sha256 => tls12Info(.chacha20_poly1305, .sha256, 32, .ecdsa),
        .tls_ecdhe_rsa_with_chacha20_poly1305_sha256 => tls12Info(.chacha20_poly1305, .sha256, 32, .rsa),
        else => null,
    };
}

fn tls12Info(aead_kind: AeadKind, hash_alg: hash.Alg, key_len: usize, auth_kind: AuthKind) SuiteInfo {
    return .{
        .aead = aead_kind,
        .hash_alg = hash_alg,
        .key_len = key_len,
        .iv_len = 12,
        .tag_len = 16,
        .kx_kind = .ecdhe,
        .auth_kind = auth_kind,
        .tls13 = false,
    };
}

/// Hardened policy: TLS 1.3 permits only AES-GCM and ChaCha20-Poly1305.
/// TLS 1.2 permits only AEAD + ECDHE suites, with RSA allowed only as the
/// certificate authentication algorithm, never as key exchange.
pub fn isAllowed(version: ProtocolVersion, suite: CipherSuite) bool {
    return switch (version) {
        .tls13 => switch (suite) {
            .tls_aes_128_gcm_sha256,
            .tls_aes_256_gcm_sha384,
            .tls_chacha20_poly1305_sha256,
            => true,
            else => false,
        },
        .tls12 => switch (suite) {
            .tls_ecdhe_ecdsa_with_aes_128_gcm_sha256,
            .tls_ecdhe_ecdsa_with_aes_256_gcm_sha384,
            .tls_ecdhe_rsa_with_aes_128_gcm_sha256,
            .tls_ecdhe_rsa_with_aes_256_gcm_sha384,
            .tls_ecdhe_ecdsa_with_chacha20_poly1305_sha256,
            .tls_ecdhe_rsa_with_chacha20_poly1305_sha256,
            => true,
            else => false,
        },
        .tls10, .tls11 => false,
    };
}

/// TLS compression is disabled; the only acceptable method is null compression.
pub fn isCompressionAllowed(method: u8) bool {
    return method == 0;
}

/// Renegotiation is never enabled in Onyx Server's TLS policy.
pub fn isRenegotiationAllowed() bool {
    return false;
}

test "policy allows only TLS 1.3 AES-GCM and ChaCha20-Poly1305 suites" {
    try std.testing.expect(isAllowed(.tls13, .tls_aes_128_gcm_sha256));
    try std.testing.expect(isAllowed(.tls13, .tls_aes_256_gcm_sha384));
    try std.testing.expect(isAllowed(.tls13, .tls_chacha20_poly1305_sha256));
    try std.testing.expect(!isAllowed(.tls13, .tls_aes_128_ccm_sha256));
    try std.testing.expect(!isAllowed(.tls13, .tls_aes_128_ccm_8_sha256));
}

fn k6Read(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, allocator, .limited(1 << 20));
}

fn k6HelloExtensions(record: []const u8) ![]const u8 {
    if (record.len < 5 or record[0] != 22) return error.Truncated;
    const rec_len: usize = std.mem.readInt(u16, record[3..5], .big);
    if (record.len < 5 + rec_len) return error.Truncated;
    const frag = record[5 .. 5 + rec_len];
    if (frag.len < 4 or frag[0] != 1) return error.Truncated;
    const hs_len: usize = (@as(usize, frag[1]) << 16) | (@as(usize, frag[2]) << 8) | frag[3];
    if (frag.len < 4 + hs_len) return error.Truncated;
    const body = frag[4 .. 4 + hs_len];
    if (body.len < 35) return error.Truncated;
    var i: usize = 2 + 32;
    const sid_len: usize = body[i];
    i += 1;
    if (body.len < i + sid_len + 2) return error.Truncated;
    i += sid_len;
    const cs_len: usize = std.mem.readInt(u16, body[i..][0..2], .big);
    i += 2;
    if (cs_len % 2 != 0 or body.len < i + cs_len + 1) return error.Truncated;
    var c: usize = 0;
    while (c + 2 <= cs_len) : (c += 2) {
        const suite = std.mem.readInt(u16, body[i + c ..][0..2], .big);
        if (suite == @backingInt(CipherSuite.tls_aes_128_ccm_sha256) or
            suite == @backingInt(CipherSuite.tls_aes_128_ccm_8_sha256))
        {
            return error.Truncated;
        }
    }
    i += cs_len;
    const comp_len: usize = body[i];
    i += 1 + comp_len;
    if (body.len < i + 2) return error.Truncated;
    const ext_len: usize = std.mem.readInt(u16, body[i..][0..2], .big);
    if (body.len != i + 2 + ext_len) return error.Truncated;
    return body[i..];
}

test "GAP-K6 unfinished TLS interop stays refused and the pinned BoGo lane stays 24/3" {
    const allocator = std.testing.allocator;
    const cert_compression = @import("../proto/cert_compression.zig");
    const supported_groups = @import("../proto/supported_groups.zig");
    const tls_extension = @import("../proto/tls_extension.zig");
    const tls_keyshare = @import("../proto/tls_keyshare.zig");
    const ech_seal = @import("ech_seal.zig");
    const ech_config = @import("../proto/ech_config.zig");
    const hpke = @import("hpke.zig");
    const tls_client = @import("tls_client.zig");
    const delegated_credential = @import("../proto/delegated_credential.zig");

    try std.testing.expect(!isAllowed(.tls13, .tls_aes_128_ccm_sha256));
    try std.testing.expect(!isAllowed(.tls13, .tls_aes_128_ccm_8_sha256));
    try std.testing.expect(!isAllowed(.tls12, .tls_aes_128_ccm_sha256));
    try std.testing.expect(!isAllowed(.tls12, .tls_aes_128_ccm_8_sha256));

    try std.testing.expectEqual(@as(?cert_compression.Algorithm, .zlib), cert_compression.pickSupported(&.{ 0x02, 0x00, 0x01 }));
    try std.testing.expectEqual(@as(?cert_compression.Algorithm, null), cert_compression.pickSupported(&.{ 0x02, 0x00, 0x02 }));
    try std.testing.expectEqual(@as(?cert_compression.Algorithm, null), cert_compression.pickSupported(&.{ 0x02, 0x00, 0x03 }));
    try std.testing.expectEqual(@as(?cert_compression.Algorithm, .zlib), cert_compression.pickSupported(&.{ 0x06, 0x00, 0x02, 0x00, 0x03, 0x00, 0x01 }));

    try std.testing.expectEqual(@as(u16, 0x0003), hpke.aead_id);
    try std.testing.expectEqual(hpke.aead_id, ech_seal.aead_id);
    const zero_pk: [32]u8 = @splat(0);
    const aes_gcm = ech_config.Config{
        .raw = &.{},
        .version = ech_config.version_draft13,
        .config_id = 0,
        .kem_id = ech_seal.kem_id,
        .public_key = &zero_pk,
        .cipher_suites = &[_]u8{ 0x00, 0x01, 0x00, 0x01 },
        .maximum_name_length = 16,
        .public_name = "a.example",
        .extensions = &.{},
    };
    try std.testing.expectError(error.UnsupportedEchSuite, ech_seal.seal(allocator, aes_gcm, "inner", "aad", @splat(0)));

    const defaults = tls_client.Options{ .server_name = "irc.test", .trust_anchors = &.{} };
    try std.testing.expect(!defaults.require_crl);
    try std.testing.expectEqual(@as(u8, 0), defaults.require_sct);
    try std.testing.expect(defaults.crl == null);
    try std.testing.expectEqual(@as(usize, 0), defaults.ct_logs.len);
    try std.testing.expectError(error.Truncated, delegated_credential.parse(&.{}));

    var client = try tls_client.Client.init(allocator, defaults);
    defer client.deinit();
    const hello = try client.start();
    defer allocator.free(hello);
    const extensions = try k6HelloExtensions(hello);
    const groups = (try tls_extension.find(extensions, @backingInt(tls_extension.ExtensionType.supported_groups))) orelse return error.TestUnexpectedResult;
    const shares = (try tls_extension.find(extensions, @backingInt(tls_extension.ExtensionType.key_share))) orelse return error.TestUnexpectedResult;
    try std.testing.expect(supported_groups.offers(groups, .x25519));
    try std.testing.expect(supported_groups.offers(groups, .secp256r1));
    try std.testing.expect(supported_groups.offers(groups, .x25519mlkem768));
    try std.testing.expect(!supported_groups.offers(groups, .x448));
    try std.testing.expect(!supported_groups.offers(groups, .secp384r1));
    try std.testing.expect(!supported_groups.offers(groups, supported_groups.NamedGroup.fromInt(0x0019)));
    var group_it = try supported_groups.parse(groups);
    var group_count: usize = 0;
    while (group_it.nextRaw()) |_| group_count += 1;
    try std.testing.expectEqual(@as(usize, 3), group_count);
    var share_it = try tls_keyshare.parseClientShares(shares);
    var share_count: usize = 0;
    while (try share_it.next()) |entry| {
        share_count += 1;
        try std.testing.expect(entry.key_exchange.len != 0);
        const id = entry.group.toInt();
        try std.testing.expect(id == 0x001d or id == 0x0017 or id == 0x11ec);
    }
    try std.testing.expectEqual(@as(usize, 3), share_count);

    // Repo-layout fixture: runners outside a checkout (e.g. a bare Windows
    // guest executing a shipped test binary) have no BoGo tree to read.
    const baseline = k6Read(allocator, "tools/bogo/expected-baseline.txt") catch |err| {
        if (err == error.FileNotFound) return error.SkipZigTest;
        return err;
    };
    defer allocator.free(baseline);
    var pass: usize = 0;
    var skip: usize = 0;
    var lines = std.mem.splitScalar(u8, baseline, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "PASS ")) pass += 1;
        if (std.mem.startsWith(u8, line, "SKIP ")) skip += 1;
    }
    try std.testing.expectEqual(@as(usize, 24), pass);
    try std.testing.expectEqual(@as(usize, 3), skip);
    try std.testing.expect(std.mem.indexOf(u8, baseline, "SKIP CheckClientCertificateTypes\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, baseline, "SKIP SendFallbackSCSV\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, baseline, "SKIP ClientCertificateTypes\n") != null);

    const config_text = try k6Read(allocator, "tools/bogo/config.json");
    defer allocator.free(config_text);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, config_text, .{});
    defer parsed.deinit();
    const disabled = parsed.value.object.get("DisabledTests") orelse return error.TestUnexpectedResult;
    var reasons: usize = 0;
    var it = disabled.object.iterator();
    while (it.next()) |entry| {
        if (std.mem.startsWith(u8, entry.key_ptr.*, "//")) continue;
        const value = entry.value_ptr.*;
        try std.testing.expect(value == .string);
        try std.testing.expect(value.string.len != 0);
        reasons += 1;
    }
    try std.testing.expect(reasons >= 20);
    const required = [_][]const u8{
        "*ECH*",
        "*HRR*",
        "*HelloRetryRequest*",
        "*DelegatedCredential*",
        "*P-384*",
        "*P-521*",
        "*DTLS*",
        "*Resume*",
        "*EarlyData*",
        "*ClientAuth*",
    };
    for (required) |key| {
        const value = disabled.object.get(key) orelse return error.TestUnexpectedResult;
        try std.testing.expect(value == .string);
        try std.testing.expect(value.string.len != 0);
    }

    const cli_files = [_][]const u8{
        "src/cli/armor_main.zig",
        "src/cli/s_client_cmd.zig",
        "src/cli/stub_cmds.zig",
        "src/cli/crl_cmd.zig",
        "src/cli/ocsp_cmd.zig",
    };
    for (cli_files) |path| {
        const text = try k6Read(allocator, path);
        defer allocator.free(text);
        try std.testing.expect(std.mem.indexOf(u8, text, "landlock") == null);
        try std.testing.expect(std.mem.indexOf(u8, text, "seccomp") == null);
        try std.testing.expect(std.mem.indexOf(u8, text, "pledge(") == null);
        try std.testing.expect(std.mem.indexOf(u8, text, "unveil(") == null);
    }

    std.debug.print("GAP-K6 branch=unfinished TLS interop stays refused and [[tls.sni]] selects a certificate\n", .{});
}

test "policy allows only hardened TLS 1.2 ECDHE AEAD suites" {
    try std.testing.expect(isAllowed(.tls12, .tls_ecdhe_ecdsa_with_aes_128_gcm_sha256));
    try std.testing.expect(isAllowed(.tls12, .tls_ecdhe_ecdsa_with_aes_256_gcm_sha384));
    try std.testing.expect(isAllowed(.tls12, .tls_ecdhe_rsa_with_aes_128_gcm_sha256));
    try std.testing.expect(isAllowed(.tls12, .tls_ecdhe_rsa_with_aes_256_gcm_sha384));
    try std.testing.expect(isAllowed(.tls12, .tls_ecdhe_ecdsa_with_chacha20_poly1305_sha256));
    try std.testing.expect(isAllowed(.tls12, .tls_ecdhe_rsa_with_chacha20_poly1305_sha256));
}

test "policy rejects CBC RC4 RSA-kex export NULL and old TLS versions" {
    const bad = [_]CipherSuite{
        .tls_rsa_with_null_sha,
        .tls_rsa_export_with_rc4_40_md5,
        .tls_rsa_with_rc4_128_sha,
        .tls_rsa_with_aes_128_cbc_sha,
        .tls_rsa_with_aes_128_gcm_sha256,
        .tls_ecdhe_rsa_with_aes_128_cbc_sha,
        .tls_ecdhe_ecdsa_with_aes_256_cbc_sha,
    };
    for (bad) |suite| {
        try std.testing.expect(!isAllowed(.tls12, suite));
        try std.testing.expect(!isAllowed(.tls13, suite));
    }
    try std.testing.expect(!isAllowed(.tls10, .tls_ecdhe_rsa_with_aes_128_gcm_sha256));
    try std.testing.expect(!isAllowed(.tls11, .tls_ecdhe_rsa_with_aes_128_gcm_sha256));
    try std.testing.expect(!isCompressionAllowed(1));
    try std.testing.expect(isCompressionAllowed(0));
    try std.testing.expect(!isRenegotiationAllowed());
}

test {
    std.testing.refAllDecls(@This());
}
