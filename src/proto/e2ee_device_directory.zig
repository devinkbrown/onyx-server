// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Onyx device directory record (ODD1) for `onyx-ogc1-v1` E2EEKEY material.
//!
//! The daemon stores only public directory bytes. It never parses OGC1 control
//! payloads, never verifies client signatures, and never holds wrap secrets.
const std = @import("std");

const Ed25519 = std.crypto.sign.Ed25519;
const P256 = std.crypto.ecc.P256;
const Sha256 = std.crypto.hash.sha2.Sha256;
const b64 = std.base64.url_safe_no_pad;

pub const stored_algorithm = "onyx-ogc1-v1";
pub const magic = "ODD1";
pub const suite: u8 = 0x01;
pub const signer_len: usize = 32;
pub const wrap_len: usize = 65;
pub const binary_len: usize = magic.len + 1 + signer_len + wrap_len;
pub const encoded_len: usize = 136;
pub const device_id_prefix = "ogc1-";
pub const device_id_hash_chars: usize = 22;
pub const device_id_len: usize = device_id_prefix.len + device_id_hash_chars;
pub const device_id_domain = "ONYX-OGC1-DEVICE-ID-v1";

/// Cross-language KAT: Ed25519 public key from seed `0x5a` × 32 via Zig's
/// `KeyPair.generateDeterministic`, plus the uncompressed P-256 generator.
pub const kat_seed: [Ed25519.KeyPair.seed_length]u8 = @splat(0x5a);
pub const kat_signer: [signer_len]u8 = .{
    0x0d, 0x75, 0x50, 0x75, 0x4e, 0x08, 0x00, 0xa5, 0xd2, 0x37, 0xee, 0xf5, 0x82, 0x60, 0x35, 0x76,
    0x6b, 0x9b, 0x3e, 0x5a, 0x15, 0x86, 0x8a, 0x94, 0x0a, 0xb2, 0x89, 0x95, 0x87, 0x88, 0xe3, 0xb0,
};
pub const kat_wrap: [wrap_len]u8 = .{
    0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
    0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2,
    0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e,
    0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51,
    0xf5,
};
pub const kat_wire: *const [encoded_len]u8 = "T0REMQENdVB1TggApdI37vWCYDV2a5s-WhWGipQKsomVh4jjsARrF9Hy4SxCR_i85uVjpEDydwN9gS3rM6D0oTlF2JjClk_jQuL-Gn-bjufrSnwPnhYrzjNXazFezsu2QGg3v1H1";
pub const kat_device_id: *const [device_id_len]u8 = "ogc1-MPEyCFzdqv8BZ2wUbf_uKD";

const wrap_uncompressed_prefix: u8 = 0x04;
const magic_off: usize = 0;
const suite_off: usize = magic.len;
const signer_off: usize = suite_off + 1;
const wrap_off: usize = signer_off + signer_len;

comptime {
    if (binary_len != 102) @compileError("ODD1 binary length must stay 102 bytes");
    if (b64.Encoder.calcSize(binary_len) != encoded_len)
        @compileError("ODD1 canonical encoding must stay 136 unpadded base64url chars");
    if (b64.Encoder.calcSize(Sha256.digest_length) < device_id_hash_chars)
        @compileError("device-id hash encoding is shorter than the advertised prefix");
}

pub fn isStoredAlgorithm(algorithm: []const u8) bool {
    return std.mem.eql(u8, algorithm, stored_algorithm);
}

pub fn parseBinary(bytes: []const u8) ?[binary_len]u8 {
    if (bytes.len != binary_len) return null;
    if (!std.mem.eql(u8, bytes[magic_off..][0..magic.len], magic)) return null;
    if (bytes[suite_off] != suite) return null;

    var signer: [signer_len]u8 = undefined;
    @memcpy(&signer, bytes[signer_off..][0..signer_len]);
    var signer_nonzero: u8 = 0;
    for (signer) |byte| signer_nonzero |= byte;
    if (signer_nonzero == 0) return null;
    _ = Ed25519.PublicKey.fromBytes(signer) catch return null;

    var wrap: [wrap_len]u8 = undefined;
    @memcpy(&wrap, bytes[wrap_off..][0..wrap_len]);
    if (wrap[0] != wrap_uncompressed_prefix) return null;
    const point = P256.fromSec1(&wrap) catch return null;
    point.rejectIdentity() catch return null;

    var out: [binary_len]u8 = undefined;
    @memcpy(&out, bytes);
    return out;
}

pub fn fromParts(signer: [signer_len]u8, wrap: [wrap_len]u8) ?[binary_len]u8 {
    var bytes: [binary_len]u8 = undefined;
    @memcpy(bytes[magic_off..][0..magic.len], magic);
    bytes[suite_off] = suite;
    @memcpy(bytes[signer_off..][0..signer_len], &signer);
    @memcpy(bytes[wrap_off..][0..wrap_len], &wrap);
    return parseBinary(&bytes);
}

pub fn encodeCanonical(odd1: [binary_len]u8, out: *[encoded_len]u8) []const u8 {
    return b64.Encoder.encode(out, &odd1);
}

pub fn parseCanonical(text: []const u8) ?[binary_len]u8 {
    if (text.len != encoded_len) return null;
    var decoded: [binary_len]u8 = undefined;
    b64.Decoder.decode(&decoded, text) catch return null;
    var canonical: [encoded_len]u8 = undefined;
    const encoded = encodeCanonical(decoded, &canonical);
    if (!std.mem.eql(u8, text, encoded)) return null;
    return parseBinary(&decoded);
}

pub fn deviceId(odd1: [binary_len]u8, out: *[device_id_len]u8) []const u8 {
    var msg: [device_id_domain.len + 1 + binary_len]u8 = undefined;
    @memcpy(msg[0..device_id_domain.len], device_id_domain);
    msg[device_id_domain.len] = 0;
    @memcpy(msg[device_id_domain.len + 1 ..], &odd1);

    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(&msg, &digest, .{});

    var encoded: [b64.Encoder.calcSize(Sha256.digest_length)]u8 = undefined;
    const hashed = b64.Encoder.encode(&encoded, &digest);
    @memcpy(out[0..device_id_prefix.len], device_id_prefix);
    @memcpy(out[device_id_prefix.len..], hashed[0..device_id_hash_chars]);
    return out;
}

pub fn matchesDeviceId(odd1: [binary_len]u8, device_id: []const u8) bool {
    var id_buf: [device_id_len]u8 = undefined;
    return std.mem.eql(u8, device_id, deviceId(odd1, &id_buf));
}

fn testSigner() [signer_len]u8 {
    const kp = Ed25519.KeyPair.generateDeterministic(kat_seed) catch unreachable;
    return kp.public_key.toBytes();
}

fn testWrap() [wrap_len]u8 {
    return P256.basePoint.toUncompressedSec1();
}

fn testOdd1() [binary_len]u8 {
    return fromParts(testSigner(), testWrap()).?;
}

test "ODD1 cross-language KAT pins exact canonical wire and device id" {
    try std.testing.expectEqualSlices(u8, &kat_signer, &testSigner());
    try std.testing.expectEqualSlices(u8, &kat_wrap, &testWrap());
    _ = Ed25519.PublicKey.fromBytes(kat_signer) catch return error.TestUnexpectedResult;
    const point = P256.fromSec1(&kat_wrap) catch return error.TestUnexpectedResult;
    try point.rejectIdentity();

    const odd1 = fromParts(kat_signer, kat_wrap) orelse return error.TestUnexpectedResult;
    var encoded: [encoded_len]u8 = undefined;
    try std.testing.expectEqualStrings(kat_wire, encodeCanonical(odd1, &encoded));
    try std.testing.expectEqual(@as(usize, 136), kat_wire.len);
    try std.testing.expect(std.mem.indexOfScalar(u8, kat_wire, '=') == null);

    var id_buf: [device_id_len]u8 = undefined;
    try std.testing.expectEqualStrings(kat_device_id, deviceId(odd1, &id_buf));
    try std.testing.expectEqualStrings(kat_device_id, "ogc1-MPEyCFzdqv8BZ2wUbf_uKD");
    try std.testing.expect(matchesDeviceId(odd1, kat_device_id));
    const parsed = parseCanonical(kat_wire) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, &odd1, &parsed);
}

test "ODD1 binary is magic suite Ed25519 signer and uncompressed P-256 wrap" {
    const odd1 = testOdd1();
    try std.testing.expectEqual(@as(usize, 102), odd1.len);
    try std.testing.expectEqualStrings(magic, odd1[0..4]);
    try std.testing.expectEqual(suite, odd1[4]);
    try std.testing.expectEqual(wrap_uncompressed_prefix, odd1[wrap_off]);
    try std.testing.expectEqualSlices(u8, &testSigner(), odd1[signer_off..][0..signer_len]);
    try std.testing.expectEqualSlices(u8, &testWrap(), odd1[wrap_off..][0..wrap_len]);
    try std.testing.expect(parseBinary(&odd1) != null);
}

test "ODD1 canonical encoding is exactly 136 unpadded base64url chars" {
    const odd1 = testOdd1();
    var encoded: [encoded_len]u8 = undefined;
    const text = encodeCanonical(odd1, &encoded);
    try std.testing.expectEqual(@as(usize, 136), text.len);
    try std.testing.expect(std.mem.indexOfScalar(u8, text, '=') == null);
    try std.testing.expect(std.mem.indexOfScalar(u8, text, '+') == null);
    try std.testing.expect(std.mem.indexOfScalar(u8, text, '/') == null);
    const parsed = parseCanonical(text) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, &odd1, &parsed);
}

test "ODD1 device id is ogc1- plus first 22 base64url SHA-256 chars" {
    const odd1 = testOdd1();
    var id_buf: [device_id_len]u8 = undefined;
    const id = deviceId(odd1, &id_buf);
    try std.testing.expectEqual(@as(usize, 27), id.len);
    try std.testing.expect(std.mem.startsWith(u8, id, device_id_prefix));
    try std.testing.expect(matchesDeviceId(odd1, id));

    var msg: [device_id_domain.len + 1 + binary_len]u8 = undefined;
    @memcpy(msg[0..device_id_domain.len], device_id_domain);
    msg[device_id_domain.len] = 0;
    @memcpy(msg[device_id_domain.len + 1 ..], &odd1);
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(&msg, &digest, .{});
    var hashed: [b64.Encoder.calcSize(Sha256.digest_length)]u8 = undefined;
    const encoded = b64.Encoder.encode(&hashed, &digest);
    try std.testing.expectEqualStrings(encoded[0..device_id_hash_chars], id[device_id_prefix.len..]);

    const other_wrap = P256.basePoint.dbl().toUncompressedSec1();
    const other = fromParts(testSigner(), other_wrap).?;
    try std.testing.expect(!matchesDeviceId(other, id));
}

test "ODD1 rejects wrong magic suite compressed wrap and noncanonical text" {
    var bad_magic = testOdd1();
    bad_magic[3] = '2';
    try std.testing.expect(parseBinary(&bad_magic) == null);

    var bad_suite = testOdd1();
    bad_suite[suite_off] = 0x00;
    try std.testing.expect(parseBinary(&bad_suite) == null);

    var zero_signer = testOdd1();
    @memset(zero_signer[signer_off..][0..signer_len], 0);
    try std.testing.expect(parseBinary(&zero_signer) == null);

    var compressed = testOdd1();
    compressed[wrap_off] = 0x02;
    try std.testing.expect(parseBinary(&compressed) == null);

    var identity = testOdd1();
    @memset(identity[wrap_off..], 0);
    identity[wrap_off] = wrap_uncompressed_prefix;
    try std.testing.expect(parseBinary(&identity) == null);

    var off_curve = testOdd1();
    off_curve[binary_len - 1] ^= 0x01;
    try std.testing.expect(parseBinary(&off_curve) == null);

    const odd1 = testOdd1();
    var encoded: [encoded_len]u8 = undefined;
    const text = encodeCanonical(odd1, &encoded);
    try std.testing.expect(parseCanonical(text[0 .. text.len - 1]) == null);

    var padded: [encoded_len + 1]u8 = undefined;
    @memcpy(padded[0..encoded_len], text);
    padded[encoded_len] = '=';
    try std.testing.expect(parseCanonical(padded[0..]) == null);

    try std.testing.expect(!isStoredAlgorithm("mls-x25519"));
    try std.testing.expect(isStoredAlgorithm(stored_algorithm));
}
