// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

const Allocator = std.mem.Allocator;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;

const key_label_prefix = "SFrame 1.0 Secret key ";
const salt_label_prefix = "SFrame 1.0 Secret salt ";

pub const max_header_len = 17;
pub const nonce_length = 12;

pub const CipherSuite = enum(u16) {
    aes_128_gcm_sha256_128 = 0x0004,
    chacha20_poly1305_sha256_128 = 0xf001,
};

pub const EncodedHeader = struct {
    bytes: [max_header_len]u8 = undefined,
    len: usize = 0,

    pub fn slice(self: *const EncodedHeader) []const u8 {
        return self.bytes[0..self.len];
    }
};

pub const ParsedHeader = struct {
    kid: u64,
    ctr: u64,
    header_len: usize,
};

pub const KeySalt = struct {
    key: [32]u8,
    key_len: usize,
    salt: [nonce_length]u8,

    pub fn keySlice(self: *const KeySalt) []const u8 {
        return self.key[0..self.key_len];
    }
};

pub fn encodeHeader(kid: u64, ctr: u64) EncodedHeader {
    var header: EncodedHeader = .{};
    var config: u8 = 0;

    if (kid < 8) {
        config |= @as(u8, @intCast(kid)) << 4;
    } else {
        const kid_len = intByteLen(kid);
        config |= 0x80 | (@as(u8, @intCast(kid_len - 1)) << 4);
    }

    if (ctr < 8) {
        config |= @as(u8, @intCast(ctr));
    } else {
        const ctr_len = intByteLen(ctr);
        config |= 0x08 | @as(u8, @intCast(ctr_len - 1));
    }

    header.bytes[0] = config;
    header.len = 1;

    if (kid >= 8) {
        const kid_len = intByteLen(kid);
        writeCompactInt(header.bytes[header.len..][0..kid_len], kid);
        header.len += kid_len;
    }

    if (ctr >= 8) {
        const ctr_len = intByteLen(ctr);
        writeCompactInt(header.bytes[header.len..][0..ctr_len], ctr);
        header.len += ctr_len;
    }

    return header;
}

pub fn decodeHeader(sframe: []const u8) !ParsedHeader {
    if (sframe.len == 0) return error.TruncatedHeader;

    const config = sframe[0];
    var off: usize = 1;

    const kid = if ((config & 0x80) == 0)
        @as(u64, (config >> 4) & 0x07)
    else kid: {
        const len = @as(usize, (config >> 4) & 0x07) + 1;
        if (sframe.len - off < len) return error.TruncatedHeader;
        const value = readCompactInt(sframe[off..][0..len]);
        if (value < 8 or intByteLen(value) != len) return error.NonCanonicalHeader;
        off += len;
        break :kid value;
    };

    const ctr = if ((config & 0x08) == 0)
        @as(u64, config & 0x07)
    else ctr: {
        const len = @as(usize, config & 0x07) + 1;
        if (sframe.len - off < len) return error.TruncatedHeader;
        const value = readCompactInt(sframe[off..][0..len]);
        if (value < 8 or intByteLen(value) != len) return error.NonCanonicalHeader;
        off += len;
        break :ctr value;
    };

    return .{ .kid = kid, .ctr = ctr, .header_len = off };
}

pub fn deriveKeySalt(suite: CipherSuite, kid: u64, base_key: []const u8) KeySalt {
    return switch (suite) {
        .aes_128_gcm_sha256_128 => deriveKeySaltWith(Aes128Gcm, suite, kid, base_key),
        .chacha20_poly1305_sha256_128 => deriveKeySaltWith(ChaCha20Poly1305, suite, kid, base_key),
    };
}

pub fn nonceFor(suite: CipherSuite, kid: u64, ctr: u64, base_key: []const u8) [nonce_length]u8 {
    const key_salt = deriveKeySalt(suite, kid, base_key);
    return nonceFromSalt(key_salt.salt, ctr);
}

pub fn encryptAlloc(
    allocator: Allocator,
    suite: CipherSuite,
    kid: u64,
    ctr: u64,
    base_key: []const u8,
    metadata: []const u8,
    plaintext: []const u8,
) ![]u8 {
    return switch (suite) {
        .aes_128_gcm_sha256_128 => encryptWith(Aes128Gcm, allocator, suite, kid, ctr, base_key, metadata, plaintext),
        .chacha20_poly1305_sha256_128 => encryptWith(ChaCha20Poly1305, allocator, suite, kid, ctr, base_key, metadata, plaintext),
    };
}

pub fn decryptAlloc(
    allocator: Allocator,
    suite: CipherSuite,
    sframe: []const u8,
    base_key: []const u8,
    metadata: []const u8,
) ![]u8 {
    return switch (suite) {
        .aes_128_gcm_sha256_128 => decryptWith(Aes128Gcm, allocator, suite, sframe, base_key, metadata),
        .chacha20_poly1305_sha256_128 => decryptWith(ChaCha20Poly1305, allocator, suite, sframe, base_key, metadata),
    };
}

fn encryptWith(
    comptime Aead: type,
    allocator: Allocator,
    suite: CipherSuite,
    kid: u64,
    ctr: u64,
    base_key: []const u8,
    metadata: []const u8,
    plaintext: []const u8,
) ![]u8 {
    const header = encodeHeader(kid, ctr);
    const aad = try joinAad(allocator, header.slice(), metadata);
    defer allocator.free(aad);

    const key_salt = deriveKeySaltWith(Aead, suite, kid, base_key);
    const nonce = nonceFromSalt(key_salt.salt, ctr);

    var out = try allocator.alloc(u8, header.len + plaintext.len + Aead.tag_length);
    errdefer allocator.free(out);

    @memcpy(out[0..header.len], header.slice());
    const ciphertext = out[header.len..][0..plaintext.len];
    const tag_out = out[header.len + plaintext.len ..][0..Aead.tag_length];
    var tag: [Aead.tag_length]u8 = undefined;
    Aead.encrypt(ciphertext, &tag, plaintext, aad, nonce, keyFor(Aead, key_salt));
    @memcpy(tag_out, tag[0..]);

    return out;
}

fn decryptWith(
    comptime Aead: type,
    allocator: Allocator,
    suite: CipherSuite,
    sframe: []const u8,
    base_key: []const u8,
    metadata: []const u8,
) ![]u8 {
    const parsed = try decodeHeader(sframe);
    if (sframe.len < parsed.header_len + Aead.tag_length) return error.CiphertextTooShort;

    const header = sframe[0..parsed.header_len];
    const body = sframe[parsed.header_len..];
    const ciphertext = body[0 .. body.len - Aead.tag_length];
    const tag_slice = body[body.len - Aead.tag_length ..];

    const aad = try joinAad(allocator, header, metadata);
    defer allocator.free(aad);

    const key_salt = deriveKeySaltWith(Aead, suite, parsed.kid, base_key);
    const nonce = nonceFromSalt(key_salt.salt, parsed.ctr);

    const plaintext = try allocator.alloc(u8, ciphertext.len);
    errdefer allocator.free(plaintext);

    var tag: [Aead.tag_length]u8 = undefined;
    @memcpy(tag[0..], tag_slice);
    try Aead.decrypt(plaintext, ciphertext, tag, aad, nonce, keyFor(Aead, key_salt));

    return plaintext;
}

fn deriveKeySaltWith(comptime Aead: type, suite: CipherSuite, kid: u64, base_key: []const u8) KeySalt {
    const secret = HkdfSha256.extract("", base_key);

    var out: KeySalt = .{
        .key = @as([32]u8, @splat(0)),
        .key_len = Aead.key_length,
        .salt = undefined,
    };

    var key_label: [key_label_prefix.len + 8 + 2]u8 = undefined;
    var salt_label: [salt_label_prefix.len + 8 + 2]u8 = undefined;
    buildLabel(key_label[0..], key_label_prefix, kid, @backingInt(suite));
    buildLabel(salt_label[0..], salt_label_prefix, kid, @backingInt(suite));

    HkdfSha256.expand(out.key[0..Aead.key_length], key_label[0..], secret);
    HkdfSha256.expand(out.salt[0..], salt_label[0..], secret);
    return out;
}

fn keyFor(comptime Aead: type, key_salt: KeySalt) [Aead.key_length]u8 {
    var key: [Aead.key_length]u8 = undefined;
    @memcpy(key[0..], key_salt.key[0..Aead.key_length]);
    return key;
}

fn buildLabel(out: []u8, comptime prefix: []const u8, kid: u64, suite_id: u16) void {
    std.debug.assert(out.len == prefix.len + 10);
    @memcpy(out[0..prefix.len], prefix);
    std.mem.writeInt(u64, out[prefix.len..][0..8], kid, .big);
    std.mem.writeInt(u16, out[prefix.len + 8 ..][0..2], suite_id, .big);
}

fn nonceFromSalt(salt: [nonce_length]u8, ctr: u64) [nonce_length]u8 {
    var ctr_bytes = @as([nonce_length]u8, @splat(0));
    std.mem.writeInt(u64, ctr_bytes[nonce_length - 8 ..][0..8], ctr, .big);

    var nonce = salt;
    for (&nonce, ctr_bytes) |*n, c| {
        n.* ^= c;
    }
    return nonce;
}

fn joinAad(allocator: Allocator, header: []const u8, metadata: []const u8) ![]u8 {
    var aad = try allocator.alloc(u8, header.len + metadata.len);
    @memcpy(aad[0..header.len], header);
    @memcpy(aad[header.len..], metadata);
    return aad;
}

fn intByteLen(value: u64) usize {
    var n: usize = 1;
    var v = value;
    while (v > 0xff) : (v >>= 8) {
        n += 1;
    }
    return n;
}

fn writeCompactInt(out: []u8, value: u64) void {
    std.debug.assert(out.len >= 1 and out.len <= 8);
    for (out, 0..) |*b, i| {
        const shift: u6 = @intCast((out.len - 1 - i) * 8);
        b.* = @intCast((value >> shift) & 0xff);
    }
}

fn readCompactInt(bytes: []const u8) u64 {
    std.debug.assert(bytes.len >= 1 and bytes.len <= 8);
    var value: u64 = 0;
    for (bytes) |b| {
        value = (value << 8) | b;
    }
    return value;
}

fn expectHeader(kid: u64, ctr: u64, expected_hex: []const u8) !void {
    var expected: [max_header_len]u8 = undefined;
    const expected_bytes = try hexToBytes(expected[0..], expected_hex);

    const encoded = encodeHeader(kid, ctr);
    try std.testing.expectEqualSlices(u8, expected_bytes, encoded.slice());

    const parsed = try decodeHeader(encoded.slice());
    try std.testing.expectEqual(kid, parsed.kid);
    try std.testing.expectEqual(ctr, parsed.ctr);
    try std.testing.expectEqual(encoded.len, parsed.header_len);
}

fn hexToBytes(out: []u8, hex: []const u8) ![]u8 {
    if (hex.len % 2 != 0) return error.InvalidHex;
    if (out.len < hex.len / 2) return error.NoSpaceLeft;

    var i: usize = 0;
    while (i < hex.len) : (i += 2) {
        out[i / 2] = (try hexNibble(hex[i]) << 4) | try hexNibble(hex[i + 1]);
    }
    return out[0 .. hex.len / 2];
}

fn hexNibble(c: u8) !u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => error.InvalidHex,
    };
}

test "header KID and CTR varint round-trip including multi-byte RFC cases" {
    try expectHeader(0, 0, "00");
    try expectHeader(0, 1, "01");
    try expectHeader(0, 7, "07");
    try expectHeader(0, 8, "0808");
    try expectHeader(0, 0xff, "08ff");
    try expectHeader(0, 0x0100, "090100");
    try expectHeader(0, 0xffff, "09ffff");
    try expectHeader(0, 0x010000, "0a010000");
    try expectHeader(0, 0xffffffff, "0bffffffff");
    try expectHeader(0, 0x0100000000, "0c0100000000");
    try expectHeader(0x0123, 0x4567, "9901234567");
    try expectHeader(0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff, "ff" ++ "ffffffffffffffff" ++ "ffffffffffffffff");
}

test "header decoder rejects truncated and non-canonical encodings" {
    try std.testing.expectError(error.TruncatedHeader, decodeHeader(""));
    try std.testing.expectError(error.TruncatedHeader, decodeHeader(&[_]u8{0x08}));
    try std.testing.expectError(error.TruncatedHeader, decodeHeader(&[_]u8{0x80}));
    try std.testing.expectError(error.NonCanonicalHeader, decodeHeader(&[_]u8{ 0x08, 0x07 }));
    try std.testing.expectError(error.NonCanonicalHeader, decodeHeader(&[_]u8{ 0x09, 0x00, 0x08 }));
    try std.testing.expectError(error.NonCanonicalHeader, decodeHeader(&[_]u8{ 0x80, 0x00 }));
}

test "encrypt decrypt round-trip with AES-GCM and ChaCha20-Poly1305" {
    const allocator = std.testing.allocator;
    const base_key = "media sender base key";
    const metadata = "rtp-ext:audio";
    const plaintext = "encoded media frame bytes";

    inline for (.{ CipherSuite.aes_128_gcm_sha256_128, CipherSuite.chacha20_poly1305_sha256_128 }) |suite| {
        const encrypted = try encryptAlloc(allocator, suite, 12, 34, base_key, metadata, plaintext);
        defer allocator.free(encrypted);

        const parsed = try decodeHeader(encrypted);
        try std.testing.expectEqual(@as(u64, 12), parsed.kid);
        try std.testing.expectEqual(@as(u64, 34), parsed.ctr);

        const decrypted = try decryptAlloc(allocator, suite, encrypted, base_key, metadata);
        defer allocator.free(decrypted);
        try std.testing.expectEqualSlices(u8, plaintext, decrypted);
    }
}

test "AES-GCM output matches RFC 9605 test vector" {
    const allocator = std.testing.allocator;
    const suite = CipherSuite.aes_128_gcm_sha256_128;
    const kid: u64 = 0x0123;
    const ctr: u64 = 0x4567;

    var base_key_buf: [16]u8 = undefined;
    const base_key = try hexToBytes(base_key_buf[0..], "000102030405060708090a0b0c0d0e0f");
    var metadata_buf: [14]u8 = undefined;
    const metadata = try hexToBytes(metadata_buf[0..], "4945544620534672616d65205747");
    var plaintext_buf: [21]u8 = undefined;
    const plaintext = try hexToBytes(plaintext_buf[0..], "64726166742d696574662d736672616d652d656e63");
    var expected_buf: [42]u8 = undefined;
    const expected = try hexToBytes(expected_buf[0..], "9901234567b7412c2513a1b66dbb48841bbaf17f598751176ad847681a69c6d0b091c07018ce4adb34eb");

    const key_salt = deriveKeySalt(suite, kid, base_key);
    var expected_key_buf: [16]u8 = undefined;
    const expected_key = try hexToBytes(expected_key_buf[0..], "d34f547f4ca4f9a7447006fe7fcbf768");
    var expected_salt_buf: [12]u8 = undefined;
    const expected_salt = try hexToBytes(expected_salt_buf[0..], "75234edefe07819026751816");
    var expected_nonce_buf: [12]u8 = undefined;
    const expected_nonce = try hexToBytes(expected_nonce_buf[0..], "75234edefe07819026755d71");
    const nonce = nonceFor(suite, kid, ctr, base_key);
    try std.testing.expectEqualSlices(u8, expected_key, key_salt.keySlice());
    try std.testing.expectEqualSlices(u8, expected_salt, key_salt.salt[0..]);
    try std.testing.expectEqualSlices(u8, expected_nonce, nonce[0..]);

    const encrypted = try encryptAlloc(allocator, suite, kid, ctr, base_key, metadata, plaintext);
    defer allocator.free(encrypted);
    try std.testing.expectEqualSlices(u8, expected, encrypted);

    const decrypted = try decryptAlloc(allocator, suite, encrypted, base_key, metadata);
    defer allocator.free(decrypted);
    try std.testing.expectEqualSlices(u8, plaintext, decrypted);
}

test "tamper of ciphertext and header are rejected" {
    const allocator = std.testing.allocator;
    const suite = CipherSuite.aes_128_gcm_sha256_128;
    const encrypted = try encryptAlloc(allocator, suite, 1, 2, "base key", "metadata", "frame");
    defer allocator.free(encrypted);

    var tampered_ciphertext = try allocator.dupe(u8, encrypted);
    defer allocator.free(tampered_ciphertext);
    tampered_ciphertext[tampered_ciphertext.len - 1] ^= 0x01;
    try std.testing.expectError(error.AuthenticationFailed, decryptAlloc(allocator, suite, tampered_ciphertext, "base key", "metadata"));

    var tampered_header = try allocator.dupe(u8, encrypted);
    defer allocator.free(tampered_header);
    tampered_header[0] ^= 0x01;
    try std.testing.expectError(error.AuthenticationFailed, decryptAlloc(allocator, suite, tampered_header, "base key", "metadata"));
}

test "wrong key and wrong metadata fail authentication" {
    const allocator = std.testing.allocator;
    const suite = CipherSuite.chacha20_poly1305_sha256_128;
    const encrypted = try encryptAlloc(allocator, suite, 9, 10, "correct base key", "metadata", "frame");
    defer allocator.free(encrypted);

    try std.testing.expectError(error.AuthenticationFailed, decryptAlloc(allocator, suite, encrypted, "wrong base key", "metadata"));
    try std.testing.expectError(error.AuthenticationFailed, decryptAlloc(allocator, suite, encrypted, "correct base key", "other metadata"));
}

test "counter increments produce distinct nonces" {
    const base_key = "nonce base key";
    const nonce0 = nonceFor(.aes_128_gcm_sha256_128, 77, 0, base_key);
    const nonce1 = nonceFor(.aes_128_gcm_sha256_128, 77, 1, base_key);
    const nonce255 = nonceFor(.aes_128_gcm_sha256_128, 77, 255, base_key);

    try std.testing.expect(!std.mem.eql(u8, nonce0[0..], nonce1[0..]));
    try std.testing.expect(!std.mem.eql(u8, nonce1[0..], nonce255[0..]));
    try std.testing.expect(!std.mem.eql(u8, nonce0[0..], nonce255[0..]));
}

test "encryption is deterministic for same key KID CTR metadata and plaintext" {
    const allocator = std.testing.allocator;
    const suite = CipherSuite.chacha20_poly1305_sha256_128;

    const a = try encryptAlloc(allocator, suite, 0x0123, 0x4567, "base key", "metadata", "frame");
    defer allocator.free(a);
    const b = try encryptAlloc(allocator, suite, 0x0123, 0x4567, "base key", "metadata", "frame");
    defer allocator.free(b);
    const c = try encryptAlloc(allocator, suite, 0x0123, 0x4568, "base key", "metadata", "frame");
    defer allocator.free(c);

    try std.testing.expectEqualSlices(u8, a, b);
    try std.testing.expect(!std.mem.eql(u8, a, c));
}
