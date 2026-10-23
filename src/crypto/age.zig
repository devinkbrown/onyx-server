// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Minimal age v1 binary format support for one X25519 recipient.
//!
//! This module is intentionally self-contained: it imports only Zig's standard
//! library and implements the local header parser, base64 helpers, X25519 file
//! key wrap, header MAC, and STREAM ChaCha20-Poly1305 payload encryption.
const std = @import("std");
const zig_compat = @import("zig_compat.zig");

const X25519 = std.crypto.dh.X25519;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Aead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const testing = std.testing;

pub const public_key_len = X25519.public_length;
pub const secret_key_len = X25519.secret_length;
pub const file_key_len = 16;
pub const payload_nonce_len = 16;
pub const stream_chunk_len = 64 * 1024;
pub const tag_len = Aead.tag_length;
pub const wrapped_file_key_len = file_key_len + tag_len;

pub const PublicKey = [public_key_len]u8;
pub const SecretKey = [secret_key_len]u8;
pub const FileKey = [file_key_len]u8;
pub const PayloadNonce = [payload_nonce_len]u8;

const version_line = "age-encryption.org/v1\n";
const stanza_prefix = "-> X25519 ";
const mac_prefix = "--- ";
const x25519_label = "age-encryption.org/v1/X25519";
const stream_chunk_sealed_len = stream_chunk_len + tag_len;

pub const Error = error{
    AuthenticationFailed,
    HeaderAuthenticationFailed,
    InvalidFormat,
    InvalidHeader,
    InvalidPublicKey,
    TruncatedPayload,
    TrailingPayload,
    EmptyFinalChunk,
    ChunkCounterExhausted,
} || std.mem.Allocator.Error;

pub const KeyPair = struct {
    public_key: PublicKey,
    secret_key: SecretKey,

    pub fn generate(io: std.Io) KeyPair {
        const kp = X25519.KeyPair.generate(io);
        return .{ .public_key = kp.public_key, .secret_key = kp.secret_key };
    }

    pub fn generateDeterministic(seed: [X25519.seed_length]u8) Error!KeyPair {
        const kp = zig_compat.x25519GenerateDeterministic(seed) catch return error.InvalidPublicKey;
        return .{ .public_key = kp.public_key, .secret_key = kp.secret_key };
    }

    pub fn wipe(self: *KeyPair) void {
        secureZero(&self.secret_key);
    }
};

pub const EncryptOptions = struct {
    ephemeral_scalar: ?SecretKey = null,
    file_key: ?FileKey = null,
    payload_nonce: ?PayloadNonce = null,
};

pub fn encrypt(
    allocator: std.mem.Allocator,
    io: std.Io,
    recipient_pubkey: PublicKey,
    plaintext: []const u8,
) Error![]u8 {
    return encryptWithOptions(allocator, io, recipient_pubkey, plaintext, .{});
}

pub fn encryptWithEphemeralScalar(
    allocator: std.mem.Allocator,
    io: std.Io,
    recipient_pubkey: PublicKey,
    plaintext: []const u8,
    ephemeral_scalar: SecretKey,
) Error![]u8 {
    return encryptWithOptions(allocator, io, recipient_pubkey, plaintext, .{ .ephemeral_scalar = ephemeral_scalar });
}

pub fn encryptWithOptions(
    allocator: std.mem.Allocator,
    io: std.Io,
    recipient_pubkey: PublicKey,
    plaintext: []const u8,
    options: EncryptOptions,
) Error![]u8 {
    var file_key: FileKey = options.file_key orelse randomFileKey(io);
    defer secureZero(&file_key);

    var payload_nonce: PayloadNonce = options.payload_nonce orelse randomPayloadNonce(io);

    const eph_secret = if (options.ephemeral_scalar) |s| s else randomScalar(io);
    const eph_pub = zig_compat.x25519RecoverPublicKey(eph_secret) catch return error.InvalidPublicKey;

    var shared = X25519.scalarmult(eph_secret, recipient_pubkey) catch return error.InvalidPublicKey;
    defer secureZero(&shared);

    var wrap_key = deriveX25519WrapKey(shared, eph_pub, recipient_pubkey);
    defer secureZero(&wrap_key);

    const wrapped = wrapFileKey(wrap_key, file_key);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    try appendHeaderWithoutMac(allocator, &out, eph_pub, wrapped);

    var mac_key = deriveKey("", &file_key, "header");
    defer secureZero(&mac_key);
    var mac: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&mac, out.items, &mac_key);
    defer secureZero(&mac);

    try out.appendSlice(allocator, mac_prefix);
    try appendBase64(allocator, &out, &mac);
    try out.append(allocator, '\n');

    try out.appendSlice(allocator, &payload_nonce);
    try encryptPayload(allocator, &out, file_key, payload_nonce, plaintext);
    secureZero(&payload_nonce);

    return try out.toOwnedSlice(allocator);
}

pub fn decrypt(
    allocator: std.mem.Allocator,
    identity_scalar: SecretKey,
    ciphertext: []const u8,
) Error![]u8 {
    const parsed = try parseHeader(ciphertext);

    var recipient_pub = zig_compat.x25519RecoverPublicKey(identity_scalar) catch return error.InvalidPublicKey;
    defer secureZero(&recipient_pub);

    var shared = X25519.scalarmult(identity_scalar, parsed.ephemeral_pubkey) catch return error.InvalidPublicKey;
    defer secureZero(&shared);

    var wrap_key = deriveX25519WrapKey(shared, parsed.ephemeral_pubkey, recipient_pub);
    defer secureZero(&wrap_key);

    var file_key = unwrapFileKey(wrap_key, parsed.wrapped_file_key) catch return error.AuthenticationFailed;
    defer secureZero(&file_key);

    var mac_key = deriveKey("", &file_key, "header");
    defer secureZero(&mac_key);
    var expected_mac: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&expected_mac, ciphertext[0..parsed.header_without_mac_end], &mac_key);
    defer secureZero(&expected_mac);

    if (!std.crypto.timing_safe.eql([HmacSha256.mac_length]u8, expected_mac, parsed.header_mac)) {
        return error.HeaderAuthenticationFailed;
    }

    if (ciphertext.len < parsed.payload_start + payload_nonce_len + tag_len) {
        return error.TruncatedPayload;
    }

    const payload_nonce = ciphertext[parsed.payload_start..][0..payload_nonce_len].*;
    const sealed_payload = ciphertext[parsed.payload_start + payload_nonce_len ..];
    return decryptPayload(allocator, file_key, payload_nonce, sealed_payload);
}

fn appendHeaderWithoutMac(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    ephemeral_pubkey: PublicKey,
    wrapped_file_key: [wrapped_file_key_len]u8,
) Error!void {
    try out.appendSlice(allocator, version_line);
    try out.appendSlice(allocator, stanza_prefix);
    try appendBase64(allocator, out, &ephemeral_pubkey);
    try out.append(allocator, '\n');
    try appendBase64(allocator, out, &wrapped_file_key);
    try out.append(allocator, '\n');
}

fn wrapFileKey(wrap_key: [Aead.key_length]u8, file_key: FileKey) [wrapped_file_key_len]u8 {
    const zero_nonce = @as([Aead.nonce_length]u8, @splat(0));
    var wrapped: [wrapped_file_key_len]u8 = undefined;
    Aead.encrypt(wrapped[0..file_key_len], wrapped[file_key_len..][0..tag_len], &file_key, "", zero_nonce, wrap_key);
    return wrapped;
}

fn unwrapFileKey(wrap_key: [Aead.key_length]u8, wrapped: [wrapped_file_key_len]u8) !FileKey {
    const zero_nonce = @as([Aead.nonce_length]u8, @splat(0));
    var file_key: FileKey = undefined;
    errdefer secureZero(&file_key);
    Aead.decrypt(&file_key, wrapped[0..file_key_len], wrapped[file_key_len..][0..tag_len].*, "", zero_nonce, wrap_key) catch
        return error.AuthenticationFailed;
    return file_key;
}

fn encryptPayload(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    file_key: FileKey,
    payload_nonce: PayloadNonce,
    plaintext: []const u8,
) Error!void {
    var stream_key = deriveKey(&payload_nonce, &file_key, "payload");
    defer secureZero(&stream_key);

    var offset: usize = 0;
    var counter: u128 = 0;
    while (true) {
        const remaining = plaintext.len - offset;
        const final = remaining <= stream_chunk_len;
        const chunk_len = if (final) remaining else stream_chunk_len;
        const chunk = plaintext[offset..][0..chunk_len];
        const nonce = try streamNonce(counter, final);

        const old_len = out.items.len;
        try out.ensureUnusedCapacity(allocator, chunk_len + tag_len);
        out.items.len = old_len + chunk_len + tag_len;
        Aead.encrypt(
            out.items[old_len..][0..chunk_len],
            out.items[old_len + chunk_len ..][0..tag_len],
            chunk,
            "",
            nonce,
            stream_key,
        );

        counter += 1;
        offset += chunk_len;
        if (final) break;
    }
}

fn decryptPayload(
    allocator: std.mem.Allocator,
    file_key: FileKey,
    payload_nonce: PayloadNonce,
    sealed_payload: []const u8,
) Error![]u8 {
    if (sealed_payload.len < tag_len) return error.TruncatedPayload;

    var stream_key = deriveKey(&payload_nonce, &file_key, "payload");
    defer secureZero(&stream_key);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    var offset: usize = 0;
    var counter: u128 = 0;
    var chunks: usize = 0;
    while (offset < sealed_payload.len) {
        const remaining = sealed_payload.len - offset;
        const final = remaining <= stream_chunk_sealed_len;
        const sealed_len = if (final) remaining else stream_chunk_sealed_len;

        if (sealed_len < tag_len) return error.TruncatedPayload;
        if (!final and sealed_len != stream_chunk_sealed_len) return error.TruncatedPayload;
        if (final and chunks != 0 and sealed_len == tag_len) return error.EmptyFinalChunk;

        const chunk_ct_len = sealed_len - tag_len;
        const sealed = sealed_payload[offset..][0..sealed_len];
        const nonce = try streamNonce(counter, final);

        const old_len = out.items.len;
        try out.ensureUnusedCapacity(allocator, chunk_ct_len);
        out.items.len = old_len + chunk_ct_len;
        Aead.decrypt(
            out.items[old_len..][0..chunk_ct_len],
            sealed[0..chunk_ct_len],
            sealed[chunk_ct_len..][0..tag_len].*,
            "",
            nonce,
            stream_key,
        ) catch return error.AuthenticationFailed;

        chunks += 1;
        counter += 1;
        offset += sealed_len;
        if (final and offset != sealed_payload.len) return error.TrailingPayload;
    }

    return try out.toOwnedSlice(allocator);
}

fn deriveX25519WrapKey(
    shared_secret: [X25519.shared_length]u8,
    ephemeral_pubkey: PublicKey,
    recipient_pubkey: PublicKey,
) [Aead.key_length]u8 {
    var salt: [public_key_len * 2]u8 = undefined;
    @memcpy(salt[0..public_key_len], &ephemeral_pubkey);
    @memcpy(salt[public_key_len..], &recipient_pubkey);
    return deriveKey(&salt, &shared_secret, x25519_label);
}

fn deriveKey(salt: []const u8, ikm: []const u8, info: []const u8) [Aead.key_length]u8 {
    const prk = HkdfSha256.extract(salt, ikm);
    var key: [Aead.key_length]u8 = undefined;
    HkdfSha256.expand(&key, info, prk);
    return key;
}

fn streamNonce(counter: u128, final: bool) Error![Aead.nonce_length]u8 {
    if (counter >= (@as(u128, 1) << 88)) return error.ChunkCounterExhausted;
    var nonce = @as([Aead.nonce_length]u8, @splat(0));
    var x = counter;
    var i: usize = 11;
    while (i > 0) {
        i -= 1;
        nonce[i] = @truncate(x);
        x >>= 8;
    }
    nonce[11] = if (final) 1 else 0;
    return nonce;
}

const ParsedHeader = struct {
    ephemeral_pubkey: PublicKey,
    wrapped_file_key: [wrapped_file_key_len]u8,
    header_mac: [HmacSha256.mac_length]u8,
    header_without_mac_end: usize,
    payload_start: usize,
};

fn parseHeader(ciphertext: []const u8) Error!ParsedHeader {
    if (!std.mem.startsWith(u8, ciphertext, version_line)) return error.InvalidFormat;

    var pos: usize = version_line.len;
    const stanza_end = findLineEnd(ciphertext, pos) orelse return error.InvalidHeader;
    const stanza = ciphertext[pos..stanza_end];
    if (!std.mem.startsWith(u8, stanza, stanza_prefix)) return error.InvalidHeader;
    const eph_pub = decodeFixed(PublicKey, stanza[stanza_prefix.len..]) catch return error.InvalidHeader;

    pos = stanza_end + 1;
    const body_end = findLineEnd(ciphertext, pos) orelse return error.InvalidHeader;
    const wrapped = decodeFixed([wrapped_file_key_len]u8, ciphertext[pos..body_end]) catch return error.InvalidHeader;

    pos = body_end + 1;
    const mac_line_start = pos;
    const mac_end = findLineEnd(ciphertext, pos) orelse return error.InvalidHeader;
    const mac_line = ciphertext[pos..mac_end];
    if (!std.mem.startsWith(u8, mac_line, mac_prefix)) return error.InvalidHeader;
    const mac = decodeFixed([HmacSha256.mac_length]u8, mac_line[mac_prefix.len..]) catch return error.InvalidHeader;

    return .{
        .ephemeral_pubkey = eph_pub,
        .wrapped_file_key = wrapped,
        .header_mac = mac,
        .header_without_mac_end = mac_line_start,
        .payload_start = mac_end + 1,
    };
}

fn findLineEnd(bytes: []const u8, start: usize) ?usize {
    return std.mem.indexOfScalarPos(u8, bytes, start, '\n');
}

fn appendBase64(allocator: std.mem.Allocator, out: *std.ArrayList(u8), bytes: []const u8) Error!void {
    const enc = std.base64.standard_no_pad.Encoder;
    const old_len = out.items.len;
    const add_len = enc.calcSize(bytes.len);
    try out.ensureUnusedCapacity(allocator, add_len);
    out.items.len = old_len + add_len;
    _ = enc.encode(out.items[old_len..][0..add_len], bytes);
}

fn decodeFixed(comptime T: type, encoded: []const u8) !T {
    var out: T = undefined;
    const dec = std.base64.standard_no_pad.Decoder;
    const expected_len = try dec.calcSizeForSlice(encoded);
    if (expected_len != std.mem.asBytes(&out).len) return error.InvalidHeader;
    try dec.decode(std.mem.asBytes(&out), encoded);
    return out;
}

fn randomScalar(io: std.Io) SecretKey {
    var scalar: SecretKey = undefined;
    io.random(&scalar);
    return scalar;
}

fn randomFileKey(io: std.Io) FileKey {
    var key: FileKey = undefined;
    io.random(&key);
    return key;
}

fn randomPayloadNonce(io: std.Io) PayloadNonce {
    var nonce: PayloadNonce = undefined;
    io.random(&nonce);
    return nonce;
}

fn secureZero(ptr: anytype) void {
    std.crypto.secureZero(u8, std.mem.asBytes(ptr));
}

const DeterministicIo = struct {
    state: u64,

    fn io(self: *DeterministicIo) std.Io {
        return .{ .userdata = self, .vtable = &vtable };
    }

    fn random(userdata: ?*anyopaque, buffer: []u8) void {
        var self: *DeterministicIo = @ptrCast(@alignCast(userdata.?));
        for (buffer) |*b| {
            self.state = self.state *% 6364136223846793005 +% 1442695040888963407;
            b.* = @truncate(self.state >> 56);
        }
    }

    const vtable: std.Io.VTable = blk: {
        var vt = std.Io.failing.vtable.*;
        vt.random = random;
        break :blk vt;
    };
};

fn fixtureKeyPair(seed_byte: u8) !KeyPair {
    return try KeyPair.generateDeterministic(@as([X25519.seed_length]u8, @splat(seed_byte)));
}

fn roundTripSize(size: usize) !void {
    const allocator = testing.allocator;
    var recipient = try fixtureKeyPair(0x42);
    defer recipient.wipe();
    var rng = DeterministicIo{ .state = 0x12345678 };

    const plaintext = try allocator.alloc(u8, size);
    defer allocator.free(plaintext);
    for (plaintext, 0..) |*b, i| b.* = @truncate((i * 131 + 7) & 0xff);

    const sealed = try encrypt(allocator, rng.io(), recipient.public_key, plaintext);
    defer allocator.free(sealed);
    const opened = try decrypt(allocator, recipient.secret_key, sealed);
    defer allocator.free(opened);

    try testing.expectEqualSlices(u8, plaintext, opened);
}

test "encrypt decrypt round-trip for empty small full and multi-chunk payloads" {
    try roundTripSize(0);
    try roundTripSize(1);
    try roundTripSize(31);
    try roundTripSize(stream_chunk_len - 1);
    try roundTripSize(stream_chunk_len);
    try roundTripSize(stream_chunk_len + 1);
    try roundTripSize(stream_chunk_len * 2 + 333);
}

test "wrong identity fails while the right identity succeeds" {
    const allocator = testing.allocator;
    var recipient = try fixtureKeyPair(0x10);
    defer recipient.wipe();
    var wrong = try fixtureKeyPair(0x20);
    defer wrong.wipe();
    var rng = DeterministicIo{ .state = 0x9999 };

    const sealed = try encrypt(allocator, rng.io(), recipient.public_key, "onyx secret");
    defer allocator.free(sealed);

    try testing.expectError(error.AuthenticationFailed, decrypt(allocator, wrong.secret_key, sealed));

    const opened = try decrypt(allocator, recipient.secret_key, sealed);
    defer allocator.free(opened);
    try testing.expectEqualSlices(u8, "onyx secret", opened);
}

test "tampered header MAC is rejected" {
    const allocator = testing.allocator;
    var recipient = try fixtureKeyPair(0x30);
    defer recipient.wipe();
    var rng = DeterministicIo{ .state = 0xabcdef };

    const sealed = try encrypt(allocator, rng.io(), recipient.public_key, "header mac");
    defer allocator.free(sealed);

    var tampered = try allocator.dupe(u8, sealed);
    defer allocator.free(tampered);
    const parsed = try parseHeader(tampered);
    const mac_first_char = parsed.header_without_mac_end + mac_prefix.len;
    tampered[mac_first_char] = if (tampered[mac_first_char] == 'A') 'B' else 'A';

    try testing.expectError(error.HeaderAuthenticationFailed, decrypt(allocator, recipient.secret_key, tampered));
}

test "tampered payload is rejected" {
    const allocator = testing.allocator;
    var recipient = try fixtureKeyPair(0x40);
    defer recipient.wipe();
    var rng = DeterministicIo{ .state = 0xabcdef01 };

    const sealed = try encrypt(allocator, rng.io(), recipient.public_key, "payload auth");
    defer allocator.free(sealed);

    var tampered = try allocator.dupe(u8, sealed);
    defer allocator.free(tampered);
    tampered[tampered.len - 1] ^= 0x80;

    try testing.expectError(error.AuthenticationFailed, decrypt(allocator, recipient.secret_key, tampered));
}

test "fixed ephemeral scalar file key and nonce make encryption deterministic" {
    const allocator = testing.allocator;
    var recipient = try fixtureKeyPair(0x50);
    defer recipient.wipe();
    var rng_a = DeterministicIo{ .state = 0x1111 };
    var rng_b = DeterministicIo{ .state = 0x2222 };

    const opts = EncryptOptions{
        .ephemeral_scalar = @as([secret_key_len]u8, @splat(0x61)),
        .file_key = @as([file_key_len]u8, @splat(0x62)),
        .payload_nonce = @as([payload_nonce_len]u8, @splat(0x63)),
    };

    const first = try encryptWithOptions(allocator, rng_a.io(), recipient.public_key, "deterministic", opts);
    defer allocator.free(first);
    const second = try encryptWithOptions(allocator, rng_b.io(), recipient.public_key, "deterministic", opts);
    defer allocator.free(second);

    try testing.expectEqualSlices(u8, first, second);

    const opened = try decrypt(allocator, recipient.secret_key, first);
    defer allocator.free(opened);
    try testing.expectEqualSlices(u8, "deterministic", opened);
}

test "fixed ephemeral scalar alone still decrypts correctly" {
    const allocator = testing.allocator;
    var recipient = try fixtureKeyPair(0x70);
    defer recipient.wipe();
    var rng = DeterministicIo{ .state = 0x3333 };

    const sealed = try encryptWithEphemeralScalar(
        allocator,
        rng.io(),
        recipient.public_key,
        "ephemeral injection",
        @as([secret_key_len]u8, @splat(0x71)),
    );
    defer allocator.free(sealed);

    const opened = try decrypt(allocator, recipient.secret_key, sealed);
    defer allocator.free(opened);
    try testing.expectEqualSlices(u8, "ephemeral injection", opened);
}

test "header parser rejects non-age input" {
    try testing.expectError(error.InvalidFormat, decrypt(testing.allocator, @as([secret_key_len]u8, @splat(1)), "not age"));
}
