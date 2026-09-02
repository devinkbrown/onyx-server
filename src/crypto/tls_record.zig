// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! TLS 1.3 record-layer framing (RFC 8446 section 5).
//!
//! This module is pure caller-buffered code: it builds and parses
//! TLSCiphertext records, derives per-record AEAD nonces, forms TLS 1.3
//! additional data from the wire header, and encodes/decodes
//! TLSInnerPlaintext.content || type || zero-padding.
const std = @import("std");
const aead = record_aead;
const tls = record_tls;

const record_tls = struct {
    pub const max_plaintext_len = 16 * 1024;
    pub const max_ciphertext_len = @This().max_plaintext_len + 256;
    pub const record_header_len = 5;
    pub const tls12_wire_version: u16 = 0x0303;

    pub const ContentType = enum(u8) {
        change_cipher_spec = 20,
        alert = 21,
        handshake = 22,
        application_data = 23,

        pub fn fromWire(v: u8) ?@This() {
            return switch (v) {
                20 => .change_cipher_spec,
                21 => .alert,
                22 => .handshake,
                23 => .application_data,
                else => null,
            };
        }
    };
};

// Mirrors src/crypto/aead.zig's typed AEAD surface for this standalone
// direct-file test target. The underlying std.crypto AEADs are the same ones
// used by aead.zig.
const record_aead = struct {
    pub const Error = error{
        AuthFailed,
        BufferLengthMismatch,
        NonceCounterExhausted,
    };

    pub const AeadAlg = enum {
        chacha20_poly1305,
        aes256_gcm,

        fn Impl(comptime alg: AeadAlg) type {
            return switch (alg) {
                .chacha20_poly1305 => std.crypto.aead.chacha_poly.ChaCha20Poly1305,
                .aes256_gcm => std.crypto.aead.aes_gcm.Aes256Gcm,
            };
        }
    };

    pub const Nonce96 = [12]u8;

    pub fn Aead(comptime alg: AeadAlg) type {
        const Impl = alg.Impl();
        return struct {
            const Self = @This();

            pub const Key = [Impl.key_length]u8;
            pub const Nonce = [Impl.nonce_length]u8;
            pub const Tag = [Impl.tag_length]u8;
            pub const key_length = Impl.key_length;
            pub const nonce_length = Impl.nonce_length;
            pub const tag_length = Impl.tag_length;

            key: Key,

            pub fn init(key: Key) Self {
                return .{ .key = key };
            }

            pub fn deinit(self: *Self) void {
                std.crypto.secureZero(u8, &self.key);
            }

            pub fn seal(
                self: *const Self,
                nonce: Nonce,
                aad: []const u8,
                plaintext: []const u8,
                out: []u8,
            ) record_aead.Error!Tag {
                if (out.len != plaintext.len) return record_aead.Error.BufferLengthMismatch;
                var tag: Tag = undefined;
                Impl.encrypt(out, &tag, plaintext, aad, nonce, self.key);
                return tag;
            }

            pub fn open(
                self: *const Self,
                nonce: Nonce,
                aad: []const u8,
                ciphertext: []const u8,
                tag: Tag,
                out: []u8,
            ) record_aead.Error!void {
                if (out.len != ciphertext.len) return record_aead.Error.BufferLengthMismatch;
                Impl.decrypt(out, ciphertext, tag, aad, nonce, self.key) catch return record_aead.Error.AuthFailed;
            }
        };
    }
};

pub const ContentType = tls.ContentType;
pub const Nonce96 = aead.Nonce96;

pub const record_header_len = tls.record_header_len;
pub const max_plaintext_len = tls.max_plaintext_len;
pub const max_ciphertext_len = tls.max_ciphertext_len;
pub const legacy_record_version = tls.tls12_wire_version;
pub const outer_content_type = ContentType.application_data;

/// RFC 8449: the largest application-data content one record may carry given a
/// peer's advertised `record_size_limit` (a TLSInnerPlaintext bound). Since
/// TLSInnerPlaintext = content + 1 content-type byte + padding(0), content must
/// be <= limit - 1, and is never allowed above the protocol max (2^14). The
/// default limit (2^14+1) yields exactly `max_plaintext_len` — no restriction.
pub fn recordContentLimit(peer_record_size_limit: usize) usize {
    const inner = if (peer_record_size_limit > 1) peer_record_size_limit - 1 else 1;
    return @min(max_plaintext_len, inner);
}

/// RFC 8449 for TLS 1.2 and earlier: the peer's advertised `record_size_limit`
/// bounds `TLSPlaintext.fragment` directly. Unlike TLS 1.3 there is no inner
/// content-type byte or padding in the plaintext, so no `- 1` adjustment
/// applies — the fragment content limit is the advertised value itself, capped
/// at the protocol max (2^14). The explicit nonce and AEAD tag are record
/// protection overhead outside the fragment and are not counted. The default
/// limit (2^14+1) yields exactly `max_plaintext_len` — no restriction.
pub fn recordContentLimit12(peer_record_size_limit: usize) usize {
    // `@max(1, …)` keeps the invariant local: a 0 limit (unreachable from the
    // wire — parse enforces ≥64 — but settable directly, e.g. in tests) would
    // otherwise make the caller's fragmentation loop emit zero-length records
    // forever. Real limits are ≥64 so this is a no-op for them.
    return @max(1, @min(max_plaintext_len, peer_record_size_limit));
}

/// RFC 8449 record_size_limit bounds: the smallest legal advertised value is 64;
/// the largest is 2^14+1 (TLSInnerPlaintext including the content-type byte).
pub const record_size_limit_min: u16 = 64;
pub const record_size_limit_max: u16 = max_plaintext_len + 1;

/// RFC 8446 §5 / Appendix D.4: in "middlebox compatibility mode" a TLS 1.3 peer
/// may interleave *unencrypted* change_cipher_spec records into the handshake,
/// and the receiver drops them. The spec is exact about what is droppable: the
/// record must carry the single byte 0x01, and "an implementation which receives
/// any other change_cipher_spec value or which receives a protected
/// change_cipher_spec record MUST abort with an unexpected_message alert".
///
/// Both halves matter for a hostile peer. Without the value check, a CCS record
/// is a free arbitrary-length channel that the receiver parses and discards
/// without ever looking at it; without a count cap, an unauthenticated peer can
/// hold a pre-handshake connection open forever, feeding CCS records that keep
/// the state machine alive while it never advances and never errors. A
/// legitimate peer sends exactly one (a server that also answers a
/// HelloRetryRequest sends two), so this bound is far above anything real.
pub const max_change_cipher_spec_records: usize = 8;

/// True when `fragment` is the one CCS body RFC 8446 §5 permits: exactly 0x01.
pub fn isLegalCompatCcs(fragment: []const u8) bool {
    return fragment.len == 1 and fragment[0] == 0x01;
}

pub const Error = aead.Error || error{
    BadRecordHeader,
    InvalidContentType,
    InvalidInnerPlaintext,
    OutputTooSmall,
    PlaintextTooLong,
    RecordOverflow,
};

pub const TLSCiphertext = struct {
    content_type: ContentType,
    legacy_record_version: u16,
    encrypted_record: []const u8,

    pub fn headerBytes(self: TLSCiphertext) [record_header_len]u8 {
        return makeAdditionalData(@intCast(self.encrypted_record.len));
    }
};

pub const OpenedPlaintext = struct {
    content_type: ContentType,
    content: []u8,
    padding_len: usize,
};

/// TLS 1.3 per-record nonce: static write_iv XOR (0x00000000 || seq_be64).
pub fn deriveNonce(write_iv: Nonce96, seq: u64) Nonce96 {
    var nonce = write_iv;
    var seq_bytes: Nonce96 = @splat(0);
    std.mem.writeInt(u64, seq_bytes[4..12], seq, .big);
    for (&nonce, seq_bytes) |*dst, rhs| {
        dst.* ^= rhs;
    }
    return nonce;
}

/// TLS 1.3 AEAD additional_data is the serialized TLSCiphertext header.
pub fn makeAdditionalData(encrypted_record_len: u16) [record_header_len]u8 {
    var aad: [record_header_len]u8 = undefined;
    aad[0] = @intFromEnum(outer_content_type);
    std.mem.writeInt(u16, aad[1..3], legacy_record_version, .big);
    std.mem.writeInt(u16, aad[3..5], encrypted_record_len, .big);
    return aad;
}

/// Parse one complete TLS 1.3 TLSCiphertext record.
pub fn parseCiphertext(record: []const u8) Error!TLSCiphertext {
    if (record.len < record_header_len) return error.BadRecordHeader;
    const length = std.mem.readInt(u16, record[3..5], .big);
    if (length > max_ciphertext_len) return error.RecordOverflow;
    if (record.len != record_header_len + @as(usize, length)) return error.BadRecordHeader;

    const ct = ContentType.fromWire(record[0]) orelse return error.BadRecordHeader;
    if (ct != outer_content_type) return error.InvalidContentType;
    const version = std.mem.readInt(u16, record[1..3], .big);
    if (version != legacy_record_version) return error.BadRecordHeader;

    return .{
        .content_type = ct,
        .legacy_record_version = version,
        .encrypted_record = record[record_header_len..],
    };
}

pub fn encodeInnerPlaintext(
    content_type: ContentType,
    plaintext: []const u8,
    padding_len: usize,
    out: []u8,
) Error![]u8 {
    if (!isInnerContentType(content_type)) return error.InvalidContentType;
    if (plaintext.len > max_plaintext_len) return error.PlaintextTooLong;
    const inner_len = plaintext.len + 1 + padding_len;
    if (inner_len > max_ciphertext_len) return error.RecordOverflow;
    if (out.len < inner_len) return error.OutputTooSmall;

    @memcpy(out[0..plaintext.len], plaintext);
    out[plaintext.len] = @intFromEnum(content_type);
    @memset(out[plaintext.len + 1 .. inner_len], 0);
    return out[0..inner_len];
}

/// Strip TLS 1.3 zero padding with a full-length scan.
pub fn decodeInnerPlaintext(inner: []u8) Error!OpenedPlaintext {
    if (inner.len == 0) return error.InvalidInnerPlaintext;

    var found: u8 = 0;
    var type_index: usize = 0;
    var type_byte: u8 = 0;

    var i = inner.len;
    while (i != 0) {
        i -= 1;
        const b = inner[i];
        const select = ctNonZero(b) & (found ^ 1);
        type_index = ctSelectUsize(select, i, type_index);
        type_byte = ctSelectU8(select, b, type_byte);
        found |= ctNonZero(b);
    }

    if (found == 0) return error.InvalidInnerPlaintext;
    if (type_index > max_plaintext_len) return error.PlaintextTooLong;
    const content_type = ContentType.fromWire(type_byte) orelse return error.InvalidContentType;
    if (!isInnerContentType(content_type)) return error.InvalidContentType;

    return .{
        .content_type = content_type,
        .content = inner[0..type_index],
        .padding_len = inner.len - type_index - 1,
    };
}

pub fn sealRecord(
    comptime alg: aead.AeadAlg,
    cipher: *const aead.Aead(alg),
    write_iv: Nonce96,
    seq: u64,
    content_type: ContentType,
    plaintext: []const u8,
    padding_len: usize,
    inner_scratch: []u8,
    record_out: []u8,
) Error![]u8 {
    const A = aead.Aead(alg);
    const inner = try encodeInnerPlaintext(content_type, plaintext, padding_len, inner_scratch);
    const encrypted_len = inner.len + A.tag_length;
    if (encrypted_len > max_ciphertext_len) return error.RecordOverflow;
    if (record_out.len < record_header_len + encrypted_len) return error.OutputTooSmall;

    const aad = makeAdditionalData(@intCast(encrypted_len));
    @memcpy(record_out[0..record_header_len], &aad);

    const ciphertext = record_out[record_header_len..][0..inner.len];
    const nonce = deriveNonce(write_iv, seq);
    const tag = try cipher.seal(nonce, &aad, inner, ciphertext);
    @memcpy(record_out[record_header_len + inner.len ..][0..A.tag_length], &tag);

    return record_out[0 .. record_header_len + encrypted_len];
}

pub fn openRecord(
    comptime alg: aead.AeadAlg,
    cipher: *const aead.Aead(alg),
    write_iv: Nonce96,
    seq: u64,
    record: []const u8,
    plaintext_out: []u8,
) Error!OpenedPlaintext {
    const A = aead.Aead(alg);
    const parsed = try parseCiphertext(record);
    if (parsed.encrypted_record.len < A.tag_length) return error.BadRecordHeader;
    const ciphertext_len = parsed.encrypted_record.len - A.tag_length;
    if (plaintext_out.len < ciphertext_len) return error.OutputTooSmall;

    const aad = parsed.headerBytes();
    const nonce = deriveNonce(write_iv, seq);
    const ciphertext = parsed.encrypted_record[0..ciphertext_len];
    var tag: A.Tag = undefined;
    @memcpy(tag[0..], parsed.encrypted_record[ciphertext_len..][0..A.tag_length]);

    try cipher.open(nonce, &aad, ciphertext, tag, plaintext_out[0..ciphertext_len]);
    return decodeInnerPlaintext(plaintext_out[0..ciphertext_len]);
}

fn isInnerContentType(content_type: ContentType) bool {
    return switch (content_type) {
        .alert, .handshake, .application_data => true,
        .change_cipher_spec => false,
    };
}

fn ctNonZero(x: u8) u8 {
    const ux: u16 = x;
    return @intCast(((ux | (0 -% ux)) >> 8) & 1);
}

fn ctSelectU8(select: u8, a: u8, b: u8) u8 {
    const mask: u8 = 0 -% select;
    return (a & mask) | (b & ~mask);
}

fn ctSelectUsize(select: u8, a: usize, b: usize) usize {
    const mask: usize = 0 -% @as(usize, select);
    return (a & mask) | (b & ~mask);
}

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "seal/open round-trip" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const A = aead.Aead(.chacha20_poly1305);
    var cipher = A.init(@as([A.key_length]u8, @splat(0x42)));
    defer cipher.deinit();

    const iv = hex("000102030405060708090a0b");
    const plaintext = "onyx tls record payload";
    const padding_len = 5;
    const inner_len = plaintext.len + 1 + padding_len;

    const inner = try allocator.alloc(u8, inner_len);
    defer allocator.free(inner);
    const record_buf = try allocator.alloc(u8, record_header_len + inner_len + A.tag_length);
    defer allocator.free(record_buf);
    const opened_buf = try allocator.alloc(u8, inner_len);
    defer allocator.free(opened_buf);

    const record = try sealRecord(
        .chacha20_poly1305,
        &cipher,
        iv,
        7,
        .application_data,
        plaintext,
        padding_len,
        inner,
        record_buf,
    );
    const opened = try openRecord(.chacha20_poly1305, &cipher, iv, 7, record, opened_buf);
    try testing.expectEqual(ContentType.application_data, opened.content_type);
    try testing.expectEqualSlices(u8, plaintext, opened.content);
    try testing.expectEqual(@as(usize, padding_len), opened.padding_len);
}

test "nonce derivation xors write_iv with sequence number" {
    const iv = hex("000102030405060708090a0b");
    const nonce = deriveNonce(iv, 0x0102030405060708);
    try std.testing.expectEqualSlices(u8, &hex("00010203050705030d0f0d03"), &nonce);
}

test "tamper detection rejects modified ciphertext and tag" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const A = aead.Aead(.chacha20_poly1305);
    var cipher = A.init(@as([A.key_length]u8, @splat(0xA5)));
    defer cipher.deinit();

    const iv = hex("101112131415161718191a1b");
    const plaintext = "authenticated record";
    const inner_len = plaintext.len + 1;
    const inner = try allocator.alloc(u8, inner_len);
    defer allocator.free(inner);
    const record_buf = try allocator.alloc(u8, record_header_len + inner_len + A.tag_length);
    defer allocator.free(record_buf);
    const opened_buf = try allocator.alloc(u8, inner_len);
    defer allocator.free(opened_buf);

    const record = try sealRecord(
        .chacha20_poly1305,
        &cipher,
        iv,
        1,
        .application_data,
        plaintext,
        0,
        inner,
        record_buf,
    );

    record_buf[record_header_len] ^= 0x01;
    try testing.expectError(error.AuthFailed, openRecord(.chacha20_poly1305, &cipher, iv, 1, record, opened_buf));
    record_buf[record_header_len] ^= 0x01;

    record_buf[record.len - 1] ^= 0x80;
    try testing.expectError(error.AuthFailed, openRecord(.chacha20_poly1305, &cipher, iv, 1, record, opened_buf));
}

test "padding strip returns content before type byte" {
    const testing = std.testing;
    const allocator = testing.allocator;
    var inner = try allocator.alloc(u8, 9);
    defer allocator.free(inner);
    @memcpy(inner[0..4], "ping");
    inner[4] = @intFromEnum(ContentType.handshake);
    @memset(inner[5..], 0);

    const opened = try decodeInnerPlaintext(inner);
    try testing.expectEqual(ContentType.handshake, opened.content_type);
    try testing.expectEqualSlices(u8, "ping", opened.content);
    try testing.expectEqual(@as(usize, 4), opened.padding_len);
}

// ---------------------------------------------------------------------------
// Adversarial corpus (`zig build test-exploit`).
//
// Every test below drives a hostile record at the TLS 1.3 record layer and
// asserts it FAILS CLOSED with a typed error — never a panic, never a silently
// accepted forgery, never a decrypt-then-trust. The record layer is the first
// code an unauthenticated network peer reaches, so each attack class the RFC
// names gets a pinned negative test here.
// ---------------------------------------------------------------------------

/// Seal one record with a throwaway key so a test can then corrupt it. Returns
/// the wire record inside `record_out` (caller-owned).
fn exploitSealFixture(
    cipher: *const aead.Aead(.chacha20_poly1305),
    iv: Nonce96,
    seq: u64,
    content_type: ContentType,
    plaintext: []const u8,
    inner_scratch: []u8,
    record_out: []u8,
) Error![]u8 {
    return sealRecord(.chacha20_poly1305, cipher, iv, seq, content_type, plaintext, 0, inner_scratch, record_out);
}

test "exploit: record header declaring more than 2^14+256 is rejected" {
    // RFC 8446 §5.2 caps TLSCiphertext.length at 2^14+256. A peer declaring more
    // is trying to make us size a buffer from an unvalidated wire integer.
    var rec: [record_header_len]u8 = undefined;
    rec[0] = @intFromEnum(outer_content_type);
    std.mem.writeInt(u16, rec[1..3], legacy_record_version, .big);
    std.mem.writeInt(u16, rec[3..5], max_ciphertext_len + 1, .big);
    try std.testing.expectError(error.RecordOverflow, parseCiphertext(&rec));

    // 0xFFFF — the largest value the 16-bit length field can express.
    std.mem.writeInt(u16, rec[3..5], 0xFFFF, .big);
    try std.testing.expectError(error.RecordOverflow, parseCiphertext(&rec));
}

test "exploit: record length disagreeing with the delivered byte count is rejected" {
    // Both directions of a framing desync: a length larger than the bytes we
    // hold (over-read attempt) and a length smaller (trailing-byte smuggling,
    // where the leftover would otherwise be silently dropped or reinterpreted).
    var over: [record_header_len + 4]u8 = undefined;
    over[0] = @intFromEnum(outer_content_type);
    std.mem.writeInt(u16, over[1..3], legacy_record_version, .big);
    std.mem.writeInt(u16, over[3..5], 64, .big); // claims 64, carries 4
    try std.testing.expectError(error.BadRecordHeader, parseCiphertext(&over));

    std.mem.writeInt(u16, over[3..5], 2, .big); // claims 2, carries 4
    try std.testing.expectError(error.BadRecordHeader, parseCiphertext(&over));

    // A bare header with a truncated body, and an empty buffer.
    try std.testing.expectError(error.BadRecordHeader, parseCiphertext(over[0..3]));
    try std.testing.expectError(error.BadRecordHeader, parseCiphertext(&.{}));
}

test "exploit: record with a non-application_data outer type is rejected" {
    // RFC 8446 §5.2: every protected record MUST carry outer type
    // application_data(23). Accepting handshake(22)/alert(21) on the outer type
    // would let a peer steer our record dispatch from OUTSIDE the AEAD, before
    // anything is authenticated.
    for ([_]u8{ 20, 21, 22, 0, 24, 255 }) |bad_type| {
        var rec: [record_header_len + 8]u8 = @splat(0);
        rec[0] = bad_type;
        std.mem.writeInt(u16, rec[1..3], legacy_record_version, .big);
        std.mem.writeInt(u16, rec[3..5], 8, .big);
        try std.testing.expectError(
            if (ContentType.fromWire(bad_type) == null) error.BadRecordHeader else error.InvalidContentType,
            parseCiphertext(&rec),
        );
    }
}

test "exploit: record with a forged legacy version is rejected" {
    // The legacy_record_version is fixed at 0x0303 on the wire for TLS 1.3. A
    // peer varying it is probing for a version-dispatch path.
    for ([_]u16{ 0x0301, 0x0302, 0x0304, 0x0000, 0xFFFF }) |bad_version| {
        var rec: [record_header_len + 8]u8 = @splat(0);
        rec[0] = @intFromEnum(outer_content_type);
        std.mem.writeInt(u16, rec[1..3], bad_version, .big);
        std.mem.writeInt(u16, rec[3..5], 8, .big);
        try std.testing.expectError(error.BadRecordHeader, parseCiphertext(&rec));
    }
}

test "exploit: a record shorter than the AEAD tag is rejected before any open" {
    // A body shorter than tag_length would underflow `len - tag_length`. This
    // must be caught structurally, never by trusting the subtraction.
    const A = aead.Aead(.chacha20_poly1305);
    var cipher = A.init(@as([A.key_length]u8, @splat(0x11)));
    defer cipher.deinit();
    const iv = hex("000102030405060708090a0b");
    var out: [64]u8 = undefined;

    var body_len: usize = 0;
    while (body_len < A.tag_length) : (body_len += 1) {
        var rec: [record_header_len + 16]u8 = @splat(0);
        rec[0] = @intFromEnum(outer_content_type);
        std.mem.writeInt(u16, rec[1..3], legacy_record_version, .big);
        std.mem.writeInt(u16, rec[3..5], @intCast(body_len), .big);
        try std.testing.expectError(
            error.BadRecordHeader,
            openRecord(.chacha20_poly1305, &cipher, iv, 0, rec[0 .. record_header_len + body_len], &out),
        );
    }
}

test "exploit: an all-zero inner plaintext (padding with no content type) is rejected" {
    // The TLS 1.3 depad scan must not fall off the front of the buffer when a
    // peer sends nothing but padding. `found == 0` is the only safe outcome, and
    // it must be an error rather than a zero-length application record.
    var inner: [32]u8 = @splat(0);
    try std.testing.expectError(error.InvalidInnerPlaintext, decodeInnerPlaintext(&inner));
    try std.testing.expectError(error.InvalidInnerPlaintext, decodeInnerPlaintext(inner[0..1]));
    try std.testing.expectError(error.InvalidInnerPlaintext, decodeInnerPlaintext(inner[0..0]));
}

test "exploit: change_cipher_spec smuggled as an inner content type is rejected" {
    // RFC 8446 §5.4: CCS is never a legal TLSInnerPlaintext type. A peer that
    // could smuggle one inside a protected record would reach the CCS-handling
    // path from within the encrypted stream.
    var inner = [_]u8{ 'x', @intFromEnum(ContentType.change_cipher_spec) };
    try std.testing.expectError(error.InvalidContentType, decodeInnerPlaintext(&inner));

    // ...and an inner type byte outside the enum entirely.
    for ([_]u8{ 0, 1, 24, 200, 255 }) |bad| {
        var probe = [_]u8{ 'x', bad };
        try std.testing.expectError(error.InvalidContentType, decodeInnerPlaintext(&probe));
    }

    // The encoder must refuse to produce one in the first place.
    var scratch: [16]u8 = undefined;
    try std.testing.expectError(
        error.InvalidContentType,
        encodeInnerPlaintext(.change_cipher_spec, "x", 0, &scratch),
    );
}

test "exploit: the sequence number is AEAD-bound — replaying a record at another seq fails" {
    // Per-record nonce = write_iv XOR seq. A record captured at seq N must not
    // open at any other sequence position: that is what stops an attacker from
    // reordering, replaying, or dropping records inside a live stream.
    const testing = std.testing;
    const allocator = testing.allocator;
    const A = aead.Aead(.chacha20_poly1305);
    var cipher = A.init(@as([A.key_length]u8, @splat(0x5C)));
    defer cipher.deinit();
    const iv = hex("0b0a090807060504030201ff");
    const plaintext = "sequence-bound payload";
    const inner_len = plaintext.len + 1;

    const inner = try allocator.alloc(u8, inner_len);
    defer allocator.free(inner);
    const record_buf = try allocator.alloc(u8, record_header_len + inner_len + A.tag_length);
    defer allocator.free(record_buf);
    const opened_buf = try allocator.alloc(u8, inner_len);
    defer allocator.free(opened_buf);

    const record = try exploitSealFixture(&cipher, iv, 42, .application_data, plaintext, inner, record_buf);

    // The genuine position opens.
    _ = try openRecord(.chacha20_poly1305, &cipher, iv, 42, record, opened_buf);

    // Every neighbouring position — and the wrap-around boundary — must not.
    for ([_]u64{ 0, 41, 43, 1 << 32, std.math.maxInt(u64) }) |wrong_seq| {
        try testing.expectError(
            error.AuthFailed,
            openRecord(.chacha20_poly1305, &cipher, iv, wrong_seq, record, opened_buf),
        );
    }
}

test "exploit: distinct sequence numbers never collide onto one nonce" {
    // Nonce reuse is catastrophic for both AEADs here (it recovers the GCM
    // authentication key outright). The seq->nonce map must be injective, so a
    // record counter can never be walked onto a previously used nonce.
    const iv = hex("aabbccddeeff001122334455");
    var seen = std.AutoHashMap(Nonce96, u64).init(std.testing.allocator);
    defer seen.deinit();

    const probes = [_]u64{
        0,                        1,
        2,                        255,
        256,                      65535,
        65536,                    0x0000_0000_FFFF_FFFF,
        0x0000_0001_0000_0000,    0x00FF_FFFF_FFFF_FFFF,
        std.math.maxInt(u64) - 1, std.math.maxInt(u64),
    };
    for (probes) |seq| {
        const nonce = deriveNonce(iv, seq);
        if (try seen.fetchPut(nonce, seq)) |prev| {
            std.debug.print("nonce collision: seq {d} and seq {d}\n", .{ prev.value, seq });
            return error.NonceCollision;
        }
    }

    // The counter only ever touches the low 8 bytes; the leading 4 IV bytes are
    // never perturbed, so a seq can never alias into the salt region.
    const base = deriveNonce(iv, 0);
    for (probes) |seq| {
        try std.testing.expectEqualSlices(u8, base[0..4], deriveNonce(iv, seq)[0..4]);
    }
}

test "exploit: the record header is AEAD-bound — a truncated body does not open" {
    // additional_data is the serialized 5-byte header, so the declared length is
    // authenticated. An attacker who shortens a record (and fixes up the length
    // field so framing still parses) must get an auth failure, not a truncated
    // plaintext.
    const testing = std.testing;
    const allocator = testing.allocator;
    const A = aead.Aead(.chacha20_poly1305);
    var cipher = A.init(@as([A.key_length]u8, @splat(0x77)));
    defer cipher.deinit();
    const iv = hex("112233445566778899aabbcc");
    const plaintext = "truncate me if you can";
    const inner_len = plaintext.len + 1;

    const inner = try allocator.alloc(u8, inner_len);
    defer allocator.free(inner);
    const record_buf = try allocator.alloc(u8, record_header_len + inner_len + A.tag_length);
    defer allocator.free(record_buf);
    const opened_buf = try allocator.alloc(u8, inner_len);
    defer allocator.free(opened_buf);

    const record = try exploitSealFixture(&cipher, iv, 3, .application_data, plaintext, inner, record_buf);
    try testing.expect(record.len == record_buf.len);

    // Chop four bytes off the body and re-declare the shorter length so the
    // framing check passes; only the AAD binding can catch this.
    const shortened = record_buf[0 .. record_buf.len - 4];
    std.mem.writeInt(u16, shortened[3..5], @intCast(shortened.len - record_header_len), .big);
    try testing.expectError(
        error.AuthFailed,
        openRecord(.chacha20_poly1305, &cipher, iv, 3, shortened, opened_buf),
    );
}

test "exploit: oversized plaintext and inner-plaintext are refused by the encoder" {
    // A caller (or a peer-driven size) above the protocol maximum must be a
    // typed error, never a heap write past the caller's scratch.
    const testing = std.testing;
    const allocator = testing.allocator;
    const huge = try allocator.alloc(u8, max_plaintext_len + 1);
    defer allocator.free(huge);
    @memset(huge, 'A');
    const scratch = try allocator.alloc(u8, max_ciphertext_len + 512);
    defer allocator.free(scratch);

    try testing.expectError(
        error.PlaintextTooLong,
        encodeInnerPlaintext(.application_data, huge, 0, scratch),
    );
    // At the maximum content length, padding that pushes the inner plaintext
    // past 2^14+256 must also be refused.
    try testing.expectError(
        error.RecordOverflow,
        encodeInnerPlaintext(.application_data, huge[0..max_plaintext_len], 512, scratch),
    );
    // An output buffer too small for the encoded inner plaintext is an error,
    // not a truncated write.
    var tiny: [4]u8 = undefined;
    try testing.expectError(
        error.OutputTooSmall,
        encodeInnerPlaintext(.application_data, "hello", 0, &tiny),
    );
}

test "exploit: an inner plaintext whose content exceeds 2^14 is rejected after decrypt" {
    // A record may legally carry up to 2^14+256 encrypted bytes, but the
    // recovered CONTENT is capped at 2^14. A peer packing content into the
    // padding allowance must be rejected rather than handed upstream.
    const testing = std.testing;
    const allocator = testing.allocator;
    const inner = try allocator.alloc(u8, max_plaintext_len + 8);
    defer allocator.free(inner);
    @memset(inner, 'B');
    inner[inner.len - 1] = @intFromEnum(ContentType.application_data);
    try testing.expectError(error.PlaintextTooLong, decodeInnerPlaintext(inner));
}

test "exploit: peer-advertised record_size_limit can never widen our records" {
    // RFC 8449. The limit is peer-controlled, so it must only ever shrink our
    // fragment size — a hostile 0/1/0xFFFF must not produce a larger bound than
    // the protocol maximum, nor a zero-length fragmentation loop.
    for ([_]usize{ 0, 1, 2, 64, record_size_limit_max, 0xFFFF, std.math.maxInt(usize) }) |limit| {
        const l13 = recordContentLimit(limit);
        try std.testing.expect(l13 >= 1);
        try std.testing.expect(l13 <= max_plaintext_len);

        const l12 = recordContentLimit12(limit);
        try std.testing.expect(l12 >= 1);
        try std.testing.expect(l12 <= max_plaintext_len);
    }
}

test {
    std.testing.refAllDecls(@This());
}
