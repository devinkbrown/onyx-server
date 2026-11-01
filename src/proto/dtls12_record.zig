// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! DTLS 1.2 record layer (RFC 6347 §4.1) — the *classic* record framing that
//! WebRTC endpoints speak, distinct from the DTLS 1.3 unified header in
//! `dtls_record.zig`.
//!
//! Covers the 13-byte DTLSPlaintext/DTLSCiphertext header
//! (`type || version || epoch || sequence_number(48) || length`), and
//! AES-128-GCM record protection (RFC 5288 / RFC 5246 §6.2.3.3) as used by the
//! WebRTC-mandatory `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` cipher suite: a
//! 4-byte fixed salt from the key block plus an 8-byte explicit nonce carried
//! on the wire, with the record's 64-bit `epoch||sequence` as the GCM AAD
//! sequence number.
//!
//! Pure and allocation-free; every parse is bounds-checked and returns an error
//! rather than trapping (this is public-internet UDP — treat input as hostile).
const std = @import("std");

const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

pub const dtls12_version: u16 = 0xfefd;
/// Serialised DTLSPlaintext record header width.
pub const record_header_len: usize = 13;
/// AES-GCM explicit (per-record) nonce carried before the ciphertext.
pub const gcm_explicit_nonce_len: usize = 8;
/// AES-128-GCM authentication tag width.
pub const gcm_tag_len: usize = 16;
/// AES-128-GCM fixed IV (salt) width, taken from the key block.
pub const gcm_salt_len: usize = 4;
/// AES-128 write key width.
pub const gcm_key_len: usize = 16;
/// Bytes GCM protection adds to a plaintext fragment.
pub const gcm_overhead: usize = gcm_explicit_nonce_len + gcm_tag_len;

pub const ContentType = enum(u8) {
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23,
    _,
};

pub const DecodeError = error{
    BufferTooShort,
    LengthOverflow,
    AuthenticationFailed,
};

pub const EncodeError = error{
    BufferTooSmall,
};

/// A DTLS 1.2 record header. `seq` is the 48-bit per-epoch record sequence
/// number; `epoch` and `seq` combine into the 64-bit AAD sequence number.
pub const RecordHeader = struct {
    content_type: ContentType,
    version: u16 = dtls12_version,
    epoch: u16,
    seq: u48,
    length: u16,

    /// The 64-bit sequence number (`epoch << 48 | seq`) used as the GCM AAD
    /// sequence number and as the conventional explicit nonce value.
    pub fn seqNum(self: RecordHeader) u64 {
        return (@as(u64, self.epoch) << 48) | @as(u64, self.seq);
    }

    pub fn encode(self: RecordHeader, out: []u8) EncodeError![]const u8 {
        if (out.len < record_header_len) return error.BufferTooSmall;
        out[0] = @backingInt(self.content_type);
        std.mem.writeInt(u16, out[1..][0..2], self.version, .big);
        std.mem.writeInt(u16, out[3..][0..2], self.epoch, .big);
        std.mem.writeInt(u48, out[5..][0..6], self.seq, .big);
        std.mem.writeInt(u16, out[11..][0..2], self.length, .big);
        return out[0..record_header_len];
    }

    /// Decode a record header and locate its fragment. Returns the header, the
    /// fragment slice (borrowing `buf`), and the total bytes consumed (header +
    /// fragment). The `length` field is bounds-checked against `buf`.
    pub fn decode(buf: []const u8) DecodeError!struct { hdr: RecordHeader, fragment: []const u8, consumed: usize } {
        if (buf.len < record_header_len) return error.BufferTooShort;
        const length = std.mem.readInt(u16, buf[11..][0..2], .big);
        const total = record_header_len + @as(usize, length);
        if (buf.len < total) return error.BufferTooShort;
        return .{
            .hdr = .{
                .content_type = @fromBackingInt(@intCast(buf[0])),
                .version = std.mem.readInt(u16, buf[1..][0..2], .big),
                .epoch = std.mem.readInt(u16, buf[3..][0..2], .big),
                .seq = std.mem.readInt(u48, buf[5..][0..6], .big),
                .length = length,
            },
            .fragment = buf[record_header_len..total],
            .consumed = total,
        };
    }
};

/// Write a whole plaintext (epoch-0) record — header + fragment — into `out`.
/// Returns the written slice.
pub fn writePlaintext(
    content_type: ContentType,
    epoch: u16,
    seq: u48,
    fragment: []const u8,
    out: []u8,
) EncodeError![]const u8 {
    if (fragment.len > std.math.maxInt(u16)) return error.BufferTooSmall;
    const total = record_header_len + fragment.len;
    if (out.len < total) return error.BufferTooSmall;
    const hdr = RecordHeader{
        .content_type = content_type,
        .epoch = epoch,
        .seq = seq,
        .length = @intCast(fragment.len),
    };
    _ = try hdr.encode(out[0..record_header_len]);
    @memcpy(out[record_header_len..total], fragment);
    return out[0..total];
}

/// Build the 13-byte GCM additional-authenticated-data:
/// `seq_num(8) || type(1) || version(2) || length(2)` where `length` is the
/// *plaintext* fragment length (RFC 5246 §6.2.3.3).
fn gcmAad(content_type: ContentType, version: u16, seq_num: u64, plaintext_len: u16) [13]u8 {
    var aad: [13]u8 = undefined;
    std.mem.writeInt(u64, aad[0..8], seq_num, .big);
    aad[8] = @backingInt(content_type);
    std.mem.writeInt(u16, aad[9..][0..2], version, .big);
    std.mem.writeInt(u16, aad[11..][0..2], plaintext_len, .big);
    return aad;
}

fn gcmNonce(salt: [gcm_salt_len]u8, explicit: [gcm_explicit_nonce_len]u8) [Aes128Gcm.nonce_length]u8 {
    var nonce: [Aes128Gcm.nonce_length]u8 = undefined;
    @memcpy(nonce[0..gcm_salt_len], &salt);
    @memcpy(nonce[gcm_salt_len..], &explicit);
    return nonce;
}

/// Seal a plaintext fragment into a GCM record fragment
/// (`explicit_nonce(8) || ciphertext || tag(16)`). The explicit nonce is the
/// record's 64-bit `epoch||seq`, matching the AAD sequence number. Returns the
/// sealed fragment slice (its length is what the record header's `length` must
/// carry).
pub fn sealGcm(
    key: [gcm_key_len]u8,
    salt: [gcm_salt_len]u8,
    content_type: ContentType,
    epoch: u16,
    seq: u48,
    plaintext: []const u8,
    out: []u8,
) EncodeError![]const u8 {
    if (plaintext.len > std.math.maxInt(u16)) return error.BufferTooSmall;
    const total = gcm_explicit_nonce_len + plaintext.len + gcm_tag_len;
    if (out.len < total) return error.BufferTooSmall;

    const seq_num = (@as(u64, epoch) << 48) | @as(u64, seq);
    var explicit: [gcm_explicit_nonce_len]u8 = undefined;
    std.mem.writeInt(u64, &explicit, seq_num, .big);
    @memcpy(out[0..gcm_explicit_nonce_len], &explicit);

    const aad = gcmAad(content_type, dtls12_version, seq_num, @intCast(plaintext.len));
    const ct = out[gcm_explicit_nonce_len..][0..plaintext.len];
    const tag = out[gcm_explicit_nonce_len + plaintext.len ..][0..gcm_tag_len];
    Aes128Gcm.encrypt(ct, tag, plaintext, &aad, gcmNonce(salt, explicit), key);
    return out[0..total];
}

/// Open a GCM record fragment. `seq_num` is the record header's 64-bit
/// `epoch||seq` (used for the AAD); the GCM nonce uses the wire explicit nonce.
/// Returns the recovered plaintext slice, or `AuthenticationFailed`.
pub fn openGcm(
    key: [gcm_key_len]u8,
    salt: [gcm_salt_len]u8,
    content_type: ContentType,
    seq_num: u64,
    fragment: []const u8,
    out: []u8,
) DecodeError![]const u8 {
    if (fragment.len < gcm_overhead) return error.BufferTooShort;
    const pt_len = fragment.len - gcm_overhead;
    if (out.len < pt_len) return error.BufferTooShort;
    if (pt_len > std.math.maxInt(u16)) return error.LengthOverflow;

    const explicit: [gcm_explicit_nonce_len]u8 = fragment[0..gcm_explicit_nonce_len].*;
    const ct = fragment[gcm_explicit_nonce_len..][0..pt_len];
    const tag: [gcm_tag_len]u8 = fragment[gcm_explicit_nonce_len + pt_len ..][0..gcm_tag_len].*;
    const aad = gcmAad(content_type, dtls12_version, seq_num, @intCast(pt_len));
    Aes128Gcm.decrypt(out[0..pt_len], ct, tag, &aad, gcmNonce(salt, explicit), key) catch
        return error.AuthenticationFailed;
    return out[0..pt_len];
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "record header encode/decode round-trips and locates the fragment" {
    const frag = "handshake-bytes";
    var buf: [record_header_len + frag.len]u8 = undefined;
    const wire = try writePlaintext(.handshake, 0, 0x0102030405, frag, &buf);
    try testing.expectEqual(@as(usize, record_header_len + frag.len), wire.len);

    const dec = try RecordHeader.decode(wire);
    try testing.expectEqual(ContentType.handshake, dec.hdr.content_type);
    try testing.expectEqual(@as(u16, dtls12_version), dec.hdr.version);
    try testing.expectEqual(@as(u16, 0), dec.hdr.epoch);
    try testing.expectEqual(@as(u48, 0x0102030405), dec.hdr.seq);
    try testing.expectEqual(@as(u16, frag.len), dec.hdr.length);
    try testing.expectEqualStrings(frag, dec.fragment);
    try testing.expectEqual(wire.len, dec.consumed);
}

test "record header seqNum combines epoch and seq" {
    const hdr = RecordHeader{ .content_type = .application_data, .epoch = 1, .seq = 5, .length = 0 };
    try testing.expectEqual(@as(u64, 0x0001_0000_0000_0005), hdr.seqNum());
}

test "record decode rejects a truncated fragment" {
    // header claims length 100 but buffer is short.
    var buf: [record_header_len]u8 = undefined;
    const hdr = RecordHeader{ .content_type = .handshake, .epoch = 0, .seq = 0, .length = 100 };
    _ = try hdr.encode(&buf);
    try testing.expectError(error.BufferTooShort, RecordHeader.decode(&buf));
}

test "record decode rejects a runt header" {
    try testing.expectError(error.BufferTooShort, RecordHeader.decode(&.{ 22, 0xfe }));
}

test "GCM seal/open round-trips" {
    const key: [gcm_key_len]u8 = @splat(0x11);
    const salt: [gcm_salt_len]u8 = @splat(0x22);
    const pt = "server finished verify_data (encrypted)";

    var sealed: [gcm_explicit_nonce_len + pt.len + gcm_tag_len]u8 = undefined;
    const frag = try sealGcm(key, salt, .handshake, 1, 0, pt, &sealed);
    try testing.expectEqual(@as(usize, gcm_explicit_nonce_len + pt.len + gcm_tag_len), frag.len);

    // Explicit nonce equals the record seq_num (epoch 1, seq 0).
    var expect_nonce: [gcm_explicit_nonce_len]u8 = undefined;
    std.mem.writeInt(u64, &expect_nonce, (@as(u64, 1) << 48) | 0, .big);
    try testing.expectEqualSlices(u8, &expect_nonce, frag[0..gcm_explicit_nonce_len]);

    var opened: [pt.len]u8 = undefined;
    const seq_num = (@as(u64, 1) << 48) | 0;
    const got = try openGcm(key, salt, .handshake, seq_num, frag, &opened);
    try testing.expectEqualStrings(pt, got);
}

test "GCM open rejects a tampered fragment" {
    const key: [gcm_key_len]u8 = @splat(0x33);
    const salt: [gcm_salt_len]u8 = @splat(0x44);
    const pt = "payload";
    var sealed: [gcm_explicit_nonce_len + pt.len + gcm_tag_len]u8 = undefined;
    const frag = try sealGcm(key, salt, .application_data, 1, 7, pt, &sealed);

    var tampered: [gcm_explicit_nonce_len + pt.len + gcm_tag_len]u8 = undefined;
    @memcpy(&tampered, frag);
    tampered[gcm_explicit_nonce_len] ^= 0x01; // flip a ciphertext bit
    var opened: [pt.len]u8 = undefined;
    try testing.expectError(
        error.AuthenticationFailed,
        openGcm(key, salt, .application_data, (@as(u64, 1) << 48) | 7, &tampered, &opened),
    );
}

test "GCM open rejects a wrong-seq AAD" {
    const key: [gcm_key_len]u8 = @splat(0x55);
    const salt: [gcm_salt_len]u8 = @splat(0x66);
    const pt = "seq-bound";
    var sealed: [gcm_explicit_nonce_len + pt.len + gcm_tag_len]u8 = undefined;
    const frag = try sealGcm(key, salt, .handshake, 1, 3, pt, &sealed);
    var opened: [pt.len]u8 = undefined;
    // Same fragment (explicit nonce says seq 3) but AAD claims seq 4 → fails.
    try testing.expectError(
        error.AuthenticationFailed,
        openGcm(key, salt, .handshake, (@as(u64, 1) << 48) | 4, frag, &opened),
    );
}

test "GCM open rejects a runt fragment" {
    const key: [gcm_key_len]u8 = @splat(0);
    const salt: [gcm_salt_len]u8 = @splat(0);
    var opened: [4]u8 = undefined;
    try testing.expectError(error.BufferTooShort, openGcm(key, salt, .handshake, 0, "short", &opened));
}
