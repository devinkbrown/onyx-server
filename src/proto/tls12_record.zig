// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! TLS 1.2 AEAD record layer.
//!
//! Implements the two modern AEAD record constructions used by TLS 1.2:
//!
//!   * AES-GCM (RFC 5288): the per-record nonce is a 4-byte fixed salt taken
//!     from the key_block (one salt per direction, constant for the life of the
//!     connection) concatenated with an 8-byte explicit nonce that is chosen
//!     by the sender and transmitted on the wire, prepended to the ciphertext.
//!     The additional data is
//!         seq_num(8) || type(1) || version(2) || length(2)
//!     where `length` is the plaintext length.
//!
//!   * ChaCha20-Poly1305 (RFC 7905): there is NO explicit nonce on the wire.
//!     The 12-byte nonce is the per-direction write IV XOR'd with the 64-bit
//!     sequence number (right-aligned), exactly as in TLS 1.3. The additional
//!     data uses the same seq||type||version||length layout as AES-GCM above.
//!
//! This is pure, caller-buffered code: it depends only on std.crypto AEAD
//! primitives and never allocates. On any authentication-tag mismatch (or
//! mismatched AAD / sequence number) decryption fails with error.AuthFailed.

const std = @import("std");

/// Maximum TLSPlaintext fragment length (2^14) per RFC 5246 section 6.2.1.
pub const max_plaintext_len: usize = 16 * 1024;

/// Length of the explicit (per-record, on-wire) nonce for AES-GCM.
pub const explicit_nonce_len: usize = 8;

/// Length of the AES-GCM fixed salt taken from the key_block.
pub const salt_len: usize = 4;

/// Length of the assembled AEAD nonce shared by all constructions here.
pub const aead_nonce_len: usize = 12;

/// Length of the ChaCha20-Poly1305 per-direction write IV.
pub const chacha_iv_len: usize = 12;

/// Length of the TLS 1.2 additional-data block: seq(8)||type(1)||ver(2)||len(2).
pub const aad_len: usize = 13;

pub const Error = error{
    /// AEAD tag verification failed, or the record is malformed/too short.
    AuthFailed,
    /// The caller-supplied output buffer cannot hold the result.
    NoSpaceLeft,
};

/// TLS record content types (RFC 5246 section 6.2.1).
pub const ContentType = enum(u8) {
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23,

    pub fn toWire(self: ContentType) u8 {
        return @backingInt(self);
    }
};

/// Build the 13-byte TLS 1.2 additional-data block.
///
///     seq_num(8, big-endian) || type(1) || version(2, big-endian) || length(2)
///
/// `length` is the plaintext length (RFC 5246 section 6.2.3.3).
fn buildAad(
    seq: u64,
    content_type: ContentType,
    version: u16,
    length: u16,
) [aad_len]u8 {
    var aad: [aad_len]u8 = undefined;
    std.mem.writeInt(u64, aad[0..8], seq, .big);
    aad[8] = content_type.toWire();
    std.mem.writeInt(u16, aad[9..11], version, .big);
    std.mem.writeInt(u16, aad[11..13], length, .big);
    return aad;
}

/// Derive the AES-GCM nonce: salt(4) || explicit(8).
fn aesGcmNonce(salt: [salt_len]u8, explicit: [explicit_nonce_len]u8) [aead_nonce_len]u8 {
    var nonce: [aead_nonce_len]u8 = undefined;
    @memcpy(nonce[0..salt_len], &salt);
    @memcpy(nonce[salt_len..aead_nonce_len], &explicit);
    return nonce;
}

/// Derive the ChaCha20-Poly1305 nonce (RFC 7905): write_iv XOR right-aligned seq.
fn chachaNonce(write_iv: [chacha_iv_len]u8, seq: u64) [aead_nonce_len]u8 {
    var nonce = write_iv;
    var seq_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &seq_bytes, seq, .big);
    // Right-align the 8-byte sequence number against the 12-byte IV.
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        nonce[aead_nonce_len - 8 + i] ^= seq_bytes[i];
    }
    return nonce;
}

/// AES-GCM record sealer/opener (RFC 5288), generic over the std AEAD impl.
///
/// `Impl` must be std.crypto.aead.aes_gcm.Aes128Gcm or Aes256Gcm.
pub fn AesGcm(comptime Impl: type) type {
    comptime std.debug.assert(Impl.nonce_length == aead_nonce_len);

    return struct {
        pub const Key = [Impl.key_length]u8;
        pub const Salt = [salt_len]u8;
        pub const tag_length = Impl.tag_length;
        pub const key_length = Impl.key_length;

        pub const Sealer = struct {
            /// Encrypt `plaintext` into `out` as
            ///     explicit_nonce(8) || ciphertext || tag(16)
            ///
            /// The explicit nonce is derived deterministically from the 64-bit
            /// sequence number, which is unique per record for the connection
            /// and therefore yields a unique GCM nonce given the fixed salt.
            /// Returns the populated slice of `out`.
            pub fn seal(
                out: []u8,
                plaintext: []const u8,
                content_type: ContentType,
                version: u16,
                seq: u64,
                key: Key,
                salt: Salt,
            ) Error![]const u8 {
                if (plaintext.len > max_plaintext_len) return Error.NoSpaceLeft;
                const total = explicit_nonce_len + plaintext.len + tag_length;
                if (out.len < total) return Error.NoSpaceLeft;

                var explicit: [explicit_nonce_len]u8 = undefined;
                std.mem.writeInt(u64, &explicit, seq, .big);
                @memcpy(out[0..explicit_nonce_len], &explicit);

                const nonce = aesGcmNonce(salt, explicit);
                const aad = buildAad(seq, content_type, version, @intCast(plaintext.len));

                const ct = out[explicit_nonce_len .. explicit_nonce_len + plaintext.len];
                var tag: [tag_length]u8 = undefined;
                Impl.encrypt(ct, &tag, plaintext, &aad, nonce, key);
                @memcpy(out[explicit_nonce_len + plaintext.len .. total], &tag);
                return out[0..total];
            }
        };

        pub const Opener = struct {
            /// Decrypt a wire record of the form
            ///     explicit_nonce(8) || ciphertext || tag(16)
            /// into `out`, returning the recovered plaintext slice.
            ///
            /// Fails with error.AuthFailed on any tag/AAD/seq mismatch.
            pub fn open(
                out: []u8,
                record: []const u8,
                content_type: ContentType,
                version: u16,
                seq: u64,
                key: Key,
                salt: Salt,
            ) Error![]const u8 {
                const overhead = explicit_nonce_len + tag_length;
                if (record.len < overhead) return Error.AuthFailed;
                const pt_len = record.len - overhead;
                if (out.len < pt_len) return Error.NoSpaceLeft;

                var explicit: [explicit_nonce_len]u8 = undefined;
                @memcpy(&explicit, record[0..explicit_nonce_len]);
                const nonce = aesGcmNonce(salt, explicit);
                const aad = buildAad(seq, content_type, version, @intCast(pt_len));

                const ct = record[explicit_nonce_len .. explicit_nonce_len + pt_len];
                var tag: [tag_length]u8 = undefined;
                @memcpy(&tag, record[explicit_nonce_len + pt_len ..]);

                const pt = out[0..pt_len];
                Impl.decrypt(pt, ct, tag, &aad, nonce, key) catch return Error.AuthFailed;
                return pt;
            }
        };
    };
}

/// ChaCha20-Poly1305 record sealer/opener (RFC 7905).
///
/// No explicit nonce is carried on the wire; the nonce is derived from the
/// per-direction write IV XOR'd with the sequence number, as in TLS 1.3.
pub const ChaCha = struct {
    const Impl = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

    pub const Key = [Impl.key_length]u8;
    pub const WriteIv = [chacha_iv_len]u8;
    pub const tag_length = Impl.tag_length;
    pub const key_length = Impl.key_length;

    comptime {
        std.debug.assert(Impl.nonce_length == aead_nonce_len);
    }

    pub const Sealer = struct {
        /// Encrypt `plaintext` into `out` as ciphertext || tag(16).
        /// Returns the populated slice of `out`.
        pub fn seal(
            out: []u8,
            plaintext: []const u8,
            content_type: ContentType,
            version: u16,
            seq: u64,
            key: Key,
            write_iv: WriteIv,
        ) Error![]const u8 {
            if (plaintext.len > max_plaintext_len) return Error.NoSpaceLeft;
            const total = plaintext.len + tag_length;
            if (out.len < total) return Error.NoSpaceLeft;

            const nonce = chachaNonce(write_iv, seq);
            const aad = buildAad(seq, content_type, version, @intCast(plaintext.len));

            const ct = out[0..plaintext.len];
            var tag: [tag_length]u8 = undefined;
            Impl.encrypt(ct, &tag, plaintext, &aad, nonce, key);
            @memcpy(out[plaintext.len..total], &tag);
            return out[0..total];
        }
    };

    pub const Opener = struct {
        /// Decrypt a wire record of the form ciphertext || tag(16) into `out`.
        /// Fails with error.AuthFailed on any tag/AAD/seq mismatch.
        pub fn open(
            out: []u8,
            record: []const u8,
            content_type: ContentType,
            version: u16,
            seq: u64,
            key: Key,
            write_iv: WriteIv,
        ) Error![]const u8 {
            if (record.len < tag_length) return Error.AuthFailed;
            const pt_len = record.len - tag_length;
            if (out.len < pt_len) return Error.NoSpaceLeft;

            const nonce = chachaNonce(write_iv, seq);
            const aad = buildAad(seq, content_type, version, @intCast(pt_len));

            const ct = record[0..pt_len];
            var tag: [tag_length]u8 = undefined;
            @memcpy(&tag, record[pt_len..]);

            const pt = out[0..pt_len];
            Impl.decrypt(pt, ct, tag, &aad, nonce, key) catch return Error.AuthFailed;
            return pt;
        }
    };
};

/// Convenience aliases for the two AES-GCM cipher suites.
pub const Aes128Gcm = AesGcm(std.crypto.aead.aes_gcm.Aes128Gcm);
pub const Aes256Gcm = AesGcm(std.crypto.aead.aes_gcm.Aes256Gcm);

const tls12_version: u16 = 0x0303;

const expectEqualSlices = std.testing.expectEqualSlices;
const expectEqual = std.testing.expectEqual;
const expectError = std.testing.expectError;

test "AES-GCM round-trip recovers plaintext for both key sizes" {
    // Arrange.
    inline for (.{ Aes128Gcm, Aes256Gcm }, .{ 16, 32 }) |Suite, _| {
        const key: Suite.Key = @splat(0x11);
        const salt: Suite.Salt = .{ 0xaa, 0xbb, 0xcc, 0xdd };
        const plaintext = "the quick brown fox jumps over the lazy dog";
        const seq: u64 = 7;
        var sealed: [256]u8 = undefined;
        var opened: [256]u8 = undefined;

        // Act.
        const record = try Suite.Sealer.seal(&sealed, plaintext, .application_data, tls12_version, seq, key, salt);
        const recovered = try Suite.Opener.open(&opened, record, .application_data, tls12_version, seq, key, salt);

        // Assert.
        try expectEqualSlices(u8, plaintext, recovered);
    }
}

test "AES-128-GCM explicit-nonce framing is correct" {
    // Arrange.
    const key: Aes128Gcm.Key = @splat(0x22);
    const salt: Aes128Gcm.Salt = .{ 1, 2, 3, 4 };
    const plaintext = "framing";
    const seq: u64 = 0x0102030405060708;
    var sealed: [128]u8 = undefined;

    // Act.
    const record = try Aes128Gcm.Sealer.seal(&sealed, plaintext, .handshake, tls12_version, seq, key, salt);

    // Assert: layout is explicit_nonce(8) || ciphertext || tag(16), and the
    // explicit nonce equals the big-endian sequence number.
    try expectEqual(explicit_nonce_len + plaintext.len + Aes128Gcm.tag_length, record.len);
    var expect_explicit: [8]u8 = undefined;
    std.mem.writeInt(u64, &expect_explicit, seq, .big);
    try expectEqualSlices(u8, &expect_explicit, record[0..8]);
}

test "AES-128-GCM tampered tag yields AuthFailed" {
    // Arrange.
    const key: Aes128Gcm.Key = @splat(0x33);
    const salt: Aes128Gcm.Salt = .{ 9, 8, 7, 6 };
    const plaintext = "do not tamper";
    const seq: u64 = 3;
    var sealed: [128]u8 = undefined;
    var opened: [128]u8 = undefined;
    const record = try Aes128Gcm.Sealer.seal(&sealed, plaintext, .application_data, tls12_version, seq, key, salt);

    // Act: flip a bit in the trailing tag.
    sealed[record.len - 1] ^= 0x01;
    const result = Aes128Gcm.Opener.open(&opened, record, .application_data, tls12_version, seq, key, salt);

    // Assert.
    try expectError(Error.AuthFailed, result);
}

test "AES-128-GCM sequence-number mismatch yields AuthFailed" {
    // Arrange.
    const key: Aes128Gcm.Key = @splat(0x44);
    const salt: Aes128Gcm.Salt = .{ 4, 4, 4, 4 };
    const plaintext = "seq must match";
    var sealed: [128]u8 = undefined;
    var opened: [128]u8 = undefined;
    const record = try Aes128Gcm.Sealer.seal(&sealed, plaintext, .application_data, tls12_version, 10, key, salt);

    // Act: open under a different sequence number (AAD seq differs).
    const result = Aes128Gcm.Opener.open(&opened, record, .application_data, tls12_version, 11, key, salt);

    // Assert.
    try expectError(Error.AuthFailed, result);
}

test "ChaCha20-Poly1305 round-trip with no explicit nonce on the wire" {
    // Arrange.
    const key: ChaCha.Key = @splat(0x66);
    const iv: ChaCha.WriteIv = @splat(0x77);
    const plaintext = "rfc 7905 chacha record";
    const seq: u64 = 42;
    var sealed: [128]u8 = undefined;
    var opened: [128]u8 = undefined;

    // Act.
    const record = try ChaCha.Sealer.seal(&sealed, plaintext, .application_data, tls12_version, seq, key, iv);
    const recovered = try ChaCha.Opener.open(&opened, record, .application_data, tls12_version, seq, key, iv);

    // Assert: record is ciphertext || tag, with no explicit nonce prefix.
    try expectEqual(plaintext.len + ChaCha.tag_length, record.len);
    try expectEqualSlices(u8, plaintext, recovered);
}

test "ChaCha20-Poly1305 content-type mismatch yields AuthFailed" {
    // Arrange.
    const key: ChaCha.Key = @splat(0x88);
    const iv: ChaCha.WriteIv = @splat(0x99);
    const plaintext = "aad binds content type";
    const seq: u64 = 5;
    var sealed: [128]u8 = undefined;
    var opened: [128]u8 = undefined;
    const record = try ChaCha.Sealer.seal(&sealed, plaintext, .application_data, tls12_version, seq, key, iv);

    // Act: open claiming a different content type (AAD differs).
    const result = ChaCha.Opener.open(&opened, record, .handshake, tls12_version, seq, key, iv);

    // Assert.
    try expectError(Error.AuthFailed, result);
}

test "nonce derivation: AES-GCM is salt||explicit and ChaCha is IV xor seq" {
    // Arrange.
    const salt: [salt_len]u8 = .{ 0x01, 0x02, 0x03, 0x04 };
    const explicit: [explicit_nonce_len]u8 = .{ 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
    const iv: [chacha_iv_len]u8 = @splat(0);

    // Act.
    const gcm_nonce = aesGcmNonce(salt, explicit);
    const cc_nonce = chachaNonce(iv, 0xff);

    // Assert.
    const want_gcm = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
    try expectEqualSlices(u8, &want_gcm, &gcm_nonce);
    var want_cc = @as([12]u8, @splat(0));
    want_cc[11] = 0xff;
    try expectEqualSlices(u8, &want_cc, &cc_nonce);
}
