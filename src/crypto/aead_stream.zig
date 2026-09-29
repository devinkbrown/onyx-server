// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Segmented STREAM-style AEAD over ChaCha20-Poly1305.
//!
//! Each plaintext chunk is encrypted independently with a nonce derived from a
//! per-stream base nonce, a monotonic u32 counter, and the last-block flag. The
//! sealed wire chunk carries the base nonce, counter, final bit, ciphertext, and
//! tag. The header is authenticated as AEAD associated data, so modifying the
//! counter or final bit invalidates the tag.
const std = @import("std");

const Aead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

pub const key_len = Aead.key_length;
pub const base_nonce_len = 7;
pub const nonce_len = Aead.nonce_length;
pub const tag_len = Aead.tag_length;
pub const header_len = 17;
pub const max_chunk_overhead = header_len + tag_len;

const magic = [_]u8{ 'M', 'Z', 'S', '1' };
const version: u8 = 1;
const flag_final: u8 = 0x01;
const allowed_flags: u8 = flag_final;

pub const Key = [key_len]u8;
pub const BaseNonce = [base_nonce_len]u8;
pub const Nonce = [nonce_len]u8;
pub const Tag = [tag_len]u8;

pub const Error = error{
    AuthFailed,
    CounterExhausted,
    MalformedChunk,
    MissingFinalBlock,
    StreamAlreadyEnded,
    UnexpectedChunk,
} || std.mem.Allocator.Error;

pub const PullResult = struct {
    /// Caller owns this buffer and must free it with the allocator passed to
    /// `pull`.
    plaintext: []u8,
    is_final: bool,
};

const Header = struct {
    flags: u8,
    base_nonce: BaseNonce,
    counter: u32,

    fn init(base_nonce: BaseNonce, counter: u32, is_final: bool) Header {
        return .{
            .flags = if (is_final) flag_final else 0,
            .base_nonce = base_nonce,
            .counter = counter,
        };
    }

    fn encode(self: Header) [header_len]u8 {
        var out: [header_len]u8 = undefined;
        @memcpy(out[0..magic.len], &magic);
        out[4] = version;
        out[5] = self.flags;
        @memcpy(out[6..][0..base_nonce_len], &self.base_nonce);
        std.mem.writeInt(u32, out[13..][0..4], self.counter, .big);
        return out;
    }

    fn decode(sealed: []const u8) Error!Header {
        if (sealed.len < max_chunk_overhead) return Error.MalformedChunk;
        if (!std.mem.eql(u8, sealed[0..magic.len], &magic)) return Error.MalformedChunk;
        if (sealed[4] != version) return Error.MalformedChunk;
        if ((sealed[5] & ~allowed_flags) != 0) return Error.MalformedChunk;

        var base_nonce: BaseNonce = undefined;
        @memcpy(&base_nonce, sealed[6..][0..base_nonce_len]);

        return .{
            .flags = sealed[5],
            .base_nonce = base_nonce,
            .counter = std.mem.readInt(u32, sealed[13..][0..4], .big),
        };
    }

    fn isFinal(self: Header) bool {
        return (self.flags & flag_final) != 0;
    }
};

fn deriveNonce(base_nonce: BaseNonce, counter: u32, is_final: bool) Nonce {
    var nonce: Nonce = undefined;
    @memcpy(nonce[0..base_nonce_len], &base_nonce);
    nonce[base_nonce_len] = if (is_final) 1 else 0;
    std.mem.writeInt(u32, nonce[base_nonce_len + 1 ..][0..4], counter, .big);
    return nonce;
}

pub fn sealedLen(plaintext_len: usize) usize {
    return max_chunk_overhead + plaintext_len;
}

pub fn plaintextLen(sealed_len: usize) Error!usize {
    if (sealed_len < max_chunk_overhead) return Error.MalformedChunk;
    return sealed_len - max_chunk_overhead;
}

/// Stateful chunk encryptor. `init` generates a fresh random base nonce.
pub const Encryptor = struct {
    key: Key,
    base_nonce: BaseNonce,
    counter: u32 = 0,
    ended: bool = false,

    pub fn init(key: Key) Encryptor {
        var base_nonce: BaseNonce = undefined;
        std.crypto.random.bytes(&base_nonce);
        return initWithNonce(key, base_nonce);
    }

    pub fn initWithNonce(key: Key, base_nonce: BaseNonce) Encryptor {
        return .{
            .key = key,
            .base_nonce = base_nonce,
        };
    }

    /// Encrypt one chunk and return an owned sealed buffer.
    ///
    /// The caller owns the returned buffer and must free it with `allocator`.
    pub fn push(
        self: *Encryptor,
        allocator: std.mem.Allocator,
        plaintext: []const u8,
        is_final: bool,
    ) Error![]u8 {
        if (self.ended) return Error.StreamAlreadyEnded;
        if (self.counter == std.math.maxInt(u32) and !is_final) return Error.CounterExhausted;

        var sealed = try allocator.alloc(u8, sealedLen(plaintext.len));
        errdefer allocator.free(sealed);

        const header = Header.init(self.base_nonce, self.counter, is_final);
        const header_bytes = header.encode();
        @memcpy(sealed[0..header_len], &header_bytes);

        const ciphertext = sealed[header_len .. sealed.len - tag_len];
        var tag: Tag = undefined;
        const nonce = deriveNonce(self.base_nonce, self.counter, is_final);
        Aead.encrypt(ciphertext, &tag, plaintext, sealed[0..header_len], nonce, self.key);
        @memcpy(sealed[sealed.len - tag_len ..], &tag);

        if (is_final) {
            self.ended = true;
        } else {
            self.counter += 1;
        }
        return sealed;
    }
};

/// Stateful chunk decryptor. Call `finish` after the transport reaches EOF to
/// reject streams that never delivered an authenticated final chunk.
pub const Decryptor = struct {
    key: Key,
    base_nonce: BaseNonce = @splat(0),
    have_base_nonce: bool = false,
    expected_counter: u32 = 0,
    ended: bool = false,

    pub fn init(key: Key) Decryptor {
        return .{ .key = key };
    }

    /// Decrypt one sealed chunk and return an owned plaintext buffer.
    ///
    /// The caller owns `PullResult.plaintext` and must free it with
    /// `allocator`.
    pub fn pull(
        self: *Decryptor,
        allocator: std.mem.Allocator,
        sealed: []const u8,
    ) Error!PullResult {
        if (self.ended) return Error.StreamAlreadyEnded;

        const header = try Header.decode(sealed);
        if (header.counter != self.expected_counter) return Error.UnexpectedChunk;
        if (self.have_base_nonce) {
            if (!std.mem.eql(u8, &self.base_nonce, &header.base_nonce)) return Error.UnexpectedChunk;
        }

        const ct_len = try plaintextLen(sealed.len);
        const plaintext = try allocator.alloc(u8, ct_len);
        errdefer allocator.free(plaintext);

        const ciphertext = sealed[header_len .. sealed.len - tag_len];
        const tag: Tag = sealed[sealed.len - tag_len ..][0..tag_len].*;
        const nonce = deriveNonce(header.base_nonce, header.counter, header.isFinal());
        Aead.decrypt(plaintext, ciphertext, tag, sealed[0..header_len], nonce, self.key) catch {
            return Error.AuthFailed;
        };
        // A non-final chunk at u32::MAX would wrap expected_counter back to 0.
        if (!header.isFinal() and self.expected_counter == std.math.maxInt(u32)) return Error.CounterExhausted;

        if (!self.have_base_nonce) {
            self.base_nonce = header.base_nonce;
            self.have_base_nonce = true;
        }
        if (header.isFinal()) {
            self.ended = true;
        } else {
            self.expected_counter += 1;
        }

        return .{
            .plaintext = plaintext,
            .is_final = header.isFinal(),
        };
    }

    pub fn finish(self: *const Decryptor) Error!void {
        if (!self.ended) return Error.MissingFinalBlock;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

const fixed_key: Key = [_]u8{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};

const fixed_nonce: BaseNonce = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6 };

fn expectPull(
    dec: *Decryptor,
    sealed: []const u8,
    expected_plaintext: []const u8,
    expected_final: bool,
) !void {
    const pulled = try dec.pull(testing.allocator, sealed);
    defer testing.allocator.free(pulled.plaintext);
    try testing.expectEqual(expected_final, pulled.is_final);
    try testing.expectEqualSlices(u8, expected_plaintext, pulled.plaintext);
}

test "multi-chunk round-trip preserves plaintext and final marker" {
    var enc = Encryptor.initWithNonce(fixed_key, fixed_nonce);
    var dec = Decryptor.init(fixed_key);

    const s0 = try enc.push(testing.allocator, "onyx ", false);
    defer testing.allocator.free(s0);
    const s1 = try enc.push(testing.allocator, "stream ", false);
    defer testing.allocator.free(s1);
    const s2 = try enc.push(testing.allocator, "aead", true);
    defer testing.allocator.free(s2);

    try expectPull(&dec, s0, "onyx ", false);
    try expectPull(&dec, s1, "stream ", false);
    try expectPull(&dec, s2, "aead", true);
    try dec.finish();
}

test "reordered chunk is rejected before decryption" {
    var enc = Encryptor.initWithNonce(fixed_key, fixed_nonce);
    var dec = Decryptor.init(fixed_key);

    const first = try enc.push(testing.allocator, "first", false);
    defer testing.allocator.free(first);
    const second = try enc.push(testing.allocator, "second", true);
    defer testing.allocator.free(second);

    try testing.expectError(Error.UnexpectedChunk, dec.pull(testing.allocator, second));
    try expectPull(&dec, first, "first", false);
    try expectPull(&dec, second, "second", true);
}

test "truncated stream missing final chunk is detected by finish" {
    var enc = Encryptor.initWithNonce(fixed_key, fixed_nonce);
    var dec = Decryptor.init(fixed_key);

    const first = try enc.push(testing.allocator, "only non-final chunk", false);
    defer testing.allocator.free(first);

    try expectPull(&dec, first, "only non-final chunk", false);
    try testing.expectError(Error.MissingFinalBlock, dec.finish());
}

test "tampered ciphertext or tag is rejected" {
    var enc = Encryptor.initWithNonce(fixed_key, fixed_nonce);
    var dec_ciphertext = Decryptor.init(fixed_key);
    var dec_tag = Decryptor.init(fixed_key);

    const sealed = try enc.push(testing.allocator, "authenticated plaintext", true);
    defer testing.allocator.free(sealed);

    const tampered_ciphertext = try testing.allocator.dupe(u8, sealed);
    defer testing.allocator.free(tampered_ciphertext);
    tampered_ciphertext[header_len] ^= 0x80;
    try testing.expectError(Error.AuthFailed, dec_ciphertext.pull(testing.allocator, tampered_ciphertext));

    const tampered_tag = try testing.allocator.dupe(u8, sealed);
    defer testing.allocator.free(tampered_tag);
    tampered_tag[tampered_tag.len - 1] ^= 0x01;
    try testing.expectError(Error.AuthFailed, dec_tag.pull(testing.allocator, tampered_tag));
}

test "final-flag forgery is rejected" {
    var enc = Encryptor.initWithNonce(fixed_key, fixed_nonce);
    var dec = Decryptor.init(fixed_key);

    const sealed = try enc.push(testing.allocator, "not final yet", false);
    defer testing.allocator.free(sealed);

    const forged_final = try testing.allocator.dupe(u8, sealed);
    defer testing.allocator.free(forged_final);
    forged_final[5] |= flag_final;

    try testing.expectError(Error.AuthFailed, dec.pull(testing.allocator, forged_final));
}

test "failed first-chunk authentication does not poison decryptor state" {
    const other_nonce: BaseNonce = [_]u8{ 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6 };
    var attacker_enc = Encryptor.initWithNonce(fixed_key, other_nonce);
    var real_enc = Encryptor.initWithNonce(fixed_key, fixed_nonce);
    var dec = Decryptor.init(fixed_key);

    const forged = try attacker_enc.push(testing.allocator, "forged", false);
    defer testing.allocator.free(forged);
    forged[forged.len - 1] ^= 0x22;
    try testing.expectError(Error.AuthFailed, dec.pull(testing.allocator, forged));

    const real = try real_enc.push(testing.allocator, "real first", true);
    defer testing.allocator.free(real);
    try expectPull(&dec, real, "real first", true);
    try dec.finish();
}

test "deterministic with fixed key and nonce" {
    var enc_a = Encryptor.initWithNonce(fixed_key, fixed_nonce);
    var enc_b = Encryptor.initWithNonce(fixed_key, fixed_nonce);

    const a0 = try enc_a.push(testing.allocator, "alpha", false);
    defer testing.allocator.free(a0);
    const a1 = try enc_a.push(testing.allocator, "omega", true);
    defer testing.allocator.free(a1);

    const b0 = try enc_b.push(testing.allocator, "alpha", false);
    defer testing.allocator.free(b0);
    const b1 = try enc_b.push(testing.allocator, "omega", true);
    defer testing.allocator.free(b1);

    try testing.expectEqualSlices(u8, a0, b0);
    try testing.expectEqualSlices(u8, a1, b1);
}

test "empty final chunk round-trips and closes stream" {
    var enc = Encryptor.initWithNonce(fixed_key, fixed_nonce);
    var dec = Decryptor.init(fixed_key);

    const sealed = try enc.push(testing.allocator, "", true);
    defer testing.allocator.free(sealed);

    try expectPull(&dec, sealed, "", true);
    try dec.finish();
    try testing.expectError(Error.StreamAlreadyEnded, dec.pull(testing.allocator, sealed));
    try testing.expectError(Error.StreamAlreadyEnded, enc.push(testing.allocator, "", true));
}

test "decryptor refuses an authenticated nonfinal chunk at exhausted counter" {
    var dec = Decryptor.init(fixed_key);
    dec.expected_counter = std.math.maxInt(u32);

    const header = Header.init(fixed_nonce, std.math.maxInt(u32), false).encode();
    var sealed: [header_len + 1 + tag_len]u8 = undefined;
    @memcpy(sealed[0..header_len], &header);
    var tag: Tag = undefined;
    Aead.encrypt(sealed[header_len .. header_len + 1], &tag, "x", sealed[0..header_len], deriveNonce(fixed_nonce, std.math.maxInt(u32), false), fixed_key);
    @memcpy(sealed[header_len + 1 ..], &tag);

    try testing.expectError(Error.CounterExhausted, dec.pull(testing.allocator, &sealed));
    try testing.expectEqual(std.math.maxInt(u32), dec.expected_counter);
    try testing.expectError(Error.MissingFinalBlock, dec.finish());
}
