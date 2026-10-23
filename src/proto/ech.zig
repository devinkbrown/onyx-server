// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! TLS Encrypted Client Hello (ECH) config framing.
//!
//! Implements ECHConfig, ECHConfigList, and ECHClientHello wire structures.
//! Handles encode/decode and config selection only; HPKE sealing is left to
//! the caller.  All allocations use a caller-supplied allocator; call `deinit`
//! to release owned slices produced by `decode`.
//!
//! Roadmap note (2026-07-06, roadmap 5.1): the LIVE client-side ECH path does NOT use
//! this module. It uses the zero-allocation `proto/ech_config.zig` (which
//! retains each config's raw bytes for the HPKE `info`, skips unknown-version
//! entries, and validates the public_name / KEM / mandatory extensions) plus
//! `crypto/ech_seal.zig` for the seal + acceptance confirmation. This module
//! remains an unwired encode/decode library. When server-side ECH lands (it
//! needs owned decodes to hold private keys), reconcile the two onto a single
//! parser that also exposes a borrowed `raw: []const u8` per entry — see
//! `ech_config.zig`'s header. Also note `ECHClientHello` here is missing the
//! current-draft outer fields (`type` + `HpkeSymmetricCipherSuite`); the live
//! outer extension is built in `ech_seal.writeOuterExtBody`.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const ArrayList = std.ArrayListUnmanaged;

pub const ECH_VERSION: u16 = 0xfe0d;
pub const MAX_PUBLIC_NAME_LEN: usize = 255;
pub const MAX_PUBLIC_KEY_LEN: usize = 65;

// HPKE algorithm identifiers (RFC 9180 §7).

pub const KemId = enum(u16) {
    dhkem_p256_hkdf_sha256 = 0x0010,
    dhkem_p384_hkdf_sha384 = 0x0011,
    dhkem_p521_hkdf_sha512 = 0x0012,
    dhkem_x25519_hkdf_sha256 = 0x0020,
    dhkem_x448_hkdf_sha512 = 0x0021,
    _,

    pub fn encLen(self: KemId) usize {
        return switch (self) {
            .dhkem_p256_hkdf_sha256 => 65,
            .dhkem_p384_hkdf_sha384 => 97,
            .dhkem_p521_hkdf_sha512 => 133,
            .dhkem_x25519_hkdf_sha256 => 32,
            .dhkem_x448_hkdf_sha512 => 56,
            _ => 0,
        };
    }
};

pub const KdfId = enum(u16) {
    hkdf_sha256 = 0x0001,
    hkdf_sha384 = 0x0002,
    hkdf_sha512 = 0x0003,
    _,
};

pub const AeadId = enum(u16) {
    aes_128_gcm = 0x0001,
    aes_256_gcm = 0x0002,
    chacha20_poly1305 = 0x0003,
    export_only = 0xffff,
    _,
};

pub const EncodeError = error{
    BufferTooSmall,
    PublicNameTooLong,
    PublicKeyTooLong,
    TooManyCipherSuites,
    TooManyConfigs,
    TooManyExtensions,
    PayloadTooLarge,
    EncTooLarge,
};

pub const DecodeError = error{
    BufferTooShort,
    TrailingBytes,
    UnsupportedVersion,
    InvalidLength,
    PublicNameTooLong,
    PublicKeyTooLong,
    TooManyCipherSuites,
    TooManyExtensions,
    TooManyConfigs,
    PayloadTooLarge,
    EncTooLarge,
};

// CipherSuite — a KDF + AEAD pair.

pub const CipherSuite = struct {
    kdf_id: KdfId,
    aead_id: AeadId,

    pub const encoded_len: usize = 4;

    pub fn encode(self: CipherSuite, buf: []u8) EncodeError!void {
        if (buf.len < encoded_len) return error.BufferTooSmall;
        mem.writeInt(u16, buf[0..2], @backingInt(self.kdf_id), .big);
        mem.writeInt(u16, buf[2..4], @backingInt(self.aead_id), .big);
    }

    pub fn decode(buf: []const u8) DecodeError!CipherSuite {
        if (buf.len < encoded_len) return error.BufferTooShort;
        return .{
            .kdf_id = @fromBackingInt(@intCast(mem.readInt(u16, buf[0..2], .big))),
            .aead_id = @fromBackingInt(@intCast(mem.readInt(u16, buf[2..4], .big))),
        };
    }

    pub fn eql(self: CipherSuite, other: CipherSuite) bool {
        return self.kdf_id == other.kdf_id and self.aead_id == other.aead_id;
    }
};

// Extension — TLS-style type + opaque data.

pub const Extension = struct {
    ext_type: u16,
    data: []const u8,

    pub fn encodedLen(self: Extension) usize {
        return 4 + self.data.len;
    }

    pub fn encode(self: Extension, buf: []u8) EncodeError!void {
        if (buf.len < self.encodedLen()) return error.BufferTooSmall;
        mem.writeInt(u16, buf[0..2], self.ext_type, .big);
        mem.writeInt(u16, buf[2..4], @intCast(self.data.len), .big);
        @memcpy(buf[4 .. 4 + self.data.len], self.data);
    }

    /// Decode one extension; returns the extension and bytes consumed.
    pub fn decode(buf: []const u8) DecodeError!struct { ext: Extension, consumed: usize } {
        if (buf.len < 4) return error.BufferTooShort;
        const ext_type = mem.readInt(u16, buf[0..2], .big);
        const data_len = mem.readInt(u16, buf[2..4], .big);
        if (buf.len < 4 + data_len) return error.BufferTooShort;
        return .{
            .ext = .{ .ext_type = ext_type, .data = buf[4 .. 4 + data_len] },
            .consumed = 4 + data_len,
        };
    }
};

// ECHConfig

pub const ECHConfig = struct {
    version: u16,
    config_id: u8,
    kem_id: KemId,
    public_key: []const u8,
    cipher_suites: []const CipherSuite,
    maximum_name_length: u8,
    public_name: []const u8,
    extensions: []const Extension,
    _arena_owned: bool = false,

    pub fn deinit(self: *ECHConfig, allocator: Allocator) void {
        if (self._arena_owned) {
            allocator.free(self.public_key);
            allocator.free(self.cipher_suites);
            allocator.free(self.public_name);
            for (self.extensions) |e| allocator.free(e.data);
            allocator.free(self.extensions);
        }
        self.* = undefined;
    }

    pub fn encodedLen(self: ECHConfig) usize {
        var ext_total: usize = 0;
        for (self.extensions) |e| ext_total += e.encodedLen();
        return 2 + 2 + 1 + 2 + 2 + self.public_key.len +
            2 + self.cipher_suites.len * CipherSuite.encoded_len +
            1 + 1 + self.public_name.len + 2 + ext_total;
    }

    /// Encode into `buf`; returns bytes written.
    pub fn encode(self: ECHConfig, buf: []u8) EncodeError!usize {
        if (self.public_name.len > MAX_PUBLIC_NAME_LEN) return error.PublicNameTooLong;
        if (self.public_key.len > MAX_PUBLIC_KEY_LEN) return error.PublicKeyTooLong;
        if (self.cipher_suites.len > 255) return error.TooManyCipherSuites;
        const total = self.encodedLen();
        if (buf.len < total) return error.BufferTooSmall;
        const content_len: u16 = @intCast(total - 4);
        var off: usize = 0;
        mem.writeInt(u16, buf[off..][0..2], self.version, .big);
        off += 2;
        mem.writeInt(u16, buf[off..][0..2], content_len, .big);
        off += 2;
        buf[off] = self.config_id;
        off += 1;
        mem.writeInt(u16, buf[off..][0..2], @backingInt(self.kem_id), .big);
        off += 2;
        mem.writeInt(u16, buf[off..][0..2], @intCast(self.public_key.len), .big);
        off += 2;
        @memcpy(buf[off .. off + self.public_key.len], self.public_key);
        off += self.public_key.len;
        const cs_bytes: u16 = @intCast(self.cipher_suites.len * CipherSuite.encoded_len);
        mem.writeInt(u16, buf[off..][0..2], cs_bytes, .big);
        off += 2;
        for (self.cipher_suites) |cs| {
            try cs.encode(buf[off..][0..CipherSuite.encoded_len]);
            off += CipherSuite.encoded_len;
        }
        buf[off] = self.maximum_name_length;
        off += 1;
        buf[off] = @intCast(self.public_name.len);
        off += 1;
        @memcpy(buf[off .. off + self.public_name.len], self.public_name);
        off += self.public_name.len;
        var ext_total: usize = 0;
        for (self.extensions) |e| ext_total += e.encodedLen();
        mem.writeInt(u16, buf[off..][0..2], @intCast(ext_total), .big);
        off += 2;
        for (self.extensions) |e| {
            try e.encode(buf[off .. off + e.encodedLen()]);
            off += e.encodedLen();
        }
        return off;
    }

    /// Decode one ECHConfig from `buf`, allocating owned copies.  Returns the
    /// config and bytes consumed.  Call `deinit` to free.
    pub fn decode(allocator: Allocator, buf: []const u8) (DecodeError || Allocator.Error)!struct { cfg: ECHConfig, consumed: usize } {
        if (buf.len < 4) return error.BufferTooShort;
        const version = mem.readInt(u16, buf[0..2], .big);
        if (version != ECH_VERSION) return error.UnsupportedVersion;
        const content_len = mem.readInt(u16, buf[2..4], .big);
        if (buf.len < 4 + content_len) return error.BufferTooShort;
        const total = 4 + @as(usize, content_len);
        const inner = buf[4..total];
        var off: usize = 0;

        if (inner.len < 1) return error.BufferTooShort;
        const config_id = inner[off];
        off += 1;
        if (inner.len < off + 2) return error.BufferTooShort;
        const kem_id: KemId = @fromBackingInt(@intCast(mem.readInt(u16, inner[off..][0..2], .big)));
        off += 2;

        if (inner.len < off + 2) return error.BufferTooShort;
        const pk_len = mem.readInt(u16, inner[off..][0..2], .big);
        off += 2;
        if (pk_len > MAX_PUBLIC_KEY_LEN) return error.PublicKeyTooLong;
        if (inner.len < off + pk_len) return error.BufferTooShort;
        const pk_owned = try allocator.dupe(u8, inner[off .. off + pk_len]);
        errdefer allocator.free(pk_owned);
        off += pk_len;

        if (inner.len < off + 2) return error.BufferTooShort;
        const cs_bytes = mem.readInt(u16, inner[off..][0..2], .big);
        off += 2;
        if (cs_bytes % CipherSuite.encoded_len != 0) return error.InvalidLength;
        const cs_count = cs_bytes / CipherSuite.encoded_len;
        if (cs_count > 255) return error.TooManyCipherSuites;
        if (inner.len < off + cs_bytes) return error.BufferTooShort;
        const cs_owned = try allocator.alloc(CipherSuite, cs_count);
        errdefer allocator.free(cs_owned);
        for (cs_owned, 0..) |*cs, i| {
            cs.* = try CipherSuite.decode(inner[off + i * CipherSuite.encoded_len ..]);
        }
        off += cs_bytes;

        if (inner.len < off + 1) return error.BufferTooShort;
        const maximum_name_length = inner[off];
        off += 1;
        if (inner.len < off + 1) return error.BufferTooShort;
        const pn_len = inner[off];
        off += 1;
        if (pn_len > MAX_PUBLIC_NAME_LEN) return error.PublicNameTooLong;
        if (inner.len < off + pn_len) return error.BufferTooShort;
        const pn_owned = try allocator.dupe(u8, inner[off .. off + pn_len]);
        errdefer allocator.free(pn_owned);
        off += pn_len;

        if (inner.len < off + 2) return error.BufferTooShort;
        const ext_total_bytes = mem.readInt(u16, inner[off..][0..2], .big);
        off += 2;
        if (inner.len < off + ext_total_bytes) return error.BufferTooShort;
        var ext_list = ArrayList(Extension).empty;
        errdefer {
            for (ext_list.items) |e| allocator.free(e.data);
            ext_list.deinit(allocator);
        }
        var ext_off: usize = 0;
        while (ext_off < ext_total_bytes) {
            const r = try Extension.decode(inner[off + ext_off ..]);
            const ext_data_owned = try allocator.dupe(u8, r.ext.data);
            try ext_list.append(allocator, .{ .ext_type = r.ext.ext_type, .data = ext_data_owned });
            ext_off += r.consumed;
        }
        off += ext_total_bytes;
        // A config whose declared content_len exceeds the sum of its fields would
        // otherwise let trailing bytes be silently skipped (list-level parser
        // desync / smuggling). Require the inner content to be fully consumed.
        if (off != inner.len) return error.TrailingBytes;
        const exts_owned = try ext_list.toOwnedSlice(allocator);
        errdefer {
            for (exts_owned) |e| allocator.free(e.data);
            allocator.free(exts_owned);
        }

        return .{
            .cfg = .{
                .version = version,
                .config_id = config_id,
                .kem_id = kem_id,
                .public_key = pk_owned,
                .cipher_suites = cs_owned,
                .maximum_name_length = maximum_name_length,
                .public_name = pn_owned,
                .extensions = exts_owned,
                ._arena_owned = true,
            },
            .consumed = total,
        };
    }
};

// ECHConfigList — length-prefixed ordered list of ECHConfig.

pub const ECHConfigList = struct {
    configs: []ECHConfig,

    pub fn deinit(self: *ECHConfigList, allocator: Allocator) void {
        for (self.configs) |*c| c.deinit(allocator);
        allocator.free(self.configs);
        self.* = undefined;
    }

    pub fn encode(self: ECHConfigList, buf: []u8) EncodeError!usize {
        var content_len: usize = 0;
        for (self.configs) |c| content_len += c.encodedLen();
        if (content_len > 0xffff) return error.TooManyConfigs;
        if (buf.len < 2 + content_len) return error.BufferTooSmall;
        mem.writeInt(u16, buf[0..2], @intCast(content_len), .big);
        var off: usize = 2;
        for (self.configs) |c| {
            const written = try c.encode(buf[off..]);
            off += written;
        }
        return off;
    }

    pub fn decode(allocator: Allocator, buf: []const u8) (DecodeError || Allocator.Error)!ECHConfigList {
        if (buf.len < 2) return error.BufferTooShort;
        const list_len = mem.readInt(u16, buf[0..2], .big);
        if (buf.len < 2 + list_len) return error.BufferTooShort;
        if (buf.len > 2 + list_len) return error.TrailingBytes;
        const list_buf = buf[2 .. 2 + list_len];
        var off: usize = 0;
        var list = ArrayList(ECHConfig).empty;
        errdefer {
            for (list.items) |*c| c.deinit(allocator);
            list.deinit(allocator);
        }
        while (off < list_len) {
            const r = try ECHConfig.decode(allocator, list_buf[off..]);
            try list.append(allocator, r.cfg);
            off += r.consumed;
        }
        return .{ .configs = try list.toOwnedSlice(allocator) };
    }
};

/// Select the first ECHConfig in `list` whose cipher_suites intersects
/// `supported_suites`.  Returns null if no compatible config exists.
pub fn selectConfig(list: ECHConfigList, supported_suites: []const CipherSuite) ?ECHConfig {
    for (list.configs) |cfg| {
        for (cfg.cipher_suites) |cs| {
            for (supported_suites) |sup| {
                if (cs.eql(sup)) return cfg;
            }
        }
    }
    return null;
}

// ECHClientHello (outer) — config_id + enc + payload.

pub const ECHClientHello = struct {
    config_id: u8,
    enc: []const u8,
    payload: []const u8,
    _arena_owned: bool = false,

    pub fn deinit(self: *ECHClientHello, allocator: Allocator) void {
        if (self._arena_owned) {
            allocator.free(self.enc);
            allocator.free(self.payload);
        }
        self.* = undefined;
    }

    pub fn encodedLen(self: ECHClientHello) usize {
        return 1 + 2 + self.enc.len + 2 + self.payload.len;
    }

    pub fn encode(self: ECHClientHello, buf: []u8) EncodeError!usize {
        if (self.enc.len > 0xffff) return error.EncTooLarge;
        if (self.payload.len > 0xffff) return error.PayloadTooLarge;
        if (buf.len < self.encodedLen()) return error.BufferTooSmall;
        var off: usize = 0;
        buf[off] = self.config_id;
        off += 1;
        mem.writeInt(u16, buf[off..][0..2], @intCast(self.enc.len), .big);
        off += 2;
        @memcpy(buf[off .. off + self.enc.len], self.enc);
        off += self.enc.len;
        mem.writeInt(u16, buf[off..][0..2], @intCast(self.payload.len), .big);
        off += 2;
        @memcpy(buf[off .. off + self.payload.len], self.payload);
        off += self.payload.len;
        return off;
    }

    /// Decode from `buf`, allocating owned copies.  Call `deinit` to free.
    pub fn decode(allocator: Allocator, buf: []const u8) (DecodeError || Allocator.Error)!ECHClientHello {
        if (buf.len < 3) return error.BufferTooShort;
        const config_id = buf[0];
        const enc_len = mem.readInt(u16, buf[1..3], .big);
        if (buf.len < 3 + enc_len + 2) return error.BufferTooShort;
        const enc_owned = try allocator.dupe(u8, buf[3 .. 3 + enc_len]);
        errdefer allocator.free(enc_owned);
        const off = 3 + enc_len;
        const payload_len = mem.readInt(u16, buf[off..][0..2], .big);
        if (buf.len < off + 2 + payload_len) return error.BufferTooShort;
        if (buf.len > off + 2 + payload_len) return error.TrailingBytes;
        const payload_owned = try allocator.dupe(u8, buf[off + 2 .. off + 2 + payload_len]);
        errdefer allocator.free(payload_owned);
        return .{
            .config_id = config_id,
            .enc = enc_owned,
            .payload = payload_owned,
            ._arena_owned = true,
        };
    }
};

// Tests

test "CipherSuite encode/decode round-trip" {
    const cs = CipherSuite{ .kdf_id = .hkdf_sha256, .aead_id = .aes_128_gcm };
    var buf: [4]u8 = undefined;
    try cs.encode(&buf);
    const cs2 = try CipherSuite.decode(&buf);
    try std.testing.expect(cs.eql(cs2));
}

test "ECHConfig encode/decode round-trip" {
    const alloc = std.testing.allocator;
    const suites = [_]CipherSuite{
        .{ .kdf_id = .hkdf_sha256, .aead_id = .aes_128_gcm },
        .{ .kdf_id = .hkdf_sha256, .aead_id = .chacha20_poly1305 },
    };
    const cfg = ECHConfig{
        .version = ECH_VERSION,
        .config_id = 0x42,
        .kem_id = .dhkem_x25519_hkdf_sha256,
        .public_key = &@as([32]u8, @splat(0xAB)),
        .cipher_suites = &suites,
        .maximum_name_length = 64,
        .public_name = "example.com",
        .extensions = &.{},
    };
    var buf: [512]u8 = undefined;
    const written = try cfg.encode(&buf);
    try std.testing.expect(written == cfg.encodedLen());
    const r = try ECHConfig.decode(alloc, buf[0..written]);
    var decoded = r.cfg;
    defer decoded.deinit(alloc);
    try std.testing.expectEqual(ECH_VERSION, decoded.version);
    try std.testing.expectEqual(@as(u8, 0x42), decoded.config_id);
    try std.testing.expectEqual(KemId.dhkem_x25519_hkdf_sha256, decoded.kem_id);
    try std.testing.expectEqualSlices(u8, cfg.public_key, decoded.public_key);
    try std.testing.expectEqual(@as(usize, 2), decoded.cipher_suites.len);
    try std.testing.expect(decoded.cipher_suites[0].eql(suites[0]));
    try std.testing.expect(decoded.cipher_suites[1].eql(suites[1]));
    try std.testing.expectEqual(@as(u8, 64), decoded.maximum_name_length);
    try std.testing.expectEqualSlices(u8, "example.com", decoded.public_name);
    try std.testing.expectEqual(@as(usize, 0), decoded.extensions.len);
    try std.testing.expectEqual(written, r.consumed);
}

test "ECHConfig with extensions encode/decode" {
    const alloc = std.testing.allocator;
    const suites = [_]CipherSuite{.{ .kdf_id = .hkdf_sha256, .aead_id = .aes_256_gcm }};
    const ext_data = [_]u8{ 0x01, 0x02, 0x03 };
    const exts = [_]Extension{.{ .ext_type = 0x0010, .data = &ext_data }};
    const cfg = ECHConfig{
        .version = ECH_VERSION,
        .config_id = 0x01,
        .kem_id = .dhkem_p256_hkdf_sha256,
        .public_key = &@as([65]u8, @splat(0xCC)),
        .cipher_suites = &suites,
        .maximum_name_length = 128,
        .public_name = "tls.example",
        .extensions = &exts,
    };
    var buf: [512]u8 = undefined;
    const written = try cfg.encode(&buf);
    const r = try ECHConfig.decode(alloc, buf[0..written]);
    var decoded = r.cfg;
    defer decoded.deinit(alloc);
    try std.testing.expectEqual(@as(usize, 1), decoded.extensions.len);
    try std.testing.expectEqual(@as(u16, 0x0010), decoded.extensions[0].ext_type);
    try std.testing.expectEqualSlices(u8, &ext_data, decoded.extensions[0].data);
}

test "ECHConfigList multiple configs encode/decode" {
    const alloc = std.testing.allocator;
    const suites1 = [_]CipherSuite{.{ .kdf_id = .hkdf_sha256, .aead_id = .aes_128_gcm }};
    const suites2 = [_]CipherSuite{.{ .kdf_id = .hkdf_sha384, .aead_id = .aes_256_gcm }};
    var cfgs = [_]ECHConfig{
        .{
            .version = ECH_VERSION,
            .config_id = 0x01,
            .kem_id = .dhkem_x25519_hkdf_sha256,
            .public_key = &@as([32]u8, @splat(0x11)),
            .cipher_suites = &suites1,
            .maximum_name_length = 64,
            .public_name = "alpha.example",
            .extensions = &.{},
        },
        .{
            .version = ECH_VERSION,
            .config_id = 0x02,
            .kem_id = .dhkem_p256_hkdf_sha256,
            .public_key = &@as([65]u8, @splat(0x22)),
            .cipher_suites = &suites2,
            .maximum_name_length = 100,
            .public_name = "beta.example",
            .extensions = &.{},
        },
    };
    const list = ECHConfigList{ .configs = &cfgs };
    var buf: [1024]u8 = undefined;
    const written = try list.encode(&buf);
    var decoded_list = try ECHConfigList.decode(alloc, buf[0..written]);
    defer decoded_list.deinit(alloc);
    try std.testing.expectEqual(@as(usize, 2), decoded_list.configs.len);
    try std.testing.expectEqual(@as(u8, 0x01), decoded_list.configs[0].config_id);
    try std.testing.expectEqual(@as(u8, 0x02), decoded_list.configs[1].config_id);
    try std.testing.expectEqualSlices(u8, "alpha.example", decoded_list.configs[0].public_name);
    try std.testing.expectEqualSlices(u8, "beta.example", decoded_list.configs[1].public_name);
    try std.testing.expect(decoded_list.configs[0].cipher_suites[0].eql(suites1[0]));
    try std.testing.expect(decoded_list.configs[1].cipher_suites[0].eql(suites2[0]));
}

test "selectConfig picks supported suite" {
    const suites_a = [_]CipherSuite{
        .{ .kdf_id = .hkdf_sha256, .aead_id = .aes_128_gcm },
        .{ .kdf_id = .hkdf_sha256, .aead_id = .chacha20_poly1305 },
    };
    const suites_b = [_]CipherSuite{.{ .kdf_id = .hkdf_sha384, .aead_id = .aes_256_gcm }};
    var cfgs = [_]ECHConfig{
        .{
            .version = ECH_VERSION,
            .config_id = 0xAA,
            .kem_id = .dhkem_x25519_hkdf_sha256,
            .public_key = &@as([32]u8, @splat(0x55)),
            .cipher_suites = &suites_a,
            .maximum_name_length = 64,
            .public_name = "first.example",
            .extensions = &.{},
        },
        .{
            .version = ECH_VERSION,
            .config_id = 0xBB,
            .kem_id = .dhkem_p256_hkdf_sha256,
            .public_key = &@as([65]u8, @splat(0x66)),
            .cipher_suites = &suites_b,
            .maximum_name_length = 64,
            .public_name = "second.example",
            .extensions = &.{},
        },
    };
    const list = ECHConfigList{ .configs = &cfgs };
    const supported = [_]CipherSuite{.{ .kdf_id = .hkdf_sha256, .aead_id = .chacha20_poly1305 }};
    const selected = selectConfig(list, &supported);
    try std.testing.expect(selected != null);
    try std.testing.expectEqual(@as(u8, 0xAA), selected.?.config_id);
}

test "selectConfig rejects when no suite matches" {
    const suites = [_]CipherSuite{.{ .kdf_id = .hkdf_sha256, .aead_id = .aes_128_gcm }};
    var cfgs = [_]ECHConfig{.{
        .version = ECH_VERSION,
        .config_id = 0x01,
        .kem_id = .dhkem_x25519_hkdf_sha256,
        .public_key = &@as([32]u8, @splat(0x77)),
        .cipher_suites = &suites,
        .maximum_name_length = 64,
        .public_name = "only.example",
        .extensions = &.{},
    }};
    const list = ECHConfigList{ .configs = &cfgs };
    const supported = [_]CipherSuite{.{ .kdf_id = .hkdf_sha384, .aead_id = .aes_256_gcm }};
    try std.testing.expect(selectConfig(list, &supported) == null);
}

test "selectConfig picks first matching config in order" {
    const suites_common = [_]CipherSuite{.{ .kdf_id = .hkdf_sha256, .aead_id = .aes_128_gcm }};
    var cfgs = [_]ECHConfig{
        .{
            .version = ECH_VERSION,
            .config_id = 0x01,
            .kem_id = .dhkem_x25519_hkdf_sha256,
            .public_key = &@as([32]u8, @splat(0x11)),
            .cipher_suites = &suites_common,
            .maximum_name_length = 64,
            .public_name = "first.example",
            .extensions = &.{},
        },
        .{
            .version = ECH_VERSION,
            .config_id = 0x02,
            .kem_id = .dhkem_x25519_hkdf_sha256,
            .public_key = &@as([32]u8, @splat(0x22)),
            .cipher_suites = &suites_common,
            .maximum_name_length = 64,
            .public_name = "second.example",
            .extensions = &.{},
        },
    };
    const list = ECHConfigList{ .configs = &cfgs };
    const selected = selectConfig(list, &suites_common);
    try std.testing.expect(selected != null);
    try std.testing.expectEqual(@as(u8, 0x01), selected.?.config_id);
}

test "ECHClientHello encode/decode round-trip" {
    const alloc = std.testing.allocator;
    const enc_data = @as([32]u8, @splat(0xDE));
    const payload_data = @as([64]u8, @splat(0xAD));
    const hello = ECHClientHello{ .config_id = 0x42, .enc = &enc_data, .payload = &payload_data };
    var buf: [256]u8 = undefined;
    const written = try hello.encode(&buf);
    try std.testing.expectEqual(hello.encodedLen(), written);
    var decoded = try ECHClientHello.decode(alloc, buf[0..written]);
    defer decoded.deinit(alloc);
    try std.testing.expectEqual(@as(u8, 0x42), decoded.config_id);
    try std.testing.expectEqualSlices(u8, &enc_data, decoded.enc);
    try std.testing.expectEqualSlices(u8, &payload_data, decoded.payload);
}

test "ECHClientHello empty enc and payload" {
    const alloc = std.testing.allocator;
    const hello = ECHClientHello{ .config_id = 0x00, .enc = &.{}, .payload = &.{} };
    var buf: [16]u8 = undefined;
    const written = try hello.encode(&buf);
    var decoded = try ECHClientHello.decode(alloc, buf[0..written]);
    defer decoded.deinit(alloc);
    try std.testing.expectEqual(@as(usize, 0), decoded.enc.len);
    try std.testing.expectEqual(@as(usize, 0), decoded.payload.len);
}

test "ECHConfig decode rejects unsupported version" {
    var buf: [9]u8 = undefined;
    mem.writeInt(u16, buf[0..2], 0xfe0c, .big);
    mem.writeInt(u16, buf[2..4], 5, .big);
    buf[4] = 0;
    buf[5] = 0;
    buf[6] = 0;
    buf[7] = 0;
    buf[8] = 0;
    try std.testing.expectError(error.UnsupportedVersion, ECHConfig.decode(std.testing.allocator, &buf));
}

test "ECHConfig decode rejects truncated input" {
    var buf: [4]u8 = undefined;
    mem.writeInt(u16, buf[0..2], ECH_VERSION, .big);
    mem.writeInt(u16, buf[2..4], 100, .big);
    try std.testing.expectError(error.BufferTooShort, ECHConfig.decode(std.testing.allocator, &buf));
}

test "ECHConfigList decode rejects trailing bytes" {
    const alloc = std.testing.allocator;
    const suites = [_]CipherSuite{.{ .kdf_id = .hkdf_sha256, .aead_id = .aes_128_gcm }};
    var cfgs = [_]ECHConfig{.{
        .version = ECH_VERSION,
        .config_id = 0x01,
        .kem_id = .dhkem_x25519_hkdf_sha256,
        .public_key = &@as([32]u8, @splat(0x99)),
        .cipher_suites = &suites,
        .maximum_name_length = 64,
        .public_name = "trail.example",
        .extensions = &.{},
    }};
    const list = ECHConfigList{ .configs = &cfgs };
    var buf: [512]u8 = undefined;
    const written = try list.encode(&buf);
    buf[written] = 0xFF;
    try std.testing.expectError(error.TrailingBytes, ECHConfigList.decode(alloc, buf[0 .. written + 1]));
}

test "ECHClientHello decode rejects trailing bytes" {
    const alloc = std.testing.allocator;
    const hello = ECHClientHello{
        .config_id = 0x01,
        .enc = &@as([4]u8, @splat(0xAA)),
        .payload = &@as([4]u8, @splat(0xBB)),
    };
    var buf: [64]u8 = undefined;
    const written = try hello.encode(&buf);
    buf[written] = 0xFF;
    try std.testing.expectError(error.TrailingBytes, ECHClientHello.decode(alloc, buf[0 .. written + 1]));
}

test "determinism: repeated encodes produce identical bytes" {
    const suites = [_]CipherSuite{.{ .kdf_id = .hkdf_sha256, .aead_id = .aes_128_gcm }};
    const cfg = ECHConfig{
        .version = ECH_VERSION,
        .config_id = 0x07,
        .kem_id = .dhkem_x25519_hkdf_sha256,
        .public_key = &@as([32]u8, @splat(0x42)),
        .cipher_suites = &suites,
        .maximum_name_length = 50,
        .public_name = "det.example",
        .extensions = &.{},
    };
    var buf1: [512]u8 = undefined;
    var buf2: [512]u8 = undefined;
    const w1 = try cfg.encode(&buf1);
    const w2 = try cfg.encode(&buf2);
    try std.testing.expectEqual(w1, w2);
    try std.testing.expectEqualSlices(u8, buf1[0..w1], buf2[0..w2]);
}
