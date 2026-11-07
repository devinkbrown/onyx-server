// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Minimal COSE_Sign1 and COSE_Mac0 support for WebAuthn/attestation.
//!
//! This file is self-contained by design: it implements only the definite-length
//! CBOR forms needed by RFC 9052 COSE structures and COSE_Key parsing.
const std = @import("std");

const Ed25519 = std.crypto.sign.Ed25519;
const Es256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
/// ES256 signing goes through the constant-time signer, never std's
/// `KeyPair.sign` (whose P256.mul leaks the nonce; see `p256_ct.zig`).
const ecdsa_p256 = @import("ecdsa_p256.zig");
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const Error = error{
    AlgorithmMismatch,
    BadCbor,
    BadCoseKey,
    BadHeader,
    BadKey,
    BadMac,
    BadSignature,
    DetachedPayload,
    NotSquare,
    UnsupportedAlgorithm,
    UnsupportedKey,
} || std.mem.Allocator.Error || std.crypto.errors.EncodingError ||
    std.crypto.errors.IdentityElementError || std.crypto.errors.KeyMismatchError ||
    std.crypto.errors.NonCanonicalError || std.crypto.errors.SignatureVerificationError ||
    std.crypto.errors.WeakPublicKeyError;

pub const Algorithm = enum(i64) {
    es256 = -7,
    eddsa = -8,
    hmac_256_256 = -16,
};

pub const P256PublicKey = struct {
    x: [32]u8,
    y: [32]u8,
};

pub const PublicKey = union(enum) {
    ed25519: [32]u8,
    p256: P256PublicKey,
};

pub fn encodeSign1Ed25519(
    allocator: std.mem.Allocator,
    payload: []const u8,
    external_aad: []const u8,
    key_pair: Ed25519.KeyPair,
) Error![]u8 {
    const protected = try protectedHeader(allocator, .eddsa);
    defer allocator.free(protected);
    const to_sign = try sigStructure(allocator, protected, external_aad, payload);
    defer allocator.free(to_sign);
    const sig = try key_pair.sign(to_sign, null);
    return encodeSign1(allocator, protected, payload, &sig.toBytes());
}

pub fn encodeSign1Es256(
    allocator: std.mem.Allocator,
    payload: []const u8,
    external_aad: []const u8,
    key_pair: Es256.KeyPair,
) Error![]u8 {
    const protected = try protectedHeader(allocator, .es256);
    defer allocator.free(protected);
    const to_sign = try sigStructure(allocator, protected, external_aad, payload);
    defer allocator.free(to_sign);
    const sig = try ecdsa_p256.sign(to_sign, key_pair);
    return encodeSign1(allocator, protected, payload, &sig.toBytes());
}

pub fn verifySign1(
    allocator: std.mem.Allocator,
    encoded: []const u8,
    external_aad: []const u8,
    public_key: PublicKey,
) Error!bool {
    var decoded = try Cbor.decode(allocator, encoded);
    defer decoded.deinit(allocator);
    const root = unwrapTag(decoded.root, 18) orelse decoded.root;
    if (root != .array or root.array.len != 4) return error.BadCbor;
    const protected = expectBytes(root.array[0]) orelse return error.BadHeader;
    const payload = expectBytes(root.array[2]) orelse return error.DetachedPayload;
    const signature = expectBytes(root.array[3]) orelse return error.BadSignature;
    const alg = try protectedAlg(allocator, protected);
    const to_sign = try sigStructure(allocator, protected, external_aad, payload);
    defer allocator.free(to_sign);

    switch (alg) {
        .eddsa => {
            if (public_key != .ed25519 or signature.len != 64) return false;
            const pk = try Ed25519.PublicKey.fromBytes(public_key.ed25519);
            const sig = Ed25519.Signature.fromBytes(signature[0..64].*);
            sig.verify(to_sign, pk) catch |err| return switch (err) {
                error.SignatureVerificationFailed => false,
                else => err,
            };
            return true;
        },
        .es256 => {
            if (public_key != .p256 or signature.len != 64) return false;
            var sec1: [65]u8 = undefined;
            sec1[0] = 0x04;
            sec1[1..33].* = public_key.p256.x;
            sec1[33..65].* = public_key.p256.y;
            const pk = try Es256.PublicKey.fromSec1(&sec1);
            const sig = Es256.Signature.fromBytes(signature[0..64].*);
            sig.verify(to_sign, pk) catch |err| return switch (err) {
                error.SignatureVerificationFailed => false,
                else => err,
            };
            return true;
        },
        else => return error.UnsupportedAlgorithm,
    }
}

pub fn encodeMac0(
    allocator: std.mem.Allocator,
    payload: []const u8,
    external_aad: []const u8,
    key: []const u8,
) Error![]u8 {
    const protected = try protectedHeader(allocator, .hmac_256_256);
    defer allocator.free(protected);
    const maced = try macStructure(allocator, protected, external_aad, payload);
    defer allocator.free(maced);
    var tag: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&tag, maced, key);
    return encodeMac0WithTag(allocator, protected, payload, &tag);
}

pub fn verifyMac0(
    allocator: std.mem.Allocator,
    encoded: []const u8,
    external_aad: []const u8,
    key: []const u8,
) Error!bool {
    var decoded = try Cbor.decode(allocator, encoded);
    defer decoded.deinit(allocator);
    const root = unwrapTag(decoded.root, 17) orelse decoded.root;
    if (root != .array or root.array.len != 4) return error.BadCbor;
    const protected = expectBytes(root.array[0]) orelse return error.BadHeader;
    if (try protectedAlg(allocator, protected) != .hmac_256_256) return error.UnsupportedAlgorithm;
    const payload = expectBytes(root.array[2]) orelse return error.DetachedPayload;
    const got = expectBytes(root.array[3]) orelse return error.BadMac;
    if (got.len != HmacSha256.mac_length) return false;
    const maced = try macStructure(allocator, protected, external_aad, payload);
    defer allocator.free(maced);
    var expected: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&expected, maced, key);
    return std.crypto.timing_safe.eql([HmacSha256.mac_length]u8, expected, got[0..HmacSha256.mac_length].*);
}

pub fn parseCoseKey(allocator: std.mem.Allocator, encoded: []const u8) Error!PublicKey {
    var decoded = try Cbor.decode(allocator, encoded);
    defer decoded.deinit(allocator);
    if (decoded.root != .map) return error.BadCoseKey;
    const kty = try intField(decoded.root, 1) orelse return error.BadCoseKey;
    const crv = try intField(decoded.root, -1) orelse return error.BadCoseKey;
    const x = bytesField(decoded.root, -2) orelse return error.BadCoseKey;
    if (kty == 1 and crv == 6) {
        if (x.len != 32) return error.BadCoseKey;
        return .{ .ed25519 = x[0..32].* };
    }
    if (kty == 2 and crv == 1) {
        const y = bytesField(decoded.root, -3) orelse return error.BadCoseKey;
        if (x.len != 32 or y.len != 32) return error.BadCoseKey;
        return .{ .p256 = .{ .x = x[0..32].*, .y = y[0..32].* } };
    }
    return error.UnsupportedKey;
}

pub fn protectedHeader(allocator: std.mem.Allocator, alg: Algorithm) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try Cbor.writeMap(&out, allocator, 1);
    try Cbor.writeInt(&out, allocator, 1);
    try Cbor.writeInt(&out, allocator, @backingInt(alg));
    return out.toOwnedSlice(allocator);
}

pub fn sigStructure(
    allocator: std.mem.Allocator,
    protected: []const u8,
    external_aad: []const u8,
    payload: []const u8,
) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try Cbor.writeArray(&out, allocator, 4);
    try Cbor.writeText(&out, allocator, "Signature1");
    try Cbor.writeBytes(&out, allocator, protected);
    try Cbor.writeBytes(&out, allocator, external_aad);
    try Cbor.writeBytes(&out, allocator, payload);
    return out.toOwnedSlice(allocator);
}

pub fn macStructure(
    allocator: std.mem.Allocator,
    protected: []const u8,
    external_aad: []const u8,
    payload: []const u8,
) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try Cbor.writeArray(&out, allocator, 4);
    try Cbor.writeText(&out, allocator, "MAC0");
    try Cbor.writeBytes(&out, allocator, protected);
    try Cbor.writeBytes(&out, allocator, external_aad);
    try Cbor.writeBytes(&out, allocator, payload);
    return out.toOwnedSlice(allocator);
}

fn encodeSign1(
    allocator: std.mem.Allocator,
    protected: []const u8,
    payload: []const u8,
    signature: []const u8,
) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try Cbor.writeTag(&out, allocator, 18);
    try Cbor.writeArray(&out, allocator, 4);
    try Cbor.writeBytes(&out, allocator, protected);
    try Cbor.writeMap(&out, allocator, 0);
    try Cbor.writeBytes(&out, allocator, payload);
    try Cbor.writeBytes(&out, allocator, signature);
    return out.toOwnedSlice(allocator);
}

fn encodeMac0WithTag(
    allocator: std.mem.Allocator,
    protected: []const u8,
    payload: []const u8,
    tag: []const u8,
) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try Cbor.writeTag(&out, allocator, 17);
    try Cbor.writeArray(&out, allocator, 4);
    try Cbor.writeBytes(&out, allocator, protected);
    try Cbor.writeMap(&out, allocator, 0);
    try Cbor.writeBytes(&out, allocator, payload);
    try Cbor.writeBytes(&out, allocator, tag);
    return out.toOwnedSlice(allocator);
}

fn protectedAlg(allocator: std.mem.Allocator, protected: []const u8) Error!Algorithm {
    var decoded = try Cbor.decode(allocator, protected);
    defer decoded.deinit(allocator);
    if (decoded.root != .map) return error.BadHeader;
    const alg = try intField(decoded.root, 1) orelse return error.BadHeader;
    return switch (alg) {
        -7 => .es256,
        -8 => .eddsa,
        -16 => .hmac_256_256,
        else => error.UnsupportedAlgorithm,
    };
}

fn unwrapTag(value: Cbor.Value, tag: u64) ?Cbor.Value {
    if (value == .tag and value.tag.number == tag) return value.tag.value.*;
    return null;
}

fn expectBytes(value: Cbor.Value) ?[]const u8 {
    return if (value == .bytes) value.bytes else null;
}

fn intField(value: Cbor.Value, key: i64) Error!?i64 {
    if (value != .map) return error.BadCbor;
    for (value.map) |entry| {
        const entry_key = try cborInt(entry.key);
        if (entry_key == key) return try cborInt(entry.value);
    }
    return null;
}

fn bytesField(value: Cbor.Value, key: i64) ?[]const u8 {
    if (value != .map) return null;
    for (value.map) |entry| {
        if ((cborInt(entry.key) catch continue) == key and entry.value == .bytes) {
            return entry.value.bytes;
        }
    }
    return null;
}

fn cborInt(value: Cbor.Value) Error!i64 {
    return switch (value) {
        .unsigned => |v| if (v <= @as(u64, @intCast(std.math.maxInt(i64)))) @intCast(v) else error.BadCbor,
        .negative => |v| v,
        else => error.BadCbor,
    };
}

pub const Cbor = struct {
    pub const Pair = struct {
        key: Value,
        value: Value,
    };

    pub const Tagged = struct {
        number: u64,
        value: *Value,
    };

    pub const Value = union(enum) {
        unsigned: u64,
        negative: i64,
        bytes: []const u8,
        text: []const u8,
        array: []Value,
        map: []Pair,
        tag: Tagged,
        null,

        fn deinit(self: Value, allocator: std.mem.Allocator) void {
            switch (self) {
                .array => |items| {
                    for (items) |item| item.deinit(allocator);
                    allocator.free(items);
                },
                .map => |items| {
                    for (items) |item| {
                        item.key.deinit(allocator);
                        item.value.deinit(allocator);
                    }
                    allocator.free(items);
                },
                .tag => |tagged| {
                    tagged.value.deinit(allocator);
                    allocator.destroy(tagged.value);
                },
                else => {},
            }
        }
    };

    pub const Document = struct {
        root: Value,

        pub fn deinit(self: *Document, allocator: std.mem.Allocator) void {
            self.root.deinit(allocator);
        }
    };

    pub fn decode(allocator: std.mem.Allocator, encoded: []const u8) Error!Document {
        var parser = Parser{ .buf = encoded };
        const root = try parser.readValue(allocator);
        if (parser.pos != encoded.len) {
            root.deinit(allocator);
            return error.BadCbor;
        }
        return .{ .root = root };
    }

    pub fn writeInt(out: *std.ArrayList(u8), allocator: std.mem.Allocator, value: i64) Error!void {
        if (value >= 0) return writeHead(out, allocator, 0, @intCast(value));
        return writeHead(out, allocator, 1, @intCast(-1 - value));
    }

    pub fn writeBytes(out: *std.ArrayList(u8), allocator: std.mem.Allocator, bytes: []const u8) Error!void {
        try writeHead(out, allocator, 2, bytes.len);
        try out.appendSlice(allocator, bytes);
    }

    pub fn writeText(out: *std.ArrayList(u8), allocator: std.mem.Allocator, text: []const u8) Error!void {
        try writeHead(out, allocator, 3, text.len);
        try out.appendSlice(allocator, text);
    }

    pub fn writeArray(out: *std.ArrayList(u8), allocator: std.mem.Allocator, len: usize) Error!void {
        try writeHead(out, allocator, 4, len);
    }

    pub fn writeMap(out: *std.ArrayList(u8), allocator: std.mem.Allocator, len: usize) Error!void {
        try writeHead(out, allocator, 5, len);
    }

    pub fn writeTag(out: *std.ArrayList(u8), allocator: std.mem.Allocator, number: u64) Error!void {
        try writeHead(out, allocator, 6, number);
    }

    fn writeHead(out: *std.ArrayList(u8), allocator: std.mem.Allocator, major: u8, value: u64) Error!void {
        const base = major << 5;
        if (value < 24) {
            try out.append(allocator, base | @as(u8, @intCast(value)));
        } else if (value <= std.math.maxInt(u8)) {
            try out.append(allocator, base | 24);
            try out.append(allocator, @intCast(value));
        } else if (value <= std.math.maxInt(u16)) {
            try out.append(allocator, base | 25);
            try be(out, allocator, u16, @intCast(value));
        } else if (value <= std.math.maxInt(u32)) {
            try out.append(allocator, base | 26);
            try be(out, allocator, u32, @intCast(value));
        } else {
            try out.append(allocator, base | 27);
            try be(out, allocator, u64, value);
        }
    }

    fn be(out: *std.ArrayList(u8), allocator: std.mem.Allocator, comptime T: type, value: T) Error!void {
        var buf: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &buf, value, .big);
        try out.appendSlice(allocator, &buf);
    }

    const max_depth = 32;

    const Parser = struct {
        buf: []const u8,
        pos: usize = 0,
        depth: u32 = 0,

        fn readValue(self: *Parser, allocator: std.mem.Allocator) Error!Value {
            // Bound nesting so a crafted deeply-nested blob can't overflow the
            // native stack (worker threads have small stacks).
            if (self.depth >= max_depth) return error.BadCbor;
            self.depth += 1;
            defer self.depth -= 1;
            const first = try self.take();
            const major = first >> 5;
            const addl = first & 0x1f;
            const n = try self.readLen(addl);
            return switch (major) {
                0 => .{ .unsigned = n },
                // Guard the i64 cast: a major-1 value > maxInt(i64) would trap.
                1 => if (n > std.math.maxInt(i64)) error.BadCbor else .{ .negative = -1 - @as(i64, @intCast(n)) },
                2 => .{ .bytes = try self.takeSlice(n) },
                3 => .{ .text = try self.takeSlice(n) },
                4 => try self.readArray(allocator, n),
                5 => try self.readMap(allocator, n),
                6 => try self.readTag(allocator, n),
                7 => if (addl == 22) .null else error.BadCbor,
                else => error.BadCbor,
            };
        }

        fn readArray(self: *Parser, allocator: std.mem.Allocator, len: u64) Error!Value {
            if (len > std.math.maxInt(usize)) return error.BadCbor;
            // Each element needs >= 1 byte on the wire; reject a declared count
            // that can't fit the remaining input (allocation-bomb amplifier).
            if (len > self.buf.len - self.pos) return error.BadCbor;
            const items = try allocator.alloc(Value, @intCast(len));
            errdefer allocator.free(items);
            var filled: usize = 0;
            errdefer for (items[0..filled]) |item| item.deinit(allocator);
            while (filled < items.len) : (filled += 1) {
                items[filled] = try self.readValue(allocator);
            }
            return .{ .array = items };
        }

        fn readMap(self: *Parser, allocator: std.mem.Allocator, len: u64) Error!Value {
            if (len > std.math.maxInt(usize)) return error.BadCbor;
            // Each pair needs >= 2 bytes; reject counts that can't fit remaining
            // input (allocation-bomb amplifier).
            if (len > (self.buf.len - self.pos)) return error.BadCbor;
            const items = try allocator.alloc(Pair, @intCast(len));
            errdefer allocator.free(items);
            var filled: usize = 0;
            errdefer for (items[0..filled]) |item| {
                item.key.deinit(allocator);
                item.value.deinit(allocator);
            };
            while (filled < items.len) : (filled += 1) {
                items[filled].key = try self.readValue(allocator);
                errdefer items[filled].key.deinit(allocator);
                items[filled].value = try self.readValue(allocator);
            }
            return .{ .map = items };
        }

        fn readTag(self: *Parser, allocator: std.mem.Allocator, number: u64) Error!Value {
            const inner = try allocator.create(Value);
            errdefer allocator.destroy(inner);
            inner.* = try self.readValue(allocator);
            return .{ .tag = .{ .number = number, .value = inner } };
        }

        fn readLen(self: *Parser, addl: u8) Error!u64 {
            return switch (addl) {
                0...23 => addl,
                24 => try self.readInt(u8),
                25 => try self.readInt(u16),
                26 => try self.readInt(u32),
                27 => try self.readInt(u64),
                else => error.BadCbor,
            };
        }

        fn readInt(self: *Parser, comptime T: type) Error!T {
            const bytes = try self.takeSlice(@sizeOf(T));
            return std.mem.readInt(T, bytes[0..@sizeOf(T)], .big);
        }

        fn take(self: *Parser) Error!u8 {
            if (self.pos >= self.buf.len) return error.BadCbor;
            defer self.pos += 1;
            return self.buf[self.pos];
        }

        fn takeSlice(self: *Parser, len64: u64) Error![]const u8 {
            if (len64 > std.math.maxInt(usize)) return error.BadCbor;
            const len: usize = @intCast(len64);
            if (self.pos + len < self.pos or self.pos + len > self.buf.len) return error.BadCbor;
            defer self.pos += len;
            return self.buf[self.pos .. self.pos + len];
        }
    };
};

fn appendCoseKeyOkp(out: *std.ArrayList(u8), allocator: std.mem.Allocator, x: [32]u8) !void {
    try Cbor.writeMap(out, allocator, 3);
    try Cbor.writeInt(out, allocator, 1);
    try Cbor.writeInt(out, allocator, 1);
    try Cbor.writeInt(out, allocator, -1);
    try Cbor.writeInt(out, allocator, 6);
    try Cbor.writeInt(out, allocator, -2);
    try Cbor.writeBytes(out, allocator, &x);
}

fn appendCoseKeyP256(out: *std.ArrayList(u8), allocator: std.mem.Allocator, pk: P256PublicKey) !void {
    try Cbor.writeMap(out, allocator, 4);
    try Cbor.writeInt(out, allocator, 1);
    try Cbor.writeInt(out, allocator, 2);
    try Cbor.writeInt(out, allocator, -1);
    try Cbor.writeInt(out, allocator, 1);
    try Cbor.writeInt(out, allocator, -2);
    try Cbor.writeBytes(out, allocator, &pk.x);
    try Cbor.writeInt(out, allocator, -3);
    try Cbor.writeBytes(out, allocator, &pk.y);
}

fn expectHex(actual: []const u8, comptime expected: []const u8) !void {
    const bytes = comptime blk: {
        var out: [expected.len / 2]u8 = undefined;
        _ = std.fmt.hexToBytes(&out, expected) catch unreachable;
        break :blk out;
    };
    try std.testing.expectEqualSlices(u8, &bytes, actual);
}

test "Sig_structure bytes correct" {
    const allocator = std.testing.allocator;
    const protected = try protectedHeader(allocator, .eddsa);
    defer allocator.free(protected);
    const actual = try sigStructure(allocator, protected, "aad", "payload");
    defer allocator.free(actual);
    try expectHex(actual, "846a5369676e61747572653143a1012743616164477061796c6f6164");
}

test "build and verify COSE_Sign1 EdDSA" {
    const allocator = std.testing.allocator;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x42)));
    const cose = try encodeSign1Ed25519(allocator, "hello", "", kp);
    defer allocator.free(cose);
    try std.testing.expect(try verifySign1(allocator, cose, "", .{ .ed25519 = kp.public_key.toBytes() }));
}

test "COSE_Sign1 ES256 verifies" {
    const allocator = std.testing.allocator;
    const kp = try ecdsa_p256.generateDeterministic(@as([32]u8, @splat(0x33)));
    const sec1 = kp.public_key.toUncompressedSec1();
    const cose = try encodeSign1Es256(allocator, "p256 payload", "ctx", kp);
    defer allocator.free(cose);
    try std.testing.expect(try verifySign1(allocator, cose, "ctx", .{
        .p256 = .{ .x = sec1[1..33].*, .y = sec1[33..65].* },
    }));
}

test "COSE_Sign1 ES256 signs in constant time: std-identical bytes and fail-closed secret" {
    const allocator = std.testing.allocator;
    const kp = try ecdsa_p256.generateDeterministic(@as([32]u8, @splat(0x34)));
    const cose = try encodeSign1Es256(allocator, "p256 payload", "ctx", kp);
    defer allocator.free(cose);
    // The 64-byte r||s signature is the last CBOR item; with null noise it is
    // byte-identical to std's deterministic signer over the Sig_structure.
    const protected = try protectedHeader(allocator, .es256);
    defer allocator.free(protected);
    const to_sign = try sigStructure(allocator, protected, "ctx", "p256 payload");
    defer allocator.free(to_sign);
    const want = (try kp.sign(to_sign, null)).toBytes();
    try std.testing.expectEqualSlices(u8, &want, cose[cose.len - 64 ..]);
    // std's signer accepted d = 0; the constant-time signer refuses it
    // (SEC 1 v2 sec. 3.2.1), so a corrupt key can never emit a signature.
    const zero_kp: Es256.KeyPair = .{ .secret_key = try Es256.SecretKey.fromBytes(@splat(0)), .public_key = kp.public_key };
    try std.testing.expectError(error.IdentityElement, encodeSign1Es256(allocator, "p", "", zero_kp));
}

test "tampered payload and protected header are rejected" {
    const allocator = std.testing.allocator;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x24)));
    const cose = try encodeSign1Ed25519(allocator, "hello", "", kp);
    defer allocator.free(cose);

    var tampered_payload = try allocator.dupe(u8, cose);
    defer allocator.free(tampered_payload);
    tampered_payload[8] ^= 1;
    try std.testing.expect(!try verifySign1(allocator, tampered_payload, "", .{ .ed25519 = kp.public_key.toBytes() }));

    var tampered_header = try allocator.dupe(u8, cose);
    defer allocator.free(tampered_header);
    tampered_header[5] = 0x22;
    try std.testing.expectError(error.UnsupportedAlgorithm, verifySign1(allocator, tampered_header, "", .{ .ed25519 = kp.public_key.toBytes() }));
}

test "COSE_Key parse for OKP Ed25519 and EC2 P-256" {
    const allocator = std.testing.allocator;
    const ed = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x11)));
    var okp_list: std.ArrayList(u8) = .empty;
    defer okp_list.deinit(allocator);
    try appendCoseKeyOkp(&okp_list, allocator, ed.public_key.toBytes());
    const okp = try parseCoseKey(allocator, okp_list.items);
    try std.testing.expectEqualSlices(u8, &ed.public_key.toBytes(), &okp.ed25519);

    const ec = try ecdsa_p256.generateDeterministic(@as([32]u8, @splat(0x12)));
    const sec1 = ec.public_key.toUncompressedSec1();
    var ec2_list: std.ArrayList(u8) = .empty;
    defer ec2_list.deinit(allocator);
    try appendCoseKeyP256(&ec2_list, allocator, .{ .x = sec1[1..33].*, .y = sec1[33..65].* });
    const ec2 = try parseCoseKey(allocator, ec2_list.items);
    try std.testing.expectEqualSlices(u8, sec1[1..33], &ec2.p256.x);
    try std.testing.expectEqualSlices(u8, sec1[33..65], &ec2.p256.y);
}

test "CBOR round-trip for COSE structures" {
    const allocator = std.testing.allocator;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x55)));
    const cose = try encodeSign1Ed25519(allocator, "round", "aad", kp);
    defer allocator.free(cose);
    var decoded = try Cbor.decode(allocator, cose);
    defer decoded.deinit(allocator);
    const root = unwrapTag(decoded.root, 18) orelse return error.BadCbor;
    try std.testing.expect(root == .array);
    try std.testing.expectEqual(@as(usize, 4), root.array.len);
    try std.testing.expectEqualSlices(u8, "round", expectBytes(root.array[2]) orelse return error.BadCbor);

    const mac = try encodeMac0(allocator, "round", "aad", "secret");
    defer allocator.free(mac);
    try std.testing.expect(try verifyMac0(allocator, mac, "aad", "secret"));
}
