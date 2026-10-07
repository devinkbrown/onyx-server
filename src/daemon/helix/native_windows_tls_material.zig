// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact serving TLS material for a Windows Helix candidate. ACME may have
//! replaced the default certificate after boot, and an Ed25519 default leaf
//! uses an independently generated TLS 1.2 certificate. Neither generation
//! can be inferred from the successor's disk reads. The source must pause ACME
//! and hold the World cut while encoding; the candidate owns decoded material
//! before READY and installs it with no allocation at COMMIT.

const std = @import("std");
const frame = @import("native_windows_companion_wire.zig");
const proof = @import("native_windows_tls_proof.zig");
const tls_certs = @import("../tls_certs.zig");
const capsule = @import("capsule.zig");
const live = @import("live.zig");
const ecdsa_p256 = @import("../../crypto/ecdsa_p256.zig");
const rsa_sign = @import("../../crypto/rsa_sign.zig");

const Ed25519 = std.crypto.sign.Ed25519;
pub const checkpoint_magic = [_]u8{ 'H', 'X', 'T', 'M' };
const domain = "onyx-windows-serving-tls-material-v1";
// The source's serving digest is included in the authenticated payload so
// candidate decoding proves the exact TLS identity before READY.
const payload_header_len: usize = 52;
pub const max_chain_count: usize = 16;
pub const max_der_bytes: usize = 512 * 1024;
pub const max_component_bytes: usize = 16 * 1024;
pub const max_checkpoint_bytes: usize = 2 * 1024 * 1024;
pub const Error = error{ InvalidSnapshot, TooLarge, MissingCheckpoint, DuplicateCheckpoint } || std.mem.Allocator.Error;

const KeyKind = enum(u8) { ed25519 = 1, ecdsa_p256 = 2, rsa = 3 };

pub const Snapshot = struct {
    default: proof.Material,
    /// The actual Server.Config TLS 1.2 view, independent of the owned
    /// generation that should back it. The encoder proves the relation before
    /// omitting this redundant view from the wire.
    tls12_serving: ?proof.Material = null,
    tls12_mode: proof.Tls12Mode,
    generated_tls12: ?proof.GeneratedTls12 = null,
    reload_pending: bool = false,
    /// Same-host monotonic deadline for retrying a failed ACME TLS disk reload.
    reload_retry_after_ms: i64 = 0,
};

/// Detached candidate state. `release` is a no-fail ownership transfer into
/// Server.reload_tls and Server.reload_tls12; all validation is completed while
/// this value is still disposable.
pub const Owned = struct {
    allocator: std.mem.Allocator,
    default: ?tls_certs.Loaded = null,
    generated_tls12: ?tls_certs.Tls12 = null,
    tls12_mode: proof.Tls12Mode,
    reload_pending: bool,
    reload_retry_after_ms: i64,

    pub fn deinit(self: *Owned) void {
        if (self.default) |*loaded| loaded.deinit(self.allocator);
        if (self.generated_tls12) |*loaded| loaded.deinit(self.allocator);
        self.default = null;
        self.generated_tls12 = null;
    }

    pub fn servingDigest(self: *const Owned) proof.Error!proof.Digest {
        const loaded = if (self.default) |*value| value else return error.InvalidMaterial;
        return proof.digestServing(proof.fromLoaded(loaded), self.tls12_mode, if (self.generated_tls12) |*leg| .{
            .cert_chain = leg.cert_chain,
            .signing_key = &leg.key,
        } else null);
    }

    pub fn release(self: *Owned) State {
        const result = State{
            .default = self.default.?,
            .generated_tls12 = self.generated_tls12,
            .tls12_mode = self.tls12_mode,
            .reload_pending = self.reload_pending,
            .reload_retry_after_ms = self.reload_retry_after_ms,
        };
        self.default = null;
        self.generated_tls12 = null;
        return result;
    }
};

pub const State = struct {
    default: tls_certs.Loaded,
    generated_tls12: ?tls_certs.Tls12,
    tls12_mode: proof.Tls12Mode,
    reload_pending: bool,
    reload_retry_after_ms: i64,
};

pub fn isCheckpoint(bytes: []const u8) bool {
    return frame.isCheckpoint(bytes, checkpoint_magic);
}

pub fn freeEncoded(allocator: std.mem.Allocator, bytes: []u8) void {
    std.crypto.secureZero(u8, bytes);
    allocator.free(bytes);
}

fn kindOf(material: proof.Material) error{InvalidSnapshot}!KeyKind {
    const n: u8 = @as(u8, @intFromBool(material.signing_key != null)) +
        @as(u8, @intFromBool(material.ecdsa_p256_signing_key != null)) +
        @as(u8, @intFromBool(material.rsa_signing_key != null));
    if (n != 1) return error.InvalidSnapshot;
    return if (material.signing_key != null) .ed25519 else if (material.ecdsa_p256_signing_key != null) .ecdsa_p256 else .rsa;
}

fn checkedAdd(total: *usize, n: usize) Error!void {
    total.* = std.math.add(usize, total.*, n) catch return error.TooLarge;
    if (total.* > max_checkpoint_bytes - frame.header_len - frame.checksum_len) return error.TooLarge;
}

fn chainLength(chain: []const []const u8) Error!usize {
    if (chain.len == 0 or chain.len > max_chain_count) return error.InvalidSnapshot;
    var total: usize = 0;
    for (chain) |der| {
        if (der.len == 0) return error.InvalidSnapshot;
        if (der.len > max_der_bytes) return error.TooLarge;
        try checkedAdd(&total, 4 + der.len);
    }
    return total;
}

fn rsaFields(key: *const rsa_sign.PrivateKey) [8]?[]const u8 {
    return .{ key.n, key.e, key.d, key.p, key.q, key.dp, key.dq, key.qinv };
}

fn keyLength(material: proof.Material, kind: KeyKind) Error!usize {
    return switch (kind) {
        .ed25519 => Ed25519.SecretKey.encoded_length,
        .ecdsa_p256 => 32,
        .rsa => blk: {
            var total: usize = 0;
            var present: u8 = 0;
            for (rsaFields(material.rsa_signing_key.?), 0..) |field, index| {
                if (index < 3 and field == null) return error.InvalidSnapshot;
                if (field) |bytes| {
                    if (bytes.len == 0 or bytes.len > max_component_bytes) return error.InvalidSnapshot;
                    if (index >= 3) present += 1;
                    try checkedAdd(&total, 4 + bytes.len);
                } else try checkedAdd(&total, 4);
            }
            if (present != 0 and present != 5) return error.InvalidSnapshot;
            break :blk total;
        },
    };
}

pub fn encodeSnapshot(allocator: std.mem.Allocator, snapshot: Snapshot) ![]u8 {
    if (snapshot.reload_retry_after_ms < 0 or
        (!snapshot.reload_pending and snapshot.reload_retry_after_ms != 0)) return error.InvalidSnapshot;
    const kind = try kindOf(snapshot.default);
    const source_digest = try proof.digestServing(snapshot.default, snapshot.tls12_mode, snapshot.generated_tls12);
    try proof.validateIdentity(snapshot.default);
    if (snapshot.generated_tls12) |leg| try proof.validateGeneratedTls12(leg);
    if ((snapshot.tls12_mode == .disabled) != (snapshot.tls12_serving == null)) return error.InvalidSnapshot;
    if (snapshot.tls12_serving) |serving| {
        try proof.validateIdentity(serving);
        const expected: proof.Material = switch (snapshot.tls12_mode) {
            .disabled => unreachable,
            .shared_default => snapshot.default,
            .generated => .{
                .cert_chain = snapshot.generated_tls12.?.cert_chain,
                .ecdsa_p256_signing_key = snapshot.generated_tls12.?.signing_key,
            },
        };
        if (!proof.equal(try proof.digest(serving), try proof.digest(expected))) return error.InvalidSnapshot;
    }
    var payload_len: usize = payload_header_len;
    try checkedAdd(&payload_len, try chainLength(snapshot.default.cert_chain));
    try checkedAdd(&payload_len, try keyLength(snapshot.default, kind));
    if (snapshot.generated_tls12) |leg| {
        try checkedAdd(&payload_len, try chainLength(leg.cert_chain));
        try checkedAdd(&payload_len, 32);
    }
    const bytes = try frame.create(allocator, checkpoint_magic, payload_len);
    errdefer freeEncoded(allocator, bytes);
    const payload = bytes[frame.header_len .. bytes.len - frame.checksum_len];
    payload[0] = @intFromBool(snapshot.reload_pending);
    payload[1] = @intFromEnum(snapshot.tls12_mode);
    payload[2] = @intFromEnum(kind);
    payload[3] = 0;
    writeU32At(payload[4..8], @intCast(snapshot.default.cert_chain.len));
    writeU32At(payload[8..12], @intCast(if (snapshot.generated_tls12) |leg| leg.cert_chain.len else 0));
    @memcpy(payload[12..44], &source_digest);
    writeI64At(payload[44..52], snapshot.reload_retry_after_ms);
    var pos: usize = payload_header_len;
    writeChain(payload, &pos, snapshot.default.cert_chain);
    switch (kind) {
        .ed25519 => {
            var secret = snapshot.default.signing_key.?.secret_key.toBytes();
            defer std.crypto.secureZero(u8, &secret);
            writeBytes(payload, &pos, &secret);
        },
        .ecdsa_p256 => {
            var secret = snapshot.default.ecdsa_p256_signing_key.?.secret_key.toBytes();
            defer std.crypto.secureZero(u8, &secret);
            writeBytes(payload, &pos, &secret);
        },
        .rsa => for (rsaFields(snapshot.default.rsa_signing_key.?)) |field| {
            const component = field orelse &.{};
            writeU32At(payload[pos..][0..4], @intCast(component.len));
            pos += 4;
            writeBytes(payload, &pos, component);
        },
    }
    if (snapshot.generated_tls12) |leg| {
        writeChain(payload, &pos, leg.cert_chain);
        var secret = leg.signing_key.secret_key.toBytes();
        defer std.crypto.secureZero(u8, &secret);
        writeBytes(payload, &pos, &secret);
    }
    std.debug.assert(pos == payload.len);
    frame.finish(bytes, domain);
    try validateCheckpoint(bytes);
    return bytes;
}

fn writeBytes(out: []u8, pos: *usize, bytes: []const u8) void {
    @memcpy(out[pos.*..][0..bytes.len], bytes);
    pos.* += bytes.len;
}

fn writeU32At(out: []u8, value: u32) void {
    std.debug.assert(out.len == 4);
    var raw: [4]u8 = undefined;
    std.mem.writeInt(u32, &raw, value, .little);
    @memcpy(out, &raw);
}

fn readU32At(bytes: []const u8) u32 {
    std.debug.assert(bytes.len == 4);
    var raw: [4]u8 = undefined;
    @memcpy(&raw, bytes);
    return std.mem.readInt(u32, &raw, .little);
}

fn writeI64At(out: []u8, value: i64) void {
    std.debug.assert(out.len == 8);
    var raw: [8]u8 = undefined;
    std.mem.writeInt(i64, &raw, value, .little);
    @memcpy(out, &raw);
}

fn readI64At(bytes: []const u8) i64 {
    std.debug.assert(bytes.len == 8);
    var raw: [8]u8 = undefined;
    @memcpy(&raw, bytes);
    return std.mem.readInt(i64, &raw, .little);
}

fn writeChain(out: []u8, pos: *usize, chain: []const []const u8) void {
    for (chain) |der| {
        writeU32At(out[pos.*..][0..4], @intCast(der.len));
        pos.* += 4;
        writeBytes(out, pos, der);
    }
}

const Header = struct {
    reload_pending: bool,
    mode: proof.Tls12Mode,
    kind: KeyKind,
    chain13_count: usize,
    chain12_count: usize,
    source_digest: proof.Digest,
    reload_retry_after_ms: i64,
    payload: []const u8,
};

fn parseHeader(bytes: []const u8) error{InvalidSnapshot}!Header {
    if (bytes.len < frame.header_len + payload_header_len + frame.checksum_len or bytes.len > max_checkpoint_bytes)
        return error.InvalidSnapshot;
    const payload = try frame.validateFrame(bytes, checkpoint_magic, domain, bytes.len - frame.header_len - frame.checksum_len);
    if (payload[0] > 1 or payload[3] != 0) return error.InvalidSnapshot;
    const mode = std.enums.fromInt(proof.Tls12Mode, payload[1]) orelse return error.InvalidSnapshot;
    const kind = std.enums.fromInt(KeyKind, payload[2]) orelse return error.InvalidSnapshot;
    const chain13_count: usize = readU32At(payload[4..8]);
    const chain12_count: usize = readU32At(payload[8..12]);
    if (chain13_count == 0 or chain13_count > max_chain_count or chain12_count > max_chain_count or
        (mode == .generated) != (chain12_count != 0) or
        (mode == .generated and kind != .ed25519) or
        (mode == .shared_default and kind == .ed25519)) return error.InvalidSnapshot;
    var source_digest: proof.Digest = undefined;
    @memcpy(&source_digest, payload[12..44]);
    const reload_retry_after_ms = readI64At(payload[44..52]);
    if (reload_retry_after_ms < 0 or (payload[0] == 0 and reload_retry_after_ms != 0)) return error.InvalidSnapshot;
    return .{ .reload_pending = payload[0] == 1, .mode = mode, .kind = kind, .chain13_count = chain13_count, .chain12_count = chain12_count, .source_digest = source_digest, .reload_retry_after_ms = reload_retry_after_ms, .payload = payload };
}

const Reader = struct {
    payload: []const u8,
    pos: usize = payload_header_len,

    fn take(self: *Reader, len: usize) error{InvalidSnapshot}![]const u8 {
        if (self.pos > self.payload.len or len > self.payload.len - self.pos) return error.InvalidSnapshot;
        const value = self.payload[self.pos..][0..len];
        self.pos += len;
        return value;
    }

    fn readU32(self: *Reader) error{InvalidSnapshot}!u32 {
        const bytes = try self.take(4);
        return readU32At(bytes);
    }

    fn der(self: *Reader) error{InvalidSnapshot}![]const u8 {
        const len: usize = try self.readU32();
        if (len == 0 or len > max_der_bytes) return error.InvalidSnapshot;
        return self.take(len);
    }
};

fn readRsaFields(reader: *Reader) error{InvalidSnapshot}![8][]const u8 {
    var fields: [8][]const u8 = undefined;
    var present: u8 = 0;
    for (&fields, 0..) |*field, index| {
        const len: usize = try reader.readU32();
        if (len > max_component_bytes or (index < 3 and len == 0)) return error.InvalidSnapshot;
        if (index >= 3 and len != 0) present += 1;
        field.* = try reader.take(len);
    }
    if (present != 0 and present != 5) return error.InvalidSnapshot;
    return fields;
}

pub fn validateCheckpoint(bytes: []const u8) error{InvalidSnapshot}!void {
    const h = try parseHeader(bytes);
    var reader = Reader{ .payload = h.payload };
    for (0..h.chain13_count) |_| _ = try reader.der();
    switch (h.kind) {
        .ed25519 => _ = try reader.take(Ed25519.SecretKey.encoded_length),
        .ecdsa_p256 => _ = try reader.take(32),
        .rsa => _ = try readRsaFields(&reader),
    }
    for (0..h.chain12_count) |_| _ = try reader.der();
    if (h.mode == .generated) _ = try reader.take(32);
    if (reader.pos != h.payload.len) return error.InvalidSnapshot;
}

fn decodeChain(allocator: std.mem.Allocator, reader: *Reader, count: usize) Error![][]const u8 {
    const chain = try allocator.alloc([]const u8, count);
    var completed: usize = 0;
    errdefer {
        for (chain[0..completed]) |der| allocator.free(der);
        allocator.free(chain);
    }
    for (chain) |*entry| {
        entry.* = try allocator.dupe(u8, try reader.der());
        completed += 1;
    }
    return chain;
}

fn freeChain(allocator: std.mem.Allocator, chain: [][]const u8) void {
    for (chain) |der| allocator.free(der);
    allocator.free(chain);
}

pub fn decodeOwned(allocator: std.mem.Allocator, bytes: []const u8) !Owned {
    try validateCheckpoint(bytes);
    const h = try parseHeader(bytes);
    var reader = Reader{ .payload = h.payload };
    const default_chain = try decodeChain(allocator, &reader, h.chain13_count);
    var result = Owned{ .allocator = allocator, .tls12_mode = h.mode, .reload_pending = h.reload_pending, .reload_retry_after_ms = h.reload_retry_after_ms };
    result.default = .{
        .cert_chain = default_chain,
        .key_kind = switch (h.kind) {
            .ed25519 => .ed25519,
            .ecdsa_p256 => .ecdsa_p256,
            .rsa => .rsa,
        },
    };
    errdefer result.deinit();
    if (result.default) |*loaded| switch (h.kind) {
        .ed25519 => {
            const encoded = try reader.take(Ed25519.SecretKey.encoded_length);
            var raw: [Ed25519.SecretKey.encoded_length]u8 = undefined;
            @memcpy(&raw, encoded);
            defer std.crypto.secureZero(u8, &raw);
            loaded.signing_key = try Ed25519.KeyPair.fromSecretKey(try Ed25519.SecretKey.fromBytes(raw));
        },
        .ecdsa_p256 => {
            const encoded = try reader.take(32);
            var raw: [32]u8 = undefined;
            @memcpy(&raw, encoded);
            defer std.crypto.secureZero(u8, &raw);
            loaded.ecdsa_p256_signing_key = try ecdsa_p256.KeyPair.fromSecretKey(try ecdsa_p256.SecretKey.fromBytes(raw));
        },
        .rsa => {
            const fields = try readRsaFields(&reader);
            var total: usize = 0;
            for (fields) |field| total += field.len;
            const storage = try allocator.alloc(u8, total);
            loaded.rsa_key_storage = storage;
            var parts: [8][]const u8 = undefined;
            var pos: usize = 0;
            for (fields, &parts) |field, *part| {
                @memcpy(storage[pos..][0..field.len], field);
                part.* = storage[pos..][0..field.len];
                pos += field.len;
            }
            loaded.rsa_signing_key = rsa_sign.PrivateKey{
                .n = parts[0],
                .e = parts[1],
                .d = parts[2],
                .p = if (parts[3].len != 0) parts[3] else null,
                .q = if (parts[4].len != 0) parts[4] else null,
                .dp = if (parts[5].len != 0) parts[5] else null,
                .dq = if (parts[6].len != 0) parts[6] else null,
                .qinv = if (parts[7].len != 0) parts[7] else null,
            };
        },
    };
    try proof.validateIdentity(proof.fromLoaded(&result.default.?));
    if (h.mode == .generated) {
        const chain = try decodeChain(allocator, &reader, h.chain12_count);
        var chain_owned = true;
        errdefer if (chain_owned) freeChain(allocator, chain);
        const encoded = try reader.take(32);
        var raw: [32]u8 = undefined;
        @memcpy(&raw, encoded);
        defer std.crypto.secureZero(u8, &raw);
        const key = try ecdsa_p256.KeyPair.fromSecretKey(try ecdsa_p256.SecretKey.fromBytes(raw));
        result.generated_tls12 = .{ .cert_chain = chain, .key = key };
        chain_owned = false;
        try proof.validateGeneratedTls12(.{ .cert_chain = chain, .signing_key = &result.generated_tls12.?.key });
    }
    if (reader.pos != h.payload.len) return error.InvalidSnapshot;
    const decoded_digest = try result.servingDigest();
    if (!proof.equal(h.source_digest, decoded_digest)) return error.InvalidSnapshot;
    return result;
}

/// Preflight the source's complete authenticated arena before a parked Windows
/// WebTransport owner borrows its serving certificate. This does not publish
/// server state. The caller retains the returned owner through listener teardown.
pub fn preflightOwnedFromArena(allocator: std.mem.Allocator, authenticated_plaintext: []const u8) Error!Owned {
    if (authenticated_plaintext.len == 0 or authenticated_plaintext.len > live.max_arena_bytes)
        return error.InvalidSnapshot;
    const caps = capsule.decodeStream(allocator, authenticated_plaintext) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidSnapshot,
    };
    defer {
        for (caps) |*item| {
            // HXTM is a mesh checkpoint, whose general capsule kind is not
            // secret-bearing. Wipe this decoded copy of its private key.
            if (item.header.kind == .mesh_checkpoint) for (item.fields) |field| {
                if (isCheckpoint(field.bytes)) std.crypto.secureZero(u8, @constCast(field.bytes));
            };
            item.deinit(allocator);
        }
        allocator.free(caps);
    }
    live.verifyHandoffManifest(caps) catch return error.InvalidSnapshot;

    var checkpoint: ?[]const u8 = null;
    const expected = capsule.Header.init(.mesh_checkpoint);
    for (caps) |item| {
        if (item.header.kind != .mesh_checkpoint or item.fields.len != 1 or
            !isCheckpoint(item.fields[0].bytes)) continue;
        if (checkpoint != null) return error.DuplicateCheckpoint;
        if (item.fields[0].ordinal != 1 or item.header.schema_id != expected.schema_id or
            item.header.version != expected.version or
            item.header.min_supported != expected.version or
            item.header.max_supported != expected.max_supported)
            return error.InvalidSnapshot;
        checkpoint = item.fields[0].bytes;
    }
    const bytes = checkpoint orelse return error.MissingCheckpoint;
    return decodeOwned(allocator, bytes) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidSnapshot,
    };
}

test "HXTM arena preflight requires one canonical checkpoint and whole manifest" {
    const allocator = std.testing.allocator;
    const x509_selfsign = @import("../../proto/x509_selfsign.zig");
    const Fixture = struct {
        fn arena(a: std.mem.Allocator, pieces: []const live.StatePiece) ![]u8 {
            var manifested = try live.appendHandoffManifest(a, pieces);
            defer manifested.deinit(a);
            var out: std.ArrayList(u8) = .empty;
            errdefer {
                std.crypto.secureZero(u8, out.items);
                out.deinit(a);
            }
            for (manifested.pieces) |piece| {
                var fields = [_]capsule.Field{.{ .ordinal = 1, .bytes = piece.bytes }};
                var item = capsule.make(piece.kind, &fields);
                if (piece.min_supported) |minimum| item.header.min_supported = minimum;
                const encoded = try capsule.encode(a, item);
                defer {
                    std.crypto.secureZero(u8, encoded);
                    a.free(encoded);
                }
                try out.appendSlice(a, encoded);
            }
            return out.toOwnedSlice(a);
        }
        fn freeArena(a: std.mem.Allocator, bytes: []u8) void {
            std.crypto.secureZero(u8, bytes);
            a.free(bytes);
        }
    };

    const key = try Ed25519.KeyPair.generateDeterministic(@splat(0x47));
    var cert_buf: [4096]u8 = undefined;
    const cert = try x509_selfsign.buildSelfSigned(&cert_buf, .{
        .common_name = "preflight.test",
        .not_before = 1_700_000_000,
        .not_after = 1_900_000_000,
        .serial = &.{7},
        .key_pair = key,
    });
    const chain = [_][]const u8{cert};
    const wire = try encodeSnapshot(allocator, .{
        .default = .{ .cert_chain = &chain, .signing_key = &key },
        .tls12_mode = .disabled,
    });
    defer freeEncoded(allocator, wire);

    const valid = try Fixture.arena(allocator, &.{.{ .kind = .mesh_checkpoint, .bytes = wire, .min_supported = 2 }});
    defer Fixture.freeArena(allocator, valid);
    var owned = try preflightOwnedFromArena(allocator, valid);
    defer owned.deinit();
    try std.testing.expectEqualSlices(u8, cert, owned.default.?.cert_chain[0]);

    const missing = try Fixture.arena(allocator, &.{.{ .kind = .mesh_checkpoint, .bytes = "other" }});
    defer Fixture.freeArena(allocator, missing);
    try std.testing.expectError(error.MissingCheckpoint, preflightOwnedFromArena(allocator, missing));

    const duplicate = try Fixture.arena(allocator, &.{
        .{ .kind = .mesh_checkpoint, .bytes = wire, .min_supported = 2 },
        .{ .kind = .mesh_checkpoint, .bytes = wire, .min_supported = 2 },
    });
    defer Fixture.freeArena(allocator, duplicate);
    try std.testing.expectError(error.DuplicateCheckpoint, preflightOwnedFromArena(allocator, duplicate));

    const malformed = try Fixture.arena(allocator, &.{.{ .kind = .mesh_checkpoint, .bytes = "HXTM", .min_supported = 2 }});
    defer Fixture.freeArena(allocator, malformed);
    try std.testing.expectError(error.InvalidSnapshot, preflightOwnedFromArena(allocator, malformed));

    const overlapping_header = try Fixture.arena(allocator, &.{.{ .kind = .mesh_checkpoint, .bytes = wire }});
    defer Fixture.freeArena(allocator, overlapping_header);
    try std.testing.expectError(error.InvalidSnapshot, preflightOwnedFromArena(allocator, overlapping_header));

    const tampered = try allocator.dupe(u8, valid);
    defer Fixture.freeArena(allocator, tampered);
    const offset = std.mem.indexOf(u8, tampered, "HXTM") orelse return error.TestUnexpectedResult;
    tampered[offset + 4] ^= 1;
    try std.testing.expectError(error.InvalidSnapshot, preflightOwnedFromArena(allocator, tampered));
}

test "HXTM carries exact Ed25519 and generated TLS 1.2 material with pending reload" {
    const allocator = std.testing.allocator;
    const x509_selfsign = @import("../../proto/x509_selfsign.zig");
    const ed = try Ed25519.KeyPair.generateDeterministic(@splat(0x42));
    const ec = try ecdsa_p256.KeyPair.fromSecretKey(try ecdsa_p256.SecretKey.fromBytes(@splat(0x23)));
    var cert13_buf: [4096]u8 = undefined;
    var cert12_buf: [4096]u8 = undefined;
    const cert13 = try x509_selfsign.buildSelfSigned(&cert13_buf, .{ .common_name = "acme.test", .not_before = 1_700_000_000, .not_after = 1_900_000_000, .serial = &.{1}, .key_pair = ed });
    const cert12 = try x509_selfsign.buildSelfSignedEcdsaP256(&cert12_buf, .{ .common_name = "acme.test", .not_before = 1_700_000_000, .not_after = 1_900_000_000, .serial = &.{2}, .key_pair = ec });
    const chain13 = [_][]const u8{cert13};
    const chain12 = [_][]const u8{cert12};
    const source = Snapshot{
        .default = .{ .cert_chain = &chain13, .signing_key = &ed },
        .tls12_serving = .{ .cert_chain = &chain12, .ecdsa_p256_signing_key = &ec },
        .tls12_mode = .generated,
        .generated_tls12 = .{ .cert_chain = &chain12, .signing_key = &ec },
        .reload_pending = true,
        .reload_retry_after_ms = 123_456_789,
    };
    const wrong_ec = try ecdsa_p256.KeyPair.fromSecretKey(try ecdsa_p256.SecretKey.fromBytes(@splat(0x24)));
    var wrong_leg = source;
    wrong_leg.tls12_serving = .{ .cert_chain = &chain12, .ecdsa_p256_signing_key = &wrong_ec };
    try std.testing.expectError(error.TlsKeyMismatch, encodeSnapshot(allocator, wrong_leg));
    const wire = try encodeSnapshot(allocator, source);
    defer freeEncoded(allocator, wire);
    var owned = try decodeOwned(allocator, wire);
    defer owned.deinit();
    try std.testing.expect(owned.reload_pending);
    try std.testing.expectEqual(@as(i64, 123_456_789), owned.reload_retry_after_ms);
    try std.testing.expectEqual(proof.Tls12Mode.generated, owned.tls12_mode);
    try std.testing.expectEqualSlices(u8, cert13, owned.default.?.cert_chain[0]);
    try std.testing.expectEqualSlices(u8, cert12, owned.generated_tls12.?.cert_chain[0]);
    const source_digest = try proof.digestServing(source.default, source.tls12_mode, source.generated_tls12);
    try std.testing.expect(proof.equal(source_digest, try owned.servingDigest()));
    const decoded_digest = try proof.digestServing(proof.fromLoaded(&owned.default.?), owned.tls12_mode, .{ .cert_chain = owned.generated_tls12.?.cert_chain, .signing_key = &owned.generated_tls12.?.key });
    try std.testing.expect(proof.equal(source_digest, decoded_digest));
    const state = owned.release();
    try std.testing.expect(owned.default == null and owned.generated_tls12 == null);
    if (state.generated_tls12) |side| {
        const repeat = try encodeSnapshot(allocator, .{
            .default = proof.fromLoaded(&state.default),
            .tls12_serving = .{ .cert_chain = side.cert_chain, .ecdsa_p256_signing_key = &side.key },
            .tls12_mode = .generated,
            .generated_tls12 = .{ .cert_chain = side.cert_chain, .signing_key = &side.key },
            .reload_pending = state.reload_pending,
            .reload_retry_after_ms = state.reload_retry_after_ms,
        });
        defer freeEncoded(allocator, repeat);
        var second = try decodeOwned(allocator, repeat);
        defer second.deinit();
        try std.testing.expect(proof.equal(source_digest, try second.servingDigest()));
        try std.testing.expect(second.reload_pending);
        try std.testing.expectEqual(state.reload_retry_after_ms, second.reload_retry_after_ms);
    } else return error.TestUnexpectedResult;
    var default_owned = state.default;
    default_owned.deinit(allocator);
    var side_owned = state.generated_tls12.?;
    side_owned.deinit(allocator);
}

test "HXTM second handoff carries a renewed generation instead of the first" {
    const allocator = std.testing.allocator;
    const x509_selfsign = @import("../../proto/x509_selfsign.zig");
    const ed_a = try Ed25519.KeyPair.generateDeterministic(@splat(0x51));
    const ed_b = try Ed25519.KeyPair.generateDeterministic(@splat(0x52));
    const ec_a = try ecdsa_p256.KeyPair.fromSecretKey(try ecdsa_p256.SecretKey.fromBytes(@splat(0x31)));
    const ec_b = try ecdsa_p256.KeyPair.fromSecretKey(try ecdsa_p256.SecretKey.fromBytes(@splat(0x32)));
    var cert13_a_buf: [4096]u8 = undefined;
    var cert13_b_buf: [4096]u8 = undefined;
    var cert12_a_buf: [4096]u8 = undefined;
    var cert12_b_buf: [4096]u8 = undefined;
    const chain13_a = [_][]const u8{try x509_selfsign.buildSelfSigned(&cert13_a_buf, .{ .common_name = "renew.test", .not_before = 1_700_000_000, .not_after = 1_900_000_000, .serial = &.{1}, .key_pair = ed_a })};
    const chain13_b = [_][]const u8{try x509_selfsign.buildSelfSigned(&cert13_b_buf, .{ .common_name = "renew.test", .not_before = 1_700_000_000, .not_after = 1_900_000_000, .serial = &.{2}, .key_pair = ed_b })};
    const chain12_a = [_][]const u8{try x509_selfsign.buildSelfSignedEcdsaP256(&cert12_a_buf, .{ .common_name = "renew.test", .not_before = 1_700_000_000, .not_after = 1_900_000_000, .serial = &.{3}, .key_pair = ec_a })};
    const chain12_b = [_][]const u8{try x509_selfsign.buildSelfSignedEcdsaP256(&cert12_b_buf, .{ .common_name = "renew.test", .not_before = 1_700_000_000, .not_after = 1_900_000_000, .serial = &.{4}, .key_pair = ec_b })};
    const source_a = Snapshot{
        .default = .{ .cert_chain = &chain13_a, .signing_key = &ed_a },
        .tls12_serving = .{ .cert_chain = &chain12_a, .ecdsa_p256_signing_key = &ec_a },
        .tls12_mode = .generated,
        .generated_tls12 = .{ .cert_chain = &chain12_a, .signing_key = &ec_a },
    };
    const wire_a = try encodeSnapshot(allocator, source_a);
    defer freeEncoded(allocator, wire_a);
    var first = try decodeOwned(allocator, wire_a);
    defer first.deinit();
    const first_digest = try first.servingDigest();
    const source_b = Snapshot{
        .default = .{ .cert_chain = &chain13_b, .signing_key = &ed_b },
        .tls12_serving = .{ .cert_chain = &chain12_b, .ecdsa_p256_signing_key = &ec_b },
        .tls12_mode = .generated,
        .generated_tls12 = .{ .cert_chain = &chain12_b, .signing_key = &ec_b },
        .reload_pending = true,
        .reload_retry_after_ms = 999_999,
    };
    const wire_b = try encodeSnapshot(allocator, source_b);
    defer freeEncoded(allocator, wire_b);
    var second = try decodeOwned(allocator, wire_b);
    defer second.deinit();
    const second_digest = try second.servingDigest();
    try std.testing.expect(!proof.equal(first_digest, second_digest));
    try std.testing.expect(proof.equal(second_digest, try proof.digestServing(source_b.default, source_b.tls12_mode, source_b.generated_tls12)));
    try std.testing.expect(second.reload_pending and !first.reload_pending);
    try std.testing.expectEqual(source_b.reload_retry_after_ms, second.reload_retry_after_ms);
    try std.testing.expectEqualSlices(u8, chain13_b[0], second.default.?.cert_chain[0]);
    try std.testing.expectEqualSlices(u8, chain12_b[0], second.generated_tls12.?.cert_chain[0]);
}

test "HXTM shared TLS 1.2 leg follows the default P256 generation" {
    const allocator = std.testing.allocator;
    const x509_selfsign = @import("../../proto/x509_selfsign.zig");
    const ec = try ecdsa_p256.KeyPair.fromSecretKey(try ecdsa_p256.SecretKey.fromBytes(@splat(0x34)));
    var cert_buf: [4096]u8 = undefined;
    const cert = try x509_selfsign.buildSelfSignedEcdsaP256(&cert_buf, .{ .common_name = "shared.test", .not_before = 1_700_000_000, .not_after = 1_900_000_000, .serial = &.{5}, .key_pair = ec });
    const chain = [_][]const u8{cert};
    const material = proof.Material{ .cert_chain = &chain, .ecdsa_p256_signing_key = &ec };
    const wire = try encodeSnapshot(allocator, .{ .default = material, .tls12_serving = material, .tls12_mode = .shared_default });
    defer freeEncoded(allocator, wire);
    var owned = try decodeOwned(allocator, wire);
    defer owned.deinit();
    try std.testing.expectEqual(proof.Tls12Mode.shared_default, owned.tls12_mode);
    try std.testing.expect(owned.generated_tls12 == null);
    try std.testing.expect(proof.equal(try owned.servingDigest(), try proof.digestServing(material, .shared_default, null)));
    try std.testing.expectEqualSlices(u8, cert, owned.default.?.cert_chain[0]);
}

test "HXTM rejects malformed flags and tampered authenticated material" {
    const allocator = std.testing.allocator;
    const x509_selfsign = @import("../../proto/x509_selfsign.zig");
    const ed = try Ed25519.KeyPair.generateDeterministic(@splat(0x43));
    var cert_buf: [4096]u8 = undefined;
    const cert = try x509_selfsign.buildSelfSigned(&cert_buf, .{ .common_name = "acme.test", .not_before = 1_700_000_000, .not_after = 1_900_000_000, .serial = &.{3}, .key_pair = ed });
    const chain = [_][]const u8{cert};
    const wire = try encodeSnapshot(allocator, .{ .default = .{ .cert_chain = &chain, .signing_key = &ed }, .tls12_mode = .disabled });
    defer freeEncoded(allocator, wire);
    const changed = try allocator.dupe(u8, wire);
    defer freeEncoded(allocator, changed);
    changed[frame.header_len] = 2;
    frame.finish(changed, domain);
    try std.testing.expectError(error.InvalidSnapshot, validateCheckpoint(changed));
    changed[frame.header_len] = 0;
    changed[frame.header_len + payload_header_len + 4] ^= 1;
    try std.testing.expectError(error.InvalidSnapshot, validateCheckpoint(changed));
    // A syntactically valid, rechecksummed frame still cannot claim a serving
    // digest different from the decoded certificate and signing key.
    @memcpy(changed, wire);
    changed[frame.header_len + 12] ^= 1;
    frame.finish(changed, domain);
    try std.testing.expectError(error.InvalidSnapshot, decodeOwned(allocator, changed));
    @memcpy(changed, wire);
    writeI64At(changed[frame.header_len + 44 ..][0..8], -1);
    frame.finish(changed, domain);
    try std.testing.expectError(error.InvalidSnapshot, validateCheckpoint(changed));
    @memcpy(changed, wire);
    writeI64At(changed[frame.header_len + 44 ..][0..8], 1);
    frame.finish(changed, domain);
    try std.testing.expectError(error.InvalidSnapshot, validateCheckpoint(changed));
}

test "HXTM detached decode rolls back every failed allocation" {
    const allocator = std.testing.allocator;
    const x509_selfsign = @import("../../proto/x509_selfsign.zig");
    const ed = try Ed25519.KeyPair.generateDeterministic(@splat(0x44));
    var cert_buf: [4096]u8 = undefined;
    const cert = try x509_selfsign.buildSelfSigned(&cert_buf, .{ .common_name = "acme.test", .not_before = 1_700_000_000, .not_after = 1_900_000_000, .serial = &.{4}, .key_pair = ed });
    const chain = [_][]const u8{cert};
    const wire = try encodeSnapshot(allocator, .{ .default = .{ .cert_chain = &chain, .signing_key = &ed }, .tls12_mode = .disabled });
    defer freeEncoded(allocator, wire);
    const Sweep = struct {
        fn run(a: std.mem.Allocator, bytes: []const u8) !void {
            var owned = try decodeOwned(a, bytes);
            defer owned.deinit();
            try std.testing.expect(owned.default != null);
        }
    };
    try std.testing.checkAllAllocationFailures(allocator, Sweep.run, .{wire});
}

test "HXTM RSA component shape requires all CRT fields together" {
    const chain = [_][]const u8{"leaf"};
    const bare = rsa_sign.PrivateKey{ .n = "n", .e = "e", .d = "d" };
    const bare_material = proof.Material{ .cert_chain = &chain, .rsa_signing_key = &bare };
    try std.testing.expectEqual(@as(usize, 8 * 4 + 3), try keyLength(bare_material, .rsa));
    const complete = rsa_sign.PrivateKey{ .n = "n", .e = "e", .d = "d", .p = "p", .q = "q", .dp = "dp", .dq = "dq", .qinv = "qi" };
    try std.testing.expectEqual(@as(usize, 8 * 4 + 11), try keyLength(.{ .cert_chain = &chain, .rsa_signing_key = &complete }, .rsa));
    const partial = rsa_sign.PrivateKey{ .n = "n", .e = "e", .d = "d", .p = "p" };
    try std.testing.expectError(error.InvalidSnapshot, keyLength(.{ .cert_chain = &chain, .rsa_signing_key = &partial }, .rsa));
}
