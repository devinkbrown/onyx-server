// SPDX-License-Identifier: AGPL-3.0-or-later
//! HXHL: the history HTTPS listener's own certificate/key generation, ticket
//! keys, and OCSP staple. It is independent of Server's current serving TLS
//! generation: the listener keeps a copy made when it opened and can lag an
//! ACME reload or ticket rotation.
const std = @import("std");
const tls_server = @import("../../crypto/tls_server.zig");
const tls_resumption = @import("../../crypto/tls_resumption.zig");
const tls_material = @import("native_windows_tls_material.zig");
const tls_proof = @import("native_windows_tls_proof.zig");
const frame = @import("native_windows_companion_wire.zig");
const capsule = @import("capsule.zig");
const live = @import("live.zig");

pub const checkpoint_magic = [_]u8{ 'H', 'X', 'H', 'L' };
const domain = "onyx-windows-history-tls-material-v2";
const payload_version: u16 = 2;
const payload_header_len: usize = 76;
const current_key_flag: u16 = 1;
const previous_key_flag: u16 = 2;
pub const max_staple_bytes: usize = 64 * 1024;
pub const max_checkpoint_bytes: usize = frame.header_len + payload_header_len + tls_material.max_checkpoint_bytes + max_staple_bytes + frame.checksum_len;
pub const Error = error{ InvalidSnapshot, TooLarge, MissingCheckpoint, DuplicateCheckpoint } || std.mem.Allocator.Error;

pub const Owned = struct {
    allocator: std.mem.Allocator,
    material: tls_material.Owned,
    staple: ?[]u8 = null,
    current_ticket_key: ?tls_resumption.TicketKey = null,
    previous_ticket_key: ?tls_resumption.TicketKey = null,

    pub fn deinit(self: *Owned) void {
        self.material.deinit();
        if (self.staple) |bytes| {
            std.crypto.secureZero(u8, bytes);
            self.allocator.free(bytes);
        }
        self.staple = null;
        if (self.current_ticket_key) |*key| std.crypto.secureZero(u8, key);
        if (self.previous_ticket_key) |*key| std.crypto.secureZero(u8, key);
        self.current_ticket_key = null;
        self.previous_ticket_key = null;
    }

    /// The returned slices borrow this detached owner. Keep it alive until
    /// Server's inherited history worker has joined and Server is deinitialized.
    pub fn tlsConfig(self: *const Owned, base: tls_server.Config) tls_server.Config {
        const loaded = &self.material.default.?;
        var config = base;
        config.cert_chain = loaded.cert_chain;
        config.signing_key = loaded.signing_key;
        config.ecdsa_p256_signing_key = loaded.ecdsa_p256_signing_key;
        config.rsa_signing_key = loaded.rsa_signing_key;
        config.ocsp_staple = self.staple orelse &.{};
        config.ticket_key = self.current_ticket_key;
        config.previous_ticket_key = self.previous_ticket_key;
        return config;
    }
};

pub fn isCheckpoint(bytes: []const u8) bool {
    return frame.isCheckpoint(bytes, checkpoint_magic);
}

pub fn freeEncoded(allocator: std.mem.Allocator, bytes: []u8) void {
    std.crypto.secureZero(u8, bytes);
    allocator.free(bytes);
}

fn sourceMaterial(config: *const tls_server.Config) tls_proof.Material {
    return .{
        .cert_chain = config.cert_chain,
        .signing_key = if (config.signing_key) |*key| key else null,
        .ecdsa_p256_signing_key = if (config.ecdsa_p256_signing_key) |*key| key else null,
        .rsa_signing_key = if (config.rsa_signing_key) |*key| key else null,
    };
}

pub fn encodeSnapshot(allocator: std.mem.Allocator, config: tls_server.Config) ![]u8 {
    if (config.ocsp_staple.len > max_staple_bytes) return error.TooLarge;
    const nested = try tls_material.encodeSnapshot(allocator, .{
        .default = sourceMaterial(&config),
        .tls12_mode = .disabled,
    });
    defer tls_material.freeEncoded(allocator, nested);
    const payload_len = payload_header_len + nested.len + config.ocsp_staple.len;
    if (payload_len > max_checkpoint_bytes - frame.header_len - frame.checksum_len) return error.TooLarge;
    const bytes = try frame.create(allocator, checkpoint_magic, payload_len);
    errdefer freeEncoded(allocator, bytes);
    const payload = bytes[frame.header_len .. bytes.len - frame.checksum_len];
    std.mem.writeInt(u16, payload[0..2], payload_version, .little);
    var flags: u16 = 0;
    if (config.ticket_key != null) flags |= current_key_flag;
    if (config.previous_ticket_key != null) flags |= previous_key_flag;
    std.mem.writeInt(u16, payload[2..4], flags, .little);
    std.mem.writeInt(u32, payload[4..8], @intCast(nested.len), .little);
    std.mem.writeInt(u32, payload[8..12], @intCast(config.ocsp_staple.len), .little);
    @memset(payload[12..76], 0);
    if (config.ticket_key) |key| @memcpy(payload[12..44], &key);
    if (config.previous_ticket_key) |key| @memcpy(payload[44..76], &key);
    @memcpy(payload[payload_header_len..][0..nested.len], nested);
    @memcpy(payload[payload_header_len + nested.len ..], config.ocsp_staple);
    frame.finish(bytes, domain);
    return bytes;
}

const Parts = struct {
    nested: []const u8,
    staple: []const u8,
    current_ticket_key: ?[]const u8,
    previous_ticket_key: ?[]const u8,
};

fn parse(bytes: []const u8) error{InvalidSnapshot}!Parts {
    if (bytes.len < frame.header_len + payload_header_len + frame.checksum_len or bytes.len > max_checkpoint_bytes)
        return error.InvalidSnapshot;
    const payload = try frame.validateFrame(bytes, checkpoint_magic, domain, bytes.len - frame.header_len - frame.checksum_len);
    const flags = std.mem.readInt(u16, payload[2..4], .little);
    const zero_key: tls_resumption.TicketKey = @splat(0);
    if (std.mem.readInt(u16, payload[0..2], .little) != payload_version or
        flags & ~(current_key_flag | previous_key_flag) != 0 or
        (flags & current_key_flag == 0 and !std.mem.eql(u8, payload[12..44], &zero_key)) or
        (flags & previous_key_flag == 0 and !std.mem.eql(u8, payload[44..76], &zero_key)))
        return error.InvalidSnapshot;
    const nested_len: usize = std.mem.readInt(u32, payload[4..8], .little);
    const staple_len: usize = std.mem.readInt(u32, payload[8..12], .little);
    if (nested_len < frame.header_len + frame.checksum_len or nested_len > tls_material.max_checkpoint_bytes or
        staple_len > max_staple_bytes or nested_len > payload.len - payload_header_len or
        staple_len != payload.len - payload_header_len - nested_len) return error.InvalidSnapshot;
    const nested = payload[payload_header_len..][0..nested_len];
    try tls_material.validateCheckpoint(nested);
    // HXTM is reused only for its exact default certificate/key codec. Reject
    // its serving TLS 1.2 and reload scheduler fields in this history-only row.
    const nested_payload = nested[frame.header_len .. nested.len - frame.checksum_len];
    if (nested_payload[0] != 0 or nested_payload[1] != @intFromEnum(tls_proof.Tls12Mode.disabled) or
        std.mem.readInt(u32, nested_payload[8..12], .little) != 0 or
        std.mem.readInt(i64, nested_payload[44..52], .little) != 0) return error.InvalidSnapshot;
    return .{
        .nested = nested,
        .staple = payload[payload_header_len + nested_len ..],
        .current_ticket_key = if (flags & current_key_flag != 0) payload[12..44] else null,
        .previous_ticket_key = if (flags & previous_key_flag != 0) payload[44..76] else null,
    };
}

pub fn validateCheckpoint(bytes: []const u8) error{InvalidSnapshot}!void {
    _ = try parse(bytes);
}

pub fn decodeOwned(allocator: std.mem.Allocator, bytes: []const u8) !Owned {
    const parts = try parse(bytes);
    var material = try tls_material.decodeOwned(allocator, parts.nested);
    errdefer material.deinit();
    var result = Owned{ .allocator = allocator, .material = material };
    if (parts.staple.len != 0) result.staple = try allocator.dupe(u8, parts.staple);
    if (parts.current_ticket_key) |key| result.current_ticket_key = key[0..32].*;
    if (parts.previous_ticket_key) |key| result.previous_ticket_key = key[0..32].*;
    return result;
}

/// Preflight the whole authenticated arena and its manifest before importing
/// the history SOCKET. This is the same strict envelope check used by HXTM.
pub fn decodeFromArena(allocator: std.mem.Allocator, plaintext: []const u8) !Owned {
    if (plaintext.len == 0 or plaintext.len > live.max_arena_bytes) return error.InvalidSnapshot;
    const caps = capsule.decodeStream(allocator, plaintext) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidSnapshot,
    };
    defer {
        for (caps) |*item| {
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
        for (item.fields) |field| {
            if (!isCheckpoint(field.bytes)) continue;
            if (checkpoint != null) return error.DuplicateCheckpoint;
            if (item.header.kind != .mesh_checkpoint or item.fields.len != 1 or field.ordinal != 1 or
                item.header.schema_id != expected.schema_id or item.header.version != expected.version or
                item.header.min_supported != expected.version or item.header.max_supported != expected.max_supported)
                return error.InvalidSnapshot;
            checkpoint = field.bytes;
        }
    }
    return decodeOwned(allocator, checkpoint orelse return error.MissingCheckpoint) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidSnapshot,
    };
}

test "HXHL carries stale history leaf and full-size OCSP independent of candidate boot" {
    const x509_selfsign = @import("../../proto/x509_selfsign.zig");
    const Ed25519 = std.crypto.sign.Ed25519;
    const allocator = std.testing.allocator;
    const source_key = try Ed25519.KeyPair.generateDeterministic(@splat(0x51));
    const boot_key = try Ed25519.KeyPair.generateDeterministic(@splat(0x52));
    var source_cert_buf: [4096]u8 = undefined;
    var boot_cert_buf: [4096]u8 = undefined;
    const source_cert = try x509_selfsign.buildSelfSigned(&source_cert_buf, .{ .common_name = "history.test", .not_before = 1_700_000_000, .not_after = 1_900_000_000, .serial = &.{1}, .key_pair = source_key });
    const boot_cert = try x509_selfsign.buildSelfSigned(&boot_cert_buf, .{ .common_name = "history.test", .not_before = 1_700_000_000, .not_after = 1_900_000_000, .serial = &.{2}, .key_pair = boot_key });
    const source_chain = [_][]const u8{source_cert};
    const boot_chain = [_][]const u8{boot_cert};
    const staple: [max_staple_bytes]u8 = @splat(0x5a);
    const wire = try encodeSnapshot(allocator, .{ .cert_chain = &source_chain, .signing_key = source_key, .ocsp_staple = &staple, .ticket_key = @splat(0x31), .previous_ticket_key = @splat(0x32) });
    defer freeEncoded(allocator, wire);
    var owned = try decodeOwned(allocator, wire);
    defer owned.deinit();
    const restored = owned.tlsConfig(.{ .cert_chain = &boot_chain, .signing_key = boot_key });
    try std.testing.expectEqualSlices(u8, source_cert, restored.cert_chain[0]);
    try std.testing.expectEqual(source_key.secret_key.toBytes(), restored.signing_key.?.secret_key.toBytes());
    try std.testing.expectEqualSlices(u8, &staple, restored.ocsp_staple);
    try std.testing.expectEqual(@as(tls_resumption.TicketKey, @splat(0x31)), restored.ticket_key.?);
    try std.testing.expectEqual(@as(tls_resumption.TicketKey, @splat(0x32)), restored.previous_ticket_key.?);
    var corrupt = try allocator.dupe(u8, wire);
    defer freeEncoded(allocator, corrupt);
    corrupt[4] = 2;
    try std.testing.expectError(error.InvalidSnapshot, validateCheckpoint(corrupt));
    @memcpy(corrupt, wire);
    corrupt[frame.header_len + 4] = 0xff;
    try std.testing.expectError(error.InvalidSnapshot, validateCheckpoint(corrupt));
    @memcpy(corrupt, wire);
    corrupt[frame.header_len] = 1;
    frame.finish(corrupt, domain);
    try std.testing.expectError(error.InvalidSnapshot, validateCheckpoint(corrupt));
    @memcpy(corrupt, wire);
    corrupt[frame.header_len + 2] &= ~@as(u8, current_key_flag);
    frame.finish(corrupt, domain);
    try std.testing.expectError(error.InvalidSnapshot, validateCheckpoint(corrupt));
}

test "HXHL rejects staple beyond accepted OCSP limit" {
    const oversized: [max_staple_bytes + 1]u8 = @splat(0x5a);
    try std.testing.expectError(error.TooLarge, encodeSnapshot(std.testing.allocator, .{ .cert_chain = &.{}, .ocsp_staple = &oversized }));
}

test "HXHL absent ticket keys have canonical zero bytes" {
    const allocator = std.testing.allocator;
    const x509_selfsign = @import("../../proto/x509_selfsign.zig");
    const Ed25519 = std.crypto.sign.Ed25519;
    const key = try Ed25519.KeyPair.generateDeterministic(@splat(0x61));
    var cert_buf: [4096]u8 = undefined;
    const cert = try x509_selfsign.buildSelfSigned(&cert_buf, .{ .common_name = "history.test", .not_before = 1_700_000_000, .not_after = 1_900_000_000, .serial = &.{1}, .key_pair = key });
    const chain = [_][]const u8{cert};
    const wire = try encodeSnapshot(allocator, .{ .cert_chain = &chain, .signing_key = key });
    defer freeEncoded(allocator, wire);
    const zero_keys: [64]u8 = @splat(0);
    try std.testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, wire[frame.header_len + 2 ..][0..2], .little));
    try std.testing.expectEqualSlices(u8, &zero_keys, wire[frame.header_len + 12 ..][0..64]);
    var owned = try decodeOwned(allocator, wire);
    defer owned.deinit();
    try std.testing.expect(owned.current_ticket_key == null and owned.previous_ticket_key == null);
    const corrupt = try allocator.dupe(u8, wire);
    defer freeEncoded(allocator, corrupt);
    corrupt[frame.header_len + 12] = 1;
    frame.finish(corrupt, domain);
    try std.testing.expectError(error.InvalidSnapshot, validateCheckpoint(corrupt));
    @memcpy(corrupt, wire);
    corrupt[frame.header_len + 44] = 1;
    frame.finish(corrupt, domain);
    try std.testing.expectError(error.InvalidSnapshot, validateCheckpoint(corrupt));
}

test "HXHL arena preflight requires one canonical checkpoint and whole manifest" {
    const allocator = std.testing.allocator;
    const x509_selfsign = @import("../../proto/x509_selfsign.zig");
    const Ed25519 = std.crypto.sign.Ed25519;
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
    const key = try Ed25519.KeyPair.generateDeterministic(@splat(0x57));
    var cert_buf: [4096]u8 = undefined;
    const cert = try x509_selfsign.buildSelfSigned(&cert_buf, .{ .common_name = "history.test", .not_before = 1_700_000_000, .not_after = 1_900_000_000, .serial = &.{7}, .key_pair = key });
    const chain = [_][]const u8{cert};
    const wire = try encodeSnapshot(allocator, .{ .cert_chain = &chain, .signing_key = key });
    defer freeEncoded(allocator, wire);
    const valid = try Fixture.arena(allocator, &.{.{ .kind = .mesh_checkpoint, .bytes = wire, .min_supported = 2 }});
    defer Fixture.freeArena(allocator, valid);
    var owned = try decodeFromArena(allocator, valid);
    defer owned.deinit();
    try std.testing.expectEqualSlices(u8, cert, owned.tlsConfig(.{ .cert_chain = &.{} }).cert_chain[0]);
    const missing = try Fixture.arena(allocator, &.{.{ .kind = .mesh_checkpoint, .bytes = "other" }});
    defer Fixture.freeArena(allocator, missing);
    try std.testing.expectError(error.MissingCheckpoint, decodeFromArena(allocator, missing));
    const duplicate = try Fixture.arena(allocator, &.{
        .{ .kind = .mesh_checkpoint, .bytes = wire, .min_supported = 2 },
        .{ .kind = .mesh_checkpoint, .bytes = wire, .min_supported = 2 },
    });
    defer Fixture.freeArena(allocator, duplicate);
    try std.testing.expectError(error.DuplicateCheckpoint, decodeFromArena(allocator, duplicate));
    const wrong_min = try Fixture.arena(allocator, &.{.{ .kind = .mesh_checkpoint, .bytes = wire }});
    defer Fixture.freeArena(allocator, wrong_min);
    try std.testing.expectError(error.InvalidSnapshot, decodeFromArena(allocator, wrong_min));
    const tampered = try allocator.dupe(u8, valid);
    defer Fixture.freeArena(allocator, tampered);
    const offset = std.mem.indexOf(u8, tampered, "HXHL") orelse return error.TestUnexpectedResult;
    tampered[offset + 4] ^= 1;
    try std.testing.expectError(error.InvalidSnapshot, decodeFromArena(allocator, tampered));
}
