// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Encrypt an entire native Helix arena before any filesystem write. OpenBSD
//! shm_open is a named /tmp file, so unlink alone does not protect snapshot
//! secrets. The per-upgrade key travels only on the validated control channel.
const std = @import("std");
const platform = @import("../../substrate/platform.zig");
const Cipher = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

pub const max_plaintext_bytes = @import("live.zig").max_arena_bytes;
pub const header_len = 48;
pub const tag_len = Cipher.tag_length;
pub const Key = [Cipher.key_length]u8;
pub const UpgradeId = [16]u8;
const magic = "ONYX-HXA";
const version: u16 = 1;

pub const Error = error{ InvalidEnvelope, WrongUpgrade, AuthenticationFailed, ArenaTooLarge, AlreadySealed } || std.mem.Allocator.Error;

pub const Sealer = struct {
    key: Key,
    nonce: [Cipher.nonce_length]u8,
    upgrade_id: UpgradeId,
    sealed: bool = false,

    /// Call only after the actual successor image has completed its capability
    /// handshake. A new key and nonce are required for every attempted upgrade.
    pub fn initRandom() error{RandomSourceFailed}!Sealer {
        var result: Sealer = undefined;
        result.sealed = false;
        errdefer result.deinit();
        try platform.fillOsEntropy(&result.key);
        try platform.fillOsEntropy(&result.nonce);
        try platform.fillOsEntropy(&result.upgrade_id);
        return result;
    }

    pub fn deinit(self: *Sealer) void {
        std.crypto.secureZero(u8, &self.key);
        std.crypto.secureZero(u8, &self.nonce);
        std.crypto.secureZero(u8, &self.upgrade_id);
        self.sealed = true;
    }

    /// Allocates only ciphertext. An allocation failure leaves this sealer
    /// unused; successful sealing cannot be repeated with the same nonce.
    pub fn seal(self: *Sealer, allocator: std.mem.Allocator, plaintext: []const u8) Error![]u8 {
        if (self.sealed) return error.AlreadySealed;
        if (plaintext.len > max_plaintext_bytes) return error.ArenaTooLarge;
        const wire = try allocator.alloc(u8, header_len + plaintext.len + tag_len);
        @memcpy(wire[0..8], magic);
        std.mem.writeInt(u16, wire[8..10], version, .big);
        std.mem.writeInt(u16, wire[10..12], 0, .big);
        std.mem.writeInt(u64, wire[12..20], @intCast(plaintext.len), .big);
        @memcpy(wire[20..36], &self.upgrade_id);
        @memcpy(wire[36..48], &self.nonce);
        var tag: [tag_len]u8 = undefined;
        Cipher.encrypt(wire[header_len..][0..plaintext.len], &tag, plaintext, wire[0..header_len], self.nonce, self.key);
        @memcpy(wire[header_len + plaintext.len ..], &tag);
        self.sealed = true;
        return wire;
    }
};

/// Authenticate the complete header and payload before any capsule decoder or
/// live-state staging sees plaintext. The caller wipes returned plaintext.
pub fn open(allocator: std.mem.Allocator, key: Key, expected_id: UpgradeId, wire: []const u8) Error![]u8 {
    if (wire.len < header_len + tag_len) return error.InvalidEnvelope;
    if (!std.mem.eql(u8, wire[0..8], magic) or
        std.mem.readInt(u16, wire[8..10], .big) != version or
        std.mem.readInt(u16, wire[10..12], .big) != 0) return error.InvalidEnvelope;
    const length = std.mem.readInt(u64, wire[12..20], .big);
    if (length > max_plaintext_bytes) return error.ArenaTooLarge;
    if (wire.len != header_len + length + tag_len) return error.InvalidEnvelope;
    if (!std.mem.eql(u8, wire[20..36], &expected_id)) return error.WrongUpgrade;
    const nonce: [Cipher.nonce_length]u8 = wire[36..48].*;
    const tag: [tag_len]u8 = wire[wire.len - tag_len ..][0..tag_len].*;
    const plaintext = try allocator.alloc(u8, @intCast(length));
    errdefer {
        std.crypto.secureZero(u8, plaintext);
        allocator.free(plaintext);
    }
    Cipher.decrypt(plaintext, wire[header_len .. wire.len - tag_len], tag, wire[0..header_len], nonce, key) catch return error.AuthenticationFailed;
    return plaintext;
}

test "native Helix arena authenticates all bytes and upgrade identity before decoding" {
    var sealer = Sealer{ .key = @splat(0x41), .nonce = @splat(0x72), .upgrade_id = @splat(0x93) };
    defer sealer.deinit();
    const allocator = std.testing.allocator;
    const original = "TLS and Mooring snapshot secret";
    const wire = try sealer.seal(allocator, original);
    defer allocator.free(wire);
    try std.testing.expect(std.mem.indexOf(u8, wire, original) == null);
    try std.testing.expectError(error.AlreadySealed, sealer.seal(allocator, original));
    const clear = try open(allocator, sealer.key, sealer.upgrade_id, wire);
    defer {
        std.crypto.secureZero(u8, clear);
        allocator.free(clear);
    }
    try std.testing.expectEqualStrings(original, clear);
    for (wire, 0..) |_, index| {
        wire[index] ^= 1;
        const decoded = open(allocator, sealer.key, sealer.upgrade_id, wire);
        if (decoded) |bad| {
            std.crypto.secureZero(u8, bad);
            allocator.free(bad);
            return error.ModifiedArenaAccepted;
        } else |_| {}
        wire[index] ^= 1;
    }
    try std.testing.expectError(error.InvalidEnvelope, open(allocator, sealer.key, sealer.upgrade_id, wire[0 .. wire.len - 1]));
    try std.testing.expectError(error.WrongUpgrade, open(allocator, sealer.key, @splat(0x94), wire));
    try std.testing.expectError(error.AuthenticationFailed, open(allocator, @splat(0x42), sealer.upgrade_id, wire));
}

test "native Helix arena allocation failure preserves seal retry and wipes keys" {
    var sealer = Sealer{ .key = @splat(0x41), .nonce = @splat(0x72), .upgrade_id = @splat(0x93) };
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, sealer.seal(failing.allocator(), "snapshot"));
    try std.testing.expect(!sealer.sealed);
    const wire = try sealer.seal(std.testing.allocator, "snapshot");
    defer std.testing.allocator.free(wire);
    try std.testing.expectError(error.OutOfMemory, open(failing.allocator(), sealer.key, sealer.upgrade_id, wire));
    sealer.deinit();
    try std.testing.expectEqual(@as(Key, @splat(0)), sealer.key);
    try std.testing.expect(sealer.sealed);
}
