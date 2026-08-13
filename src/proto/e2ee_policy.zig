// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! E2EE control-plane policy for room metadata and device-key advertisements.
//!
//! The daemon never decrypts client payloads. This module defines the small
//! protocol contract the server can enforce: channel policy values, the
//! client-only tag proving a message is encrypted to clients, and bounded device
//! key identifiers/values stored as user PROP metadata.
const std = @import("std");
const e2ee_device_directory = @import("e2ee_device_directory.zig");

pub const policy_prop = "encryption-policy";
pub const encrypted_tag_key = "+onyx/e2ee";
pub const device_prop_prefix = "e2ee.device.";
pub const max_device_id_len: usize = 32;
pub const max_algorithm_len: usize = 32;
pub const max_public_key_len: usize = 180;
pub const max_device_value_len: usize = max_algorithm_len + 1 + max_public_key_len;

pub const Policy = enum {
    off,
    optional,
    required,
};

pub fn policyValue(raw: []const u8) ?Policy {
    if (std.ascii.eqlIgnoreCase(raw, "off")) return .off;
    if (std.ascii.eqlIgnoreCase(raw, "optional")) return .optional;
    if (std.ascii.eqlIgnoreCase(raw, "required")) return .required;
    return null;
}

pub fn validPolicyValue(raw: []const u8) bool {
    return policyValue(raw) != null;
}

pub fn isEncryptedTagKey(key: []const u8) bool {
    return std.mem.eql(u8, key, encrypted_tag_key);
}

pub fn encryptedTagPresent(raw_tags: ?[]const u8) bool {
    const raw = raw_tags orelse return false;
    var it = std.mem.splitScalar(u8, raw, ';');
    while (it.next()) |tag| {
        if (tag.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, tag, '=') orelse tag.len;
        if (!isEncryptedTagKey(tag[0..eq])) continue;
        if (eq == tag.len) return true;
        const value = tag[eq + 1 ..];
        return value.len == 0 or std.mem.eql(u8, value, "1") or std.ascii.eqlIgnoreCase(value, "mls") or std.ascii.eqlIgnoreCase(value, "sframe");
    }
    return false;
}

pub fn validDeviceId(raw: []const u8) bool {
    if (raw.len == 0 or raw.len > max_device_id_len) return false;
    for (raw) |byte| switch (byte) {
        'a'...'z', 'A'...'Z', '0'...'9', '_', '-', '.' => {},
        else => return false,
    };
    return true;
}

pub fn validAlgorithm(raw: []const u8) bool {
    if (raw.len == 0 or raw.len > max_algorithm_len) return false;
    for (raw) |byte| switch (byte) {
        'a'...'z', 'A'...'Z', '0'...'9', '_', '-' => {},
        else => return false,
    };
    return true;
}

pub fn validPublicKey(raw: []const u8) bool {
    if (raw.len == 0 or raw.len > max_public_key_len) return false;
    for (raw) |byte| switch (byte) {
        'a'...'z', 'A'...'Z', '0'...'9', '_', '-', '+', '/', '=', '.', ':' => {},
        else => return false,
    };
    return true;
}

pub const AdvertisementError = error{
    InvalidDevice,
    InvalidKey,
};

/// Strict `onyx-ogc1-v1` directory checks only. Every other algorithm keeps the
/// existing charset/length contract so stored legacy values stay byte-identical.
pub fn validateAdvertisement(
    device_id: []const u8,
    algorithm: []const u8,
    public_key: []const u8,
) AdvertisementError!void {
    if (!validDeviceId(device_id)) return error.InvalidDevice;
    if (e2ee_device_directory.isStoredAlgorithm(algorithm)) {
        const odd1 = e2ee_device_directory.parseCanonical(public_key) orelse
            return error.InvalidKey;
        if (!e2ee_device_directory.matchesDeviceId(odd1, device_id))
            return error.InvalidDevice;
        return;
    }
    if (!validAlgorithm(algorithm) or !validPublicKey(public_key)) return error.InvalidKey;
}

/// Validate the representation after a device id has crossed the IRCX PROP
/// store's ASCII-folding boundary. ODD1 payload bytes remain canonical and the
/// id must still derive from them; only ASCII case in the already-folded key is
/// ignored. Wire ingress must continue to use `validateAdvertisement`.
pub fn validateStoredAdvertisement(
    folded_device_id: []const u8,
    algorithm: []const u8,
    public_key: []const u8,
) AdvertisementError!void {
    if (!validDeviceId(folded_device_id)) return error.InvalidDevice;
    if (!e2ee_device_directory.isStoredAlgorithm(algorithm))
        return validateAdvertisement(folded_device_id, algorithm, public_key);
    const odd1 = e2ee_device_directory.parseCanonical(public_key) orelse
        return error.InvalidKey;
    var derived_buf: [e2ee_device_directory.device_id_len]u8 = undefined;
    const derived = e2ee_device_directory.deviceId(odd1, &derived_buf);
    if (!std.ascii.eqlIgnoreCase(folded_device_id, derived))
        return error.InvalidDevice;
}

pub fn devicePropKey(device_id: []const u8, out: []u8) ?[]const u8 {
    if (!validDeviceId(device_id)) return null;
    if (device_prop_prefix.len + device_id.len > out.len) return null;
    @memcpy(out[0..device_prop_prefix.len], device_prop_prefix);
    @memcpy(out[device_prop_prefix.len..][0..device_id.len], device_id);
    return out[0 .. device_prop_prefix.len + device_id.len];
}

pub fn deviceValue(algorithm: []const u8, public_key: []const u8, out: []u8) ?[]const u8 {
    if (e2ee_device_directory.isStoredAlgorithm(algorithm)) {
        if (e2ee_device_directory.parseCanonical(public_key) == null) return null;
    } else if (!validAlgorithm(algorithm) or !validPublicKey(public_key)) {
        return null;
    }
    const need = algorithm.len + 1 + public_key.len;
    if (need > out.len or need > max_device_value_len) return null;
    @memcpy(out[0..algorithm.len], algorithm);
    out[algorithm.len] = ':';
    @memcpy(out[algorithm.len + 1 ..][0..public_key.len], public_key);
    return out[0..need];
}

pub fn isDevicePropKey(key: []const u8) bool {
    return std.mem.startsWith(u8, key, device_prop_prefix) and validDeviceId(key[device_prop_prefix.len..]);
}

test "encryption policy values and tag validation" {
    try std.testing.expectEqual(Policy.required, policyValue("required").?);
    try std.testing.expect(validPolicyValue("optional"));
    try std.testing.expect(!validPolicyValue("mandatory"));
    try std.testing.expect(encryptedTagPresent("+onyx/e2ee=1;+x=y"));
    try std.testing.expect(encryptedTagPresent("+onyx/e2ee=mls"));
    try std.testing.expect(!encryptedTagPresent("+onyx/e2ee=0"));
}

test "device key metadata is bounded and prop-safe" {
    var key_buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("e2ee.device.phone", devicePropKey("phone", &key_buf).?);
    try std.testing.expect(devicePropKey("bad device", &key_buf) == null);
    var value_buf: [max_device_value_len]u8 = undefined;
    try std.testing.expectEqualStrings("mls-x25519:abcd+/=", deviceValue("mls-x25519", "abcd+/=", &value_buf).?);
    try std.testing.expect(deviceValue("bad alg!", "abcd", &value_buf) == null);
    try std.testing.expect(isDevicePropKey("e2ee.device.phone"));
    try std.testing.expect(!isDevicePropKey("e2ee.device.bad id"));
    try validateAdvertisement("phone", "mls-x25519", "abcd+/=");
}

test "onyx-ogc1-v1 advertisements are strict and leave legacy algorithms unchanged" {
    const Ed25519 = std.crypto.sign.Ed25519;
    const kp = try Ed25519.KeyPair.generateDeterministic(
        @as([Ed25519.KeyPair.seed_length]u8, @splat(0x5a)),
    );
    const odd1 = e2ee_device_directory.fromParts(
        kp.public_key.toBytes(),
        std.crypto.ecc.P256.basePoint.toUncompressedSec1(),
    ).?;
    var encoded: [e2ee_device_directory.encoded_len]u8 = undefined;
    const public_key = e2ee_device_directory.encodeCanonical(odd1, &encoded);
    var id_buf: [e2ee_device_directory.device_id_len]u8 = undefined;
    const device_id = e2ee_device_directory.deviceId(odd1, &id_buf);

    try validateAdvertisement(device_id, e2ee_device_directory.stored_algorithm, public_key);
    var value_buf: [max_device_value_len]u8 = undefined;
    const stored = deviceValue(e2ee_device_directory.stored_algorithm, public_key, &value_buf).?;
    try std.testing.expect(std.mem.startsWith(u8, stored, "onyx-ogc1-v1:"));
    try std.testing.expectEqualStrings(public_key, stored["onyx-ogc1-v1:".len..]);

    try std.testing.expectError(
        error.InvalidDevice,
        validateAdvertisement("phone", e2ee_device_directory.stored_algorithm, public_key),
    );
    var folded_id: [e2ee_device_directory.device_id_len]u8 = undefined;
    _ = std.ascii.lowerString(&folded_id, device_id);
    try validateStoredAdvertisement(&folded_id, e2ee_device_directory.stored_algorithm, public_key);
    try std.testing.expectError(
        error.InvalidDevice,
        validateStoredAdvertisement("ogc1-aaaaaaaaaaaaaaaaaaaaaa", e2ee_device_directory.stored_algorithm, public_key),
    );
    try std.testing.expect(deviceValue(e2ee_device_directory.stored_algorithm, "abcd+/=", &value_buf) == null);
    try std.testing.expectError(
        error.InvalidKey,
        validateAdvertisement(device_id, e2ee_device_directory.stored_algorithm, "abcd+/="),
    );

    try validateAdvertisement("legacy.1", "mls-x25519", "abcd+/=");
    try std.testing.expectEqualStrings(
        "mls-x25519:abcd+/=",
        deviceValue("mls-x25519", "abcd+/=", &value_buf).?,
    );
}
