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
/// Required-room client tag value. Optional/off rooms still accept the
/// legacy `1`/`mls`/`sframe` helpers below; required admission is exact.
pub const encrypted_tag_value_mls = "mls";
pub const room_envelope_prefix = "ONYXROOM1 ";
pub const room_envelope_version: u8 = 1;
/// version u8 + epoch u32be + nonce12 + GCM tag16.
pub const min_room_envelope_decoded_len: usize = 1 + 4 + 12 + 16;
/// Wire ceiling for `ONYXROOM1 ` + unpadded base64url. This is the signed mesh
/// relay body limit: required-room ciphertext must remain deliverable on every
/// peer, rather than merely fitting a local draft/multiline aggregation buffer.
pub const max_room_envelope_wire_len: usize = 4096;
/// Largest decoded body whose unpadded encoding still fits in
/// `max_room_envelope_wire_len` after the prefix.
pub const max_room_envelope_decoded_len: usize = maxDecodedForWire(max_room_envelope_wire_len);
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

/// Required-room tag gate: exactly one `+onyx/e2ee=mls`. Missing, wrong,
/// duplicate, or conflicting copies of the same key fail closed.
pub fn requiredEncryptedTagPresent(raw_tags: ?[]const u8) bool {
    const raw = raw_tags orelse return false;
    var seen = false;
    var it = std.mem.splitScalar(u8, raw, ';');
    while (it.next()) |tag| {
        if (tag.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, tag, '=') orelse tag.len;
        if (!isEncryptedTagKey(tag[0..eq])) continue;
        if (seen) return false;
        if (eq == tag.len) return false;
        if (!std.mem.eql(u8, tag[eq + 1 ..], encrypted_tag_value_mls)) return false;
        seen = true;
    }
    return seen;
}

/// Payload-blind ONYXROOM1 wire-shape check matching client groupEnvelope.ts.
/// Allocation-free: only the version byte and leftover pad-bit group are decoded.
pub fn isCanonicalRoomEnvelope(body: []const u8) bool {
    if (body.len > max_room_envelope_wire_len) return false;
    if (!std.mem.startsWith(u8, body, room_envelope_prefix)) return false;
    const payload = body[room_envelope_prefix.len..];
    if (payload.len == 0) return false;
    for (payload) |byte| switch (byte) {
        'A'...'Z', 'a'...'z', '0'...'9', '-', '_' => {},
        else => return false,
    };
    if (payload.len % 4 == 1) return false;

    const decoder = std.base64.url_safe_no_pad.Decoder;
    const encoder = std.base64.url_safe_no_pad.Encoder;
    const decoded_len = decoder.calcSizeForSlice(payload) catch return false;
    if (decoded_len < min_room_envelope_decoded_len or
        decoded_len > max_room_envelope_decoded_len)
        return false;
    if (encoder.calcSize(decoded_len) != payload.len) return false;

    var header: [3]u8 = undefined;
    decoder.decode(&header, payload[0..4]) catch return false;
    if (header[0] != room_envelope_version) return false;
    return leftoverPadBitsCanonical(payload, decoded_len);
}

/// Required rooms admit only the exact supported room-text pairing.
pub fn requiredRoomTextPairing(raw_tags: ?[]const u8, body: []const u8) bool {
    return requiredEncryptedTagPresent(raw_tags) and isCanonicalRoomEnvelope(body);
}

/// Required-room admission for a channel command.
/// TAGMSG is tag-only: the existing required-room policy never demanded a
/// text envelope (or even the e2ee tag) for it, so typing/react traffic
/// stays admitted. PRIVMSG/NOTICE still need the exact mls + ONYXROOM1 pair.
pub fn requiredRoomCommandAdmitted(raw_tags: ?[]const u8, body: []const u8, tag_only: bool) bool {
    if (tag_only) return true;
    return requiredRoomTextPairing(raw_tags, body);
}

fn maxDecodedForWire(max_wire: usize) usize {
    if (max_wire <= room_envelope_prefix.len) return 0;
    const max_payload = max_wire - room_envelope_prefix.len;
    return (max_payload / 4) * 3 + switch (max_payload % 4) {
        2 => 1,
        3 => 2,
        else => 0,
    };
}

fn leftoverPadBitsCanonical(payload: []const u8, decoded_len: usize) bool {
    const rem = decoded_len % 3;
    if (rem == 0) return true;
    const group_chars: usize = if (rem == 1) 2 else 3;
    if (payload.len < group_chars) return false;
    const group = payload[payload.len - group_chars ..];
    var decoded_group: [2]u8 = undefined;
    const decoder = std.base64.url_safe_no_pad.Decoder;
    const encoder = std.base64.url_safe_no_pad.Encoder;
    decoder.decode(decoded_group[0..rem], group) catch return false;
    var recoded: [3]u8 = undefined;
    const out = encoder.encode(recoded[0..group_chars], decoded_group[0..rem]);
    return std.mem.eql(u8, out, group);
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
    try std.testing.expect(encryptedTagPresent("+onyx/e2ee=sframe"));
    try std.testing.expect(!encryptedTagPresent("+onyx/e2ee=0"));
}

fn testEncodeRoomEnvelope(body: []const u8, out: []u8) []const u8 {
    const encoder = std.base64.url_safe_no_pad.Encoder;
    const need = room_envelope_prefix.len + encoder.calcSize(body.len);
    std.debug.assert(out.len >= need);
    @memcpy(out[0..room_envelope_prefix.len], room_envelope_prefix);
    _ = encoder.encode(out[room_envelope_prefix.len..need], body);
    return out[0..need];
}

fn testMinRoomBody(version: u8) [min_room_envelope_decoded_len]u8 {
    var body: [min_room_envelope_decoded_len]u8 = @splat(0);
    body[0] = version;
    return body;
}

test "required room tag is exact mls and rejects missing wrong duplicate conflicting" {
    try std.testing.expect(requiredEncryptedTagPresent("+onyx/e2ee=mls"));
    try std.testing.expect(requiredEncryptedTagPresent("+x=y;+onyx/e2ee=mls"));
    try std.testing.expect(!requiredEncryptedTagPresent(null));
    try std.testing.expect(!requiredEncryptedTagPresent(""));
    try std.testing.expect(!requiredEncryptedTagPresent("+draft/reply=1"));
    try std.testing.expect(!requiredEncryptedTagPresent("+onyx/e2ee"));
    try std.testing.expect(!requiredEncryptedTagPresent("+onyx/e2ee="));
    try std.testing.expect(!requiredEncryptedTagPresent("+onyx/e2ee=1"));
    try std.testing.expect(!requiredEncryptedTagPresent("+onyx/e2ee=sframe"));
    try std.testing.expect(!requiredEncryptedTagPresent("+onyx/e2ee=MLS"));
    try std.testing.expect(!requiredEncryptedTagPresent("+onyx/e2ee=mls;+onyx/e2ee=mls"));
    try std.testing.expect(!requiredEncryptedTagPresent("+onyx/e2ee=mls;+onyx/e2ee=1"));
    try std.testing.expect(!requiredEncryptedTagPresent("+onyx/e2ee=1;+onyx/e2ee=mls"));
}

test "canonical ONYXROOM1 envelope accepts min and rejects every malformed shape" {
    var wire_buf: [96]u8 = undefined;
    const min_body = testMinRoomBody(1);
    const min_wire = testEncodeRoomEnvelope(&min_body, &wire_buf);
    try std.testing.expect(isCanonicalRoomEnvelope(min_wire));
    try std.testing.expect(requiredRoomTextPairing("+onyx/e2ee=mls", min_wire));
    try std.testing.expect(!requiredRoomTextPairing("+onyx/e2ee=1", min_wire));
    try std.testing.expect(!requiredRoomTextPairing("+onyx/e2ee=mls", "tagged plaintext"));
    try std.testing.expect(!requiredRoomTextPairing(null, min_wire));

    try std.testing.expect(!isCanonicalRoomEnvelope("tagged plaintext"));
    try std.testing.expect(!isCanonicalRoomEnvelope("ONYXROOM1"));
    try std.testing.expect(!isCanonicalRoomEnvelope("ONYXROOM1 "));
    try std.testing.expect(!isCanonicalRoomEnvelope("onyxroom1 AQID"));
    var leading_space: [96]u8 = undefined;
    leading_space[0] = ' ';
    @memcpy(leading_space[1..][0..min_wire.len], min_wire);
    try std.testing.expect(!isCanonicalRoomEnvelope(leading_space[0 .. min_wire.len + 1]));
    var extra_space: [96]u8 = undefined;
    @memcpy(extra_space[0..room_envelope_prefix.len], room_envelope_prefix);
    extra_space[room_envelope_prefix.len] = ' ';
    @memcpy(extra_space[room_envelope_prefix.len + 1 ..][0 .. min_wire.len - room_envelope_prefix.len], min_wire[room_envelope_prefix.len..]);
    try std.testing.expect(!isCanonicalRoomEnvelope(extra_space[0 .. min_wire.len + 1]));

    var trailing_space: [96]u8 = undefined;
    @memcpy(trailing_space[0..min_wire.len], min_wire);
    trailing_space[min_wire.len] = ' ';
    try std.testing.expect(!isCanonicalRoomEnvelope(trailing_space[0 .. min_wire.len + 1]));

    var padded: [96]u8 = undefined;
    @memcpy(padded[0..min_wire.len], min_wire);
    padded[min_wire.len] = '=';
    try std.testing.expect(!isCanonicalRoomEnvelope(padded[0 .. min_wire.len + 1]));

    var plus_form: [96]u8 = undefined;
    @memcpy(plus_form[0..min_wire.len], min_wire);
    plus_form[room_envelope_prefix.len] = '+';
    try std.testing.expect(!isCanonicalRoomEnvelope(plus_form[0..min_wire.len]));

    var slash_form: [96]u8 = undefined;
    @memcpy(slash_form[0..min_wire.len], min_wire);
    slash_form[room_envelope_prefix.len] = '/';
    try std.testing.expect(!isCanonicalRoomEnvelope(slash_form[0..min_wire.len]));

    try std.testing.expect(!isCanonicalRoomEnvelope("ONYXROOM1 A")); // %4 == 1
    try std.testing.expect(!isCanonicalRoomEnvelope("ONYXROOM1 AQ")); // too short

    const bad_version = testMinRoomBody(2);
    try std.testing.expect(!isCanonicalRoomEnvelope(testEncodeRoomEnvelope(&bad_version, &wire_buf)));

    var short_body: [min_room_envelope_decoded_len - 1]u8 = @splat(0);
    short_body[0] = 1;
    try std.testing.expect(!isCanonicalRoomEnvelope(testEncodeRoomEnvelope(&short_body, &wire_buf)));

    var rem_body: [min_room_envelope_decoded_len + 1]u8 = @splat(0);
    rem_body[0] = 1;
    const rem_wire = testEncodeRoomEnvelope(&rem_body, &wire_buf);
    try std.testing.expect(isCanonicalRoomEnvelope(rem_wire));
    var mutated: [96]u8 = undefined;
    @memcpy(mutated[0..rem_wire.len], rem_wire);
    // 34-byte body ends in a 2-char group. Flip unused pad bits only.
    mutated[rem_wire.len - 1] = 'B';
    try std.testing.expect(!isCanonicalRoomEnvelope(mutated[0..rem_wire.len]));

    var rem2_body: [min_room_envelope_decoded_len + 2]u8 = @splat(0);
    rem2_body[0] = 1;
    var rem2_buf: [96]u8 = undefined;
    const rem2_wire = testEncodeRoomEnvelope(&rem2_body, &rem2_buf);
    try std.testing.expect(isCanonicalRoomEnvelope(rem2_wire));
    var mutated2: [96]u8 = undefined;
    @memcpy(mutated2[0..rem2_wire.len], rem2_wire);
    // 35-byte body ends in a 3-char group. Flip unused pad bits only.
    mutated2[rem2_wire.len - 1] = 'B';
    try std.testing.expect(!isCanonicalRoomEnvelope(mutated2[0..rem2_wire.len]));

    const oversize = try std.testing.allocator.alloc(u8, max_room_envelope_wire_len + 1);
    defer std.testing.allocator.free(oversize);
    @memcpy(oversize[0..room_envelope_prefix.len], room_envelope_prefix);
    @memset(oversize[room_envelope_prefix.len..], 'A');
    try std.testing.expect(!isCanonicalRoomEnvelope(oversize));
}

test "daemon-bound room envelope ceiling is canonical at its exact wire limit" {
    const encoder = std.base64.url_safe_no_pad.Encoder;
    const decoded = try std.testing.allocator.alloc(u8, max_room_envelope_decoded_len);
    defer std.testing.allocator.free(decoded);
    @memset(decoded, 0);
    decoded[0] = room_envelope_version;
    const exact_need = room_envelope_prefix.len + encoder.calcSize(decoded.len);
    try std.testing.expectEqual(max_room_envelope_wire_len, exact_need);
    const exact = try std.testing.allocator.alloc(u8, exact_need);
    defer std.testing.allocator.free(exact);
    try std.testing.expect(isCanonicalRoomEnvelope(testEncodeRoomEnvelope(decoded, exact)));

    var flipped = try std.testing.allocator.alloc(u8, exact_need);
    defer std.testing.allocator.free(flipped);
    @memcpy(flipped, exact);
    flipped[flipped.len - 1] = 'B';
    try std.testing.expect(!isCanonicalRoomEnvelope(flipped));

    const over_decoded = try std.testing.allocator.alloc(u8, max_room_envelope_decoded_len + 1);
    defer std.testing.allocator.free(over_decoded);
    @memset(over_decoded, 0);
    over_decoded[0] = room_envelope_version;
    const over_need = room_envelope_prefix.len + encoder.calcSize(over_decoded.len);
    try std.testing.expect(over_need > max_room_envelope_wire_len);
    const over_wire = try std.testing.allocator.alloc(u8, over_need);
    defer std.testing.allocator.free(over_wire);
    try std.testing.expect(!isCanonicalRoomEnvelope(testEncodeRoomEnvelope(over_decoded, over_wire)));
}

test "required rooms do not demand a text envelope for tag-only TAGMSG" {
    // Existing required-room policy never gated TAGMSG. A genuinely tag-only
    // command has no ONYXROOM1 body; requiring one would drop typing/react.
    try std.testing.expect(requiredRoomCommandAdmitted("+typing=active", "", true));
    try std.testing.expect(requiredRoomCommandAdmitted(null, "", true));
    try std.testing.expect(requiredRoomCommandAdmitted("+onyx/e2ee=mls", "", true));
    try std.testing.expect(!requiredRoomCommandAdmitted("+typing=active", "", false));
    try std.testing.expect(!requiredRoomCommandAdmitted("+onyx/e2ee=mls", "", false));
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
