// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! TLS 1.3 KeyUpdate handshake message codec (RFC 8446 §4.6.3).
//!
//! This module is pure: it only encodes/decodes the fixed-shape KeyUpdate
//! handshake message and computes the post-update application traffic secret
//! via TLS 1.3's HKDF-Expand-Label "traffic upd" ratchet. It performs no I/O
//! and holds no record or socket state. The Expand-Label primitive is reused
//! from the typed crypto surface in `../crypto/hash.zig`.
//!
//! Wire layout of the full handshake message (5 bytes):
//!   msg_type   (1 byte)  = 24  (key_update)
//!   length     (3 bytes) = 1
//!   request    (1 byte)  = 0 (not_requested) | 1 (requested)

const std = @import("std");
const hash = @import("../crypto/hash.zig");

/// Handshake message type for KeyUpdate (RFC 8446 §4, HandshakeType).
pub const msg_type_key_update: u8 = 24;

/// Body length of a KeyUpdate message: a single request_update byte.
pub const body_len: usize = 1;

/// Total encoded size: 1 (type) + 3 (length) + 1 (body).
pub const encoded_len: usize = 5;

/// Size of the SHA-256 application traffic secret carried through the ratchet.
pub const secret_len: usize = 32;

pub const Error = error{
    /// Output buffer too small to hold the 5-byte message.
    NoSpaceLeft,
    /// msg_type field was not 24 (key_update).
    BadMsgType,
    /// Declared/handshake length was not exactly 1.
    BadLength,
    /// Input slice was shorter than a full KeyUpdate message.
    Truncated,
    /// request_update byte was not 0 or 1.
    BadRequest,
};

/// request_update enum (RFC 8446 §4.6.3, KeyUpdateRequest).
pub const KeyUpdateRequest = enum(u8) {
    not_requested = 0,
    requested = 1,
};

/// Encode a complete KeyUpdate handshake message into `out`.
///
/// Returns the 5-byte slice written at the front of `out`. Fails with
/// `error.NoSpaceLeft` when `out` cannot hold the message.
pub fn encode(out: []u8, req: KeyUpdateRequest) Error![]const u8 {
    if (out.len < encoded_len) return error.NoSpaceLeft;
    out[0] = msg_type_key_update;
    // 24-bit big-endian length = 1.
    out[1] = 0;
    out[2] = 0;
    out[3] = @intCast(body_len);
    out[4] = @backingInt(req);
    return out[0..encoded_len];
}

/// Parse a KeyUpdate handshake message, validating msg_type and length.
///
/// Trailing bytes after the 5-byte message are ignored, allowing parsing from
/// a larger buffer. Returns the decoded request_update value.
pub fn parse(bytes: []const u8) Error!KeyUpdateRequest {
    if (bytes.len < encoded_len) return error.Truncated;
    if (bytes[0] != msg_type_key_update) return error.BadMsgType;

    const len: u32 = (@as(u32, bytes[1]) << 16) |
        (@as(u32, bytes[2]) << 8) |
        @as(u32, bytes[3]);
    if (len != body_len) return error.BadLength;

    return switch (bytes[4]) {
        0 => .not_requested,
        1 => .requested,
        else => error.BadRequest,
    };
}

/// Derive the next application traffic secret after a KeyUpdate.
///
/// application_traffic_secret_N+1 =
///     HKDF-Expand-Label(application_traffic_secret_N, "traffic upd", "", 32)
///
/// Reuses the TLS 1.3 Expand-Label primitive from `hash.zig`. The HKDF inputs
/// here are fixed-shape and cannot exceed the documented limits, so the
/// expansion never fails; an unexpected failure is treated as unreachable.
pub fn nextApplicationSecret(prev: [secret_len]u8) [secret_len]u8 {
    const Prk = hash.HkdfSha256.Prk;
    var prk = Prk.init(prev);
    defer prk.wipe();

    var out: [secret_len]u8 = undefined;
    hash.HkdfSha256.expandLabel(&prk, "traffic upd", "", &out) catch unreachable;
    return out;
}

// ---------------------------------------------------------------------------
// Tests (Arrange-Act-Assert)
// ---------------------------------------------------------------------------

const testing = std.testing;

test "encode produces the canonical 5-byte not_requested message" {
    // Arrange
    var buf: [16]u8 = undefined;

    // Act
    const msg = try encode(&buf, .not_requested);

    // Assert
    try testing.expectEqual(@as(usize, encoded_len), msg.len);
    try testing.expectEqualSlices(u8, &[_]u8{ 24, 0, 0, 1, 0 }, msg);
}

test "encode produces the canonical 5-byte requested message" {
    // Arrange
    var buf: [16]u8 = undefined;

    // Act
    const msg = try encode(&buf, .requested);

    // Assert
    try testing.expectEqualSlices(u8, &[_]u8{ 24, 0, 0, 1, 1 }, msg);
}

test "encode round-trips both variants through parse" {
    // Arrange
    const variants = [_]KeyUpdateRequest{ .not_requested, .requested };
    var buf: [encoded_len]u8 = undefined;

    inline for (variants) |req| {
        // Act
        const msg = try encode(&buf, req);
        const decoded = try parse(msg);

        // Assert
        try testing.expectEqual(req, decoded);
    }
}

test "encode rejects an undersized output buffer" {
    // Arrange
    var buf: [encoded_len - 1]u8 = undefined;

    // Act
    const result = encode(&buf, .requested);

    // Assert
    try testing.expectError(error.NoSpaceLeft, result);
}

test "parse rejects a wrong msg_type" {
    // Arrange: msg_type 25 instead of 24.
    const bytes = [_]u8{ 25, 0, 0, 1, 0 };

    // Act
    const result = parse(&bytes);

    // Assert
    try testing.expectError(error.BadMsgType, result);
}

test "parse rejects a wrong length" {
    // Arrange: declared length 2 instead of 1.
    const bytes = [_]u8{ 24, 0, 0, 2, 0 };

    // Act
    const result = parse(&bytes);

    // Assert
    try testing.expectError(error.BadLength, result);
}

test "parse rejects a truncated message" {
    // Arrange
    const bytes = [_]u8{ 24, 0, 0, 1 };

    // Act
    const result = parse(&bytes);

    // Assert
    try testing.expectError(error.Truncated, result);
}

test "parse rejects an out-of-range request byte" {
    // Arrange: request_update = 2.
    const bytes = [_]u8{ 24, 0, 0, 1, 2 };

    // Act
    const result = parse(&bytes);

    // Assert
    try testing.expectError(error.BadRequest, result);
}

test "parse ignores trailing bytes after the message" {
    // Arrange: a valid message followed by junk.
    const bytes = [_]u8{ 24, 0, 0, 1, 1, 0xff, 0xff };

    // Act
    const decoded = try parse(&bytes);

    // Assert
    try testing.expectEqual(KeyUpdateRequest.requested, decoded);
}

test "nextApplicationSecret is deterministic for a fixed input" {
    // Arrange
    var prev: [secret_len]u8 = undefined;
    for (&prev, 0..) |*b, i| b.* = @intCast(i);

    // Act
    const first = nextApplicationSecret(prev);
    const second = nextApplicationSecret(prev);

    // Assert
    try testing.expectEqualSlices(u8, &first, &second);
}

test "nextApplicationSecret matches the HKDF-Expand-Label definition" {
    // Arrange
    var prev: [secret_len]u8 = undefined;
    for (&prev, 0..) |*b, i| b.* = @intCast(0xa0 +% i);

    var prk = hash.HkdfSha256.Prk.init(prev);
    defer prk.wipe();
    var expected: [secret_len]u8 = undefined;
    try hash.HkdfSha256.expandLabel(&prk, "traffic upd", "", &expected);

    // Act
    const got = nextApplicationSecret(prev);

    // Assert
    try testing.expectEqualSlices(u8, &expected, &got);
}

test "nextApplicationSecret changes the secret and ratchets forward" {
    // Arrange
    var prev: [secret_len]u8 = @splat(0x11);

    // Act
    const gen1 = nextApplicationSecret(prev);
    const gen2 = nextApplicationSecret(gen1);

    // Assert: each generation differs from the prior one.
    try testing.expect(!std.mem.eql(u8, &prev, &gen1));
    try testing.expect(!std.mem.eql(u8, &gen1, &gen2));
}
