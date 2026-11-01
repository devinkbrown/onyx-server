// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! TLS 1.3 Alert protocol codec (RFC 8446 §6).
//!
//! Wire format is two bytes: a one-byte AlertLevel followed by a one-byte
//! AlertDescription.  This module is a pure codec — it neither performs I/O nor
//! reads any clock/RNG, and it never allocates.  Callers own all buffers.
//!
//! Self-contained: only std is imported (for testing helpers).
const std = @import("std");

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// An encoded alert is always exactly two bytes on the wire.
pub const encoded_len: usize = 2;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

pub const ParseError = error{
    /// Input was not exactly `encoded_len` bytes.
    InvalidLength,
    /// Level byte was not a recognised AlertLevel value.
    InvalidLevel,
};

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// AlertLevel (RFC 8446 §6).  In TLS 1.3 every alert except `close_notify`
/// and `user_canceled` is treated as fatal regardless of this field, but the
/// field is still carried on the wire and round-tripped faithfully here.
pub const AlertLevel = enum(u8) {
    warning = 1,
    fatal = 2,
};

/// AlertDescription (RFC 8446 §6).  Non-exhaustive: any code not enumerated
/// below decodes to `_` (an unknown variant) rather than failing, so callers
/// can observe and forward unrecognised alerts without crashing.
pub const AlertDescription = enum(u8) {
    close_notify = 0,
    unexpected_message = 10,
    bad_record_mac = 20,
    record_overflow = 22,
    handshake_failure = 40,
    bad_certificate = 42,
    unsupported_certificate = 43,
    certificate_revoked = 44,
    certificate_expired = 45,
    certificate_unknown = 46,
    illegal_parameter = 47,
    unknown_ca = 48,
    access_denied = 49,
    decode_error = 50,
    decrypt_error = 51,
    protocol_version = 70,
    internal_error = 80,
    user_canceled = 90,
    missing_extension = 109,
    unsupported_extension = 110,
    unrecognized_name = 112,
    certificate_required = 116,
    no_application_protocol = 120,
    _,

    /// Map a raw byte to a description.  Unknown codes fall through to the
    /// non-exhaustive `_` variant; the raw value is preserved.
    pub fn fromInt(code: u8) AlertDescription {
        return @fromBackingInt(@intCast(code));
    }

    /// True when the byte does not correspond to a named description.
    pub fn isUnknown(self: AlertDescription) bool {
        return switch (self) {
            .close_notify,
            .unexpected_message,
            .bad_record_mac,
            .record_overflow,
            .handshake_failure,
            .bad_certificate,
            .unsupported_certificate,
            .certificate_revoked,
            .certificate_expired,
            .certificate_unknown,
            .illegal_parameter,
            .unknown_ca,
            .access_denied,
            .decode_error,
            .decrypt_error,
            .protocol_version,
            .internal_error,
            .user_canceled,
            .missing_extension,
            .unsupported_extension,
            .unrecognized_name,
            .certificate_required,
            .no_application_protocol,
            => false,
            _ => true,
        };
    }
};

// ---------------------------------------------------------------------------
// Alert value type
// ---------------------------------------------------------------------------

pub const Alert = struct {
    level: AlertLevel,
    description: AlertDescription,
};

// ---------------------------------------------------------------------------
// Codec
// ---------------------------------------------------------------------------

/// Serialise `alert` into `out`.  Returns the two-byte slice written.
/// Returns `error.NoSpaceLeft` when `out` is smaller than `encoded_len`.
pub fn encode(out: []u8, alert: Alert) error{NoSpaceLeft}![]const u8 {
    if (out.len < encoded_len) return error.NoSpaceLeft;
    out[0] = @backingInt(alert.level);
    out[1] = @backingInt(alert.description);
    return out[0..encoded_len];
}

/// Parse exactly `encoded_len` bytes into an `Alert`.  The level byte must be
/// a recognised AlertLevel; the description is mapped via `fromInt`, so unknown
/// description codes parse successfully into the unknown variant.
pub fn parse(bytes: []const u8) ParseError!Alert {
    if (bytes.len != encoded_len) return ParseError.InvalidLength;
    const level: AlertLevel = switch (bytes[0]) {
        1 => .warning,
        2 => .fatal,
        else => return ParseError.InvalidLevel,
    };
    return .{
        .level = level,
        .description = AlertDescription.fromInt(bytes[1]),
    };
}

/// True when this alert ends the connection: any alert with fatal level, plus
/// `close_notify` which is a clean shutdown signal that also terminates the
/// connection in both directions (RFC 8446 §6.1).
pub fn isFatal(alert: Alert) bool {
    if (alert.level == .fatal) return true;
    return alert.description == .close_notify;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "encode then parse round-trips a warning close_notify" {
    // Arrange
    const alert: Alert = .{ .level = .warning, .description = .close_notify };
    var buf: [encoded_len]u8 = undefined;

    // Act
    const wire = try encode(&buf, alert);
    const decoded = try parse(wire);

    // Assert
    try std.testing.expectEqual(@as(usize, encoded_len), wire.len);
    try std.testing.expectEqual(@as(u8, 1), wire[0]);
    try std.testing.expectEqual(@as(u8, 0), wire[1]);
    try std.testing.expectEqual(AlertLevel.warning, decoded.level);
    try std.testing.expectEqual(AlertDescription.close_notify, decoded.description);
}

test "encode then parse round-trips a fatal handshake_failure" {
    // Arrange
    const alert: Alert = .{ .level = .fatal, .description = .handshake_failure };
    var buf: [encoded_len]u8 = undefined;

    // Act
    const wire = try encode(&buf, alert);
    const decoded = try parse(wire);

    // Assert
    try std.testing.expectEqual(@as(u8, 2), wire[0]);
    try std.testing.expectEqual(@as(u8, 40), wire[1]);
    try std.testing.expectEqual(AlertLevel.fatal, decoded.level);
    try std.testing.expectEqual(AlertDescription.handshake_failure, decoded.description);
}

test "encode reports NoSpaceLeft when the output buffer is too small" {
    // Arrange
    const alert: Alert = .{ .level = .fatal, .description = .bad_record_mac };
    var buf: [1]u8 = undefined;

    // Act / Assert
    try std.testing.expectError(error.NoSpaceLeft, encode(&buf, alert));
}

test "parse rejects input that is not exactly two bytes" {
    // Arrange
    const too_short = [_]u8{2};
    const too_long = [_]u8{ 2, 40, 0 };
    const empty: []const u8 = &[_]u8{};

    // Act / Assert
    try std.testing.expectError(ParseError.InvalidLength, parse(&too_short));
    try std.testing.expectError(ParseError.InvalidLength, parse(&too_long));
    try std.testing.expectError(ParseError.InvalidLength, parse(empty));
}

test "parse rejects an unrecognised level byte" {
    // Arrange
    const bad_level = [_]u8{ 3, 0 };

    // Act / Assert
    try std.testing.expectError(ParseError.InvalidLevel, parse(&bad_level));
}

test "parse maps an unknown description code to the unknown variant without crashing" {
    // Arrange — 255 is not an assigned AlertDescription.
    const bytes = [_]u8{ 2, 255 };

    // Act
    const decoded = try parse(&bytes);

    // Assert
    try std.testing.expect(decoded.description.isUnknown());
    try std.testing.expectEqual(@as(u8, 255), @backingInt(decoded.description));
    try std.testing.expectEqual(AlertLevel.fatal, decoded.level);
}

test "isUnknown is false for every named description" {
    // Arrange
    const named = [_]AlertDescription{
        .close_notify,            .unexpected_message, .bad_record_mac,
        .record_overflow,         .handshake_failure,  .bad_certificate,
        .protocol_version,        .internal_error,     .user_canceled,
        .no_application_protocol,
    };

    // Act / Assert
    for (named) |d| {
        try std.testing.expect(!d.isUnknown());
    }
}

test "isFatal is true for fatal-level alerts" {
    // Arrange
    const alert: Alert = .{ .level = .fatal, .description = .decrypt_error };

    // Act / Assert
    try std.testing.expect(isFatal(alert));
}

test "isFatal is true for close_notify even at warning level" {
    // Arrange
    const alert: Alert = .{ .level = .warning, .description = .close_notify };

    // Act / Assert
    try std.testing.expect(isFatal(alert));
}

test "isFatal is false for a non-close warning alert" {
    // Arrange
    const alert: Alert = .{ .level = .warning, .description = .user_canceled };

    // Act / Assert
    try std.testing.expect(!isFatal(alert));
}
