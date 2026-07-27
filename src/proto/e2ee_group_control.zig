// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded, opaque group-E2EE control records.
//!
//! The daemon is a delivery service, never a group member. This module parses
//! only the routing metadata the daemon must authorize; `payload` remains
//! opaque base64url and is never decrypted, derived, or persisted here.
const std = @import("std");
const e2ee_policy = @import("e2ee_policy.zig");

pub const max_account_len: usize = 64;
pub const max_payload_len: usize = 4096;

pub const Kind = enum(u8) {
    key_package = 1,
    welcome = 2,
    commit = 3,

    pub fn wireTag(self: Kind) []const u8 {
        return switch (self) {
            .key_package => "E2EE.KEYPACKAGE",
            .welcome => "E2EE.WELCOME",
            .commit => "E2EE.COMMIT",
        };
    }
};

pub const Record = struct {
    channel: []const u8,
    kind: Kind,
    from_device: []const u8,
    to_account: ?[]const u8 = null,
    to_device: ?[]const u8 = null,
    payload: []const u8,
};

pub const ParseError = error{
    NeedMoreParams,
    TooManyParams,
    InvalidChannel,
    InvalidKind,
    InvalidDevice,
    InvalidAccount,
    InvalidPayload,
};

/// Validate a fully constructed control record. Mesh codecs use this same
/// function so local commands and signed relays cannot drift on bounds or
/// targeting rules.
pub fn validate(record: Record) ParseError!void {
    if (!validChannel(record.channel)) return error.InvalidChannel;
    if (!e2ee_policy.validDeviceId(record.from_device)) return error.InvalidDevice;
    if (!validOpaquePayload(record.payload)) return error.InvalidPayload;

    if (record.kind == .welcome) {
        const to_account = record.to_account orelse return error.NeedMoreParams;
        const to_device = record.to_device orelse return error.NeedMoreParams;
        if (!validAccount(to_account)) return error.InvalidAccount;
        if (!e2ee_policy.validDeviceId(to_device)) return error.InvalidDevice;
    } else if (record.to_account != null or record.to_device != null) {
        return error.TooManyParams;
    }
}

fn parseKind(raw: []const u8) ?Kind {
    if (std.ascii.eqlIgnoreCase(raw, "key-package")) return .key_package;
    if (std.ascii.eqlIgnoreCase(raw, "welcome")) return .welcome;
    if (std.ascii.eqlIgnoreCase(raw, "commit")) return .commit;
    return null;
}

fn validChannel(raw: []const u8) bool {
    if (raw.len < 2 or raw.len > 128) return false;
    if (raw[0] != '#' and raw[0] != '&') return false;
    for (raw[1..]) |byte| switch (byte) {
        0...32, ',', ':', 127 => return false,
        else => {},
    };
    return true;
}

fn validAccount(raw: []const u8) bool {
    if (raw.len == 0 or raw.len > max_account_len) return false;
    for (raw) |byte| switch (byte) {
        'a'...'z', 'A'...'Z', '0'...'9', '_', '-', '.', '@' => {},
        else => return false,
    };
    return true;
}

fn validOpaquePayload(raw: []const u8) bool {
    if (raw.len == 0 or raw.len > max_payload_len) return false;
    for (raw) |byte| switch (byte) {
        'a'...'z', 'A'...'Z', '0'...'9', '_', '-' => {},
        else => return false,
    };

    const decoder = std.base64.url_safe_no_pad.Decoder;
    const encoder = std.base64.url_safe_no_pad.Encoder;
    const decoded_len = decoder.calcSizeForSlice(raw) catch return false;
    var decoded: [max_payload_len]u8 = undefined;
    decoder.decode(decoded[0..decoded_len], raw) catch return false;

    const canonical_len = encoder.calcSize(decoded_len);
    if (canonical_len != raw.len) return false;
    var canonical: [max_payload_len]u8 = undefined;
    const encoded = encoder.encode(canonical[0..canonical_len], decoded[0..decoded_len]);
    return std.mem.eql(u8, raw, encoded);
}

/// Parse the parameters after `E2EEGROUP`.
///
/// Non-welcome:
///   `<channel> <key-package|commit> <from-device> :<opaque-b64url>`
/// Welcome:
///   `<channel> welcome <from-device> <to-account> <to-device> :<opaque-b64url>`
pub fn parse(params: []const []const u8) ParseError!Record {
    if (params.len < 4) return error.NeedMoreParams;
    const channel = params[0];
    const kind = parseKind(params[1]) orelse return error.InvalidKind;
    const from_device = params[2];

    if (kind == .welcome) {
        if (params.len < 6) return error.NeedMoreParams;
        if (params.len > 6) return error.TooManyParams;
        const record: Record = .{
            .channel = channel,
            .kind = kind,
            .from_device = from_device,
            .to_account = params[3],
            .to_device = params[4],
            .payload = params[5],
        };
        try validate(record);
        return record;
    }

    if (params.len > 4) return error.TooManyParams;
    const record: Record = .{
        .channel = channel,
        .kind = kind,
        .from_device = from_device,
        .payload = params[3],
    };
    try validate(record);
    return record;
}

test "parse bounded commit record without opening its payload" {
    const params = [_][]const u8{ "#root", "commit", "laptop.1", "AQIDBA" };
    const record = try parse(&params);
    try std.testing.expectEqual(Kind.commit, record.kind);
    try std.testing.expectEqualStrings("#root", record.channel);
    try std.testing.expectEqualStrings("laptop.1", record.from_device);
    try std.testing.expectEqualStrings("AQIDBA", record.payload);
    try std.testing.expect(record.to_account == null);
    try std.testing.expectEqualStrings("E2EE.COMMIT", record.kind.wireTag());
}

test "parse targeted welcome routing metadata" {
    const params = [_][]const u8{
        "&staff", "WELCOME", "desktop", "Kain", "phone-2", "b3BhcXVl",
    };
    const record = try parse(&params);
    try std.testing.expectEqual(Kind.welcome, record.kind);
    try std.testing.expectEqualStrings("Kain", record.to_account.?);
    try std.testing.expectEqualStrings("phone-2", record.to_device.?);
    try std.testing.expectEqualStrings("E2EE.WELCOME", record.kind.wireTag());
}

test "reject malformed, ambiguous, and oversized control records" {
    try std.testing.expectError(error.NeedMoreParams, parse(&.{
        "#root", "commit", "phone",
    }));
    try std.testing.expectError(error.InvalidChannel, parse(&.{
        "root", "commit", "phone", "opaque",
    }));
    var unicode_channel: [130]u8 = undefined;
    unicode_channel[0] = '#';
    for (0..43) |index| {
        @memcpy(unicode_channel[1 + index * 3 ..][0..3], "界");
    }
    try std.testing.expectError(error.InvalidChannel, parse(&.{
        &unicode_channel, "commit", "phone", "AQ",
    }));
    try std.testing.expectError(error.InvalidKind, parse(&.{
        "#root", "epoch", "phone", "opaque",
    }));
    try std.testing.expectError(error.InvalidDevice, parse(&.{
        "#root", "commit", "bad device", "opaque",
    }));
    try std.testing.expectError(error.NeedMoreParams, parse(&.{
        "#root", "welcome", "phone", "Kain", "tablet",
    }));
    try std.testing.expectError(error.InvalidAccount, parse(&.{
        "#root", "welcome", "phone", "bad account", "tablet", "opaque",
    }));
    try std.testing.expectError(error.InvalidPayload, parse(&.{
        "#root", "commit", "phone", "not+base64url",
    }));
    try std.testing.expectError(error.InvalidPayload, parse(&.{
        "#root", "commit", "phone", "A",
    }));
    try std.testing.expectError(error.TooManyParams, parse(&.{
        "#root", "commit", "phone", "opaque", "smuggled",
    }));

    const oversized: [max_payload_len + 1]u8 = @splat('A');
    try std.testing.expectError(error.InvalidPayload, parse(&.{
        "#root", "key-package", "phone", &oversized,
    }));
}
