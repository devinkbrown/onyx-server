// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Proposed structural probe codec only: no peer authentication, capability
//! admission, nonce generation or link-state negotiation is performed here.
const std = @import("std");

pub const wire_len: usize = 54;
pub const Kind = enum(u8) { request = 1, reply = 2 };
pub const Message = struct {
    kind: Kind,
    nonce: [16]u8,
    bundle_digest: [32]u8,
};
pub const Error = error{ BadLength, BadMarker, UnsupportedVersion, BadKind };

pub fn encode(message: Message) [wire_len]u8 {
    var out: [wire_len]u8 = undefined;
    @memcpy(out[0..4], "OXEP");
    out[4] = 1;
    out[5] = @backingInt(message.kind);
    out[6..22].* = message.nonce;
    out[22..54].* = message.bundle_digest;
    return out;
}

pub fn decode(bytes: []const u8) Error!Message {
    if (bytes.len != wire_len) return error.BadLength;
    if (!std.mem.eql(u8, bytes[0..4], "OXEP")) return error.BadMarker;
    if (bytes[4] != 1) return error.UnsupportedVersion;
    const kind = std.enums.fromInt(Kind, bytes[5]) orelse return error.BadKind;
    return .{ .kind = kind, .nonce = bytes[6..22].*, .bundle_digest = bytes[22..54].* };
}

/// Produces only the structurally distinct reply. The caller owns all transport,
/// authentication, freshness, bundle-policy and ordered-queue decisions.
pub fn replyFor(request: Message) error{ExpectedRequest}![wire_len]u8 {
    if (request.kind != .request) return error.ExpectedRequest;
    var response = request;
    response.kind = .reply;
    return encode(response);
}

test "literal complete request and reply vectors" {
    const message: Message = .{
        .kind = .request,
        .nonce = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
        .bundle_digest = .{ 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47 },
    };
    const expected: [wire_len]u8 = .{
        'O', 'X', 'E', 'P', 1,  1,
        0,   1,   2,   3,   4,  5,
        6,   7,   8,   9,   10, 11,
        12,  13,  14,  15,  16, 17,
        18,  19,  20,  21,  22, 23,
        24,  25,  26,  27,  28, 29,
        30,  31,  32,  33,  34, 35,
        36,  37,  38,  39,  40, 41,
        42,  43,  44,  45,  46, 47,
    };
    const actual = encode(message);
    try std.testing.expectEqualSlices(u8, &expected, &actual);
    try std.testing.expectEqualDeep(message, try decode(&expected));
    const reply = try replyFor(message);
    for (expected, reply, 0..) |before, after, i| {
        if (i == 5) try std.testing.expectEqual(@as(u8, 2), after) else try std.testing.expectEqual(before, after);
    }
    try std.testing.expectEqual(Kind.reply, (try decode(&reply)).kind);
    try std.testing.expectError(error.ExpectedRequest, replyFor(try decode(&reply)));
    // An older peer echoes the request bytes; it cannot produce reply kind.
    try std.testing.expectEqual(Kind.request, (try decode(&expected)).kind);
}

test "length marker version and kind reject malformed encodings" {
    const message = Message{ .kind = .request, .nonce = @splat(0), .bundle_digest = @splat(0) };
    const wire = encode(message);
    for (0..wire_len) |n| try std.testing.expectError(error.BadLength, decode(wire[0..n]));
    var long: [1024]u8 = @splat(0);
    @memcpy(long[0..wire_len], &wire);
    for (wire_len + 1..long.len + 1) |n| try std.testing.expectError(error.BadLength, decode(long[0..n]));
    for (0..4) |i| {
        var bad = wire;
        bad[i] ^= 1;
        try std.testing.expectError(error.BadMarker, decode(&bad));
    }
    var bad = wire;
    bad[4] = 2;
    try std.testing.expectError(error.UnsupportedVersion, decode(&bad));
    for ([_]u8{ 0, 3, 255 }) |kind| {
        bad = wire;
        bad[5] = kind;
        try std.testing.expectError(error.BadKind, decode(&bad));
    }
}

test "arbitrary binary nonce and unknown digest round trip without normalization" {
    const message: Message = .{ .kind = .reply, .nonce = .{ 0, 255, 128, 10, 13, 32, 127, 1, 2, 3, 4, 5, 6, 7, 8, 9 }, .bundle_digest = @splat(0xff) };
    const wire = encode(message);
    try std.testing.expectEqualDeep(message, try decode(&wire));
    const zero: Message = .{ .kind = .request, .nonce = @splat(0), .bundle_digest = @splat(0) };
    const zero_wire = encode(zero);
    try std.testing.expectEqualDeep(zero, try decode(&zero_wire));
}
