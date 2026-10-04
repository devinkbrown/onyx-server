// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Endpoint capability v1 direction/purpose derivation. This is a codec helper,
//! never an endpoint admission proof. Owners generate fresh master material,
//! bind the issued stream to their actual Domain candidate, and wipe every copy.
const std = @import("std");
const hash = @import("../crypto/hash.zig");
const frame = @import("cadence_frame.zig");
const feedback = @import("native_feedback.zig");
pub const key_bytes = 32;
pub const Keys = struct {
    c2s_frame: [key_bytes]u8,
    s2c_frame: [key_bytes]u8,
    c2s_feedback: [key_bytes]u8,
    s2c_feedback: [key_bytes]u8,
    pub fn wipe(self: *Keys) void {
        inline for (comptime std.meta.fieldNames(Keys)) |name| std.crypto.secureZero(u8, &@field(self, name));
    }
};
const labels = [_][]const u8{
    "onyx native endpoint capability v1 c2s frame",
    "onyx native endpoint capability v1 s2c frame",
    "onyx native endpoint capability v1 c2s feedback",
    "onyx native endpoint capability v1 s2c feedback",
};
pub fn derive(master: *const [key_bytes]u8, issued_stream: u32) error{InvalidStream}!Keys {
    if (issued_stream == 0) return error.InvalidStream;
    var stream: [4]u8 = undefined;
    std.mem.writeInt(u32, &stream, issued_stream, .big);
    var keys: Keys = undefined;
    inline for (comptime std.meta.fieldNames(Keys), labels) |name, label| {
        var mac = hash.HmacSha256.init(master);
        mac.update(label);
        mac.update(&.{0});
        mac.update(&stream);
        @field(keys, name) = mac.final();
        std.crypto.secureZero(u8, std.mem.asBytes(&mac));
    }
    return keys;
}

/// Configured ONFB payload canonicality. The legacy parser's permissive-tail
/// policy stays independent. Repeated authenticated operations are allowed;
/// a MAC provides no feedback freshness or replay-resistance guarantee.
pub fn validateFeedbackPayload(bytes: []const u8, seq_out: []u32) feedback.Error!feedback.Message {
    const message = try feedback.parse(bytes, seq_out);
    const expected: usize = switch (message) {
        .nack => |nack| 7 + nack.seqs.len * 4,
        .keyframe_request => 5,
        .receiver_report => 18,
        else => return error.BadKind,
    };
    if (bytes.len != expected) return error.Truncated;
    return message;
}

test "media capability v1 exact independent HMAC vectors and stream separation" {
    var master: [key_bytes]u8 = undefined;
    for (&master, 0..) |*byte, n| byte.* = @intCast(n);
    defer std.crypto.secureZero(u8, &master);
    var keys = try derive(&master, 0x12345678);
    defer keys.wipe();
    const vectors = [_][]const u8{
        "abe4c65cac6c9a4006b074c30d9d44583d8918b7374ad7b23a68939a5ea9091b",
        "b294c6db61a5f511a22c4524126947496b3d505b76e2083e98749f9e6c68a573",
        "6d623bd8b8e159ed461ccc33dc992246809c169d5760bc868b90b042ee341d94",
        "dbfca72410e0dcdc4d795c889f63a7d5a7271476af99830dfabe98db031852dc",
    };
    inline for (comptime std.meta.fieldNames(Keys), vectors) |name, vector| {
        const expected = comptime hexBytes(vector);
        try std.testing.expectEqualSlices(u8, &expected, &@field(keys, name));
    }
    var other = try derive(&master, 0x12345679);
    defer other.wipe();
    inline for (comptime std.meta.fieldNames(Keys)) |name| try std.testing.expect(!std.mem.eql(u8, &@field(keys, name), &@field(other, name)));
    try std.testing.expectError(error.InvalidStream, derive(&master, 0));
}

test "media capability v1 rejects reflected frame and feedback authentication" {
    var master: [key_bytes]u8 = @splat(0x27);
    defer std.crypto.secureZero(u8, &master);
    var keys = try derive(&master, 0x1234);
    defer keys.wipe();
    var plain: [128]u8 = undefined;
    const encoded_len = try frame.encode(.{ .band_id = 64, .stream_id = 0x1234, .sequence = 1, .timestamp = 2, .keyframe = false, .codec = .cadencevox_audio, .payload = "opus-equivalent" }, &plain);
    var wire: [160]u8 = undefined;
    const outbound = try frame.appendNativeMediaMacWithKey(&keys.s2c_frame, plain[0..encoded_len], &wire);
    _ = try frame.verifyNativeMediaMacWithKey(&keys.s2c_frame, outbound);
    try std.testing.expectError(error.BadTag, frame.verifyNativeMediaMacWithKey(&master, outbound));
    try std.testing.expectError(error.BadTag, frame.verifyNativeMediaMacWithKey(&keys.c2s_frame, outbound));
    try std.testing.expectError(error.BadTag, frame.verifyNativeMediaMacWithKey(&keys.s2c_feedback, outbound));
    var payload: [32]u8 = undefined;
    const nack = try feedback.encodeNack(0x5678, &.{17}, &payload);
    var envelope: [128]u8 = undefined;
    const result = try feedback.encodeEnvelope(0x1234, nack, &keys.s2c_feedback, &envelope);
    _ = try feedback.openEnvelope(result, &keys.s2c_feedback);
    try std.testing.expectError(error.BadTag, feedback.openEnvelope(result, &master));
    try std.testing.expectError(error.BadTag, feedback.openEnvelope(result, &keys.c2s_feedback));
    try std.testing.expectError(error.BadTag, feedback.openEnvelope(result, &keys.s2c_frame));
    var foreign_master: [key_bytes]u8 = @splat(0x28);
    defer std.crypto.secureZero(u8, &foreign_master);
    var foreign_keys = try derive(&foreign_master, 0x1234);
    defer foreign_keys.wipe();
    try std.testing.expectError(error.BadTag, frame.verifyNativeMediaMacWithKey(&foreign_keys.s2c_frame, outbound));
    try std.testing.expectError(error.BadTag, feedback.openEnvelope(result, &foreign_keys.s2c_feedback));
}

test "media capability v1 payload strict length and bounded repeated NACK" {
    var payload: [32]u8 = undefined;
    const nack = try feedback.encodeNack(8, &.{ 1, 2 }, &payload);
    var seqs: [2]u32 = undefined;
    _ = try validateFeedbackPayload(nack, &seqs);
    _ = try validateFeedbackPayload(nack, &seqs); // explicit repeated-operation policy
    try std.testing.expectError(error.TooMany, validateFeedbackPayload(nack, seqs[0..1]));
    payload[nack.len] = 0;
    try std.testing.expectError(error.Truncated, validateFeedbackPayload(payload[0 .. nack.len + 1], &seqs));
    keysWipeTest();
}

test "media capability v1 strict keyframe and receiver report retain legacy tail policy" {
    var storage: [32]u8 = undefined;
    var seqs: [2]u32 = undefined;
    const keyframe = try feedback.encodeKeyframeRequest(0x1234, &storage);
    const parsed_keyframe = try validateFeedbackPayload(keyframe, &seqs);
    try std.testing.expectEqual(@as(u32, 0x1234), parsed_keyframe.keyframe_request.stream_id);
    for (0..keyframe.len) |length| try std.testing.expectError(error.Truncated, validateFeedbackPayload(storage[0..length], &seqs));
    storage[keyframe.len] = 0xa5;
    _ = try feedback.parse(storage[0 .. keyframe.len + 1], &seqs);
    try std.testing.expectError(error.Truncated, validateFeedbackPayload(storage[0 .. keyframe.len + 1], &seqs));
    const expected = feedback.ReceiverReport{ .stream_id = 0x5678, .fraction_lost = 3, .cumulative_lost = 4, .jitter = 5, .highest_seq = 6 };
    const report = try feedback.encodeReceiverReport(expected, &storage);
    const parsed_report = try validateFeedbackPayload(report, &seqs);
    try std.testing.expectEqual(expected, parsed_report.receiver_report);
    for (0..report.len) |length| try std.testing.expectError(error.Truncated, validateFeedbackPayload(storage[0..length], &seqs));
    storage[report.len] = 0xa5;
    _ = try feedback.parse(storage[0 .. report.len + 1], &seqs);
    try std.testing.expectError(error.Truncated, validateFeedbackPayload(storage[0 .. report.len + 1], &seqs));
    storage[0] = 0xff;
    try std.testing.expectError(error.BadKind, validateFeedbackPayload(storage[0..1], &seqs));
}
fn keysWipeTest() void {
    var keys = Keys{ .c2s_frame = @splat(1), .s2c_frame = @splat(2), .c2s_feedback = @splat(3), .s2c_feedback = @splat(4) };
    keys.wipe();
    inline for (comptime std.meta.fieldNames(Keys)) |name| for (@field(keys, name)) |byte| std.debug.assert(byte == 0);
}

fn hexBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}
