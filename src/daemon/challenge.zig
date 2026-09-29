// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pre-001 challenge ladder.
//!
//! `admit` is the one step a connection must pass. A later method is another
//! arm of that function. The client wire stays `CHALLENGE <answer>`.

const std = @import("std");

pub const max_text: usize = 160;
pub const max_answer: usize = 64;
pub const fail_delay_ms: i64 = 5_000;

pub const Method = enum(u8) {
    pow = 1,
    question = 2,
};

pub const Material = struct {
    seed: []const u8 = "",
    expected: []const u8 = "",
};

pub fn hexEncode(raw: []const u8, out: []u8) []const u8 {
    const hex = "0123456789abcdef";
    const n = @min(raw.len, out.len / 2);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        out[i * 2] = hex[raw[i] >> 4];
        out[i * 2 + 1] = hex[raw[i] & 0xf];
    }
    return out[0 .. n * 2];
}

/// True when `answer` satisfies `method`. Success is only this boolean.
/// It does not create an account.
pub fn admit(method: Method, material: Material, answer: []const u8) bool {
    if (answer.len == 0 or answer.len > max_answer) return false;
    if (hasControl(answer)) return false;
    return switch (method) {
        .pow => powOk(material.seed, answer),
        .question => material.expected.len != 0 and ctEqual(material.expected, answer),
    };
}

fn powOk(seed: []const u8, answer: []const u8) bool {
    if (seed.len == 0 or seed.len > 32) return false;
    var msg: [32 + max_answer]u8 = undefined;
    @memcpy(msg[0..seed.len], seed);
    @memcpy(msg[seed.len .. seed.len + answer.len], answer);
    var digest: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(msg[0 .. seed.len + answer.len], &digest, .{});
    return digest[0] == 0;
}

fn hasControl(bytes: []const u8) bool {
    for (bytes) |b| if (b < 0x20 or b == 0x7f) return true;
    return false;
}

fn ctEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, b) |x, y| diff |= x ^ y;
    return diff == 0;
}

test "GAP-P8 admit is one function for proof of work and a question" {
    var seed = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    var nonce_buf: [8]u8 = undefined;
    var found: []const u8 = "";
    var i: u32 = 0;
    while (i < 4096) : (i += 1) {
        const text = std.fmt.bufPrint(&nonce_buf, "{d}", .{i}) catch continue;
        if (admit(.pow, .{ .seed = &seed }, text)) {
            found = text;
            break;
        }
    }
    try std.testing.expect(found.len != 0);
    try std.testing.expect(admit(.pow, .{ .seed = &seed }, found));
    try std.testing.expect(!admit(.pow, .{ .seed = &seed }, "nope"));
    try std.testing.expect(admit(.question, .{ .expected = "onyx" }, "onyx"));
    try std.testing.expect(!admit(.question, .{ .expected = "onyx" }, "nope"));
    try std.testing.expect(!admit(.question, .{ .expected = "" }, "onyx"));
    var hex: [32]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 32), hexEncode(&seed, &hex).len);
}
