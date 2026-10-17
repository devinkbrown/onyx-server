// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! UTF-8 validation and IRC casemapping.
//!
//! This module is a small, allocation-free substrate helper for IRCv3
//! `utf8-only` and ISUPPORT `CASEMAPPING`. Validation rejects overlong
//! sequences, surrogate scalars, truncated input, and bytes outside the UTF-8
//! scalar range. Folding is caller-buffered for storage keys, while equality
//! compares folded bytes/scalars directly without allocating.
const std = @import("std");

/// IRC casemapping variants Onyx Server accepts for client-visible identifiers.
pub const Casemapping = enum {
    ascii,
    rfc1459,
    utf8_only,
};

pub const Utf8Error = error{
    InvalidUtf8,
};

pub const FoldError = Utf8Error || error{
    OutputTooSmall,
};

/// Compile-time limits and channel prefix policy for nick/channel checks.
pub const NameOptions = struct {
    max_nick_bytes: usize = 64,
    max_channel_bytes: usize = 200,
    allow_ampersand_channel: bool = false,
    allow_bang_channel: bool = false,
};

const ASCII_VECTOR_BYTES: usize = 32;

/// Return true when `input` is well-formed UTF-8.
pub fn validateUtf8(input: []const u8) bool {
    validateUtf8Error(input) catch return false;
    return true;
}

/// Validate `input` as UTF-8, returning a compact error on malformed input.
pub fn validateUtf8Error(input: []const u8) Utf8Error!void {
    var index = skipAsciiVector(input, 0);

    while (index < input.len) {
        const first = input[index];
        if (first < 0x80) {
            index += 1;
            index = skipAsciiVector(input, index);
            continue;
        }

        index = try skipUtf8Sequence(input, index);
    }
}

/// Fold `input` into caller-owned `out` according to `mapping`.
pub fn fold(comptime mapping: Casemapping, input: []const u8, out: []u8) FoldError![]const u8 {
    return switch (mapping) {
        .ascii, .rfc1459 => foldBytes(mapping, input, out),
        .utf8_only => foldUtf8Only(input, out),
    };
}

/// Case-insensitive equality under the selected IRC casemapping.
pub fn eql(comptime mapping: Casemapping, a: []const u8, b: []const u8) bool {
    return switch (mapping) {
        .ascii, .rfc1459 => eqlBytes(mapping, a, b),
        .utf8_only => eqlUtf8Only(a, b),
    };
}

/// Return true when `nick` is a valid nickname for `mapping`.
pub fn isValidNick(comptime mapping: Casemapping, nick: []const u8) bool {
    return isValidNickWith(mapping, nick, .{});
}

/// Return true when `nick` is valid under caller-provided compile-time limits.
pub fn isValidNickWith(comptime mapping: Casemapping, nick: []const u8, comptime options: NameOptions) bool {
    if (nick.len == 0 or nick.len > options.max_nick_bytes) return false;

    return switch (mapping) {
        .ascii, .rfc1459 => isValidAsciiNick(nick),
        .utf8_only => isValidUtf8Nick(nick),
    };
}

/// Return true when `channel` is a valid channel name for `mapping`.
pub fn isValidChannel(comptime mapping: Casemapping, channel: []const u8) bool {
    return isValidChannelWith(mapping, channel, .{});
}

/// Return true when `channel` is valid under caller-provided compile-time limits.
pub fn isValidChannelWith(comptime mapping: Casemapping, channel: []const u8, comptime options: NameOptions) bool {
    if (channel.len < 2 or channel.len > options.max_channel_bytes) return false;
    if (!validChannelPrefix(channel[0], options)) return false;

    return switch (mapping) {
        .ascii, .rfc1459 => isValidAsciiChannelRest(channel[1..]),
        .utf8_only => isValidUtf8ChannelRest(channel[1..]),
    };
}

fn skipAsciiVector(input: []const u8, start: usize) usize {
    if (input.len - start < ASCII_VECTOR_BYTES) return start;

    const Vec = @Vector(ASCII_VECTOR_BYTES, u8);
    const high_bits: Vec = @splat(0x80);
    var index = start;

    while (index + ASCII_VECTOR_BYTES <= input.len) {
        const block: Vec = input[index..][0..ASCII_VECTOR_BYTES].*;
        if (@reduce(.Or, block & high_bits) != 0) break;
        index += ASCII_VECTOR_BYTES;
    }

    return index;
}

fn skipUtf8Sequence(input: []const u8, index: usize) Utf8Error!usize {
    const first = input[index];

    if (first >= 0xC2 and first <= 0xDF) {
        if (index + 1 >= input.len or !isContinuation(input[index + 1])) return error.InvalidUtf8;
        return index + 2;
    }

    if (first == 0xE0) {
        if (index + 2 >= input.len) return error.InvalidUtf8;
        const second = input[index + 1];
        if (second < 0xA0 or second > 0xBF or !isContinuation(input[index + 2])) return error.InvalidUtf8;
        return index + 3;
    }

    if (first >= 0xE1 and first <= 0xEC) {
        if (index + 2 >= input.len or !isContinuation(input[index + 1]) or !isContinuation(input[index + 2])) return error.InvalidUtf8;
        return index + 3;
    }

    if (first == 0xED) {
        if (index + 2 >= input.len) return error.InvalidUtf8;
        const second = input[index + 1];
        if (second < 0x80 or second > 0x9F or !isContinuation(input[index + 2])) return error.InvalidUtf8;
        return index + 3;
    }

    if (first >= 0xEE and first <= 0xEF) {
        if (index + 2 >= input.len or !isContinuation(input[index + 1]) or !isContinuation(input[index + 2])) return error.InvalidUtf8;
        return index + 3;
    }

    if (first == 0xF0) {
        if (index + 3 >= input.len) return error.InvalidUtf8;
        const second = input[index + 1];
        if (second < 0x90 or second > 0xBF or !isContinuation(input[index + 2]) or !isContinuation(input[index + 3])) return error.InvalidUtf8;
        return index + 4;
    }

    if (first >= 0xF1 and first <= 0xF3) {
        if (index + 3 >= input.len or !isContinuation(input[index + 1]) or !isContinuation(input[index + 2]) or !isContinuation(input[index + 3])) return error.InvalidUtf8;
        return index + 4;
    }

    if (first == 0xF4) {
        if (index + 3 >= input.len) return error.InvalidUtf8;
        const second = input[index + 1];
        if (second < 0x80 or second > 0x8F or !isContinuation(input[index + 2]) or !isContinuation(input[index + 3])) return error.InvalidUtf8;
        return index + 4;
    }

    return error.InvalidUtf8;
}

fn isContinuation(byte: u8) bool {
    return byte >= 0x80 and byte <= 0xBF;
}

fn readScalar(input: []const u8, index: *usize) Utf8Error!u21 {
    if (index.* >= input.len) return error.InvalidUtf8;

    const start = index.*;
    const first = input[start];
    if (first < 0x80) {
        index.* += 1;
        return @intCast(first);
    }

    const next = try skipUtf8Sequence(input, start);
    index.* = next;

    return switch (next - start) {
        2 => (@as(u21, first & 0x1F) << 6) | @as(u21, input[start + 1] & 0x3F),
        3 => (@as(u21, first & 0x0F) << 12) |
            (@as(u21, input[start + 1] & 0x3F) << 6) |
            @as(u21, input[start + 2] & 0x3F),
        4 => (@as(u21, first & 0x07) << 18) |
            (@as(u21, input[start + 1] & 0x3F) << 12) |
            (@as(u21, input[start + 2] & 0x3F) << 6) |
            @as(u21, input[start + 3] & 0x3F),
        else => error.InvalidUtf8,
    };
}

fn foldBytes(comptime mapping: Casemapping, input: []const u8, out: []u8) FoldError![]const u8 {
    if (out.len < input.len) return error.OutputTooSmall;
    for (input, 0..) |byte, index| out[index] = foldByte(mapping, byte);
    return out[0..input.len];
}

fn foldUtf8Only(input: []const u8, out: []u8) FoldError![]const u8 {
    var read: usize = 0;
    var write: usize = 0;

    while (read < input.len) {
        const scalar = simpleLowerScalar(try readScalar(input, &read));
        var tmp: [4]u8 = undefined;
        const encoded_len = encodeScalar(scalar, &tmp);
        if (write + encoded_len > out.len) return error.OutputTooSmall;
        @memcpy(out[write .. write + encoded_len], tmp[0..encoded_len]);
        write += encoded_len;
    }

    return out[0..write];
}

fn eqlBytes(comptime mapping: Casemapping, a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |left, right| {
        if (foldByte(mapping, left) != foldByte(mapping, right)) return false;
    }
    return true;
}

fn eqlUtf8Only(a: []const u8, b: []const u8) bool {
    var left_index: usize = 0;
    var right_index: usize = 0;

    while (left_index < a.len and right_index < b.len) {
        const left = simpleLowerScalar(readScalar(a, &left_index) catch return false);
        const right = simpleLowerScalar(readScalar(b, &right_index) catch return false);
        if (left != right) return false;
    }

    return left_index == a.len and right_index == b.len;
}

fn foldByte(comptime mapping: Casemapping, byte: u8) u8 {
    if (byte >= 'A' and byte <= 'Z') return byte + ('a' - 'A');

    return switch (mapping) {
        .rfc1459 => switch (byte) {
            '[' => '{',
            ']' => '}',
            '\\' => '|',
            '~' => '^',
            else => byte,
        },
        .ascii, .utf8_only => byte,
    };
}

fn simpleLowerScalar(scalar: u21) u21 {
    if (scalar >= 'A' and scalar <= 'Z') return scalar + ('a' - 'A');
    if (scalar >= 0x00C0 and scalar <= 0x00D6) return scalar + 0x20;
    if (scalar >= 0x00D8 and scalar <= 0x00DE) return scalar + 0x20;

    if (scalar >= 0x0100 and scalar <= 0x012F and scalar % 2 == 0) return scalar + 1;
    if (scalar >= 0x0132 and scalar <= 0x0137 and scalar % 2 == 0) return scalar + 1;
    if (scalar >= 0x0139 and scalar <= 0x0148 and scalar % 2 == 1) return scalar + 1;
    if (scalar >= 0x014A and scalar <= 0x0177 and scalar % 2 == 0) return scalar + 1;
    if (scalar == 0x0178) return 0x00FF;

    if (scalar == 0x0386) return 0x03AC;
    if (scalar >= 0x0388 and scalar <= 0x038A) return scalar + 0x25;
    if (scalar == 0x038C) return 0x03CC;
    if (scalar >= 0x038E and scalar <= 0x038F) return scalar + 0x3F;
    if (scalar >= 0x0391 and scalar <= 0x03A1) return scalar + 0x20;
    if (scalar >= 0x03A3 and scalar <= 0x03AB) return scalar + 0x20;

    if (scalar >= 0x0410 and scalar <= 0x042F) return scalar + 0x20;
    if (scalar >= 0xFF21 and scalar <= 0xFF3A) return scalar + 0x20;

    return scalar;
}

fn encodeScalar(scalar: u21, out: *[4]u8) usize {
    if (scalar <= 0x7F) {
        out[0] = @intCast(scalar);
        return 1;
    }
    if (scalar <= 0x7FF) {
        out[0] = @intCast(0xC0 | (scalar >> 6));
        out[1] = @intCast(0x80 | (scalar & 0x3F));
        return 2;
    }
    if (scalar <= 0xFFFF) {
        out[0] = @intCast(0xE0 | (scalar >> 12));
        out[1] = @intCast(0x80 | ((scalar >> 6) & 0x3F));
        out[2] = @intCast(0x80 | (scalar & 0x3F));
        return 3;
    }

    out[0] = @intCast(0xF0 | (scalar >> 18));
    out[1] = @intCast(0x80 | ((scalar >> 12) & 0x3F));
    out[2] = @intCast(0x80 | ((scalar >> 6) & 0x3F));
    out[3] = @intCast(0x80 | (scalar & 0x3F));
    return 4;
}

fn isValidAsciiNick(nick: []const u8) bool {
    if (!isNickFirstAscii(nick[0])) return false;
    for (nick[1..]) |byte| {
        if (!isNickRestAscii(byte)) return false;
    }
    return true;
}

fn isValidUtf8Nick(nick: []const u8) bool {
    if (containsIdentifierSpoof(nick)) return false;
    var index: usize = 0;
    const first = readScalar(nick, &index) catch return false;
    if (!isNickFirstScalar(first)) return false;

    while (index < nick.len) {
        const scalar = readScalar(nick, &index) catch return false;
        if (!isNickRestScalar(scalar)) return false;
    }

    return true;
}

fn isValidAsciiChannelRest(rest: []const u8) bool {
    for (rest) |byte| {
        if (!isChannelScalar(byte)) return false;
        if (byte >= 0x80) return false;
    }
    return true;
}

fn isValidUtf8ChannelRest(rest: []const u8) bool {
    if (containsIdentifierSpoof(rest)) return false;
    var index: usize = 0;
    while (index < rest.len) {
        const scalar = readScalar(rest, &index) catch return false;
        if (!isChannelScalar(scalar)) return false;
    }
    return true;
}

fn validChannelPrefix(prefix: u8, comptime options: NameOptions) bool {
    return prefix == '#' or
        (options.allow_ampersand_channel and prefix == '&') or
        (options.allow_bang_channel and prefix == '!');
}

/// True when `text` would let one identifier be confused with another.
/// ASCII is never spoofed. A bidi override, an invisible scalar, a
/// confusable presentation form, or two letter scripts in one name is.
/// `%#` and other ASCII prefixes are not a second script.
pub fn containsIdentifierSpoof(text: []const u8) bool {
    var index: usize = 0;
    var seen: u8 = 0;
    while (index < text.len) {
        if (text[index] < 0x80) {
            const byte = text[index];
            index += 1;
            if (asciiAlpha(byte)) {
                if (seen != 0 and seen != 1) return true;
                seen = 1;
            }
            continue;
        }
        const scalar = readScalar(text, &index) catch return true;
        if (isSpoofScalar(scalar)) return true;
        if (letterScript(scalar)) |script| {
            if (seen != 0 and seen != script) return true;
            seen = script;
        }
    }
    return false;
}

fn isSpoofScalar(scalar: u21) bool {
    return switch (scalar) {
        0x00AD, 0x061C, 0x180E, 0xFEFF, 0xE0001 => true,
        0x0300...0x036F,
        0x1AB0...0x1AFF,
        0x1DC0...0x1DFF,
        0x200B...0x200F,
        0x202A...0x202E,
        0x2060...0x2064,
        0x2066...0x206F,
        0x20D0...0x20FF,
        0x2100...0x214F,
        0xFE00...0xFE0F,
        0xFE20...0xFE2F,
        0xFF01...0xFF5E,
        0x1D400...0x1D7FF,
        0xE0020...0xE007F,
        0xE0100...0xE01EF,
        => true,
        else => false,
    };
}

/// One letter-script id. ASCII letters are Latin (1). Common punctuation
/// and symbols return null so they can sit beside a single script.
fn letterScript(scalar: u21) ?u8 {
    if (scalar <= 0x7F) {
        if (asciiAlpha(@intCast(scalar))) return 1;
        return null;
    }
    if ((scalar >= 0x00C0 and scalar <= 0x00D6) or
        (scalar >= 0x00D8 and scalar <= 0x00F6) or
        (scalar >= 0x00F8 and scalar <= 0x024F) or
        (scalar >= 0x1E00 and scalar <= 0x1EFF) or
        (scalar >= 0x2C60 and scalar <= 0x2C7F) or
        (scalar >= 0xA720 and scalar <= 0xA7FF) or
        (scalar >= 0xAB30 and scalar <= 0xAB6F)) return 1;
    if ((scalar >= 0x0370 and scalar <= 0x03FF) or (scalar >= 0x1F00 and scalar <= 0x1FFF)) return 2;
    if ((scalar >= 0x0400 and scalar <= 0x052F) or
        (scalar >= 0x1C80 and scalar <= 0x1C8F) or
        (scalar >= 0x2DE0 and scalar <= 0x2DFF) or
        (scalar >= 0xA640 and scalar <= 0xA69F)) return 3;
    if (scalar >= 0x0590 and scalar <= 0x05FF) return 4;
    if ((scalar >= 0x0600 and scalar <= 0x06FF) or
        (scalar >= 0x0750 and scalar <= 0x077F) or
        (scalar >= 0x08A0 and scalar <= 0x08FF)) return 5;
    if ((scalar >= 0x3040 and scalar <= 0x30FF) or
        (scalar >= 0x3400 and scalar <= 0x9FFF) or
        (scalar >= 0xF900 and scalar <= 0xFAFF)) return 6;
    if ((scalar >= 0x1100 and scalar <= 0x11FF) or (scalar >= 0xAC00 and scalar <= 0xD7AF)) return 7;
    return null;
}

fn isNickFirstAscii(byte: u8) bool {
    return asciiAlpha(byte) or isIrcSpecial(byte);
}

fn isNickRestAscii(byte: u8) bool {
    return isNickFirstAscii(byte) or asciiDigit(byte) or byte == '-';
}

fn isNickFirstScalar(scalar: u21) bool {
    if (!isNickVisibleScalar(scalar)) return false;
    if (scalar < 0x80) return isNickFirstAscii(@intCast(scalar));
    return true;
}

fn isNickRestScalar(scalar: u21) bool {
    if (!isNickVisibleScalar(scalar)) return false;
    if (scalar < 0x80) return isNickRestAscii(@intCast(scalar));
    return true;
}

fn isNickVisibleScalar(scalar: u21) bool {
    if (isForbiddenNameScalar(scalar)) return false;
    return switch (scalar) {
        '#', '&', '+', '@', '%', ':', ',', '!', '*', '?' => false,
        else => true,
    };
}

fn isChannelScalar(scalar: u21) bool {
    if (isForbiddenNameScalar(scalar)) return false;
    return scalar != ',';
}

fn isForbiddenNameScalar(scalar: u21) bool {
    if (scalar <= 0x20) return true;
    if (scalar >= 0x7F and scalar <= 0x9F) return true;
    return switch (scalar) {
        0x00A0, 0x1680, 0x2000...0x200A, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, ':' => true,
        else => false,
    };
}

fn asciiAlpha(byte: u8) bool {
    return (byte >= 'A' and byte <= 'Z') or (byte >= 'a' and byte <= 'z');
}

fn asciiDigit(byte: u8) bool {
    return byte >= '0' and byte <= '9';
}

fn isIrcSpecial(byte: u8) bool {
    return switch (byte) {
        '[', ']', '\\', '`', '_', '^', '{', '|', '}', '~' => true,
        else => false,
    };
}

test "valid utf8 accepts ascii and multi byte scalars" {
    try std.testing.expect(validateUtf8(""));
    try std.testing.expect(validateUtf8("plain ascii"));
    try std.testing.expect(validateUtf8("\xC2\xA2"));
    try std.testing.expect(validateUtf8("\xE2\x82\xAC"));
    try std.testing.expect(validateUtf8("\xF0\x9F\x92\xA9"));
}

test "invalid utf8 rejects overlong surrogate and truncated sequences" {
    try std.testing.expect(!validateUtf8("\xC0\xAF"));
    try std.testing.expect(!validateUtf8("\xED\xA0\x80"));
    try std.testing.expect(!validateUtf8("\xE2\x82"));
    try std.testing.expectError(error.InvalidUtf8, validateUtf8Error("\xF4\x90\x80\x80"));
}

test "ascii and rfc1459 casefold differ on bracket backslash tilde" {
    const storage = try std.testing.allocator.alloc(u8, 16);
    defer std.testing.allocator.free(storage);

    try std.testing.expectEqualStrings("[]\\~az", try fold(.ascii, "[]\\~AZ", storage));
    try std.testing.expectEqualStrings("{}|^az", try fold(.rfc1459, "[]\\~AZ", storage));
    try std.testing.expect(!eql(.ascii, "[]\\~", "{}|^"));
    try std.testing.expect(eql(.rfc1459, "[]\\~", "{}|^"));
}

test "utf8 only casefold lowers a simple unicode subset" {
    var storage: [32]u8 = undefined;
    try std.testing.expectEqualStrings("\xC3\xA9clair", try fold(.utf8_only, "\xC3\x89CLAIR", &storage));
    try std.testing.expect(eql(.utf8_only, "\xC3\x89clair", "\xC3\xA9CLAIR"));
    try std.testing.expect(eql(.utf8_only, "\xD0\x9CIZUCHI", "\xD0\xBCizuchi"));
}

test "case insensitive nick equality follows the selected mapping" {
    try std.testing.expect(eql(.ascii, "Alice", "alice"));
    try std.testing.expect(!eql(.ascii, "Nick[\\~]", "nick{|^}"));
    try std.testing.expect(eql(.rfc1459, "Nick[\\~]", "nick{|^}"));
    try std.testing.expect(eql(.utf8_only, "\xC3\x89clair", "\xC3\xA9CLAIR"));
    try std.testing.expect(!eql(.utf8_only, "\xC0\xAF", "\xC0\xAF"));
}

test "nick validity is bounded and mapping aware" {
    try std.testing.expect(isValidNick(.ascii, "Alice-42"));
    try std.testing.expect(isValidNick(.rfc1459, "[nick]"));
    try std.testing.expect(!isValidNick(.ascii, "4lice"));
    try std.testing.expect(!isValidNick(.ascii, "bad,nick"));
    try std.testing.expect(!isValidNickWith(.ascii, "toolong", .{ .max_nick_bytes = 3 }));
    try std.testing.expect(isValidNick(.utf8_only, "\xCE\x94\xCE\xB5\xCE\xBB\xCF\x84\xCE\xB1"));
    try std.testing.expect(!isValidNick(.utf8_only, "\xCE\x94elta"));
    try std.testing.expect(!isValidNick(.utf8_only, "\xC0\xAF"));
}

test "identifier spoof rejects bidi overrides and mixed scripts" {
    try std.testing.expect(!containsIdentifierSpoof("Ann"));
    try std.testing.expect(!containsIdentifierSpoof("#onyx"));
    try std.testing.expect(!containsIdentifierSpoof("%#room"));
    try std.testing.expect(!containsIdentifierSpoof("\xCE\x94\xCE\xB5\xCE\xBB\xCF\x84\xCE\xB1"));
    try std.testing.expect(!containsIdentifierSpoof("#d\xC3\xA9j\xC3\xA0"));
    try std.testing.expect(containsIdentifierSpoof("Ann\u{202E}"));
    try std.testing.expect(containsIdentifierSpoof("A\u{0430}"));
    try std.testing.expect(containsIdentifierSpoof("\u{FF21}lice"));
    try std.testing.expect(containsIdentifierSpoof("#room\u{200B}"));
    try std.testing.expect(!isValidChannel(.utf8_only, "#room\u{202E}"));
    try std.testing.expect(isValidChannel(.utf8_only, "#d\xC3\xA9j\xC3\xA0"));
}

test "channel name validity rejects missing prefixes separators and invalid utf8" {
    try std.testing.expect(isValidChannel(.ascii, "#onyx"));
    try std.testing.expect(isValidChannel(.rfc1459, "#Suzu[\\~]"));
    try std.testing.expect(isValidChannel(.utf8_only, "#d\xC3\xA9j\xC3\xA0"));
    try std.testing.expect(!isValidChannel(.ascii, "onyx"));
    try std.testing.expect(!isValidChannel(.ascii, "#bad name"));
    try std.testing.expect(!isValidChannel(.ascii, "#bad,chan"));
    try std.testing.expect(!isValidChannel(.ascii, "#d\xC3\xA9j\xC3\xA0"));
    try std.testing.expect(!isValidChannel(.utf8_only, "#\xC0\xAF"));
    try std.testing.expect(isValidChannelWith(.ascii, "&local", .{ .allow_ampersand_channel = true }));
    try std.testing.expect(!isValidChannel(.ascii, "&local"));
}
