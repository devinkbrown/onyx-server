// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! IRCv3 RPL_ISUPPORT (005) token building and parsing.
//!
//! This module is intentionally self-contained: it owns parsed keys and values,
//! imports only `std`, and does not depend on Onyx Server registration code.
const std = @import("std");
const protocol_inventory = @import("protocol_inventory.zig");
const chanmode = @import("../daemon/chanmode.zig");

pub const MAX_TOKENS_PER_LINE: usize = 13;
pub const TRAILING_TEXT = "are supported by this server";

pub const IsupportError = std.mem.Allocator.Error || error{
    InvalidLine,
    InvalidToken,
    InvalidKey,
    InvalidEscape,
};

pub const Token = struct {
    key: []const u8,
    value: ?[]const u8 = null,
    negated: bool = false,
};

pub const BuildOptions = struct {
    server: []const u8 = "onyx",
    target: []const u8 = "*",
};

pub const Entry = struct {
    value: ?[]const u8 = null,
    negated: bool = false,
};

pub const Map = struct {
    allocator: std.mem.Allocator,
    items: std.StringHashMap(Entry),

    pub fn init(allocator: std.mem.Allocator) Map {
        return .{
            .allocator = allocator,
            .items = std.StringHashMap(Entry).init(allocator),
        };
    }

    pub fn deinit(self: *Map) void {
        var iter = self.items.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            if (entry.value_ptr.value) |value| self.allocator.free(value);
        }
        self.items.deinit();
        self.* = undefined;
    }

    pub fn has(self: *const Map, key: []const u8) bool {
        const entry = self.items.get(key) orelse return false;
        return !entry.negated;
    }

    pub fn isNegated(self: *const Map, key: []const u8) bool {
        const entry = self.items.get(key) orelse return false;
        return entry.negated;
    }

    pub fn getStr(self: *const Map, key: []const u8) ?[]const u8 {
        const entry = self.items.get(key) orelse return null;
        if (entry.negated) return null;
        return entry.value;
    }

    pub fn getInt(self: *const Map, comptime T: type, key: []const u8) !?T {
        const value = self.getStr(key) orelse return null;
        return try std.fmt.parseInt(T, value, 10);
    }

    fn putOwned(self: *Map, key: []u8, entry: Entry) IsupportError!void {
        if (self.items.fetchRemove(key)) |removed| {
            self.allocator.free(removed.key);
            if (removed.value.value) |value| self.allocator.free(value);
        }
        try self.items.put(key, entry);
    }
};

/// Build complete `005` wire lines ending in CRLF. Values are ISUPPORT-escaped,
/// and output is chunked to at most 13 tokens per line.
pub fn buildLines(
    allocator: std.mem.Allocator,
    tokens: []const Token,
    options: BuildOptions,
) IsupportError![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    var cursor: usize = 0;
    while (cursor < tokens.len or (tokens.len == 0 and cursor == 0)) {
        const end = @min(cursor + MAX_TOKENS_PER_LINE, tokens.len);
        try appendLinePrefix(allocator, &out, options);

        for (tokens[cursor..end], 0..) |token, index| {
            try validateToken(token);
            if (index != 0) try out.append(allocator, ' ');
            try appendToken(allocator, &out, token);
        }

        try out.appendSlice(allocator, " :");
        try out.appendSlice(allocator, TRAILING_TEXT);
        try out.appendSlice(allocator, "\r\n");

        if (tokens.len == 0) break;
        cursor = end;
    }

    return try out.toOwnedSlice(allocator);
}

/// Parse one RPL_ISUPPORT (005) line. Returned keys and values are owned by
/// the map and remain valid until `Map.deinit`.
pub fn parseLine(allocator: std.mem.Allocator, line: []const u8) IsupportError!Map {
    var map = Map.init(allocator);
    errdefer map.deinit();

    const trimmed = std.mem.trim(u8, line, " \r\n");
    if (trimmed.len == 0) return error.InvalidLine;

    var words = std.mem.tokenizeScalar(u8, trimmed, ' ');
    const first = words.next() orelse return error.InvalidLine;
    const numeric = if (first.len != 0 and first[0] == ':')
        words.next() orelse return error.InvalidLine
    else
        first;
    if (!std.mem.eql(u8, numeric, "005")) return error.InvalidLine;
    _ = words.next() orelse return error.InvalidLine;

    while (words.next()) |word| {
        if (word.len == 0) continue;
        if (word[0] == ':') break;
        try parseTokenInto(allocator, &map, word);
    }

    return map;
}

fn appendLinePrefix(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    options: BuildOptions,
) IsupportError!void {
    if (options.server.len != 0) {
        try out.append(allocator, ':');
        try out.appendSlice(allocator, options.server);
        try out.append(allocator, ' ');
    }
    try out.appendSlice(allocator, "005 ");
    try out.appendSlice(allocator, options.target);
    try out.append(allocator, ' ');
}

fn appendToken(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    token: Token,
) IsupportError!void {
    if (token.negated) try out.append(allocator, '-');
    try out.appendSlice(allocator, token.key);
    if (token.value) |value| {
        try out.append(allocator, '=');
        try appendEscapedValue(allocator, out, value);
    }
}

fn appendEscapedValue(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    value: []const u8,
) IsupportError!void {
    for (value) |byte| {
        if (needsEscape(byte)) {
            try out.appendSlice(allocator, "\\x");
            try out.append(allocator, hexDigit(byte >> 4));
            try out.append(allocator, hexDigit(byte & 0x0f));
        } else {
            try out.append(allocator, byte);
        }
    }
}

fn parseTokenInto(
    allocator: std.mem.Allocator,
    map: *Map,
    token: []const u8,
) IsupportError!void {
    var body = token;
    const negated = body.len != 0 and body[0] == '-';
    if (negated) body = body[1..];

    const eq_index = std.mem.indexOfScalar(u8, body, '=');
    const key = if (eq_index) |index| body[0..index] else body;
    if (!validKey(key)) return error.InvalidKey;
    if (negated and eq_index != null) return error.InvalidToken;

    const owned_key = try allocator.dupe(u8, key);
    errdefer allocator.free(owned_key);

    const owned_value = if (eq_index) |index|
        try unescapeValue(allocator, body[index + 1 ..])
    else
        null;
    errdefer if (owned_value) |value| allocator.free(value);

    try map.putOwned(owned_key, .{
        .value = owned_value,
        .negated = negated,
    });
}

fn unescapeValue(allocator: std.mem.Allocator, value: []const u8) IsupportError![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    var cursor: usize = 0;
    while (cursor < value.len) {
        if (value[cursor] != '\\') {
            try out.append(allocator, value[cursor]);
            cursor += 1;
            continue;
        }

        if (cursor + 4 > value.len or value[cursor + 1] != 'x') {
            return error.InvalidEscape;
        }
        const high = hexValue(value[cursor + 2]) orelse return error.InvalidEscape;
        const low = hexValue(value[cursor + 3]) orelse return error.InvalidEscape;
        try out.append(allocator, (high << 4) | low);
        cursor += 4;
    }

    return try out.toOwnedSlice(allocator);
}

fn validateToken(token: Token) IsupportError!void {
    if (!validKey(token.key)) return error.InvalidKey;
    if (token.negated and token.value != null) return error.InvalidToken;
}

fn validKey(key: []const u8) bool {
    if (key.len == 0) return false;
    for (key) |byte| {
        switch (byte) {
            'A'...'Z', '0'...'9', '-' => {},
            else => return false,
        }
    }
    return true;
}

fn needsEscape(byte: u8) bool {
    return switch (byte) {
        0...' ', 0x7f, '=', '\\' => true,
        else => false,
    };
}

fn hexDigit(nibble: u8) u8 {
    return if (nibble < 10) '0' + nibble else 'A' + (nibble - 10);
}

fn hexValue(byte: u8) ?u8 {
    return switch (byte) {
        '0'...'9' => byte - '0',
        'a'...'f' => byte - 'a' + 10,
        'A'...'F' => byte - 'A' + 10,
        else => null,
    };
}

const common_tokens = [_]Token{
    .{ .key = "CHANMODES", .value = protocol_inventory.chanmodes_token["CHANMODES=".len..] },
    .{ .key = "PREFIX", .value = chanmode.MemberModes.isupport_prefix },
    .{ .key = "CHANTYPES", .value = "#&" },
    .{ .key = "NETWORK", .value = "Onyx" },
    .{ .key = "CASEMAPPING", .value = "rfc1459" },
    .{ .key = "TARGMAX", .value = "NAMES:1,LIST:1,KICK:1,PRIVMSG:4" },
};

test "build chunks at the 13-token boundary" {
    const tokens = [_]Token{
        .{ .key = "A" },
        .{ .key = "B" },
        .{ .key = "C" },
        .{ .key = "D" },
        .{ .key = "E" },
        .{ .key = "F" },
        .{ .key = "G" },
        .{ .key = "H" },
        .{ .key = "I" },
        .{ .key = "J" },
        .{ .key = "K" },
        .{ .key = "L" },
        .{ .key = "M" },
        .{ .key = "N" },
    };

    const out = try buildLines(std.testing.allocator, &tokens, .{ .server = "irc.test", .target = "nick" });
    defer std.testing.allocator.free(out);

    try std.testing.expectEqualStrings(
        ":irc.test 005 nick A B C D E F G H I J K L M :are supported by this server\r\n" ++
            ":irc.test 005 nick N :are supported by this server\r\n",
        out,
    );
}

test "round-trip parse of common ISUPPORT tokens" {
    const out = try buildLines(std.testing.allocator, &common_tokens, .{ .server = "irc.test", .target = "nick" });
    defer std.testing.allocator.free(out);

    var map = try parseLine(std.testing.allocator, out);
    defer map.deinit();

    try std.testing.expectEqualStrings(protocol_inventory.chanmodes_token["CHANMODES=".len..], map.getStr("CHANMODES").?);
    try std.testing.expectEqualStrings(chanmode.MemberModes.isupport_prefix, map.getStr("PREFIX").?);
    try std.testing.expectEqualStrings("#&", map.getStr("CHANTYPES").?);
    try std.testing.expectEqualStrings("Onyx", map.getStr("NETWORK").?);
    try std.testing.expectEqualStrings("rfc1459", map.getStr("CASEMAPPING").?);
    try std.testing.expectEqualStrings("NAMES:1,LIST:1,KICK:1,PRIVMSG:4", map.getStr("TARGMAX").?);
    try std.testing.expect(map.has("PREFIX"));
}

test "value escape and unescape" {
    const tokens = [_]Token{
        // Space in the NETWORK value forces \x20 encoding (round-trip fixture).
        .{ .key = "NETWORK", .value = "Onyx Net" },
        .{ .key = "ESCAPE", .value = "a\\b=c" },
    };

    const out = try buildLines(std.testing.allocator, &tokens, .{ .server = "irc.test", .target = "nick" });
    defer std.testing.allocator.free(out);

    try std.testing.expectEqualStrings(
        ":irc.test 005 nick NETWORK=Onyx\\x20Net ESCAPE=a\\x5Cb\\x3Dc :are supported by this server\r\n",
        out,
    );

    var map = try parseLine(std.testing.allocator, ":irc.test 005 nick NETWORK=Onyx\\x20Net ESCAPE=a\\x5cb\\x3Dc :are supported by this server\r\n");
    defer map.deinit();

    try std.testing.expectEqualStrings("Onyx Net", map.getStr("NETWORK").?);
    try std.testing.expectEqualStrings("a\\b=c", map.getStr("ESCAPE").?);
}

test "negation parses as absent but tracked" {
    var map = try parseLine(std.testing.allocator, ":irc.test 005 nick -SAFELIST CASEMAPPING=ascii :are supported by this server");
    defer map.deinit();

    try std.testing.expect(!map.has("SAFELIST"));
    try std.testing.expect(map.isNegated("SAFELIST"));
    try std.testing.expectEqualStrings("ascii", map.getStr("CASEMAPPING").?);
}

test "missing key typed getters return null" {
    var map = try parseLine(std.testing.allocator, ":irc.test 005 nick MODES=4 CHANLIMIT=#:50 :are supported by this server");
    defer map.deinit();

    try std.testing.expect(!map.has("MISSING"));
    try std.testing.expectEqual(@as(?[]const u8, null), map.getStr("MISSING"));
    try std.testing.expectEqual(@as(?u16, 4), try map.getInt(u16, "MODES"));
    try std.testing.expectEqual(@as(?u16, null), try map.getInt(u16, "MISSING"));
}
