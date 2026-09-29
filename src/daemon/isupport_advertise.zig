// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Checks the tokens supplied to the live registration 005 path.
const std = @import("std");
const server = @import("server.zig");
const inventory = @import("../proto/protocol_inventory.zig");
const irc_isupport = @import("../proto/irc_isupport.zig");

test "005 CHATHISTORY and auditorium mode come from the live CHANMODES table" {
    const allocator = std.testing.allocator;
    const rendered = try server.buildIsupportTokens(allocator, .{ .port = 0 });
    defer server.freeIsupportTokens(allocator, rendered);

    const tokens = try allocator.alloc(irc_isupport.Token, rendered.len);
    defer allocator.free(tokens);
    for (rendered, 0..) |raw, i| {
        if (std.mem.indexOfScalar(u8, raw, '=')) |eq| {
            tokens[i] = .{ .key = raw[0..eq], .value = raw[eq + 1 ..] };
        } else {
            tokens[i] = .{ .key = raw };
        }
    }
    const lines = try irc_isupport.buildLines(allocator, tokens, .{ .server = "onyx", .target = "alice" });
    defer allocator.free(lines);
    try std.testing.expect(std.mem.indexOf(u8, lines, " 005 alice ") != null);
    try std.testing.expect(std.mem.indexOf(u8, lines, " CHATHISTORY=64 ") != null);

    var found = false;
    for (rendered) |raw| {
        if (!std.mem.startsWith(u8, raw, "CHANMODES=")) continue;
        try std.testing.expectEqualStrings(inventory.chanmodes_token, raw);
        var classes = std.mem.splitScalar(u8, raw["CHANMODES=".len..], ',');
        _ = classes.next();
        _ = classes.next();
        _ = classes.next();
        const flags = classes.next() orelse return error.TestUnexpectedResult;
        try std.testing.expect(std.mem.indexOfScalar(u8, flags, 'x') != null);
        try std.testing.expect(classes.next() == null);
        found = true;
    }
    try std.testing.expect(found);
}
