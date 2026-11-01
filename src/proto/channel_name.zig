//! Shared World channel-name grammar. No length policy, display rewrite or case folding.
const ident_utf8 = @import("../substrate/utf8.zig");
const std = @import("std");

pub fn isChannelName(name: []const u8) bool {
    if (name.len == 0) return false;
    const prefixed = switch (name[0]) {
        '#', '&' => true,
        '%' => name.len >= 2 and (name[1] == '#' or name[1] == '&'),
        else => false,
    };
    if (!prefixed) return false;
    return !ident_utf8.containsIdentifierSpoof(name);
}

/// Membership scope 1 excludes both local-only channel sigils.
pub fn isNetworkChannelName(name: []const u8) bool {
    return isChannelName(name) and (name[0] == '#' or
        (name.len >= 2 and name[0] == '%' and name[1] == '#'));
}

test "shared World grammar preserves local sigils UTF8 and spoof refusal" {
    for ([_][]const u8{ "#chan", "&local", "%#utf8", "%&utf8local", "#привет" }) |name|
        try std.testing.expect(isChannelName(name));
    for ([_][]const u8{ "", "nick", "%", "%nope", "^hexchan", "#room\u{202E}", "#A\u{0430}" }) |name|
        try std.testing.expect(!isChannelName(name));
    try std.testing.expect(isNetworkChannelName("#network"));
    try std.testing.expect(isNetworkChannelName("%#привет"));
    try std.testing.expect(!isNetworkChannelName("&local"));
    try std.testing.expect(!isNetworkChannelName("%&local"));
}
