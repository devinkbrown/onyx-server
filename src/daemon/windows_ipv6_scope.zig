// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Native Windows IPv6 zone resolution for configured listener and mesh hosts.
//! A zone is a local interface index or the interface alias shown by Windows.

const std = @import("std");
const builtin = @import("builtin");

const win = if (builtin.os.tag == .windows) struct {
    const windows = std.os.windows;

    extern "iphlpapi" fn ConvertInterfaceAliasToLuid(
        alias: [*:0]const u16,
        luid: *windows.NET.LUID,
    ) callconv(.winapi) u32;
    extern "iphlpapi" fn ConvertInterfaceLuidToIndex(
        luid: *const windows.NET.LUID,
        index: *windows.NET.IFINDEX,
    ) callconv(.winapi) u32;
} else struct {};

/// Parse an IPv6 literal, including a numeric `%index` or Windows `%alias`.
/// This never resolves hostnames. The caller can therefore reject a malformed
/// zone without sending it through DNS as a fallback.
pub fn parseLiteral(host: []const u8, port: u16) error{InvalidAddress}!std.Io.net.Ip6Address {
    if (std.mem.indexOfScalar(u8, host, 0) != null) return error.InvalidAddress;
    if (std.mem.indexOfScalar(u8, host, '%')) |percent| {
        var address = std.Io.net.Ip6Address.parse(host[0..percent], port) catch return error.InvalidAddress;
        address.interface = .{ .index = try resolveZone(host[percent + 1 ..]) };
        return address;
    }
    return std.Io.net.Ip6Address.parse(host, port) catch error.InvalidAddress;
}

/// Resolve one zone suffix to the scope id stored in `sockaddr_in6`. Decimal
/// values are indices; any other nonempty UTF-8 value is a Windows alias.
pub fn resolveZone(zone: []const u8) error{InvalidAddress}!u32 {
    if (zone.len == 0 or std.mem.indexOfAny(u8, zone, "\x00%") != null)
        return error.InvalidAddress;

    var numeric = true;
    for (zone) |byte| {
        if (byte < '0' or byte > '9') {
            numeric = false;
            break;
        }
    }
    if (numeric) {
        if (zone.len > 10) return error.InvalidAddress;
        const index = std.fmt.parseInt(u32, zone, 10) catch return error.InvalidAddress;
        if (index == 0) return error.InvalidAddress;
        return index;
    }

    if (comptime builtin.os.tag == .windows) {
        // IF_MAX_STRING_SIZE is 256 UTF-16 code units. Size the stack buffer
        // for that maximum plus its terminator; no allocator or libc is needed.
        const count = std.unicode.calcUtf16LeLen(zone) catch return error.InvalidAddress;
        if (count == 0 or count > 256) return error.InvalidAddress;
        var wide: [257]u16 = undefined;
        const written = std.unicode.utf8ToUtf16Le(wide[0..count], zone) catch return error.InvalidAddress;
        wide[written] = 0;
        const alias = wide[0..written :0];
        var luid: win.windows.NET.LUID = undefined;
        if (win.ConvertInterfaceAliasToLuid(alias.ptr, &luid) != 0)
            return error.InvalidAddress;
        var index: win.windows.NET.IFINDEX = undefined;
        if (win.ConvertInterfaceLuidToIndex(&luid, &index) != 0)
            return error.InvalidAddress;
        const scope_id = @intFromEnum(index);
        if (scope_id == 0) return error.InvalidAddress;
        return scope_id;
    } else return error.InvalidAddress;
}

test "Windows IPv6 scope resolves numeric zones and rejects malformed literals" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const parsed = try parseLiteral("fe80::1%7", 6900);
    try std.testing.expectEqual(@as(u16, 6900), parsed.port);
    try std.testing.expectEqual(@as(u32, 7), parsed.interface.index);
    try std.testing.expectEqual(@as(u8, 0xfe), parsed.bytes[0]);
    try std.testing.expectEqual(@as(u8, 0x80), parsed.bytes[1]);
    try std.testing.expectEqual(@as(u8, 1), parsed.bytes[15]);
    try std.testing.expectEqual(@as(u32, 7), try resolveZone("007"));
    for ([_][]const u8{
        "fe80::1%",     "fe80::1%0",   "fe80::1%4294967296", "fe80::1%00000000000",
        "fe80::1%7%8",  "127.0.0.1%7", "invalid::1%7",       "fe80::1%Ethernet\x00other",
        "fe80::1%\xff",
    }) |host| try std.testing.expectError(error.InvalidAddress, parseLiteral(host, 6900));
    var too_long: [8 + 257]u8 = undefined;
    @memcpy(too_long[0..8], "fe80::1%");
    @memset(too_long[8..], 'x');
    try std.testing.expectError(error.InvalidAddress, parseLiteral(&too_long, 6900));
}
