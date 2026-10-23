// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Configured-nameserver address selection for blocking, out-of-band callers.
//! No system discovery, public fallback, search suffixes, or target connection.

const std = @import("std");
const dns = @import("../proto/dns.zig");
const engine = @import("../proto/dns/query_engine.zig");
const Deadline = @import("../proto/dns/deadline.zig").Deadline;

pub const Family = enum { a, aaaa };
pub const Error = dns.EncodeError || error{ NoNameservers, HostNotFound };

/// Return the first validated address of the requested family, with the caller's
/// target port. All nameservers, CNAME follow-ups, and TCP fallback share one
/// absolute budget (clamped by the DNS engine to 1..5000 ms). Each nameserver
/// gets a fair share of the remaining time; negative answers still permit the
/// next configured server, matching the existing single-address caller policy.
/// Literal handling and config-file read errors belong to the caller.
pub fn resolve(text: []const u8, host: []const u8, target_port: u16, dns_port: u16, family: Family, budget_ms: u32) Error!std.Io.net.IpAddress {
    return resolveUntil(text, host, target_port, dns_port, family, Deadline.after(budget_ms));
}

/// Shared-deadline variant for callers that coordinate multiple family lookups.
/// The supplied absolute deadline is never renewed, including after scheduling
/// delays or configuration/name validation.
pub fn resolveUntil(text: []const u8, host: []const u8, target_port: u16, dns_port: u16, family: Family, deadline: Deadline) Error!std.Io.net.IpAddress {
    const cfg = try configuration(text, dns_port);
    const qtype: dns.RecordType = switch (family) {
        .a => .a,
        .aaaa => .aaaa,
    };
    // Preserve name-validation errors before endpoint errors are aggregated.
    var query: [dns.max_message_len]u8 = undefined;
    _ = try dns.encodeQuery(&query, 0, host, qtype);
    for (cfg.nsSlice(), 0..) |address, index| {
        const remaining = deadline.remaining() catch break;
        const share = @max(1, remaining / @as(u32, @intCast(cfg.nameserver_count - index)));
        const endpoint_deadline = deadline.slice(share) catch break;
        var endpoint = dns.ResolverConfig{ .port = dns_port, .timeout_ms = share, .attempts = 1 };
        endpoint.addNameserver(address);
        endpoint.nameserver_scope_ids[0] = cfg.nameserver_scope_ids[index];
        const result = engine.resolveUntil(&endpoint, host, qtype, endpoint_deadline) catch continue;
        if (result.outcome != .positive) continue;
        for (result.addressSlice()) |answer| switch (answer) {
            .ipv4 => |bytes| if (family == .a) return .{ .ip4 = .{ .bytes = bytes, .port = target_port } },
            .ipv6 => |bytes| if (family == .aaaa) return .{ .ip6 = .{ .bytes = bytes, .port = target_port } },
        };
    }
    return error.HostNotFound;
}

fn configuration(text: []const u8, port: u16) error{NoNameservers}!dns.ResolverConfig {
    var cfg = dns.ResolverConfig{ .port = port };
    if (dns.parseResolvConf(text, &cfg) == 0) return error.NoNameservers;
    // Caller budgets govern this adapter. Parsed options must never multiply
    // attempts or expand the absolute deadline, including across aliases.
    cfg.attempts = 1;
    cfg.timeout_ms = 0;
    return cfg;
}

test "DNS address lookup preserves four ordered scoped endpoints without fallback" {
    const cfg = try configuration(
        "nameserver 127.0.0.2\nnameserver fe80::1%7\nnameserver fe80::1%7\nnameserver fe80::1%8\nnameserver ::1\nnameserver 127.0.0.3\noptions timeout:99 attempts:99\n",
        5353,
    );
    try std.testing.expectEqual(@as(usize, 4), cfg.nameserver_count);
    try std.testing.expectEqualSlices(u8, &.{ 127, 0, 0, 2 }, &cfg.nameservers[0].ipv4);
    try std.testing.expectEqual(@as(u32, 7), cfg.nameserver_scope_ids[1]);
    try std.testing.expectEqual(@as(u32, 8), cfg.nameserver_scope_ids[2]);
    try std.testing.expectEqual(@as(u8, 1), cfg.nameservers[3].ipv6[15]);
    try std.testing.expectEqual(@as(u16, 5353), cfg.port);
    try std.testing.expectEqual(@as(u8, 1), cfg.attempts);
    try std.testing.expectEqual(@as(u32, 0), cfg.timeout_ms);
    try std.testing.expectError(error.NoNameservers, configuration("nameserver fe80::1\nnameserver invalid", 53));
}

test "DNS address lookup preserves config before hostname error precedence" {
    try std.testing.expectError(error.NoNameservers, resolve("", "bad..name", 443, 53, .a, 3000));
    try std.testing.expectError(error.InvalidName, resolve("nameserver 127.0.0.1", "bad..name", 443, 0, .a, 3000));
    const long_name: [254]u8 = @splat('a');
    try std.testing.expectError(error.NameTooLong, resolve("nameserver 127.0.0.1", &long_name, 443, 53, .a, 3000));
    try std.testing.expectError(error.HostNotFound, resolve("nameserver 127.0.0.1", "host.test", 443, 0, .a, 3000));
}
