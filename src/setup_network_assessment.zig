// SPDX-License-Identifier: AGPL-3.0-or-later
//! Static configuration facts only. No DNS, network traffic, or socket binding.
const std = @import("std");
const workflow = @import("setup_workflow.zig");
pub const Input = struct {
    hostname: []const u8,
    listen_host: []const u8,
    irc_port: u16,
    tls_enabled: bool,
    tls_port: u16,
    validated: bool,
};
pub const Assessment = struct {
    hostname: []const u8,
    candidate_validation: []const u8,
    hostname_check: []const u8,
    hostname_resolution: []const u8 = "unknown; DNS was not queried",
    listen_host: []const u8,
    address_check: []const u8,
    address_ownership: []const u8 = "unknown; local interface ownership was not checked",
    irc_port: u16,
    tls_enabled: bool,
    tls_port: u16,
    port_check: []const u8,
    port_availability: []const u8 = "unknown; no socket was bound",
    public_reachability: []const u8 = "unknown; no network probes were sent",
};
pub fn assess(input: Input) Assessment {
    return .{
        .hostname = input.hostname,
        .candidate_validation = if (input.validated) "configuration loader and static checks passed" else "candidate validation pending",
        .hostname_check = if (workflow.validHostname(input.hostname)) "DNS-label syntax valid; DNS not queried" else "not a DNS-label hostname; DNS not queried",
        .listen_host = input.listen_host,
        .address_check = if (std.Io.net.IpAddress.parse(input.listen_host, input.irc_port)) |address| switch (address) {
            .ip4 => "numeric IPv4 syntax valid",
            .ip6 => "numeric IPv6 syntax valid",
        } else |_| "not a numeric IP; runtime binding not checked",
        .irc_port = input.irc_port,
        .tls_enabled = input.tls_enabled,
        .tls_port = input.tls_port,
        .port_check = if (input.irc_port == 0) "IRC port zero; runtime assignment unknown" else if (input.tls_enabled and input.irc_port == input.tls_port) "configured IRC and TLS ports match; other conflicts not assessed" else if (input.tls_enabled) "IRC and TLS ports differ; other conflicts not assessed" else "TLS listener disabled; other port conflicts not assessed",
    };
}

test "network assessment distinguishes syntax from unobserved reachability" {
    const v4 = assess(.{ .hostname = "irc.example.test", .listen_host = "127.0.0.1", .irc_port = 6680, .tls_enabled = true, .tls_port = 6697, .validated = true });
    try std.testing.expectEqualStrings("numeric IPv4 syntax valid", v4.address_check);
    try std.testing.expectEqualStrings("DNS-label syntax valid; DNS not queried", v4.hostname_check);
    try std.testing.expectEqualStrings("unknown; no network probes were sent", v4.public_reachability);
    const v6 = assess(.{ .hostname = "bad name", .listen_host = "::1", .irc_port = 7000, .tls_enabled = true, .tls_port = 7000, .validated = false });
    try std.testing.expectEqualStrings("numeric IPv6 syntax valid", v6.address_check);
    try std.testing.expectEqualStrings("not a DNS-label hostname; DNS not queried", v6.hostname_check);
    try std.testing.expectEqualStrings("configured IRC and TLS ports match; other conflicts not assessed", v6.port_check);
}
