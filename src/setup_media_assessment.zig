// SPDX-License-Identifier: AGPL-3.0-or-later
//! Observational assessment of generated setup candidates only. No probes.
const workflow = @import("setup_workflow.zig");

/// Values projected from the same candidate or authoritative boot load.
/// Ports are configured intents; zero means an ephemeral port when enabled.
pub const Configured = struct {
    enabled: bool,
    media_port: u16,
    native_media_port: u16,
    advertised_host: []const u8,
    stun_host: []const u8,
    stun_port: u16,
    websocket_port: u16,
    websocket_media_relay: bool,
    existing: bool = false,
};
pub const Assessment = struct {
    enabled: []const u8,
    socket: []const u8,
    native_socket: []const u8,
    candidate: []const u8,
    network: []const u8,
    fallback: []const u8,
    configured: ?Configured = null,
    observation: []const u8 = "No media sockets, relays, NAT, or reachability were tested.",
    relay: []const u8 = "unknown; external relay availability and operation were not checked",
};

pub fn assess(profile: workflow.Profile, port: u16) Assessment {
    if (profile == .existing) return .{
        .enabled = "unknown; existing configuration is not assessed here",
        .socket = "unknown; inspect the existing configuration",
        .native_socket = "unknown; inspect the existing configuration",
        .candidate = "unknown; inspect the existing configuration",
        .network = "unknown; no reachability or NAT checks",
        .fallback = "unknown; inspect configured services and client support",
    };
    if (profile != .media) return .{
        .enabled = "no",
        .socket = "disabled; configured media port is not bound",
        .native_socket = "disabled; no native media UDP socket",
        .candidate = "not advertised while media is disabled",
        .network = "unknown; no reachability or NAT checks",
        .fallback = "chat availability does not establish media readiness",
    };
    return .{
        .enabled = "yes",
        .socket = if (port == 0) "IPv4 wildcard UDP; OS chooses an ephemeral port at startup" else "IPv4 wildcard UDP; the configured media port is used at startup",
        .native_socket = "IPv4 wildcard UDP; separate ephemeral native media port at startup",
        .candidate = "default 127.0.0.1 is local-only; configure listen.media_host or STUN for remote candidates",
        .network = "NAT, firewall and reachability unknown; STUN discovery does not prove media reachability",
        .fallback = "UDP restrictions may require a compatible external relay; none is configured here. Browser WebSocket media may be an alternative for compatible clients, but its listener is not configured here. Neither path is verified.",
    };
}

/// Configured values describe intended startup, never an observed connection.
pub fn assessConfigured(config: Configured) Assessment {
    var result = assess(if (config.enabled) .media else .private, config.media_port);
    result.configured = config;
    if (!config.existing) return result;
    result.candidate = if (config.enabled) "Configured advertised host and STUN are listed; the effective public candidate is unknown until startup." else "Media is disabled; no media candidate is advertised.";
    result.socket = if (!config.enabled) "disabled; configured media port is not bound" else if (config.media_port == 0) "IPv4 wildcard UDP; OS chooses an ephemeral port at startup" else "IPv4 wildcard UDP; the configured media port is used at startup";
    result.native_socket = if (!config.enabled) "disabled; no native media UDP socket" else if (config.native_media_port == 0) "IPv4 wildcard UDP; separate ephemeral native media port at startup" else "IPv4 wildcard UDP; configured native media port is used at startup";
    result.fallback = if (config.websocket_media_relay and config.websocket_port != 0) "WebSocket media and its listener are configured; client compatibility and operation are unverified. UDP restrictions may require an external relay." else if (config.websocket_media_relay) "WebSocket media is configured without a WebSocket listener; operation is unverified. UDP restrictions may require an external relay." else "WebSocket media is not configured; UDP restrictions may require an external relay. No relay operation was verified.";
    return result;
}

test "setup media assessment distinguishes generated profiles and port zero" {
    const testing = @import("std").testing;
    try testing.expectEqualStrings("no", assess(.private, 5000).enabled);
    try testing.expectEqualStrings("no", assess(.community, 0).enabled);
    const ephemeral = assess(.media, 0);
    const fixed = assess(.media, 5000);
    try testing.expectEqualStrings("yes", ephemeral.enabled);
    try testing.expect(@import("std").mem.indexOf(u8, ephemeral.socket, "ephemeral") != null);
    try testing.expect(@import("std").mem.indexOf(u8, fixed.socket, "configured media port") != null);
    try testing.expect(@import("std").mem.indexOf(u8, ephemeral.candidate, "127.0.0.1") != null);
    try testing.expect(@import("std").mem.indexOf(u8, assess(.existing, 0).enabled, "unknown") != null);
}

test "existing media assessment retains configured values and unknown operation" {
    const config: Configured = .{ .enabled = true, .media_port = 7100, .native_media_port = 7101, .advertised_host = "203.0.113.4", .stun_host = "198.51.100.9", .stun_port = 3478, .websocket_port = 7443, .websocket_media_relay = true, .existing = true };
    const result = assessConfigured(config);
    try @import("std").testing.expectEqualDeep(config, result.configured.?);
    try @import("std").testing.expect(@import("std").mem.indexOf(u8, result.native_socket, "configured native media port") != null);
    try @import("std").testing.expect(@import("std").mem.indexOf(u8, result.fallback, "unverified") != null);
    try @import("std").testing.expect(@import("std").mem.indexOf(u8, result.relay, "unknown") != null);
    var off = config;
    off.enabled = false;
    const disabled = assessConfigured(off);
    try @import("std").testing.expectEqualStrings("disabled; configured media port is not bound", disabled.socket);
    try @import("std").testing.expectEqual(@as(u16, 7100), disabled.configured.?.media_port);
}
