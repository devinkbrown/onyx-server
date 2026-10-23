// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! SMTP relay address selection and connection trust policy.

const std = @import("std");
const builtin = @import("builtin");
const net = std.Io.net;
const smtp_client = @import("../../proto/smtp_client.zig");
const http_fetch = @import("../http_fetch.zig");
const Socket = @import("native_io.zig").Socket;
const connectAddr = @import("native_io.zig").connectAddr;

/// True if `addr` is a loopback address (IPv4 127.0.0.0/8 or IPv6 ::1). Used to
/// decide whether AUTH over an unverified TLS session is acceptable.
pub fn isLoopback(addr: net.IpAddress) bool {
    return switch (addr) {
        .ip4 => |x| x.bytes[0] == 127,
        .ip6 => |x| std.mem.eql(u8, &x.bytes, &(@as([15]u8, @splat(0)) ++ [_]u8{1})),
    };
}

// ---- raw socket helpers (mirror http_fetch) ---------------------------------

pub fn resolveRelayAddress(host: []const u8, port: u16, timeout_ms: u31) !net.IpAddress {
    return resolveRelayAddressWith(http_fetch.resolveHostA, http_fetch.resolveHostAAAA, host, port, timeout_ms);
}

pub fn resolveRelayAddressWith(comptime resolve_a: anytype, comptime resolve_aaaa: anytype, host: []const u8, port: u16, timeout_ms: u31) !net.IpAddress {
    return resolve_a(host, port, timeout_ms) catch |err| {
        if (comptime builtin.os.tag == .windows) {
            if (err == error.HostNotFound) return resolve_aaaa(host, port, timeout_ms);
        }
        return err;
    };
}

pub fn connectRelayAddress(host: []const u8, port: u16, first_addr: net.IpAddress, timeout_ms: u31, has_credentials: bool, verified: bool) !Socket {
    if (has_credentials and !isLoopback(first_addr) and !verified) return error.UnverifiedAuthRelay;
    return connectAddr(first_addr, timeout_ms) catch |err| {
        // Only an unsuccessful TCP dial can move to another address. No SMTP
        // greeting, TLS flight, or command has been exchanged at this point.
        if (comptime builtin.os.tag == .windows) {
            const literal = net.IpAddress.parse(host, port) catch null;
            if (first_addr == .ip4 and literal == null and
                (err == error.ConnectFailed or err == error.ConnectTimeout))
            {
                const next = try http_fetch.resolveHostAAAA(host, port, timeout_ms);
                if (has_credentials and !isLoopback(next) and !verified) return error.UnverifiedAuthRelay;
                return connectAddr(next, timeout_ms);
            }
        }
        return err;
    };
}
