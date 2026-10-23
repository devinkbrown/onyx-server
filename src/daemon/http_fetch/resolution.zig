// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! HTTP address policy over the shared DNS engine; dual families share one deadline.

const std = @import("std");
const builtin = @import("builtin");
const address_lookup = @import("../dns_address_lookup.zig");
const Deadline = @import("../../proto/dns/deadline.zig").Deadline;
const net = std.Io.net;
const Error = @import("contracts.zig").Error;
const HostFamilies = @import("contracts.zig").HostFamilies;
const resolveHostFamiliesWindows = @import("windows_resolver.zig").resolveHostFamiliesWindows;
const resolveHostWindows = @import("windows_resolver.zig").resolveHostWindows;
const readSmallFile = @import("native_io.zig").readSmallFile;

// ---- Single-family resolution (blocking, bounded) -------------------------

/// Resolve `host` to an address: IP literals parse directly; otherwise query
/// the system resolver with a bounded wait (Windows) or each configured DNS
/// server (Unix). The POSIX lookup shares timeout_ms across every server, alias,
/// and TCP fallback, clamped to 1..5000 ms. Public for mesh hostname dialing.
pub fn resolveHostA(host: []const u8, port: u16, timeout_ms: u31) Error!net.IpAddress {
    if (net.IpAddress.parse(host, port)) |addr| return addr else |_| {}
    if (comptime builtin.os.tag == .windows) {
        return resolveHostWindows(host, port, timeout_ms, false);
    }

    return resolveSingleFamily(host, port, timeout_ms, .a);
}

/// Like `resolveHostA` but requests IPv6 addresses over configured nameservers
/// of either family. Windows keeps its native system-resolver policy.
pub fn resolveHostAAAA(host: []const u8, port: u16, timeout_ms: u31) Error!net.IpAddress {
    if (net.IpAddress.parse(host, port)) |addr| switch (addr) {
        .ip6 => return addr,
        .ip4 => {}, // an IPv4 literal is not an AAAA answer — fall through to DNS
    } else |_| {}
    if (comptime builtin.os.tag == .windows) {
        return resolveHostWindows(host, port, timeout_ms, true);
    }

    return resolveSingleFamily(host, port, timeout_ms, .aaaa);
}

/// Only single-family lookups use this policy. Config-file ownership and the
/// legacy HTTP error surface stay here; packet validation and socket deadlines
/// belong to the shared address lookup. No public resolver fallback is allowed.
fn resolveSingleFamily(host: []const u8, port: u16, timeout_ms: u31, family: address_lookup.Family) Error!net.IpAddress {
    if (comptime builtin.is_test) {
        if (Testing.config) |config| {
            const text = config.text orelse return error.NoNameservers;
            return resolveConfiguredFamily(text, host, port, config.dns_port, family, timeout_ms);
        }
    }
    var conf_buf: [4096]u8 = undefined;
    const text = readSmallFile("/etc/resolv.conf", &conf_buf) catch return error.NoNameservers;
    return resolveConfiguredFamily(text, host, port, 53, family, timeout_ms);
}

fn resolveConfiguredFamily(text: []const u8, host: []const u8, port: u16, dns_port: u16, family: address_lookup.Family, timeout_ms: u31) Error!net.IpAddress {
    return address_lookup.resolve(text, host, port, dns_port, family, timeout_ms) catch |err| switch (err) {
        error.NoNameservers => error.NoNameservers,
        else => error.HostNotFound,
    };
}

/// Per-test-thread config-file substitute. Tests call the actual public resolver
/// entry points; no override or mutable test state exists in production builds.
pub const Testing = if (builtin.is_test) struct {
    pub const Config = struct { text: ?[]const u8, dns_port: u16 = 53 };
    pub threadlocal var config: ?Config = null;
    pub const WorkerStart = enum { normal, fail };
    pub threadlocal var worker_start: WorkerStart = .normal;
} else struct {};

pub fn resolveHostFamilies(host: []const u8, timeout_ms: u31) Error!HostFamilies {
    if (host.len == 0 or std.mem.indexOfScalar(u8, host, 0) != null) return error.HostNotFound;
    if (net.IpAddress.parse(host, 0)) |addr| {
        return switch (addr) {
            .ip4 => |a4| .{ .v4 = a4.bytes },
            .ip6 => |a6| .{ .v6 = a6.bytes },
        };
    } else |_| {}
    if (comptime builtin.os.tag == .windows) return resolveHostFamiliesWindows(host, timeout_ms);

    if (comptime builtin.is_test) {
        if (Testing.config) |config| {
            const text = config.text orelse return error.NoNameservers;
            return resolveConfiguredFamilies(text, host, config.dns_port, timeout_ms);
        }
    }
    var conf_buf: [4096]u8 = undefined;
    const text = readSmallFile("/etc/resolv.conf", &conf_buf) catch return error.NoNameservers;
    return resolveConfiguredFamilies(text, host, 53, timeout_ms);
}

/// One helper owns the AAAA result. Its immutable inputs borrow the caller's
/// config/name only until the mandatory join; the caller performs A in parallel.
const Ipv6Lookup = struct {
    text: []const u8,
    host: []const u8,
    dns_port: u16,
    deadline: Deadline,
    result: address_lookup.Error!net.IpAddress = error.HostNotFound,

    fn start(self: *Ipv6Lookup) ?std.Thread {
        if (comptime builtin.is_test) {
            if (Testing.worker_start == .fail) return null;
        }
        return std.Thread.spawn(.{}, run, .{self}) catch null;
    }

    fn run(self: *Ipv6Lookup) void {
        self.result = address_lookup.resolveUntil(self.text, self.host, 0, self.dns_port, .aaaa, self.deadline);
    }
};

fn resolveConfiguredFamilies(text: []const u8, host: []const u8, dns_port: u16, timeout_ms: u31) Error!HostFamilies {
    const deadline = Deadline.after(timeout_ms);
    var ipv6 = Ipv6Lookup{ .text = text, .host = host, .dns_port = dns_port, .deadline = deadline };
    const ipv4 = lookup: {
        const helper = ipv6.start();
        // Join even when A fails. This fences all result reads and borrowed
        // input lifetimes; helper start failure deliberately leaves A-only work.
        defer if (helper) |thread| thread.join();
        break :lookup address_lookup.resolveUntil(text, host, 0, dns_port, .a, deadline);
    };
    var found = HostFamilies{};
    if (ipv4) |address| {
        found.v4 = address.ip4.bytes;
    } else |err| {
        if (err == error.NoNameservers) return error.NoNameservers;
    }
    if (ipv6.result) |address| {
        found.v6 = address.ip6.bytes;
    } else |_| {}
    if (found.v4 == null and found.v6 == null) return error.HostNotFound;
    return found;
}
