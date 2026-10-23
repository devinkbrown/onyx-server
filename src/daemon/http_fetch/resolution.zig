// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unix dual-stack DNS query transport and reply validation.

const std = @import("std");
const builtin = @import("builtin");
const sys = if (builtin.os.tag == .windows) std.os.linux else std.posix.system;
const posix = std.posix;
const dns = @import("../../proto/dns.zig");
const resolv_conf = @import("../../proto/resolv_conf.zig");
const tls_client = @import("../../crypto/tls_client.zig");
const net = std.Io.net;
const Error = @import("contracts.zig").Error;
const HostFamilies = @import("contracts.zig").HostFamilies;
const resolveHostFamiliesWindows = @import("windows_resolver.zig").resolveHostFamiliesWindows;
const resolveHostWindows = @import("windows_resolver.zig").resolveHostWindows;
const udpSocketFamily = @import("native_io.zig").udpSocketFamily;
const setRecvTimeout = @import("native_io.zig").setRecvTimeout;
const closeFd = @import("native_io.zig").closeFd;
const writeAll = @import("native_io.zig").writeAll;
const readSmallFile = @import("native_io.zig").readSmallFile;
const osEntropy = @import("native_io.zig").osEntropy;

// ---- DNS (A-record over UDP, blocking) --------------------------------------

/// Resolve `host` to an address: IP literals parse directly; otherwise query
/// the system resolver with a bounded wait (Windows) or each configured DNS
/// server (Unix). Public so mesh auto-connect can dial hostname peers.
pub fn resolveHostA(host: []const u8, port: u16, timeout_ms: u31) Error!net.IpAddress {
    if (net.IpAddress.parse(host, port)) |addr| return addr else |_| {}
    if (comptime builtin.os.tag == .windows) {
        return resolveHostWindows(host, port, timeout_ms, false);
    }

    var conf_buf: [4096]u8 = undefined;
    const text = readSmallFile("/etc/resolv.conf", &conf_buf) catch return error.NoNameservers;
    const conf = resolv_conf.parse(text);
    const servers = conf.nameserverSlice();
    if (servers.len == 0) return error.NoNameservers;

    var id_seed: [2]u8 = undefined;
    osEntropy(&id_seed);
    const query_id = std.mem.readInt(u16, &id_seed, .big);
    var query_buf: [dns.max_message_len]u8 = undefined;
    const query = dns.encodeQuery(&query_buf, query_id, host, .a) catch return error.HostNotFound;

    for (servers) |srv| {
        if (queryOneServer(srv, query, timeout_ms)) |ipv4| {
            return .{ .ip4 = .{ .bytes = ipv4, .port = port } };
        } else |_| {}
    }
    return error.HostNotFound;
}

fn queryOneServer(ns: dns.Address, query: []const u8, timeout_ms: u31) Error![4]u8 {
    const msg = try queryServerPort(ns, 53, query, timeout_ms);
    for (msg.answerSlice()) |rr| switch (rr.data) {
        .a => |ipv4| return ipv4,
        else => {},
    };
    return error.HostNotFound;
}

pub fn queryServerPort(ns: dns.Address, port: u16, query: []const u8, timeout_ms: u31) Error!dns.Message(1, dns.max_cache_addrs) {
    const fd = try udpSocketFamily(if (ns == .ipv4) posix.AF.INET else posix.AF.INET6, false);
    defer closeFd(fd);
    try setRecvTimeout(fd, timeout_ms);
    try connectUdp(fd, ns, port);
    try writeAll(fd, query);
    var resp: [dns.max_message_len]u8 = undefined;
    const rc = sys.read(fd, &resp, resp.len);
    if (posix.errno(rc) != .SUCCESS) return error.HostNotFound;
    return acceptedResponse(query, resp[0..@intCast(rc)]) orelse error.HostNotFound;
}

fn acceptedResponse(query: []const u8, raw: []const u8) ?dns.Message(1, dns.max_cache_addrs) {
    const question = dns.parseMessage(1, 0, query) catch return null;
    if (question.question_count != 1) return null;
    const msg = dns.parseMessage(1, dns.max_cache_addrs, raw) catch return null;
    const q = question.questions[0];
    if (msg.header.id != question.header.id or msg.header.rcode() != 0 or
        msg.header.flags & 0x7a00 != 0 or
        !dns.responseMatchesQuestion(1, dns.max_cache_addrs, &msg, q.name.slice(), q.qtype)) return null;
    if (!dns.responseAnswersFollowCnames(dns.max_cache_addrs, raw, q.name.slice(), q.qtype)) return null;
    return msg;
}

/// Like `resolveHostA` but requests IPv6 addresses. The Unix path queries AAAA
/// records over configured IPv4 nameservers; Windows uses its system resolver.
pub fn resolveHostAAAA(host: []const u8, port: u16, timeout_ms: u31) Error!net.IpAddress {
    if (net.IpAddress.parse(host, port)) |addr| switch (addr) {
        .ip6 => return addr,
        .ip4 => {}, // an IPv4 literal is not an AAAA answer — fall through to DNS
    } else |_| {}
    if (comptime builtin.os.tag == .windows) {
        return resolveHostWindows(host, port, timeout_ms, true);
    }

    var conf_buf: [4096]u8 = undefined;
    const text = readSmallFile("/etc/resolv.conf", &conf_buf) catch return error.NoNameservers;
    const conf = resolv_conf.parse(text);
    const servers = conf.nameserverSlice();
    if (servers.len == 0) return error.NoNameservers;

    var id_seed: [2]u8 = undefined;
    osEntropy(&id_seed);
    const query_id = std.mem.readInt(u16, &id_seed, .big);
    var query_buf: [dns.max_message_len]u8 = undefined;
    const query = dns.encodeQuery(&query_buf, query_id, host, .aaaa) catch return error.HostNotFound;

    for (servers) |srv| {
        if (queryOneServer6(srv, query, timeout_ms)) |ipv6| {
            return .{ .ip6 = .{ .bytes = ipv6, .port = port } };
        } else |_| {}
    }
    return error.HostNotFound;
}

pub fn resolveHostFamilies(host: []const u8, timeout_ms: u31) Error!HostFamilies {
    if (host.len == 0 or std.mem.indexOfScalar(u8, host, 0) != null) return error.HostNotFound;
    if (net.IpAddress.parse(host, 0)) |addr| {
        return switch (addr) {
            .ip4 => |a4| .{ .v4 = a4.bytes },
            .ip6 => |a6| .{ .v6 = a6.bytes },
        };
    } else |_| {}
    if (comptime builtin.os.tag == .windows) return resolveHostFamiliesWindows(host, timeout_ms);

    var conf_buf: [4096]u8 = undefined;
    const text = readSmallFile("/etc/resolv.conf", &conf_buf) catch return error.NoNameservers;
    const conf = resolv_conf.parse(text);
    const servers = conf.nameserverSlice();
    if (servers.len == 0) return error.NoNameservers;

    var found = HostFamilies{};
    for (servers) |srv| {
        if (found.v4 != null and found.v6 != null) break;
        const part = queryFamilies(srv, 53, host, timeout_ms, found.v4 == null, found.v6 == null);
        if (found.v4 == null) found.v4 = part.v4;
        if (found.v6 == null) found.v6 = part.v6;
    }
    if (found.v4 == null and found.v6 == null) return error.HostNotFound;
    return found;
}

pub fn queryFamilies(
    ns: dns.Address,
    port: u16,
    host: []const u8,
    timeout_ms: u31,
    want_v4: bool,
    want_v6: bool,
) HostFamilies {
    var found = HostFamilies{};
    if (!want_v4 and !want_v6) return found;
    var seed: [4]u8 = undefined;
    osEntropy(&seed);
    const id_a = std.mem.readInt(u16, seed[0..2], .big);
    var id_aaaa = std.mem.readInt(u16, seed[2..4], .big);
    if (id_aaaa == id_a) id_aaaa +%= 1;

    var query_a_buf: [dns.max_message_len]u8 = undefined;
    var query_aaaa_buf: [dns.max_message_len]u8 = undefined;
    const query_a: ?[]const u8 = if (!want_v4) null else dns.encodeQuery(&query_a_buf, id_a, host, .a) catch null;
    const query_aaaa: ?[]const u8 = if (!want_v6) null else dns.encodeQuery(&query_aaaa_buf, id_aaaa, host, .aaaa) catch null;
    if (query_a == null and query_aaaa == null) return found;

    const family: u32 = if (ns == .ipv4) posix.AF.INET else posix.AF.INET6;
    var a_fd: ?sys.fd_t = null;
    var aaaa_fd: ?sys.fd_t = null;
    defer if (a_fd) |fd| closeFd(fd);
    defer if (aaaa_fd) |fd| closeFd(fd);
    if (query_a) |query| {
        if (udpSocketFamily(family, true)) |fd| {
            if (connectUdp(fd, ns, port)) {
                if (writeAll(fd, query)) |_| a_fd = fd else |_| closeFd(fd);
            } else |_| closeFd(fd);
        } else |_| {}
    }
    if (query_aaaa) |query| {
        if (udpSocketFamily(family, true)) |fd| {
            if (connectUdp(fd, ns, port)) {
                if (writeAll(fd, query)) |_| aaaa_fd = fd else |_| closeFd(fd);
            } else |_| closeFd(fd);
        } else |_| {}
    }
    if (a_fd == null and aaaa_fd == null) return found;

    const started = monoMs();
    while (monoMs() - started <= timeout_ms) {
        var polls: [2]sys.pollfd = undefined;
        var n: usize = 0;
        var a_slot: ?usize = null;
        var aaaa_slot: ?usize = null;
        if (a_fd) |fd| {
            polls[n] = .{ .fd = fd, .events = posix.POLL.IN, .revents = 0 };
            a_slot = n;
            n += 1;
        }
        if (aaaa_fd) |fd| {
            polls[n] = .{ .fd = fd, .events = posix.POLL.IN, .revents = 0 };
            aaaa_slot = n;
            n += 1;
        }
        if (n == 0) break;
        const elapsed = monoMs() - started;
        const remain: i32 = if (elapsed >= timeout_ms) 0 else @intCast(timeout_ms - @as(u31, @intCast(elapsed)));
        const ready = pollCount(polls[0..n], remain) orelse break;
        if (ready == 0) break;
        if (a_slot) |slot| {
            if (polls[slot].revents != 0) {
                if (a_fd) |fd| {
                    if (readFamily(fd, query_a.?)) |addr| {
                        found.v4 = addr.v4;
                    }
                }
                if (a_fd) |fd| closeFd(fd);
                a_fd = null;
            }
        }
        if (aaaa_slot) |slot| {
            if (polls[slot].revents != 0) {
                if (aaaa_fd) |fd| {
                    if (readFamily(fd, query_aaaa.?)) |addr| {
                        found.v6 = addr.v6;
                    }
                }
                if (aaaa_fd) |fd| closeFd(fd);
                aaaa_fd = null;
            }
        }
    }
    return found;
}

const FamilyAnswer = struct { v4: ?[4]u8 = null, v6: ?[16]u8 = null };

fn readFamily(fd: sys.fd_t, query: []const u8) ?FamilyAnswer {
    var resp: [dns.max_message_len]u8 = undefined;
    const rc = sys.read(fd, &resp, resp.len);
    if (posix.errno(rc) != .SUCCESS or rc == 0) return null;
    const msg = acceptedResponse(query, resp[0..@intCast(rc)]) orelse return null;
    var out = FamilyAnswer{};
    for (msg.answerSlice()) |rr| switch (rr.data) {
        .a => |ipv4| {
            if (out.v4 == null) out.v4 = ipv4;
        },
        .aaaa => |ipv6| {
            if (out.v6 == null) out.v6 = ipv6;
        },
        else => {},
    };
    if (out.v4 == null and out.v6 == null) return null;
    return out;
}

fn pollCount(polls: []sys.pollfd, timeout_ms: i32) ?usize {
    while (true) {
        const rc = sys.poll(polls.ptr, @intCast(polls.len), timeout_ms);
        switch (posix.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            else => return null,
        }
    }
}

fn monoMs() i64 {
    var ts: sys.timespec = undefined;
    if (posix.errno(sys.clock_gettime(posix.CLOCK.MONOTONIC, &ts)) != .SUCCESS) return 0;
    const sec: i64 = @intCast(ts.sec);
    const ms: i64 = @intCast(@divTrunc(ts.nsec, 1_000_000));
    return sec * 1000 + ms;
}

fn connectUdp(fd: sys.fd_t, ns: dns.Address, port: u16) Error!void {
    const rc = switch (ns) {
        .ipv4 => |bytes| blk: {
            var sa = sys.sockaddr.in{ .port = std.mem.nativeToBig(u16, port), .addr = @bitCast(bytes) };
            break :blk sys.connect(fd, @ptrCast(&sa), @sizeOf(sys.sockaddr.in));
        },
        .ipv6 => |bytes| blk: {
            var sa = sys.sockaddr.in6{
                .port = std.mem.nativeToBig(u16, port),
                .flowinfo = 0,
                .addr = bytes,
                .scope_id = 0,
            };
            break :blk sys.connect(fd, @ptrCast(&sa), @sizeOf(sys.sockaddr.in6));
        },
    };
    if (posix.errno(rc) != .SUCCESS) return error.ConnectFailed;
}

fn queryOneServer6(ns: dns.Address, query: []const u8, timeout_ms: u31) Error![16]u8 {
    const msg = try queryServerPort(ns, 53, query, timeout_ms);
    for (msg.answerSlice()) |rr| switch (rr.data) {
        .aaaa => |ipv6| return ipv6,
        else => {},
    };
    return error.HostNotFound;
}
