// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Resolver policy and bounded host nameserver discovery.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const win = @import("windows_abi.zig");
const wire = @import("wire.zig");

pub const max_nameservers: usize = 4;

/// Resolver settings: UDP/TCP nameservers plus timeout/retry policy.
/// Field layout is also consumed by the daemon resolver configuration digest.
pub const ResolverConfig = struct {
    nameservers: [max_nameservers]wire.Address = undefined,
    /// IPv6 scoped nameservers use a native interface index on every platform.
    nameserver_scope_ids: [max_nameservers]u32 = @splat(0),
    nameserver_count: usize = 0,
    port: u16 = 53,
    timeout_ms: u32 = 2000,
    attempts: u8 = 2,

    pub fn addNameserver(self: *ResolverConfig, addr: wire.Address) void {
        if (self.nameserver_count >= max_nameservers) return;
        self.nameservers[self.nameserver_count] = addr;
        self.nameserver_scope_ids[self.nameserver_count] = 0;
        self.nameserver_count += 1;
    }

    fn addSystemNameserver(self: *ResolverConfig, addr: wire.Address, scope_id: u32) void {
        for (self.nsSlice(), 0..) |existing, index| {
            if (wire.addressEql(existing, addr) and self.nameserver_scope_ids[index] == scope_id) return;
        }
        if (self.nameserver_count >= max_nameservers) return;
        self.nameservers[self.nameserver_count] = addr;
        self.nameserver_scope_ids[self.nameserver_count] = scope_id;
        self.nameserver_count += 1;
    }

    pub fn nsSlice(self: *const ResolverConfig) []const wire.Address {
        return self.nameservers[0..self.nameserver_count];
    }
};

/// Parse an IPv4 or IPv6 literal into an Address (null on malformed input).
pub fn parseIpLiteral(text: []const u8) ?wire.Address {
    const net = std.Io.net;
    if (net.IpAddress.parseIp4(text, 0)) |addr| {
        return wire.Address{ .ipv4 = addr.ip4.bytes };
    } else |_| {}
    if (net.IpAddress.parseIp6(text, 0)) |addr| {
        return wire.Address{ .ipv6 = addr.ip6.bytes };
    } else |_| {}
    return null;
}

/// Parse resolv.conf nameservers and bounded timeout/attempt options. Interface
/// scopes may be numeric or native POSIX interface names. Invalid scopes are
/// rejected rather than silently sending link-local queries on interface zero.
/// Search lists and suffix expansion are intentionally outside this stub API.
pub fn parseResolvConf(text: []const u8, cfg: *ResolverConfig) usize {
    var lines = std.mem.tokenizeAny(u8, text, "\r\n");
    while (lines.next()) |raw| {
        const comment = std.mem.indexOfAny(u8, raw, "#;") orelse raw.len;
        var fields = std.mem.tokenizeAny(u8, raw[0..comment], " \t");
        const keyword = fields.next() orelse continue;
        if (std.mem.eql(u8, keyword, "options")) {
            while (fields.next()) |option| {
                if (std.mem.startsWith(u8, option, "timeout:")) {
                    const seconds = std.fmt.parseInt(u32, option[8..], 10) catch continue;
                    cfg.timeout_ms = @as(u32, @min(@max(seconds, 1), 5)) * 1000;
                } else if (std.mem.startsWith(u8, option, "attempts:")) {
                    const attempts = std.fmt.parseInt(u32, option[9..], 10) catch continue;
                    cfg.attempts = @intCast(@min(@max(attempts, 1), 3));
                }
            }
            continue;
        }
        if (!std.mem.eql(u8, keyword, "nameserver")) continue;
        const field = fields.next() orelse continue;
        const split = std.mem.indexOfScalar(u8, field, '%');
        const address = parseIpLiteral(field[0..(split orelse field.len)]) orelse continue;
        var scope: u32 = 0;
        if (split) |index| {
            if (address != .ipv6) continue;
            scope = scopeIndex(field[index + 1 ..]) orelse continue;
        }
        if (address == .ipv6 and address.ipv6[0] == 0xfe and address.ipv6[1] & 0xc0 == 0x80 and scope == 0) continue;
        cfg.addSystemNameserver(address, scope);
    }
    return cfg.nameserver_count;
}

fn scopeIndex(zone: []const u8) ?u32 {
    if (zone.len == 0) return null;
    if (std.fmt.parseInt(u32, zone, 10)) |index| return if (index == 0) null else index else |_| {}
    if (zone.len >= 16) return null;
    // Interface names cannot contain a DNS delimiter or path component.
    for (zone) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '_' and byte != '-' and byte != '.') return null;
    if (comptime builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const raw = linux.socket(posix.AF.INET6, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, posix.IPPROTO.UDP);
        if (posix.errno(raw) != .SUCCESS) return null;
        const fd: posix.fd_t = @intCast(raw);
        defer _ = linux.close(fd);
        var request: linux.ifreq = std.mem.zeroes(linux.ifreq);
        @memcpy(request.ifrn.name[0..zone.len], zone);
        if (posix.errno(linux.ioctl(fd, linux.SIOCGIFINDEX, @intFromPtr(&request))) != .SUCCESS or request.ifru.ivalue <= 0) return null;
        return @intCast(request.ifru.ivalue);
    } else if (comptime builtin.os.tag == .openbsd) {
        var name: [16:0]u8 = @splat(0);
        @memcpy(name[0..zone.len], zone);
        const index = std.c.if_nametoindex(&name);
        return if (index > 0) @intCast(index) else null;
    }
    return null;
}

/// Build a resolver config from the host's configured DNS servers. Windows
/// fails closed when adapter discovery is unavailable; POSIX retains its
/// historical resolv.conf and public-resolver fallback.
pub fn systemResolverConfig() ResolverConfig {
    var cfg = ResolverConfig{};
    if (comptime builtin.os.tag == .windows) {
        windowsSystemNameservers(&cfg);
        return cfg;
    }
    var buf: [8192]u8 = undefined;
    if (readFileZ("/etc/resolv.conf", &buf)) |contents| {
        // A full buffer may end inside a directive. Parse complete lines only.
        const end = if (contents.len == buf.len) std.mem.lastIndexOfScalar(u8, contents, '\n') orelse 0 else contents.len;
        _ = parseResolvConf(contents[0..end], &cfg);
    }
    if (cfg.nameserver_count == 0) {
        cfg.addNameserver(.{ .ipv4 = .{ 1, 1, 1, 1 } });
        cfg.addNameserver(.{ .ipv4 = .{ 8, 8, 8, 8 } });
    }
    return cfg;
}

fn windowsSystemNameservers(cfg: *ResolverConfig) void {
    if (comptime builtin.os.tag != .windows) return;
    // Microsoft recommends a 15 KiB starting buffer. Retry if the adapter
    // list changes between sizing and filling instead of dropping DNS entirely.
    var bytes_needed: u32 = 15 * 1024;
    for (0..4) |_| {
        if (bytes_needed > win.max_adapter_bytes) return;
        const bytes = std.heap.page_allocator.alignedAlloc(u8, .@"8", @intCast(bytes_needed)) catch return;
        defer std.heap.page_allocator.free(bytes);
        var actual_size = bytes_needed;
        const first: *win.AdapterAddresses = @ptrCast(bytes.ptr);
        const status = win.GetAdaptersAddresses(win.af_unspec, 0, null, first, &actual_size);
        if (status == win.error_buffer_overflow) {
            if (actual_size <= bytes_needed) return;
            bytes_needed = actual_size;
            continue;
        }
        if (status != 0 or actual_size < @sizeOf(win.AdapterAddresses) or
            @as(usize, actual_size) > bytes.len) return;
        if (windowsCollectNameservers(cfg, first, bytes[0..@intCast(actual_size)]))
            std.log.warn("Windows exposes more DNS servers than the resolver's {} slots; selected servers across operational adapters by priority", .{max_nameservers});
        return;
    }
}

const WindowsDnsCandidate = struct {
    address: wire.Address,
    scope_id: u32,
    // Prefer the first usable server on each adapter before its backups so
    // four entries from one adapter cannot hide another adapter's resolver.
    backup: bool,
    // GetAdaptersAddresses orders adapters by route metric on Windows 10+.
    // Its native order also reflects the user-set binding order on older OSes.
    adapter_order: usize,
    sequence: usize,

    fn before(a: @This(), b: @This()) bool {
        if (a.backup != b.backup) return !a.backup;
        if (a.adapter_order != b.adapter_order) return a.adapter_order < b.adapter_order;
        return a.sequence < b.sequence;
    }

    fn queryBefore(a: @This(), b: @This()) bool {
        if (a.adapter_order != b.adapter_order) return a.adapter_order < b.adapter_order;
        return a.sequence < b.sequence;
    }
};

const WindowsDnsSelection = struct {
    candidates: [max_nameservers]WindowsDnsCandidate = undefined,
    count: usize = 0,
    overflowed: bool = false,

    fn consider(self: *@This(), candidate: WindowsDnsCandidate) void {
        var selected = candidate;
        for (self.candidates[0..self.count], 0..) |existing, index| {
            if (!wire.addressEql(existing.address, candidate.address) or existing.scope_id != candidate.scope_id) continue;
            // Keep the first query position, but count the endpoint as an
            // adapter primary if any adapter lists it first. Otherwise a
            // later primary could be evicted merely because it also appears
            // as an earlier adapter's backup.
            if (!existing.backup or candidate.backup) return;
            selected = existing;
            selected.backup = false;
            var shift = index;
            while (shift + 1 < self.count) : (shift += 1) self.candidates[shift] = self.candidates[shift + 1];
            self.count -= 1;
            break;
        }

        var insert_at: usize = 0;
        while (insert_at < self.count and !selected.before(self.candidates[insert_at])) : (insert_at += 1) {}
        if (self.count == max_nameservers and insert_at == max_nameservers) {
            self.overflowed = true;
            return;
        }
        if (self.count == max_nameservers) {
            self.overflowed = true;
        } else {
            self.count += 1;
        }
        var shift = self.count - 1;
        while (shift > insert_at) : (shift -= 1) self.candidates[shift] = self.candidates[shift - 1];
        self.candidates[insert_at] = selected;
    }

    fn write(self: *const @This(), cfg: *ResolverConfig) void {
        // Selection favors adapter diversity; query order must still honor
        // Windows' adapter priority and each adapter's DNS server order. A
        // lower-priority adapter's NXDOMAIN must not preempt a preferred
        // adapter's backup server in a split-DNS setup.
        var ordered: [max_nameservers]WindowsDnsCandidate = undefined;
        @memcpy(ordered[0..self.count], self.candidates[0..self.count]);
        if (self.count > 1) {
            for (1..self.count) |index| {
                const candidate = ordered[index];
                var insert_at = index;
                while (insert_at > 0 and candidate.queryBefore(ordered[insert_at - 1])) : (insert_at -= 1)
                    ordered[insert_at] = ordered[insert_at - 1];
                ordered[insert_at] = candidate;
            }
        }
        for (ordered[0..self.count]) |candidate|
            cfg.addSystemNameserver(candidate.address, candidate.scope_id);
    }
};

fn windowsCollectNameservers(cfg: *ResolverConfig, first: *win.AdapterAddresses, filled: []const u8) bool {
    var selection = WindowsDnsSelection{};
    var adapter: ?*win.AdapterAddresses = first;
    var adapter_count: usize = 0;
    var sequence: usize = 0;
    while (adapter) |item| : (adapter_count += 1) {
        if (adapter_count >= filled.len / @sizeOf(win.AdapterAddresses) or
            !windowsPointerInBuffer(win.AdapterAddresses, item, filled) or
            item.length < @sizeOf(win.AdapterAddresses)) break;
        adapter = item.next;
        if (item.oper_status != win.if_oper_status_up) continue;

        var server = item.first_dns;
        var server_count: usize = 0;
        var usable_count: usize = 0;
        while (server) |dns_server| : (server_count += 1) {
            if (server_count >= filled.len / @sizeOf(win.DnsServerAddress) or
                !windowsPointerInBuffer(win.DnsServerAddress, dns_server, filled) or
                dns_server.length < @sizeOf(win.DnsServerAddress)) break;
            server = dns_server.next;
            const raw = dns_server.address.sockaddr orelse continue;
            if (dns_server.address.length < @sizeOf(u16) or
                !windowsPointerInBuffer(u16, raw, filled)) continue;
            const family: *const u16 = @ptrCast(@alignCast(raw));
            const address: wire.Address = if (family.* == win.af_inet and
                dns_server.address.length >= @sizeOf(win.SockAddr4) and
                windowsPointerInBuffer(win.SockAddr4, raw, filled))
            blk: {
                const addr: *const win.SockAddr4 = @ptrCast(@alignCast(raw));
                break :blk .{ .ipv4 = addr.addr };
            } else if (family.* == win.af_inet6 and
                dns_server.address.length >= @sizeOf(win.SockAddr6) and
                windowsPointerInBuffer(win.SockAddr6, raw, filled))
            blk: {
                const addr: *const win.SockAddr6 = @ptrCast(@alignCast(raw));
                break :blk .{ .ipv6 = addr.addr };
            } else continue;
            const raw_scope: u32 = if (address == .ipv6) (@as(*const win.SockAddr6, @ptrCast(@alignCast(raw)))).scope_id else 0;
            const scope_id = windowsUsableDnsScope(address, raw_scope, item.ipv6_if_index) orelse continue;
            selection.consider(.{
                .address = address,
                .scope_id = scope_id,
                .backup = usable_count != 0,
                .adapter_order = adapter_count,
                .sequence = sequence,
            });
            usable_count += 1;
            sequence += 1;
        }
    }
    selection.write(cfg);
    return selection.overflowed;
}

fn windowsUsableDnsScope(address: wire.Address, raw_scope: u32, adapter_scope: u32) ?u32 {
    switch (address) {
        .ipv4 => |ip| {
            // 0/8 is not a remote endpoint; 224/4 and above are multicast or
            // reserved. Loopback remains valid for a local resolver service.
            if (ip[0] == 0 or ip[0] >= 224) return null;
            return 0;
        },
        .ipv6 => |ip| {
            if (!windowsAddressNonzero(&ip) or ip[0] == 0xff) return null;
            // Windows can expose these deprecated site-local defaults when no
            // real IPv6 DNS server was configured.
            const placeholder_prefix = [_]u8{ 0xfe, 0xc0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0 };
            if (std.mem.eql(u8, ip[0..15], placeholder_prefix[0..15]) and ip[15] >= 1 and ip[15] <= 3) return null;
            if (ip[0] == 0xfe and (ip[1] & 0xc0) == 0x80) {
                const scope = if (raw_scope != 0) raw_scope else adapter_scope;
                return if (scope != 0) scope else null;
            }
            return raw_scope;
        },
    }
}

fn windowsPointerInBuffer(comptime T: type, ptr: *const anyopaque, bytes: []const u8) bool {
    const start = @intFromPtr(bytes.ptr);
    const current = @intFromPtr(ptr);
    return bytes.len >= @sizeOf(T) and current >= start and current - start <= bytes.len - @sizeOf(T) and
        current % @alignOf(T) == 0;
}

fn windowsAddressNonzero(bytes: []const u8) bool {
    for (bytes) |byte| if (byte != 0) return true;
    return false;
}

/// Read a small file into `buf` (no allocator / Io dependency), or null on error.
/// Linux `open` is syscall 2. That number is `fork` on FreeBSD, so this uses
/// the target POSIX open rather than `std.os.linux`.
fn readFileZ(path: [*:0]const u8, buf: []u8) ?[]u8 {
    if (comptime builtin.os.tag == .windows) return null;
    const fd = posix.openatZ(posix.AT.FDCWD, path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0) catch return null;
    defer _ = posix.system.close(fd);
    var total: usize = 0;
    while (total < buf.len) {
        const got = posix.read(fd, buf[total..]) catch return null;
        if (got == 0) break;
        total += got;
    }
    return buf[0..total];
}

test "parses IPv4 and IPv6 nameserver literals" {
    try std.testing.expectEqual(wire.Address{ .ipv4 = .{ 1, 1, 1, 1 } }, parseIpLiteral("1.1.1.1").?);
    const v6 = parseIpLiteral("2001:4860:4860::8888").?;
    try std.testing.expect(v6 == .ipv6);
    try std.testing.expectEqual(@as(u8, 0x20), v6.ipv6[0]);
    try std.testing.expect(parseIpLiteral("not-an-ip") == null);
    try std.testing.expect(parseIpLiteral("999.1.1.1") == null);
}

test "systemResolverConfig bounds host DNS entries and retains the POSIX fallback" {
    const cfg = systemResolverConfig();
    if (builtin.os.tag != .windows) try std.testing.expect(cfg.nameserver_count > 0);
    try std.testing.expect(cfg.nameserver_count <= max_nameservers);
}

test "Windows DNS candidates reject placeholders and repair link-local scope" {
    try std.testing.expect(windowsUsableDnsScope(.{ .ipv4 = .{ 0, 1, 2, 3 } }, 0, 0) == null);
    try std.testing.expect(windowsUsableDnsScope(.{ .ipv4 = .{ 224, 0, 0, 1 } }, 0, 0) == null);
    try std.testing.expectEqual(@as(?u32, 0), windowsUsableDnsScope(.{ .ipv4 = .{ 127, 0, 0, 1 } }, 0, 0));
    try std.testing.expect(windowsUsableDnsScope(parseIpLiteral("::").?, 0, 0) == null);
    try std.testing.expect(windowsUsableDnsScope(parseIpLiteral("ff02::1").?, 0, 0) == null);
    for ([_][]const u8{ "fec0:0:0:ffff::1", "fec0:0:0:ffff::2", "fec0:0:0:ffff::3" }) |placeholder|
        try std.testing.expect(windowsUsableDnsScope(parseIpLiteral(placeholder).?, 0, 0) == null);
    const link_local = parseIpLiteral("fe80::53").?;
    try std.testing.expect(windowsUsableDnsScope(link_local, 0, 0) == null);
    try std.testing.expectEqual(@as(?u32, 9), windowsUsableDnsScope(link_local, 0, 9));
    try std.testing.expectEqual(@as(?u32, 11), windowsUsableDnsScope(link_local, 11, 9));
    try std.testing.expectEqual(@as(?u32, 0), windowsUsableDnsScope(parseIpLiteral("::1").?, 0, 0));
}

test "Windows DNS discovery scans beyond four entries and honors live adapter order" {
    const Fixture = struct {
        adapters: [3]win.AdapterAddresses,
        servers: [6]win.DnsServerAddress,
        addresses: [6]win.SockAddr4,
    };
    var fixture = std.mem.zeroes(Fixture);
    for (&fixture.adapters) |*adapter| adapter.length = @sizeOf(win.AdapterAddresses);
    for (&fixture.servers, 0..) |*server, index| {
        server.length = @sizeOf(win.DnsServerAddress);
        fixture.addresses[index] = .{ .family = win.af_inet, .port = 0, .addr = .{ 10, 0, 0, @intCast(index + 1) } };
        server.address = .{ .sockaddr = @ptrCast(&fixture.addresses[index]), .length = @sizeOf(win.SockAddr4) };
    }
    fixture.adapters[0].next = &fixture.adapters[1];
    fixture.adapters[0].first_dns = &fixture.servers[0];
    fixture.adapters[0].oper_status = 2; // disconnected, even though DNS is configured
    fixture.adapters[1].next = &fixture.adapters[2];
    fixture.adapters[1].first_dns = &fixture.servers[5];
    fixture.adapters[1].oper_status = win.if_oper_status_up;
    fixture.adapters[2].first_dns = &fixture.servers[1];
    fixture.adapters[2].oper_status = win.if_oper_status_up;
    for (1..4) |index| fixture.servers[index].next = &fixture.servers[index + 1];

    var cfg = ResolverConfig{};
    try std.testing.expect(windowsCollectNameservers(&cfg, &fixture.adapters[0], std.mem.asBytes(&fixture)));
    try std.testing.expectEqual(max_nameservers, cfg.nameserver_count);
    try std.testing.expectEqual(wire.Address{ .ipv4 = .{ 10, 0, 0, 6 } }, cfg.nameservers[0]);
    try std.testing.expectEqual(wire.Address{ .ipv4 = .{ 10, 0, 0, 2 } }, cfg.nameservers[1]);
    try std.testing.expectEqual(wire.Address{ .ipv4 = .{ 10, 0, 0, 3 } }, cfg.nameservers[2]);
    try std.testing.expectEqual(wire.Address{ .ipv4 = .{ 10, 0, 0, 4 } }, cfg.nameservers[3]);
}

test "Windows DNS discovery handles down and empty adapters with no candidates" {
    var adapter = std.mem.zeroes(win.AdapterAddresses);
    adapter.length = @sizeOf(win.AdapterAddresses);
    for ([_]u32{ 2, win.if_oper_status_up }) |status| {
        adapter.oper_status = status;
        var cfg = ResolverConfig{};
        try std.testing.expect(!windowsCollectNameservers(&cfg, &adapter, std.mem.asBytes(&adapter)));
        try std.testing.expectEqual(@as(usize, 0), cfg.nameserver_count);
    }
}

test "Windows DNS selection keeps the earliest duplicate in native query order" {
    var selection = WindowsDnsSelection{};
    selection.consider(.{ .address = .{ .ipv4 = .{ 10, 0, 0, 1 } }, .scope_id = 0, .backup = false, .adapter_order = 0, .sequence = 0 });
    selection.consider(.{ .address = .{ .ipv4 = .{ 192, 0, 2, 53 } }, .scope_id = 0, .backup = true, .adapter_order = 0, .sequence = 1 });
    selection.consider(.{ .address = .{ .ipv4 = .{ 10, 0, 0, 3 } }, .scope_id = 0, .backup = true, .adapter_order = 0, .sequence = 2 });
    selection.consider(.{ .address = .{ .ipv4 = .{ 192, 0, 2, 53 } }, .scope_id = 0, .backup = false, .adapter_order = 1, .sequence = 3 });
    var cfg = ResolverConfig{};
    selection.write(&cfg);
    try std.testing.expectEqual(@as(usize, 3), cfg.nameserver_count);
    try std.testing.expectEqual(wire.Address{ .ipv4 = .{ 10, 0, 0, 1 } }, cfg.nameservers[0]);
    try std.testing.expectEqual(wire.Address{ .ipv4 = .{ 192, 0, 2, 53 } }, cfg.nameservers[1]);
    try std.testing.expectEqual(wire.Address{ .ipv4 = .{ 10, 0, 0, 3 } }, cfg.nameservers[2]);
    try std.testing.expect(!selection.overflowed);
}

test "Windows DNS duplicate primary survives capacity without moving its query position" {
    var selection = WindowsDnsSelection{};
    selection.consider(.{ .address = .{ .ipv4 = .{ 10, 0, 0, 1 } }, .scope_id = 0, .backup = false, .adapter_order = 0, .sequence = 0 }); // A: P
    selection.consider(.{ .address = .{ .ipv4 = .{ 10, 0, 0, 2 } }, .scope_id = 0, .backup = true, .adapter_order = 0, .sequence = 1 }); // A: X
    selection.consider(.{ .address = .{ .ipv4 = .{ 10, 0, 0, 3 } }, .scope_id = 0, .backup = true, .adapter_order = 0, .sequence = 2 }); // A: Y
    selection.consider(.{ .address = .{ .ipv4 = .{ 10, 0, 0, 4 } }, .scope_id = 0, .backup = true, .adapter_order = 0, .sequence = 3 }); // A: Z
    selection.consider(.{ .address = .{ .ipv4 = .{ 10, 0, 0, 2 } }, .scope_id = 0, .backup = false, .adapter_order = 1, .sequence = 4 }); // B: X
    selection.consider(.{ .address = .{ .ipv4 = .{ 10, 0, 0, 5 } }, .scope_id = 0, .backup = false, .adapter_order = 2, .sequence = 5 }); // C: Q
    selection.consider(.{ .address = .{ .ipv4 = .{ 10, 0, 0, 6 } }, .scope_id = 0, .backup = false, .adapter_order = 3, .sequence = 6 }); // D: R
    selection.consider(.{ .address = .{ .ipv4 = .{ 10, 0, 0, 7 } }, .scope_id = 0, .backup = false, .adapter_order = 4, .sequence = 7 }); // E: S
    var cfg = ResolverConfig{};
    selection.write(&cfg);
    try std.testing.expect(selection.overflowed);
    try std.testing.expectEqual(max_nameservers, cfg.nameserver_count);
    try std.testing.expectEqual(wire.Address{ .ipv4 = .{ 10, 0, 0, 1 } }, cfg.nameservers[0]);
    try std.testing.expectEqual(wire.Address{ .ipv4 = .{ 10, 0, 0, 2 } }, cfg.nameservers[1]);
    try std.testing.expectEqual(wire.Address{ .ipv4 = .{ 10, 0, 0, 5 } }, cfg.nameservers[2]);
    try std.testing.expectEqual(wire.Address{ .ipv4 = .{ 10, 0, 0, 6 } }, cfg.nameservers[3]);
}

test "Windows DNS query order tries preferred adapter backup before another adapter" {
    var selection = WindowsDnsSelection{};
    selection.consider(.{ .address = .{ .ipv4 = .{ 10, 0, 0, 1 } }, .scope_id = 0, .backup = false, .adapter_order = 0, .sequence = 0 });
    selection.consider(.{ .address = .{ .ipv4 = .{ 10, 0, 0, 2 } }, .scope_id = 0, .backup = true, .adapter_order = 0, .sequence = 1 });
    selection.consider(.{ .address = .{ .ipv4 = .{ 203, 0, 113, 53 } }, .scope_id = 0, .backup = false, .adapter_order = 1, .sequence = 2 });
    var cfg = ResolverConfig{};
    selection.write(&cfg);
    try std.testing.expectEqual(@as(usize, 3), cfg.nameserver_count);
    try std.testing.expectEqual(wire.Address{ .ipv4 = .{ 10, 0, 0, 1 } }, cfg.nameservers[0]);
    try std.testing.expectEqual(wire.Address{ .ipv4 = .{ 10, 0, 0, 2 } }, cfg.nameservers[1]);
    try std.testing.expectEqual(wire.Address{ .ipv4 = .{ 203, 0, 113, 53 } }, cfg.nameservers[2]);
}

test "parseResolvConf extracts nameservers and ignores noise" {
    var cfg = ResolverConfig{};
    const text =
        \\# generated
        \\nameserver 8.8.8.8
        \\options ndots:1
        \\nameserver 2606:4700:4700::1111
        \\;nameserver 9.9.9.9
        \\nameserver 192.168.1.1 # router
        \\search lan
    ;
    const n = parseResolvConf(text, &cfg);
    try std.testing.expectEqual(@as(usize, 3), n);
    try std.testing.expectEqual(wire.Address{ .ipv4 = .{ 8, 8, 8, 8 } }, cfg.nameservers[0]);
    try std.testing.expect(cfg.nameservers[1] == .ipv6);
    try std.testing.expectEqual(wire.Address{ .ipv4 = .{ 192, 168, 1, 1 } }, cfg.nameservers[2]);
}

test "ResolverConfig caps nameservers at max_nameservers" {
    var cfg = ResolverConfig{};
    var i: usize = 0;
    while (i < max_nameservers + 3) : (i += 1) cfg.addNameserver(.{ .ipv4 = .{ 10, 0, 0, @intCast(i) } });
    try std.testing.expectEqual(max_nameservers, cfg.nameserver_count);
    try std.testing.expectEqual(max_nameservers, cfg.nsSlice().len);
}

test "parseResolvConf requires whitespace after nameserver keyword" {
    var cfg = ResolverConfig{};
    const text =
        "nameserver192.0.2.1\n" ++
        "nameserver2001:db8::1\n" ++
        "nameserver=192.0.2.2\n" ++
        "nameserver\n" ++
        "nameserver \t\n" ++
        "nameserver\t192.0.2.53\n" ++
        " nameserver  2001:db8::53 # valid IPv6\n";
    try std.testing.expectEqual(@as(usize, 2), parseResolvConf(text, &cfg));
    try std.testing.expectEqual(wire.Address{ .ipv4 = .{ 192, 0, 2, 53 } }, cfg.nameservers[0]);
    try std.testing.expectEqual(parseIpLiteral("2001:db8::53").?, cfg.nameservers[1]);
}

test "DNS resolv.conf preserves numeric IPv6 scopes deduplicates and bounds retry options" {
    var cfg = ResolverConfig{};
    const text =
        \\nameserver fe80::53%7
        \\nameserver fe80::53%7
        \\nameserver fe80::53%8 # distinct interface
        \\nameserver fe80::53
        \\nameserver fe80::53%0
        \\nameserver fe80::53%4294967296
        \\nameserver 192.0.2.1%2
        \\nameserver 192.0.2.53
        \\options timeout:999 attempts:999
    ;
    try std.testing.expectEqual(@as(usize, 3), parseResolvConf(text, &cfg));
    try std.testing.expectEqualSlices(u32, &.{ 7, 8, 0 }, cfg.nameserver_scope_ids[0..3]);
    try std.testing.expectEqual(@as(u32, 5000), cfg.timeout_ms);
    try std.testing.expectEqual(@as(u8, 3), cfg.attempts);
    _ = parseResolvConf("options timeout:0 attempts:0\noptions timeout:bad attempts:bad", &cfg);
    try std.testing.expectEqual(@as(u32, 1000), cfg.timeout_ms);
    try std.testing.expectEqual(@as(u8, 1), cfg.attempts);
}

test "DNS resolv.conf resolves native loopback interface scopes" {
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
    var cfg = ResolverConfig{};
    const line = if (builtin.os.tag == .linux) "nameserver fe80::53%lo" else "nameserver fe80::53%lo0";
    try std.testing.expectEqual(@as(usize, 1), parseResolvConf(line, &cfg));
    try std.testing.expect(cfg.nameserver_scope_ids[0] != 0);
}
