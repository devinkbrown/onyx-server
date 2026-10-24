// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Stable rDNS checkpoint model and resolver-configuration commitment.
//!
//! Runtime cache ownership and worker scheduling live in `rdns.zig`. This
//! module contains the portable checkpoint shape and its strict validation so
//! Helix encoders and runtime capture share one definition.

const std = @import("std");
const dns = @import("../proto/dns.zig");

pub const max_host_len: usize = dns.max_domain_text_len;
pub const cache_slots: usize = 1024;
pub const job_capacity: usize = 256;

pub const State = enum(u8) { empty, pending, ready };

pub const CacheEntry = struct {
    key: dns.Address = .{ .ipv4 = .{ 0, 0, 0, 0 } },
    has_key: bool = false,
    state: State = .empty,
    host: [max_host_len]u8 = @splat(0),
    host_len: u16 = 0,
    resolved_ms: i64 = 0,
};

pub const Execution = enum(u8) { unstarted, paused };

pub const Snapshot = struct {
    allocator: std.mem.Allocator,
    entries: []CacheEntry,
    /// Backing is exactly job_capacity; only job_count records are initialized.
    jobs: []dns.Address,
    job_count: usize,
    config_digest: [32]u8,
    captured_monotonic_ms: i64,
    execution: Execution,

    pub fn deinit(self: *Snapshot) void {
        self.allocator.free(self.entries);
        self.allocator.free(self.jobs);
        self.* = undefined;
    }

    pub fn validate(self: *const Snapshot, cfg: dns.ResolverConfig) !void {
        if (self.entries.len != cache_slots or self.jobs.len != job_capacity or self.job_count > job_capacity) return error.InvalidState;
        if (self.captured_monotonic_ms < 0) return error.InvalidState;
        if (!std.mem.eql(u8, &self.config_digest, &try resolverConfigDigest(cfg))) return error.ConfigMismatch;
        for (self.entries, 0..) |entry, i| {
            if (entry.host_len > max_host_len) return error.InvalidState;
            if (!std.mem.allEqual(u8, entry.host[entry.host_len..], 0)) return error.InvalidState;
            if (!entry.has_key and (entry.state != .empty or entry.host_len != 0 or entry.resolved_ms != 0 or
                !addressEql(entry.key, .{ .ipv4 = .{ 0, 0, 0, 0 } }))) return error.InvalidState;
            if (entry.has_key and entry.state == .empty) return error.InvalidState;
            if (entry.state != .ready and entry.host_len != 0) return error.InvalidState;
            if (entry.state == .ready and (entry.resolved_ms < 0 or entry.resolved_ms > self.captured_monotonic_ms)) return error.InvalidState;
            if (entry.host_len != 0 and !validConfirmedHost(entry.host[0..entry.host_len])) return error.InvalidState;
            if (entry.has_key) for (self.entries[0..i]) |prior| {
                if (prior.has_key and addressEql(prior.key, entry.key)) return error.InvalidState;
            };
        }
        for (self.jobs[0..self.job_count], 0..) |ip, i| for (self.jobs[0..i]) |prior| {
            if (addressEql(ip, prior)) return error.InvalidState;
        };
    }
};

/// Apply the DNS name constraints to restored text before WHOIS can emit it.
pub fn validConfirmedHost(host: []const u8) bool {
    var label_len: usize = 0;
    for (host) |ch| {
        if (ch == '.') {
            if (label_len == 0 or label_len > 63) return false;
            label_len = 0;
        } else switch (ch) {
            'a'...'z', 'A'...'Z', '0'...'9', '-', '_' => label_len += 1,
            else => return false,
        }
    }
    return label_len != 0 and label_len <= 63;
}

/// Hash only initialized configured fields; do not hash union padding or unused
/// nameserver tails. DNSBL uses the same exact DNS context commitment.
pub fn resolverConfigDigest(cfg: dns.ResolverConfig) ![32]u8 {
    if (cfg.nameserver_count > dns.max_nameservers) return error.InvalidState;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("onyx/companion/dns-config/v2");
    hash.update(&.{@intCast(cfg.nameserver_count)});
    for (cfg.nameservers[0..cfg.nameserver_count], cfg.nameserver_scope_ids[0..cfg.nameserver_count]) |address, scope_id| {
        hashAddress(&hash, address);
        var scope_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &scope_bytes, scope_id, .big);
        hash.update(&scope_bytes);
    }
    var numbers: [7]u8 = undefined;
    std.mem.writeInt(u16, numbers[0..2], cfg.port, .big);
    std.mem.writeInt(u32, numbers[2..6], cfg.timeout_ms, .big);
    numbers[6] = cfg.attempts;
    hash.update(&numbers);
    return hash.finalResult();
}

pub fn hashAddress(hash: *std.crypto.hash.sha2.Sha256, address: dns.Address) void {
    switch (address) {
        .ipv4 => |bytes| {
            hash.update(&.{4});
            hash.update(&bytes);
        },
        .ipv6 => |bytes| {
            hash.update(&.{6});
            hash.update(&bytes);
        },
    }
}

pub fn addressEql(a: dns.Address, b: dns.Address) bool {
    return switch (a) {
        .ipv4 => |x| switch (b) {
            .ipv4 => |y| std.mem.eql(u8, &x, &y),
            else => false,
        },
        .ipv6 => |x| switch (b) {
            .ipv6 => |y| std.mem.eql(u8, &x, &y),
            else => false,
        },
    };
}

test "rDNS config digest commits scoped IPv6 nameserver identity" {
    var cfg: dns.ResolverConfig = .{};
    cfg.addNameserver(.{ .ipv6 = .{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } });
    const first = try resolverConfigDigest(cfg);
    cfg.nameserver_scope_ids[0] = 17;
    const scoped = try resolverConfigDigest(cfg);
    try std.testing.expect(!std.mem.eql(u8, &first, &scoped));
    cfg.nameserver_scope_ids[0] = 0;
    try std.testing.expectEqualSlices(u8, &first, &try resolverConfigDigest(cfg));
}
