// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Portable DNSBL checkpoint model and resolver-configuration commitment.
//!
//! Worker scheduling and cache ownership stay in the resolver module. This
//! module owns the stable carry shape and validates it before the live
//! resolver publishes any restored state.

const std = @import("std");
const dns = @import("../proto/dns.zig");
const dnsbl = @import("dnsbl.zig");
const rdns_snapshot = @import("rdns_snapshot.zig");

pub const max_zones: usize = 8;
pub const cache_slots: usize = 1024;
pub const job_capacity: usize = 256;

pub const State = enum(u8) { empty, pending, ready };

/// A resolved blocklist verdict for one client IP.
pub const Verdict = struct {
    /// True when at least one configured zone listed the IP.
    listed: bool,
    /// Return code (last octet of the listing answer) of the first hit; 0 when
    /// not listed.
    code: u8 = 0,
};

pub const CacheEntry = struct {
    key: dns.Address = .{ .ipv4 = .{ 0, 0, 0, 0 } },
    has_key: bool = false,
    state: State = .empty,
    verdict: Verdict = .{ .listed = false },
    resolved_ms: i64 = 0,
};

pub const Execution = enum(u8) { unstarted, paused };

pub const Snapshot = struct {
    allocator: std.mem.Allocator,
    entries: []CacheEntry,
    jobs: []dns.Address,
    job_count: usize,
    zones: [][]u8,
    config_digest: [32]u8,
    captured_monotonic_ms: i64,
    execution: Execution,

    pub fn deinit(self: *Snapshot) void {
        for (self.zones) |zone| self.allocator.free(zone);
        self.allocator.free(self.zones);
        self.allocator.free(self.jobs);
        self.allocator.free(self.entries);
        self.* = undefined;
    }

    pub fn validate(self: *const Snapshot, cfg: dns.ResolverConfig, zones: []const []const u8) !void {
        if (self.entries.len != cache_slots or self.jobs.len != job_capacity or self.job_count > job_capacity or self.zones.len != zones.len) return error.InvalidState;
        if (self.captured_monotonic_ms < 0) return error.InvalidState;
        if (!std.mem.eql(u8, &self.config_digest, &try configDigest(cfg, zones))) return error.ConfigMismatch;
        for (self.zones, zones) |carried, actual| if (!std.mem.eql(u8, carried, actual)) return error.ConfigMismatch;
        for (self.entries, 0..) |entry, i| {
            if (!entry.has_key and (entry.state != .empty or entry.verdict.listed or entry.verdict.code != 0 or
                entry.resolved_ms != 0 or !addressEql(entry.key, .{ .ipv4 = .{ 0, 0, 0, 0 } }))) return error.InvalidState;
            if (entry.has_key and entry.state == .empty) return error.InvalidState;
            if (entry.state != .ready and (entry.verdict.listed or entry.verdict.code != 0 or entry.resolved_ms != 0)) return error.InvalidState;
            if (entry.state == .ready and ((!entry.verdict.listed and entry.verdict.code != 0) or
                entry.resolved_ms < 0 or entry.resolved_ms > self.captured_monotonic_ms)) return error.InvalidState;
            if (entry.has_key) for (self.entries[0..i]) |prior| {
                if (prior.has_key and addressEql(prior.key, entry.key)) return error.InvalidState;
            };
        }
        for (self.jobs[0..self.job_count], 0..) |ip, i| for (self.jobs[0..i]) |prior| {
            if (addressEql(ip, prior)) return error.InvalidState;
        };
    }
};

/// Commit to the exact ordered zones and DNS server context used for probes.
pub fn configDigest(cfg: dns.ResolverConfig, zones: []const []const u8) ![32]u8 {
    try validateZones(zones);
    const dns_digest = try rdns_snapshot.resolverConfigDigest(cfg);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("onyx/companion/dnsbl-config/v1");
    hash.update(&dns_digest);
    hash.update(&.{@intCast(zones.len)});
    for (zones) |zone| {
        const len = std.math.cast(u32, zone.len) orelse return error.Capacity;
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, len, .big);
        hash.update(&bytes);
        hash.update(zone);
    }
    return hash.finalResult();
}

/// A configured zone must produce a valid A query for both IPv4 and IPv6
/// clients. Validate at boot rather than silently treating every lookup as a
/// clean result when the zone can never be queried.
pub fn validateZones(zones: []const []const u8) !void {
    if (zones.len > max_zones) return error.TooManyZones;
    for (zones) |zone| {
        var name_buf: [dns.max_domain_text_len]u8 = undefined;
        const name = try dnsbl.reverseNameV6(@splat(0), zone, &name_buf);
        var query_buf: [dns.max_message_len]u8 = undefined;
        _ = try dns.encodeQuery(&query_buf, 1, name, .a);
    }
}

pub fn addressEql(a: dns.Address, b: dns.Address) bool {
    return rdns_snapshot.addressEql(a, b);
}

test "DNSBL config digest commits ordered zones and resolver context" {
    var cfg: dns.ResolverConfig = .{};
    cfg.addNameserver(.{ .ipv4 = .{ 192, 0, 2, 53 } });

    const first = try configDigest(cfg, &.{ "one.test", "two.test" });
    try std.testing.expect(!std.mem.eql(u8, &first, &try configDigest(cfg, &.{ "two.test", "one.test" })));
    try std.testing.expect(!std.mem.eql(u8, &first, &try configDigest(cfg, &.{"one.test"})));

    cfg.port += 1;
    try std.testing.expect(!std.mem.eql(u8, &first, &try configDigest(cfg, &.{ "one.test", "two.test" })));
}
