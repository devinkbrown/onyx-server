// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Immutable exact-fact grants, not signing-root or general mesh authority.
const std = @import("std");
const sign = @import("../crypto/sign.zig");

pub const Digest = [32]u8;
pub const max_grants: usize = 4096;
pub const Grant = struct {
    group_key: Digest,
    issuer_key: sign.PublicKey,
    fact_digest: Digest,
};
pub const Error = error{ TooManyGrants, DuplicateGrant, InvalidGrant, NonCanonicalGrants };

pub fn compare(a: Grant, b: Grant) std.math.Order {
    const group = std.mem.order(u8, &a.group_key, &b.group_key);
    if (group != .eq) return group;
    const issuer = std.mem.order(u8, &a.issuer_key, &b.issuer_key);
    if (issuer != .eq) return issuer;
    return std.mem.order(u8, &a.fact_digest, &b.fact_digest);
}

/// Exact value equality for already-canonical immutable policy lists. Used to
/// reject policy changes before a warm handoff can acquire external resources.
pub fn same(a: []const Grant, b: []const Grant) bool {
    if (a.len != b.len) return false;
    for (a, b) |left, right| if (compare(left, right) != .eq) return false;
    return true;
}

pub fn validateCanonical(grants: []const Grant) Error!void {
    if (grants.len > max_grants) return error.TooManyGrants;
    for (grants, 0..) |grant, i| {
        if (std.mem.allEqual(u8, &grant.issuer_key, 0) or
            std.mem.allEqual(u8, &grant.group_key, 0) or
            std.mem.allEqual(u8, &grant.fact_digest, 0)) return error.InvalidGrant;
        if (i == 0) continue;
        switch (compare(grants[i - 1], grant)) {
            .eq => return error.DuplicateGrant,
            .gt => return error.NonCanonicalGrants,
            .lt => {},
        }
    }
}

/// Caller owns the sorted immutable grant list. Alternatives for one group are
/// retained; only identical group/issuer/fact triples are duplicates.
pub fn canonicalize(allocator: std.mem.Allocator, grants: []const Grant) (Error || std.mem.Allocator.Error)![]Grant {
    if (grants.len > max_grants) return error.TooManyGrants;
    const owned = try allocator.dupe(Grant, grants);
    errdefer allocator.free(owned);
    std.mem.sort(Grant, owned, {}, struct {
        fn lessThan(_: void, a: Grant, b: Grant) bool {
            return compare(a, b) == .lt;
        }
    }.lessThan);
    try validateCanonical(owned);
    return owned;
}

/// `grants` must have passed validateCanonical during configuration staging.
/// Exact triple lookup is logarithmic and conveys no authority for other facts.
pub fn allows(grants: []const Grant, key: sign.PublicKey, group: Digest, fact: Digest) bool {
    if (grants.len > max_grants) return false;
    const wanted: Grant = .{ .group_key = group, .issuer_key = key, .fact_digest = fact };
    var low: usize = 0;
    var high = grants.len;
    while (low < high) {
        const middle = low + (high - low) / 2;
        switch (compare(grants[middle], wanted)) {
            .lt => low = middle + 1,
            .gt => high = middle,
            .eq => return true,
        }
    }
    return false;
}

test "retired fence policy canonical exact alternatives remain narrowly scoped" {
    const a: Grant = .{ .group_key = @splat(1), .issuer_key = @splat(2), .fact_digest = @splat(3) };
    var b = a;
    b.fact_digest = @splat(4);
    const owned = try canonicalize(std.testing.allocator, &.{ b, a });
    defer std.testing.allocator.free(owned);
    try std.testing.expect(allows(owned, a.issuer_key, a.group_key, a.fact_digest));
    try std.testing.expect(allows(owned, b.issuer_key, b.group_key, b.fact_digest));
    try std.testing.expect(!allows(owned, @splat(5), a.group_key, a.fact_digest));
    try std.testing.expect(!allows(owned, a.issuer_key, @splat(5), a.fact_digest));
    try std.testing.expect(!allows(owned, a.issuer_key, a.group_key, @splat(5)));
    try std.testing.expectError(error.DuplicateGrant, canonicalize(std.testing.allocator, &.{ a, a }));
    try std.testing.expectError(error.NonCanonicalGrants, validateCanonical(&.{ b, a }));
    var invalid = a;
    invalid.issuer_key = @splat(0);
    try std.testing.expectError(error.InvalidGrant, validateCanonical(&.{invalid}));
    const oversized = try std.testing.allocator.alloc(Grant, max_grants + 1);
    defer std.testing.allocator.free(oversized);
    try std.testing.expectError(error.TooManyGrants, canonicalize(std.testing.allocator, oversized));
    const Sweep = struct {
        fn run(allocator: std.mem.Allocator, grants: []const Grant) !void {
            const copy = try canonicalize(allocator, grants);
            defer allocator.free(copy);
            try std.testing.expectEqual(@as(usize, 2), copy.len);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Sweep.run, .{@as([]const Grant, &.{ b, a })});
}

test "retired fence policy equality compares canonical values across owned copies" {
    const grants = [_]Grant{
        .{ .group_key = @splat(1), .issuer_key = @splat(2), .fact_digest = @splat(3) },
        .{ .group_key = @splat(4), .issuer_key = @splat(5), .fact_digest = @splat(6) },
    };
    const owned = try canonicalize(std.testing.allocator, &grants);
    defer std.testing.allocator.free(owned);
    try std.testing.expect(same(&grants, owned));
    try std.testing.expect(same(&.{}, &.{}));
    try std.testing.expect(!same(owned, owned[0..1]));
    var changed = grants;
    changed[1].fact_digest[0] ^= 1;
    try std.testing.expect(!same(owned, &changed));
    changed = grants;
    changed[1].issuer_key[0] ^= 1;
    try std.testing.expect(!same(owned, &changed));
    changed = grants;
    changed[1].group_key[0] ^= 1;
    try std.testing.expect(!same(owned, &changed));
}
