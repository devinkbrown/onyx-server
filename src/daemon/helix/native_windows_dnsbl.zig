// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded Windows Helix custody for DNSBL verdicts, zones, and queued probes.
//! The caller authenticates this image and holds the source worker pause and
//! producer fence until COMMIT or ABORT.
const std = @import("std");
const dns = @import("../../proto/dns.zig");
const dnsbl = @import("../dnsbl_resolver.zig");
const runtime_pause = @import("../runtime_pause.zig");

const magic = "HXDB";
const version: u16 = 1;
const header_len: usize = 64;
const entry_len: usize = 32;
const job_len: usize = 17;
pub const max_capture_bytes: usize = @sizeOf(dnsbl.Snapshot) +
    dnsbl.cache_slots * @sizeOf(dnsbl.CacheEntry) + dnsbl.job_capacity * @sizeOf(dns.Address) +
    dnsbl.max_zones * (@sizeOf([]u8) + dns.max_domain_text_len);
pub const max_snapshot_bytes: usize = header_len +
    dnsbl.max_zones * (2 + dns.max_domain_text_len) +
    dnsbl.cache_slots * entry_len + dnsbl.job_capacity * job_len;

comptime {
    if (dnsbl.cache_slots > std.math.maxInt(u16) or dnsbl.job_capacity > std.math.maxInt(u16) or
        dnsbl.max_zones > std.math.maxInt(u8) or dns.max_domain_text_len > std.math.maxInt(u16) or
        max_snapshot_bytes > std.math.maxInt(u32))
        @compileError("Windows DNSBL checkpoint exceeds its wire bounds");
}

pub const Error = std.mem.Allocator.Error || error{ InvalidSnapshot, ConfigMismatch, TooLarge };

fn validate(carry: *const dnsbl.Snapshot, cfg: dns.ResolverConfig, zones: []const []const u8) Error!void {
    carry.validate(cfg, zones) catch |err| switch (err) {
        error.ConfigMismatch => return error.ConfigMismatch,
        else => return error.InvalidSnapshot,
    };
}

fn writeAddress(kind: *u8, payload: []u8, address: dns.Address) void {
    @memset(payload, 0);
    switch (address) {
        .ipv4 => |bytes| {
            kind.* = 4;
            @memcpy(payload[0..4], &bytes);
        },
        .ipv6 => |bytes| {
            kind.* = 6;
            @memcpy(payload[0..16], &bytes);
        },
    }
}

fn readAddress(kind: u8, payload: []const u8) Error!dns.Address {
    if (payload.len != 16) return error.InvalidSnapshot;
    return switch (kind) {
        4 => blk: {
            if (!std.mem.allEqual(u8, payload[4..], 0)) return error.InvalidSnapshot;
            break :blk .{ .ipv4 = payload[0..4].* };
        },
        6 => .{ .ipv6 = payload[0..16].* },
        else => error.InvalidSnapshot,
    };
}

/// Keep a corrupt mandatory HXDB image in the relation validator's namespace.
pub fn isCheckpoint(bytes: []const u8) bool {
    return bytes.len >= magic.len and std.mem.eql(u8, bytes[0..magic.len], magic);
}

/// Allocation-free framing and semantic validation before any candidate owner
/// changes. The candidate's local DNS context is compared by decodeSnapshot.
pub fn validateCheckpoint(bytes: []const u8) error{InvalidSnapshot}!void {
    if (bytes.len < header_len + dnsbl.cache_slots * entry_len or bytes.len > max_snapshot_bytes or
        !isCheckpoint(bytes) or std.mem.readInt(u16, bytes[4..6], .big) != version or
        std.mem.readInt(u16, bytes[6..8], .big) != 0 or
        std.mem.readInt(u16, bytes[8..10], .big) != dnsbl.cache_slots or
        bytes[14] != 0 or bytes[15] != 0 or
        @as(usize, std.mem.readInt(u32, bytes[56..60], .big)) != bytes.len - header_len or
        std.mem.readInt(u32, bytes[60..64], .big) != 0)
        return error.InvalidSnapshot;
    const count: usize = std.mem.readInt(u16, bytes[10..12], .big);
    const zone_count: usize = bytes[12];
    if (count > dnsbl.job_capacity or zone_count > dnsbl.max_zones) return error.InvalidSnapshot;
    _ = std.enums.fromInt(dnsbl.Execution, bytes[13]) orelse return error.InvalidSnapshot;
    const captured: i64 = @bitCast(std.mem.readInt(u64, bytes[16..24], .big));
    if (captured < 0) return error.InvalidSnapshot;
    const jobs_start = bytes.len - count * job_len;
    if (jobs_start < header_len + dnsbl.cache_slots * entry_len) return error.InvalidSnapshot;
    const zone_limit = jobs_start - dnsbl.cache_slots * entry_len;

    var zone_views: [dnsbl.max_zones][]const u8 = undefined;
    var pos: usize = header_len;
    for (zone_views[0..zone_count]) |*zone| {
        if (pos + 2 > zone_limit) return error.InvalidSnapshot;
        const len: usize = std.mem.readInt(u16, bytes[pos..][0..2], .big);
        pos += 2;
        if (len == 0 or len > dns.max_domain_text_len or pos + len > zone_limit) return error.InvalidSnapshot;
        zone.* = bytes[pos..][0..len];
        pos += len;
    }
    dnsbl.validateZones(zone_views[0..zone_count]) catch return error.InvalidSnapshot;

    var seen_entries: [dnsbl.cache_slots]dns.Address = undefined;
    var seen_count: usize = 0;
    for (0..dnsbl.cache_slots) |_| {
        if (pos + entry_len > jobs_start or bytes[pos] > 1 or bytes[pos + 20] > 1 or
            std.mem.readInt(u16, bytes[pos + 22 ..][0..2], .big) != 0 or bytes[pos + 3] != 0)
            return error.InvalidSnapshot;
        const has_key = bytes[pos] == 1;
        const state = std.enums.fromInt(dnsbl.State, bytes[pos + 1]) orelse return error.InvalidSnapshot;
        const address = readAddress(bytes[pos + 2], bytes[pos + 4 ..][0..16]) catch return error.InvalidSnapshot;
        const listed = bytes[pos + 20] == 1;
        const code = bytes[pos + 21];
        const resolved: i64 = @bitCast(std.mem.readInt(u64, bytes[pos + 24 ..][0..8], .big));
        if (!has_key) {
            if (state != .empty or listed or code != 0 or resolved != 0 or
                !std.meta.eql(address, dns.Address{ .ipv4 = .{ 0, 0, 0, 0 } }))
                return error.InvalidSnapshot;
        } else {
            if (state == .empty or (state != .ready and (listed or code != 0 or resolved != 0)) or
                (state == .ready and ((!listed and code != 0) or resolved < 0 or resolved > captured)))
                return error.InvalidSnapshot;
            for (seen_entries[0..seen_count]) |prior| if (std.meta.eql(prior, address)) return error.InvalidSnapshot;
            seen_entries[seen_count] = address;
            seen_count += 1;
        }
        pos += entry_len;
    }
    if (pos != jobs_start) return error.InvalidSnapshot;
    var seen_jobs: [dnsbl.job_capacity]dns.Address = undefined;
    for (0..count) |index| {
        const address = readAddress(bytes[pos], bytes[pos + 1 ..][0..16]) catch return error.InvalidSnapshot;
        for (seen_jobs[0..index]) |prior| if (std.meta.eql(prior, address)) return error.InvalidSnapshot;
        seen_jobs[index] = address;
        pos += job_len;
    }
    if (pos != bytes.len) return error.InvalidSnapshot;
}

/// Encode only initialized zone text, cache fields, and FIFO jobs. Native
/// pointer, union padding, and uninitialized job tails never enter the wire.
pub fn encodeSnapshot(allocator: std.mem.Allocator, carry: *const dnsbl.Snapshot, cfg: dns.ResolverConfig, zones: []const []const u8) Error![]u8 {
    try validate(carry, cfg, zones);
    var total = header_len + dnsbl.cache_slots * entry_len + carry.job_count * job_len;
    for (carry.zones) |zone| total += 2 + zone.len;
    if (total > max_snapshot_bytes) return error.TooLarge;
    const bytes = try allocator.alloc(u8, total);
    @memcpy(bytes[0..4], magic);
    std.mem.writeInt(u16, bytes[4..6], version, .big);
    @memset(bytes[6..16], 0);
    std.mem.writeInt(u16, bytes[8..10], @intCast(dnsbl.cache_slots), .big);
    std.mem.writeInt(u16, bytes[10..12], @intCast(carry.job_count), .big);
    bytes[12] = @intCast(carry.zones.len);
    bytes[13] = @intFromEnum(carry.execution);
    std.mem.writeInt(u64, bytes[16..24], @bitCast(carry.captured_monotonic_ms), .big);
    @memcpy(bytes[24..56], &carry.config_digest);
    std.mem.writeInt(u32, bytes[56..60], @intCast(total - header_len), .big);
    @memset(bytes[60..64], 0);

    var pos: usize = header_len;
    for (carry.zones) |zone| {
        std.mem.writeInt(u16, bytes[pos..][0..2], @intCast(zone.len), .big);
        pos += 2;
        @memcpy(bytes[pos..][0..zone.len], zone);
        pos += zone.len;
    }
    for (carry.entries) |entry| {
        bytes[pos] = @intFromBool(entry.has_key);
        bytes[pos + 1] = @intFromEnum(entry.state);
        writeAddress(&bytes[pos + 2], bytes[pos + 4 ..][0..16], entry.key);
        bytes[pos + 3] = 0;
        bytes[pos + 20] = @intFromBool(entry.verdict.listed);
        bytes[pos + 21] = entry.verdict.code;
        std.mem.writeInt(u16, bytes[pos + 22 ..][0..2], 0, .big);
        std.mem.writeInt(u64, bytes[pos + 24 ..][0..8], @bitCast(entry.resolved_ms), .big);
        pos += entry_len;
    }
    for (carry.jobs[0..carry.job_count]) |address| {
        writeAddress(&bytes[pos], bytes[pos + 1 ..][0..16], address);
        pos += job_len;
    }
    std.debug.assert(pos == bytes.len);
    return bytes;
}

/// Check framing and config before allocation; the returned state remains
/// inert until one of the two exact-owner restore calls publishes it.
pub fn decodeSnapshot(allocator: std.mem.Allocator, bytes: []const u8, cfg: dns.ResolverConfig, zones: []const []const u8) Error!dnsbl.Snapshot {
    try validateCheckpoint(bytes);
    const count: usize = std.mem.readInt(u16, bytes[10..12], .big);
    const zone_count: usize = bytes[12];
    const expected_digest = dnsbl.configDigest(cfg, zones) catch return error.InvalidSnapshot;
    if (!std.crypto.timing_safe.eql([32]u8, expected_digest, bytes[24..56].*)) return error.ConfigMismatch;
    const jobs_start = bytes.len - count * job_len;

    var pos: usize = header_len;
    if (zone_count != zones.len) return error.ConfigMismatch;
    for (zones) |zone| {
        const len: usize = std.mem.readInt(u16, bytes[pos..][0..2], .big);
        pos += 2;
        if (!std.mem.eql(u8, zone, bytes[pos..][0..len])) return error.ConfigMismatch;
        pos += len;
    }
    const entries = try allocator.alloc(dnsbl.CacheEntry, dnsbl.cache_slots);
    errdefer allocator.free(entries);
    const jobs = try allocator.alloc(dns.Address, dnsbl.job_capacity);
    errdefer allocator.free(jobs);
    const carried_zones = try allocator.alloc([]u8, zone_count);
    errdefer allocator.free(carried_zones);
    var copied: usize = 0;
    errdefer for (carried_zones[0..copied]) |zone| allocator.free(zone);
    var zone_pos: usize = header_len;
    for (carried_zones) |*zone| {
        const len: usize = std.mem.readInt(u16, bytes[zone_pos..][0..2], .big);
        zone_pos += 2;
        zone.* = try allocator.dupe(u8, bytes[zone_pos..][0..len]);
        copied += 1;
        zone_pos += len;
    }
    std.debug.assert(zone_pos == pos);
    for (entries) |*entry| {
        const key = try readAddress(bytes[pos + 2], bytes[pos + 4 ..][0..16]);
        entry.* = .{
            .key = key,
            .has_key = bytes[pos] == 1,
            .state = std.enums.fromInt(dnsbl.State, bytes[pos + 1]).?,
            .verdict = .{ .listed = bytes[pos + 20] == 1, .code = bytes[pos + 21] },
            .resolved_ms = @bitCast(std.mem.readInt(u64, bytes[pos + 24 ..][0..8], .big)),
        };
        pos += entry_len;
    }
    if (pos != jobs_start) return error.InvalidSnapshot;
    for (jobs[0..count]) |*job| {
        job.* = try readAddress(bytes[pos], bytes[pos + 1 ..][0..16]);
        pos += job_len;
    }
    std.debug.assert(pos == bytes.len);
    const carry = dnsbl.Snapshot{
        .allocator = allocator,
        .entries = entries,
        .jobs = jobs,
        .job_count = count,
        .zones = carried_zones,
        .config_digest = bytes[24..56].*,
        .captured_monotonic_ms = @bitCast(std.mem.readInt(u64, bytes[16..24], .big)),
        .execution = std.enums.fromInt(dnsbl.Execution, bytes[13]).?,
    };
    try validate(&carry, cfg, zones);
    return carry;
}

/// The source producer fence and actual worker pause are retained by caller.
pub fn captureFrozenEncoded(allocator: std.mem.Allocator, owner: *dnsbl.Resolver, fence: runtime_pause.ProducerFence, token: ?runtime_pause.Token) ![]u8 {
    var carry = try owner.captureFrozen(allocator, fence, token, max_capture_bytes);
    defer carry.deinit();
    return encodeSnapshot(allocator, &carry, owner.cfg, owner.zones[0..owner.zone_count]);
}

pub fn restoreEncoded(allocator: std.mem.Allocator, owner: *dnsbl.Resolver, bytes: []const u8) !void {
    var carry = try decodeSnapshot(allocator, bytes, owner.cfg, owner.zones[0..owner.zone_count]);
    defer carry.deinit();
    try owner.restoreSnapshot(&carry);
}

pub fn restoreEncodedParked(allocator: std.mem.Allocator, owner: *dnsbl.Resolver, bytes: []const u8) !void {
    var carry = try decodeSnapshot(allocator, bytes, owner.cfg, owner.zones[0..owner.zone_count]);
    defer carry.deinit();
    try owner.restoreSnapshotParked(&carry);
}

test "Windows Helix DNSBL checkpoint preserves ordered zones verdicts and pending FIFO" {
    const allocator = std.testing.allocator;
    var cfg: dns.ResolverConfig = .{};
    cfg.addNameserver(.{ .ipv4 = .{ 192, 0, 2, 53 } });
    const zones = [_][]const u8{ "first.invalid", "second.invalid" };
    var source = try dnsbl.Resolver.initConfigured(allocator, std.testing.io, cfg, &zones);
    defer source.deinit();
    const listed: dns.Address = .{ .ipv4 = .{ 203, 0, 113, 1 } };
    const pending: dns.Address = .{ .ipv6 = @splat(7) };
    source.request(listed);
    source.request(pending);
    source.remember(listed, .{ .listed = true, .code = 0 });
    const fence = try source.fenceProducers();
    const wire = try captureFrozenEncoded(allocator, &source, fence, null);
    try source.resumeProducers(fence);
    defer allocator.free(wire);
    try std.testing.expect(isCheckpoint(wire));
    try validateCheckpoint(wire);
    var decoded = try decodeSnapshot(allocator, wire, cfg, &zones);
    defer decoded.deinit();
    try std.testing.expectEqual(@as(usize, 2), decoded.job_count);
    try std.testing.expectEqualStrings(zones[0], decoded.zones[0]);
    try std.testing.expectEqualStrings(zones[1], decoded.zones[1]);
    const again = try encodeSnapshot(allocator, &decoded, cfg, &zones);
    defer allocator.free(again);
    try std.testing.expectEqualSlices(u8, wire, again);
    var candidate = try dnsbl.Resolver.initConfigured(allocator, std.testing.io, cfg, &zones);
    defer candidate.deinit();
    try candidate.restoreSnapshot(&decoded);
    try std.testing.expect(candidate.lookup(listed).?.listed);
    try std.testing.expectEqual(@as(u8, 0), candidate.lookup(listed).?.code);
    try std.testing.expect(std.meta.eql(listed, candidate.jobs[0].ip));
    try std.testing.expect(std.meta.eql(pending, candidate.jobs[1].ip));
}

test "Windows Helix DNSBL checkpoint rejects malformed and configuration mismatched images before allocation" {
    const allocator = std.testing.allocator;
    const zones = [_][]const u8{"listed.invalid"};
    var cfg: dns.ResolverConfig = .{};
    cfg.addNameserver(.{ .ipv6 = .{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } });
    cfg.nameserver_scope_ids[0] = 7;
    var source = try dnsbl.Resolver.initConfigured(allocator, std.testing.io, cfg, &zones);
    defer source.deinit();
    source.request(.{ .ipv4 = .{ 192, 0, 2, 1 } });
    var carry = try source.captureUnstarted(allocator, max_capture_bytes);
    defer carry.deinit();
    const wire = try encodeSnapshot(allocator, &carry, cfg, &zones);
    defer allocator.free(wire);
    try std.testing.expectError(error.InvalidSnapshot, validateCheckpoint(wire[0 .. wire.len - 1]));
    var damaged = try allocator.dupe(u8, wire);
    defer allocator.free(damaged);
    damaged[6] = 1;
    try std.testing.expectError(error.InvalidSnapshot, validateCheckpoint(damaged));
    damaged[6] = 0;
    damaged[header_len + 2] = ' ';
    try std.testing.expectError(error.InvalidSnapshot, validateCheckpoint(damaged));
    damaged[header_len + 2] = 'l';
    const first_entry = header_len + 2 + zones[0].len;
    damaged[first_entry + 8] = 1;
    try std.testing.expectError(error.InvalidSnapshot, validateCheckpoint(damaged));
    damaged[first_entry + 8] = 0;
    damaged[first_entry + 20] = 2;
    try std.testing.expectError(error.InvalidSnapshot, validateCheckpoint(damaged));
    damaged[first_entry + 20] = 0;
    var changed_scope = cfg;
    changed_scope.nameserver_scope_ids[0] = 8;
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.ConfigMismatch, decodeSnapshot(failing.allocator(), wire, changed_scope, &zones));
    try std.testing.expectEqual(@as(usize, 0), failing.alloc_index);
    try std.testing.expectError(error.ConfigMismatch, decodeSnapshot(failing.allocator(), wire, cfg, &.{"other.invalid"}));
    try std.testing.expectEqual(@as(usize, 0), failing.alloc_index);
}

test "Windows Helix DNSBL checkpoint decode allocation failures leave candidate unchanged" {
    const allocator = std.testing.allocator;
    const zones = [_][]const u8{ "one.invalid", "two.invalid" };
    var source = try dnsbl.Resolver.initConfigured(allocator, std.testing.io, .{}, &zones);
    defer source.deinit();
    const ip: dns.Address = .{ .ipv4 = .{ 192, 0, 2, 11 } };
    source.request(ip);
    const fence = try source.fenceProducers();
    const wire = try captureFrozenEncoded(allocator, &source, fence, null);
    try source.resumeProducers(fence);
    defer allocator.free(wire);
    var candidate = try dnsbl.Resolver.initConfigured(allocator, std.testing.io, .{}, &zones);
    defer candidate.deinit();
    for (0..5) |fail_index| {
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = fail_index });
        try std.testing.expectError(error.OutOfMemory, restoreEncoded(failing.allocator(), &candidate, wire));
        try std.testing.expectEqual(@as(usize, 0), candidate.job_count);
        try std.testing.expect(candidate.lookup(ip) == null);
    }
    var succeeding = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 5 });
    try restoreEncoded(succeeding.allocator(), &candidate, wire);
    try std.testing.expectEqual(@as(usize, 1), candidate.job_count);
}

test "Windows Helix DNSBL checkpoint restores only to the real parked Gate owner" {
    const allocator = std.testing.allocator;
    var cfg: dns.ResolverConfig = .{};
    cfg.addNameserver(.{ .ipv4 = .{ 127, 0, 0, 1 } });
    const zones = [_][]const u8{"listed.invalid"};
    var source = try dnsbl.Resolver.initConfigured(allocator, std.testing.io, cfg, &zones);
    defer source.deinit();
    source.request(.{ .ipv4 = .{ 192, 0, 2, 41 } });
    const fence = try source.fenceProducers();
    const wire = try captureFrozenEncoded(allocator, &source, fence, null);
    try source.resumeProducers(fence);
    defer allocator.free(wire);

    var candidate = try dnsbl.Resolver.initConfigured(allocator, std.testing.io, cfg, &zones);
    const specs = [_]runtime_pause.start_gate.ParticipantSpec{.{ .kind = .dnsbl, .instance = 0, .owner_identity = &candidate }};
    const gate = runtime_pause.start_gate.create(allocator, std.testing.io, &specs) catch |err| {
        candidate.deinit();
        return err;
    };
    defer {
        candidate.requestStopAndWake();
        gate.control.cancelAllAndJoin();
        candidate.detachAfterJoined() catch unreachable;
        candidate.deinit();
        gate.control.destroyJoined();
    }
    try candidate.prepareDormantWorker(gate.control, gate.view, try gate.view.slot(.dnsbl, 0, &candidate));
    try gate.control.awaitAllParked(std.Io.Clock.Timestamp.fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
    try candidate.requireParked();
    try std.testing.expectError(error.AlreadyStarted, restoreEncoded(allocator, &candidate, wire));
    try restoreEncodedParked(allocator, &candidate, wire);
    try std.testing.expectEqual(@as(usize, 1), candidate.job_count);
    try candidate.requireParked();
}
