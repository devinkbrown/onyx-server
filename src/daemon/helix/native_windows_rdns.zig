// SPDX-License-Identifier: AGPL-3.0-or-later
//! Canonical, bounded Windows Helix custody for the forward-confirmed rDNS
//! resolver. The caller authenticates these bytes in the native handoff and
//! holds the source producer fence and worker pause through COMMIT or ABORT.
const std = @import("std");
const dns = @import("../../proto/dns.zig");
const rdns = @import("../rdns.zig");
const runtime_pause = @import("../runtime_pause.zig");

const magic = "HXRD";
const version: u16 = 1;
const header_len: usize = 64;
const entry_len: usize = 32;
const job_len: usize = 17;
pub const max_capture_bytes: usize = @sizeOf(rdns.Snapshot) +
    rdns.cache_slots * @sizeOf(rdns.CacheEntry) + rdns.job_capacity * @sizeOf(dns.Address);
pub const max_snapshot_bytes: usize = header_len +
    rdns.cache_slots * (entry_len + rdns.max_host_len) + rdns.job_capacity * job_len;

comptime {
    if (rdns.cache_slots > std.math.maxInt(u16) or rdns.job_capacity > std.math.maxInt(u16) or
        rdns.max_host_len > std.math.maxInt(u16) or max_snapshot_bytes > std.math.maxInt(u32))
        @compileError("Windows rDNS checkpoint exceeds its wire bounds");
}

pub const Error = std.mem.Allocator.Error || error{ InvalidSnapshot, ConfigMismatch, TooLarge };

fn validate(carry: *const rdns.Snapshot, cfg: dns.ResolverConfig) Error!void {
    carry.validate(cfg) catch |err| switch (err) {
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

/// Recognize the family even when its framing is corrupt, so handoff relation
/// validation cannot treat a damaged mandatory rDNS image as an unknown extra.
pub fn isCheckpoint(bytes: []const u8) bool {
    return bytes.len >= magic.len and std.mem.eql(u8, bytes[0..magic.len], magic);
}

/// Shape and semantic validation for the whole-handoff relation pass. This
/// uses bounded stack storage only; the candidate has not allocated or changed
/// a resolver yet. Its local DNS config digest is checked by decodeSnapshot.
pub fn validateCheckpoint(bytes: []const u8) error{InvalidSnapshot}!void {
    if (bytes.len < header_len + rdns.cache_slots * entry_len or bytes.len > max_snapshot_bytes or
        !isCheckpoint(bytes) or std.mem.readInt(u16, bytes[4..6], .big) != version or
        std.mem.readInt(u16, bytes[6..8], .big) != 0 or
        std.mem.readInt(u16, bytes[8..10], .big) != rdns.cache_slots or
        bytes[13] != 0 or bytes[14] != 0 or bytes[15] != 0 or
        @as(usize, std.mem.readInt(u32, bytes[56..60], .big)) != bytes.len - header_len or
        std.mem.readInt(u32, bytes[60..64], .big) != 0)
        return error.InvalidSnapshot;
    const count: usize = std.mem.readInt(u16, bytes[10..12], .big);
    if (count > rdns.job_capacity) return error.InvalidSnapshot;
    _ = std.enums.fromInt(rdns.Execution, bytes[12]) orelse return error.InvalidSnapshot;
    const captured: i64 = @bitCast(std.mem.readInt(u64, bytes[16..24], .big));
    if (captured < 0) return error.InvalidSnapshot;
    const jobs_start = bytes.len - count * job_len;
    if (jobs_start < header_len + rdns.cache_slots * entry_len) return error.InvalidSnapshot;

    var seen_entries: [rdns.cache_slots]dns.Address = undefined;
    var seen_count: usize = 0;
    var pos: usize = header_len;
    for (0..rdns.cache_slots) |_| {
        if (pos + entry_len > jobs_start or bytes[pos] > 1 or bytes[pos + 3] != 0 or
            std.mem.readInt(u16, bytes[pos + 22 ..][0..2], .big) != 0)
            return error.InvalidSnapshot;
        const has_key = bytes[pos] == 1;
        const state = std.enums.fromInt(rdns.State, bytes[pos + 1]) orelse return error.InvalidSnapshot;
        const address = readAddress(bytes[pos + 2], bytes[pos + 4 ..][0..16]) catch return error.InvalidSnapshot;
        const host_len: usize = std.mem.readInt(u16, bytes[pos + 20 ..][0..2], .big);
        const resolved: i64 = @bitCast(std.mem.readInt(u64, bytes[pos + 24 ..][0..8], .big));
        if (host_len > rdns.max_host_len or pos + entry_len + host_len > jobs_start) return error.InvalidSnapshot;
        pos += entry_len;
        const host = bytes[pos..][0..host_len];
        if (!has_key) {
            if (state != .empty or host_len != 0 or resolved != 0 or
                !std.meta.eql(address, dns.Address{ .ipv4 = .{ 0, 0, 0, 0 } }))
                return error.InvalidSnapshot;
        } else {
            if (state == .empty or (state != .ready and host_len != 0) or
                (state == .ready and (resolved < 0 or resolved > captured)) or
                (host_len != 0 and !rdns.validConfirmedHost(host)))
                return error.InvalidSnapshot;
            for (seen_entries[0..seen_count]) |prior| if (std.meta.eql(prior, address)) return error.InvalidSnapshot;
            seen_entries[seen_count] = address;
            seen_count += 1;
        }
        pos += host_len;
    }
    if (pos != jobs_start) return error.InvalidSnapshot;
    var seen_jobs: [rdns.job_capacity]dns.Address = undefined;
    for (0..count) |index| {
        const address = readAddress(bytes[pos], bytes[pos + 1 ..][0..16]) catch return error.InvalidSnapshot;
        for (seen_jobs[0..index]) |prior| if (std.meta.eql(prior, address)) return error.InvalidSnapshot;
        seen_jobs[index] = address;
        pos += job_len;
    }
    if (pos != bytes.len) return error.InvalidSnapshot;
}

/// Only initialized cache text and FIFO jobs enter the wire. No native union
/// padding, allocator pointer, unused job slot, or uninitialized host tail is
/// exposed. The source's actual DNS configuration is committed by its digest.
pub fn encodeSnapshot(allocator: std.mem.Allocator, carry: *const rdns.Snapshot, cfg: dns.ResolverConfig) Error![]u8 {
    try validate(carry, cfg);
    var total = header_len + rdns.cache_slots * entry_len + carry.job_count * job_len;
    for (carry.entries) |entry| total += entry.host_len;
    if (total > max_snapshot_bytes) return error.TooLarge;
    const bytes = try allocator.alloc(u8, total);
    @memcpy(bytes[0..4], magic);
    std.mem.writeInt(u16, bytes[4..6], version, .big);
    @memset(bytes[6..16], 0);
    std.mem.writeInt(u16, bytes[8..10], @intCast(rdns.cache_slots), .big);
    std.mem.writeInt(u16, bytes[10..12], @intCast(carry.job_count), .big);
    bytes[12] = @intFromEnum(carry.execution);
    std.mem.writeInt(u64, bytes[16..24], @bitCast(carry.captured_monotonic_ms), .big);
    @memcpy(bytes[24..56], &carry.config_digest);
    std.mem.writeInt(u32, bytes[56..60], @intCast(total - header_len), .big);
    @memset(bytes[60..64], 0);

    var pos: usize = header_len;
    for (carry.entries) |entry| {
        bytes[pos] = @intFromBool(entry.has_key);
        bytes[pos + 1] = @intFromEnum(entry.state);
        writeAddress(&bytes[pos + 2], bytes[pos + 4 ..][0..16], entry.key);
        bytes[pos + 3] = 0;
        std.mem.writeInt(u16, bytes[pos + 20 ..][0..2], entry.host_len, .big);
        std.mem.writeInt(u16, bytes[pos + 22 ..][0..2], 0, .big);
        std.mem.writeInt(u64, bytes[pos + 24 ..][0..8], @bitCast(entry.resolved_ms), .big);
        pos += entry_len;
        @memcpy(bytes[pos..][0..entry.host_len], entry.host[0..entry.host_len]);
        pos += entry.host_len;
    }
    for (carry.jobs[0..carry.job_count]) |address| {
        writeAddress(&bytes[pos], bytes[pos + 1 ..][0..16], address);
        pos += job_len;
    }
    std.debug.assert(pos == bytes.len);
    return bytes;
}

/// Fail closed before allocation for framing and DNS-config mismatches. A
/// decoded carry owns its arrays and is still inert until restoreSnapshot.
pub fn decodeSnapshot(allocator: std.mem.Allocator, bytes: []const u8, cfg: dns.ResolverConfig) Error!rdns.Snapshot {
    try validateCheckpoint(bytes);
    const count: usize = std.mem.readInt(u16, bytes[10..12], .big);
    const execution = std.enums.fromInt(rdns.Execution, bytes[12]).?;
    const expected_digest = rdns.resolverConfigDigest(cfg) catch return error.InvalidSnapshot;
    if (!std.crypto.timing_safe.eql([32]u8, expected_digest, bytes[24..56].*)) return error.ConfigMismatch;
    const jobs_start = bytes.len - count * job_len;

    const entries = try allocator.alloc(rdns.CacheEntry, rdns.cache_slots);
    errdefer allocator.free(entries);
    const jobs = try allocator.alloc(dns.Address, rdns.job_capacity);
    errdefer allocator.free(jobs);
    var pos: usize = header_len;
    for (entries) |*entry| {
        if (pos + entry_len > jobs_start or bytes[pos] > 1 or bytes[pos + 3] != 0 or
            std.mem.readInt(u16, bytes[pos + 22 ..][0..2], .big) != 0)
            return error.InvalidSnapshot;
        const state = std.enums.fromInt(rdns.State, bytes[pos + 1]) orelse return error.InvalidSnapshot;
        const key = try readAddress(bytes[pos + 2], bytes[pos + 4 ..][0..16]);
        const host_len: usize = std.mem.readInt(u16, bytes[pos + 20 ..][0..2], .big);
        if (host_len > rdns.max_host_len or pos + entry_len + host_len > jobs_start) return error.InvalidSnapshot;
        entry.* = .{
            .key = key,
            .has_key = bytes[pos] == 1,
            .state = state,
            .host_len = @intCast(host_len),
            .resolved_ms = @bitCast(std.mem.readInt(u64, bytes[pos + 24 ..][0..8], .big)),
        };
        pos += entry_len;
        @memcpy(entry.host[0..host_len], bytes[pos..][0..host_len]);
        pos += host_len;
    }
    if (pos != jobs_start) return error.InvalidSnapshot;
    for (jobs[0..count]) |*job| {
        job.* = try readAddress(bytes[pos], bytes[pos + 1 ..][0..16]);
        pos += job_len;
    }
    std.debug.assert(pos == bytes.len);
    const carry = rdns.Snapshot{
        .allocator = allocator,
        .entries = entries,
        .jobs = jobs,
        .job_count = count,
        .config_digest = bytes[24..56].*,
        .captured_monotonic_ms = @bitCast(std.mem.readInt(u64, bytes[16..24], .big)),
        .execution = execution,
    };
    try validate(&carry, cfg);
    return carry;
}

/// Call only under the real source producer fence and (when started) its parked
/// worker token. The caller retains both until the native transaction decides.
pub fn captureFrozenEncoded(
    allocator: std.mem.Allocator,
    owner: *rdns.Resolver,
    fence: runtime_pause.ProducerFence,
    token: ?runtime_pause.Token,
) ![]u8 {
    var carry = try owner.captureFrozen(allocator, fence, token, max_capture_bytes);
    defer carry.deinit();
    return encodeSnapshot(allocator, &carry, owner.cfg);
}

/// Candidate-only: decode/validate the whole image before restoreSnapshot's
/// allocation-free mutation. Its worker must still be unstarted and unarmed.
pub fn restoreEncoded(allocator: std.mem.Allocator, owner: *rdns.Resolver, bytes: []const u8) !void {
    var carry = try decodeSnapshot(allocator, bytes, owner.cfg);
    defer carry.deinit();
    try owner.restoreSnapshot(&carry);
}

/// Same atomic restore with an actual Gate-owned worker already parked. The
/// creator still controls release; decoding never starts a resolver thread.
pub fn restoreEncodedParked(allocator: std.mem.Allocator, owner: *rdns.Resolver, bytes: []const u8) !void {
    var carry = try decodeSnapshot(allocator, bytes, owner.cfg);
    defer carry.deinit();
    try owner.restoreSnapshotParked(&carry);
}

test "Windows Helix rDNS checkpoint preserves ordered cache and jobs canonically" {
    const allocator = std.testing.allocator;
    var cfg: dns.ResolverConfig = .{};
    cfg.addNameserver(.{ .ipv4 = .{ 192, 0, 2, 53 } });
    var source = try rdns.Resolver.initConfigured(allocator, std.testing.io, cfg);
    defer source.deinit();
    source.request(.{ .ipv4 = .{ 203, 0, 113, 1 } });
    source.request(.{ .ipv6 = @splat(7) });
    var carry = try source.captureUnstarted(allocator, max_capture_bytes);
    defer carry.deinit();
    carry.entries[1].state = .ready;
    carry.entries[1].resolved_ms = 123;
    const host = "host.example.test";
    @memcpy(carry.entries[1].host[0..host.len], host);
    carry.entries[1].host_len = host.len;
    const wire = try encodeSnapshot(allocator, &carry, cfg);
    defer allocator.free(wire);
    try std.testing.expect(isCheckpoint(wire));
    try validateCheckpoint(wire);
    var decoded = try decodeSnapshot(allocator, wire, cfg);
    defer decoded.deinit();
    try std.testing.expectEqual(carry.execution, decoded.execution);
    try std.testing.expectEqual(carry.job_count, decoded.job_count);
    try std.testing.expectEqualStrings(host, decoded.entries[1].host[0..decoded.entries[1].host_len]);
    const again = try encodeSnapshot(allocator, &decoded, cfg);
    defer allocator.free(again);
    try std.testing.expectEqualSlices(u8, wire, again);
    var candidate = try rdns.Resolver.initConfigured(allocator, std.testing.io, cfg);
    defer candidate.deinit();
    try candidate.restoreSnapshot(&decoded);
    try std.testing.expectEqual(@as(usize, 2), candidate.job_count);
    try std.testing.expect(std.meta.eql(carry.jobs[0], candidate.jobs[0].ip));
    try std.testing.expect(std.meta.eql(carry.jobs[1], candidate.jobs[1].ip));
    try std.testing.expectEqualStrings(host, candidate.entries[1].host_buf[0..candidate.entries[1].host_len]);
}

test "Windows Helix rDNS checkpoint rejects malformed, mismatched, and noncanonical images" {
    const allocator = std.testing.allocator;
    var owner = try rdns.Resolver.initConfigured(allocator, std.testing.io, .{});
    defer owner.deinit();
    owner.request(.{ .ipv4 = .{ 192, 0, 2, 1 } });
    var carry = try owner.captureUnstarted(allocator, max_capture_bytes);
    defer carry.deinit();
    const wire = try encodeSnapshot(allocator, &carry, owner.cfg);
    defer allocator.free(wire);
    try std.testing.expectError(error.InvalidSnapshot, decodeSnapshot(allocator, wire[0 .. wire.len - 1], owner.cfg));
    var damaged = try allocator.dupe(u8, wire);
    defer allocator.free(damaged);
    damaged[6] = 1;
    try std.testing.expectError(error.InvalidSnapshot, decodeSnapshot(allocator, damaged, owner.cfg));
    damaged[6] = 0;
    damaged[header_len + 8] = 1; // nonzero IPv4 padding
    try std.testing.expectError(error.InvalidSnapshot, validateCheckpoint(damaged));
    try std.testing.expectError(error.InvalidSnapshot, decodeSnapshot(allocator, damaged, owner.cfg));
    damaged[header_len + 8] = 0;
    damaged[header_len + 1] = 99; // invalid state tag
    try std.testing.expectError(error.InvalidSnapshot, decodeSnapshot(allocator, damaged, owner.cfg));
    damaged[header_len + 1] = @intFromEnum(rdns.State.pending);
    damaged[24] ^= 1;
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.ConfigMismatch, decodeSnapshot(failing.allocator(), damaged, owner.cfg));
    try std.testing.expectEqual(@as(usize, 0), failing.alloc_index);
    carry.entries[0].state = .ready;
    carry.entries[0].resolved_ms = 0;
    carry.entries[0].host[0] = '\n';
    carry.entries[0].host_len = 1;
    try std.testing.expectError(error.InvalidSnapshot, encodeSnapshot(allocator, &carry, owner.cfg));
}

test "Windows Helix rDNS checkpoint decode allocation failure leaves candidate untouched" {
    const allocator = std.testing.allocator;
    var source = try rdns.Resolver.initConfigured(allocator, std.testing.io, .{});
    defer source.deinit();
    source.request(.{ .ipv4 = .{ 192, 0, 2, 11 } });
    const fence = try source.fenceProducers();
    const wire = try captureFrozenEncoded(allocator, &source, fence, null);
    try source.resumeProducers(fence);
    defer allocator.free(wire);
    var candidate = try rdns.Resolver.initConfigured(allocator, std.testing.io, .{});
    defer candidate.deinit();
    for (0..2) |fail_index| {
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = fail_index });
        try std.testing.expectError(error.OutOfMemory, restoreEncoded(failing.allocator(), &candidate, wire));
        try std.testing.expectEqual(@as(usize, 0), candidate.job_count);
    }
    try restoreEncoded(allocator, &candidate, wire);
    try std.testing.expectEqual(@as(usize, 1), candidate.job_count);
}

test "Windows Helix rDNS checkpoint restores only to the real parked Gate owner" {
    const allocator = std.testing.allocator;
    var cfg: dns.ResolverConfig = .{};
    cfg.addNameserver(.{ .ipv4 = .{ 127, 0, 0, 1 } });
    var source = try rdns.Resolver.initConfigured(allocator, std.testing.io, cfg);
    defer source.deinit();
    source.request(.{ .ipv4 = .{ 192, 0, 2, 41 } });
    const fence = try source.fenceProducers();
    const wire = try captureFrozenEncoded(allocator, &source, fence, null);
    try source.resumeProducers(fence);
    defer allocator.free(wire);

    var candidate = try rdns.Resolver.initConfigured(allocator, std.testing.io, cfg);
    const specs = [_]runtime_pause.start_gate.ParticipantSpec{.{ .kind = .rdns, .instance = 0, .owner_identity = &candidate }};
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
    try candidate.prepareDormantWorker(gate.control, gate.view, try gate.view.slot(.rdns, 0, &candidate));
    try gate.control.awaitAllParked(std.Io.Clock.Timestamp.fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
    try candidate.requireParked();
    try std.testing.expectError(error.AlreadyStarted, restoreEncoded(allocator, &candidate, wire));
    try restoreEncodedParked(allocator, &candidate, wire);
    try std.testing.expectEqual(@as(usize, 1), candidate.job_count);
    try candidate.requireParked();
}
