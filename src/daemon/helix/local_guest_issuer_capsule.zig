// SPDX-License-Identifier: AGPL-3.0-or-later
//! Mandatory coupled local guest issuer data. Authenticated Core handoff owns
//! descriptor provenance, predecessor fencing, physical witness and publication.
const std = @import("std");
const issuer = @import("../mesh_presence_issuer.zig");
const frontier = @import("../../proto/mesh_presence_frontier.zig");
const binding = @import("local_guest_binding_snapshot.zig");
const presence = @import("../../proto/mesh_presence.zig");

pub const TicketRef = struct { incarnation: u64, slot: usize, generation: u64 };
pub const Latch = struct {
    physical: u64,
    ticket: ?TicketRef = null,
    capture_pending: bool = false,
    refresh_pending: bool = false,
    close_retry: bool = false,
    registration_pending: bool = false,
};
pub const Active = struct {
    issuer: issuer.Issuer.HotTransferImage,
    lease_fd_index: u32,
    bindings: []const u8,
    latches: []const Latch,
};
pub const Limits = struct { physical: usize, tickets: usize, wire_bytes: usize };
pub const Error = std.mem.Allocator.Error || error{ Invalid, Limit, Truncated, Trailing, NonCanonical };
pub const Owned = struct {
    arena: std.heap.ArenaAllocator,
    active: ?Active,
    pub fn deinit(self: *Owned) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

fn latchAt(latches: []const Latch, physical: u64) ?Latch {
    var lo: usize = 0;
    var hi = latches.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (latches[mid].physical == physical) return latches[mid];
        if (latches[mid].physical < physical) lo = mid + 1 else hi = mid;
    }
    return null;
}
fn validate(a: std.mem.Allocator, active: Active, limits: Limits) Error!void {
    if (active.issuer.generation == 0 or std.mem.allEqual(u8, &active.issuer.metadata.origin, 0) or active.issuer.frontier_bytes.len > frontier.max_wire_len or active.bindings.len > limits.wire_bytes or active.latches.len > limits.physical) return error.Invalid;
    const raw = active.issuer.metadata.encode();
    _ = issuer.validateRows(&raw, active.issuer.frontier_bytes, active.issuer.metadata.origin) catch return error.Invalid;
    const proof = frontier.decode(active.issuer.frontier_bytes) catch return error.Invalid;
    var image = binding.decodeOwned(a, active.bindings, .{ .rows = limits.physical, .tickets = limits.tickets, .wire_bytes = limits.wire_bytes }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.Invalid,
    };
    defer image.deinit();
    var previous: ?u64 = null;
    for (active.latches) |latch| {
        if (latch.physical == std.math.maxInt(u64)) return error.Invalid;
        if (previous) |v| if (latch.physical <= v) return error.NonCanonical;
        previous = latch.physical;
        if (latch.ticket) |ref| {
            if (ref.incarnation != image.image.incarnation or ref.slot >= image.image.tickets.len) return error.Invalid;
            const ticket = image.image.tickets[ref.slot];
            if (ticket.physical == null or ticket.physical.? != latch.physical or ticket.generation != ref.generation) return error.Invalid;
        }
    }
    var guests = std.AutoHashMap(presence.GuestId, void).init(a);
    defer guests.deinit();
    for (image.image.rows) |row| {
        const latch = latchAt(active.latches, row.physical) orelse return error.Invalid;
        if (!std.mem.eql(u8, &row.origin, &active.issuer.metadata.origin) or latch.ticket != null) return error.Invalid;
        const subject = presence.subject(row.guest) catch return error.Invalid;
        if (subject.epoch != active.issuer.metadata.epoch or subject.counter > active.issuer.metadata.issued_through or proof.retires(active.issuer.metadata.origin, subject.epoch, subject.counter) or (try guests.getOrPut(row.guest)).found_existing) return error.Invalid;
    }
    for (image.image.tickets, 0..) |ticket, slot| {
        if (ticket.physical) |physical| {
            if (ticket.reserved) |guest| {
                const subject = presence.subject(guest) catch return error.Invalid;
                if (subject.epoch != active.issuer.metadata.epoch or subject.counter > active.issuer.metadata.issued_through or proof.retires(active.issuer.metadata.origin, subject.epoch, subject.counter) or (try guests.getOrPut(guest)).found_existing) return error.Invalid;
            }
            const latch = latchAt(active.latches, physical) orelse return error.Invalid;
            const ref = latch.ticket orelse return error.Invalid;
            // A ticket without public facts cannot reserve or commit. The
            // owning reactor must still be scheduled to capture those facts.
            if (ticket.facts == null and !latch.capture_pending) return error.Invalid;
            if (ref.incarnation != image.image.incarnation or ref.slot != slot or ref.generation != ticket.generation) return error.Invalid;
        }
    }
}
const Writer = struct {
    a: std.mem.Allocator,
    limit: usize,
    out: std.ArrayList(u8) = .empty,
    fn bytes(self: *Writer, value: []const u8) Error!void {
        if (value.len > self.limit or self.out.items.len > self.limit - value.len) return error.Limit;
        try self.out.appendSlice(self.a, value);
    }
    fn number(self: *Writer, comptime T: type, n: T) Error!void {
        var raw: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &raw, n, .big);
        try self.bytes(&raw);
    }
};
pub fn encode(a: std.mem.Allocator, maybe: ?Active, limits: Limits) Error![]u8 {
    if (maybe) |active| try validate(a, active, limits);
    var w = Writer{ .a = a, .limit = limits.wire_bytes };
    errdefer w.out.deinit(a);
    try w.bytes("LGI1");
    try w.number(u8, 1);
    try w.number(u8, @intFromBool(maybe != null));
    if (maybe) |active| {
        try w.bytes(&active.issuer.metadata.encode());
        try w.number(u64, active.issuer.generation);
        try w.number(u64, active.issuer.lease_identity.device);
        try w.number(u64, active.issuer.lease_identity.inode);
        try w.number(u64, active.issuer.lease_identity.inode_high);
        try w.number(u32, active.lease_fd_index);
        try w.number(u32, std.math.cast(u32, active.issuer.frontier_bytes.len) orelse return error.Limit);
        try w.bytes(active.issuer.frontier_bytes);
        try w.number(u32, std.math.cast(u32, active.bindings.len) orelse return error.Limit);
        try w.bytes(active.bindings);
        try w.number(u32, std.math.cast(u32, active.latches.len) orelse return error.Limit);
        for (active.latches) |latch| {
            try w.number(u64, latch.physical);
            const flags: u8 = @as(u8, @intFromBool(latch.ticket != null)) | (@as(u8, @intFromBool(latch.capture_pending)) << 1) | (@as(u8, @intFromBool(latch.refresh_pending)) << 2) | (@as(u8, @intFromBool(latch.close_retry)) << 3) | (@as(u8, @intFromBool(latch.registration_pending)) << 4);
            try w.number(u8, flags);
            if (latch.ticket) |ref| {
                try w.number(u64, ref.incarnation);
                try w.number(u64, std.math.cast(u64, ref.slot) orelse return error.Limit);
                try w.number(u64, ref.generation);
            }
        }
    }
    return w.out.toOwnedSlice(a);
}
const Reader = struct {
    data: []const u8,
    pos: usize = 0,
    fn take(self: *Reader, n: usize) Error![]const u8 {
        if (n > self.data.len - self.pos) return error.Truncated;
        const value = self.data[self.pos..][0..n];
        self.pos += n;
        return value;
    }
    fn number(self: *Reader, comptime T: type) Error!T {
        return std.mem.readInt(T, (try self.take(@sizeOf(T)))[0..@sizeOf(T)], .big);
    }
};
/// Allocation-free structural census only. This does not authenticate the
/// issuer, frontier, latches, descriptor custody, or physical ownership; full
/// decodeOwned and Core validation are mandatory before adoption.
pub fn leaseFdIndex(bytes: []const u8) Error!?u32 {
    var r = Reader{ .data = bytes };
    if (!std.mem.eql(u8, try r.take(4), "LGI1") or try r.number(u8) != 1) return error.Invalid;
    const enabled = try r.number(u8);
    if (enabled > 1) return error.Invalid;
    if (enabled == 0) {
        if (r.pos != bytes.len) return error.Trailing;
        return null;
    }
    const raw = try r.take(issuer.metadata_len);
    if (!std.mem.eql(u8, raw[0..4], "OPIS") or raw[4] != 1) return error.Invalid;
    _ = try r.number(u64); // generation
    _ = try r.number(u64); // device
    _ = try r.number(u64); // inode
    _ = try r.number(u64); // inode_high
    const fd = try r.number(u32);
    const proof_len = try r.number(u32);
    if (proof_len > frontier.max_wire_len) return error.Limit;
    _ = try r.take(proof_len);
    const binding_len = try r.number(u32);
    _ = try r.take(binding_len);
    const count = try r.number(u32);
    if (count > (bytes.len - r.pos) / 9) return error.Truncated;
    for (0..count) |_| {
        _ = try r.number(u64);
        const flags = try r.number(u8);
        if (flags & 0xe0 != 0) return error.Invalid;
        if (flags & 1 != 0) _ = try r.take(24);
    }
    if (r.pos != bytes.len) return error.Trailing;
    return fd;
}

pub fn decodeOwned(a: std.mem.Allocator, bytes: []const u8, limits: Limits) Error!Owned {
    if (bytes.len > limits.wire_bytes) return error.Limit;
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const aa = arena.allocator();
    const copy = try aa.dupe(u8, bytes);
    var r = Reader{ .data = copy };
    if (!std.mem.eql(u8, try r.take(4), "LGI1") or try r.number(u8) != 1) return error.Invalid;
    const enabled = try r.number(u8);
    if (enabled > 1) return error.Invalid;
    if (enabled == 0) {
        if (r.pos != copy.len) return error.Trailing;
        return .{ .arena = arena, .active = null };
    }
    const raw = try r.take(issuer.metadata_len);
    if (!std.mem.eql(u8, raw[0..4], "OPIS") or raw[4] != 1) return error.Invalid;
    const metadata: issuer.Metadata = .{
        .origin = raw[5..37].*,
        .epoch = std.mem.readInt(u64, raw[37..45], .big),
        .issued_through = std.mem.readInt(u64, raw[45..53], .big),
        .frontier_revision = std.mem.readInt(u64, raw[53..61], .big),
        .frontier_through = std.mem.readInt(u64, raw[61..69], .big),
        .frontier_digest = raw[69..101].*,
    };
    const generation = try r.number(u64);
    const identity: @import("../mesh_presence_lease.zig").Identity = .{ .device = try r.number(u64), .inode = try r.number(u64), .inode_high = try r.number(u64) };
    const fd = try r.number(u32);
    const frontier_len = try r.number(u32);
    if (frontier_len > frontier.max_wire_len) return error.Limit;
    const frontier_bytes = try r.take(frontier_len);
    const binding_len = try r.number(u32);
    const bindings = try r.take(binding_len);
    const count = try r.number(u32);
    if (count > limits.physical or count > (copy.len - r.pos) / 9) return error.Limit;
    const latches = try aa.alloc(Latch, count);
    for (latches) |*latch| {
        const physical = try r.number(u64);
        const flags = try r.number(u8);
        if (flags & 0xe0 != 0) return error.Invalid;
        var ticket: ?TicketRef = null;
        if (flags & 1 != 0) ticket = .{ .incarnation = try r.number(u64), .slot = std.math.cast(usize, try r.number(u64)) orelse return error.Limit, .generation = try r.number(u64) };
        latch.* = .{ .physical = physical, .ticket = ticket, .capture_pending = flags & 2 != 0, .refresh_pending = flags & 4 != 0, .close_retry = flags & 8 != 0, .registration_pending = flags & 16 != 0 };
    }
    if (r.pos != copy.len) return error.Trailing;
    const active: Active = .{ .issuer = .{ .metadata = metadata, .frontier_bytes = frontier_bytes, .lease_identity = identity, .generation = generation }, .lease_fd_index = fd, .bindings = bindings, .latches = latches };
    try validate(a, active, limits);
    return .{ .arena = arena, .active = active };
}

test "disabled issuer family is mandatory and canonical" {
    const a = std.testing.allocator;
    const limits: Limits = .{ .physical = 8, .tickets = 8, .wire_bytes = 4096 };
    const bytes = try encode(a, null, limits);
    defer a.free(bytes);
    try std.testing.expectEqualSlices(u8, "LGI1\x01\x00", bytes);
    var decoded = try decodeOwned(a, bytes, limits);
    defer decoded.deinit();
    try std.testing.expect(decoded.active == null);
    try std.testing.expectEqual(@as(?u32, null), try leaseFdIndex(bytes));
    try std.testing.expectError(error.Trailing, leaseFdIndex("LGI1\x01\x00\x00"));
    try std.testing.expectError(error.Invalid, leaseFdIndex("LGI1\x01\x02"));
    try std.testing.expectError(error.Trailing, decodeOwned(a, "LGI1\x01\x00\x00", limits));
    try std.testing.expectError(error.Invalid, decodeOwned(a, "LGI1\x01\x02", limits));
}

test "issuer family binds ticket identity, rejects malformed cuts, and cleans allocation failures" {
    const a = std.testing.allocator;
    var key = try @import("../../crypto/sign.zig").KeyPair.fromSeed(@splat(12));
    defer key.deinit();
    var frontier_buffer: [frontier.max_wire_len]u8 = undefined;
    const proof = try frontier.encode(.{ .origin = key.public_key, .epoch = 1, .revision = 1, .through = 0, .issued_ms = 1, .active = &.{} }, &key, &frontier_buffer);
    var digest: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(proof, &digest, .{});
    const limits: Limits = .{ .physical = 3, .tickets = 2, .wire_bytes = 4096 };
    const tickets = [_]binding.Ticket{.{ .generation = 9, .physical = 42, .issuer_incarnation = 2 }};
    const lgb = try binding.encode(a, .{ .incarnation = 3, .issuer_incarnation = 2, .rows = &.{}, .tickets = &tickets }, .{ .rows = 3, .tickets = 2, .wire_bytes = 4096 });
    defer a.free(lgb);
    var latches = [_]Latch{.{ .physical = 42, .ticket = .{ .incarnation = 3, .slot = 0, .generation = 9 }, .capture_pending = true }};
    var active: Active = .{
        .issuer = .{ .metadata = .{ .origin = key.public_key, .epoch = 1, .issued_through = 0, .frontier_revision = 1, .frontier_through = 0, .frontier_digest = digest }, .frontier_bytes = proof, .lease_identity = .{ .device = 4, .inode = 5 }, .generation = 7 },
        .lease_fd_index = 6,
        .bindings = lgb,
        .latches = &latches,
    };
    const bytes = try encode(a, active, limits);
    defer a.free(bytes);
    var decoded = try decodeOwned(a, bytes, limits);
    defer decoded.deinit();
    const got = decoded.active.?;
    try std.testing.expectEqual(@as(?u32, 6), try leaseFdIndex(bytes));
    try std.testing.expectEqual(@as(u64, 7), got.issuer.generation);
    try std.testing.expectEqual(@as(u64, 5), got.issuer.lease_identity.inode);
    try std.testing.expectEqual(@as(u32, 6), got.lease_fd_index);
    try std.testing.expectEqualSlices(u8, lgb, got.bindings);
    try std.testing.expect(got.latches[0].capture_pending);
    try std.testing.expectEqual(@as(u64, 9), got.latches[0].ticket.?.generation);
    latches[0].capture_pending = false;
    try std.testing.expectError(error.Invalid, encode(a, active, limits));
    latches[0].capture_pending = true;
    // The signed outer family may be structurally intact while its actor latch
    // contradicts LGB1. Full decoding must reject before Core can activate it.
    const stalled = try a.dupe(u8, bytes);
    defer a.free(stalled);
    const latch_ticket_bytes = 3 * @sizeOf(u64);
    const flags_index = stalled.len - latch_ticket_bytes - 1;
    stalled[flags_index] &= ~@as(u8, 2);
    try std.testing.expectEqual(@as(?u32, 6), try leaseFdIndex(stalled));
    try std.testing.expectError(error.Invalid, decodeOwned(a, stalled, limits));
    for (0..bytes.len) |n| {
        if (leaseFdIndex(bytes[0..n])) |_| return error.TestUnexpectedResult else |_| {}
        if (decodeOwned(a, bytes[0..n], limits)) |value| {
            var unexpected = value;
            unexpected.deinit();
            return error.TestUnexpectedResult;
        } else |_| {}
    }
    latches[0].ticket.?.generation = 10;
    try std.testing.expectError(error.Invalid, encode(a, active, limits));
    latches[0].ticket.?.generation = 9;
    active.latches = &.{};
    try std.testing.expectError(error.Invalid, encode(a, active, limits));
    const duplicates = [_]Latch{ latches[0], latches[0] };
    active.latches = &duplicates;
    try std.testing.expectError(error.NonCanonical, encode(a, active, limits));
    active.latches = &latches;
    active.issuer.metadata.origin[0] ^= 1;
    try std.testing.expectError(error.Invalid, encode(a, active, limits));
    const Sweep = struct {
        fn run(allocator: std.mem.Allocator, wire: []const u8, bounds: Limits) !void {
            var image = try decodeOwned(allocator, wire, bounds);
            defer image.deinit();
            try std.testing.expect(image.active != null);
        }
    };
    try std.testing.checkAllAllocationFailures(a, Sweep.run, .{ bytes, limits });
}

test "issuer family rejects retired binding and ticket reservation while accepting live exceptions" {
    const a = std.testing.allocator;
    var key = try @import("../../crypto/sign.zig").KeyPair.fromSeed(@splat(31));
    defer key.deinit();
    var above_buffer: [frontier.max_wire_len]u8 = undefined;
    var retired_buffer: [frontier.max_wire_len]u8 = undefined;
    var exception_buffer: [frontier.max_wire_len]u8 = undefined;
    const above = try frontier.encode(.{ .origin = key.public_key, .epoch = 1, .revision = 1, .through = 0, .issued_ms = 1, .active = &.{} }, &key, &above_buffer);
    const retired = try frontier.encode(.{ .origin = key.public_key, .epoch = 1, .revision = 2, .through = 1, .issued_ms = 2, .active = &.{} }, &key, &retired_buffer);
    const exception = try frontier.encode(.{ .origin = key.public_key, .epoch = 1, .revision = 2, .through = 1, .issued_ms = 2, .active = &.{1} }, &key, &exception_buffer);
    try std.testing.expectEqual(above.len, retired.len);
    var guest: presence.GuestId = undefined;
    std.mem.writeInt(u64, guest[0..8], 1, .big);
    std.mem.writeInt(u64, guest[8..16], 1, .big);
    const facts: binding.Facts = .{ .nick = "n", .username = "u", .host = "h", .realname = "r", .server = "s", .description = "d" };
    const limits: Limits = .{ .physical = 2, .tickets = 2, .wire_bytes = 4096 };
    for ([_]bool{ false, true }) |reserved| {
        const rows = [_]binding.Row{.{ .physical = 42, .origin = key.public_key, .guest = guest, .facts = facts }};
        const tickets = [_]binding.Ticket{.{ .generation = 9, .physical = 42, .facts = facts, .reserved = guest, .issuer_incarnation = 2 }};
        const wire = try binding.encode(a, .{ .incarnation = 3, .issuer_incarnation = 2, .rows = if (reserved) &.{} else &rows, .tickets = if (reserved) &tickets else &.{} }, .{ .rows = 2, .tickets = 2, .wire_bytes = 4096 });
        defer a.free(wire);
        const latches = [_]Latch{.{ .physical = 42, .ticket = if (reserved) .{ .incarnation = 3, .slot = 0, .generation = 9 } else null }};
        var digest: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(above, &digest, .{});
        var active: Active = .{
            .issuer = .{ .metadata = .{ .origin = key.public_key, .epoch = 1, .issued_through = 1, .frontier_revision = 1, .frontier_through = 0, .frontier_digest = digest }, .frontier_bytes = above, .lease_identity = .{ .device = 4, .inode = 5 }, .generation = 7 },
            .lease_fd_index = 6,
            .bindings = wire,
            .latches = &latches,
        };
        // Issued counter above the signed frontier remains live.
        const bytes = try encode(a, active, limits);
        defer a.free(bytes);
        var decoded = try decodeOwned(a, bytes, limits);
        decoded.deinit();
        const Sweep = struct {
            fn run(allocator: std.mem.Allocator, input: []const u8, bounds: Limits) !void {
                var owned = try decodeOwned(allocator, input, bounds);
                defer owned.deinit();
                try std.testing.expect(owned.active != null);
            }
        };
        try std.testing.checkAllAllocationFailures(a, Sweep.run, .{ bytes, limits });

        // A signed retirement of exactly that issued counter must reject both
        // producer validation and an authenticated but contradictory wire.
        std.crypto.hash.Blake3.hash(retired, &digest, .{});
        active.issuer.metadata.frontier_revision = 2;
        active.issuer.metadata.frontier_through = 1;
        active.issuer.metadata.frontier_digest = digest;
        active.issuer.frontier_bytes = retired;
        try std.testing.expectError(error.Invalid, encode(a, active, limits));
        const bad = try a.dupe(u8, bytes);
        defer a.free(bad);
        const metadata_start = 6;
        const proof_start = metadata_start + issuer.metadata_len + 8 * 4 + 4 + 4;
        @memcpy(bad[metadata_start..][0..issuer.metadata_len], &active.issuer.metadata.encode());
        @memcpy(bad[proof_start..][0..retired.len], retired);
        try std.testing.expectEqual(@as(?u32, 6), try leaseFdIndex(bad));
        try std.testing.expectError(error.Invalid, decodeOwned(a, bad, limits));

        // An explicit active exception in the same frontier admits the guest.
        std.crypto.hash.Blake3.hash(exception, &digest, .{});
        active.issuer.metadata.frontier_digest = digest;
        active.issuer.frontier_bytes = exception;
        const accepted = try encode(a, active, limits);
        defer a.free(accepted);
        var accepted_decoded = try decodeOwned(a, accepted, limits);
        accepted_decoded.deinit();
    }
}
