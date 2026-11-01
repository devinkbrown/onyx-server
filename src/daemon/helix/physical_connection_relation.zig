// SPDX-License-Identifier: AGPL-3.0-or-later
//! Strict Helix old physical-ID to inherited owner-index relation. Structural
//! parsing is not adoption: independently supplied IRC/S2S owner indices must
//! pass validateBijection. Neither nick nor session token grants authority.
const std = @import("std");

/// Roles are supplied by Core after its independent admission checks. A wire
/// role is a claim, not evidence of a canonically admitted mesh connection.
pub const Role = enum(u8) { client = 1, canonical_mesh = 2 };
pub const Entry = struct { old_client: u64, fd_index: u32, role: Role = .client };
pub const ExpectedOwner = struct { fd_index: u32, role: Role };
pub const Error = std.mem.Allocator.Error || error{ BadMagic, BadVersion, Reserved, Truncated, TrailingBytes, CountLimit, InvalidClient, NonCanonicalOrder, DuplicateFdIndex, InvalidFdIndex, ScratchSize, OwnerSetMismatch, InvalidRole, RoleMismatch };
const magic = "HPC2";
const header_len = 16;
const row_len = 13;

pub const Iterator = struct {
    bytes: []const u8,
    pos: usize = header_len,
    pub fn next(self: *Iterator) ?Entry {
        if (self.pos == self.bytes.len) return null;
        const at = self.pos;
        self.pos += row_len;
        return .{ .old_client = std.mem.readInt(u64, self.bytes[at..][0..8], .big), .fd_index = std.mem.readInt(u32, self.bytes[at + 8 ..][0..4], .big), .role = @fromBackingInt(@intCast(self.bytes[at + 12])) };
    }
};
/// Borrows original bytes; structurally valid but NOT yet an owner bijection.
pub const View = struct {
    bytes: []const u8,
    count: usize,
    pub fn iterator(self: View) Iterator {
        return .{ .bytes = self.bytes };
    }
};
/// Both original wire and caller's scratch must remain alive and unchanged
/// through validation and adoption. Caller separately verifies OS-fd identity.
pub const ValidatedView = struct {
    view: View,
    pub fn iterator(self: ValidatedView) Iterator {
        return self.view.iterator();
    }
};

fn byFd(_: void, a: Entry, b: Entry) bool {
    return a.fd_index < b.fd_index;
}
fn byClient(_: void, a: Entry, b: Entry) bool {
    return a.old_client < b.old_client;
}

/// Copies and canonicalizes input; caller owns result. No input is mutated.
pub fn encode(allocator: std.mem.Allocator, entries: []const Entry, max_entries: usize) Error![]u8 {
    if (entries.len > max_entries) return error.CountLimit;
    const total = std.math.add(usize, header_len, std.math.mul(usize, entries.len, row_len) catch return error.CountLimit) catch return error.CountLimit;
    const sorted = try allocator.dupe(Entry, entries);
    defer allocator.free(sorted);
    for (sorted) |entry| if (entry.old_client == std.math.maxInt(u64)) return error.InvalidClient;
    std.mem.sort(Entry, sorted, {}, byFd);
    if (sorted.len > 1) for (sorted[1..], 0..) |entry, i| if (entry.fd_index == sorted[i].fd_index) return error.DuplicateFdIndex;
    std.mem.sort(Entry, sorted, {}, byClient);
    if (sorted.len > 1) for (sorted[1..], 0..) |entry, i| if (entry.old_client == sorted[i].old_client) return error.NonCanonicalOrder;
    const out = try allocator.alloc(u8, total);
    @memcpy(out[0..4], magic);
    out[4] = 2;
    @memset(out[5..8], 0);
    std.mem.writeInt(u64, out[8..16], @intCast(entries.len), .big);
    for (sorted, 0..) |entry, i| {
        const pos = header_len + i * row_len;
        std.mem.writeInt(u64, out[pos..][0..8], entry.old_client, .big);
        std.mem.writeInt(u32, out[pos + 8 ..][0..4], entry.fd_index, .big);
        out[pos + 12] = @backingInt(entry.role);
    }
    return out;
}

/// No allocation and no FD-uniqueness/owner proof: use validateBijection.
pub fn validateWire(bytes: []const u8, max_entries: usize, state_fd_count: usize) Error!View {
    if (bytes.len < header_len) return error.Truncated;
    if (!std.mem.eql(u8, bytes[0..4], magic)) return error.BadMagic;
    if (bytes[4] != 2) return error.BadVersion;
    if (!std.mem.allEqual(u8, bytes[5..8], 0)) return error.Reserved;
    const raw_count = std.mem.readInt(u64, bytes[8..16], .big);
    const count = std.math.cast(usize, raw_count) orelse return error.CountLimit;
    if (count > max_entries) return error.CountLimit;
    const total = std.math.add(usize, header_len, std.math.mul(usize, count, row_len) catch return error.CountLimit) catch return error.CountLimit;
    if (bytes.len < total) return error.Truncated;
    if (bytes.len > total) return error.TrailingBytes;
    // Check the discriminants before the iterator converts any byte to Role.
    for (0..count) |i| {
        const role = bytes[header_len + i * row_len + 12];
        if (role != @backingInt(Role.client) and role != @backingInt(Role.canonical_mesh)) return error.InvalidRole;
    }
    const view = View{ .bytes = bytes, .count = count };
    var it = view.iterator();
    var previous: ?u64 = null;
    while (it.next()) |entry| {
        if (entry.old_client == std.math.maxInt(u64)) return error.InvalidClient;
        if (previous) |value| if (entry.old_client <= value) return error.NonCanonicalOrder;
        if (@as(u64, entry.fd_index) >= state_fd_count) return error.InvalidFdIndex;
        previous = entry.old_client;
    }
    return view;
}

/// The independently derived owners and roles cover IRC and S2S only, not every
/// descriptor. Scratch is caller-owned and exactly state_fd_count bytes.
pub fn validateBijection(view: View, expected_owners: []const ExpectedOwner, state_fd_count: usize, scratch: []u8) Error!ValidatedView {
    if (scratch.len != state_fd_count) return error.ScratchSize;
    const checked = try validateWire(view.bytes, view.count, state_fd_count);
    if (checked.count != view.count) return error.OwnerSetMismatch;
    @memset(scratch, 0);
    for (expected_owners) |owner| {
        const fd_index = owner.fd_index;
        if (@as(u64, fd_index) >= state_fd_count) return error.InvalidFdIndex;
        if (scratch[fd_index] != 0) return error.DuplicateFdIndex;
        scratch[fd_index] = @backingInt(owner.role);
    }
    if (view.count != expected_owners.len) return error.OwnerSetMismatch;
    var it = view.iterator();
    while (it.next()) |entry| {
        if (@as(u64, entry.fd_index) >= state_fd_count) return error.InvalidFdIndex;
        const expected = scratch[entry.fd_index];
        if (expected >= 3) return error.DuplicateFdIndex;
        if (expected == 0) return error.OwnerSetMismatch;
        if (expected != @backingInt(entry.role)) return error.RoleMismatch;
        scratch[entry.fd_index] = expected + 2;
    }
    for (scratch) |value| if (value == 1 or value == 2) return error.OwnerSetMismatch;
    return .{ .view = view };
}

test "physical connection relation canonical set supports zero and fd gaps" {
    const a = std.testing.allocator;
    const rows = [_]Entry{ .{ .old_client = 0x8765432100000001, .fd_index = 5, .role = .canonical_mesh }, .{ .old_client = 0, .fd_index = 1 } };
    const bytes = try encode(a, &rows, 2);
    defer a.free(bytes);
    try std.testing.expectEqual(@as(u8, 'H'), bytes[0]);
    const view = try validateWire(bytes, 2, 7);
    var scratch: [7]u8 = undefined;
    const verified = try validateBijection(view, &.{ .{ .fd_index = 5, .role = .canonical_mesh }, .{ .fd_index = 1, .role = .client } }, 7, &scratch);
    var iter = verified.iterator();
    try std.testing.expectEqualDeep(Entry{ .old_client = 0, .fd_index = 1 }, iter.next().?);
    try std.testing.expectEqualDeep(Entry{ .old_client = 0x8765432100000001, .fd_index = 5, .role = .canonical_mesh }, iter.next().?);
    try std.testing.expect(iter.next() == null);
    try std.testing.expectError(error.RoleMismatch, validateBijection(view, &.{ .{ .fd_index = 1, .role = .canonical_mesh }, .{ .fd_index = 5, .role = .client } }, 7, &scratch));
    try std.testing.expectError(error.RoleMismatch, validateBijection(view, &.{ .{ .fd_index = 1, .role = .client }, .{ .fd_index = 5, .role = .client } }, 7, &scratch));
    try std.testing.expectError(error.OwnerSetMismatch, validateBijection(view, &.{ .{ .fd_index = 1, .role = .client }, .{ .fd_index = 4, .role = .canonical_mesh } }, 7, &scratch));
    try std.testing.expectError(error.DuplicateFdIndex, validateBijection(view, &.{ .{ .fd_index = 1, .role = .client }, .{ .fd_index = 1, .role = .canonical_mesh } }, 7, &scratch));
    try std.testing.expectError(error.ScratchSize, validateBijection(view, &.{ .{ .fd_index = 1, .role = .client }, .{ .fd_index = 5, .role = .canonical_mesh } }, 7, scratch[0..6]));
}

test "physical connection relation rejects corrupt framing, duplicates and sentinel" {
    const a = std.testing.allocator;
    const bytes = try encode(a, &.{ .{ .old_client = 0, .fd_index = 1 }, .{ .old_client = 2, .fd_index = 3 } }, 2);
    defer a.free(bytes);
    for (0..bytes.len) |len| try std.testing.expectError(error.Truncated, validateWire(bytes[0..len], 2, 4));
    try std.testing.expectError(error.CountLimit, validateWire(bytes, 1, 4));
    var longer: [header_len + 2 * row_len + 1]u8 = undefined;
    @memcpy(longer[0..bytes.len], bytes);
    longer[bytes.len] = 0;
    try std.testing.expectError(error.TrailingBytes, validateWire(&longer, 2, 4));
    var bad: [header_len + 2 * row_len]u8 = undefined;
    @memcpy(&bad, bytes);
    bad[0] = 'X';
    try std.testing.expectError(error.BadMagic, validateWire(&bad, 2, 4));
    @memcpy(&bad, bytes);
    bad[3] = '1';
    bad[4] = 1;
    try std.testing.expectError(error.BadMagic, validateWire(&bad, 2, 4));
    @memcpy(&bad, bytes);
    bad[header_len + 12] = 0;
    try std.testing.expectError(error.InvalidRole, validateWire(&bad, 2, 4));
    bad[header_len + 12] = 255;
    try std.testing.expectError(error.InvalidRole, validateWire(&bad, 2, 4));
    @memcpy(&bad, bytes);
    bad[4] = 1;
    try std.testing.expectError(error.BadVersion, validateWire(&bad, 2, 4));
    @memcpy(&bad, bytes);
    std.mem.writeInt(u64, bad[header_len + row_len ..][0..8], 0, .big);
    try std.testing.expectError(error.NonCanonicalOrder, validateWire(&bad, 2, 4));
    @memcpy(&bad, bytes);
    std.mem.writeInt(u32, bad[header_len + row_len + 8 ..][0..4], 4, .big);
    try std.testing.expectError(error.InvalidFdIndex, validateWire(&bad, 2, 4));
    @memcpy(&bad, bytes);
    bad[5] = 1;
    try std.testing.expectError(error.Reserved, validateWire(&bad, 2, 4));
    @memcpy(&bad, bytes);
    std.mem.writeInt(u64, bad[8..16], std.math.maxInt(u64), .big);
    try std.testing.expectError(error.CountLimit, validateWire(&bad, 2, 4));
    @memcpy(&bad, bytes);
    std.mem.writeInt(u32, bad[header_len + row_len + 8 ..][0..4], 1, .big);
    const structurally_valid = try validateWire(&bad, 2, 4);
    var scratch: [4]u8 = undefined;
    try std.testing.expectError(error.DuplicateFdIndex, validateBijection(structurally_valid, &.{ .{ .fd_index = 1, .role = .client }, .{ .fd_index = 3, .role = .client } }, 4, &scratch));
    try std.testing.expectError(error.InvalidClient, encode(a, &.{.{ .old_client = std.math.maxInt(u64), .fd_index = 0 }}, 1));
    try std.testing.expectError(error.DuplicateFdIndex, encode(a, &.{ .{ .old_client = 1, .fd_index = 0 }, .{ .old_client = 2, .fd_index = 0 } }, 2));
    try std.testing.expectError(error.NonCanonicalOrder, encode(a, &.{ .{ .old_client = 1, .fd_index = 0 }, .{ .old_client = 1, .fd_index = 1 } }, 2));
}

test "physical connection relation empty must have header and empty owners" {
    const a = std.testing.allocator;
    const bytes = try encode(a, &.{}, 0);
    defer a.free(bytes);
    try std.testing.expectError(error.Truncated, validateWire("", 0, 0));
    const view = try validateWire(bytes, 0, 3);
    var scratch: [3]u8 = undefined;
    _ = try validateBijection(view, &.{}, 3, &scratch);
    try std.testing.expectError(error.OwnerSetMismatch, validateBijection(view, &.{.{ .fd_index = 1, .role = .client }}, 3, &scratch));
}

fn allocationFailureEncode(a: std.mem.Allocator) !void {
    const bytes = try encode(a, &.{ .{ .old_client = 9, .fd_index = 3 }, .{ .old_client = 0, .fd_index = 1 } }, 2);
    defer a.free(bytes);
    _ = try validateWire(bytes, 2, 4);
}
test "physical connection relation encode allocation failures unwind" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationFailureEncode, .{});
}
