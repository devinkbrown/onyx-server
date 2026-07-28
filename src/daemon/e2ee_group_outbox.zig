// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded hop-custody outbox for origin-signed E2EEGROUP controls.
//!
//! Each obligation is keyed by one authenticated direct peer and the immutable
//! E2EEGROUP `RelayId`. Only the exact canonical origin-signed wire is retained;
//! this module never decrypts the opaque group payload and has no offline-client
//! delivery, disk persistence, or Helix checkpoint semantics.
//!
//! The caller must serialize every operation on one `Outbox`, including the
//! complete interval from `prepare` through `Prepared.commit` or abort. Prepare
//! performs all validation and allocation and owns a complete replacement list.
//! Commit is allocation-free and cannot fail.

const std = @import("std");

const group_relay = @import("../substrate/undertow/e2ee_group_relay.zig");

pub const RelayId = group_relay.RelayId;
pub const default_max_entries: usize = 8192;
pub const hard_max_entries: usize = 65_536;

pub const Error = std.mem.Allocator.Error || error{
    InvalidConfig,
    InvalidPeer,
    InvalidWire,
    OriginMismatch,
    BadSignature,
    InvalidSemantic,
    NonCanonicalWire,
    RelayIdMismatch,
    Equivocation,
    CapacityExceeded,
    PreparedMutationActive,
};

/// Borrowed retry view. The wire remains valid until the next successful
/// mutation or `Outbox.deinit`.
pub const Obligation = struct {
    peer: u64,
    relay_id: RelayId,
    wire: []const u8,
};

pub const PrepareOutcome = struct {
    inserted: usize,
    skipped: usize,
};

/// Fully allocated candidate waiting to join a larger daemon admission cut.
/// Logically non-copyable: keep one mutable value and immediately install
/// `defer prepared.deinit()`.
pub const Prepared = struct {
    const State = enum { prepared, committed, aborted };

    outbox: *Outbox,
    expected_epoch: u64,
    candidate: std.ArrayListUnmanaged(Obligation),
    borrowed_len: usize,
    outcome_value: PrepareOutcome,
    replace_live: bool,
    state: State = .prepared,

    pub fn outcome(self: *const Prepared) PrepareOutcome {
        return self.outcome_value;
    }

    /// Publish the prepared obligations. This transfers every newly-owned wire
    /// into the live outbox, allocates nothing, and cannot fail.
    pub fn commit(self: *Prepared) PrepareOutcome {
        std.debug.assert(self.state == .prepared);
        std.debug.assert(self.outbox.prepared_active);
        std.debug.assert(self.outbox.mutation_epoch == self.expected_epoch);

        if (self.replace_live) {
            var previous = self.outbox.entries;
            self.outbox.entries = self.candidate;
            self.candidate = .empty;
            // The candidate shallow-copied the previous wires, so only the old
            // list allocation is retired here.
            previous.deinit(self.outbox.allocator);
        }
        self.outbox.prepared_active = false;
        self.outbox.bumpEpoch();
        self.state = .committed;
        return self.outcome_value;
    }

    /// Discard the candidate without changing the live obligation set.
    pub fn abort(self: *Prepared) void {
        if (self.state != .prepared) return;
        if (self.replace_live) {
            for (self.candidate.items[self.borrowed_len..]) |entry|
                self.outbox.allocator.free(entry.wire);
            self.candidate.deinit(self.outbox.allocator);
            self.candidate = .empty;
        }
        std.debug.assert(self.outbox.prepared_active);
        std.debug.assert(self.outbox.mutation_epoch == self.expected_epoch);
        self.outbox.prepared_active = false;
        self.state = .aborted;
    }

    pub fn deinit(self: *Prepared) void {
        if (self.state == .prepared) self.abort();
        self.* = undefined;
    }
};

pub const SnapshotEntry = struct {
    peer: u64,
    relay_id: RelayId,
    wire: []const u8,
};

/// Deep retry snapshot whose exact wires remain valid independently of the
/// source outbox.
pub const Snapshot = struct {
    allocator: std.mem.Allocator,
    entries: []SnapshotEntry,

    pub fn deinit(self: *Snapshot) void {
        for (self.entries) |entry| self.allocator.free(entry.wire);
        self.allocator.free(self.entries);
        self.* = undefined;
    }
};

pub const Outbox = struct {
    allocator: std.mem.Allocator,
    max_entries: usize,
    entries: std.ArrayListUnmanaged(Obligation) = .empty,
    mutation_epoch: u64 = 0,
    prepared_active: bool = false,

    pub fn init(allocator: std.mem.Allocator, max_entries: usize) error{InvalidConfig}!Outbox {
        if (max_entries == 0 or max_entries > hard_max_entries)
            return error.InvalidConfig;
        return .{
            .allocator = allocator,
            .max_entries = max_entries,
        };
    }

    pub fn deinit(self: *Outbox) void {
        std.debug.assert(!self.prepared_active);
        for (self.entries.items) |entry| self.allocator.free(entry.wire);
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn len(self: *const Outbox) usize {
        return self.entries.items.len;
    }

    pub fn contains(self: *const Outbox, peer: u64, relay_id: RelayId) bool {
        return self.indexOf(peer, relay_id) != null;
    }

    /// Allocation-free borrowed retry iteration. The caller must keep the
    /// outbox serialized while consuming the returned slice.
    pub fn retryItems(self: *const Outbox) []const Obligation {
        std.debug.assert(!self.prepared_active);
        return self.entries.items;
    }

    /// Deep-copy the current retry obligations for work that must outlive the
    /// caller's serialized access to this outbox.
    pub fn snapshot(self: *const Outbox, allocator: std.mem.Allocator) std.mem.Allocator.Error!Snapshot {
        std.debug.assert(!self.prepared_active);
        const entries = try allocator.alloc(SnapshotEntry, self.entries.items.len);
        var initialized: usize = 0;
        errdefer {
            for (entries[0..initialized]) |entry| allocator.free(entry.wire);
            allocator.free(entries);
        }
        for (self.entries.items) |entry| {
            entries[initialized] = .{
                .peer = entry.peer,
                .relay_id = entry.relay_id,
                .wire = try allocator.dupe(u8, entry.wire),
            };
            initialized += 1;
        }
        return .{
            .allocator = allocator,
            .entries = entries,
        };
    }

    /// Stage one exact-wire obligation for every distinct direct peer.
    ///
    /// The supplied `relay_id` must be the identity derived from a canonical,
    /// origin-authenticated E2EEGROUP wire. Existing identical peer/id
    /// obligations are idempotent. An existing peer/id with different bytes is
    /// equivocation. The returned plan owns all new wire copies and all list
    /// capacity required by `commit`; no live obligation changes before commit.
    pub fn prepare(
        self: *Outbox,
        peers: []const u64,
        relay_id: RelayId,
        wire: []const u8,
    ) Error!Prepared {
        if (self.prepared_active) return error.PreparedMutationActive;
        self.prepared_active = true;
        errdefer self.prepared_active = false;
        const expected_epoch = self.mutation_epoch;

        try validateWireAndId(self.allocator, relay_id, wire);
        if (peers.len > hard_max_entries) return error.CapacityExceeded;

        const sorted_peers = try self.allocator.dupe(u64, peers);
        defer self.allocator.free(sorted_peers);
        std.mem.sort(u64, sorted_peers, {}, std.sort.asc(u64));

        var unique_len: usize = 0;
        for (sorted_peers) |peer| {
            if (peer == 0) return error.InvalidPeer;
            if (unique_len != 0 and sorted_peers[unique_len - 1] == peer) continue;
            sorted_peers[unique_len] = peer;
            unique_len += 1;
        }
        const unique_peers = sorted_peers[0..unique_len];

        var needed: usize = 0;
        for (unique_peers) |peer| {
            if (self.indexOf(peer, relay_id)) |index| {
                if (!std.mem.eql(u8, self.entries.items[index].wire, wire))
                    return error.Equivocation;
            } else {
                needed += 1;
            }
        }
        if (needed > self.max_entries - self.entries.items.len)
            return error.CapacityExceeded;

        if (needed == 0) {
            return .{
                .outbox = self,
                .expected_epoch = expected_epoch,
                .candidate = .empty,
                .borrowed_len = 0,
                .outcome_value = .{
                    .inserted = 0,
                    .skipped = peers.len,
                },
                .replace_live = false,
            };
        }

        var candidate: std.ArrayListUnmanaged(Obligation) = .empty;
        var borrowed_len: usize = 0;
        errdefer {
            for (candidate.items[borrowed_len..]) |entry|
                self.allocator.free(entry.wire);
            candidate.deinit(self.allocator);
        }
        try candidate.ensureTotalCapacity(
            self.allocator,
            self.entries.items.len + needed,
        );
        candidate.appendSliceAssumeCapacity(self.entries.items);
        borrowed_len = self.entries.items.len;
        for (unique_peers) |peer| {
            if (self.indexOf(peer, relay_id) != null) continue;
            candidate.appendAssumeCapacity(.{
                .peer = peer,
                .relay_id = relay_id,
                .wire = try self.allocator.dupe(u8, wire),
            });
        }
        std.debug.assert(candidate.items.len == self.entries.items.len + needed);
        return .{
            .outbox = self,
            .expected_epoch = expected_epoch,
            .candidate = candidate,
            .borrowed_len = borrowed_len,
            .outcome_value = .{
                .inserted = needed,
                .skipped = peers.len - needed,
            },
            .replace_live = true,
        };
    }

    /// Remove exactly one authenticated direct peer's acknowledged RelayId.
    /// Authentication and direct-neighbor membership are daemon responsibilities
    /// above this dormant leaf.
    pub fn acknowledge(
        self: *Outbox,
        peer: u64,
        relay_id: RelayId,
    ) error{ PreparedMutationActive, InvalidPeer }!bool {
        if (self.prepared_active) return error.PreparedMutationActive;
        if (peer == 0) return error.InvalidPeer;
        const index = self.indexOf(peer, relay_id) orelse return false;
        const removed = self.entries.orderedRemove(index);
        self.allocator.free(removed.wire);
        self.bumpEpoch();
        return true;
    }

    fn indexOf(self: *const Outbox, peer: u64, relay_id: RelayId) ?usize {
        for (self.entries.items, 0..) |entry, index| {
            if (entry.peer == peer and idsEqual(entry.relay_id, relay_id))
                return index;
        }
        return null;
    }

    fn bumpEpoch(self: *Outbox) void {
        self.mutation_epoch +%= 1;
    }
};

fn idsEqual(a: RelayId, b: RelayId) bool {
    return std.mem.eql(u8, &a, &b);
}

fn validateWireAndId(
    allocator: std.mem.Allocator,
    expected_id: RelayId,
    wire: []const u8,
) Error!void {
    if (wire.len == 0 or wire.len > group_relay.max_wire_len)
        return error.InvalidWire;
    var owned = group_relay.decode(allocator, wire) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidWire,
    };
    defer owned.deinit(allocator);

    const derived = switch (try group_relay.verifyAndRelayId(allocator, owned.record)) {
        .verified => |id| id,
        .origin_mismatch => return error.OriginMismatch,
        .bad_signature => return error.BadSignature,
        .invalid_semantic => return error.InvalidSemantic,
    };
    if (!idsEqual(derived, expected_id)) return error.RelayIdMismatch;

    const canonical = group_relay.encode(allocator, owned.record) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidWire,
    };
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, wire)) return error.NonCanonicalWire;
}

const testing = std.testing;
const sign = @import("../crypto/sign.zig");
const signed_frame = @import("../substrate/undertow/signed_frame.zig");
const cpv = @import("../proto/coilpack_value.zig");

const Fixture = struct {
    relay_id: RelayId,
    wire: []u8,

    fn deinit(self: *Fixture, allocator: std.mem.Allocator) void {
        allocator.free(self.wire);
        self.* = undefined;
    }
};

fn fixture(
    allocator: std.mem.Allocator,
    seed: u8,
    hlc: u64,
    payload: []const u8,
) !Fixture {
    var kp = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(seed)));
    defer kp.deinit();
    var pubkey: [group_relay.pubkey_len]u8 = undefined;
    var signature: [group_relay.sig_len]u8 = undefined;
    var record = group_relay.RelayRecord{
        .kind = .commit,
        .channel = "#secure",
        .source_prefix = "alice!user@example.invalid",
        .account = "alice",
        .from_device = "laptop.1",
        .payload = payload,
        .origin_node = signed_frame.originShortId(kp.public_key),
        .hlc = hlc,
    };
    try group_relay.stampOrigin(allocator, &record, &kp, &pubkey, &signature);
    const relay_id = switch (try group_relay.verifyAndRelayId(allocator, record)) {
        .verified => |id| id,
        else => return error.TestUnexpectedResult,
    };
    return .{
        .relay_id = relay_id,
        .wire = try group_relay.encode(allocator, record),
    };
}

fn testId(byte: u8) RelayId {
    return @splat(byte);
}

fn reorderedMapWire(
    allocator: std.mem.Allocator,
    canonical: []const u8,
) ![]u8 {
    var value = try cpv.Decoder.decode(allocator, canonical);
    defer value.deinit(allocator);
    const entries = switch (value) {
        .map => |map| map,
        else => return error.TestUnexpectedResult,
    };
    if (entries.len >= 0x80) return error.TestUnexpectedResult;

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    // CoilPack map tag and single-byte canonical count. Values remain
    // canonical, but reverse key order must be rejected by the strict decoder.
    try out.append(allocator, 0x08);
    try out.append(allocator, @intCast(entries.len));
    var index = entries.len;
    while (index != 0) {
        index -= 1;
        const entry = entries[index];
        if (entry.key.len >= 0x80) return error.TestUnexpectedResult;
        try out.append(allocator, @intCast(entry.key.len));
        try out.appendSlice(allocator, entry.key);
        try cpv.Encoder.appendValue(allocator, &out, entry.value);
    }
    return out.toOwnedSlice(allocator);
}

test "E2EEGROUP outbox prepare commits deduplicated multi-peer exact wires" {
    var encoded = try fixture(testing.allocator, 0x81, 41, "AQIDBA");
    defer encoded.deinit(testing.allocator);
    var outbox = try Outbox.init(testing.allocator, 4);
    defer outbox.deinit();

    var prepared = try outbox.prepare(&.{ 9, 7, 9 }, encoded.relay_id, encoded.wire);
    defer prepared.deinit();
    try testing.expectEqual(@as(usize, 0), outbox.len());
    try testing.expectEqual(PrepareOutcome{ .inserted = 2, .skipped = 1 }, prepared.outcome());
    try testing.expectEqual(prepared.outcome(), prepared.commit());

    const retry = outbox.retryItems();
    try testing.expectEqual(@as(usize, 2), retry.len);
    try testing.expectEqual(@as(u64, 7), retry[0].peer);
    try testing.expectEqual(@as(u64, 9), retry[1].peer);
    for (retry) |entry| {
        try testing.expectEqual(encoded.relay_id, entry.relay_id);
        try testing.expectEqualSlices(u8, encoded.wire, entry.wire);
    }
}

test "E2EEGROUP outbox is idempotent and rejects id mismatch and equivocation" {
    var encoded = try fixture(testing.allocator, 0x82, 42, "BQYHCA");
    defer encoded.deinit(testing.allocator);
    var outbox = try Outbox.init(testing.allocator, 3);
    defer outbox.deinit();

    var first = try outbox.prepare(&.{11}, encoded.relay_id, encoded.wire);
    defer first.deinit();
    _ = first.commit();

    var duplicate = try outbox.prepare(&.{ 11, 11 }, encoded.relay_id, encoded.wire);
    defer duplicate.deinit();
    try testing.expectEqual(PrepareOutcome{ .inserted = 0, .skipped = 2 }, duplicate.commit());
    try testing.expectEqual(@as(usize, 1), outbox.len());

    try testing.expectError(
        error.RelayIdMismatch,
        outbox.prepare(&.{12}, testId(0xff), encoded.wire),
    );
    try testing.expectEqual(@as(usize, 1), outbox.len());

    // Simulate a corrupt/conflicting live obligation: the authentic canonical
    // input still matches its supplied id, but not the same peer/id's bytes.
    @constCast(outbox.entries.items[0].wire)[0] ^= 1;
    try testing.expectError(
        error.Equivocation,
        outbox.prepare(&.{11}, encoded.relay_id, encoded.wire),
    );
    try testing.expectEqual(@as(usize, 1), outbox.len());
}

test "E2EEGROUP outbox rejects noncanonical and wrong-origin wires before reservation" {
    var encoded = try fixture(testing.allocator, 0x83, 43, "CQoLDA");
    defer encoded.deinit(testing.allocator);
    var outbox = try Outbox.init(testing.allocator, 2);
    defer outbox.deinit();

    const trailing = try testing.allocator.alloc(u8, encoded.wire.len + 1);
    defer testing.allocator.free(trailing);
    @memcpy(trailing[0..encoded.wire.len], encoded.wire);
    trailing[encoded.wire.len] = 0;
    try testing.expectError(
        error.InvalidWire,
        outbox.prepare(&.{1}, encoded.relay_id, trailing),
    );

    const reordered = try reorderedMapWire(testing.allocator, encoded.wire);
    defer testing.allocator.free(reordered);
    try testing.expectError(
        error.InvalidWire,
        outbox.prepare(&.{1}, encoded.relay_id, reordered),
    );

    var owned = try group_relay.decode(testing.allocator, encoded.wire);
    defer owned.deinit(testing.allocator);
    owned.record.origin_node ^= 1;
    const wrong_origin = try group_relay.encode(testing.allocator, owned.record);
    defer testing.allocator.free(wrong_origin);
    try testing.expectError(
        error.OriginMismatch,
        outbox.prepare(&.{1}, encoded.relay_id, wrong_origin),
    );
    try testing.expectEqual(@as(usize, 0), outbox.len());
}

test "E2EEGROUP outbox ACK removes only the exact peer and relay id" {
    var encoded = try fixture(testing.allocator, 0x84, 44, "DQ4PEA");
    defer encoded.deinit(testing.allocator);
    var second = try fixture(testing.allocator, 0x94, 54, "JSYnKA");
    defer second.deinit(testing.allocator);
    var outbox = try Outbox.init(testing.allocator, 3);
    defer outbox.deinit();
    var prepared = try outbox.prepare(&.{ 21, 22 }, encoded.relay_id, encoded.wire);
    defer prepared.deinit();
    _ = prepared.commit();
    var same_peer = try outbox.prepare(&.{21}, second.relay_id, second.wire);
    defer same_peer.deinit();
    _ = same_peer.commit();

    try testing.expect(!(try outbox.acknowledge(21, testId(0x22))));
    try testing.expect(!(try outbox.acknowledge(23, encoded.relay_id)));
    try testing.expect(try outbox.acknowledge(21, encoded.relay_id));
    try testing.expect(!outbox.contains(21, encoded.relay_id));
    try testing.expect(outbox.contains(21, second.relay_id));
    try testing.expect(outbox.contains(22, encoded.relay_id));
    try testing.expectEqual(@as(usize, 2), outbox.len());
}

test "E2EEGROUP outbox capacity fails closed and exact duplicates still fit" {
    var encoded = try fixture(testing.allocator, 0x85, 45, "ERITFA");
    defer encoded.deinit(testing.allocator);
    var outbox = try Outbox.init(testing.allocator, 1);
    defer outbox.deinit();

    try testing.expectError(
        error.CapacityExceeded,
        outbox.prepare(&.{ 31, 32 }, encoded.relay_id, encoded.wire),
    );
    try testing.expectEqual(@as(usize, 0), outbox.len());

    var first = try outbox.prepare(&.{31}, encoded.relay_id, encoded.wire);
    defer first.deinit();
    _ = first.commit();
    var duplicate = try outbox.prepare(&.{31}, encoded.relay_id, encoded.wire);
    defer duplicate.deinit();
    _ = duplicate.commit();
    try testing.expectError(
        error.CapacityExceeded,
        outbox.prepare(&.{32}, encoded.relay_id, encoded.wire),
    );
    try testing.expectEqual(@as(usize, 1), outbox.len());
}

test "E2EEGROUP outbox abort leaves live storage and obligations unchanged" {
    var first_encoded = try fixture(testing.allocator, 0x86, 46, "FRYXGA");
    defer first_encoded.deinit(testing.allocator);
    var second_encoded = try fixture(testing.allocator, 0x87, 47, "GRobHA");
    defer second_encoded.deinit(testing.allocator);
    var outbox = try Outbox.init(testing.allocator, 3);
    defer outbox.deinit();

    var first = try outbox.prepare(&.{41}, first_encoded.relay_id, first_encoded.wire);
    defer first.deinit();
    _ = first.commit();
    const before_ptr = outbox.entries.items.ptr;
    const before_capacity = outbox.entries.capacity;
    const before_wire_ptr = outbox.entries.items[0].wire.ptr;

    var aborted = try outbox.prepare(&.{42}, second_encoded.relay_id, second_encoded.wire);
    defer aborted.deinit();
    try testing.expectEqual(@as(usize, 1), outbox.len());
    aborted.abort();
    try testing.expectEqual(@as(usize, 1), outbox.len());
    try testing.expectEqual(before_ptr, outbox.entries.items.ptr);
    try testing.expectEqual(before_capacity, outbox.entries.capacity);
    try testing.expectEqual(before_wire_ptr, outbox.entries.items[0].wire.ptr);
    try testing.expectEqualSlices(u8, first_encoded.wire, outbox.entries.items[0].wire);
}

test "E2EEGROUP outbox serializes prepare through commit or abort" {
    var encoded = try fixture(testing.allocator, 0x95, 55, "KSorLA");
    defer encoded.deinit(testing.allocator);
    var outbox = try Outbox.init(testing.allocator, 2);
    defer outbox.deinit();

    var held = try outbox.prepare(&.{45}, encoded.relay_id, encoded.wire);
    defer held.deinit();
    try testing.expectError(
        error.PreparedMutationActive,
        outbox.prepare(&.{46}, encoded.relay_id, encoded.wire),
    );
    try testing.expectError(
        error.PreparedMutationActive,
        outbox.acknowledge(45, encoded.relay_id),
    );
    held.abort();

    var retry = try outbox.prepare(&.{45}, encoded.relay_id, encoded.wire);
    defer retry.deinit();
    _ = retry.commit();
    try testing.expect(try outbox.acknowledge(45, encoded.relay_id));
    try testing.expectEqual(@as(usize, 0), outbox.len());
}

test "E2EEGROUP outbox prepare is allocation-failure atomic and leak free" {
    var baseline = try fixture(testing.allocator, 0x88, 48, "HR4fIA");
    defer baseline.deinit(testing.allocator);
    var addition = try fixture(testing.allocator, 0x89, 49, "ISIjJA");
    defer addition.deinit(testing.allocator);

    const Sweep = struct {
        fn run(
            allocator: std.mem.Allocator,
            baseline_wire: []const u8,
            baseline_id: RelayId,
            addition_wire: []const u8,
            addition_id: RelayId,
        ) !void {
            var outbox = try Outbox.init(allocator, 4);
            defer outbox.deinit();
            var initial = try outbox.prepare(&.{51}, baseline_id, baseline_wire);
            defer initial.deinit();
            _ = initial.commit();

            var prepared = outbox.prepare(
                &.{ 52, 53 },
                addition_id,
                addition_wire,
            ) catch |err| {
                try testing.expectEqual(@as(usize, 1), outbox.len());
                try testing.expect(outbox.contains(51, baseline_id));
                try testing.expectEqualSlices(u8, baseline_wire, outbox.retryItems()[0].wire);
                return err;
            };
            defer prepared.deinit();
            try testing.expectEqual(@as(usize, 1), outbox.len());
            _ = prepared.commit();
            try testing.expectEqual(@as(usize, 3), outbox.len());
        }
    };
    try testing.checkAllAllocationFailures(
        testing.allocator,
        Sweep.run,
        .{
            baseline.wire,
            baseline.relay_id,
            addition.wire,
            addition.relay_id,
        },
    );
}

test "E2EEGROUP outbox retry snapshot preserves opaque exact wire independently" {
    const opaque_payload = "AAECAwQFBgcICQ";
    var encoded = try fixture(testing.allocator, 0x8a, 50, opaque_payload);
    defer encoded.deinit(testing.allocator);
    var outbox = try Outbox.init(testing.allocator, 2);
    defer outbox.deinit();
    var prepared = try outbox.prepare(&.{ 61, 62 }, encoded.relay_id, encoded.wire);
    defer prepared.deinit();
    _ = prepared.commit();

    try testing.expectEqualSlices(u8, encoded.wire, outbox.retryItems()[0].wire);
    const SnapshotSweep = struct {
        fn run(allocator: std.mem.Allocator, source: *const Outbox, exact_wire: []const u8) !void {
            var snapshot_copy = try source.snapshot(allocator);
            defer snapshot_copy.deinit();
            try testing.expectEqual(@as(usize, 2), snapshot_copy.entries.len);
            for (snapshot_copy.entries) |entry|
                try testing.expectEqualSlices(u8, exact_wire, entry.wire);
        }
    };
    try testing.checkAllAllocationFailures(
        testing.allocator,
        SnapshotSweep.run,
        .{ &outbox, encoded.wire },
    );
    try testing.expectEqual(@as(usize, 2), outbox.len());

    var copied = try outbox.snapshot(testing.allocator);
    defer copied.deinit();
    try testing.expectEqual(@as(usize, 2), copied.entries.len);
    try testing.expectEqualSlices(u8, encoded.wire, copied.entries[0].wire);
    try testing.expect(std.mem.indexOf(u8, copied.entries[0].wire, opaque_payload) != null);

    try testing.expect(try outbox.acknowledge(61, encoded.relay_id));
    try testing.expectEqual(@as(usize, 1), outbox.retryItems().len);
    try testing.expectEqualSlices(u8, encoded.wire, copied.entries[0].wire);
}
