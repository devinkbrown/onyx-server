// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded hop-custody outbox + durable ingress Receipt ledger for origin-signed
//! E2EEGROUP controls.
//!
//! Custody obligations are keyed by one authenticated direct peer and the
//! immutable E2EEGROUP `RelayId`. Only the exact canonical origin-signed wire is
//! retained until that peer authenticates an ACK. This module never decrypts the
//! opaque group payload and never seals live wires into Helix (authority encode
//! fails closed while obligations remain).
//!
//! Ingress receipts are metadata-only (`peer`, `RelayId`, `retry_after_ms`,
//! `attempts`). They are not completed tombstones: the receiver retransmits ACK
//! until the original ingress peer returns authenticated ACK_CONFIRM. Receipts
//! never expire or rotate; capacity is fail-closed temporary backpressure.
//! EGRG Helix seals receipts (with pending exact identities) only when custody
//! is empty.
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
/// Hard ceiling for ingress receipts. Coherent with EGRG v2 wire which serializes
/// receipt count as `u16` (max 65535); config/runtime refuse anything larger.
pub const hard_max_receipts: usize = std.math.maxInt(u16);

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
    InvalidReceiptPeer,
};

/// Borrowed retry view. The wire remains valid until the next successful
/// mutation or `Outbox.deinit`.
pub const Obligation = struct {
    peer: u64,
    relay_id: RelayId,
    wire: []const u8,
};

/// Durable proof that one immediate peer's exact E2EEGROUP was admitted. Retried
/// via ACK until that peer authenticates ACK_CONFIRM. Never expires/rotates.
pub const Receipt = struct {
    peer: u64,
    relay_id: RelayId,
    retry_after_ms: u64,
    attempts: u32 = 0,
};

pub const PrepareOutcome = struct {
    inserted: usize,
    skipped: usize,
};

/// Fully allocated candidate waiting to join a larger daemon admission cut.
/// Stages event-time custody wires and an optional new ingress Receipt. Logically
/// non-copyable: keep one mutable value and immediately install `defer prepared.deinit()`.
///
/// Commit paths are allocation-free and cannot fail:
/// - `commitAccepted` publishes custody + optional receipt
/// - `commitDuplicate` publishes receipt only (never custody)
/// - `abort` discards both
pub const Prepared = struct {
    const State = enum { prepared, committed, aborted };

    outbox: *Outbox,
    expected_epoch: u64,
    candidate: std.ArrayListUnmanaged(Obligation),
    borrowed_len: usize,
    outcome_value: PrepareOutcome,
    replace_live: bool,
    /// Staged new ingress receipt (capacity already reserved on the live list).
    staged_receipt: ?Receipt = null,
    receipt_is_new: bool = false,
    state: State = .prepared,

    pub fn outcome(self: *const Prepared) PrepareOutcome {
        return self.outcome_value;
    }

    pub fn willPublishCustody(self: *const Prepared) bool {
        return self.replace_live and self.outcome_value.inserted > 0;
    }

    pub fn willPublishReceipt(self: *const Prepared) bool {
        return self.receipt_is_new;
    }

    /// Accepted cut: publish custody (if any) and optional new receipt. No-fail.
    pub fn commitAccepted(self: *Prepared) PrepareOutcome {
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
        self.publishReceiptIfNew();
        self.outbox.prepared_active = false;
        self.outbox.bumpEpoch();
        self.state = .committed;
        return self.outcome_value;
    }

    /// Duplicate cut: never publish custody; optional new receipt only. No-fail.
    pub fn commitDuplicate(self: *Prepared) PrepareOutcome {
        std.debug.assert(self.state == .prepared);
        std.debug.assert(self.outbox.prepared_active);
        std.debug.assert(self.outbox.mutation_epoch == self.expected_epoch);

        // Capture before publishReceiptIfNew clears the flag.
        const publish_receipt = self.receipt_is_new;
        if (self.replace_live) {
            for (self.candidate.items[self.borrowed_len..]) |entry|
                self.outbox.allocator.free(entry.wire);
            self.candidate.deinit(self.outbox.allocator);
            self.candidate = .empty;
        }
        self.publishReceiptIfNew();
        self.outbox.prepared_active = false;
        if (publish_receipt) self.outbox.bumpEpoch();
        self.state = .committed;
        return .{ .inserted = 0, .skipped = 0 };
    }

    /// Publish prepared obligations (accepted cut). Alias for `commitAccepted`.
    pub fn commit(self: *Prepared) PrepareOutcome {
        return self.commitAccepted();
    }

    /// Discard custody candidate and staged receipt without live mutation.
    pub fn abort(self: *Prepared) void {
        if (self.state != .prepared) return;
        if (self.replace_live) {
            for (self.candidate.items[self.borrowed_len..]) |entry|
                self.outbox.allocator.free(entry.wire);
            self.candidate.deinit(self.outbox.allocator);
            self.candidate = .empty;
        }
        // Receipt capacity reservation is only an ensureUnusedCapacity; drop the
        // staged fact without shrinking live storage.
        self.staged_receipt = null;
        self.receipt_is_new = false;
        std.debug.assert(self.outbox.prepared_active);
        std.debug.assert(self.outbox.mutation_epoch == self.expected_epoch);
        self.outbox.prepared_active = false;
        self.state = .aborted;
    }

    pub fn deinit(self: *Prepared) void {
        if (self.state == .prepared) self.abort();
        self.* = undefined;
    }

    fn publishReceiptIfNew(self: *Prepared) void {
        if (!self.receipt_is_new) return;
        const receipt = self.staged_receipt orelse return;
        // Capacity was reserved during prepare; append cannot fail.
        self.outbox.receipts.appendAssumeCapacity(receipt);
        self.staged_receipt = null;
        self.receipt_is_new = false;
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
    max_receipts: usize,
    entries: std.ArrayListUnmanaged(Obligation) = .empty,
    receipts: std.ArrayListUnmanaged(Receipt) = .empty,
    mutation_epoch: u64 = 0,
    prepared_active: bool = false,
    /// Non-authoritative fair-sweep cursor for due receipts. Never checkpointed.
    receipt_retry_cursor: usize = 0,

    pub fn init(allocator: std.mem.Allocator, max_entries: usize) error{InvalidConfig}!Outbox {
        return initWithReceipts(allocator, max_entries, max_entries);
    }

    pub fn initWithReceipts(
        allocator: std.mem.Allocator,
        max_entries: usize,
        max_receipts: usize,
    ) error{InvalidConfig}!Outbox {
        if (max_entries == 0 or max_entries > hard_max_entries)
            return error.InvalidConfig;
        if (max_receipts == 0 or max_receipts > hard_max_receipts)
            return error.InvalidConfig;
        return .{
            .allocator = allocator,
            .max_entries = max_entries,
            .max_receipts = max_receipts,
        };
    }

    pub fn deinit(self: *Outbox) void {
        std.debug.assert(!self.prepared_active);
        for (self.entries.items) |entry| self.allocator.free(entry.wire);
        self.entries.deinit(self.allocator);
        self.receipts.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn len(self: *const Outbox) usize {
        return self.entries.items.len;
    }

    pub fn receiptLen(self: *const Outbox) usize {
        return self.receipts.items.len;
    }

    pub fn contains(self: *const Outbox, peer: u64, relay_id: RelayId) bool {
        return self.indexOf(peer, relay_id) != null;
    }

    pub fn containsReceipt(self: *const Outbox, peer: u64, relay_id: RelayId) bool {
        return self.receiptIndexOf(peer, relay_id) != null;
    }

    pub fn containsAnyCustody(self: *const Outbox, relay_id: RelayId) bool {
        for (self.entries.items) |entry| {
            if (idsEqual(entry.relay_id, relay_id)) return true;
        }
        return false;
    }

    pub fn containsAnyReceipt(self: *const Outbox, relay_id: RelayId) bool {
        for (self.receipts.items) |receipt| {
            if (idsEqual(receipt.relay_id, relay_id)) return true;
        }
        return false;
    }

    pub fn isUnsettled(self: *const Outbox, relay_id: RelayId) bool {
        return self.containsAnyCustody(relay_id) or self.containsAnyReceipt(relay_id);
    }

    pub fn receiptItems(self: *const Outbox) []const Receipt {
        std.debug.assert(!self.prepared_active);
        return self.receipts.items;
    }

    pub fn mutableReceiptItems(self: *Outbox) []Receipt {
        std.debug.assert(!self.prepared_active);
        return self.receipts.items;
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

    /// Stage one exact-wire obligation for every distinct direct peer (no
    /// ingress receipt). See `prepareWithIngress`.
    pub fn prepare(
        self: *Outbox,
        peers: []const u64,
        relay_id: RelayId,
        wire: []const u8,
    ) Error!Prepared {
        return self.prepareWithIngress(peers, relay_id, wire, null, 0);
    }

    /// Stage event-time custody for every distinct direct peer and optionally
    /// one new ingress Receipt. All validation and allocation complete before
    /// return; live outbox/receipts are unchanged until a no-fail commit.
    ///
    /// The supplied `relay_id` must be the identity derived from a canonical,
    /// origin-authenticated E2EEGROUP wire. Existing identical peer/id
    /// obligations are idempotent. An existing peer/id with different bytes is
    /// equivocation. Existing peer/id receipts are idempotent (not re-staged).
    pub fn prepareWithIngress(
        self: *Outbox,
        peers: []const u64,
        relay_id: RelayId,
        wire: []const u8,
        ingress_peer: ?u64,
        retry_after_ms: u64,
    ) Error!Prepared {
        if (self.prepared_active) return error.PreparedMutationActive;
        self.prepared_active = true;
        errdefer self.prepared_active = false;
        const expected_epoch = self.mutation_epoch;

        try validateWireAndId(self.allocator, relay_id, wire);
        if (peers.len > hard_max_entries) return error.CapacityExceeded;

        var staged_receipt: ?Receipt = null;
        var receipt_is_new = false;
        if (ingress_peer) |peer| {
            if (peer == 0) return error.InvalidReceiptPeer;
            if (!self.containsReceipt(peer, relay_id)) {
                if (self.receipts.items.len >= self.max_receipts)
                    return error.CapacityExceeded;
                try self.receipts.ensureUnusedCapacity(self.allocator, 1);
                staged_receipt = .{
                    .peer = peer,
                    .relay_id = relay_id,
                    .retry_after_ms = retry_after_ms,
                    .attempts = 0,
                };
                receipt_is_new = true;
            }
        }

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
                .staged_receipt = staged_receipt,
                .receipt_is_new = receipt_is_new,
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
            .staged_receipt = staged_receipt,
            .receipt_is_new = receipt_is_new,
        };
    }

    /// Remove exactly one authenticated direct peer's acknowledged RelayId
    /// (outgoing custody). Authentication and direct-neighbor membership are
    /// daemon responsibilities above this leaf.
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

    /// Remove only the accepted-control receipt confirmed by its authenticated
    /// immediate peer (ACK_CONFIRM). Another peer cannot retire it.
    pub fn confirmReceipt(
        self: *Outbox,
        peer: u64,
        relay_id: RelayId,
    ) error{ PreparedMutationActive, InvalidReceiptPeer }!bool {
        if (self.prepared_active) return error.PreparedMutationActive;
        if (peer == 0) return error.InvalidReceiptPeer;
        const index = self.receiptIndexOf(peer, relay_id) orelse return false;
        _ = self.receipts.orderedRemove(index);
        self.repairReceiptCursor(index);
        self.bumpEpoch();
        return true;
    }

    /// Resume-fair collection of due receipts for ACK retransmit. Does not
    /// mutate retry_after_ms/attempts; the daemon updates those after send via
    /// `markReceiptAttempt`.
    pub fn collectDueReceipts(self: *Outbox, now_ms: u64, out: []Receipt) usize {
        std.debug.assert(!self.prepared_active);
        const total = self.receipts.items.len;
        if (total == 0) {
            self.receipt_retry_cursor = 0;
            return 0;
        }
        if (out.len == 0) return 0;
        var index = self.receipt_retry_cursor % total;
        var scanned: usize = 0;
        var collected: usize = 0;
        while (scanned < total and collected < out.len) : (scanned += 1) {
            const receipt = self.receipts.items[index];
            index = (index + 1) % total;
            if (now_ms < receipt.retry_after_ms) continue;
            out[collected] = receipt;
            collected += 1;
        }
        self.receipt_retry_cursor = index;
        return collected;
    }

    /// Record one outbound ACK send attempt for an exact peer/RelayId receipt.
    ///
    /// Policy: call once after each ACK transmit (or transmit attempt that
    /// consumed a send slot). Sets `retry_after_ms` to `next_retry_ms` and
    /// saturating-increments `attempts`. Returns false when no exact match.
    pub fn markReceiptAttempt(
        self: *Outbox,
        peer: u64,
        relay_id: RelayId,
        next_retry_ms: u64,
    ) error{ PreparedMutationActive, InvalidReceiptPeer }!bool {
        if (self.prepared_active) return error.PreparedMutationActive;
        if (peer == 0) return error.InvalidReceiptPeer;
        const index = self.receiptIndexOf(peer, relay_id) orelse return false;
        const receipt = &self.receipts.items[index];
        receipt.retry_after_ms = next_retry_ms;
        receipt.attempts = std.math.add(u32, receipt.attempts, 1) catch std.math.maxInt(u32);
        self.bumpEpoch();
        return true;
    }

    /// Deep-copy current receipts in canonical `(peer, relay_id)` order.
    /// Metadata only — no wires. Independent of live outbox after return.
    pub fn snapshotReceipts(
        self: *const Outbox,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error![]Receipt {
        std.debug.assert(!self.prepared_active);
        const out = try allocator.alloc(Receipt, self.receipts.items.len);
        @memcpy(out, self.receipts.items);
        std.mem.sort(Receipt, out, {}, receiptLess);
        return out;
    }

    /// Replace the live receipt set (Helix restore). Validates peer≠0 and unique
    /// `(peer, RelayId)`, installs a canonical sorted copy, and is allocation-
    /// failure atomic (OOM/validation leave self unchanged). Metadata only.
    pub fn replaceReceipts(self: *Outbox, next: []const Receipt) Error!void {
        if (self.prepared_active) return error.PreparedMutationActive;
        if (next.len > self.max_receipts) return error.CapacityExceeded;
        for (next) |receipt| {
            if (receipt.peer == 0) return error.InvalidReceiptPeer;
        }
        for (next, 0..) |receipt, i| {
            for (next[0..i]) |prior| {
                if (prior.peer == receipt.peer and idsEqual(prior.relay_id, receipt.relay_id))
                    return error.Equivocation;
            }
        }
        var staged: std.ArrayListUnmanaged(Receipt) = .empty;
        errdefer staged.deinit(self.allocator);
        try staged.ensureTotalCapacity(self.allocator, next.len);
        staged.appendSliceAssumeCapacity(next);
        std.mem.sort(Receipt, staged.items, {}, receiptLess);
        self.receipts.deinit(self.allocator);
        self.receipts = staged;
        self.receipt_retry_cursor = 0;
        self.bumpEpoch();
    }

    fn indexOf(self: *const Outbox, peer: u64, relay_id: RelayId) ?usize {
        for (self.entries.items, 0..) |entry, index| {
            if (entry.peer == peer and idsEqual(entry.relay_id, relay_id))
                return index;
        }
        return null;
    }

    fn receiptIndexOf(self: *const Outbox, peer: u64, relay_id: RelayId) ?usize {
        for (self.receipts.items, 0..) |receipt, index| {
            if (receipt.peer == peer and idsEqual(receipt.relay_id, relay_id))
                return index;
        }
        return null;
    }

    fn repairReceiptCursor(self: *Outbox, removed_index: usize) void {
        if (removed_index < self.receipt_retry_cursor) self.receipt_retry_cursor -= 1;
        if (self.receipts.items.len == 0) self.receipt_retry_cursor = 0;
    }

    fn bumpEpoch(self: *Outbox) void {
        self.mutation_epoch +%= 1;
    }
};

fn idsEqual(a: RelayId, b: RelayId) bool {
    return std.mem.eql(u8, &a, &b);
}

fn receiptLess(_: void, a: Receipt, b: Receipt) bool {
    if (a.peer != b.peer) return a.peer < b.peer;
    return std.mem.lessThan(u8, &a.relay_id, &b.relay_id);
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

test "E2EEGROUP outbox first prepareWithIngress commits custody and receipt" {
    var encoded = try fixture(testing.allocator, 0xb1, 61, "UkVDLUZJUlNU");
    defer encoded.deinit(testing.allocator);
    var outbox = try Outbox.initWithReceipts(testing.allocator, 4, 4);
    defer outbox.deinit();

    var prepared = try outbox.prepareWithIngress(
        &.{ 3, 5 },
        encoded.relay_id,
        encoded.wire,
        7,
        100,
    );
    defer prepared.deinit();
    try testing.expect(prepared.willPublishCustody());
    try testing.expect(prepared.willPublishReceipt());
    try testing.expectEqual(@as(usize, 0), outbox.len());
    try testing.expectEqual(@as(usize, 0), outbox.receiptLen());
    try testing.expectEqual(
        PrepareOutcome{ .inserted = 2, .skipped = 0 },
        prepared.commitAccepted(),
    );
    try testing.expectEqual(@as(usize, 2), outbox.len());
    try testing.expectEqual(@as(usize, 1), outbox.receiptLen());
    try testing.expect(outbox.containsReceipt(7, encoded.relay_id));
    try testing.expectEqual(@as(u64, 100), outbox.receiptItems()[0].retry_after_ms);
    try testing.expectEqual(@as(u32, 0), outbox.receiptItems()[0].attempts);
    try testing.expect(outbox.isUnsettled(encoded.relay_id));
}

test "E2EEGROUP outbox commitDuplicate publishes receipt only never custody" {
    var encoded = try fixture(testing.allocator, 0xb2, 62, "UkVDLURVUA"); // REC-DUP
    defer encoded.deinit(testing.allocator);
    var outbox = try Outbox.initWithReceipts(testing.allocator, 4, 4);
    defer outbox.deinit();

    // First accepted cut establishes custody for peer 9 only.
    var first = try outbox.prepareWithIngress(
        &.{9},
        encoded.relay_id,
        encoded.wire,
        11,
        0,
    );
    defer first.deinit();
    _ = first.commitAccepted();
    try testing.expectEqual(@as(usize, 1), outbox.len());
    try testing.expectEqual(@as(usize, 1), outbox.receiptLen());

    // Duplicate path with new peer obligations staged but must not publish them;
    // only a new ingress receipt (peer 12) is allowed to land.
    var dup = try outbox.prepareWithIngress(
        &.{ 9, 10 },
        encoded.relay_id,
        encoded.wire,
        12,
        50,
    );
    defer dup.deinit();
    try testing.expect(dup.willPublishCustody());
    try testing.expect(dup.willPublishReceipt());
    try testing.expectEqual(
        PrepareOutcome{ .inserted = 0, .skipped = 0 },
        dup.commitDuplicate(),
    );
    try testing.expectEqual(@as(usize, 1), outbox.len());
    try testing.expect(outbox.contains(9, encoded.relay_id));
    try testing.expect(!outbox.contains(10, encoded.relay_id));
    try testing.expectEqual(@as(usize, 2), outbox.receiptLen());
    try testing.expect(outbox.containsReceipt(11, encoded.relay_id));
    try testing.expect(outbox.containsReceipt(12, encoded.relay_id));

    // Existing receipt is idempotent (not re-staged).
    var same = try outbox.prepareWithIngress(&.{}, encoded.relay_id, encoded.wire, 11, 999);
    defer same.deinit();
    try testing.expect(!same.willPublishReceipt());
    _ = same.commitDuplicate();
    try testing.expectEqual(@as(usize, 2), outbox.receiptLen());
    try testing.expectEqual(@as(u64, 0), outbox.receiptItems()[0].retry_after_ms);
}

test "E2EEGROUP outbox first prepare OOM is allocation-failure atomic" {
    var encoded = try fixture(testing.allocator, 0xb3, 63, "T09NLUZJUlNU");
    defer encoded.deinit(testing.allocator);

    const Sweep = struct {
        fn run(allocator: std.mem.Allocator, wire: []const u8, relay_id: RelayId) !void {
            var outbox = try Outbox.initWithReceipts(allocator, 4, 4);
            defer outbox.deinit();
            var prepared = outbox.prepareWithIngress(
                &.{ 21, 22 },
                relay_id,
                wire,
                30,
                0,
            ) catch |err| {
                try testing.expectEqual(@as(usize, 0), outbox.len());
                try testing.expectEqual(@as(usize, 0), outbox.receiptLen());
                try testing.expect(!outbox.prepared_active);
                try testing.expect(!outbox.isUnsettled(relay_id));
                return err;
            };
            defer prepared.deinit();
            try testing.expectEqual(@as(usize, 0), outbox.len());
            try testing.expectEqual(@as(usize, 0), outbox.receiptLen());
            _ = prepared.commitAccepted();
            try testing.expectEqual(@as(usize, 2), outbox.len());
            try testing.expectEqual(@as(usize, 1), outbox.receiptLen());
        }
    };
    try testing.checkAllAllocationFailures(
        testing.allocator,
        Sweep.run,
        .{ encoded.wire, encoded.relay_id },
    );
}

test "E2EEGROUP outbox duplicate prepare OOM leaves prior custody and receipts intact" {
    var encoded = try fixture(testing.allocator, 0xb4, 64, "T09NLURVUExJ");
    defer encoded.deinit(testing.allocator);

    const Sweep = struct {
        fn run(allocator: std.mem.Allocator, wire: []const u8, relay_id: RelayId) !void {
            var outbox = try Outbox.initWithReceipts(allocator, 8, 8);
            defer outbox.deinit();
            var first = try outbox.prepareWithIngress(&.{41}, relay_id, wire, 7, 10);
            defer first.deinit();
            _ = first.commitAccepted();
            try testing.expectEqual(@as(usize, 1), outbox.len());
            try testing.expectEqual(@as(usize, 1), outbox.receiptLen());

            const epoch_before = outbox.mutation_epoch;
            var prepared = outbox.prepareWithIngress(
                &.{ 41, 42 },
                relay_id,
                wire,
                8,
                20,
            ) catch |err| {
                try testing.expectEqual(@as(usize, 1), outbox.len());
                try testing.expectEqual(@as(usize, 1), outbox.receiptLen());
                try testing.expect(outbox.contains(41, relay_id));
                try testing.expect(outbox.containsReceipt(7, relay_id));
                try testing.expect(!outbox.containsReceipt(8, relay_id));
                try testing.expect(!outbox.prepared_active);
                try testing.expectEqual(epoch_before, outbox.mutation_epoch);
                return err;
            };
            defer prepared.deinit();
            _ = prepared.commitDuplicate();
            try testing.expectEqual(@as(usize, 1), outbox.len());
            try testing.expect(!outbox.contains(42, relay_id));
            try testing.expectEqual(@as(usize, 2), outbox.receiptLen());
            try testing.expect(outbox.containsReceipt(8, relay_id));
        }
    };
    try testing.checkAllAllocationFailures(
        testing.allocator,
        Sweep.run,
        .{ encoded.wire, encoded.relay_id },
    );
}

test "E2EEGROUP outbox receipt capacity fails closed and recovers after confirm" {
    var a = try fixture(testing.allocator, 0xb5, 65, "Q0FQLUEx");
    defer a.deinit(testing.allocator);
    var b = try fixture(testing.allocator, 0xb6, 66, "Q0FQLUIy");
    defer b.deinit(testing.allocator);
    var c = try fixture(testing.allocator, 0xb7, 67, "Q0FQLUMz");
    defer c.deinit(testing.allocator);
    var outbox = try Outbox.initWithReceipts(testing.allocator, 4, 2);
    defer outbox.deinit();

    var p1 = try outbox.prepareWithIngress(&.{}, a.relay_id, a.wire, 1, 0);
    defer p1.deinit();
    _ = p1.commitAccepted();
    var p2 = try outbox.prepareWithIngress(&.{}, b.relay_id, b.wire, 2, 0);
    defer p2.deinit();
    _ = p2.commitAccepted();
    try testing.expectEqual(@as(usize, 2), outbox.receiptLen());

    try testing.expectError(
        error.CapacityExceeded,
        outbox.prepareWithIngress(&.{}, c.relay_id, c.wire, 3, 0),
    );
    try testing.expectEqual(@as(usize, 2), outbox.receiptLen());
    try testing.expect(!outbox.containsReceipt(3, c.relay_id));
    try testing.expect(!outbox.prepared_active);

    try testing.expect(try outbox.confirmReceipt(1, a.relay_id));
    try testing.expectEqual(@as(usize, 1), outbox.receiptLen());
    var p3 = try outbox.prepareWithIngress(&.{}, c.relay_id, c.wire, 3, 0);
    defer p3.deinit();
    _ = p3.commitAccepted();
    try testing.expect(outbox.containsReceipt(3, c.relay_id));
    try testing.expectEqual(@as(usize, 2), outbox.receiptLen());
}

test "E2EEGROUP outbox lost ACK_CONFIRM keeps receipt until exact-peer confirm" {
    var encoded = try fixture(testing.allocator, 0xb8, 68, "TE9TVC1DT05G");
    defer encoded.deinit(testing.allocator);
    var outbox = try Outbox.initWithReceipts(testing.allocator, 2, 4);
    defer outbox.deinit();

    var prepared = try outbox.prepareWithIngress(&.{}, encoded.relay_id, encoded.wire, 55, 0);
    defer prepared.deinit();
    _ = prepared.commitAccepted();

    // Simulate transmit then lost ACK_CONFIRM: schedule next attempt later.
    try testing.expect(try outbox.markReceiptAttempt(55, encoded.relay_id, 1_000));
    try testing.expectEqual(@as(u32, 1), outbox.receiptItems()[0].attempts);
    var due: [2]Receipt = undefined;
    try testing.expectEqual(@as(usize, 0), outbox.collectDueReceipts(999, &due));
    try testing.expectEqual(@as(usize, 1), outbox.collectDueReceipts(1_000, &due));
    try testing.expectEqual(@as(u64, 55), due[0].peer);

    // Retry forever: many attempts, still present.
    var attempt: u32 = 0;
    while (attempt < 8) : (attempt += 1) {
        try testing.expect(try outbox.markReceiptAttempt(55, encoded.relay_id, 2_000 + attempt));
    }
    try testing.expectEqual(@as(u32, 9), outbox.receiptItems()[0].attempts);
    try testing.expect(outbox.containsReceipt(55, encoded.relay_id));

    // Saturating attempts.
    outbox.mutableReceiptItems()[0].attempts = std.math.maxInt(u32);
    try testing.expect(try outbox.markReceiptAttempt(55, encoded.relay_id, 9_999));
    try testing.expectEqual(std.math.maxInt(u32), outbox.receiptItems()[0].attempts);
    try testing.expectEqual(@as(u64, 9_999), outbox.receiptItems()[0].retry_after_ms);

    // Wrong peer cannot retire; exact peer settles.
    try testing.expect(!(try outbox.confirmReceipt(56, encoded.relay_id)));
    try testing.expect(outbox.containsReceipt(55, encoded.relay_id));
    try testing.expect(try outbox.confirmReceipt(55, encoded.relay_id));
    try testing.expect(!outbox.containsReceipt(55, encoded.relay_id));
    try testing.expect(!outbox.isUnsettled(encoded.relay_id));
}

test "E2EEGROUP outbox collectDueReceipts is round-robin fair across cursor" {
    var r1 = try fixture(testing.allocator, 0xb9, 69, "Y3Vyc29yMQ");
    defer r1.deinit(testing.allocator);
    var r2 = try fixture(testing.allocator, 0xba, 70, "Y3Vyc29yMg");
    defer r2.deinit(testing.allocator);
    var r3 = try fixture(testing.allocator, 0xbb, 71, "Y3Vyc29yMw");
    defer r3.deinit(testing.allocator);
    var outbox = try Outbox.initWithReceipts(testing.allocator, 2, 8);
    defer outbox.deinit();

    inline for (.{
        .{ r1.relay_id, r1.wire, @as(u64, 1) },
        .{ r2.relay_id, r2.wire, @as(u64, 2) },
        .{ r3.relay_id, r3.wire, @as(u64, 3) },
    }) |row| {
        var prepared = try outbox.prepareWithIngress(&.{}, row[0], row[1], row[2], 0);
        defer prepared.deinit();
        _ = prepared.commitAccepted();
    }
    try testing.expectEqual(@as(usize, 3), outbox.receiptLen());

    var page: [1]Receipt = undefined;
    try testing.expectEqual(@as(usize, 1), outbox.collectDueReceipts(0, &page));
    try testing.expectEqual(@as(u64, 1), page[0].peer);
    try testing.expectEqual(@as(usize, 1), outbox.collectDueReceipts(0, &page));
    try testing.expectEqual(@as(u64, 2), page[0].peer);
    try testing.expectEqual(@as(usize, 1), outbox.collectDueReceipts(0, &page));
    try testing.expectEqual(@as(u64, 3), page[0].peer);
    try testing.expectEqual(@as(usize, 1), outbox.collectDueReceipts(0, &page));
    try testing.expectEqual(@as(u64, 1), page[0].peer);

    // Confirm mid-list repairs cursor without skipping unfairly forever.
    try testing.expect(try outbox.confirmReceipt(2, r2.relay_id));
    try testing.expectEqual(@as(usize, 1), outbox.collectDueReceipts(0, &page));
    try testing.expect(page[0].peer == 1 or page[0].peer == 3);
}

test "E2EEGROUP outbox snapshotReceipts and replaceReceipts are canonical and OOM-atomic" {
    var a = try fixture(testing.allocator, 0xbc, 72, "U05BUC1B");
    defer a.deinit(testing.allocator);
    var b = try fixture(testing.allocator, 0xbd, 73, "U05BUC1C");
    defer b.deinit(testing.allocator);
    var outbox = try Outbox.initWithReceipts(testing.allocator, 2, 8);
    defer outbox.deinit();

    // Install out of order so replace must canonicalize.
    const raw = [_]Receipt{
        .{ .peer = 20, .relay_id = b.relay_id, .retry_after_ms = 5, .attempts = 2 },
        .{ .peer = 10, .relay_id = a.relay_id, .retry_after_ms = 1, .attempts = 0 },
    };
    try outbox.replaceReceipts(&raw);
    try testing.expectEqual(@as(usize, 2), outbox.receiptLen());
    try testing.expectEqual(@as(u64, 10), outbox.receiptItems()[0].peer);
    try testing.expectEqual(@as(u64, 20), outbox.receiptItems()[1].peer);
    try testing.expectEqual(@as(u32, 0), outbox.receiptItems()[0].attempts);
    try testing.expectEqual(@as(u32, 2), outbox.receiptItems()[1].attempts);

    try testing.expectError(error.InvalidReceiptPeer, outbox.replaceReceipts(&[_]Receipt{.{
        .peer = 0,
        .relay_id = a.relay_id,
        .retry_after_ms = 0,
        .attempts = 0,
    }}));
    try testing.expectError(error.Equivocation, outbox.replaceReceipts(&[_]Receipt{
        .{ .peer = 10, .relay_id = a.relay_id, .retry_after_ms = 0, .attempts = 0 },
        .{ .peer = 10, .relay_id = a.relay_id, .retry_after_ms = 1, .attempts = 1 },
    }));
    // Failed validation leaves prior receipts intact.
    try testing.expectEqual(@as(usize, 2), outbox.receiptLen());

    const snap = try outbox.snapshotReceipts(testing.allocator);
    defer testing.allocator.free(snap);
    try testing.expectEqual(@as(usize, 2), snap.len);
    try testing.expectEqual(@as(u64, 10), snap[0].peer);
    try testing.expectEqual(@as(u64, 20), snap[1].peer);

    // Independent restore into empty outbox.
    var restored = try Outbox.initWithReceipts(testing.allocator, 2, 8);
    defer restored.deinit();
    try restored.replaceReceipts(snap);
    try testing.expectEqual(@as(usize, 2), restored.receiptLen());
    try testing.expectEqualSlices(u8, &a.relay_id, &restored.receiptItems()[0].relay_id);
    try testing.expectEqual(@as(u32, 2), restored.receiptItems()[1].attempts);

    const ReplaceSweep = struct {
        fn run(allocator: std.mem.Allocator, rows: []const Receipt) !void {
            var box = try Outbox.initWithReceipts(allocator, 2, 8);
            defer box.deinit();
            // Seed one receipt so failed replace must preserve it.
            try box.replaceReceipts(rows[0..1]);
            box.replaceReceipts(rows) catch |err| {
                try testing.expectEqual(@as(usize, 1), box.receiptLen());
                try testing.expectEqual(rows[0].peer, box.receiptItems()[0].peer);
                return err;
            };
            try testing.expectEqual(rows.len, box.receiptLen());
        }
    };
    try testing.checkAllAllocationFailures(
        testing.allocator,
        ReplaceSweep.run,
        .{&raw},
    );
}

test "E2EEGROUP outbox settled recovery releases isUnsettled after ack and confirm" {
    var encoded = try fixture(testing.allocator, 0xbe, 74, "U0VUVExFRA"); // SETTLED
    defer encoded.deinit(testing.allocator);
    var outbox = try Outbox.initWithReceipts(testing.allocator, 4, 4);
    defer outbox.deinit();

    var prepared = try outbox.prepareWithIngress(
        &.{99},
        encoded.relay_id,
        encoded.wire,
        88,
        0,
    );
    defer prepared.deinit();
    _ = prepared.commitAccepted();
    try testing.expect(outbox.isUnsettled(encoded.relay_id));
    try testing.expect(outbox.containsAnyCustody(encoded.relay_id));
    try testing.expect(outbox.containsAnyReceipt(encoded.relay_id));

    try testing.expect(try outbox.acknowledge(99, encoded.relay_id));
    try testing.expect(outbox.isUnsettled(encoded.relay_id)); // receipt remains
    try testing.expect(try outbox.confirmReceipt(88, encoded.relay_id));
    try testing.expect(!outbox.isUnsettled(encoded.relay_id));
    try testing.expectEqual(@as(usize, 0), outbox.len());
    try testing.expectEqual(@as(usize, 0), outbox.receiptLen());

    // Capacity fully recovered for a new admit of the same identity metadata.
    var again = try outbox.prepareWithIngress(&.{}, encoded.relay_id, encoded.wire, 88, 0);
    defer again.deinit();
    try testing.expect(again.willPublishReceipt());
    _ = again.commitAccepted();
    try testing.expect(outbox.containsReceipt(88, encoded.relay_id));
}

test "E2EEGROUP outbox hard_max_receipts is u16-coherent and boundary-checked" {
    try testing.expectEqual(@as(usize, std.math.maxInt(u16)), hard_max_receipts);
    try testing.expectEqual(@as(usize, 65_535), hard_max_receipts);
    try testing.expectError(
        error.InvalidConfig,
        Outbox.initWithReceipts(testing.allocator, 1, hard_max_receipts + 1),
    );
    try testing.expectError(
        error.InvalidConfig,
        Outbox.initWithReceipts(testing.allocator, 1, 65_536),
    );
    try testing.expectError(
        error.InvalidConfig,
        Outbox.initWithReceipts(testing.allocator, 1, 0),
    );
    var at_max = try Outbox.initWithReceipts(testing.allocator, 1, hard_max_receipts);
    defer at_max.deinit();
    try testing.expectEqual(hard_max_receipts, at_max.max_receipts);

    // Runtime replace also refuses anything above the configured max (including
    // the hard ceiling when configured at max).
    const over = try testing.allocator.alloc(Receipt, hard_max_receipts + 1);
    defer testing.allocator.free(over);
    for (over, 0..) |*row, i| {
        row.* = .{
            .peer = i + 1,
            .relay_id = testId(@intCast(i % 256)),
            .retry_after_ms = 0,
            .attempts = 0,
        };
    }
    try testing.expectError(error.CapacityExceeded, at_max.replaceReceipts(over));
    try testing.expectEqual(@as(usize, 0), at_max.receiptLen());
}

test "E2EEGROUP outbox abort drops staged receipt without live mutation" {
    var encoded = try fixture(testing.allocator, 0xbf, 75, "QUJPUlQx");
    defer encoded.deinit(testing.allocator);
    var outbox = try Outbox.initWithReceipts(testing.allocator, 4, 4);
    defer outbox.deinit();

    var held = try outbox.prepareWithIngress(&.{1}, encoded.relay_id, encoded.wire, 2, 0);
    defer held.deinit();
    try testing.expect(held.willPublishReceipt());
    try testing.expectError(
        error.PreparedMutationActive,
        outbox.confirmReceipt(2, encoded.relay_id),
    );
    try testing.expectError(
        error.PreparedMutationActive,
        outbox.markReceiptAttempt(2, encoded.relay_id, 1),
    );
    held.abort();
    try testing.expectEqual(@as(usize, 0), outbox.len());
    try testing.expectEqual(@as(usize, 0), outbox.receiptLen());
    try testing.expect(!outbox.prepared_active);
}
