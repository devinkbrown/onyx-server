// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Dormant composite mesh authority for origin-signed E2EEGROUP controls.
//!
//! Owns one replay `Guard` plus one RAM hop-custody/`Receipt` `Outbox`. The
//! future server mutex serializes every operation externally; this leaf never
//! takes locks.
//!
//! Admission cut (prepare-first):
//! 1. `outbox.prepare` stages exact-wire peer obligations (or fails closed).
//! 2. Optional ingress receipt capacity is checked fail-closed.
//! 3. `guard.admitAuthorized` commits replay authority (window + watermark).
//! 4. On first `accepted`: publish custody, optional ingress receipt, and
//!    pending-exact identity when unsettled (custody or receipt). Local settled
//!    traffic (no peers, no ingress) never consumes pending capacity.
//! 5. On exact `duplicate` from a new ingress: reserve that peer's receipt only
//!    (never custody). Pending proof is retained while unsettled.
//! 6. `equivocation` / `retired` / `origin_capacity` abort prepared custody.
//!
//! Safe retirement: ACK removes outgoing custody; ACK_CONFIRM clears the ingress
//! receipt. When both are gone for a RelayId, pending exact is released. Ordinary
//! window still handles recent duplicates. EGRG seals RVG2 + pending exact +
//! receipts only when custody is empty (payload/wire never sealed).

const std = @import("std");

const group_outbox = @import("e2ee_group_outbox.zig");
const group_guard = @import("e2ee_group_replay_guard.zig");
const group_relay = @import("../substrate/undertow/e2ee_group_relay.zig");

pub const PublicKey = group_guard.PublicKey;
pub const RelayId = group_guard.RelayId;
pub const VerifiedRecord = group_guard.VerifiedRecord;
pub const AuthenticatedIdentity = group_guard.AuthenticatedIdentity;
pub const Verification = group_guard.Verification;
pub const Admission = group_guard.Admission;
pub const Decision = group_guard.Decision;
pub const IdentityLookup = group_guard.IdentityLookup;
pub const PrepareOutcome = group_outbox.PrepareOutcome;
pub const Obligation = group_outbox.Obligation;
pub const Receipt = group_outbox.Receipt;
pub const Snapshot = group_outbox.Snapshot;
pub const SnapshotEntry = group_outbox.SnapshotEntry;

pub const isFutureSkewed = group_guard.isFutureSkewed;

pub const Config = struct {
    replay: group_guard.Config = .{},
    max_outbox_entries: usize = group_outbox.default_max_entries,
    max_receipts: usize = group_outbox.default_max_entries,
};

pub const InitError = group_guard.InitError || error{InvalidConfig};
pub const CheckpointError = group_guard.CheckpointError || error{CustodyOutstanding};
pub const AdmitError = group_outbox.Error;

/// Decision plus any custody published in the same atomic cut.
/// Rejected admissions always report zero custody inserts/skips.
pub const AdmitWithCustody = struct {
    admission: Admission,
    custody: PrepareOutcome,
    /// True when a new ingress receipt was reserved in this cut.
    receipt_reserved: bool = false,
};

pub const isCheckpoint = group_guard.isCheckpoint;
pub const validateCheckpoint = group_guard.validateCheckpoint;

pub const Authority = struct {
    allocator: std.mem.Allocator,
    config: Config,
    guard: group_guard.Guard,
    outbox: group_outbox.Outbox,

    pub fn init(allocator: std.mem.Allocator, config: Config) InitError!Authority {
        var guard = try group_guard.Guard.init(allocator, config.replay);
        errdefer guard.deinit();
        const outbox = group_outbox.Outbox.initWithReceipts(
            allocator,
            config.max_outbox_entries,
            config.max_receipts,
        ) catch return error.InvalidConfig;
        return .{
            .allocator = allocator,
            .config = config,
            .guard = guard,
            .outbox = outbox,
        };
    }

    pub fn deinit(self: *Authority) void {
        self.outbox.deinit();
        self.guard.deinit();
        self.* = undefined;
    }

    pub fn authenticateRecord(
        self: *Authority,
        record: group_relay.RelayRecord,
    ) std.mem.Allocator.Error!AuthenticatedIdentity {
        return self.guard.authenticateRecord(record);
    }

    pub fn verifyRecord(
        self: *Authority,
        record: group_relay.RelayRecord,
        now_ms: u64,
        max_future_skew_ms: u64,
    ) std.mem.Allocator.Error!Verification {
        return self.guard.verifyRecord(record, now_ms, max_future_skew_ms);
    }

    pub fn probeIdentity(self: *const Authority, verified: VerifiedRecord) IdentityLookup {
        return self.guard.probeIdentity(verified);
    }

    /// Atomic prepare-first admit with optional ingress receipt. `ingress_peer`
    /// null means local/settled path for that hop (no receipt). Empty `peers`
    /// means no outgoing custody. Local settled (empty peers + null ingress)
    /// never reserves pending-exact capacity.
    ///
    /// Cut: outbox prepare (custody + optional receipt) → pending prepare →
    /// inner admit → one no-fail commit. OOM/capacity leave guard/outbox/pending
    /// byte-identical.
    pub fn admitAuthorizedWithCustody(
        self: *Authority,
        verified: VerifiedRecord,
        peers: []const u64,
        wire: []const u8,
    ) AdmitError!AdmitWithCustody {
        return self.admitAuthorizedWithCustodyAndIngress(
            verified,
            peers,
            wire,
            null,
            0,
        );
    }

    pub fn admitAuthorizedWithCustodyAndIngress(
        self: *Authority,
        verified: VerifiedRecord,
        peers: []const u64,
        wire: []const u8,
        ingress_peer: ?u64,
        retry_after_ms: u64,
    ) AdmitError!AdmitWithCustody {
        if (ingress_peer) |peer| if (peer == 0) return error.InvalidReceiptPeer;

        var prepared = try self.outbox.prepareWithIngress(
            peers,
            verified.relay_id,
            wire,
            ingress_peer,
            retry_after_ms,
        );
        defer prepared.deinit();

        // Pending is required only when this cut will leave RelayId unsettled
        // (new custody, new receipt, or already unsettled). Settled local never.
        const already_unsettled = self.outbox.isUnsettled(verified.relay_id);
        const will_unsettled_accepted = prepared.willPublishCustody() or
            prepared.willPublishReceipt() or already_unsettled;
        const will_unsettled_duplicate = prepared.willPublishReceipt() or already_unsettled;
        const needs_pending = (will_unsettled_accepted or will_unsettled_duplicate) and
            !self.guard.hasPendingExact(
                verified.origin_pubkey,
                verified.hlc,
                verified.relay_id,
            );

        var pending_prep: ?group_guard.PreparedPending = null;
        defer if (pending_prep) |*pp| pp.deinit();

        if (needs_pending) {
            switch (try self.guard.preparePendingExactResult(
                verified.origin_pubkey,
                verified.hlc,
                verified.relay_id,
            )) {
                .prepared => |pp| pending_prep = pp,
                .already => {},
                .origin_capacity => {
                    prepared.abort();
                    return .{
                        .admission = .origin_capacity,
                        .custody = .{ .inserted = 0, .skipped = 0 },
                    };
                },
                .equivocation => {
                    // Same origin+HLC already pending with a different RelayId —
                    // surface as admission equivocation (not a fallible error).
                    prepared.abort();
                    return .{
                        .admission = .equivocation,
                        .custody = .{ .inserted = 0, .skipped = 0 },
                    };
                },
            }
        }

        const admission = self.guard.admitAuthorized(verified) catch |err| {
            // Inner admit is OOM-atomic; aborts above leave outbox/pending unchanged.
            return err;
        };

        switch (admission) {
            .accepted => {
                if (!will_unsettled_accepted) {
                    if (pending_prep) |*pp| pp.abort();
                    pending_prep = null;
                } else if (pending_prep) |*pp| {
                    pp.commit();
                    pending_prep = null;
                }
                const receipt_reserved = prepared.willPublishReceipt();
                const custody = prepared.commitAccepted();
                return .{
                    .admission = admission,
                    .custody = custody,
                    .receipt_reserved = receipt_reserved,
                };
            },
            .duplicate => {
                if (!will_unsettled_duplicate) {
                    if (pending_prep) |*pp| pp.abort();
                    pending_prep = null;
                } else if (pending_prep) |*pp| {
                    pp.commit();
                    pending_prep = null;
                }
                const receipt_reserved = prepared.willPublishReceipt();
                _ = prepared.commitDuplicate();
                return .{
                    .admission = admission,
                    .custody = .{ .inserted = 0, .skipped = 0 },
                    .receipt_reserved = receipt_reserved,
                };
            },
            .equivocation, .retired, .origin_capacity => {
                if (pending_prep) |*pp| pp.abort();
                pending_prep = null;
                prepared.abort();
                return .{
                    .admission = admission,
                    .custody = .{ .inserted = 0, .skipped = 0 },
                };
            },
        }
    }

    /// Remove one authenticated peer's outgoing custody ACK. Retires pending
    /// exact when no custody and no ingress receipts remain for RelayId.
    pub fn acknowledge(
        self: *Authority,
        peer: u64,
        relay_id: RelayId,
    ) error{ PreparedMutationActive, InvalidPeer }!bool {
        return self.acknowledgeOutgoing(peer, relay_id);
    }

    pub fn acknowledgeOutgoing(
        self: *Authority,
        peer: u64,
        relay_id: RelayId,
    ) error{ PreparedMutationActive, InvalidPeer }!bool {
        const removed = try self.outbox.acknowledge(peer, relay_id);
        if (removed) self.releasePendingIfSettled(relay_id);
        return removed;
    }

    /// ACK with explicit origin identity (avoids origin scan).
    pub fn acknowledgeKnown(
        self: *Authority,
        peer: u64,
        relay_id: RelayId,
        origin_pubkey: PublicKey,
        hlc: u64,
    ) error{ PreparedMutationActive, InvalidPeer }!bool {
        const removed = try self.outbox.acknowledge(peer, relay_id);
        if (removed) self.maybeReleasePending(origin_pubkey, hlc, relay_id);
        return removed;
    }

    /// ACK_CONFIRM from the authenticated ingress peer. Retires pending when
    /// custody and all receipts for RelayId are gone.
    pub fn confirmReceipt(
        self: *Authority,
        peer: u64,
        relay_id: RelayId,
    ) error{ PreparedMutationActive, InvalidReceiptPeer }!bool {
        return self.confirmIngress(peer, relay_id);
    }

    pub fn confirmIngress(
        self: *Authority,
        peer: u64,
        relay_id: RelayId,
    ) error{ PreparedMutationActive, InvalidReceiptPeer }!bool {
        const removed = try self.outbox.confirmReceipt(peer, relay_id);
        if (removed) self.releasePendingIfSettled(relay_id);
        return removed;
    }

    pub fn confirmReceiptKnown(
        self: *Authority,
        peer: u64,
        relay_id: RelayId,
        origin_pubkey: PublicKey,
        hlc: u64,
    ) error{ PreparedMutationActive, InvalidReceiptPeer }!bool {
        const removed = try self.outbox.confirmReceipt(peer, relay_id);
        if (removed) self.maybeReleasePending(origin_pubkey, hlc, relay_id);
        return removed;
    }

    pub fn custodyLen(self: *const Authority) usize {
        return self.outbox.len();
    }

    pub fn receiptLen(self: *const Authority) usize {
        return self.outbox.receiptLen();
    }

    pub fn containsCustody(self: *const Authority, peer: u64, relay_id: RelayId) bool {
        return self.outbox.contains(peer, relay_id);
    }

    pub fn containsReceipt(self: *const Authority, peer: u64, relay_id: RelayId) bool {
        return self.outbox.containsReceipt(peer, relay_id);
    }

    pub fn receiptItems(self: *const Authority) []const Receipt {
        return self.outbox.receiptItems();
    }

    pub fn collectDueReceipts(self: *Authority, now_ms: u64, out: []Receipt) usize {
        return self.outbox.collectDueReceipts(now_ms, out);
    }

    /// Exact-match receipt send-attempt bookkeeping (saturating attempts + retry_after).
    pub fn markReceiptAttempt(
        self: *Authority,
        peer: u64,
        relay_id: RelayId,
        next_retry_ms: u64,
    ) error{ PreparedMutationActive, InvalidReceiptPeer }!bool {
        return self.outbox.markReceiptAttempt(peer, relay_id, next_retry_ms);
    }

    /// Drop pending-exact facts whose RelayId is fully settled (no custody, no
    /// receipt). Allocation-free: walks the live pending map without heap keys.
    pub fn pruneSettledPending(self: *Authority) void {
        while (true) {
            var released_any = false;
            var it = self.guard.pending.keyIterator();
            while (it.next()) |key_ptr| {
                const key = key_ptr.*;
                const facts = self.guard.exactHistoryOf(key);
                for (facts) |fact| {
                    if (self.outbox.isUnsettled(fact.relay_id)) continue;
                    _ = self.guard.releasePendingExact(key, fact.hlc, fact.relay_id);
                    released_any = true;
                    // Map may rehash on empty-origin removal; restart scan.
                    break;
                }
                if (released_any) break;
            }
            if (!released_any) break;
        }
    }

    pub fn retryItems(self: *const Authority) []const Obligation {
        return self.outbox.retryItems();
    }

    pub fn snapshot(self: *const Authority, allocator: std.mem.Allocator) std.mem.Allocator.Error!Snapshot {
        return self.outbox.snapshot(allocator);
    }

    /// RVG2 + pending exact + receipts. Fails closed while hop custody remains.
    pub fn encodeCheckpoint(
        self: *const Authority,
        allocator: std.mem.Allocator,
    ) CheckpointError![]u8 {
        if (self.outbox.len() != 0) return error.CustodyOutstanding;
        return self.guard.encodeCheckpointWithReceipts(
            allocator,
            self.outbox.receiptItems(),
        );
    }

    pub fn decodeCheckpoint(
        allocator: std.mem.Allocator,
        expected_config: Config,
        bytes: []const u8,
    ) CheckpointError!Authority {
        var outbox = group_outbox.Outbox.initWithReceipts(
            allocator,
            expected_config.max_outbox_entries,
            expected_config.max_receipts,
        ) catch return error.InvalidConfig;
        errdefer outbox.deinit();

        var decoded = try group_guard.Guard.decodeCheckpointWithReceipts(
            allocator,
            expected_config.replay,
            bytes,
        );
        errdefer {
            decoded.guard.deinit();
            decoded.receipts.deinit(allocator);
        }

        outbox.replaceReceipts(decoded.receipts.items) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.CapacityExceeded => return error.CapacityExceeded,
            error.InvalidReceiptPeer, error.Equivocation, error.PreparedMutationActive => return error.InvalidField,
            else => return error.InvalidField,
        };
        decoded.receipts.deinit(allocator);

        return .{
            .allocator = allocator,
            .config = expected_config,
            .guard = decoded.guard,
            .outbox = outbox,
        };
    }

    pub fn replaceFromCheckpoint(self: *Authority, bytes: []const u8) CheckpointError!void {
        if (self.outbox.len() != 0) return error.CustodyOutstanding;
        var replacement = try decodeCheckpoint(self.allocator, self.config, bytes);
        const previous = self.*;
        self.* = replacement;
        replacement = previous;
        replacement.deinit();
    }

    fn maybeReleasePending(
        self: *Authority,
        origin_pubkey: PublicKey,
        hlc: u64,
        relay_id: RelayId,
    ) void {
        if (self.outbox.isUnsettled(relay_id)) return;
        _ = self.guard.releasePendingExact(origin_pubkey, hlc, relay_id);
    }

    /// Allocation-free pending drop after custody/receipt settlement. Walks the
    /// live pending map (public field) without temporary key lists.
    fn releasePendingIfSettled(self: *Authority, relay_id: RelayId) void {
        if (self.outbox.isUnsettled(relay_id)) return;
        var it = self.guard.pending.keyIterator();
        while (it.next()) |key_ptr| {
            const key = key_ptr.*;
            for (self.guard.exactHistoryOf(key)) |fact| {
                if (!std.mem.eql(u8, &fact.relay_id, &relay_id)) continue;
                _ = self.guard.releasePendingExact(key, fact.hlc, relay_id);
                return;
            }
        }
    }
};

const testing = std.testing;
const sign = @import("../crypto/sign.zig");
const signed_frame = @import("../substrate/undertow/signed_frame.zig");
const mesh_clock = @import("../substrate/undertow/mesh_clock.zig");

const Fixture = struct {
    verified: VerifiedRecord,
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
    var guard = try group_guard.Guard.init(allocator, .{});
    defer guard.deinit();
    const verified = switch (try guard.verifyRecord(record, 0, 0)) {
        .verified => |identity| identity,
        else => return error.TestUnexpectedResult,
    };
    return .{
        .verified = verified,
        .wire = try group_relay.encode(allocator, record),
    };
}

fn testId(byte: u8) RelayId {
    return @splat(byte);
}

test "E2EEGROUP mesh authority authenticateRecord ignores wall clock; verifyRecord still skews" {
    var auth = try Authority.init(testing.allocator, .{ .max_outbox_entries = 2 });
    defer auth.deinit();
    var kp = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0xb2)));
    defer kp.deinit();
    var pubkey: [group_relay.pubkey_len]u8 = undefined;
    var signature: [group_relay.sig_len]u8 = undefined;
    const now_ms: u64 = 1_700_000_000_000;
    const hlc = (now_ms << mesh_clock.seq_bits) | 3;
    var record = group_relay.RelayRecord{
        .kind = .commit,
        .channel = "#secure",
        .source_prefix = "alice!user@example.invalid",
        .account = "alice",
        .from_device = "laptop.1",
        .payload = "YXV0aC1hdXRo",
        .origin_node = signed_frame.originShortId(kp.public_key),
        .hlc = hlc,
    };
    try group_relay.stampOrigin(testing.allocator, &record, &kp, &pubkey, &signature);

    const identity = switch (try auth.authenticateRecord(record)) {
        .verified => |verified| verified,
        else => return error.TestUnexpectedResult,
    };
    try testing.expectEqual(hlc, identity.hlc);
    try testing.expect(!isFutureSkewed(identity, now_ms, mesh_clock.default_max_future_skew_ms));
    try testing.expectEqual(
        std.meta.Tag(Verification).verified,
        std.meta.activeTag(try auth.verifyRecord(
            record,
            now_ms,
            mesh_clock.default_max_future_skew_ms,
        )),
    );

    var max_pubkey: [group_relay.pubkey_len]u8 = undefined;
    var max_signature: [group_relay.sig_len]u8 = undefined;
    var maxed = record;
    maxed.hlc = std.math.maxInt(u64);
    try group_relay.stampOrigin(testing.allocator, &maxed, &kp, &max_pubkey, &max_signature);
    const max_identity = switch (try auth.authenticateRecord(maxed)) {
        .verified => |verified| verified,
        else => return error.TestUnexpectedResult,
    };
    try testing.expect(isFutureSkewed(max_identity, now_ms, mesh_clock.default_max_future_skew_ms));
    try testing.expect(isFutureSkewed(
        max_identity,
        std.math.maxInt(u64),
        std.math.maxInt(u64),
    ));
    try testing.expectEqual(
        std.meta.Tag(Verification).future_skew,
        std.meta.activeTag(try auth.verifyRecord(
            maxed,
            std.math.maxInt(u64),
            std.math.maxInt(u64),
        )),
    );
    try testing.expectEqual(@as(usize, 0), auth.custodyLen());
}

test "E2EEGROUP mesh authority identity probe is non-mutating across unseen duplicate equivocation retired" {
    var first = try fixture(testing.allocator, 0xb1, 10, "UFJPQkUtRk9VTkQ");
    defer first.deinit(testing.allocator);
    var conflict = try fixture(testing.allocator, 0xb1, 10, "UFJPQkUtQ09ORkxJQ1Q");
    defer conflict.deinit(testing.allocator);
    try testing.expect(!std.mem.eql(u8, &first.verified.relay_id, &conflict.verified.relay_id));

    var auth = try Authority.init(testing.allocator, .{
        .replay = .{ .window_size = 1, .max_origins = 1, .exact_history_size = 2 },
        .max_outbox_entries = 2,
    });
    defer auth.deinit();

    try testing.expectEqual(IdentityLookup.unseen, auth.probeIdentity(first.verified));
    try testing.expectEqual(@as(usize, 0), auth.custodyLen());
    const empty_before = try auth.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(empty_before);
    try testing.expectEqual(IdentityLookup.unseen, auth.probeIdentity(first.verified));
    const empty_after = try auth.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(empty_after);
    try testing.expectEqualSlices(u8, empty_before, empty_after);

    // Unsettled admit (custody) retains pending exact.
    const accepted = try auth.admitAuthorizedWithCustody(first.verified, &.{1}, first.wire);
    try testing.expectEqual(
        std.meta.Tag(Admission).accepted,
        std.meta.activeTag(accepted.admission),
    );
    try testing.expectEqual(@as(usize, 1), auth.custodyLen());
    try testing.expectEqual(IdentityLookup.duplicate, auth.probeIdentity(first.verified));
    try testing.expectEqual(IdentityLookup.equivocation, auth.probeIdentity(conflict.verified));
    try testing.expectEqual(@as(usize, 1), auth.custodyLen());

    // Still unsettled: pending proves after window eviction.
    var newer = try fixture(testing.allocator, 0xb1, 20, "UFJPQkUtTkVXRVI");
    defer newer.deinit(testing.allocator);
    _ = try auth.admitAuthorizedWithCustody(newer.verified, &.{}, newer.wire);
    try testing.expectEqual(IdentityLookup.duplicate, auth.probeIdentity(first.verified));
    try testing.expectEqual(IdentityLookup.duplicate, auth.probeIdentity(newer.verified));

    // ACK settles first: pending released; recent newer stays in window.
    try testing.expect(try auth.acknowledge(1, first.verified.relay_id));
    try testing.expectEqual(@as(usize, 0), auth.custodyLen());
    try testing.expectEqual(IdentityLookup.retired, auth.probeIdentity(first.verified));
    try testing.expectEqual(IdentityLookup.duplicate, auth.probeIdentity(newer.verified));
    const settled = try auth.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(settled);
    const settled_again = try auth.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(settled_again);
    try testing.expectEqual(IdentityLookup.retired, auth.probeIdentity(first.verified));
    try testing.expectEqualSlices(u8, settled, settled_again);
}

test "E2EEGROUP mesh authority accepts with multi-peer custody atomically" {
    var encoded = try fixture(testing.allocator, 0xa1, 101, "QUNDRVBURUQ");
    defer encoded.deinit(testing.allocator);
    var auth = try Authority.init(testing.allocator, .{ .max_outbox_entries = 4 });
    defer auth.deinit();

    const result = try auth.admitAuthorizedWithCustody(
        encoded.verified,
        &.{ 7, 9, 7 },
        encoded.wire,
    );
    try testing.expectEqual(
        std.meta.Tag(Admission).accepted,
        std.meta.activeTag(result.admission),
    );
    try testing.expectEqual(PrepareOutcome{ .inserted = 2, .skipped = 1 }, result.custody);
    try testing.expectEqual(@as(usize, 2), auth.custodyLen());
    try testing.expect(auth.containsCustody(7, encoded.verified.relay_id));
    try testing.expect(auth.containsCustody(9, encoded.verified.relay_id));

    const retry = auth.retryItems();
    try testing.expectEqual(@as(usize, 2), retry.len);
    for (retry) |entry| {
        try testing.expectEqual(encoded.verified.relay_id, entry.relay_id);
        try testing.expectEqualSlices(u8, encoded.wire, entry.wire);
    }

    // Exact duplicate aborts prepared plan: zero inserts/skips, peer set frozen.
    const dup = try auth.admitAuthorizedWithCustody(
        encoded.verified,
        &.{7},
        encoded.wire,
    );
    try testing.expectEqual(
        std.meta.Tag(Admission).duplicate,
        std.meta.activeTag(dup.admission),
    );
    try testing.expectEqual(PrepareOutcome{ .inserted = 0, .skipped = 0 }, dup.custody);
    try testing.expectEqual(@as(usize, 2), auth.custodyLen());
}

test "E2EEGROUP mesh authority duplicate never adds newly eligible peers" {
    var encoded = try fixture(testing.allocator, 0xa2, 102, "RFVQLU5FVw");
    defer encoded.deinit(testing.allocator);
    var auth = try Authority.init(testing.allocator, .{ .max_outbox_entries = 4 });
    defer auth.deinit();

    const first = try auth.admitAuthorizedWithCustody(
        encoded.verified,
        &.{11},
        encoded.wire,
    );
    try testing.expectEqual(
        std.meta.Tag(Admission).accepted,
        std.meta.activeTag(first.admission),
    );
    try testing.expectEqual(@as(usize, 1), first.custody.inserted);

    const second = try auth.admitAuthorizedWithCustody(
        encoded.verified,
        &.{ 11, 12 },
        encoded.wire,
    );
    try testing.expectEqual(
        std.meta.Tag(Admission).duplicate,
        std.meta.activeTag(second.admission),
    );
    try testing.expectEqual(PrepareOutcome{ .inserted = 0, .skipped = 0 }, second.custody);
    try testing.expectEqual(@as(usize, 1), auth.custodyLen());
    try testing.expect(auth.containsCustody(11, encoded.verified.relay_id));
    try testing.expect(!auth.containsCustody(12, encoded.verified.relay_id));
}

test "E2EEGROUP mesh authority equivocation and never-admitted retired abort custody" {
    var first = try fixture(testing.allocator, 0xa3, 10, "RVFVSVY");
    defer first.deinit(testing.allocator);
    var conflicting = try fixture(testing.allocator, 0xa3, 10, "Q09ORkxJQ1Q");
    defer conflicting.deinit(testing.allocator);
    // Same origin seed+hlc but different payload ⇒ different RelayId (equivocation).
    try testing.expect(!std.mem.eql(u8, &first.verified.relay_id, &conflicting.verified.relay_id));
    try testing.expectEqualSlices(u8, &first.verified.origin_pubkey, &conflicting.verified.origin_pubkey);

    var auth = try Authority.init(testing.allocator, .{
        .replay = .{ .window_size = 2, .max_origins = 1, .exact_history_size = 4 },
        .max_outbox_entries = 4,
    });
    defer auth.deinit();

    _ = try auth.admitAuthorizedWithCustody(first.verified, &.{21}, first.wire);
    try testing.expectEqual(@as(usize, 1), auth.custodyLen());

    const eq = try auth.admitAuthorizedWithCustody(
        conflicting.verified,
        &.{22},
        conflicting.wire,
    );
    try testing.expectEqual(
        std.meta.Tag(Admission).equivocation,
        std.meta.activeTag(eq.admission),
    );
    try testing.expectEqual(PrepareOutcome{ .inserted = 0, .skipped = 0 }, eq.custody);
    try testing.expectEqual(@as(usize, 1), auth.custodyLen());
    try testing.expect(!auth.containsCustody(22, conflicting.verified.relay_id));
    try testing.expect(auth.containsCustody(21, first.verified.relay_id));

    // Fill window so the original HLC leaves greatest-W. Pending (custody still
    // unsettled on peer 21) proves the prior accept as duplicate (lost-ACK path).
    var mid = try fixture(testing.allocator, 0xa3, 20, "TUlELUhMQw");
    defer mid.deinit(testing.allocator);
    var high = try fixture(testing.allocator, 0xa3, 30, "SElHSC1ITEM");
    defer high.deinit(testing.allocator);
    _ = try auth.admitAuthorizedWithCustody(mid.verified, &.{}, mid.wire);
    _ = try auth.admitAuthorizedWithCustody(high.verified, &.{}, high.wire);

    const proven = try auth.admitAuthorizedWithCustody(
        first.verified,
        &.{23},
        first.wire,
    );
    try testing.expectEqual(
        std.meta.Tag(Admission).duplicate,
        std.meta.activeTag(proven.admission),
    );
    try testing.expectEqual(PrepareOutcome{ .inserted = 0, .skipped = 0 }, proven.custody);
    try testing.expect(!auth.containsCustody(23, first.verified.relay_id));
    try testing.expect(auth.containsCustody(21, first.verified.relay_id));

    // Never-admitted HLC below the watermark remains retired and aborts custody.
    var never = try fixture(testing.allocator, 0xa3, 5, "TkVWRVItSVRFTQ");
    defer never.deinit(testing.allocator);
    const retired = try auth.admitAuthorizedWithCustody(
        never.verified,
        &.{24},
        never.wire,
    );
    try testing.expectEqual(
        std.meta.Tag(Admission).retired,
        std.meta.activeTag(retired.admission),
    );
    try testing.expectEqual(PrepareOutcome{ .inserted = 0, .skipped = 0 }, retired.custody);
    try testing.expect(!auth.containsCustody(24, never.verified.relay_id));
}

test "E2EEGROUP mesh authority rejects RelayId and wire mismatches before mutation" {
    var encoded = try fixture(testing.allocator, 0xa4, 104, "TUlTTUFUQ0g");
    defer encoded.deinit(testing.allocator);
    var auth = try Authority.init(testing.allocator, .{ .max_outbox_entries = 2 });
    defer auth.deinit();

    var bad_id = encoded.verified;
    bad_id.relay_id = testId(0xff);
    try testing.expectError(
        error.RelayIdMismatch,
        auth.admitAuthorizedWithCustody(bad_id, &.{1}, encoded.wire),
    );
    try testing.expectEqual(@as(usize, 0), auth.custodyLen());

    // Guard still has no record of the identity.
    const accept = try auth.admitAuthorizedWithCustody(
        encoded.verified,
        &.{1},
        encoded.wire,
    );
    try testing.expectEqual(
        std.meta.Tag(Admission).accepted,
        std.meta.activeTag(accept.admission),
    );
}

test "E2EEGROUP mesh authority ACK removes exact peer and relay id" {
    var encoded = try fixture(testing.allocator, 0xa5, 105, "QUNLLVRFU1Q");
    defer encoded.deinit(testing.allocator);
    var second = try fixture(testing.allocator, 0xb5, 115, "U0VDT05ELUlE");
    defer second.deinit(testing.allocator);
    var auth = try Authority.init(testing.allocator, .{ .max_outbox_entries = 4 });
    defer auth.deinit();

    _ = try auth.admitAuthorizedWithCustody(encoded.verified, &.{ 31, 32 }, encoded.wire);
    _ = try auth.admitAuthorizedWithCustody(second.verified, &.{31}, second.wire);

    try testing.expect(!(try auth.acknowledge(31, testId(0x22))));
    try testing.expect(!(try auth.acknowledge(33, encoded.verified.relay_id)));
    try testing.expect(try auth.acknowledge(31, encoded.verified.relay_id));
    try testing.expect(!auth.containsCustody(31, encoded.verified.relay_id));
    try testing.expect(auth.containsCustody(31, second.verified.relay_id));
    try testing.expect(auth.containsCustody(32, encoded.verified.relay_id));
    try testing.expectEqual(@as(usize, 2), auth.custodyLen());

    var snap = try auth.snapshot(testing.allocator);
    defer snap.deinit();
    try testing.expectEqual(@as(usize, 2), snap.entries.len);
}

test "E2EEGROUP mesh authority allocation-failure never publishes guard-only acceptance" {
    var encoded = try fixture(testing.allocator, 0xa6, 106, "T09NLVNXRUVQ");
    defer encoded.deinit(testing.allocator);

    const Sweep = struct {
        fn run(
            allocator: std.mem.Allocator,
            verified: VerifiedRecord,
            wire: []const u8,
        ) !void {
            var auth = try Authority.init(allocator, .{
                .replay = .{ .window_size = 4, .max_origins = 4 },
                .max_outbox_entries = 4,
            });
            defer auth.deinit();

            const result = auth.admitAuthorizedWithCustody(
                verified,
                &.{ 41, 42 },
                wire,
            ) catch |err| {
                // No semantic mutation: empty custody. Guard admit is atomic on
                // OOM, and prepare-first abort never publishes partial wires.
                try testing.expectEqual(@as(usize, 0), auth.custodyLen());
                // Direct proof the verified record was not retained: a retained
                // exact fact re-admits allocation-free as `.duplicate`. Unseen
                // origin insert may still OOM under the failing allocator.
                const probe = auth.guard.admitAuthorized(verified) catch {
                    return err;
                };
                try testing.expectEqual(
                    std.meta.Tag(Admission).accepted,
                    std.meta.activeTag(probe),
                );
                return err;
            };

            try testing.expectEqual(
                std.meta.Tag(Admission).accepted,
                std.meta.activeTag(result.admission),
            );
            try testing.expectEqual(@as(usize, 2), result.custody.inserted);
            try testing.expectEqual(@as(usize, 2), auth.custodyLen());
            try testing.expect(auth.containsCustody(41, verified.relay_id));
            try testing.expect(auth.containsCustody(42, verified.relay_id));
            for (auth.retryItems()) |entry|
                try testing.expectEqualSlices(u8, wire, entry.wire);

            // Duplicate path aborts prepared custody; concurrent-style second
            // prepare cannot add peers even when the failing allocator succeeds.
            const more = try auth.admitAuthorizedWithCustody(
                verified,
                &.{ 41, 43 },
                wire,
            );
            try testing.expectEqual(
                std.meta.Tag(Admission).duplicate,
                std.meta.activeTag(more.admission),
            );
            try testing.expectEqual(PrepareOutcome{ .inserted = 0, .skipped = 0 }, more.custody);
            try testing.expectEqual(@as(usize, 2), auth.custodyLen());
            try testing.expect(!auth.containsCustody(43, verified.relay_id));
        }
    };
    try testing.checkAllAllocationFailures(
        testing.allocator,
        Sweep.run,
        .{ encoded.verified, encoded.wire },
    );
}

test "E2EEGROUP mesh authority checkpoint requires empty custody and restores metadata only" {
    const opaque_payload = "RE8tTk9ULUNIRUNLUE9JTlQtUEFZTE9BRA";
    var encoded = try fixture(testing.allocator, 0xa7, 107, opaque_payload);
    defer encoded.deinit(testing.allocator);
    const cfg = Config{
        .replay = .{ .window_size = 4, .max_origins = 2, .exact_history_size = 8 },
        .max_outbox_entries = 4,
    };
    var auth = try Authority.init(testing.allocator, cfg);
    defer auth.deinit();

    _ = try auth.admitAuthorizedWithCustody(
        encoded.verified,
        &.{ 51, 52 },
        encoded.wire,
    );
    try testing.expectError(error.CustodyOutstanding, auth.encodeCheckpoint(testing.allocator));
    try testing.expectError(
        error.CustodyOutstanding,
        auth.replaceFromCheckpoint(&[_]u8{}),
    );

    try testing.expect(try auth.acknowledge(51, encoded.verified.relay_id));
    try testing.expect(try auth.acknowledge(52, encoded.verified.relay_id));
    try testing.expectEqual(@as(usize, 0), auth.custodyLen());

    const checkpoint = try auth.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(checkpoint);
    try testing.expect(isCheckpoint(checkpoint));
    try testing.expect(std.mem.indexOf(u8, checkpoint, opaque_payload) == null);
    try testing.expectEqual(
        cfg.replay.window_size,
        (try validateCheckpoint(checkpoint)).window_size,
    );
    try testing.expectEqual(
        cfg.replay.exact_history_size,
        (try validateCheckpoint(checkpoint)).exact_history_size,
    );

    var restored = try Authority.decodeCheckpoint(testing.allocator, cfg, checkpoint);
    defer restored.deinit();
    try testing.expectEqual(@as(usize, 0), restored.custodyLen());
    // Exact history restores; event-time peer set is not republished on duplicate.
    const dup = try restored.admitAuthorizedWithCustody(
        encoded.verified,
        &.{ 51, 52, 53 },
        encoded.wire,
    );
    try testing.expectEqual(
        std.meta.Tag(Admission).duplicate,
        std.meta.activeTag(dup.admission),
    );
    try testing.expectEqual(PrepareOutcome{ .inserted = 0, .skipped = 0 }, dup.custody);
    try testing.expectEqual(@as(usize, 0), restored.custodyLen());
    try testing.expect(!restored.containsCustody(51, encoded.verified.relay_id));
    try testing.expect(!restored.containsCustody(52, encoded.verified.relay_id));
    try testing.expect(!restored.containsCustody(53, encoded.verified.relay_id));
}

test "E2EEGROUP mesh authority checkpoint restores pending exact after window eviction" {
    var target = try fixture(testing.allocator, 0xd1, 10, "RVhBQ1QtSElTVC1SRVNUT1JF");
    defer target.deinit(testing.allocator);
    const cfg = Config{
        .replay = .{ .window_size = 1, .max_origins = 1, .exact_history_size = 8 },
        .max_outbox_entries = 2,
        .max_receipts = 4,
    };
    var auth = try Authority.init(testing.allocator, cfg);
    defer auth.deinit();
    // Ingress receipt keeps target unsettled so pending survives window eviction.
    _ = try auth.admitAuthorizedWithCustodyAndIngress(
        target.verified,
        &.{},
        target.wire,
        77,
        0,
    );
    try testing.expect(auth.containsReceipt(77, target.verified.relay_id));

    var later = try fixture(testing.allocator, 0xd1, 20, "TEFURVItV0lORE9X");
    defer later.deinit(testing.allocator);
    _ = try auth.admitAuthorizedWithCustody(later.verified, &.{}, later.wire);
    try testing.expectEqual(IdentityLookup.duplicate, auth.probeIdentity(target.verified));

    // Seal requires empty custody; receipt + pending remain.
    const checkpoint = try auth.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(checkpoint);
    try testing.expect(std.mem.indexOf(u8, checkpoint, "RVhBQ1QtSElTVC1SRVNUT1JF") == null);

    var restored = try Authority.decodeCheckpoint(testing.allocator, cfg, checkpoint);
    defer restored.deinit();
    try testing.expectEqual(IdentityLookup.duplicate, restored.probeIdentity(target.verified));
    try testing.expect(restored.containsReceipt(77, target.verified.relay_id));
    const reack = try restored.admitAuthorizedWithCustody(target.verified, &.{61}, target.wire);
    try testing.expectEqual(
        std.meta.Tag(Admission).duplicate,
        std.meta.activeTag(reack.admission),
    );
    try testing.expectEqual(PrepareOutcome{ .inserted = 0, .skipped = 0 }, reack.custody);
    try testing.expect(!restored.containsCustody(61, target.verified.relay_id));
}

test "E2EEGROUP mesh authority pending capacity fails closed before custody publish" {
    var auth = try Authority.init(testing.allocator, .{
        .replay = .{ .window_size = 4, .max_origins = 1, .exact_history_size = 2 },
        .max_outbox_entries = 4,
    });
    defer auth.deinit();
    var a = try fixture(testing.allocator, 0xd2, 10, "Q0FQQUEtQQ");
    defer a.deinit(testing.allocator);
    var b = try fixture(testing.allocator, 0xd2, 20, "Q0FQQUEtQg");
    defer b.deinit(testing.allocator);
    var c = try fixture(testing.allocator, 0xd2, 30, "Q0FQQUEtQw");
    defer c.deinit(testing.allocator);

    // Unsettled admits fill pending slots (settled would not).
    _ = try auth.admitAuthorizedWithCustody(a.verified, &.{1}, a.wire);
    _ = try auth.admitAuthorizedWithCustody(b.verified, &.{2}, b.wire);
    const before_receipts = auth.receiptLen();
    const before_custody = auth.custodyLen();

    const refused = try auth.admitAuthorizedWithCustody(c.verified, &.{99}, c.wire);
    try testing.expectEqual(
        std.meta.Tag(Admission).origin_capacity,
        std.meta.activeTag(refused.admission),
    );
    try testing.expectEqual(PrepareOutcome{ .inserted = 0, .skipped = 0 }, refused.custody);
    try testing.expectEqual(before_custody, auth.custodyLen());
    try testing.expectEqual(before_receipts, auth.receiptLen());
    try testing.expect(!auth.containsCustody(99, c.verified.relay_id));
    try testing.expectEqual(IdentityLookup.duplicate, auth.probeIdentity(a.verified));
    try testing.expectEqual(IdentityLookup.unseen, auth.probeIdentity(c.verified));
}

test "E2EEGROUP mesh authority corrupt and config-mismatch replacement is atomic" {
    const cfg = Config{
        .replay = .{ .window_size = 2, .max_origins = 2 },
        .max_outbox_entries = 3,
    };
    var source = try Authority.init(testing.allocator, cfg);
    defer source.deinit();
    var encoded = try fixture(testing.allocator, 0xa8, 108, "UkVQTEFDRS1PSw");
    defer encoded.deinit(testing.allocator);
    _ = try source.admitAuthorizedWithCustody(encoded.verified, &.{}, encoded.wire);
    const checkpoint = try source.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(checkpoint);

    var live = try Authority.init(testing.allocator, cfg);
    defer live.deinit();
    var other = try fixture(testing.allocator, 0xa9, 109, "TElWRS1PUklH");
    defer other.deinit(testing.allocator);
    _ = try live.admitAuthorizedWithCustody(other.verified, &.{}, other.wire);

    const corrupt = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(corrupt);
    if (corrupt.len > 16) corrupt[16] ^= 1;
    try testing.expectError(error.ChecksumMismatch, live.replaceFromCheckpoint(corrupt));
    // Preexisting live fact remains.
    const still = try live.admitAuthorizedWithCustody(other.verified, &.{}, other.wire);
    try testing.expectEqual(
        std.meta.Tag(Admission).duplicate,
        std.meta.activeTag(still.admission),
    );

    var mismatched = try Authority.init(testing.allocator, .{
        .replay = .{ .window_size = 8, .max_origins = 2 },
        .max_outbox_entries = 3,
    });
    defer mismatched.deinit();
    _ = try mismatched.admitAuthorizedWithCustody(other.verified, &.{}, other.wire);
    try testing.expectError(
        error.ConfigMismatch,
        mismatched.replaceFromCheckpoint(checkpoint),
    );
    const still_mismatch = try mismatched.admitAuthorizedWithCustody(
        other.verified,
        &.{},
        other.wire,
    );
    try testing.expectEqual(
        std.meta.Tag(Admission).duplicate,
        std.meta.activeTag(still_mismatch.admission),
    );

    try live.replaceFromCheckpoint(checkpoint);
    const restored_dup = try live.admitAuthorizedWithCustody(
        encoded.verified,
        &.{},
        encoded.wire,
    );
    try testing.expectEqual(
        std.meta.Tag(Admission).duplicate,
        std.meta.activeTag(restored_dup.admission),
    );

    var local = try fixture(testing.allocator, 0xaa, 110, "U1dFRVAtUkVQ");
    defer local.deinit(testing.allocator);
    const ReplaceSweep = struct {
        fn run(
            allocator: std.mem.Allocator,
            expected: Config,
            bytes: []const u8,
            verified: VerifiedRecord,
            wire: []const u8,
        ) !void {
            var auth = try Authority.init(allocator, expected);
            defer auth.deinit();
            _ = try auth.admitAuthorizedWithCustody(verified, &.{}, wire);
            auth.replaceFromCheckpoint(bytes) catch |err| {
                // Failed replace must leave the preexisting origin fact intact.
                // Duplicate probe of a retained origin is allocation-free.
                try testing.expectEqual(
                    std.meta.Tag(Admission).duplicate,
                    std.meta.activeTag(try auth.guard.admitAuthorized(verified)),
                );
                try testing.expectEqual(@as(usize, 0), auth.custodyLen());
                return err;
            };
            // Successful replace swaps replay authority and keeps custody empty.
            try testing.expectEqual(@as(usize, 0), auth.custodyLen());
        }
    };
    try testing.checkAllAllocationFailures(
        testing.allocator,
        ReplaceSweep.run,
        .{ cfg, checkpoint, local.verified, local.wire },
    );
}

test "E2EEGROUP mesh authority accepted peers B/C ACK then duplicate B/C/D publishes zero custody" {
    var encoded = try fixture(testing.allocator, 0xc1, 201, "UkVGTE9PRC1DWUNMRQ");
    defer encoded.deinit(testing.allocator);
    var auth = try Authority.init(testing.allocator, .{ .max_outbox_entries = 4 });
    defer auth.deinit();

    const first = try auth.admitAuthorizedWithCustody(
        encoded.verified,
        &.{ 71, 72 }, // B/C
        encoded.wire,
    );
    try testing.expectEqual(
        std.meta.Tag(Admission).accepted,
        std.meta.activeTag(first.admission),
    );
    try testing.expectEqual(PrepareOutcome{ .inserted = 2, .skipped = 0 }, first.custody);
    try testing.expectEqual(@as(usize, 2), auth.custodyLen());

    try testing.expect(try auth.acknowledge(71, encoded.verified.relay_id));
    try testing.expect(try auth.acknowledge(72, encoded.verified.relay_id));
    try testing.expectEqual(@as(usize, 0), auth.custodyLen());

    // Later exact duplicate with B/C/D must abort prepared custody entirely.
    const again = try auth.admitAuthorizedWithCustody(
        encoded.verified,
        &.{ 71, 72, 73 }, // B/C/D
        encoded.wire,
    );
    try testing.expectEqual(
        std.meta.Tag(Admission).duplicate,
        std.meta.activeTag(again.admission),
    );
    try testing.expectEqual(PrepareOutcome{ .inserted = 0, .skipped = 0 }, again.custody);
    try testing.expectEqual(@as(usize, 0), auth.custodyLen());
    try testing.expect(!auth.containsCustody(71, encoded.verified.relay_id));
    try testing.expect(!auth.containsCustody(72, encoded.verified.relay_id));
    try testing.expect(!auth.containsCustody(73, encoded.verified.relay_id));

    // Cyclic re-publication stays quiesced — no non-quiescing reflood loop.
    var cycle: usize = 0;
    while (cycle < 4) : (cycle += 1) {
        const loop = try auth.admitAuthorizedWithCustody(
            encoded.verified,
            &.{ 71, 72, 71 },
            encoded.wire,
        );
        try testing.expectEqual(
            std.meta.Tag(Admission).duplicate,
            std.meta.activeTag(loop.admission),
        );
        try testing.expectEqual(PrepareOutcome{ .inserted = 0, .skipped = 0 }, loop.custody);
        try testing.expectEqual(@as(usize, 0), auth.custodyLen());
    }
}

test "E2EEGROUP mesh authority concurrent-style second prepared duplicate cannot add peers" {
    var encoded = try fixture(testing.allocator, 0xc3, 203, "Q09OQ1VSUi1EVVA");
    defer encoded.deinit(testing.allocator);
    var auth = try Authority.init(testing.allocator, .{ .max_outbox_entries = 8 });
    defer auth.deinit();

    // First admission freezes event-time peers {91, 92}.
    const first = try auth.admitAuthorizedWithCustody(
        encoded.verified,
        &.{ 91, 92 },
        encoded.wire,
    );
    try testing.expectEqual(
        std.meta.Tag(Admission).accepted,
        std.meta.activeTag(first.admission),
    );
    try testing.expectEqual(@as(usize, 2), auth.custodyLen());

    // Simulate an overlapping second prepare race: prepare stages a wider peer
    // set, but exact-duplicate admission aborts without publishing.
    var staged = try auth.outbox.prepare(&.{ 91, 92, 93, 94 }, encoded.verified.relay_id, encoded.wire);
    defer staged.deinit();
    try testing.expect(staged.outcome().inserted >= 1);
    try testing.expectEqual(
        std.meta.Tag(Admission).duplicate,
        std.meta.activeTag(try auth.guard.admitAuthorized(encoded.verified)),
    );
    staged.abort();
    try testing.expectEqual(@as(usize, 2), auth.custodyLen());
    try testing.expect(!auth.containsCustody(93, encoded.verified.relay_id));
    try testing.expect(!auth.containsCustody(94, encoded.verified.relay_id));

    // Full admit path for the same wider set must also publish zero custody.
    const second = try auth.admitAuthorizedWithCustody(
        encoded.verified,
        &.{ 91, 92, 93, 94 },
        encoded.wire,
    );
    try testing.expectEqual(
        std.meta.Tag(Admission).duplicate,
        std.meta.activeTag(second.admission),
    );
    try testing.expectEqual(PrepareOutcome{ .inserted = 0, .skipped = 0 }, second.custody);
    try testing.expectEqual(@as(usize, 2), auth.custodyLen());
    try testing.expect(!auth.containsCustody(93, encoded.verified.relay_id));
    try testing.expect(!auth.containsCustody(94, encoded.verified.relay_id));
}

test "E2EEGROUP mesh authority lost ACK remains proven after more than one replay window" {
    var target = try fixture(testing.allocator, 0xc2, 10, "TE9TVC1BQ0stVEFSR0VU");
    defer target.deinit(testing.allocator);
    var auth = try Authority.init(testing.allocator, .{
        .replay = .{ .window_size = 2, .max_origins = 1, .exact_history_size = 8 },
        .max_outbox_entries = 8,
    });
    defer auth.deinit();

    // Outstanding custody keeps pending exact while ACKs are lost.
    const accepted = try auth.admitAuthorizedWithCustody(target.verified, &.{80}, target.wire);
    try testing.expectEqual(
        std.meta.Tag(Admission).accepted,
        std.meta.activeTag(accepted.admission),
    );
    try testing.expect(auth.containsCustody(80, target.verified.relay_id));

    // More than one full window of later traffic ages the target out of W.
    const later_payloads = [_][]const u8{ "TEFURVIw", "TEFURVIx", "TEFURVIy", "TEFURVIz", "TEFURVI0" };
    for (later_payloads, 0..) |payload, i| {
        var later = try fixture(testing.allocator, 0xc2, 20 + i * 10, payload);
        defer later.deinit(testing.allocator);
        _ = try auth.admitAuthorizedWithCustody(later.verified, &.{}, later.wire);
    }

    try testing.expectEqual(IdentityLookup.duplicate, auth.probeIdentity(target.verified));
    const retry = try auth.admitAuthorizedWithCustody(
        target.verified,
        &.{81},
        target.wire,
    );
    try testing.expectEqual(
        std.meta.Tag(Admission).duplicate,
        std.meta.activeTag(retry.admission),
    );
    // Pending still proves the identity; duplicates never stage new peers.
    try testing.expectEqual(PrepareOutcome{ .inserted = 0, .skipped = 0 }, retry.custody);
    try testing.expect(!auth.containsCustody(81, target.verified.relay_id));
    try testing.expect(auth.containsCustody(80, target.verified.relay_id));
}

test "E2EEGROUP mesh authority receipt retry attempt API saturates and matches exactly" {
    var encoded = try fixture(testing.allocator, 0xe1, 301, "UkVDRUlQVC1SRVRSWQ");
    defer encoded.deinit(testing.allocator);
    var auth = try Authority.init(testing.allocator, .{
        .max_outbox_entries = 2,
        .max_receipts = 4,
    });
    defer auth.deinit();
    const first = try auth.admitAuthorizedWithCustodyAndIngress(
        encoded.verified,
        &.{},
        encoded.wire,
        11,
        50,
    );
    try testing.expect(first.receipt_reserved);
    try testing.expect(auth.containsReceipt(11, encoded.verified.relay_id));
    try testing.expect(!(try auth.markReceiptAttempt(12, encoded.verified.relay_id, 99)));
    try testing.expect(try auth.markReceiptAttempt(11, encoded.verified.relay_id, 200));
    try testing.expectEqual(@as(u32, 1), auth.receiptItems()[0].attempts);
    try testing.expectEqual(@as(u64, 200), auth.receiptItems()[0].retry_after_ms);
    var due_buf: [4]Receipt = undefined;
    try testing.expectEqual(@as(usize, 0), auth.collectDueReceipts(199, &due_buf));
    try testing.expectEqual(@as(usize, 1), auth.collectDueReceipts(200, &due_buf));
    // Confirm settles; pending released.
    try testing.expect(try auth.confirmIngress(11, encoded.verified.relay_id));
    try testing.expect(!auth.containsReceipt(11, encoded.verified.relay_id));
    try testing.expectEqual(@as(usize, 0), auth.guard.exactHistoryOf(encoded.verified.origin_pubkey).len);
}

test "E2EEGROUP mesh authority OOM around first admit and duplicate ingress leaves state identical" {
    var encoded = try fixture(testing.allocator, 0xe2, 302, "T09NLUFUT01JQw");
    defer encoded.deinit(testing.allocator);

    const Sweep = struct {
        fn run(
            allocator: std.mem.Allocator,
            verified: VerifiedRecord,
            wire: []const u8,
        ) !void {
            var auth = try Authority.init(allocator, .{
                .replay = .{ .window_size = 4, .max_origins = 4, .exact_history_size = 8 },
                .max_outbox_entries = 4,
                .max_receipts = 4,
            });
            defer auth.deinit();

            // First admit with custody + ingress.
            const first = auth.admitAuthorizedWithCustodyAndIngress(
                verified,
                &.{41},
                wire,
                7,
                0,
            ) catch |err| {
                try testing.expectEqual(@as(usize, 0), auth.custodyLen());
                try testing.expectEqual(@as(usize, 0), auth.receiptLen());
                try testing.expectEqual(@as(usize, 0), auth.guard.exactHistoryOf(verified.origin_pubkey).len);
                return err;
            };
            try testing.expectEqual(
                std.meta.Tag(Admission).accepted,
                std.meta.activeTag(first.admission),
            );
            try testing.expectEqual(@as(usize, 1), auth.custodyLen());
            try testing.expectEqual(@as(usize, 1), auth.receiptLen());

            const guard_cp = try auth.guard.encodeCheckpointWithReceipts(
                allocator,
                auth.receiptItems(),
            );
            defer allocator.free(guard_cp);
            const custody_before = auth.custodyLen();
            const receipt_before = auth.receiptLen();

            // Duplicate with new ingress peer under OOM must not mutate.
            const dup = auth.admitAuthorizedWithCustodyAndIngress(
                verified,
                &.{},
                wire,
                8,
                0,
            ) catch |err| {
                try testing.expectEqual(custody_before, auth.custodyLen());
                try testing.expectEqual(receipt_before, auth.receiptLen());
                const after = try auth.guard.encodeCheckpointWithReceipts(
                    allocator,
                    auth.receiptItems(),
                );
                defer allocator.free(after);
                try testing.expectEqualSlices(u8, guard_cp, after);
                return err;
            };
            try testing.expectEqual(
                std.meta.Tag(Admission).duplicate,
                std.meta.activeTag(dup.admission),
            );
            try testing.expect(dup.receipt_reserved);
            try testing.expect(auth.containsReceipt(8, verified.relay_id));
        }
    };
    try testing.checkAllAllocationFailures(
        testing.allocator,
        Sweep.run,
        .{ encoded.verified, encoded.wire },
    );
}

test "E2EEGROUP mesh authority healthy traffic exceeds 10x pending cap without pending pressure" {
    var auth = try Authority.init(testing.allocator, .{
        .replay = .{ .window_size = 4, .max_origins = 1, .exact_history_size = 2 },
        .max_outbox_entries = 4,
    });
    defer auth.deinit();
    // >10x pending cap of settled local admits must succeed (no pending use).
    const payloads = [_][]const u8{
        "SEVBTFRIWS0wMA", "SEVBTFRIWS0wMQ", "SEVBTFRIWS0wMg", "SEVBTFRIWS0wMw", "SEVBTFRIWS0wNA",
        "SEVBTFRIWS0wNQ", "SEVBTFRIWS0wNg", "SEVBTFRIWS0wNw", "SEVBTFRIWS0wOA", "SEVBTFRIWS0wOQ",
        "SEVBTFRIWS0xMA", "SEVBTFRIWS0xMQ", "SEVBTFRIWS0xMg", "SEVBTFRIWS0xMw", "SEVBTFRIWS0xNA",
        "SEVBTFRIWS0xNQ", "SEVBTFRIWS0xNg", "SEVBTFRIWS0xNw", "SEVBTFRIWS0xOA", "SEVBTFRIWS0xOQ",
        "SEVBTFRIWS0yMA", "SEVBTFRIWS0yMQ", "SEVBTFRIWS0yMg", "SEVBTFRIWS0yMw", "SEVBTFRIWS0yNA",
    };
    for (payloads, 0..) |payload, i| {
        var enc = try fixture(testing.allocator, 0xe3, 10 + i * 10, payload);
        defer enc.deinit(testing.allocator);
        const r = try auth.admitAuthorizedWithCustody(enc.verified, &.{}, enc.wire);
        try testing.expectEqual(
            std.meta.Tag(Admission).accepted,
            std.meta.activeTag(r.admission),
        );
        try testing.expectEqual(@as(usize, 0), auth.guard.exactHistoryOf(enc.verified.origin_pubkey).len);
    }
    try testing.expectEqual(@as(usize, 0), auth.custodyLen());
}

test "E2EEGROUP mesh authority lost ACK_CONFIRM remains proven beyond replay window" {
    var target = try fixture(testing.allocator, 0xe4, 10, "TE9TVC1DT05GSVJN");
    defer target.deinit(testing.allocator);
    var auth = try Authority.init(testing.allocator, .{
        .replay = .{ .window_size = 2, .max_origins = 1, .exact_history_size = 8 },
        .max_outbox_entries = 4,
        .max_receipts = 4,
    });
    defer auth.deinit();

    // Ingress receipt (no outgoing peers) keeps pending while ACK_CONFIRM is lost.
    const accepted = try auth.admitAuthorizedWithCustodyAndIngress(
        target.verified,
        &.{},
        target.wire,
        90,
        0,
    );
    try testing.expectEqual(
        std.meta.Tag(Admission).accepted,
        std.meta.activeTag(accepted.admission),
    );
    try testing.expect(accepted.receipt_reserved);
    try testing.expect(auth.containsReceipt(90, target.verified.relay_id));
    try testing.expectEqual(@as(usize, 1), auth.guard.exactHistoryOf(target.verified.origin_pubkey).len);

    // Age the target out of greatest-W with settled local traffic.
    const later_payloads = [_][]const u8{ "TEFURVItQQ", "TEFURVItQg", "TEFURVItQw", "TEFURVItRA", "TEFURVItRQ" };
    for (later_payloads, 0..) |payload, i| {
        var later = try fixture(testing.allocator, 0xe4, 20 + i * 10, payload);
        defer later.deinit(testing.allocator);
        _ = try auth.admitAuthorizedWithCustody(later.verified, &.{}, later.wire);
    }

    try testing.expectEqual(IdentityLookup.duplicate, auth.probeIdentity(target.verified));
    // Retransmit from a new ingress while ACK_CONFIRM is still outstanding: receipt
    // only, never custody, pending proof retained.
    const retry = try auth.admitAuthorizedWithCustodyAndIngress(
        target.verified,
        &.{91},
        target.wire,
        91,
        0,
    );
    try testing.expectEqual(
        std.meta.Tag(Admission).duplicate,
        std.meta.activeTag(retry.admission),
    );
    try testing.expectEqual(PrepareOutcome{ .inserted = 0, .skipped = 0 }, retry.custody);
    try testing.expect(retry.receipt_reserved);
    try testing.expect(!auth.containsCustody(91, target.verified.relay_id));
    try testing.expect(auth.containsReceipt(90, target.verified.relay_id));
    try testing.expect(auth.containsReceipt(91, target.verified.relay_id));

    try testing.expect(try auth.confirmIngress(90, target.verified.relay_id));
    try testing.expect(auth.outbox.isUnsettled(target.verified.relay_id));
    try testing.expectEqual(@as(usize, 1), auth.guard.exactHistoryOf(target.verified.origin_pubkey).len);
    try testing.expect(try auth.confirmIngress(91, target.verified.relay_id));
    try testing.expect(!auth.outbox.isUnsettled(target.verified.relay_id));
    try testing.expectEqual(@as(usize, 0), auth.guard.exactHistoryOf(target.verified.origin_pubkey).len);
}

test "E2EEGROUP mesh authority temporary partition capacity recovers after settle" {
    var auth = try Authority.init(testing.allocator, .{
        .replay = .{ .window_size = 8, .max_origins = 1, .exact_history_size = 2 },
        .max_outbox_entries = 8,
        .max_receipts = 8,
    });
    defer auth.deinit();
    var a = try fixture(testing.allocator, 0xe5, 10, "UEFSVC1B");
    defer a.deinit(testing.allocator);
    var b = try fixture(testing.allocator, 0xe5, 20, "UEFSVC1C");
    defer b.deinit(testing.allocator);
    var c = try fixture(testing.allocator, 0xe5, 30, "UEFSVC1D");
    defer c.deinit(testing.allocator);

    _ = try auth.admitAuthorizedWithCustodyAndIngress(a.verified, &.{1}, a.wire, 11, 0);
    _ = try auth.admitAuthorizedWithCustodyAndIngress(b.verified, &.{2}, b.wire, 12, 0);
    try testing.expectEqual(@as(usize, 2), auth.guard.exactHistoryOf(a.verified.origin_pubkey).len);

    const blocked = try auth.admitAuthorizedWithCustodyAndIngress(
        c.verified,
        &.{3},
        c.wire,
        13,
        0,
    );
    try testing.expectEqual(
        std.meta.Tag(Admission).origin_capacity,
        std.meta.activeTag(blocked.admission),
    );
    try testing.expectEqual(PrepareOutcome{ .inserted = 0, .skipped = 0 }, blocked.custody);
    try testing.expect(!auth.containsCustody(3, c.verified.relay_id));
    try testing.expect(!auth.containsReceipt(13, c.verified.relay_id));
    try testing.expectEqual(IdentityLookup.unseen, auth.probeIdentity(c.verified));

    // Settle A fully (ACK + ACK_CONFIRM) → pending slot frees allocation-free.
    try testing.expect(try auth.acknowledgeOutgoing(1, a.verified.relay_id));
    try testing.expect(try auth.confirmIngress(11, a.verified.relay_id));
    try testing.expectEqual(@as(usize, 1), auth.guard.exactHistoryOf(a.verified.origin_pubkey).len);

    const recovered = try auth.admitAuthorizedWithCustodyAndIngress(
        c.verified,
        &.{3},
        c.wire,
        13,
        0,
    );
    try testing.expectEqual(
        std.meta.Tag(Admission).accepted,
        std.meta.activeTag(recovered.admission),
    );
    try testing.expectEqual(@as(usize, 1), recovered.custody.inserted);
    try testing.expect(recovered.receipt_reserved);
    try testing.expect(auth.containsCustody(3, c.verified.relay_id));
    try testing.expect(auth.containsReceipt(13, c.verified.relay_id));
}

test "E2EEGROUP mesh authority allocation-free settlement via known ACK and ACK_CONFIRM" {
    // Single wrapper: admit under parent-forwarded alloc, then flip fail_allocs
    // so settle must be allocation-free. Free always hits the testing parent —
    // no post-admit allocator pointer swap on Authority fields.
    const ModeAlloc = struct {
        parent: std.mem.Allocator,
        fail_allocs: bool = false,

        fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
            const s: *@This() = @ptrCast(@alignCast(ctx));
            if (s.fail_allocs) return null;
            return s.parent.rawAlloc(len, alignment, ra);
        }
        fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) bool {
            const s: *@This() = @ptrCast(@alignCast(ctx));
            if (s.fail_allocs) return false;
            return s.parent.rawResize(memory, alignment, new_len, ra);
        }
        fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
            const s: *@This() = @ptrCast(@alignCast(ctx));
            if (s.fail_allocs) return null;
            return s.parent.rawRemap(memory, alignment, new_len, ra);
        }
        fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ra: usize) void {
            const s: *@This() = @ptrCast(@alignCast(ctx));
            s.parent.rawFree(memory, alignment, ra);
        }
        fn allocator(self: *@This()) std.mem.Allocator {
            return .{
                .ptr = self,
                .vtable = &.{
                    .alloc = alloc,
                    .resize = resize,
                    .remap = remap,
                    .free = free,
                },
            };
        }
    };

    var mode = ModeAlloc{ .parent = testing.allocator };
    const alloc = mode.allocator();
    var encoded = try fixture(alloc, 0xe6, 40, "U0VUVExFLUZSRUU");
    defer encoded.deinit(alloc);
    var auth = try Authority.init(alloc, .{
        .replay = .{ .window_size = 4, .max_origins = 2, .exact_history_size = 4 },
        .max_outbox_entries = 4,
        .max_receipts = 4,
    });
    defer auth.deinit();

    _ = try auth.admitAuthorizedWithCustodyAndIngress(
        encoded.verified,
        &.{ 5, 6 },
        encoded.wire,
        7,
        0,
    );
    try testing.expectEqual(@as(usize, 2), auth.custodyLen());
    try testing.expectEqual(@as(usize, 1), auth.receiptLen());
    try testing.expectEqual(@as(usize, 1), auth.guard.exactHistoryOf(encoded.verified.origin_pubkey).len);

    // Known settle paths release via releasePendingExact only (no key-list alloc).
    mode.fail_allocs = true;

    try testing.expect(try auth.acknowledgeKnown(
        5,
        encoded.verified.relay_id,
        encoded.verified.origin_pubkey,
        encoded.verified.hlc,
    ));
    try testing.expect(auth.outbox.isUnsettled(encoded.verified.relay_id));
    try testing.expectEqual(@as(usize, 1), auth.guard.exactHistoryOf(encoded.verified.origin_pubkey).len);

    try testing.expect(try auth.acknowledgeKnown(
        6,
        encoded.verified.relay_id,
        encoded.verified.origin_pubkey,
        encoded.verified.hlc,
    ));
    try testing.expect(auth.outbox.isUnsettled(encoded.verified.relay_id));
    try testing.expectEqual(@as(usize, 1), auth.guard.exactHistoryOf(encoded.verified.origin_pubkey).len);

    try testing.expect(try auth.confirmReceiptKnown(
        7,
        encoded.verified.relay_id,
        encoded.verified.origin_pubkey,
        encoded.verified.hlc,
    ));
    try testing.expect(!auth.outbox.isUnsettled(encoded.verified.relay_id));
    try testing.expectEqual(@as(usize, 0), auth.guard.exactHistoryOf(encoded.verified.origin_pubkey).len);
    try testing.expectEqual(@as(usize, 0), auth.custodyLen());
    try testing.expectEqual(@as(usize, 0), auth.receiptLen());
}

test "E2EEGROUP mesh authority first admit OOM sweep leaves byte-identical empty state" {
    var encoded = try fixture(testing.allocator, 0xe7, 50, "T09NLUZJUlNULUNVVA");
    defer encoded.deinit(testing.allocator);

    const Sweep = struct {
        fn run(
            allocator: std.mem.Allocator,
            verified: VerifiedRecord,
            wire: []const u8,
        ) !void {
            var auth = try Authority.init(allocator, .{
                .replay = .{ .window_size = 4, .max_origins = 4, .exact_history_size = 8 },
                .max_outbox_entries = 4,
                .max_receipts = 4,
            });
            defer auth.deinit();
            const before = try auth.guard.encodeCheckpointWithReceipts(allocator, &.{});
            defer allocator.free(before);

            const result = auth.admitAuthorizedWithCustodyAndIngress(
                verified,
                &.{ 21, 22 },
                wire,
                8,
                10,
            ) catch |err| {
                try testing.expectEqual(@as(usize, 0), auth.custodyLen());
                try testing.expectEqual(@as(usize, 0), auth.receiptLen());
                try testing.expectEqual(@as(usize, 0), auth.guard.exactHistoryOf(verified.origin_pubkey).len);
                const after = try auth.guard.encodeCheckpointWithReceipts(allocator, &.{});
                defer allocator.free(after);
                try testing.expectEqualSlices(u8, before, after);
                return err;
            };
            try testing.expectEqual(
                std.meta.Tag(Admission).accepted,
                std.meta.activeTag(result.admission),
            );
            try testing.expectEqual(@as(usize, 2), result.custody.inserted);
            try testing.expect(result.receipt_reserved);
            try testing.expectEqual(@as(usize, 2), auth.custodyLen());
            try testing.expectEqual(@as(usize, 1), auth.receiptLen());
            try testing.expectEqual(@as(usize, 1), auth.guard.exactHistoryOf(verified.origin_pubkey).len);
        }
    };
    try testing.checkAllAllocationFailures(
        testing.allocator,
        Sweep.run,
        .{ encoded.verified, encoded.wire },
    );
}

test "E2EEGROUP mesh authority duplicate new-ingress OOM never publishes custody or partial receipt" {
    var encoded = try fixture(testing.allocator, 0xe8, 60, "T09NLURVUC1JTkdS");
    defer encoded.deinit(testing.allocator);

    // checkAllAllocationFailures re-runs from empty; first cut may OOM too.
    // Accept either empty failure or successful first+failed/succeeded second.
    const SweepFull = struct {
        fn run(
            allocator: std.mem.Allocator,
            verified: VerifiedRecord,
            wire: []const u8,
        ) !void {
            var auth = try Authority.init(allocator, .{
                .replay = .{ .window_size = 4, .max_origins = 4, .exact_history_size = 8 },
                .max_outbox_entries = 4,
                .max_receipts = 4,
            });
            defer auth.deinit();
            const empty_cp = try auth.guard.encodeCheckpointWithReceipts(allocator, &.{});
            defer allocator.free(empty_cp);

            const first = auth.admitAuthorizedWithCustodyAndIngress(
                verified,
                &.{31},
                wire,
                40,
                0,
            ) catch |err| {
                try testing.expectEqual(@as(usize, 0), auth.custodyLen());
                try testing.expectEqual(@as(usize, 0), auth.receiptLen());
                const after = try auth.guard.encodeCheckpointWithReceipts(allocator, &.{});
                defer allocator.free(after);
                try testing.expectEqualSlices(u8, empty_cp, after);
                return err;
            };
            try testing.expectEqual(
                std.meta.Tag(Admission).accepted,
                std.meta.activeTag(first.admission),
            );
            const after_first = try auth.guard.encodeCheckpointWithReceipts(
                allocator,
                auth.receiptItems(),
            );
            defer allocator.free(after_first);
            const custody_before = auth.custodyLen();
            const receipt_before = auth.receiptLen();

            const dup = auth.admitAuthorizedWithCustodyAndIngress(
                verified,
                &.{ 31, 32 },
                wire,
                41,
                0,
            ) catch |err| {
                try testing.expectEqual(custody_before, auth.custodyLen());
                try testing.expectEqual(receipt_before, auth.receiptLen());
                try testing.expect(!auth.containsCustody(32, verified.relay_id));
                try testing.expect(!auth.containsReceipt(41, verified.relay_id));
                const after = try auth.guard.encodeCheckpointWithReceipts(
                    allocator,
                    auth.receiptItems(),
                );
                defer allocator.free(after);
                try testing.expectEqualSlices(u8, after_first, after);
                return err;
            };
            try testing.expectEqual(
                std.meta.Tag(Admission).duplicate,
                std.meta.activeTag(dup.admission),
            );
            try testing.expectEqual(PrepareOutcome{ .inserted = 0, .skipped = 0 }, dup.custody);
            try testing.expect(dup.receipt_reserved);
            try testing.expect(!auth.containsCustody(32, verified.relay_id));
            try testing.expect(auth.containsReceipt(40, verified.relay_id));
            try testing.expect(auth.containsReceipt(41, verified.relay_id));
        }
    };
    try testing.checkAllAllocationFailures(
        testing.allocator,
        SweepFull.run,
        .{ encoded.verified, encoded.wire },
    );
}

test "E2EEGROUP mesh authority non-known ACK and confirm release pending allocation-free" {
    // Same ModeAlloc pattern as known-ACK settle: one allocator identity for
    // admit + settle; flip fail_allocs after admit (no Authority field swap).
    const ModeAlloc = struct {
        parent: std.mem.Allocator,
        fail_allocs: bool = false,

        fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
            const s: *@This() = @ptrCast(@alignCast(ctx));
            if (s.fail_allocs) return null;
            return s.parent.rawAlloc(len, alignment, ra);
        }
        fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) bool {
            const s: *@This() = @ptrCast(@alignCast(ctx));
            if (s.fail_allocs) return false;
            return s.parent.rawResize(memory, alignment, new_len, ra);
        }
        fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
            const s: *@This() = @ptrCast(@alignCast(ctx));
            if (s.fail_allocs) return null;
            return s.parent.rawRemap(memory, alignment, new_len, ra);
        }
        fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ra: usize) void {
            const s: *@This() = @ptrCast(@alignCast(ctx));
            s.parent.rawFree(memory, alignment, ra);
        }
        fn allocator(self: *@This()) std.mem.Allocator {
            return .{
                .ptr = self,
                .vtable = &.{
                    .alloc = alloc,
                    .resize = resize,
                    .remap = remap,
                    .free = free,
                },
            };
        }
    };

    var mode = ModeAlloc{ .parent = testing.allocator };
    const alloc = mode.allocator();
    var encoded = try fixture(alloc, 0xe9, 70, "U0NBTi1SRUxFQVNF");
    defer encoded.deinit(alloc);
    var auth = try Authority.init(alloc, .{
        .max_outbox_entries = 4,
        .max_receipts = 4,
    });
    defer auth.deinit();
    _ = try auth.admitAuthorizedWithCustodyAndIngress(
        encoded.verified,
        &.{15},
        encoded.wire,
        16,
        0,
    );
    try testing.expectEqual(@as(usize, 1), auth.guard.exactHistoryOf(encoded.verified.origin_pubkey).len);

    mode.fail_allocs = true;

    try testing.expect(try auth.acknowledgeOutgoing(15, encoded.verified.relay_id));
    try testing.expect(auth.outbox.isUnsettled(encoded.verified.relay_id));
    try testing.expectEqual(@as(usize, 1), auth.guard.exactHistoryOf(encoded.verified.origin_pubkey).len);
    try testing.expect(try auth.confirmIngress(16, encoded.verified.relay_id));
    try testing.expect(!auth.outbox.isUnsettled(encoded.verified.relay_id));
    try testing.expectEqual(@as(usize, 0), auth.guard.exactHistoryOf(encoded.verified.origin_pubkey).len);
}
