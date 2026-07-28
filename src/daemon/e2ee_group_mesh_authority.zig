// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Dormant composite mesh authority for origin-signed E2EEGROUP controls.
//!
//! Owns one replay `Guard` plus one RAM hop-custody `Outbox`. The future server
//! mutex serializes every operation externally; this leaf never takes locks.
//!
//! Admission cut (prepare-first):
//! 1. `outbox.prepare` stages exact-wire peer obligations (or fails closed).
//! 2. `guard.admitAuthorized` commits replay authority.
//! 3. On `accepted` or exact `duplicate`, `Prepared.commit` publishes custody
//!    allocation-free. On `equivocation` / `retired` / `origin_capacity` or any
//!    error after prepare, the prepared plan aborts and the live outbox is
//!    unchanged. Allocation failure after prepare never publishes custody and
//!    never leaves guard-only acceptance.
//!
//! Helix checkpoints encode guard metadata only and only when the outbox is
//! empty (`CustodyOutstanding` otherwise). Opaque control payloads are never
//! checkpointed. Decode/replace create or require empty custody and stay
//! allocation-failure atomic. No disk or offline-client persistence.

const std = @import("std");

const group_outbox = @import("e2ee_group_outbox.zig");
const group_guard = @import("e2ee_group_replay_guard.zig");
const group_relay = @import("../substrate/undertow/e2ee_group_relay.zig");

pub const PublicKey = group_guard.PublicKey;
pub const RelayId = group_guard.RelayId;
pub const VerifiedRecord = group_guard.VerifiedRecord;
pub const Verification = group_guard.Verification;
pub const Admission = group_guard.Admission;
pub const Decision = group_guard.Decision;
pub const PrepareOutcome = group_outbox.PrepareOutcome;
pub const Obligation = group_outbox.Obligation;
pub const Snapshot = group_outbox.Snapshot;
pub const SnapshotEntry = group_outbox.SnapshotEntry;

pub const Config = struct {
    replay: group_guard.Config = .{},
    max_outbox_entries: usize = group_outbox.default_max_entries,
};

pub const InitError = group_guard.InitError || error{InvalidConfig};
pub const CheckpointError = group_guard.CheckpointError || error{CustodyOutstanding};
pub const AdmitError = group_outbox.Error;

/// Decision plus any custody published in the same atomic cut.
/// Rejected admissions always report zero custody inserts/skips.
pub const AdmitWithCustody = struct {
    admission: Admission,
    custody: PrepareOutcome,
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
        const outbox = group_outbox.Outbox.init(allocator, config.max_outbox_entries) catch
            return error.InvalidConfig;
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

    /// Authenticate without mutating replay or custody state.
    pub fn verifyRecord(
        self: *Authority,
        record: group_relay.RelayRecord,
        now_ms: u64,
        max_future_skew_ms: u64,
    ) std.mem.Allocator.Error!Verification {
        return self.guard.verifyRecord(record, now_ms, max_future_skew_ms);
    }

    /// Atomic prepare-first admit: stage hop custody, then commit replay, then
    /// publish custody only for `accepted` / exact `duplicate`.
    pub fn admitAuthorizedWithCustody(
        self: *Authority,
        verified: VerifiedRecord,
        peers: []const u64,
        wire: []const u8,
    ) AdmitError!AdmitWithCustody {
        var prepared = try self.outbox.prepare(peers, verified.relay_id, wire);
        defer prepared.deinit();

        const admission = self.guard.admitAuthorized(verified) catch |err| {
            // defer aborts prepared; live outbox and guard (on OOM) stay clean.
            return err;
        };

        switch (admission) {
            .accepted, .duplicate => {
                const custody = prepared.commit();
                return .{
                    .admission = admission,
                    .custody = custody,
                };
            },
            .equivocation, .retired, .origin_capacity => {
                prepared.abort();
                return .{
                    .admission = admission,
                    .custody = .{ .inserted = 0, .skipped = 0 },
                };
            },
        }
    }

    /// Remove exactly one authenticated direct peer's acknowledged RelayId.
    pub fn acknowledge(
        self: *Authority,
        peer: u64,
        relay_id: RelayId,
    ) error{ PreparedMutationActive, InvalidPeer }!bool {
        return self.outbox.acknowledge(peer, relay_id);
    }

    pub fn custodyLen(self: *const Authority) usize {
        return self.outbox.len();
    }

    pub fn containsCustody(self: *const Authority, peer: u64, relay_id: RelayId) bool {
        return self.outbox.contains(peer, relay_id);
    }

    /// Borrowed retry view; valid until the next successful mutation or deinit.
    pub fn retryItems(self: *const Authority) []const Obligation {
        return self.outbox.retryItems();
    }

    /// Deep retry snapshot independent of the live outbox.
    pub fn snapshot(self: *const Authority, allocator: std.mem.Allocator) std.mem.Allocator.Error!Snapshot {
        return self.outbox.snapshot(allocator);
    }

    /// Guard-metadata Helix checkpoint. Fails closed while hop custody remains.
    pub fn encodeCheckpoint(
        self: *const Authority,
        allocator: std.mem.Allocator,
    ) CheckpointError![]u8 {
        if (self.outbox.len() != 0) return error.CustodyOutstanding;
        return self.guard.encodeCheckpoint(allocator);
    }

    /// Cold restore: empty hop custody plus decoded replay authority.
    pub fn decodeCheckpoint(
        allocator: std.mem.Allocator,
        expected_config: Config,
        bytes: []const u8,
    ) CheckpointError!Authority {
        var guard = try group_guard.Guard.decodeCheckpoint(
            allocator,
            expected_config.replay,
            bytes,
        );
        errdefer guard.deinit();
        const outbox = group_outbox.Outbox.init(
            allocator,
            expected_config.max_outbox_entries,
        ) catch return error.InvalidConfig;
        return .{
            .allocator = allocator,
            .config = expected_config,
            .guard = guard,
            .outbox = outbox,
        };
    }

    /// Transactional replacement: requires empty custody; corruption / mismatch /
    /// OOM leave the live authority untouched.
    pub fn replaceFromCheckpoint(self: *Authority, bytes: []const u8) CheckpointError!void {
        if (self.outbox.len() != 0) return error.CustodyOutstanding;
        try self.guard.replaceFromCheckpoint(bytes);
    }
};

const testing = std.testing;
const sign = @import("../crypto/sign.zig");
const signed_frame = @import("../substrate/undertow/signed_frame.zig");

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

    // Exact duplicate local decision; no second delivery decision.
    const dup = try auth.admitAuthorizedWithCustody(
        encoded.verified,
        &.{7},
        encoded.wire,
    );
    try testing.expectEqual(
        std.meta.Tag(Admission).duplicate,
        std.meta.activeTag(dup.admission),
    );
    try testing.expectEqual(PrepareOutcome{ .inserted = 0, .skipped = 1 }, dup.custody);
    try testing.expectEqual(@as(usize, 2), auth.custodyLen());
}

test "E2EEGROUP mesh authority duplicate may add newly eligible peers" {
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
    try testing.expectEqual(PrepareOutcome{ .inserted = 1, .skipped = 1 }, second.custody);
    try testing.expectEqual(@as(usize, 2), auth.custodyLen());
    try testing.expect(auth.containsCustody(11, encoded.verified.relay_id));
    try testing.expect(auth.containsCustody(12, encoded.verified.relay_id));
}

test "E2EEGROUP mesh authority equivocation and retired abort custody" {
    var first = try fixture(testing.allocator, 0xa3, 10, "RVFVSVY");
    defer first.deinit(testing.allocator);
    var conflicting = try fixture(testing.allocator, 0xa3, 10, "Q09ORkxJQ1Q");
    defer conflicting.deinit(testing.allocator);
    // Same origin seed+hlc but different payload ⇒ different RelayId (equivocation).
    try testing.expect(!std.mem.eql(u8, &first.verified.relay_id, &conflicting.verified.relay_id));
    try testing.expectEqualSlices(u8, &first.verified.origin_pubkey, &conflicting.verified.origin_pubkey);

    var auth = try Authority.init(testing.allocator, .{
        .replay = .{ .window_size = 2, .max_origins = 1 },
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

    // Fill window so the original HLC retires, then prove retired aborts custody.
    var mid = try fixture(testing.allocator, 0xa3, 20, "TUlELUhMQw");
    defer mid.deinit(testing.allocator);
    var high = try fixture(testing.allocator, 0xa3, 30, "SElHSC1ITEM");
    defer high.deinit(testing.allocator);
    _ = try auth.admitAuthorizedWithCustody(mid.verified, &.{}, mid.wire);
    _ = try auth.admitAuthorizedWithCustody(high.verified, &.{}, high.wire);

    const retired = try auth.admitAuthorizedWithCustody(
        first.verified,
        &.{23},
        first.wire,
    );
    try testing.expectEqual(
        std.meta.Tag(Admission).retired,
        std.meta.activeTag(retired.admission),
    );
    try testing.expectEqual(PrepareOutcome{ .inserted = 0, .skipped = 0 }, retired.custody);
    try testing.expect(!auth.containsCustody(23, first.verified.relay_id));
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

            // Duplicate path must also be all-or-nothing for new peers.
            const more = auth.admitAuthorizedWithCustody(
                verified,
                &.{ 41, 43 },
                wire,
            ) catch |err| {
                try testing.expectEqual(@as(usize, 2), auth.custodyLen());
                try testing.expect(!auth.containsCustody(43, verified.relay_id));
                return err;
            };
            try testing.expectEqual(
                std.meta.Tag(Admission).duplicate,
                std.meta.activeTag(more.admission),
            );
            try testing.expectEqual(@as(usize, 1), more.custody.inserted);
            try testing.expectEqual(@as(usize, 3), auth.custodyLen());
            try testing.expect(auth.containsCustody(43, verified.relay_id));
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
        .replay = .{ .window_size = 4, .max_origins = 2 },
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

    var restored = try Authority.decodeCheckpoint(testing.allocator, cfg, checkpoint);
    defer restored.deinit();
    try testing.expectEqual(@as(usize, 0), restored.custodyLen());
    const dup = try restored.admitAuthorizedWithCustody(
        encoded.verified,
        &.{53},
        encoded.wire,
    );
    try testing.expectEqual(
        std.meta.Tag(Admission).duplicate,
        std.meta.activeTag(dup.admission),
    );
    try testing.expectEqual(@as(usize, 1), dup.custody.inserted);
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
