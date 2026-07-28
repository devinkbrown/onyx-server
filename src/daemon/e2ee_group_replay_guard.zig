// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Replay and equivocation authority for origin-signed E2EEGROUP controls.
//!
//! Distinct guard instance and checkpoint family from chat MESSAGE_V2. Ordinary
//! greatest-W window/watermark lives in the inner RVG2 guard. This wrapper owns
//! bounded pending-exact facts only for identities with unsettled outgoing
//! custody or ingress receipts (temporary partition backpressure). Settled local
//! traffic never consumes pending capacity; when the last custody and receipt
//! for a RelayId clear, pending is released allocation-free. Recent duplicates
//! remain covered by the greatest-W window.
//!
//! Durable EGRG v2 seals RVG2 + pending exact + metadata-only ingress receipts.
//! Opaque payloads and live hop-custody wires are never sealed (Authority
//! refuses encode while custody is outstanding).

const std = @import("std");

const group_outbox = @import("e2ee_group_outbox.zig");
const group_relay = @import("../substrate/undertow/e2ee_group_relay.zig");
const mesh_clock = @import("../substrate/undertow/mesh_clock.zig");
const replay = @import("relay_v2_replay_guard.zig");

pub const PublicKey = [group_relay.pubkey_len]u8;
pub const RelayId = group_relay.RelayId;
pub const Decision = replay.Decision;
pub const IdentityLookup = replay.IdentityLookup;
pub const Receipt = group_outbox.Receipt;

pub const default_exact_history_size: usize = 256;
pub const hard_max_exact_history_size: usize = 4096;

pub const ExactFact = struct {
    hlc: u64,
    relay_id: RelayId,
};

pub const Config = struct {
    window_size: usize = replay.default_window_size,
    max_origins: usize = replay.default_max_origins,
    /// Bound on pending-exact slots per origin (unsettled only).
    exact_history_size: usize = default_exact_history_size,

    pub fn valid(self: Config) bool {
        return self.window_size > 0 and self.window_size <= replay.hard_max_window_size and
            self.max_origins > 0 and self.max_origins <= replay.hard_max_origins and
            self.exact_history_size > 0 and
            self.exact_history_size <= hard_max_exact_history_size;
    }

    fn toInner(self: Config) replay.Config {
        return .{ .window_size = self.window_size, .max_origins = self.max_origins };
    }
};

pub const Admission = union(enum) {
    accepted: RelayId,
    duplicate: RelayId,
    equivocation,
    retired,
    origin_capacity,
};

pub const VerifiedRecord = struct {
    origin_pubkey: PublicKey,
    hlc: u64,
    relay_id: RelayId,
};

pub const AuthenticatedIdentity = union(enum) {
    verified: VerifiedRecord,
    origin_mismatch,
    bad_signature,
    invalid_semantic,
};

pub const Verification = union(enum) {
    verified: VerifiedRecord,
    origin_mismatch,
    bad_signature,
    invalid_semantic,
    future_skew,
};

pub fn isFutureSkewed(
    verified: VerifiedRecord,
    now_ms: u64,
    max_future_skew_ms: u64,
) bool {
    if (verified.hlc == std.math.maxInt(u64)) return true;
    const latest_physical = std.math.add(u64, now_ms, max_future_skew_ms) catch
        std.math.maxInt(u64);
    return mesh_clock.MeshClock.physicalOf(verified.hlc) > latest_physical;
}

pub const InitError = replay.InitError;
pub const CheckpointError = replay.CheckpointError || error{
    ExactHistorySizeMismatch,
};

const magic = [_]u8{ 'E', 'G', 'R', 'G' };
const checkpoint_version: u8 = 2;
const header_len: usize = magic.len + 1 + 4;
const checksum_len: usize = std.crypto.hash.Blake3.digest_length;
const checkpoint_checksum_domain = "onyx-e2ee-group-replay-checkpoint-v2";
const exact_entry_len: usize = 8 + @sizeOf(RelayId);
const receipt_entry_len: usize = 8 + @sizeOf(RelayId) + 8 + 4;
const rvg2_header_len: usize = 19;
const rvg2_origin_prefix_len: usize = @sizeOf(PublicKey) + 1 + 8 + 2;
const rvg2_entry_len: usize = 8 + @sizeOf(RelayId);

const PendingOrigin = struct {
    facts: std.ArrayListUnmanaged(ExactFact) = .empty,

    fn deinit(self: *PendingOrigin, allocator: std.mem.Allocator) void {
        self.facts.deinit(allocator);
        self.* = undefined;
    }
};

pub fn isCheckpoint(bytes: []const u8) bool {
    return bytes.len >= magic.len and std.mem.eql(u8, bytes[0..magic.len], &magic);
}

fn checkpointChecksum(prefix: []const u8, out: *[checksum_len]u8) void {
    var hash = std.crypto.hash.Blake3.init(.{});
    hash.update(checkpoint_checksum_domain);
    hash.update(prefix);
    hash.final(out);
}

const ParsedEnvelope = struct {
    rvg2: []const u8,
    exact_history_size: usize,
    exact_section: []const u8,
    receipt_section: []const u8,
};

/// Deterministic join/uniqueness work counter for structural regression tests.
/// Counts hash membership probes (get/put/contains), not wall-clock time.
pub const CheckpointJoinWork = struct {
    hash_ops: usize = 0,

    fn bump(self: ?*CheckpointJoinWork, n: usize) void {
        if (self) |w| w.hash_ops = std.math.add(usize, w.hash_ops, n) catch std.math.maxInt(usize);
    }
};

fn parseEnvelopeBody(
    allocator: std.mem.Allocator,
    body: []const u8,
    work: ?*CheckpointJoinWork,
) CheckpointError!ParsedEnvelope {
    if (body.len < 4) return error.Truncated;
    const rvg2_len: usize = std.mem.readInt(u32, body[0..4], .big);
    if (rvg2_len > body.len - 4) return error.Truncated;
    const rvg2 = body[4 .. 4 + rvg2_len];
    _ = try replay.validateCheckpoint(rvg2);
    if (rvg2.len < rvg2_header_len) return error.Truncated;
    const origin_count: usize = std.mem.readInt(u32, rvg2[11..15], .big);
    const rvg2_body_len: usize = std.mem.readInt(u32, rvg2[15..19], .big);
    const rvg2_prefix_len = std.math.add(usize, rvg2_header_len, rvg2_body_len) catch
        return error.CheckpointTooLarge;
    if (rvg2_prefix_len > rvg2.len) return error.Truncated;

    var pos: usize = 4 + rvg2_len;
    if (body.len - pos < 2) return error.Truncated;
    const exact_history_size: usize = std.mem.readInt(u16, body[pos..][0..2], .big);
    pos += 2;
    if (exact_history_size == 0 or exact_history_size > hard_max_exact_history_size)
        return error.InvalidConfig;

    const exact_start = pos;
    var rvg2_pos: usize = rvg2_header_len;
    // No artificial global aggregate cap: per-origin pending capacity is
    // `exact_history_size` (≤ hard_max_exact_history_size). Within/cross-origin
    // RelayId uniqueness and exact↔receipt joins use allocator-backed hash maps
    // (O(n) expected / O(n log n) worst) so multi-origin aggregates above 4096
    // remain legal and non-quadratic. Exact↔window validation builds one
    // per-origin HLC→RelayId map from the RVG2 window then O(1)-expected lookups
    // (no O(exact_count×window_count) scans).
    var exact_rids: std.AutoHashMapUnmanaged(RelayId, void) = .empty;
    defer exact_rids.deinit(allocator);
    var window_by_hlc: std.AutoHashMapUnmanaged(u64, RelayId) = .empty;
    defer window_by_hlc.deinit(allocator);

    var o: usize = 0;
    while (o < origin_count) : (o += 1) {
        if (rvg2_pos > rvg2_prefix_len or rvg2_prefix_len - rvg2_pos < rvg2_origin_prefix_len)
            return error.Truncated;
        rvg2_pos += @sizeOf(PublicKey);
        const retired_present = rvg2[rvg2_pos];
        rvg2_pos += 1;
        if (retired_present > 1) return error.InvalidField;
        const retired_raw = std.mem.readInt(u64, rvg2[rvg2_pos..][0..8], .big);
        rvg2_pos += 8;
        const retired: ?u64 = if (retired_present == 1) retired_raw else null;
        const window_count: usize = std.mem.readInt(u16, rvg2[rvg2_pos..][0..2], .big);
        rvg2_pos += 2;
        const window_bytes = std.math.mul(usize, window_count, rvg2_entry_len) catch
            return error.CheckpointTooLarge;
        if (window_bytes > rvg2_prefix_len - rvg2_pos) return error.Truncated;
        const window_section = rvg2[rvg2_pos .. rvg2_pos + window_bytes];
        rvg2_pos += window_bytes;

        // One allocator-backed HLC→RelayId index for this origin's RVG2 window.
        // Capacity staged first so OOM fails closed; RVG2 unique-HLC invariant.
        window_by_hlc.clearRetainingCapacity();
        if (window_count > 0)
            try window_by_hlc.ensureTotalCapacity(allocator, @intCast(window_count));
        var w: usize = 0;
        while (w < window_count) : (w += 1) {
            const wh = std.mem.readInt(u64, window_section[w * rvg2_entry_len ..][0..8], .big);
            const wr = window_section[w * rvg2_entry_len + 8 ..][0..@sizeOf(RelayId)].*;
            CheckpointJoinWork.bump(work, 1);
            window_by_hlc.putAssumeCapacity(wh, wr);
        }

        if (body.len - pos < 2) return error.Truncated;
        const exact_count: usize = std.mem.readInt(u16, body[pos..][0..2], .big);
        pos += 2;
        if (exact_count > exact_history_size) return error.CapacityExceeded;
        const entries_bytes = std.math.mul(usize, exact_count, exact_entry_len) catch
            return error.CheckpointTooLarge;
        if (entries_bytes > body.len - pos) return error.Truncated;
        const exact_entries = body[pos .. pos + entries_bytes];
        // Stage this origin's inserts before mutation; OOM fails closed with no partial live state.
        if (exact_count > 0)
            try exact_rids.ensureUnusedCapacity(allocator, @intCast(exact_count));

        var previous_hlc: ?u64 = null;
        var e: usize = 0;
        while (e < exact_count) : (e += 1) {
            const hlc = std.mem.readInt(u64, exact_entries[e * exact_entry_len ..][0..8], .big);
            const er = exact_entries[e * exact_entry_len + 8 ..][0..@sizeOf(RelayId)].*;
            if (previous_hlc) |prev| {
                if (hlc == prev) return error.DuplicateHlc;
                if (hlc < prev) return error.NonCanonicalOrder;
            }
            previous_hlc = hlc;
            // Expected O(1) window membership + RelayId match; watermark/retired
            // semantics: above-watermark pending must be present in the window.
            CheckpointJoinWork.bump(work, 1);
            if (window_by_hlc.get(hlc)) |wr| {
                if (!std.mem.eql(u8, &wr, &er)) return error.InvalidField;
            } else {
                const above_watermark = if (retired) |wm| hlc > wm else true;
                if (above_watermark) return error.InvalidField;
            }
            // Global exact RelayId uniqueness (within + cross origin) via hash set.
            CheckpointJoinWork.bump(work, 1);
            const gop = exact_rids.getOrPutAssumeCapacity(er);
            if (gop.found_existing) return error.InvalidField;
        }
        pos += entries_bytes;
    }
    if (rvg2_pos != rvg2_prefix_len) return error.TrailingBytes;
    const exact_section = body[exact_start..pos];

    if (body.len - pos < 2) return error.Truncated;
    const receipt_count: usize = std.mem.readInt(u16, body[pos..][0..2], .big);
    pos += 2;
    const receipt_bytes = std.math.mul(usize, receipt_count, receipt_entry_len) catch
        return error.CheckpointTooLarge;
    if (receipt_bytes > body.len - pos) return error.Truncated;
    const receipt_section = body[pos - 2 .. pos + receipt_bytes];
    const receipt_rows = body[pos .. pos + receipt_bytes];
    pos += receipt_bytes;
    if (pos != body.len) return error.TrailingBytes;

    var covered: std.AutoHashMapUnmanaged(RelayId, void) = .empty;
    defer covered.deinit(allocator);
    if (exact_rids.count() > 0)
        try covered.ensureTotalCapacity(allocator, exact_rids.count());

    var previous_peer: ?u64 = null;
    var previous_rid: ?RelayId = null;
    var r: usize = 0;
    while (r < receipt_count) : (r += 1) {
        const base = r * receipt_entry_len;
        const peer = std.mem.readInt(u64, receipt_rows[base..][0..8], .big);
        const rid = receipt_rows[base + 8 ..][0..@sizeOf(RelayId)].*;
        if (peer == 0) return error.InvalidField;
        if (previous_peer) |pp| {
            if (peer < pp) return error.NonCanonicalOrder;
            if (peer == pp) {
                if (previous_rid) |pr| {
                    if (std.mem.eql(u8, &pr, &rid)) return error.DuplicateHlc;
                    if (!std.mem.lessThan(u8, &pr, &rid)) return error.NonCanonicalOrder;
                }
            }
        }
        previous_peer = peer;
        previous_rid = rid;
        // receipt → pending exact (orphan receipts fail closed).
        CheckpointJoinWork.bump(work, 1);
        if (!exact_rids.contains(rid)) return error.InvalidField;
        CheckpointJoinWork.bump(work, 1);
        try covered.put(allocator, rid, {});
    }
    // Seal-time invariant: every pending exact maps to ≥1 receipt (custody empty).
    if (covered.count() != exact_rids.count()) return error.InvalidField;

    return .{
        .rvg2 = rvg2,
        .exact_history_size = exact_history_size,
        .exact_section = exact_section,
        .receipt_section = receipt_section,
    };
}

fn openEnvelope(bytes: []const u8) CheckpointError![]const u8 {
    if (bytes.len < header_len + checksum_len) return error.Truncated;
    if (!std.mem.eql(u8, bytes[0..magic.len], &magic)) return error.BadMagic;
    if (bytes[magic.len] != checkpoint_version) return error.UnsupportedVersion;

    const body_len: usize = std.mem.readInt(u32, bytes[5..9], .big);
    const prefix_len = std.math.add(usize, header_len, body_len) catch
        return error.CheckpointTooLarge;
    const expected_len = std.math.add(usize, prefix_len, checksum_len) catch
        return error.CheckpointTooLarge;
    if (expected_len > replay.hard_max_checkpoint_bytes) return error.CheckpointTooLarge;
    if (bytes.len < expected_len) return error.Truncated;
    if (bytes.len > expected_len) return error.TrailingBytes;

    var actual: [checksum_len]u8 = undefined;
    checkpointChecksum(bytes[0..prefix_len], &actual);
    if (!std.mem.eql(u8, &actual, bytes[prefix_len..])) return error.ChecksumMismatch;
    return bytes[header_len..prefix_len];
}

/// Validate with a caller-provided allocator for join/uniqueness maps.
/// Allocation is staged and OOM fails closed (typed `error.OutOfMemory`).
pub fn validateCheckpointWithAllocator(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) CheckpointError!Config {
    return validateCheckpointWithAllocatorWork(allocator, bytes, null);
}

fn validateCheckpointWithAllocatorWork(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    work: ?*CheckpointJoinWork,
) CheckpointError!Config {
    const body = try openEnvelope(bytes);
    const parsed = try parseEnvelopeBody(allocator, body, work);
    const rvg2_cfg = try replay.validateCheckpoint(parsed.rvg2);
    return .{
        .window_size = rvg2_cfg.window_size,
        .max_origins = rvg2_cfg.max_origins,
        .exact_history_size = parsed.exact_history_size,
    };
}

/// Allocation-free call sites: uses `page_allocator` for join maps; OOM is typed.
pub fn validateCheckpoint(bytes: []const u8) CheckpointError!Config {
    return validateCheckpointWithAllocator(std.heap.page_allocator, bytes);
}

/// Prepared pending-exact reservation. Allocates capacity before mutation;
/// commit/abort are no-fail.
pub const PreparedPending = struct {
    const State = enum { prepared, committed, aborted };
    const Kind = enum { none, insert, already };

    guard: *Guard,
    pubkey: PublicKey,
    fact: ExactFact,
    kind: Kind,
    /// When insert installs a brand-new origin map entry.
    new_origin: bool = false,
    state: State = .prepared,

    pub fn commit(self: *PreparedPending) void {
        std.debug.assert(self.state == .prepared);
        switch (self.kind) {
            .none, .already => {},
            .insert => {
                const origin = self.guard.pending.getPtr(self.pubkey) orelse unreachable;
                origin.facts.appendAssumeCapacity(self.fact);
            },
        }
        self.guard.prepared_pending_active = false;
        self.state = .committed;
    }

    pub fn abort(self: *PreparedPending) void {
        if (self.state != .prepared) return;
        if (self.kind == .insert and self.new_origin) {
            if (self.guard.pending.fetchRemove(self.pubkey)) |kv| {
                var origin = kv.value;
                origin.deinit(self.guard.inner.allocator);
            }
        }
        self.guard.prepared_pending_active = false;
        self.state = .aborted;
    }

    pub fn deinit(self: *PreparedPending) void {
        if (self.state == .prepared) self.abort();
        self.* = undefined;
    }
};

pub const Guard = struct {
    inner: replay.Guard,
    config: Config,
    /// Wrapper-owned pending exact facts (unsettled only).
    pending: std.AutoHashMapUnmanaged(PublicKey, PendingOrigin) = .empty,
    prepared_pending_active: bool = false,

    pub fn init(allocator: std.mem.Allocator, config: Config) InitError!Guard {
        if (!config.valid()) return error.InvalidConfig;
        return .{
            .inner = try replay.Guard.init(allocator, config.toInner()),
            .config = config,
        };
    }

    pub fn deinit(self: *Guard) void {
        std.debug.assert(!self.prepared_pending_active);
        var it = self.pending.valueIterator();
        while (it.next()) |origin| origin.deinit(self.inner.allocator);
        self.pending.deinit(self.inner.allocator);
        self.inner.deinit();
        self.* = undefined;
    }

    pub fn admit(
        self: *Guard,
        pubkey: PublicKey,
        hlc: u64,
        relay_id: RelayId,
    ) std.mem.Allocator.Error!Decision {
        return switch (try self.admitAuthorized(.{
            .origin_pubkey = pubkey,
            .hlc = hlc,
            .relay_id = relay_id,
        })) {
            .accepted => .accepted,
            .duplicate => .duplicate,
            .equivocation => .equivocation,
            .retired => .retired,
            .origin_capacity => .origin_capacity,
        };
    }

    pub fn authenticateRecord(
        self: *Guard,
        record: group_relay.RelayRecord,
    ) std.mem.Allocator.Error!AuthenticatedIdentity {
        const relay_id = switch (try group_relay.verifyAndRelayId(self.inner.allocator, record)) {
            .verified => |id| id,
            .origin_mismatch => return .origin_mismatch,
            .bad_signature => return .bad_signature,
            .invalid_semantic => return .invalid_semantic,
        };
        const pubkey: PublicKey = record.origin_pubkey[0..@sizeOf(PublicKey)].*;
        return .{ .verified = .{
            .origin_pubkey = pubkey,
            .hlc = record.hlc,
            .relay_id = relay_id,
        } };
    }

    pub fn verifyRecord(
        self: *Guard,
        record: group_relay.RelayRecord,
        now_ms: u64,
        max_future_skew_ms: u64,
    ) std.mem.Allocator.Error!Verification {
        const identity = switch (try self.authenticateRecord(record)) {
            .verified => |verified| verified,
            .origin_mismatch => return .origin_mismatch,
            .bad_signature => return .bad_signature,
            .invalid_semantic => return .invalid_semantic,
        };
        if (isFutureSkewed(identity, now_ms, max_future_skew_ms)) return .future_skew;
        return .{ .verified = identity };
    }

    /// Commit a previously verified identity. Pending exact upgrades below-
    /// watermark retired to exact duplicate / equivocation when retained.
    pub fn admitAuthorized(
        self: *Guard,
        verified: VerifiedRecord,
    ) std.mem.Allocator.Error!Admission {
        const pending_hit = self.lookupPending(verified.origin_pubkey, verified.hlc, verified.relay_id);
        const decision = try self.inner.admit(
            verified.origin_pubkey,
            verified.hlc,
            verified.relay_id,
        );
        return switch (decision) {
            .accepted => .{ .accepted = verified.relay_id },
            .duplicate => .{ .duplicate = verified.relay_id },
            .equivocation => .equivocation,
            .origin_capacity => .origin_capacity,
            .retired => switch (pending_hit) {
                .duplicate => .{ .duplicate = verified.relay_id },
                .equivocation => .equivocation,
                .retired, .unseen => .retired,
            },
        };
    }

    pub fn probeIdentity(self: *const Guard, verified: VerifiedRecord) IdentityLookup {
        const window = self.inner.probeIdentity(
            verified.origin_pubkey,
            verified.hlc,
            verified.relay_id,
        );
        return switch (window) {
            .duplicate, .equivocation => window,
            .unseen => self.lookupPending(verified.origin_pubkey, verified.hlc, verified.relay_id),
            .retired => switch (self.lookupPending(verified.origin_pubkey, verified.hlc, verified.relay_id)) {
                .duplicate => .duplicate,
                .equivocation => .equivocation,
                .retired, .unseen => .retired,
            },
        };
    }

    pub fn exactHistoryOf(self: *const Guard, pubkey: PublicKey) []const ExactFact {
        const origin = self.pending.getPtr(pubkey) orelse return &.{};
        return origin.facts.items;
    }

    /// Ordered pubkeys that currently hold pending-exact facts (not RVG2 origins).
    pub fn orderedPendingPubkeys(
        self: *const Guard,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error![]PublicKey {
        const count = self.pending.count();
        var keys = try allocator.alloc(PublicKey, count);
        errdefer allocator.free(keys);
        var it = self.pending.keyIterator();
        var index: usize = 0;
        while (it.next()) |key| : (index += 1) keys[index] = key.*;
        std.mem.sort(PublicKey, keys, {}, struct {
            fn less(_: void, a: PublicKey, b: PublicKey) bool {
                return std.mem.lessThan(u8, &a, &b);
            }
        }.less);
        return keys;
    }

    pub fn orderedOriginPubkeys(
        self: *const Guard,
        allocator: std.mem.Allocator,
    ) CheckpointError![]PublicKey {
        return self.inner.orderedOriginPubkeys(allocator);
    }

    pub fn hasPendingExact(
        self: *const Guard,
        pubkey: PublicKey,
        hlc: u64,
        relay_id: RelayId,
    ) bool {
        return self.lookupPending(pubkey, hlc, relay_id) == .duplicate;
    }

    /// Prepare result distinguishing capacity/conflict for authority.
    pub const PendingPrepare = union(enum) {
        prepared: PreparedPending,
        already: void,
        origin_capacity: void,
        equivocation: void,
    };

    pub fn preparePendingExactResult(
        self: *Guard,
        pubkey: PublicKey,
        hlc: u64,
        relay_id: RelayId,
    ) error{ OutOfMemory, PreparedMutationActive }!PendingPrepare {
        if (self.prepared_pending_active) return error.PreparedMutationActive;
        if (self.pending.getPtr(pubkey)) |origin| {
            for (origin.facts.items) |entry| {
                if (entry.hlc != hlc) continue;
                if (std.mem.eql(u8, &entry.relay_id, &relay_id)) return .already;
                return .equivocation;
            }
            if (origin.facts.items.len >= self.config.exact_history_size)
                return .origin_capacity;
            self.prepared_pending_active = true;
            errdefer self.prepared_pending_active = false;
            try origin.facts.ensureUnusedCapacity(self.inner.allocator, 1);
            return .{ .prepared = .{
                .guard = self,
                .pubkey = pubkey,
                .fact = .{ .hlc = hlc, .relay_id = relay_id },
                .kind = .insert,
                .new_origin = false,
            } };
        }
        self.prepared_pending_active = true;
        errdefer self.prepared_pending_active = false;
        try self.pending.ensureUnusedCapacity(self.inner.allocator, 1);
        var origin = PendingOrigin{};
        errdefer origin.deinit(self.inner.allocator);
        try origin.facts.ensureTotalCapacity(self.inner.allocator, 1);
        self.pending.putAssumeCapacity(pubkey, origin);
        return .{ .prepared = .{
            .guard = self,
            .pubkey = pubkey,
            .fact = .{ .hlc = hlc, .relay_id = relay_id },
            .kind = .insert,
            .new_origin = true,
        } };
    }

    pub fn releasePendingExact(
        self: *Guard,
        pubkey: PublicKey,
        hlc: u64,
        relay_id: RelayId,
    ) bool {
        std.debug.assert(!self.prepared_pending_active);
        const origin = self.pending.getPtr(pubkey) orelse return false;
        for (origin.facts.items, 0..) |entry, index| {
            if (entry.hlc != hlc or !std.mem.eql(u8, &entry.relay_id, &relay_id)) continue;
            _ = origin.facts.orderedRemove(index);
            if (origin.facts.items.len == 0) {
                if (self.pending.fetchRemove(pubkey)) |kv| {
                    var empty = kv.value;
                    empty.deinit(self.inner.allocator);
                }
            }
            return true;
        }
        return false;
    }

    pub fn encodeCheckpoint(
        self: *const Guard,
        allocator: std.mem.Allocator,
    ) CheckpointError![]u8 {
        return encodeEnvelope(allocator, self, &.{});
    }

    pub fn encodeCheckpointWithReceipts(
        self: *const Guard,
        allocator: std.mem.Allocator,
        receipts: []const Receipt,
    ) CheckpointError![]u8 {
        return encodeEnvelope(allocator, self, receipts);
    }

    pub fn decodeCheckpoint(
        allocator: std.mem.Allocator,
        expected_config: Config,
        bytes: []const u8,
    ) CheckpointError!Guard {
        var decoded = try decodeEnvelope(allocator, expected_config, bytes);
        decoded.receipts.deinit(allocator);
        return decoded.guard;
    }

    pub const Decoded = struct {
        guard: Guard,
        receipts: std.ArrayListUnmanaged(Receipt),
    };

    pub fn decodeCheckpointWithReceipts(
        allocator: std.mem.Allocator,
        expected_config: Config,
        bytes: []const u8,
    ) CheckpointError!Decoded {
        return decodeEnvelope(allocator, expected_config, bytes);
    }

    pub fn replaceFromCheckpoint(self: *Guard, bytes: []const u8) CheckpointError!void {
        var replacement = try decodeCheckpoint(self.inner.allocator, self.config, bytes);
        const previous = self.*;
        self.* = replacement;
        replacement = previous;
        replacement.deinit();
    }

    fn lookupPending(
        self: *const Guard,
        pubkey: PublicKey,
        hlc: u64,
        relay_id: RelayId,
    ) IdentityLookup {
        const origin = self.pending.getPtr(pubkey) orelse return .unseen;
        for (origin.facts.items) |entry| {
            if (entry.hlc != hlc) continue;
            return if (std.mem.eql(u8, &entry.relay_id, &relay_id))
                .duplicate
            else
                .equivocation;
        }
        return .unseen;
    }
};

fn exactFactLess(_: void, a: ExactFact, b: ExactFact) bool {
    return a.hlc < b.hlc;
}

fn receiptLess(_: void, a: Receipt, b: Receipt) bool {
    if (a.peer != b.peer) return a.peer < b.peer;
    return std.mem.lessThan(u8, &a.relay_id, &b.relay_id);
}

fn encodeEnvelope(
    allocator: std.mem.Allocator,
    guard: *const Guard,
    receipts: []const Receipt,
) CheckpointError![]u8 {
    return encodeEnvelopeWork(allocator, guard, receipts, null);
}

fn encodeEnvelopeWork(
    allocator: std.mem.Allocator,
    guard: *const Guard,
    receipts: []const Receipt,
    work: ?*CheckpointJoinWork,
) CheckpointError![]u8 {
    std.debug.assert(!guard.prepared_pending_active);
    // Receipt count is a u16 on the wire; refuse early (typed, no @intCast trap).
    const receipt_count_u16 = std.math.cast(u16, receipts.len) orelse
        return error.CapacityExceeded;
    const rvg2 = try guard.inner.encodeCheckpoint(allocator);
    defer allocator.free(rvg2);
    if (rvg2.len > std.math.maxInt(u32)) return error.CheckpointTooLarge;

    const keys = try guard.inner.orderedOriginPubkeys(allocator);
    defer allocator.free(keys);

    // Envelope exact sections are 1:1 with RVG2 origin order. Pending that is
    // not also present as an RVG2 origin cannot be sealed (caller must admit
    // before commit, or abort prepared state first).
    const pending_keys = try guard.orderedPendingPubkeys(allocator);
    defer allocator.free(pending_keys);
    var origin_set: std.AutoHashMapUnmanaged(PublicKey, void) = .empty;
    defer origin_set.deinit(allocator);
    if (keys.len > 0)
        try origin_set.ensureTotalCapacity(allocator, @intCast(keys.len));
    for (keys) |k| {
        CheckpointJoinWork.bump(work, 1);
        origin_set.putAssumeCapacity(k, {});
    }
    for (pending_keys) |pk| {
        CheckpointJoinWork.bump(work, 1);
        if (!origin_set.contains(pk)) return error.InvalidField;
    }

    var sorted_exact = try allocator.alloc(?[]ExactFact, keys.len);
    @memset(sorted_exact, null);
    defer {
        for (sorted_exact) |maybe| {
            if (maybe) |facts| allocator.free(facts);
        }
        allocator.free(sorted_exact);
    }
    var exact_rids: std.AutoHashMapUnmanaged(RelayId, void) = .empty;
    defer exact_rids.deinit(allocator);
    var exact_bytes: usize = 0;
    for (keys, 0..) |key, ki| {
        const facts = guard.exactHistoryOf(key);
        if (facts.len > guard.config.exact_history_size) return error.InvalidField;
        const copy = try allocator.alloc(ExactFact, facts.len);
        errdefer allocator.free(copy);
        @memcpy(copy, facts);
        std.mem.sort(ExactFact, copy, {}, exactFactLess);
        // Canonical per-origin HLC order + uniqueness after sort (adjacent O(n)).
        var prev_hlc: ?u64 = null;
        if (copy.len > 0)
            try exact_rids.ensureUnusedCapacity(allocator, @intCast(copy.len));
        for (copy) |fact| {
            if (prev_hlc) |prev| {
                if (fact.hlc == prev) return error.DuplicateHlc;
                if (fact.hlc < prev) return error.NonCanonicalOrder;
            }
            prev_hlc = fact.hlc;
            // Global exact RelayId uniqueness (within + cross origin).
            CheckpointJoinWork.bump(work, 1);
            const gop = exact_rids.getOrPutAssumeCapacity(fact.relay_id);
            if (gop.found_existing) return error.InvalidField;
        }
        sorted_exact[ki] = copy;
        const entries_bytes = std.math.mul(usize, copy.len, exact_entry_len) catch
            return error.CheckpointTooLarge;
        exact_bytes = std.math.add(usize, exact_bytes, 2 + entries_bytes) catch
            return error.CheckpointTooLarge;
    }

    var covered: std.AutoHashMapUnmanaged(RelayId, void) = .empty;
    defer covered.deinit(allocator);
    if (exact_rids.count() > 0)
        try covered.ensureTotalCapacity(allocator, exact_rids.count());
    for (receipts) |receipt| {
        if (receipt.peer == 0) return error.InvalidField;
        CheckpointJoinWork.bump(work, 1);
        if (!exact_rids.contains(receipt.relay_id)) return error.InvalidField;
        CheckpointJoinWork.bump(work, 1);
        try covered.put(allocator, receipt.relay_id, {});
    }
    if (covered.count() != exact_rids.count()) return error.InvalidField;

    const sorted_receipts = try allocator.alloc(Receipt, receipts.len);
    defer allocator.free(sorted_receipts);
    @memcpy(sorted_receipts, receipts);
    std.mem.sort(Receipt, sorted_receipts, {}, receiptLess);
    // (peer, RelayId) uniqueness after canonical sort: adjacent O(n).
    if (sorted_receipts.len > 0) {
        var i: usize = 1;
        while (i < sorted_receipts.len) : (i += 1) {
            const prev = sorted_receipts[i - 1];
            const cur = sorted_receipts[i];
            if (prev.peer == cur.peer and std.mem.eql(u8, &prev.relay_id, &cur.relay_id))
                return error.InvalidField;
        }
    }
    const receipt_bytes = std.math.mul(usize, sorted_receipts.len, receipt_entry_len) catch
        return error.CheckpointTooLarge;

    var body_len: usize = 4;
    body_len = std.math.add(usize, body_len, rvg2.len) catch return error.CheckpointTooLarge;
    body_len = std.math.add(usize, body_len, 2) catch return error.CheckpointTooLarge;
    body_len = std.math.add(usize, body_len, exact_bytes) catch return error.CheckpointTooLarge;
    body_len = std.math.add(usize, body_len, 2) catch return error.CheckpointTooLarge;
    body_len = std.math.add(usize, body_len, receipt_bytes) catch return error.CheckpointTooLarge;
    if (body_len > std.math.maxInt(u32)) return error.CheckpointTooLarge;

    const prefix_len = std.math.add(usize, header_len, body_len) catch
        return error.CheckpointTooLarge;
    const total_len = std.math.add(usize, prefix_len, checksum_len) catch
        return error.CheckpointTooLarge;
    if (total_len > replay.hard_max_checkpoint_bytes) return error.CheckpointTooLarge;

    const out = try allocator.alloc(u8, total_len);
    errdefer allocator.free(out);
    @memcpy(out[0..magic.len], &magic);
    out[magic.len] = checkpoint_version;
    std.mem.writeInt(u32, out[5..9], @intCast(body_len), .big);

    var pos: usize = header_len;
    std.mem.writeInt(u32, out[pos..][0..4], @intCast(rvg2.len), .big);
    pos += 4;
    @memcpy(out[pos .. pos + rvg2.len], rvg2);
    pos += rvg2.len;
    const exact_hist_u16 = std.math.cast(u16, guard.config.exact_history_size) orelse
        return error.InvalidConfig;
    std.mem.writeInt(u16, out[pos..][0..2], exact_hist_u16, .big);
    pos += 2;
    for (sorted_exact) |maybe| {
        const facts = maybe orelse return error.InvalidField;
        const fact_count_u16 = std.math.cast(u16, facts.len) orelse
            return error.CapacityExceeded;
        std.mem.writeInt(u16, out[pos..][0..2], fact_count_u16, .big);
        pos += 2;
        for (facts) |fact| {
            std.mem.writeInt(u64, out[pos..][0..8], fact.hlc, .big);
            pos += 8;
            @memcpy(out[pos..][0..@sizeOf(RelayId)], &fact.relay_id);
            pos += @sizeOf(RelayId);
        }
    }
    std.mem.writeInt(u16, out[pos..][0..2], receipt_count_u16, .big);
    pos += 2;
    for (sorted_receipts) |receipt| {
        std.mem.writeInt(u64, out[pos..][0..8], receipt.peer, .big);
        pos += 8;
        @memcpy(out[pos..][0..@sizeOf(RelayId)], &receipt.relay_id);
        pos += @sizeOf(RelayId);
        std.mem.writeInt(u64, out[pos..][0..8], receipt.retry_after_ms, .big);
        pos += 8;
        std.mem.writeInt(u32, out[pos..][0..4], receipt.attempts, .big);
        pos += 4;
    }
    std.debug.assert(pos == prefix_len);
    checkpointChecksum(out[0..prefix_len], out[prefix_len..][0..checksum_len]);
    return out;
}

fn decodeEnvelope(
    allocator: std.mem.Allocator,
    expected_config: Config,
    bytes: []const u8,
) CheckpointError!Guard.Decoded {
    if (!expected_config.valid()) return error.InvalidConfig;
    const body = try openEnvelope(bytes);
    const parsed = try parseEnvelopeBody(allocator, body, null);
    if (parsed.exact_history_size != expected_config.exact_history_size)
        return error.ExactHistorySizeMismatch;

    var inner = try replay.Guard.decodeCheckpoint(allocator, expected_config.toInner(), parsed.rvg2);
    errdefer inner.deinit();

    const keys = try inner.orderedOriginPubkeys(allocator);
    defer allocator.free(keys);
    if (keys.len != std.mem.readInt(u32, parsed.rvg2[11..15], .big))
        return error.InvalidField;

    var pending: std.AutoHashMapUnmanaged(PublicKey, PendingOrigin) = .empty;
    errdefer {
        var it = pending.valueIterator();
        while (it.next()) |origin| origin.deinit(allocator);
        pending.deinit(allocator);
    }
    try pending.ensureTotalCapacity(allocator, @intCast(keys.len));

    var exact_pos: usize = 0;
    for (keys) |key| {
        if (parsed.exact_section.len - exact_pos < 2) return error.Truncated;
        const exact_count: usize = std.mem.readInt(u16, parsed.exact_section[exact_pos..][0..2], .big);
        exact_pos += 2;
        if (exact_count > expected_config.exact_history_size) return error.CapacityExceeded;
        const entries_bytes = std.math.mul(usize, exact_count, exact_entry_len) catch
            return error.CheckpointTooLarge;
        if (entries_bytes > parsed.exact_section.len - exact_pos) return error.Truncated;
        var origin = PendingOrigin{};
        errdefer origin.deinit(allocator);
        try origin.facts.ensureTotalCapacity(allocator, exact_count);
        var i: usize = 0;
        while (i < exact_count) : (i += 1) {
            const base = exact_pos + i * exact_entry_len;
            origin.facts.appendAssumeCapacity(.{
                .hlc = std.mem.readInt(u64, parsed.exact_section[base..][0..8], .big),
                .relay_id = parsed.exact_section[base + 8 ..][0..@sizeOf(RelayId)].*,
            });
        }
        if (exact_count != 0)
            pending.putAssumeCapacity(key, origin)
        else
            origin.deinit(allocator);
        exact_pos += entries_bytes;
    }
    if (exact_pos != parsed.exact_section.len) return error.TrailingBytes;

    if (parsed.receipt_section.len < 2) return error.Truncated;
    const receipt_count: usize = std.mem.readInt(u16, parsed.receipt_section[0..2], .big);
    const receipt_bytes = std.math.mul(usize, receipt_count, receipt_entry_len) catch
        return error.CheckpointTooLarge;
    if (parsed.receipt_section.len != 2 + receipt_bytes) return error.Truncated;
    var receipts: std.ArrayListUnmanaged(Receipt) = .empty;
    errdefer receipts.deinit(allocator);
    try receipts.ensureTotalCapacity(allocator, receipt_count);
    var r: usize = 0;
    while (r < receipt_count) : (r += 1) {
        const base = 2 + r * receipt_entry_len;
        receipts.appendAssumeCapacity(.{
            .peer = std.mem.readInt(u64, parsed.receipt_section[base..][0..8], .big),
            .relay_id = parsed.receipt_section[base + 8 ..][0..@sizeOf(RelayId)].*,
            .retry_after_ms = std.mem.readInt(u64, parsed.receipt_section[base + 8 + @sizeOf(RelayId) ..][0..8], .big),
            .attempts = std.mem.readInt(u32, parsed.receipt_section[base + 8 + @sizeOf(RelayId) + 8 ..][0..4], .big),
        });
    }

    return .{
        .guard = .{
            .inner = inner,
            .config = expected_config,
            .pending = pending,
        },
        .receipts = receipts,
    };
}

const testing = std.testing;
const sign = @import("../crypto/sign.zig");
const signed_frame = @import("../substrate/undertow/signed_frame.zig");

fn testKey(byte: u8) PublicKey {
    return @splat(byte);
}

fn testId(byte: u8) RelayId {
    return @splat(byte);
}

fn signedRecord(
    kp: *const sign.KeyPair,
    hlc: u64,
    payload: []const u8,
    pubkey: *[group_relay.pubkey_len]u8,
    signature: *[group_relay.sig_len]u8,
) !group_relay.RelayRecord {
    var record = group_relay.RelayRecord{
        .kind = .commit,
        .channel = "#root",
        .source_prefix = "alice!user@example.invalid",
        .account = "alice",
        .from_device = "laptop.1",
        .payload = payload,
        .origin_node = signed_frame.originShortId(kp.public_key),
        .hlc = hlc,
    };
    try group_relay.stampOrigin(testing.allocator, &record, kp, pubkey, signature);
    return record;
}

test "E2EEGROUP replay guard detects duplicates equivocation retirement and capacity" {
    var guard = try Guard.init(testing.allocator, .{
        .window_size = 2,
        .max_origins = 1,
        .exact_history_size = 4,
    });
    defer guard.deinit();
    const key = testKey(1);

    try testing.expectEqual(Decision.accepted, try guard.admit(key, 10, testId(10)));
    try testing.expectEqual(Decision.duplicate, try guard.admit(key, 10, testId(10)));
    try testing.expectEqual(Decision.equivocation, try guard.admit(key, 10, testId(11)));
    try testing.expectEqual(Decision.accepted, try guard.admit(key, 20, testId(20)));
    try testing.expectEqual(Decision.accepted, try guard.admit(key, 30, testId(30)));
    // Without pending, HLC 10 is retired after window eviction.
    try testing.expectEqual(Decision.retired, try guard.admit(key, 10, testId(10)));
    try testing.expectEqual(Decision.retired, try guard.admit(key, 5, testId(5)));
    try testing.expectEqual(Decision.origin_capacity, try guard.admit(testKey(2), 40, testId(40)));
}

test "E2EEGROUP pending exact prepare commits and proves after window eviction" {
    var guard = try Guard.init(testing.allocator, .{
        .window_size = 1,
        .max_origins = 1,
        .exact_history_size = 2,
    });
    defer guard.deinit();
    const key = testKey(0x51);
    const id = testId(0x10);

    try testing.expectEqual(Decision.accepted, try guard.admit(key, 10, id));
    var prep = switch (try guard.preparePendingExactResult(key, 10, id)) {
        .prepared => |p| p,
        else => return error.TestUnexpectedResult,
    };
    defer prep.deinit();
    prep.commit();
    try testing.expectEqual(@as(usize, 1), guard.exactHistoryOf(key).len);

    try testing.expectEqual(Decision.accepted, try guard.admit(key, 20, testId(0x20)));
    try testing.expectEqual(IdentityLookup.duplicate, guard.probeIdentity(.{
        .origin_pubkey = key,
        .hlc = 10,
        .relay_id = id,
    }));
    try testing.expectEqual(Decision.duplicate, try guard.admit(key, 10, id));
    try testing.expect(guard.releasePendingExact(key, 10, id));
    try testing.expectEqual(@as(usize, 0), guard.exactHistoryOf(key).len);
    try testing.expectEqual(Decision.retired, try guard.admit(key, 10, id));
}

test "E2EEGROUP pending capacity fails closed without mutation" {
    var guard = try Guard.init(testing.allocator, .{
        .window_size = 4,
        .max_origins = 1,
        .exact_history_size = 1,
    });
    defer guard.deinit();
    const key = testKey(0x52);
    try testing.expectEqual(Decision.accepted, try guard.admit(key, 10, testId(1)));
    var p1 = switch (try guard.preparePendingExactResult(key, 10, testId(1))) {
        .prepared => |p| p,
        else => return error.TestUnexpectedResult,
    };
    p1.commit();
    try testing.expectEqual(
        std.meta.Tag(Guard.PendingPrepare).origin_capacity,
        std.meta.activeTag(try guard.preparePendingExactResult(key, 20, testId(2))),
    );
    try testing.expectEqual(@as(usize, 1), guard.exactHistoryOf(key).len);
}

test "E2EEGROUP admission verifies before reserving replay state" {
    var guard = try Guard.init(testing.allocator, .{});
    defer guard.deinit();
    var kp = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0x73)));
    defer kp.deinit();
    var pubkey: [group_relay.pubkey_len]u8 = undefined;
    var signature: [group_relay.sig_len]u8 = undefined;
    const valid = try signedRecord(&kp, 41, "b3BhcXVlLWNvbnRyb2wtbWF0ZXJpYWw", &pubkey, &signature);

    var forged = valid;
    forged.payload = "Zm9yZ2VkLWNvbnRyb2wtbWF0ZXJpYWw";
    try testing.expectEqual(
        std.meta.Tag(Verification).bad_signature,
        std.meta.activeTag(try guard.verifyRecord(forged, 0, 0)),
    );
    const verified = switch (try guard.verifyRecord(valid, 0, 0)) {
        .verified => |identity| identity,
        else => return error.TestUnexpectedResult,
    };
    try testing.expectEqual(
        std.meta.Tag(Admission).accepted,
        std.meta.activeTag(try guard.admitAuthorized(verified)),
    );
    try testing.expectEqual(
        std.meta.Tag(Admission).duplicate,
        std.meta.activeTag(try guard.admitAuthorized(verified)),
    );
}

test "E2EEGROUP checkpoint seals pending and receipts only" {
    const cfg = Config{ .window_size = 2, .max_origins = 1, .exact_history_size = 4 };
    var guard = try Guard.init(testing.allocator, cfg);
    defer guard.deinit();
    const key = testKey(1);
    try testing.expectEqual(Decision.accepted, try guard.admit(key, 10, testId(10)));
    var prep = switch (try guard.preparePendingExactResult(key, 10, testId(10))) {
        .prepared => |p| p,
        else => return error.TestUnexpectedResult,
    };
    prep.commit();
    const receipts = [_]Receipt{.{
        .peer = 7,
        .relay_id = testId(10),
        .retry_after_ms = 100,
        .attempts = 2,
    }};
    const bytes = try guard.encodeCheckpointWithReceipts(testing.allocator, &receipts);
    defer testing.allocator.free(bytes);
    try testing.expect(isCheckpoint(bytes));
    try testing.expectEqual(cfg.exact_history_size, (try validateCheckpoint(bytes)).exact_history_size);

    var decoded = try Guard.decodeCheckpointWithReceipts(testing.allocator, cfg, bytes);
    defer {
        decoded.receipts.deinit(testing.allocator);
        decoded.guard.deinit();
    }
    try testing.expectEqual(@as(usize, 1), decoded.guard.exactHistoryOf(key).len);
    try testing.expectEqual(@as(usize, 1), decoded.receipts.items.len);
    try testing.expectEqual(@as(u32, 2), decoded.receipts.items[0].attempts);
}

test "E2EEGROUP checkpoint rejects pending without receipt" {
    const cfg = Config{ .window_size = 2, .max_origins = 1, .exact_history_size = 4 };
    var guard = try Guard.init(testing.allocator, cfg);
    defer guard.deinit();
    try testing.expectEqual(Decision.accepted, try guard.admit(testKey(1), 10, testId(10)));
    var prep = switch (try guard.preparePendingExactResult(testKey(1), 10, testId(10))) {
        .prepared => |p| p,
        else => return error.TestUnexpectedResult,
    };
    prep.commit();
    try testing.expectError(error.InvalidField, guard.encodeCheckpoint(testing.allocator));
}

test "E2EEGROUP pending prepare abort is allocation-free and leaves guard unchanged" {
    var guard = try Guard.init(testing.allocator, .{
        .window_size = 2,
        .max_origins = 1,
        .exact_history_size = 2,
    });
    defer guard.deinit();
    const key = testKey(0x61);
    try testing.expectEqual(Decision.accepted, try guard.admit(key, 10, testId(1)));
    const before = try guard.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(before);

    var prep = switch (try guard.preparePendingExactResult(key, 10, testId(1))) {
        .prepared => |p| p,
        else => return error.TestUnexpectedResult,
    };
    prep.abort();
    try testing.expectEqual(@as(usize, 0), guard.exactHistoryOf(key).len);
    try testing.expect(!guard.prepared_pending_active);

    const after = try guard.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(after);
    try testing.expectEqualSlices(u8, before, after);
}

test "E2EEGROUP pending prepare is OOM-atomic and retry succeeds" {
    const Sweep = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var guard = try Guard.init(allocator, .{
                .window_size = 2,
                .max_origins = 2,
                .exact_history_size = 4,
            });
            defer guard.deinit();
            const key = testKey(0x71);
            try testing.expectEqual(Decision.accepted, try guard.admit(key, 10, testId(1)));
            const before = try guard.encodeCheckpoint(testing.allocator);
            defer testing.allocator.free(before);

            var prep = guard.preparePendingExactResult(key, 10, testId(1)) catch |err| {
                try testing.expectEqual(@as(usize, 0), guard.exactHistoryOf(key).len);
                try testing.expect(!guard.prepared_pending_active);
                const after = try guard.encodeCheckpoint(testing.allocator);
                defer testing.allocator.free(after);
                try testing.expectEqualSlices(u8, before, after);
                return err;
            };
            switch (prep) {
                .prepared => |*p| {
                    p.commit();
                    try testing.expectEqual(@as(usize, 1), guard.exactHistoryOf(key).len);
                },
                else => return error.TestUnexpectedResult,
            }
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Sweep.run, .{});
}

test "E2EEGROUP authorization precedes replay mutation and future clocks fail closed" {
    var guard = try Guard.init(testing.allocator, .{});
    defer guard.deinit();
    var kp = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0x75)));
    defer kp.deinit();
    var pubkey_a: [group_relay.pubkey_len]u8 = undefined;
    var signature_a: [group_relay.sig_len]u8 = undefined;
    const now_ms: u64 = 1_700_000_000_000;
    const hlc = (now_ms << mesh_clock.seq_bits) | 1;
    const unauthorized = try signedRecord(
        &kp,
        hlc,
        "dW5hdXRob3JpemVk",
        &pubkey_a,
        &signature_a,
    );
    const rejected_identity = switch (try guard.verifyRecord(
        unauthorized,
        now_ms,
        mesh_clock.default_max_future_skew_ms,
    )) {
        .verified => |identity| identity,
        else => return error.TestUnexpectedResult,
    };
    // Membership/device policy rejects before admission — guard still empty.
    try testing.expectEqual(
        IdentityLookup.unseen,
        guard.probeIdentity(rejected_identity),
    );

    var pubkey_b: [group_relay.pubkey_len]u8 = undefined;
    var signature_b: [group_relay.sig_len]u8 = undefined;
    const authorized = try signedRecord(
        &kp,
        hlc,
        "YXV0aG9yaXplZA",
        &pubkey_b,
        &signature_b,
    );
    const accepted_identity = switch (try guard.verifyRecord(
        authorized,
        now_ms,
        mesh_clock.default_max_future_skew_ms,
    )) {
        .verified => |identity| identity,
        else => return error.TestUnexpectedResult,
    };
    try testing.expect(!isFutureSkewed(
        accepted_identity,
        now_ms,
        mesh_clock.default_max_future_skew_ms,
    ));
    try testing.expectEqual(
        std.meta.Tag(Admission).accepted,
        std.meta.activeTag(try guard.admitAuthorized(accepted_identity)),
    );

    var pubkey_future: [group_relay.pubkey_len]u8 = undefined;
    var signature_future: [group_relay.sig_len]u8 = undefined;
    const future = try signedRecord(
        &kp,
        std.math.maxInt(u64),
        "ZnV0dXJl",
        &pubkey_future,
        &signature_future,
    );
    try testing.expectEqual(
        std.meta.Tag(Verification).future_skew,
        std.meta.activeTag(try guard.verifyRecord(
            future,
            now_ms,
            mesh_clock.default_max_future_skew_ms,
        )),
    );
    try testing.expectEqual(
        std.meta.Tag(Verification).future_skew,
        std.meta.activeTag(try guard.verifyRecord(
            future,
            std.math.maxInt(u64),
            std.math.maxInt(u64),
        )),
    );
}

test "E2EEGROUP checkpoint config checksum and exact_history mismatch fail closed" {
    const cfg = Config{ .window_size = 2, .max_origins = 1, .exact_history_size = 4 };
    var guard = try Guard.init(testing.allocator, cfg);
    defer guard.deinit();
    try testing.expectEqual(Decision.accepted, try guard.admit(testKey(1), 10, testId(10)));
    const bytes = try guard.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(bytes);

    try testing.expect(isCheckpoint(bytes));
    try testing.expect(!replay.isCheckpoint(bytes));
    try testing.expectEqual(cfg, try validateCheckpoint(bytes));

    const corrupt = try testing.allocator.dupe(u8, bytes);
    defer testing.allocator.free(corrupt);
    if (corrupt.len > 20) corrupt[20] ^= 0x5a;
    try testing.expectError(error.ChecksumMismatch, validateCheckpoint(corrupt));
    try testing.expectError(
        error.ChecksumMismatch,
        Guard.decodeCheckpoint(testing.allocator, cfg, corrupt),
    );

    try testing.expectError(
        error.ExactHistorySizeMismatch,
        Guard.decodeCheckpoint(testing.allocator, .{
            .window_size = 2,
            .max_origins = 1,
            .exact_history_size = 8,
        }, bytes),
    );
    try testing.expectError(
        error.ConfigMismatch,
        Guard.decodeCheckpoint(testing.allocator, .{
            .window_size = 4,
            .max_origins = 1,
            .exact_history_size = 4,
        }, bytes),
    );
}

test "E2EEGROUP checkpoint allocation paths are leak-free and replacement is atomic" {
    const cfg = Config{ .window_size = 2, .max_origins = 2, .exact_history_size = 4 };
    var source = try Guard.init(testing.allocator, cfg);
    defer source.deinit();
    const key = testKey(0x81);
    try testing.expectEqual(Decision.accepted, try source.admit(key, 10, testId(10)));
    var prep = switch (try source.preparePendingExactResult(key, 10, testId(10))) {
        .prepared => |p| p,
        else => return error.TestUnexpectedResult,
    };
    prep.commit();
    const receipts = [_]Receipt{.{
        .peer = 3,
        .relay_id = testId(10),
        .retry_after_ms = 0,
        .attempts = 1,
    }};

    const EncodeSweep = struct {
        fn run(allocator: std.mem.Allocator, guard: *const Guard, r: []const Receipt) !void {
            const bytes = try guard.encodeCheckpointWithReceipts(allocator, r);
            defer allocator.free(bytes);
            try testing.expect(isCheckpoint(bytes));
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, EncodeSweep.run, .{ &source, &receipts });

    const checkpoint = try source.encodeCheckpointWithReceipts(testing.allocator, &receipts);
    defer testing.allocator.free(checkpoint);

    const DecodeSweep = struct {
        fn run(allocator: std.mem.Allocator, config: Config, bytes: []const u8) !void {
            var decoded = try Guard.decodeCheckpointWithReceipts(allocator, config, bytes);
            defer {
                decoded.receipts.deinit(allocator);
                decoded.guard.deinit();
            }
            try testing.expectEqual(@as(usize, 1), decoded.receipts.items.len);
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, DecodeSweep.run, .{ cfg, checkpoint });

    const ReplaceSweep = struct {
        fn run(allocator: std.mem.Allocator, config: Config, bytes: []const u8) !void {
            // Thread the failure-injected allocator through init + replace so
            // staged decode maps OOM fail closed without mutating live state.
            var guard = try Guard.init(allocator, config);
            defer guard.deinit();
            try testing.expectEqual(
                Decision.accepted,
                try guard.admit(testKey(0x82), 20, testId(20)),
            );
            const before = try guard.encodeCheckpoint(testing.allocator);
            defer testing.allocator.free(before);

            guard.replaceFromCheckpoint(bytes) catch |err| {
                const after_fail = try guard.encodeCheckpoint(testing.allocator);
                defer testing.allocator.free(after_fail);
                try testing.expectEqualSlices(u8, before, after_fail);
                return err;
            };
            try testing.expectEqual(@as(usize, 1), guard.exactHistoryOf(testKey(0x81)).len);
        }
    };
    try testing.checkAllAllocationFailures(
        testing.allocator,
        ReplaceSweep.run,
        .{ cfg, checkpoint },
    );

    var live = try Guard.init(testing.allocator, cfg);
    defer live.deinit();
    try testing.expectEqual(Decision.accepted, try live.admit(testKey(0x82), 20, testId(20)));
    const before = try live.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(before);
    const corrupt = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(corrupt);
    if (corrupt.len > 16) corrupt[16] ^= 1;
    try testing.expectError(error.ChecksumMismatch, live.replaceFromCheckpoint(corrupt));
    const after = try live.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(after);
    try testing.expectEqualSlices(u8, before, after);
}

fn testIdU64(n: u64) RelayId {
    var id: RelayId = @splat(0);
    std.mem.writeInt(u64, id[0..8], n, .big);
    return id;
}

fn resealCheckpoint(bytes: []u8) void {
    std.debug.assert(bytes.len >= header_len + checksum_len);
    const body_len: usize = std.mem.readInt(u32, bytes[5..9], .big);
    const prefix_len = header_len + body_len;
    std.debug.assert(bytes.len == prefix_len + checksum_len);
    checkpointChecksum(bytes[0..prefix_len], bytes[prefix_len..][0..checksum_len]);
}

test "E2EEGROUP encode rejects receipt count above u16 without trap" {
    const cfg = Config{ .window_size = 2, .max_origins = 1, .exact_history_size = 4 };
    var guard = try Guard.init(testing.allocator, cfg);
    defer guard.deinit();
    const key = testKey(0x91);
    const rid = testId(0x10);
    try testing.expectEqual(Decision.accepted, try guard.admit(key, 10, rid));
    var prep = switch (try guard.preparePendingExactResult(key, 10, rid)) {
        .prepared => |p| p,
        else => return error.TestUnexpectedResult,
    };
    prep.commit();

    // Over u16: fail-closed typed error before any sort/map work (no trap).
    const over = @as(usize, std.math.maxInt(u16)) + 1;
    const receipts = try testing.allocator.alloc(Receipt, over);
    defer testing.allocator.free(receipts);
    @memset(receipts, .{
        .peer = 1,
        .relay_id = rid,
        .retry_after_ms = 0,
        .attempts = 0,
    });
    try testing.expectError(
        error.CapacityExceeded,
        guard.encodeCheckpointWithReceipts(testing.allocator, receipts),
    );

    // Wire-coherent max is encodable: one receipt (count fits u16); outbox
    // hard_max_receipts == maxInt(u16) is covered in the outbox boundary test.
    const one = receipts[0..1];
    one[0].peer = 7;
    const sealed = try guard.encodeCheckpointWithReceipts(testing.allocator, one);
    defer testing.allocator.free(sealed);
    try testing.expect(isCheckpoint(sealed));
    try testing.expectEqual(@as(usize, std.math.maxInt(u16)), group_outbox.hard_max_receipts);
    try testing.expectEqual(
        @as(?u16, std.math.maxInt(u16)),
        std.math.cast(u16, group_outbox.hard_max_receipts),
    );
    try testing.expectEqual(
        @as(?u16, null),
        std.math.cast(u16, group_outbox.hard_max_receipts + 1),
    );
}

test "E2EEGROUP multi-origin aggregate pending above 4096 roundtrips and adopts" {
    // Per-origin cap remains exact_history_size; aggregate across origins may
    // exceed the old global [4096] workspace without CapacityExceeded.
    const per_origin: usize = 2049;
    const cfg = Config{
        .window_size = per_origin,
        .max_origins = 2,
        .exact_history_size = per_origin,
    };
    var guard = try Guard.init(testing.allocator, cfg);
    defer guard.deinit();

    const key_a = testKey(0xa1);
    const key_b = testKey(0xb2);
    var receipts = try testing.allocator.alloc(Receipt, per_origin * 2);
    defer testing.allocator.free(receipts);
    var ri: usize = 0;

    var i: usize = 0;
    while (i < per_origin) : (i += 1) {
        const hlc: u64 = 10 + i;
        const rid = testIdU64(0x1000 + i);
        try testing.expectEqual(Decision.accepted, try guard.admit(key_a, hlc, rid));
        var prep = switch (try guard.preparePendingExactResult(key_a, hlc, rid)) {
            .prepared => |p| p,
            else => return error.TestUnexpectedResult,
        };
        prep.commit();
        receipts[ri] = .{
            .peer = 1,
            .relay_id = rid,
            .retry_after_ms = 0,
            .attempts = 0,
        };
        ri += 1;
    }
    i = 0;
    while (i < per_origin) : (i += 1) {
        const hlc: u64 = 10 + i;
        const rid = testIdU64(0x8000 + i);
        try testing.expectEqual(Decision.accepted, try guard.admit(key_b, hlc, rid));
        var prep = switch (try guard.preparePendingExactResult(key_b, hlc, rid)) {
            .prepared => |p| p,
            else => return error.TestUnexpectedResult,
        };
        prep.commit();
        receipts[ri] = .{
            .peer = 2,
            .relay_id = rid,
            .retry_after_ms = 0,
            .attempts = 0,
        };
        ri += 1;
    }
    try testing.expectEqual(per_origin * 2, ri);
    try testing.expect(ri > 4096);
    try testing.expectEqual(per_origin, guard.exactHistoryOf(key_a).len);
    try testing.expectEqual(per_origin, guard.exactHistoryOf(key_b).len);

    const sealed = try guard.encodeCheckpointWithReceipts(testing.allocator, receipts);
    defer testing.allocator.free(sealed);
    try testing.expect(isCheckpoint(sealed));
    try testing.expectEqual(cfg, try validateCheckpoint(sealed));

    var decoded = try Guard.decodeCheckpointWithReceipts(testing.allocator, cfg, sealed);
    defer {
        decoded.receipts.deinit(testing.allocator);
        decoded.guard.deinit();
    }
    try testing.expectEqual(per_origin, decoded.guard.exactHistoryOf(key_a).len);
    try testing.expectEqual(per_origin, decoded.guard.exactHistoryOf(key_b).len);
    try testing.expectEqual(per_origin * 2, decoded.receipts.items.len);

    var adopt = try Guard.init(testing.allocator, cfg);
    defer adopt.deinit();
    try adopt.replaceFromCheckpoint(sealed);
    try testing.expectEqual(per_origin, adopt.exactHistoryOf(key_a).len);
    try testing.expectEqual(per_origin, adopt.exactHistoryOf(key_b).len);
}

test "E2EEGROUP checkpoint rejects malformed cross-section and within-origin RelayId duplicates" {
    const cfg = Config{ .window_size = 4, .max_origins = 2, .exact_history_size = 4 };
    var guard = try Guard.init(testing.allocator, cfg);
    defer guard.deinit();

    const key_a = testKey(0xc1);
    const key_b = testKey(0xc2);
    const rid_a = testIdU64(0x1111);
    const rid_b = testIdU64(0x2222);
    const rid_c = testIdU64(0x3333);

    try testing.expectEqual(Decision.accepted, try guard.admit(key_a, 10, rid_a));
    var pa = switch (try guard.preparePendingExactResult(key_a, 10, rid_a)) {
        .prepared => |p| p,
        else => return error.TestUnexpectedResult,
    };
    pa.commit();
    try testing.expectEqual(Decision.accepted, try guard.admit(key_a, 20, rid_c));
    var pc = switch (try guard.preparePendingExactResult(key_a, 20, rid_c)) {
        .prepared => |p| p,
        else => return error.TestUnexpectedResult,
    };
    pc.commit();
    try testing.expectEqual(Decision.accepted, try guard.admit(key_b, 10, rid_b));
    var pb = switch (try guard.preparePendingExactResult(key_b, 10, rid_b)) {
        .prepared => |p| p,
        else => return error.TestUnexpectedResult,
    };
    pb.commit();

    const receipts = [_]Receipt{
        .{ .peer = 1, .relay_id = rid_a, .retry_after_ms = 0, .attempts = 0 },
        .{ .peer = 1, .relay_id = rid_c, .retry_after_ms = 0, .attempts = 0 },
        .{ .peer = 2, .relay_id = rid_b, .retry_after_ms = 0, .attempts = 0 },
    };
    const sealed = try guard.encodeCheckpointWithReceipts(testing.allocator, &receipts);
    defer testing.allocator.free(sealed);

    // Cross-origin: force origin B's pending RelayId to equal origin A's first.
    {
        const dup = try testing.allocator.dupe(u8, sealed);
        defer testing.allocator.free(dup);
        const body = try openEnvelope(dup);
        const parsed = try parseEnvelopeBody(testing.allocator, body, null);
        // Exact section layout: [countA][entriesA...][countB][entriesB...]
        var p: usize = 0;
        const count_a: usize = std.mem.readInt(u16, parsed.exact_section[p..][0..2], .big);
        p += 2 + count_a * exact_entry_len;
        const count_b: usize = std.mem.readInt(u16, parsed.exact_section[p..][0..2], .big);
        try testing.expect(count_b >= 1);
        p += 2;
        // Body offset of this entry's RelayId inside the full checkpoint.
        const exact_off_in_body = @intFromPtr(parsed.exact_section.ptr) - @intFromPtr(body.ptr);
        const rid_off_in_envelope = header_len + exact_off_in_body + p + 8;
        @memcpy(dup[rid_off_in_envelope..][0..@sizeOf(RelayId)], &rid_a);
        // Receipt for origin B must still name the mutated id so only the
        // cross-section uniqueness check fails (not the receipt map).
        const receipt_off_in_body = @intFromPtr(parsed.receipt_section.ptr) - @intFromPtr(body.ptr);
        // receipt_section includes the u16 count prefix; rows start at +2.
        // Sorted receipts: peer1/rid_a, peer1/rid_c, peer2/rid_b → third row is rid_b.
        const third_rid = header_len + receipt_off_in_body + 2 + 2 * receipt_entry_len + 8;
        @memcpy(dup[third_rid..][0..@sizeOf(RelayId)], &rid_a);
        resealCheckpoint(dup);
        try testing.expectError(error.InvalidField, validateCheckpoint(dup));
        try testing.expectError(
            error.InvalidField,
            validateCheckpointWithAllocator(testing.allocator, dup),
        );
        try testing.expectError(
            error.InvalidField,
            Guard.decodeCheckpointWithReceipts(testing.allocator, cfg, dup),
        );
    }

    // Within-origin: force origin A's second RelayId to equal its first.
    {
        const dup = try testing.allocator.dupe(u8, sealed);
        defer testing.allocator.free(dup);
        const body = try openEnvelope(dup);
        const parsed = try parseEnvelopeBody(testing.allocator, body, null);
        const count_a: usize = std.mem.readInt(u16, parsed.exact_section[0..2], .big);
        try testing.expect(count_a >= 2);
        const exact_off_in_body = @intFromPtr(parsed.exact_section.ptr) - @intFromPtr(body.ptr);
        // Second entry RelayId of origin A.
        const rid_off = header_len + exact_off_in_body + 2 + 1 * exact_entry_len + 8;
        @memcpy(dup[rid_off..][0..@sizeOf(RelayId)], &rid_a);
        // Keep receipt map coherent for the duplicated id (rid_c receipt → rid_a).
        const receipt_off_in_body = @intFromPtr(parsed.receipt_section.ptr) - @intFromPtr(body.ptr);
        // Sorted: peer1/rid_a, peer1/rid_c, peer2/rid_b → second row is rid_c.
        const second_rid = header_len + receipt_off_in_body + 2 + 1 * receipt_entry_len + 8;
        @memcpy(dup[second_rid..][0..@sizeOf(RelayId)], &rid_a);
        resealCheckpoint(dup);
        try testing.expectError(error.InvalidField, validateCheckpoint(dup));
        try testing.expectError(
            error.InvalidField,
            Guard.decodeCheckpointWithReceipts(testing.allocator, cfg, dup),
        );
    }

    // Missing cross-section: rid_c loses its only receipt (mapped onto rid_b,
    // already covered by peer2 — not a (peer,rid) duplicate).
    {
        const dup = try testing.allocator.dupe(u8, sealed);
        defer testing.allocator.free(dup);
        const body = try openEnvelope(dup);
        const parsed = try parseEnvelopeBody(testing.allocator, body, null);
        const receipt_off_in_body = @intFromPtr(parsed.receipt_section.ptr) - @intFromPtr(body.ptr);
        const second_rid = header_len + receipt_off_in_body + 2 + 1 * receipt_entry_len + 8;
        @memcpy(dup[second_rid..][0..@sizeOf(RelayId)], &rid_b);
        resealCheckpoint(dup);
        try testing.expectError(error.InvalidField, validateCheckpoint(dup));
    }

    // Orphan receipt: receipt RelayId not present in any exact section.
    {
        const orphan = testIdU64(0xdead);
        const dup = try testing.allocator.dupe(u8, sealed);
        defer testing.allocator.free(dup);
        const body = try openEnvelope(dup);
        const parsed = try parseEnvelopeBody(testing.allocator, body, null);
        const receipt_off_in_body = @intFromPtr(parsed.receipt_section.ptr) - @intFromPtr(body.ptr);
        const second_rid = header_len + receipt_off_in_body + 2 + 1 * receipt_entry_len + 8;
        @memcpy(dup[second_rid..][0..@sizeOf(RelayId)], &orphan);
        resealCheckpoint(dup);
        try testing.expectError(error.InvalidField, validateCheckpoint(dup));
    }
}

test "E2EEGROUP checkpoint join work is linear at 65535 rows across many origins" {
    // 255 origins × 257 pending exacts = 65535 receipts (u16 max). Structural
    // hash-op budget is O(n); no wall-clock threshold.
    const origins: usize = 255;
    const per_origin: usize = 257;
    const total_rows: usize = origins * per_origin;
    try testing.expectEqual(@as(usize, std.math.maxInt(u16)), total_rows);

    const cfg = Config{
        .window_size = per_origin,
        .max_origins = origins,
        .exact_history_size = per_origin,
    };
    var guard = try Guard.init(testing.allocator, cfg);
    defer guard.deinit();

    var receipts = try testing.allocator.alloc(Receipt, total_rows);
    defer testing.allocator.free(receipts);
    var ri: usize = 0;
    var o: usize = 0;
    while (o < origins) : (o += 1) {
        var pk = testKey(0);
        std.mem.writeInt(u16, pk[0..2], @intCast(o + 1), .big);
        var i: usize = 0;
        while (i < per_origin) : (i += 1) {
            const hlc: u64 = 1 + i;
            // Globally unique RelayIds: origin << 32 | index.
            const rid = testIdU64((@as(u64, @intCast(o)) << 32) | @as(u64, @intCast(i)));
            try testing.expectEqual(Decision.accepted, try guard.admit(pk, hlc, rid));
            var prep = switch (try guard.preparePendingExactResult(pk, hlc, rid)) {
                .prepared => |p| p,
                else => return error.TestUnexpectedResult,
            };
            prep.commit();
            receipts[ri] = .{
                .peer = @as(u64, @intCast(o + 1)),
                .relay_id = rid,
                .retry_after_ms = 0,
                .attempts = 0,
            };
            ri += 1;
        }
    }
    try testing.expectEqual(total_rows, ri);

    var encode_work: CheckpointJoinWork = .{};
    const sealed = try encodeEnvelopeWork(testing.allocator, &guard, receipts, &encode_work);
    defer testing.allocator.free(sealed);
    try testing.expect(isCheckpoint(sealed));

    // Hash ops: origin set inserts + pending contains + exact inserts + receipt
    // contains/puts. Bound is a small constant × rows (quadratic would be ~2e9).
    const encode_budget = 16 * (total_rows + origins + 8);
    try testing.expect(encode_work.hash_ops <= encode_budget);
    try testing.expect(encode_work.hash_ops >= total_rows);

    var parse_work: CheckpointJoinWork = .{};
    const validated = try validateCheckpointWithAllocatorWork(
        testing.allocator,
        sealed,
        &parse_work,
    );
    try testing.expectEqual(cfg, validated);
    // Parse: window HLC map build + exact O(1) lookups + exact inserts +
    // receipt contains/puts. Linear in rows; extended vs pre-map budget.
    const parse_budget = 24 * (total_rows + origins + 8);
    try testing.expect(parse_work.hash_ops <= parse_budget);
    try testing.expect(parse_work.hash_ops >= total_rows);

    var decoded = try Guard.decodeCheckpointWithReceipts(testing.allocator, cfg, sealed);
    defer {
        decoded.receipts.deinit(testing.allocator);
        decoded.guard.deinit();
    }
    try testing.expectEqual(total_rows, decoded.receipts.items.len);
}
