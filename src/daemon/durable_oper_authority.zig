// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! OCG2 durable authority image. This leaf owns persistence semantics only; it
//! is intentionally not consulted by runtime operator authorization.
//!
//! The durable cut is the caller's successful prepared OroStore snapshot put.
//! Every allocation, validation, replacement image, and encoded snapshot is
//! completed before that cut. After a successful store commit, `commitInto` is
//! allocation-free. An ambiguous store result cannot be rolled back in-process:
//! callers must make privilege serving unavailable and reopen/replay the store.

const std = @import("std");
const oper_cred_share = @import("../proto/oper_cred_share.zig");
const node_identity = @import("node_identity.zig");
const node_short_id = @import("../crypto/node_short_id.zig");

const Ed25519 = std.crypto.sign.Ed25519;
const Blake3 = std.crypto.hash.Blake3;

pub const magic = "OCG2STATE";
/// Snapshot version currently emitted by the inactive authority image.  v3
/// separates the durable security-time floor from its reservation horizon and
/// records whether an explicit reservation cut has authorized inspection.
pub const version: u8 = 3;
/// v2 carried only `reserved_until_ms`.  It remains strict-decode-only and is
/// never serving until a v3 reservation cut supplies a floor and authorization.
pub const reservation_only_version: u8 = 2;
/// Version accepted only as an exact legacy image.  Decoding it does not make
/// a v1 image authoritative for new writes: the next prepared cut emits v2.
pub const legacy_version: u8 = 1;
pub const marker_magic = "OCG2INIT";
pub const marker_version: u8 = 1;
pub const marker_key = "ocg2:init";
pub const snapshot_key = "ocg2:snapshot";
pub const max_records: usize = 256;
pub const max_snapshot_bytes: usize = 512 * 1024;
pub const digest_len = Blake3.digest_length;
pub const max_wire_len = oper_cred_share.ocg2_max_wire_len;
pub const max_account_len = oper_cred_share.ocg2_max_account_len;
/// Inactive security-horizon renewal lead time.  A remaining reservation at or
/// below this threshold must be extended by `security_horizon_window_ms`.
pub const security_horizon_renewal_threshold_ms: u64 = 3_600_000;
/// Durable reservation window: one OCG2 TTL plus the renewal threshold.
pub const security_horizon_window_ms: u64 = oper_cred_share.ocg2_max_ttl_ms + security_horizon_renewal_threshold_ms;

comptime {
    if (security_horizon_renewal_threshold_ms != 3_600_000)
        @compileError("S6-C2 renewal threshold is frozen at 3_600_000ms");
    if (oper_cred_share.ocg2_max_ttl_ms != 86_400_000)
        @compileError("S6-C2 window depends on the frozen 24h OCG2 TTL");
    if (security_horizon_window_ms != 90_000_000)
        @compileError("S6-C2 window is frozen at ocg2_max_ttl_ms + threshold");
    if (security_horizon_window_ms != oper_cred_share.ocg2_max_ttl_ms + security_horizon_renewal_threshold_ms)
        @compileError("S6-C2 window must be TTL plus the renewal threshold");
}
pub const marker_len = marker_magic.len + 1 + 8 + Ed25519.PublicKey.encoded_length + digest_len;
const legacy_header_len = magic.len + 1 + 8 + Ed25519.PublicKey.encoded_length + 8 + 4;
// v2 appends the security-time reservation after the unchanged v1 fields.
// Keeping the v1 prefix byte-identical makes strict migration and old image
// diagnostics straightforward while preserving the global revision layout.
const reservation_header_len = legacy_header_len + 8;
// v3 appends the durable boot floor and explicit reservation authorization.
const header_len = reservation_header_len + 8 + 1;
const record_fixed_len = 1 + 8 + 1 + 1 + 8 + 8 + digest_len + digest_len + 2;
const trailer_len = digest_len;
const snapshot_domain_v1 = "onyx-server-ocg2-authority-state-v1";
const snapshot_domain_v2 = "onyx-server-ocg2-authority-state-v2";
const snapshot_domain_v3 = "onyx-server-ocg2-authority-state-v3";
// Existing tests and local callers use this name for the currently emitted
// image.  Legacy decode selects snapshot_domain_v1 explicitly.
const snapshot_domain = snapshot_domain_v3;
const marker_domain = "onyx-server-ocg2-authority-marker-v1";

const store_payload_header_len: usize = 10;
const store_record_header_len: usize = 8;
pub const max_store_payload_bytes = store_payload_header_len + snapshot_key.len + max_snapshot_bytes;
pub const max_store_wal_record_bytes = store_record_header_len + max_store_payload_bytes;

pub const Config = struct {
    authority_node_id: u64,
    authority_pubkey: [Ed25519.PublicKey.encoded_length]u8,
};

pub const Error = error{
    InvalidAuthority,
    BadMagic,
    BadVersion,
    BadChecksum,
    Truncated,
    TrailingBytes,
    NonCanonical,
    InvalidRecord,
    CapacityExceeded,
    BoundsExceeded,
    PreparedMutationActive,
    GenerationExhausted,
    ReservationNotExtended,
    ReservationOverflow,
    StateUnavailable,
    StateDestroyed,
};

pub const PrepareError = Error || oper_cred_share.Ocg2Error || std.mem.Allocator.Error;

pub const RecordView = struct {
    account: []const u8,
    revision: u64,
    kind: oper_cred_share.Ocg2Kind,
    issued_ms: u64,
    expiry_ms: u64,
    digest: [digest_len]u8,
    conflict_digest: [digest_len]u8,
    equivocation: bool,
    wire: []const u8,

    pub fn effective(self: RecordView, now_ms: u64) bool {
        return !self.equivocation and self.kind == .grant and
            self.issued_ms <= now_ms and now_ms < self.expiry_ms;
    }
};

/// Allocation-free copied identity of one durable OCG2 transaction.  The
/// copy deliberately includes both digest domains: `digest` is the persisted
/// BLAKE3 identity and `wire_sha256` is the exact-wire inspection identity.
/// `conflict_digest` is zero for a non-equivocated record and the other
/// terminal digest for an equivocation.
pub const TransactionCopy = struct {
    account_buf: [max_account_len]u8 = @splat(0),
    account_len: usize = 0,
    revision: u64 = 0,
    kind: oper_cred_share.Ocg2Kind = .grant,
    issued_ms: u64 = 0,
    expiry_ms: u64 = 0,
    authority_node_id: u64 = 0,
    authority_pubkey: [Ed25519.PublicKey.encoded_length]u8 = @splat(0),
    digest: [digest_len]u8 = @splat(0),
    wire_sha256: [digest_len]u8 = @splat(0),
    conflict_digest: [digest_len]u8 = @splat(0),
    equivocation: bool = false,
    wire_buf: [max_wire_len]u8 = @splat(0),
    wire_len: usize = 0,

    pub fn account(self: *const TransactionCopy) []const u8 {
        return self.account_buf[0..self.account_len];
    }

    pub fn signedWire(self: *const TransactionCopy) []const u8 {
        return self.wire_buf[0..self.wire_len];
    }
};

pub const CopyTransactionsError = error{
    CapacityExceeded,
    InvalidRecord,
};

const OwnedRecord = struct {
    account: []u8,
    revision: u64,
    kind: oper_cred_share.Ocg2Kind,
    issued_ms: u64,
    expiry_ms: u64,
    digest: [digest_len]u8,
    conflict_digest: [digest_len]u8 = @splat(0),
    equivocation: bool = false,
    wire: []u8,

    fn fromVerified(allocator: std.mem.Allocator, fields: oper_cred_share.Ocg2Fields, wire: []const u8) !OwnedRecord {
        const account = try allocator.dupe(u8, fields.account);
        errdefer allocator.free(account);
        return .{
            .account = account,
            .revision = fields.revision,
            .kind = fields.kind,
            .issued_ms = fields.issued_ms,
            .expiry_ms = fields.expiry_ms,
            .digest = digestWire(wire),
            .wire = try allocator.dupe(u8, wire),
        };
    }

    fn clone(self: *const OwnedRecord, allocator: std.mem.Allocator) !OwnedRecord {
        const account = try allocator.dupe(u8, self.account);
        errdefer allocator.free(account);
        return .{
            .account = account,
            .revision = self.revision,
            .kind = self.kind,
            .issued_ms = self.issued_ms,
            .expiry_ms = self.expiry_ms,
            .digest = self.digest,
            .conflict_digest = self.conflict_digest,
            .equivocation = self.equivocation,
            .wire = try allocator.dupe(u8, self.wire),
        };
    }

    fn view(self: *const OwnedRecord) RecordView {
        return .{
            .account = self.account,
            .revision = self.revision,
            .kind = self.kind,
            .issued_ms = self.issued_ms,
            .expiry_ms = self.expiry_ms,
            .digest = self.digest,
            .conflict_digest = self.conflict_digest,
            .equivocation = self.equivocation,
            .wire = self.wire,
        };
    }

    fn deinit(self: *OwnedRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.account);
        allocator.free(self.wire);
        self.* = undefined;
    }
};

const ActivePrepared = struct {
    generation: u64,
    expected_epoch: u64,
    records: std.ArrayListUnmanaged(OwnedRecord),
    local_revision_floor: u64,
    security_floor_ms: u64,
    reserved_until_ms: u64,
    security_time_authorized: bool,
    security_clock_started: bool,
    security_boot_effective_ms: u64,
    security_last_effective_ms: u64,
    snapshot: []u8,

    fn deinit(self: *ActivePrepared, allocator: std.mem.Allocator) void {
        deinitRecords(allocator, &self.records);
        allocator.free(self.snapshot);
        self.* = undefined;
    }
};

pub const State = struct {
    allocator: std.mem.Allocator,
    config: Config,
    records: std.ArrayListUnmanaged(OwnedRecord) = .empty,
    local_revision_floor: u64 = 0,
    /// Last durable lower bound used as the boot anchor after reopen.
    security_floor_ms: u64 = 0,
    /// Highest security-time horizon that has crossed a durable cut.  Zero
    /// means no runtime security time has been reserved yet.
    reserved_until_ms: u64 = 0,
    /// Only an explicit security-time reservation cut authorizes inspection.
    security_time_authorized: bool = false,
    /// Process-local clock anchors.  They are deliberately not encoded: reopen
    /// starts from `security_floor_ms` and never trusts a carried monotonic age.
    security_clock_started: bool = false,
    security_boot_effective_ms: u64 = 0,
    security_last_effective_ms: u64 = 0,
    snapshot_bytes: []u8 = &.{},
    epoch: u64 = 0,
    generation: u64 = 0,
    active: ?ActivePrepared = null,
    serving_available: bool = false,
    destroyed: bool = false,

    pub fn init(allocator: std.mem.Allocator, config: Config) Error!State {
        try validateConfig(config);
        return .{ .allocator = allocator, .config = config };
    }

    pub fn deinit(self: *State) void {
        if (self.destroyed) return;
        if (self.active) |*active| active.deinit(self.allocator);
        deinitRecords(self.allocator, &self.records);
        self.allocator.free(self.snapshot_bytes);
        self.destroyed = true;
    }

    pub fn count(self: *const State) usize {
        return self.records.items.len;
    }

    pub fn snapshot(self: *const State) []const u8 {
        return self.snapshot_bytes;
    }

    pub fn authority(self: *const State) Config {
        return self.config;
    }

    /// Return the persisted security-time horizon.  This value only advances
    /// through `prepareSecurityTimeReservation` followed by a durable cut.
    pub fn securityReservedUntil(self: *const State) u64 {
        return self.reserved_until_ms;
    }

    pub fn securityFloor(self: *const State) u64 {
        return self.security_floor_ms;
    }

    pub fn securityTimeAuthorized(self: *const State) bool {
        return self.security_time_authorized;
    }

    /// True when a strict v1/v2 image is awaiting its first v3 prepared cut.
    /// Legacy images remain inactive until an explicit security reservation.
    pub fn requiresV2Migration(self: *const State) bool {
        return self.snapshot_bytes.len > magic.len and
            self.snapshot_bytes[magic.len] != version;
    }

    pub fn latest(self: *const State, account: []const u8) ?RecordView {
        const index = lowerBound(self.records.items, account);
        if (index == self.records.items.len or !std.mem.eql(u8, self.records.items[index].account, account)) return null;
        return self.records.items[index].view();
    }

    pub fn effective(self: *const State, account: []const u8, now_ms: u64) ?RecordView {
        if (!self.serving_available) return null;
        const record = self.latest(account) orelse return null;
        return if (record.effective(now_ms)) record else null;
    }

    pub fn servingAvailable(self: *const State) bool {
        return self.serving_available;
    }

    pub fn markUnavailable(self: *State) void {
        self.serving_available = false;
    }

    pub fn prepareMerge(self: *State, wire: []const u8, now_ms: u64) PrepareError!PrepareOutcome {
        if (self.destroyed) return error.StateDestroyed;
        if (self.active != null) return error.PreparedMutationActive;
        if (wire.len > max_wire_len) return error.BoundsExceeded;
        const public_key = Ed25519.PublicKey.fromBytes(self.config.authority_pubkey) catch return error.InvalidAuthority;
        const fields = try oper_cred_share.verifyOcg2(wire, public_key, self.config.authority_node_id, now_ms);
        const incoming_digest = digestWire(wire);
        const index = lowerBound(self.records.items, fields.account);
        const exists = index < self.records.items.len and std.mem.eql(u8, self.records.items[index].account, fields.account);
        if (exists) {
            const old = &self.records.items[index];
            if (fields.revision < old.revision) return .stale;
            if (fields.revision == old.revision and std.mem.eql(u8, &incoming_digest, &old.digest)) return .replay;
            if (fields.revision == old.revision and old.equivocation and
                std.mem.eql(u8, &incoming_digest, &old.conflict_digest)) return .replay;
        } else if (self.records.items.len >= max_records) return error.CapacityExceeded;

        var replacement = try cloneRecords(self.allocator, self.records.items, self.records.items.len + @intFromBool(!exists));
        errdefer deinitRecords(self.allocator, &replacement);
        var disposition: UpdateDisposition = .successor;
        if (exists and fields.revision == replacement.items[index].revision) {
            const old_digest = replacement.items[index].digest;
            const old_high = if (replacement.items[index].equivocation)
                replacement.items[index].conflict_digest
            else
                old_digest;
            if (std.mem.order(u8, &incoming_digest, &old_digest) == .lt) {
                var incoming = try OwnedRecord.fromVerified(self.allocator, fields, wire);
                incoming.equivocation = true;
                incoming.conflict_digest = old_high;
                replacement.items[index].deinit(self.allocator);
                replacement.items[index] = incoming;
            } else {
                replacement.items[index].equivocation = true;
                if (std.mem.order(u8, &incoming_digest, &old_high) == .gt)
                    replacement.items[index].conflict_digest = incoming_digest;
            }
            disposition = .equivocation;
        } else {
            const incoming = try OwnedRecord.fromVerified(self.allocator, fields, wire);
            if (exists) {
                replacement.items[index].deinit(self.allocator);
                replacement.items[index] = incoming;
            } else {
                replacement.appendAssumeCapacity(incoming);
                var cursor = replacement.items.len - 1;
                while (cursor > index) : (cursor -= 1) replacement.items[cursor] = replacement.items[cursor - 1];
                replacement.items[index] = incoming;
            }
        }
        return try self.installPrepared(
            replacement,
            @max(self.local_revision_floor, fields.revision),
            self.security_floor_ms,
            self.reserved_until_ms,
            self.security_time_authorized,
            disposition,
            null,
        );
    }

    /// Prepare a durable authority-side revision allocation. The returned
    /// revision is candidate-only until the caller durably commits `snapshot()`;
    /// no transmitter exists in this module and callers must not expose it first.
    pub fn prepareRevision(self: *State, account: []const u8) PrepareError!PreparedRevision {
        if (self.destroyed) return error.StateDestroyed;
        if (self.active != null) return error.PreparedMutationActive;
        if (!validAccount(account)) return error.InvalidRecord;
        var floor = self.local_revision_floor;
        if (self.latest(account)) |record| floor = @max(floor, record.revision);
        if (floor == std.math.maxInt(u64)) return error.GenerationExhausted;
        const revision = floor + 1;
        var replacement = try cloneRecords(self.allocator, self.records.items, self.records.items.len);
        errdefer deinitRecords(self.allocator, &replacement);
        const outcome = try self.installPrepared(
            replacement,
            revision,
            self.security_floor_ms,
            self.reserved_until_ms,
            self.security_time_authorized,
            .revision_only,
            revision,
        );
        return switch (outcome) {
            .update => |update| .{ .update = update, .revision = revision },
            else => unreachable,
        };
    }

    /// Prepare a monotonic security-time reservation.  The returned prepared
    /// value has no externally visible effect until its snapshot crosses the
    /// caller's OroStore durable cut and `commitIntoChecked` succeeds.
    pub fn prepareSecurityTimeReservation(
        self: *State,
        raw_now_ms: u64,
        new_reserved_until_ms: u64,
    ) PrepareError!PreparedSecurityTimeReservation {
        if (self.destroyed) return error.StateDestroyed;
        if (self.active != null) return error.PreparedMutationActive;
        if (self.security_time_authorized and !self.serving_available) return error.StateUnavailable;
        if (new_reserved_until_ms < self.reserved_until_ms) return error.ReservationNotExtended;
        if (new_reserved_until_ms == self.reserved_until_ms) return error.ReservationNotExtended;
        var clock_started = self.security_clock_started;
        var boot_effective_ms = self.security_boot_effective_ms;
        var last_effective_ms = self.security_last_effective_ms;
        if (!clock_started) {
            boot_effective_ms = @max(raw_now_ms, self.security_floor_ms);
            last_effective_ms = boot_effective_ms;
            clock_started = true;
        } else {
            last_effective_ms = @max(last_effective_ms, raw_now_ms);
        }
        const required_floor_ms = @max(
            @max(self.security_floor_ms, self.reserved_until_ms),
            last_effective_ms,
        );
        if (new_reserved_until_ms <= required_floor_ms) return error.ReservationOverflow;
        // The durable boot floor advances to the reserved horizon.  The live
        // process retains its lower in-memory boot anchor, so it can use the
        // interval immediately; a restart fast-forwards to the horizon and must
        // reserve the next interval before time advances again.  This prevents
        // any time observed within the prior reservation from resurrecting.
        const next_floor_ms = new_reserved_until_ms;
        var replacement = try cloneRecords(self.allocator, self.records.items, self.records.items.len);
        errdefer deinitRecords(self.allocator, &replacement);
        const outcome = try self.installPrepared(
            replacement,
            self.local_revision_floor,
            next_floor_ms,
            new_reserved_until_ms,
            true,
            .reservation_only,
            null,
        );
        const active = &self.active.?;
        active.security_clock_started = clock_started;
        active.security_boot_effective_ms = boot_effective_ms;
        active.security_last_effective_ms = last_effective_ms;
        return switch (outcome) {
            .update => |update| .{ .update = update, .reserved_until_ms = new_reserved_until_ms },
            else => unreachable,
        };
    }

    /// Allocation-free copy of every latest durable transaction in canonical
    /// account order, including future, expired, tombstone, and equivocation
    /// records.  Destination bytes are untouched unless every record validates
    /// and `out` can hold the complete set.
    pub fn copyTransactions(self: *const State, out: []TransactionCopy) CopyTransactionsError!usize {
        if (self.destroyed) return error.InvalidRecord;
        const needed = self.records.items.len;
        if (out.len < needed) return error.CapacityExceeded;
        for (self.records.items) |*record| {
            if (copyTransaction(self.config, record.view()) == null) return error.InvalidRecord;
        }
        for (self.records.items, 0..) |*record, index| {
            out[index] = copyTransaction(self.config, record.view()).?;
        }
        return needed;
    }

    /// Test-only digest flip used to prove copyTransactions fails closed
    /// without writing a partial destination.  Not a production mutation API.
    pub fn testXorRecordDigest(self: *State, index: usize) void {
        if (index >= self.records.items.len) return;
        self.records.items[index].digest[0] ^= 0xff;
    }

    /// Overlay process-local security anchors onto the active prepared
    /// reservation so an elapsed-derived effective time survives the durable
    /// cut.  The overlay is discarded if the caller aborts before commit.
    pub fn overlayPreparedSecurityAnchors(
        self: *State,
        boot_effective_ms: u64,
        last_effective_ms: u64,
    ) bool {
        const active = &(self.active orelse return false);
        active.security_clock_started = true;
        active.security_boot_effective_ms = boot_effective_ms;
        active.security_last_effective_ms = last_effective_ms;
        return true;
    }

    fn installPrepared(
        self: *State,
        replacement: std.ArrayListUnmanaged(OwnedRecord),
        revision_floor: u64,
        security_floor_ms: u64,
        reserved_until_ms: u64,
        security_time_authorized: bool,
        disposition: UpdateDisposition,
        allocated_revision: ?u64,
    ) PrepareError!PrepareOutcome {
        if (self.generation == std.math.maxInt(u64)) return error.GenerationExhausted;
        const next_generation = self.generation + 1;
        const image = try encodeRecords(
            self.allocator,
            self.config,
            revision_floor,
            security_floor_ms,
            reserved_until_ms,
            security_time_authorized,
            replacement.items,
        );
        self.active = .{
            .generation = next_generation,
            .expected_epoch = self.epoch,
            .records = replacement,
            .local_revision_floor = revision_floor,
            .security_floor_ms = security_floor_ms,
            .reserved_until_ms = reserved_until_ms,
            .security_time_authorized = security_time_authorized,
            .security_clock_started = self.security_clock_started,
            .security_boot_effective_ms = self.security_boot_effective_ms,
            .security_last_effective_ms = self.security_last_effective_ms,
            .snapshot = image,
        };
        self.generation = next_generation;
        return .{ .update = .{
            .state = self,
            .generation = next_generation,
            .disposition = disposition,
            .allocated_revision = allocated_revision,
            .reserved_until_ms = reserved_until_ms,
        } };
    }
};

pub const UpdateDisposition = enum { successor, equivocation, revision_only, reservation_only };
pub const PrepareOutcome = union(enum) { stale, replay, update: PreparedUpdate };
pub const PreparedRevision = struct { update: PreparedUpdate, revision: u64 };
pub const PreparedSecurityTimeReservation = struct {
    update: PreparedUpdate,
    reserved_until_ms: u64,
};

pub const PreparedUpdate = struct {
    state: *State,
    generation: u64,
    disposition: UpdateDisposition,
    allocated_revision: ?u64,
    reserved_until_ms: u64,

    pub fn snapshot(self: *const PreparedUpdate) []const u8 {
        const active = self.state.active orelse return &.{};
        return if (active.generation == self.generation) active.snapshot else &.{};
    }

    pub fn commitInto(self: *PreparedUpdate, state: *State) void {
        _ = self.commitIntoChecked(state);
    }

    /// Allocation-free publication with an explicit success result for callers
    /// that have already crossed a durable boundary and must fail closed if an
    /// impossible lifecycle/generation mismatch is observed.
    pub fn commitIntoChecked(self: *PreparedUpdate, state: *State) bool {
        if (state != self.state or state.destroyed) return false;
        const active_view = state.active orelse return false;
        if (active_view.generation != self.generation or active_view.expected_epoch != state.epoch) return false;
        const active = state.active.?;
        state.active = null;
        var old_records = state.records;
        const old_snapshot = state.snapshot_bytes;
        state.records = active.records;
        state.local_revision_floor = active.local_revision_floor;
        state.security_floor_ms = active.security_floor_ms;
        state.reserved_until_ms = active.reserved_until_ms;
        state.security_time_authorized = active.security_time_authorized;
        state.security_clock_started = active.security_clock_started;
        state.security_boot_effective_ms = active.security_boot_effective_ms;
        state.security_last_effective_ms = active.security_last_effective_ms;
        state.serving_available = active.security_time_authorized;
        state.snapshot_bytes = active.snapshot;
        state.epoch +%= 1;
        deinitRecords(state.allocator, &old_records);
        state.allocator.free(old_snapshot);
        return true;
    }

    pub fn abort(self: *PreparedUpdate) void {
        const active_view = self.state.active orelse return;
        if (active_view.generation != self.generation) return;
        var active = self.state.active.?;
        self.state.active = null;
        active.deinit(self.state.allocator);
    }
};

pub fn marker(config: Config, out: *[marker_len]u8) Error![]const u8 {
    try validateConfig(config);
    var pos: usize = 0;
    @memcpy(out[pos..][0..marker_magic.len], marker_magic);
    pos += marker_magic.len;
    out[pos] = marker_version;
    pos += 1;
    std.mem.writeInt(u64, out[pos..][0..8], config.authority_node_id, .big);
    pos += 8;
    @memcpy(out[pos..][0..config.authority_pubkey.len], &config.authority_pubkey);
    pos += config.authority_pubkey.len;
    checksum(marker_domain, out[0..pos], out[pos..][0..digest_len]);
    return out;
}

pub fn validateMarker(bytes: []const u8, config: Config) Error!void {
    var expected: [marker_len]u8 = undefined;
    const canonical = try marker(config, &expected);
    if (!std.mem.eql(u8, bytes, canonical)) return error.InvalidAuthority;
}

pub fn encode(allocator: std.mem.Allocator, state: *const State) ![]u8 {
    return encodeRecords(
        allocator,
        state.config,
        state.local_revision_floor,
        state.security_floor_ms,
        state.reserved_until_ms,
        state.security_time_authorized,
        state.records.items,
    );
}

pub fn decode(allocator: std.mem.Allocator, config: Config, bytes: []const u8) PrepareError!State {
    try validateConfig(config);
    if (bytes.len < legacy_header_len + trailer_len) return error.Truncated;
    if (bytes.len > max_snapshot_bytes) return error.BoundsExceeded;
    if (!std.mem.eql(u8, bytes[0..magic.len], magic)) return error.BadMagic;
    const snapshot_version = bytes[magic.len];
    if (snapshot_version != legacy_version and snapshot_version != reservation_only_version and
        snapshot_version != version) return error.BadVersion;
    const body_end = bytes.len - trailer_len;
    var expected_checksum: [digest_len]u8 = undefined;
    checksum(
        switch (snapshot_version) {
            legacy_version => snapshot_domain_v1,
            reservation_only_version => snapshot_domain_v2,
            version => snapshot_domain_v3,
            else => unreachable,
        },
        bytes[0..body_end],
        &expected_checksum,
    );
    if (!std.mem.eql(u8, &expected_checksum, bytes[body_end..])) return error.BadChecksum;
    var pos: usize = magic.len + 1;
    const authority_node = takeU64(bytes[0..body_end], &pos) orelse return error.Truncated;
    const authority_key = take(bytes[0..body_end], &pos, config.authority_pubkey.len) orelse return error.Truncated;
    if (authority_node != config.authority_node_id or !std.mem.eql(u8, authority_key, &config.authority_pubkey)) return error.InvalidAuthority;
    const revision_floor = takeU64(bytes[0..body_end], &pos) orelse return error.Truncated;
    const count = takeU32(bytes[0..body_end], &pos) orelse return error.Truncated;
    const reserved_until_ms = if (snapshot_version == reservation_only_version or snapshot_version == version)
        (takeU64(bytes[0..body_end], &pos) orelse return error.Truncated)
    else
        0;
    const security_floor_ms = if (snapshot_version == version)
        (takeU64(bytes[0..body_end], &pos) orelse return error.Truncated)
    else
        0;
    const security_time_authorized = if (snapshot_version == version) blk: {
        const flag = (take(bytes[0..body_end], &pos, 1) orelse return error.Truncated)[0];
        if (flag > 1) return error.NonCanonical;
        break :blk flag == 1;
    } else false;
    if (security_time_authorized and (reserved_until_ms == 0 or reserved_until_ms < security_floor_ms))
        return error.NonCanonical;
    if (!security_time_authorized and security_floor_ms != 0) return error.NonCanonical;
    if (count > max_records) return error.CapacityExceeded;
    var state = try State.init(allocator, config);
    errdefer state.deinit();
    try state.records.ensureTotalCapacity(allocator, @intCast(count));
    var previous: []const u8 = "";
    var maximum_revision: u64 = 0;
    for (0..count) |_| {
        const account_len = (take(bytes[0..body_end], &pos, 1) orelse return error.Truncated)[0];
        const account = take(bytes[0..body_end], &pos, account_len) orelse return error.Truncated;
        const revision = takeU64(bytes[0..body_end], &pos) orelse return error.Truncated;
        const kind_byte = (take(bytes[0..body_end], &pos, 1) orelse return error.Truncated)[0];
        const kind: oper_cred_share.Ocg2Kind = switch (kind_byte) {
            1 => .grant,
            2 => .tombstone,
            else => return error.InvalidRecord,
        };
        const equivocation = (take(bytes[0..body_end], &pos, 1) orelse return error.Truncated)[0];
        if (equivocation > 1) return error.NonCanonical;
        const issued_ms = takeU64(bytes[0..body_end], &pos) orelse return error.Truncated;
        const expiry_ms = takeU64(bytes[0..body_end], &pos) orelse return error.Truncated;
        const digest = (take(bytes[0..body_end], &pos, digest_len) orelse return error.Truncated)[0..digest_len].*;
        const conflict = (take(bytes[0..body_end], &pos, digest_len) orelse return error.Truncated)[0..digest_len].*;
        const wire_len = takeU16(bytes[0..body_end], &pos) orelse return error.Truncated;
        if (wire_len == 0 or wire_len > max_wire_len) return error.BoundsExceeded;
        const wire = take(bytes[0..body_end], &pos, wire_len) orelse return error.Truncated;
        if (!validAccount(account) or (previous.len != 0 and std.mem.order(u8, previous, account) != .lt)) return error.NonCanonical;
        if (!std.mem.eql(u8, &digestWire(wire), &digest)) return error.InvalidRecord;
        const public_key = Ed25519.PublicKey.fromBytes(config.authority_pubkey) catch return error.InvalidAuthority;
        const fields = try oper_cred_share.verifyOcg2(wire, public_key, config.authority_node_id, issued_ms);
        if (!std.mem.eql(u8, fields.account, account) or fields.revision != revision or fields.kind != kind or
            fields.issued_ms != issued_ms or fields.expiry_ms != expiry_ms) return error.InvalidRecord;
        if ((equivocation == 0 and !allZero(conflict)) or (equivocation == 1 and allZero(conflict))) return error.NonCanonical;
        if (equivocation == 1 and std.mem.order(u8, &digest, &conflict) != .lt) return error.NonCanonical;
        const owned: OwnedRecord = blk: {
            const owned_account = try allocator.dupe(u8, account);
            errdefer allocator.free(owned_account);
            const owned_wire = try allocator.dupe(u8, wire);
            break :blk .{
                .account = owned_account,
                .revision = revision,
                .kind = kind,
                .issued_ms = issued_ms,
                .expiry_ms = expiry_ms,
                .digest = digest,
                .conflict_digest = conflict,
                .equivocation = equivocation == 1,
                .wire = owned_wire,
            };
        };
        state.records.appendAssumeCapacity(owned);
        maximum_revision = @max(maximum_revision, revision);
        previous = account;
    }
    if (pos != body_end) return error.TrailingBytes;
    if (revision_floor < maximum_revision) return error.NonCanonical;
    state.local_revision_floor = revision_floor;
    state.security_floor_ms = security_floor_ms;
    state.reserved_until_ms = reserved_until_ms;
    state.security_time_authorized = security_time_authorized;
    // A legacy image is decoded for strict inactive migration/inspection only;
    // it can never silently serve an authority grant.  A v3 image is available
    // only after its authenticated reservation flag and floor/horizon tuple
    // survive strict canonical decoding.
    state.serving_available = snapshot_version == version and security_time_authorized;
    state.snapshot_bytes = try allocator.dupe(u8, bytes);
    return state;
}

fn encodeRecords(
    allocator: std.mem.Allocator,
    config: Config,
    revision_floor: u64,
    security_floor_ms: u64,
    reserved_until_ms: u64,
    security_time_authorized: bool,
    records: []const OwnedRecord,
) ![]u8 {
    if (records.len > max_records) return error.CapacityExceeded;
    if (security_time_authorized and (reserved_until_ms == 0 or reserved_until_ms < security_floor_ms))
        return error.NonCanonical;
    if (!security_time_authorized and security_floor_ms != 0) return error.NonCanonical;
    var total: usize = header_len + trailer_len;
    for (records) |record| total = std.math.add(usize, total, record_fixed_len + record.account.len + record.wire.len) catch return error.BoundsExceeded;
    if (total > max_snapshot_bytes) return error.BoundsExceeded;
    const out = try allocator.alloc(u8, total);
    errdefer allocator.free(out);
    var pos: usize = 0;
    put(out, &pos, magic);
    out[pos] = version;
    pos += 1;
    putU64(out, &pos, config.authority_node_id);
    put(out, &pos, &config.authority_pubkey);
    putU64(out, &pos, revision_floor);
    putU32(out, &pos, @intCast(records.len));
    putU64(out, &pos, reserved_until_ms);
    putU64(out, &pos, security_floor_ms);
    out[pos] = @intFromBool(security_time_authorized);
    pos += 1;
    var previous: []const u8 = "";
    for (records) |record| {
        if (!validAccount(record.account) or (previous.len != 0 and std.mem.order(u8, previous, record.account) != .lt)) return error.NonCanonical;
        out[pos] = @intCast(record.account.len);
        pos += 1;
        put(out, &pos, record.account);
        putU64(out, &pos, record.revision);
        out[pos] = @intFromEnum(record.kind);
        pos += 1;
        out[pos] = @intFromBool(record.equivocation);
        pos += 1;
        putU64(out, &pos, record.issued_ms);
        putU64(out, &pos, record.expiry_ms);
        put(out, &pos, &record.digest);
        put(out, &pos, &record.conflict_digest);
        std.mem.writeInt(u16, out[pos..][0..2], @intCast(record.wire.len), .big);
        pos += 2;
        put(out, &pos, record.wire);
        previous = record.account;
    }
    checksum(snapshot_domain, out[0..pos], out[pos..][0..digest_len]);
    return out;
}

/// Copy one verified record into fixed storage for inspection after the state
/// lock is released.  This does not grant authority and deliberately exposes
/// no borrowed slices.
pub fn copyTransaction(config: Config, record: RecordView) ?TransactionCopy {
    if (record.account.len == 0 or record.account.len > max_account_len or
        record.wire.len == 0 or record.wire.len > max_wire_len)
        return null;
    var blake3_digest: [digest_len]u8 = undefined;
    Blake3.hash(record.wire, &blake3_digest, .{});
    if (!std.mem.eql(u8, &blake3_digest, &record.digest)) return null;
    var wire_sha256: [digest_len]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(record.wire, &wire_sha256, .{});
    var out = TransactionCopy{
        .revision = record.revision,
        .kind = record.kind,
        .issued_ms = record.issued_ms,
        .expiry_ms = record.expiry_ms,
        .authority_node_id = config.authority_node_id,
        .authority_pubkey = config.authority_pubkey,
        .digest = record.digest,
        .wire_sha256 = wire_sha256,
        .conflict_digest = record.conflict_digest,
        .equivocation = record.equivocation,
    };
    @memcpy(out.account_buf[0..record.account.len], record.account);
    out.account_len = record.account.len;
    @memcpy(out.wire_buf[0..record.wire.len], record.wire);
    out.wire_len = record.wire.len;
    return out;
}

fn validateConfig(config: Config) Error!void {
    if (config.authority_node_id == 0) return error.InvalidAuthority;
    _ = Ed25519.PublicKey.fromBytes(config.authority_pubkey) catch return error.InvalidAuthority;
    if (node_short_id.shortId(node_identity.nodeIdFromPublicKey(config.authority_pubkey)) != config.authority_node_id)
        return error.InvalidAuthority;
}

fn validAccount(account: []const u8) bool {
    if (account.len == 0 or account.len > max_account_len) return false;
    for (account) |byte| if (!((byte >= 'a' and byte <= 'z') or (byte >= '0' and byte <= '9') or byte == '_' or byte == '.' or byte == '-')) return false;
    return true;
}

fn lowerBound(records: []const OwnedRecord, account: []const u8) usize {
    var lo: usize = 0;
    var hi = records.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (std.mem.order(u8, records[mid].account, account) == .lt) lo = mid + 1 else hi = mid;
    }
    return lo;
}

fn cloneRecords(allocator: std.mem.Allocator, records: []const OwnedRecord, capacity: usize) !std.ArrayListUnmanaged(OwnedRecord) {
    var out: std.ArrayListUnmanaged(OwnedRecord) = .empty;
    errdefer deinitRecords(allocator, &out);
    try out.ensureTotalCapacity(allocator, capacity);
    for (records) |*record| out.appendAssumeCapacity(try record.clone(allocator));
    return out;
}

fn deinitRecords(allocator: std.mem.Allocator, records: *std.ArrayListUnmanaged(OwnedRecord)) void {
    for (records.items) |*record| record.deinit(allocator);
    records.deinit(allocator);
}

fn digestWire(wire: []const u8) [digest_len]u8 {
    var out: [digest_len]u8 = undefined;
    Blake3.hash(wire, &out, .{});
    return out;
}

fn checksum(domain: []const u8, bytes: []const u8, out: []u8) void {
    var hash = Blake3.init(.{});
    hash.update(domain);
    hash.update(&.{0});
    hash.update(bytes);
    hash.final(out[0..digest_len]);
}

fn allZero(bytes: [digest_len]u8) bool {
    for (bytes) |byte| if (byte != 0) return false;
    return true;
}

fn put(out: []u8, pos: *usize, bytes: []const u8) void {
    @memcpy(out[pos.*..][0..bytes.len], bytes);
    pos.* += bytes.len;
}
fn putU64(out: []u8, pos: *usize, value: u64) void {
    std.mem.writeInt(u64, out[pos.*..][0..8], value, .big);
    pos.* += 8;
}
fn putU32(out: []u8, pos: *usize, value: u32) void {
    std.mem.writeInt(u32, out[pos.*..][0..4], value, .big);
    pos.* += 4;
}
fn take(bytes: []const u8, pos: *usize, len: usize) ?[]const u8 {
    if (len > bytes.len -| pos.*) return null;
    const value = bytes[pos.*..][0..len];
    pos.* += len;
    return value;
}
fn takeU64(bytes: []const u8, pos: *usize) ?u64 {
    return std.mem.readInt(u64, (take(bytes, pos, 8) orelse return null)[0..8], .big);
}
fn takeU32(bytes: []const u8, pos: *usize) ?u32 {
    return std.mem.readInt(u32, (take(bytes, pos, 4) orelse return null)[0..4], .big);
}
fn takeU16(bytes: []const u8, pos: *usize) ?u16 {
    return std.mem.readInt(u16, (take(bytes, pos, 2) orelse return null)[0..2], .big);
}

const testing = std.testing;

fn testKey(seed: u8) !Ed25519.KeyPair {
    return Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(seed)));
}

fn testConfig(kp: Ed25519.KeyPair) Config {
    const public_key = kp.public_key.toBytes();
    return .{
        .authority_node_id = node_short_id.shortId(node_identity.nodeIdFromPublicKey(public_key)),
        .authority_pubkey = public_key,
    };
}

fn testWire(
    kp: Ed25519.KeyPair,
    account: []const u8,
    revision: u64,
    kind: oper_cred_share.Ocg2Kind,
    title: []const u8,
    issued_ms: u64,
    expiry_ms: u64,
    out: []u8,
) ![]const u8 {
    const config = testConfig(kp);
    return out[0..try oper_cred_share.signOcg2(kp, .{
        .kind = kind,
        .account = account,
        .revision = revision,
        .privilege_bits = if (kind == .grant) @as(u64, 1) << 3 else 0,
        .class = if (kind == .grant) "moderator" else "",
        .title = if (kind == .grant) title else "",
        .authority_node_id = config.authority_node_id,
        .authority_pubkey = config.authority_pubkey,
        .issued_ms = issued_ms,
        .expiry_ms = if (kind == .grant) expiry_ms else 0,
    }, issued_ms, out)];
}

fn testCommit(state: *State, wire: []const u8, now_ms: u64) !UpdateDisposition {
    if (!state.securityTimeAuthorized()) {
        const horizon = std.math.add(u64, now_ms, oper_cred_share.ocg2_max_ttl_ms + 1) catch
            std.math.maxInt(u64);
        var reservation = try state.prepareSecurityTimeReservation(now_ms, horizon);
        reservation.update.commitInto(state);
    }
    var outcome = try state.prepareMerge(wire, now_ms);
    return switch (outcome) {
        .update => |*update| blk: {
            const disposition = update.disposition;
            update.commitInto(state);
            break :blk disposition;
        },
        else => error.TestUnexpectedResult,
    };
}

test "OCG2AUTH merge order converges higher successor tombstone floor and expired retention" {
    const kp = try testKey(0x81);
    const config = testConfig(kp);
    var grant_buf: [max_wire_len]u8 = undefined;
    var tomb_buf: [max_wire_len]u8 = undefined;
    const grant = try testWire(kp, "alice", 1, .grant, "Guardian", 1000, 2000, &grant_buf);
    const tomb = try testWire(kp, "alice", 2, .tombstone, "", 1100, 0, &tomb_buf);

    var forward = try State.init(testing.allocator, config);
    defer forward.deinit();
    try testing.expectEqual(UpdateDisposition.successor, try testCommit(&forward, grant, 1000));
    try testing.expect(forward.effective("alice", 1500) != null);
    try testing.expect(forward.effective("alice", 2000) == null);
    try testing.expect(forward.latest("alice") != null); // expired grant retained
    try testing.expectEqual(UpdateDisposition.successor, try testCommit(&forward, tomb, 1100));
    try testing.expect(forward.effective("alice", 1100) == null);
    try testing.expectEqual(@as(u64, 2), forward.latest("alice").?.revision);

    var reverse = try State.init(testing.allocator, config);
    defer reverse.deinit();
    _ = try testCommit(&reverse, tomb, 1100);
    try testing.expectEqual(PrepareOutcome.stale, try reverse.prepareMerge(grant, 1000));
    try testing.expectEqual(@as(u64, 2), reverse.latest("alice").?.revision);
    try testing.expectEqual(oper_cred_share.Ocg2Kind.tombstone, reverse.latest("alice").?.kind);
}

test "OCG2PROV future-skew admission never serves early and survives restore" {
    const kp = try testKey(0x8C);
    const config = testConfig(kp);
    const now_ms: u64 = 1_000;
    const issued_ms = now_ms + oper_cred_share.ocg2_max_future_skew_ms;
    const expiry_ms = issued_ms + 1_000;
    var future_buf: [max_wire_len]u8 = undefined;
    const future = try testWire(kp, "alice", 1, .grant, "Future", issued_ms, expiry_ms, &future_buf);

    // Codec admission permits the bounded clock-skew window, but the durable
    // serving predicate remains strict: a future-issued grant is not effective
    // until its own issued_ms.  prepareMerge performs the same admission check
    // as verifyOcg2 and therefore accepts this record at now_ms.
    var state = try State.init(testing.allocator, config);
    defer state.deinit();
    _ = try testCommit(&state, future, now_ms);
    _ = try oper_cred_share.verifyOcg2(
        future,
        kp.public_key,
        config.authority_node_id,
        now_ms,
    );
    try testing.expect(state.effective("alice", now_ms) == null);
    try testing.expect(state.effective("alice", issued_ms - 1) == null);
    try testing.expect(state.effective("alice", issued_ms) != null);

    const image = try encode(testing.allocator, &state);
    defer testing.allocator.free(image);
    var restored = try decode(testing.allocator, config, image);
    defer restored.deinit();
    try testing.expect(restored.effective("alice", now_ms) == null);
    try testing.expect(restored.effective("alice", issued_ms - 1) == null);
    try testing.expect(restored.effective("alice", issued_ms) != null);

    // A signed record beyond the codec's admission skew is still structurally
    // valid when verified at its own issue time, but must be rejected when
    // received at the older local clock.
    var beyond_buf: [max_wire_len]u8 = undefined;
    const beyond_issued = issued_ms + 1;
    const beyond = try testWire(kp, "bob", 1, .grant, "Beyond", beyond_issued, beyond_issued + 1_000, &beyond_buf);
    try testing.expectError(
        error.InvalidTime,
        oper_cred_share.verifyOcg2(beyond, kp.public_key, config.authority_node_id, now_ms),
    );
}

test "OCG2AUTH replay equivocation persists fail closed and strictly higher clears" {
    const kp = try testKey(0x82);
    var state = try State.init(testing.allocator, testConfig(kp));
    defer state.deinit();
    var first_buf: [max_wire_len]u8 = undefined;
    var conflict_buf: [max_wire_len]u8 = undefined;
    var higher_buf: [max_wire_len]u8 = undefined;
    const first = try testWire(kp, "alice", 5, .grant, "First", 1000, 5000, &first_buf);
    const conflict = try testWire(kp, "alice", 5, .grant, "Conflict", 1000, 5000, &conflict_buf);
    const higher = try testWire(kp, "alice", 6, .grant, "Recovered", 1001, 5000, &higher_buf);
    _ = try testCommit(&state, first, 1000);
    try testing.expectEqual(PrepareOutcome.replay, try state.prepareMerge(first, 1000));
    try testing.expectEqual(UpdateDisposition.equivocation, try testCommit(&state, conflict, 1000));
    const poisoned = state.latest("alice").?;
    try testing.expect(poisoned.equivocation);
    try testing.expect(!std.mem.eql(u8, &poisoned.digest, &poisoned.conflict_digest));
    try testing.expect(state.effective("alice", 1000) == null);
    const poisoned_image = try encode(testing.allocator, &state);
    defer testing.allocator.free(poisoned_image);

    var reverse = try State.init(testing.allocator, testConfig(kp));
    defer reverse.deinit();
    _ = try testCommit(&reverse, conflict, 1000);
    try testing.expectEqual(UpdateDisposition.equivocation, try testCommit(&reverse, first, 1000));
    const reverse_image = try encode(testing.allocator, &reverse);
    defer testing.allocator.free(reverse_image);
    try testing.expectEqualSlices(u8, poisoned_image, reverse_image);

    var restored = try decode(testing.allocator, testConfig(kp), poisoned_image);
    defer restored.deinit();
    try testing.expect(restored.latest("alice").?.equivocation);
    _ = try testCommit(&restored, higher, 1001);
    try testing.expect(!restored.latest("alice").?.equivocation);
    try testing.expect(restored.effective("alice", 1001) != null);
}

test "OCG2AUTH all merge permutations converge to one canonical snapshot" {
    const kp = try testKey(0x88);
    const config = testConfig(kp);
    var alice_old_buf: [max_wire_len]u8 = undefined;
    var alice_new_buf: [max_wire_len]u8 = undefined;
    var bob_buf: [max_wire_len]u8 = undefined;
    const wires = [_][]const u8{
        try testWire(kp, "alice", 1, .grant, "Old", 1000, 5000, &alice_old_buf),
        try testWire(kp, "alice", 5, .tombstone, "", 1001, 0, &alice_new_buf),
        try testWire(kp, "bob", 3, .grant, "Bob", 1002, 5000, &bob_buf),
    };
    const permutations = [_][3]usize{
        .{ 0, 1, 2 }, .{ 0, 2, 1 }, .{ 1, 0, 2 },
        .{ 1, 2, 0 }, .{ 2, 0, 1 }, .{ 2, 1, 0 },
    };
    var canonical: ?[]u8 = null;
    defer if (canonical) |image| testing.allocator.free(image);
    for (permutations) |order| {
        var state = try State.init(testing.allocator, config);
        defer state.deinit();
        for (order) |wire_index| {
            var outcome = try state.prepareMerge(wires[wire_index], 1002);
            switch (outcome) {
                .update => |*update| update.commitInto(&state),
                .stale, .replay => {},
            }
        }
        const image = try encode(testing.allocator, &state);
        if (canonical) |expected| {
            defer testing.allocator.free(image);
            try testing.expectEqualSlices(u8, expected, image);
        } else {
            canonical = image;
        }
    }
}

test "OCG2AUTH canonical snapshot restart marker corruption authority and framing fail closed" {
    const kp = try testKey(0x83);
    const other = try testKey(0x84);
    const config = testConfig(kp);
    var state = try State.init(testing.allocator, config);
    defer state.deinit();
    var wire_buf: [max_wire_len]u8 = undefined;
    const wire = try testWire(kp, "bob", 9, .grant, "Bob", 1000, 5000, &wire_buf);
    _ = try testCommit(&state, wire, 1000);
    const image = try encode(testing.allocator, &state);
    defer testing.allocator.free(image);
    var restored = try decode(testing.allocator, config, image);
    defer restored.deinit();
    try testing.expectEqualSlices(u8, wire, restored.latest("bob").?.wire);

    var marker_buf: [marker_len]u8 = undefined;
    const marker_bytes = try marker(config, &marker_buf);
    try validateMarker(marker_bytes, config);
    try testing.expectError(error.InvalidAuthority, validateMarker(marker_bytes, testConfig(other)));
    const invalid_key: [Ed25519.PublicKey.encoded_length]u8 = @splat(0xff);
    const invalid_config = Config{
        .authority_node_id = node_short_id.shortId(node_identity.nodeIdFromPublicKey(invalid_key)),
        .authority_pubkey = invalid_key,
    };
    try testing.expectError(error.InvalidAuthority, State.init(testing.allocator, invalid_config));
    var corrupt = try testing.allocator.dupe(u8, image);
    defer testing.allocator.free(corrupt);
    corrupt[corrupt.len - 1] ^= 1;
    try testing.expectError(error.BadChecksum, decode(testing.allocator, config, corrupt));
    try testing.expectError(error.InvalidAuthority, decode(testing.allocator, testConfig(other), image));
    const trailing = try testing.allocator.alloc(u8, image.len + 1);
    defer testing.allocator.free(trailing);
    @memcpy(trailing[0..image.len], image);
    trailing[image.len] = 0;
    try testing.expectError(error.BadChecksum, decode(testing.allocator, config, trailing));
}

test "OCG2AUTH prepared revision is invisible until commit and survives restart" {
    const kp = try testKey(0x85);
    const config = testConfig(kp);
    var state = try State.init(testing.allocator, config);
    defer state.deinit();
    var first = try state.prepareRevision("alice");
    try testing.expectEqual(@as(u64, 1), first.revision);
    try testing.expectEqual(@as(u64, 0), state.local_revision_floor);
    first.update.abort();
    var second = try state.prepareRevision("alice");
    try testing.expectEqual(@as(u64, 1), second.revision);
    second.update.commitInto(&state);
    try testing.expectEqual(@as(u64, 1), state.local_revision_floor);
    const image = try encode(testing.allocator, &state);
    defer testing.allocator.free(image);
    var restored = try decode(testing.allocator, config, image);
    defer restored.deinit();
    var third = try restored.prepareRevision("alice");
    defer third.update.abort();
    try testing.expectEqual(@as(u64, 2), third.revision);
}

test "OCG2AUTH prepare and decode are allocation failure atomic" {
    const kp = try testKey(0x86);
    const config = testConfig(kp);
    var wire_buf: [max_wire_len]u8 = undefined;
    const wire = try testWire(kp, "alice", 1, .grant, "Alice", 1000, 5000, &wire_buf);
    const PrepareSweep = struct {
        fn run(allocator: std.mem.Allocator, cfg: Config, bytes: []const u8) !void {
            var state = try State.init(allocator, cfg);
            defer state.deinit();
            var outcome = try state.prepareMerge(bytes, 1000);
            switch (outcome) {
                .update => |*update| update.commitInto(&state),
                else => return error.TestUnexpectedResult,
            }
            try testing.expectEqual(@as(usize, 1), state.count());
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, PrepareSweep.run, .{ config, wire });

    var source = try State.init(testing.allocator, config);
    defer source.deinit();
    _ = try testCommit(&source, wire, 1000);
    const image = try encode(testing.allocator, &source);
    defer testing.allocator.free(image);
    const DecodeSweep = struct {
        fn run(allocator: std.mem.Allocator, cfg: Config, bytes: []const u8) !void {
            var state = try decode(allocator, cfg, bytes);
            defer state.deinit();
            try testing.expectEqual(@as(usize, 1), state.count());
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, DecodeSweep.run, .{ config, image });
}

test "OCG2AUTH decoder rejects count over capacity before records" {
    const kp = try testKey(0x87);
    const config = testConfig(kp);
    var state = try State.init(testing.allocator, config);
    defer state.deinit();
    var image = try encode(testing.allocator, &state);
    defer testing.allocator.free(image);
    const count_offset = magic.len + 1 + 8 + config.authority_pubkey.len + 8;
    std.mem.writeInt(u32, image[count_offset..][0..4], max_records + 1, .big);
    checksum(snapshot_domain, image[0 .. image.len - trailer_len], image[image.len - trailer_len ..]);
    try testing.expectError(error.CapacityExceeded, decode(testing.allocator, config, image));
}

test "OCG2CLOCK reservation rollback extension and restart restore" {
    const kp = try testKey(0x89);
    const config = testConfig(kp);
    var state = try State.init(testing.allocator, config);
    defer state.deinit();

    var rolled_back = try state.prepareSecurityTimeReservation(1_000, 5_000);
    try testing.expectEqual(@as(u64, 5_000), rolled_back.reserved_until_ms);
    try testing.expectEqual(@as(u64, 0), state.securityReservedUntil());
    rolled_back.update.abort();
    try testing.expectEqual(@as(u64, 0), state.securityReservedUntil());

    var committed = try state.prepareSecurityTimeReservation(1_000, 5_000);
    committed.update.commitInto(&state);
    try testing.expectEqual(@as(u64, 5_000), state.securityReservedUntil());
    try testing.expectError(error.ReservationNotExtended, state.prepareSecurityTimeReservation(1_000, 4_999));
    try testing.expectError(error.ReservationNotExtended, state.prepareSecurityTimeReservation(1_000, 5_000));

    const image = try encode(testing.allocator, &state);
    defer testing.allocator.free(image);
    var restored = try decode(testing.allocator, config, image);
    defer restored.deinit();
    try testing.expectEqual(@as(u64, 5_000), restored.securityReservedUntil());
    try testing.expect(!restored.requiresV2Migration());

    var extended = try restored.prepareSecurityTimeReservation(5_000, 9_000);
    extended.update.abort();
    try testing.expectEqual(@as(u64, 5_000), restored.securityReservedUntil());
}

test "OCG2CLOCK strict v1 and v2 migrate inactive until explicit reservation cut" {
    const kp = try testKey(0x8A);
    const config = testConfig(kp);
    var state = try State.init(testing.allocator, config);
    defer state.deinit();
    const current = try encode(testing.allocator, &state);
    defer testing.allocator.free(current);

    // Remove every post-v1 field while retaining the exact record framing.
    // prefix and record framing, then authenticate it under the v1 domain.
    const legacy = try testing.allocator.alloc(u8, current.len - (header_len - legacy_header_len));
    defer testing.allocator.free(legacy);
    @memcpy(legacy[0..legacy_header_len], current[0..legacy_header_len]);
    @memcpy(legacy[legacy_header_len..], current[header_len..]);
    legacy[magic.len] = legacy_version;
    checksum(snapshot_domain_v1, legacy[0 .. legacy.len - trailer_len], legacy[legacy.len - trailer_len ..]);

    var migrated = try decode(testing.allocator, config, legacy);
    defer migrated.deinit();
    try testing.expect(migrated.requiresV2Migration());
    try testing.expect(!migrated.servingAvailable());
    try testing.expect(migrated.effective("alice", 0) == null);
    try testing.expectEqual(@as(u64, 0), migrated.securityReservedUntil());
    const generic_v1_migration = try encode(testing.allocator, &migrated);
    defer testing.allocator.free(generic_v1_migration);
    var generic_v1_reopen = try decode(testing.allocator, config, generic_v1_migration);
    defer generic_v1_reopen.deinit();
    try testing.expect(!generic_v1_reopen.servingAvailable());
    try testing.expect(!generic_v1_reopen.securityTimeAuthorized());

    // The old v2 reservation-only layout is also strict-decode-only.  Merely
    // re-encoding it as v3 cannot turn its legacy horizon into authorization.
    const old_v2 = try testing.allocator.alloc(u8, current.len - (header_len - reservation_header_len));
    defer testing.allocator.free(old_v2);
    @memcpy(old_v2[0..reservation_header_len], current[0..reservation_header_len]);
    @memcpy(old_v2[reservation_header_len..], current[header_len..]);
    old_v2[magic.len] = reservation_only_version;
    std.mem.writeInt(u64, old_v2[legacy_header_len..][0..8], 4_000, .big);
    checksum(snapshot_domain_v2, old_v2[0 .. old_v2.len - trailer_len], old_v2[old_v2.len - trailer_len ..]);
    var v2_migrated = try decode(testing.allocator, config, old_v2);
    defer v2_migrated.deinit();
    try testing.expect(v2_migrated.requiresV2Migration());
    try testing.expect(!v2_migrated.servingAvailable());
    try testing.expectEqual(@as(u64, 4_000), v2_migrated.securityReservedUntil());
    const generic_v2_migration = try encode(testing.allocator, &v2_migrated);
    defer testing.allocator.free(generic_v2_migration);
    var generic_v2_reopen = try decode(testing.allocator, config, generic_v2_migration);
    defer generic_v2_reopen.deinit();
    try testing.expect(!generic_v2_reopen.servingAvailable());

    // Only the explicit reservation prepare/cut authorizes the v3 image.
    var reservation = try migrated.prepareSecurityTimeReservation(1_000, 5_000);
    reservation.update.commitInto(&migrated);
    try testing.expect(migrated.servingAvailable());
    try testing.expect(migrated.securityTimeAuthorized());
    const authorized = try encode(testing.allocator, &migrated);
    defer testing.allocator.free(authorized);
    var authorized_reopen = try decode(testing.allocator, config, authorized);
    defer authorized_reopen.deinit();
    try testing.expect(authorized_reopen.servingAvailable());
    try testing.expectEqual(@as(u64, 5_000), authorized_reopen.securityFloor());
    try testing.expectEqual(@as(u64, 5_000), authorized_reopen.securityReservedUntil());

    legacy[legacy.len - 1] ^= 1;
    try testing.expectError(error.BadChecksum, decode(testing.allocator, config, legacy));
}

test "OCG2CLOCK reservation preparation is allocation-failure atomic" {
    const kp = try testKey(0x8B);
    const config = testConfig(kp);
    const Sweep = struct {
        fn run(allocator: std.mem.Allocator, cfg: Config) !void {
            var state = try State.init(allocator, cfg);
            defer state.deinit();
            var prepared = try state.prepareSecurityTimeReservation(1_000, 4_000);
            defer prepared.update.abort();
            try testing.expectEqual(@as(u64, 0), state.securityReservedUntil());
            try testing.expectEqual(@as(u64, 4_000), prepared.reserved_until_ms);
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Sweep.run, .{config});
}

fn expectExactCopy(copy: TransactionCopy, config: Config, wire: []const u8, account: []const u8, revision: u64, kind: oper_cred_share.Ocg2Kind, issued_ms: u64, expiry_ms: u64, equivocation: bool) !void {
    try testing.expectEqualStrings(account, copy.account());
    try testing.expectEqual(revision, copy.revision);
    try testing.expectEqual(kind, copy.kind);
    try testing.expectEqual(issued_ms, copy.issued_ms);
    try testing.expectEqual(expiry_ms, copy.expiry_ms);
    try testing.expectEqual(config.authority_node_id, copy.authority_node_id);
    try testing.expectEqualSlices(u8, &config.authority_pubkey, &copy.authority_pubkey);
    try testing.expectEqual(equivocation, copy.equivocation);
    try testing.expectEqualSlices(u8, wire, copy.signedWire());
    var blake3_digest: [digest_len]u8 = undefined;
    Blake3.hash(wire, &blake3_digest, .{});
    try testing.expectEqualSlices(u8, &blake3_digest, &copy.digest);
    var sha256_digest: [digest_len]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(wire, &sha256_digest, .{});
    try testing.expectEqualSlices(u8, &sha256_digest, &copy.wire_sha256);
}

test "S6C2 copyTransactions empty exact over and under leave dest untouched" {
    const kp = try testKey(0xC2);
    const config = testConfig(kp);
    var state = try State.init(testing.allocator, config);
    defer state.deinit();

    const sentinel = TransactionCopy{ .revision = 0xdead_beef };
    var empty_out = [_]TransactionCopy{sentinel};
    try testing.expectEqual(@as(usize, 0), try state.copyTransactions(empty_out[0..0]));
    try testing.expectEqual(@as(u64, 0xdead_beef), empty_out[0].revision);

    var alice_buf: [max_wire_len]u8 = undefined;
    const alice = try testWire(kp, "alice", 1, .grant, "Now", 1_000, 5_000, &alice_buf);
    try testing.expectEqual(UpdateDisposition.successor, try testCommit(&state, alice, 1_000));
    var bob_buf: [max_wire_len]u8 = undefined;
    const bob = try testWire(kp, "bob", 1, .tombstone, "", 1_100, 0, &bob_buf);
    try testing.expectEqual(UpdateDisposition.successor, try testCommit(&state, bob, 1_100));

    var under = [_]TransactionCopy{sentinel};
    try testing.expectError(error.CapacityExceeded, state.copyTransactions(under[0..1]));
    try testing.expectEqual(@as(u64, 0xdead_beef), under[0].revision);
    try testing.expectEqual(@as(usize, 0), under[0].account_len);
    try testing.expectEqual(@as(usize, 0), under[0].wire_len);

    var exact: [2]TransactionCopy = .{ sentinel, sentinel };
    try testing.expectEqual(@as(usize, 2), try state.copyTransactions(&exact));
    try testing.expectEqualStrings("alice", exact[0].account());
    try testing.expectEqualStrings("bob", exact[1].account());

    var over: [3]TransactionCopy = .{ sentinel, sentinel, sentinel };
    try testing.expectEqual(@as(usize, 2), try state.copyTransactions(&over));
    try testing.expectEqualStrings("alice", over[0].account());
    try testing.expectEqualStrings("bob", over[1].account());
    try testing.expectEqual(@as(u64, 0xdead_beef), over[2].revision);
}

test "S6C2 copyTransactions lists every latest kind in canonical order with exact fields" {
    const kp = try testKey(0xC3);
    const config = testConfig(kp);
    var state = try State.init(testing.allocator, config);
    defer state.deinit();

    var car_buf: [max_wire_len]u8 = undefined;
    const car = try testWire(kp, "car", 1, .grant, "Future", 4_000, 9_000, &car_buf);
    try testing.expectEqual(UpdateDisposition.successor, try testCommit(&state, car, 1_000));
    var alice_expired_buf: [max_wire_len]u8 = undefined;
    const alice_expired = try testWire(kp, "alice", 1, .grant, "Expired", 500, 900, &alice_expired_buf);
    try testing.expectEqual(UpdateDisposition.successor, try testCommit(&state, alice_expired, 500));
    var alice_live_buf: [max_wire_len]u8 = undefined;
    const alice_live = try testWire(kp, "alice", 2, .grant, "Live", 1_000, 5_000, &alice_live_buf);
    try testing.expectEqual(UpdateDisposition.successor, try testCommit(&state, alice_live, 1_000));
    var bob_first_buf: [max_wire_len]u8 = undefined;
    const bob_first = try testWire(kp, "bob", 1, .grant, "First", 1_000, 5_000, &bob_first_buf);
    try testing.expectEqual(UpdateDisposition.successor, try testCommit(&state, bob_first, 1_000));
    var bob_conflict_buf: [max_wire_len]u8 = undefined;
    const bob_conflict = try testWire(kp, "bob", 1, .grant, "Conflict", 1_000, 5_000, &bob_conflict_buf);
    try testing.expectEqual(UpdateDisposition.equivocation, try testCommit(&state, bob_conflict, 1_000));
    var zed_buf: [max_wire_len]u8 = undefined;
    const zed = try testWire(kp, "zed", 1, .tombstone, "", 1_200, 0, &zed_buf);
    try testing.expectEqual(UpdateDisposition.successor, try testCommit(&state, zed, 1_200));

    var out: [4]TransactionCopy = undefined;
    try testing.expectEqual(@as(usize, 4), try state.copyTransactions(&out));
    try testing.expectEqualStrings("alice", out[0].account());
    try testing.expectEqualStrings("bob", out[1].account());
    try testing.expectEqualStrings("car", out[2].account());
    try testing.expectEqualStrings("zed", out[3].account());
    try expectExactCopy(out[0], config, alice_live, "alice", 2, .grant, 1_000, 5_000, false);
    try testing.expect(out[1].equivocation);
    try testing.expectEqual(oper_cred_share.Ocg2Kind.grant, out[1].kind);
    try testing.expectEqualStrings("bob", out[1].account());
    try testing.expect(!std.mem.allEqual(u8, &out[1].conflict_digest, 0));
    try testing.expect(!std.mem.eql(u8, &out[1].digest, &out[1].conflict_digest));
    try expectExactCopy(out[2], config, car, "car", 1, .grant, 4_000, 9_000, false);
    try expectExactCopy(out[3], config, zed, "zed", 1, .tombstone, 1_200, 0, false);
    try testing.expect(out[2].issued_ms > 1_000);
    try testing.expect(out[0].signedWire().ptr != alice_live.ptr);
}

test "S6C2 copyTransactions copies outlive state and share no borrowed slices" {
    const kp = try testKey(0xC4);
    const config = testConfig(kp);
    var copy: TransactionCopy = .{};
    {
        var state = try State.init(testing.allocator, config);
        defer state.deinit();
        var wire_buf: [max_wire_len]u8 = undefined;
        const wire = try testWire(kp, "alice", 1, .grant, "Owned", 1_000, 5_000, &wire_buf);
        try testing.expectEqual(UpdateDisposition.successor, try testCommit(&state, wire, 1_000));
        var out: [1]TransactionCopy = undefined;
        try testing.expectEqual(@as(usize, 1), try state.copyTransactions(&out));
        copy = out[0];
        var successor_buf: [max_wire_len]u8 = undefined;
        const successor = try testWire(kp, "alice", 2, .grant, "Next", 1_100, 6_000, &successor_buf);
        try testing.expectEqual(UpdateDisposition.successor, try testCommit(&state, successor, 1_100));
        try testing.expectEqual(@as(u64, 1), copy.revision);
        try expectExactCopy(copy, config, wire, "alice", 1, .grant, 1_000, 5_000, false);
    }
    try testing.expectEqualStrings("alice", copy.account());
    try testing.expectEqual(@as(u64, 1), copy.revision);
    try testing.expect(copy.signedWire().len != 0);
}

test "S6C2 copyTransactions rejects internal corruption without partial writes" {
    const kp = try testKey(0xC5);
    var state = try State.init(testing.allocator, testConfig(kp));
    defer state.deinit();
    var alice_buf: [max_wire_len]u8 = undefined;
    const alice = try testWire(kp, "alice", 1, .grant, "A", 1_000, 5_000, &alice_buf);
    try testing.expectEqual(UpdateDisposition.successor, try testCommit(&state, alice, 1_000));
    var bob_buf: [max_wire_len]u8 = undefined;
    const bob = try testWire(kp, "bob", 1, .grant, "B", 1_000, 5_000, &bob_buf);
    try testing.expectEqual(UpdateDisposition.successor, try testCommit(&state, bob, 1_000));

    const sentinel = TransactionCopy{ .revision = 7 };
    var out = [_]TransactionCopy{ sentinel, sentinel };
    state.testXorRecordDigest(1);
    try testing.expectError(error.InvalidRecord, state.copyTransactions(&out));
    try testing.expectEqual(@as(u64, 7), out[0].revision);
    try testing.expectEqual(@as(u64, 7), out[1].revision);
    try testing.expectEqual(@as(usize, 0), out[0].account_len);
    try testing.expectEqual(@as(usize, 0), out[1].wire_len);
}

test "S6C2 copyTransactions is allocation-free" {
    const kp = try testKey(0xC6);
    const config = testConfig(kp);
    var state = try State.init(testing.allocator, config);
    defer state.deinit();
    var wire_buf: [max_wire_len]u8 = undefined;
    const wire = try testWire(kp, "alice", 1, .grant, "Alloc", 1_000, 5_000, &wire_buf);
    try testing.expectEqual(UpdateDisposition.successor, try testCommit(&state, wire, 1_000));

    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    const original_allocator = state.allocator;
    state.allocator = failing.allocator();
    var out: [1]TransactionCopy = undefined;
    try testing.expectEqual(@as(usize, 1), try state.copyTransactions(&out));
    state.allocator = original_allocator;
    try expectExactCopy(out[0], config, wire, "alice", 1, .grant, 1_000, 5_000, false);
}
