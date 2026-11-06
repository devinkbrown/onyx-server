// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! M03: digest -> detail -> delta -> full-repair reconciliation over
//! family-keyed state.
//!
//! This is a pure, deterministic leaf: no transport, no live server state. A
//! `FamilyState` holds `key -> (version, value_hash, deleted)` rows for one
//! UNDERTOW entity family, kept sorted by key so every derived digest is a
//! canonical function of the logical state (never of insertion order).
//!
//! Every key hashes (domain-separated SHA-256, not the recursive Merkle
//! prefix walk in `merkle.zig`) to one of `num_units` = 64 x 64 units. A unit
//! root commits to the unit's rows; a bucket root commits to its 64 unit
//! roots; the family root commits to the counts and 64 bucket roots.
//! `Summary` carries only bucket roots, `FamilyDetail` carries the unit roots
//! of requested buckets, and each has a strict, bounded wire codec.
//!
//! Ladder:
//!   1. `plan()` compares local state against a peer's decoded summary and
//!      returns `in_sync`, a per-family `delta` plan naming the units to
//!      ship, or `full_repair` with a reason (untrusted or inconsistent
//!      summary). Families tracked by one side only are listed in
//!      `DeltaDecision.one_sided` and never escalate the shared families,
//!      so a mixed-version mesh still reconciles what both sides track by
//!      digest and delta. A plan whose bucket-resolution
//!      row count exceeds `Budget` (`anti_entropy.selectStrategy`'s cost
//!      model) is marked `needs_detail` instead of escalating.
//!   2. `refine()` narrows a `needs_detail` plan with the peer's unit roots
//!      for exactly the differing buckets, then re-applies the budget; only a
//!      family still over budget at unit resolution falls to
//!      `full_repair(too_divergent)`.
//!   3. `buildDelta()` ships EVERY local row in the planned units, split into
//!      frames of at most `max_delta_entries` rows (`max_delta_wire_len`
//!      bytes). Each frame carries the sender's full digest plus the unit
//!      roots of every bucket it touches, so the receiver verifies each frame
//!      independently before touching state: a truncated, tampered, or
//!      incomplete frame is rejected and escalates; nothing is applied.
//!   4. `applyDelta()` merges one verified frame by LWW join over the total
//!      order `(version, deleted, value_hash)`. A same-key, same-version,
//!      same-flag hash conflict is an equivocation: the strict delta path
//!      aborts (state untouched) and escalates.
//!   5. `fullRepair()` is the fallback: the same verified per-frame join over
//!      every frame of `buildFullSnapshot`, with equivocations resolved
//!      deterministically (greater `value_hash` wins) and counted.
//!
//! A family is reconcilable while no single unit holds more than
//! `max_delta_entries` rows (about 3.5 million uniformly hashed rows); past
//! that, building fails closed with `error.UnitTooLarge` rather than
//! producing an unencodable frame.
//!
//! Tombstone GC: `gcTombstones` records a per-family `gc_floor`. A replica
//! with a floor drops any incoming row at or below it that it does not hold,
//! and a frame from such a replica prunes the receiver's rows at or below the
//! sender's floor that the sender lacks in the shipped units. A collected
//! delete therefore stays deleted when a partitioned peer or a late frame
//! still carries the pre-delete live row.
//!
//! The per-key join is commutative and idempotent, so one delta exchange in
//! each direction makes both replicas byte-identical to the LWW join of their
//! prior states: no accepted write above a floor is lost, replayed or stale
//! frames never roll state back, and tombstones beat a stale live row instead
//! of being resurrected. Every merge reserves all memory it needs before its
//! first mutation, so allocation failure or rejection leaves the target
//! byte-for-byte unchanged.
const std = @import("std");

const anti_entropy = @import("anti_entropy.zig");
const s2s_frame = @import("../../proto/s2s_frame.zig");

const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Hash = [32]u8;

/// Coarse digest buckets per family (the summary resolution).
pub const num_buckets: usize = 64;
/// Units per bucket (the detail and delta resolution).
pub const subs_per_bucket: usize = 64;
/// Total units per family. Fixed (not configurable) so peers never silently
/// talk past each other over mismatched layouts; `wire_version` guards it.
pub const num_units: usize = num_buckets * subs_per_bucket;
/// A set of units, indexed `bucket * subs_per_bucket + sub`.
pub const UnitMask = std.StaticBitSet(num_units);

const summary_magic = "OM03";
const detail_magic = "OM3S";
const delta_magic = "OM3D";
const wire_version: u8 = 2;
/// A summary names at most this many families. Keeps `decodeSummary`
/// allocation and work bounded by the wire header alone.
pub const max_families: usize = 64;
pub const max_family_name_len: usize = 64;
/// Longest row key a delta may carry on the wire.
pub const max_key_len: usize = 512;
/// Most rows one delta frame may carry.
pub const max_delta_entries: usize = 1024;
/// Largest row count an untrusted digest may advertise. Keeps peer-supplied
/// counts far from `usize` overflow in the cost model on every target.
pub const max_family_entries: u64 = std.math.maxInt(u32);

const digest_body_len: usize = 8 + 8 + 32 + 32 * num_buckets;
const floor_len: usize = 1 + 8;
const sub_roots_len: usize = 32 * subs_per_bucket;
const delta_part_len: usize = 1 + 8 + sub_roots_len;
const detail_part_len: usize = 1 + sub_roots_len;
const delta_row_fixed_len: usize = 2 + 8 + 1 + 32;

/// Largest encoded delta frame: every bucket touched and every row at
/// `max_key_len`. Fits one S2S frame with its header.
pub const max_delta_wire_len: usize = delta_magic.len + 1 + 1 + max_family_name_len + digest_body_len + floor_len +
    1 + num_buckets * delta_part_len + 2 + max_delta_entries * (delta_row_fixed_len + max_key_len);

comptime {
    std.debug.assert(max_delta_wire_len + s2s_frame.header_len <= s2s_frame.default_max_frame_size);
}

/// One logical row in a family: a key with an HLC/rev version, a content
/// hash, and a tombstone flag. `key` is heap-owned by whichever container
/// holds the entry.
pub const Entry = struct {
    key: []u8,
    version: u64,
    value_hash: Hash,
    deleted: bool,
};

/// A deterministic live view of one UNDERTOW entity family. `entries` is
/// always sorted by key with unique keys, so every digest derived from it is
/// independent of how callers inserted rows.
///
/// `local` arguments to `plan`/`buildSummary` are trusted, already-owned
/// state (not a wire boundary): callers pass family lists sorted ascending
/// by name with unique names, matching the invariant the wire decoder
/// enforces on peer bytes.
pub const FamilyState = struct {
    allocator: Allocator,
    family: []u8,
    entries: std.ArrayList(Entry) = .empty,
    /// Highest `gcTombstones` watermark applied, or null before the first.
    /// With a floor set, this replica holds every live write at or below it
    /// and has collected every tombstone at or below it, so a row at or
    /// below the floor that it does not hold is dead.
    gc_floor: ?u64 = null,

    pub fn init(allocator: Allocator, family: []const u8) Allocator.Error!FamilyState {
        return .{ .allocator = allocator, .family = try allocator.dupe(u8, family) };
    }

    pub fn deinit(self: *FamilyState) void {
        for (self.entries.items) |e| self.allocator.free(e.key);
        self.entries.deinit(self.allocator);
        self.allocator.free(self.family);
        self.* = undefined;
    }

    pub fn clone(self: *const FamilyState) Allocator.Error!FamilyState {
        var out = try FamilyState.init(self.allocator, self.family);
        errdefer out.deinit();
        out.gc_floor = self.gc_floor;
        try out.entries.ensureTotalCapacityPrecise(self.allocator, self.entries.items.len);
        for (self.entries.items) |e| {
            const key = try self.allocator.dupe(u8, e.key);
            out.entries.appendAssumeCapacity(.{ .key = key, .version = e.version, .value_hash = e.value_hash, .deleted = e.deleted });
        }
        return out;
    }

    /// Upsert a row. This is a raw setter for authoritative local
    /// bookkeeping, not the LWW merge `applyDelta` uses for peer frames.
    pub fn put(self: *FamilyState, key: []const u8, version: u64, value_hash: Hash, deleted: bool) Allocator.Error!void {
        const found = self.findKeyIndex(key);
        if (found.exists) {
            const row = &self.entries.items[found.index];
            row.version = version;
            row.value_hash = value_hash;
            row.deleted = deleted;
            return;
        }
        const owned = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(owned);
        try self.entries.insert(self.allocator, found.index, .{ .key = owned, .version = version, .value_hash = value_hash, .deleted = deleted });
    }

    /// Append a row without keeping key order, for bulk loading a family
    /// projected from unordered live state. Call `normalize` before any
    /// other method; until then lookups and digests are undefined. On
    /// allocation failure nothing is appended.
    pub fn appendUnsorted(self: *FamilyState, key: []const u8, version: u64, value_hash: Hash, deleted: bool) Allocator.Error!void {
        try self.entries.ensureUnusedCapacity(self.allocator, 1);
        const owned = try self.allocator.dupe(u8, key);
        self.entries.appendAssumeCapacity(.{ .key = owned, .version = version, .value_hash = value_hash, .deleted = deleted });
    }

    /// Restore the sorted, unique-key invariant after `appendUnsorted`.
    /// Duplicate keys collapse to the greatest row under the LWW total order
    /// `(version, deleted, value_hash)`, so the result (and every digest) is
    /// independent of append order. Never allocates. Returns false when two
    /// collapsed rows of one key differed (version, tombstone or hash), so a
    /// caller that needs every appended row reflected in the digest can fail
    /// closed instead of digesting only the winner.
    pub fn normalize(self: *FamilyState) bool {
        const items = self.entries.items;
        std.mem.sort(Entry, items, {}, entryNormalizeLessThan);
        var kept: usize = 0;
        var conflict_free = true;
        for (items) |e| {
            if (kept != 0 and std.mem.eql(u8, items[kept - 1].key, e.key)) {
                const prev = items[kept - 1];
                if (prev.version != e.version or prev.deleted != e.deleted or
                    !std.mem.eql(u8, &prev.value_hash, &e.value_hash)) conflict_free = false;
                // Sorted ascending by row order within a key: the later row
                // is the greater one and replaces the kept row.
                self.allocator.free(prev.key);
                items[kept - 1] = e;
                continue;
            }
            items[kept] = e;
            kept += 1;
        }
        self.entries.shrinkRetainingCapacity(kept);
        return conflict_free;
    }

    fn entryNormalizeLessThan(_: void, a: Entry, b: Entry) bool {
        switch (std.mem.order(u8, a.key, b.key)) {
            .lt => return true,
            .gt => return false,
            .eq => {},
        }
        if (a.version != b.version) return a.version < b.version;
        if (a.deleted != b.deleted) return !a.deleted;
        return std.mem.order(u8, &a.value_hash, &b.value_hash) == .lt;
    }

    pub fn get(self: *const FamilyState, key: []const u8) ?Entry {
        const found = self.findKeyIndex(key);
        if (!found.exists) return null;
        return self.entries.items[found.index];
    }

    pub fn len(self: *const FamilyState) usize {
        return self.entries.items.len;
    }

    pub fn digest(self: *const FamilyState) Allocator.Error!FamilyDigest {
        const rows = try digestRows(self.allocator, self.family, self.entries.items);
        return .{
            .family = try self.allocator.dupe(u8, self.family),
            .entry_count = rows.entry_count,
            .tombstone_count = rows.tombstone_count,
            .root = rows.root,
            .buckets = rows.buckets,
        };
    }

    /// Drop tombstones at or below `watermark` and raise `gc_floor` to it.
    /// The caller must derive `watermark` from
    /// `anti_entropy.causalStabilityWatermark` over EVERY member that can
    /// still deliver state for this family, partitioned ones included, not
    /// only live peers. The floor then never discards a live write. If the
    /// watermark covers live peers only, a partitioned member's write at or
    /// below the floor is discarded on reconnect: the delete wins and the row
    /// is never resurrected. Returns the count removed. Never allocates.
    pub fn gcTombstones(self: *FamilyState, watermark: u64) usize {
        self.gc_floor = @max(self.gc_floor orelse 0, watermark);
        const items = self.entries.items;
        var kept: usize = 0;
        for (items) |e| {
            if (e.deleted and e.version <= watermark) {
                self.allocator.free(e.key);
                continue;
            }
            items[kept] = e;
            kept += 1;
        }
        const removed = items.len - kept;
        self.entries.shrinkRetainingCapacity(kept);
        return removed;
    }

    const FindResult = struct { index: usize, exists: bool };

    fn findKeyIndex(self: *const FamilyState, key: []const u8) FindResult {
        var low: usize = 0;
        var high: usize = self.entries.items.len;
        while (low < high) {
            const mid = low + (high - low) / 2;
            switch (std.mem.order(u8, self.entries.items[mid].key, key)) {
                .lt => low = mid + 1,
                .eq => return .{ .index = mid, .exists = true },
                .gt => high = mid,
            }
        }
        return .{ .index = low, .exists = false };
    }
};

fn belowFloor(version: u64, floor: ?u64) bool {
    return if (floor) |f| version <= f else false;
}

/// A family's two-level fingerprint: a whole-family root and 64 bucket roots
/// that localize divergence without exposing any individual key or value.
pub const FamilyDigest = struct {
    family: []u8,
    entry_count: u64,
    tombstone_count: u64,
    root: Hash,
    buckets: [num_buckets]Hash,

    pub fn deinit(self: *FamilyDigest, allocator: Allocator) void {
        allocator.free(self.family);
        self.* = undefined;
    }
};

/// A decoded or caller-built bundle of every family's digest for one peer.
/// `families` is always sorted ascending by name with unique names.
pub const Summary = struct {
    allocator: Allocator,
    families: []FamilyDigest,

    pub fn deinit(self: *Summary) void {
        for (self.families) |*f| f.deinit(self.allocator);
        self.allocator.free(self.families);
        self.* = undefined;
    }
};

/// One bucket's 64 unit roots, as a peer reported them.
pub const BucketDetail = struct {
    bucket: u8,
    sub_roots: [subs_per_bucket]Hash,
};

/// A peer's unit roots for the buckets a `needs_detail` plan named, plus its
/// full digest at build time. Every `sub_roots` hashes to `buckets[bucket]`.
pub const FamilyDetail = struct {
    allocator: Allocator,
    family: []u8,
    entry_count: u64,
    tombstone_count: u64,
    root: Hash,
    buckets: [num_buckets]Hash,
    /// Strictly ascending by bucket; never empty.
    details: []BucketDetail,

    pub fn deinit(self: *FamilyDetail) void {
        self.allocator.free(self.details);
        self.allocator.free(self.family);
        self.* = undefined;
    }
};

/// Cost budget for the delta-vs-full-repair decision. Reuses
/// `anti_entropy.StrategyConfig`'s thresholds and `selectStrategy`'s cost
/// model rather than inventing a second set of divergence knobs. Any
/// threshold is encodable: deltas are chunked into bounded frames.
pub const Budget = struct {
    cfg: anti_entropy.StrategyConfig = .{},
};

pub const FullRepairReason = enum {
    /// The peer summary or detail failed strict decode or is inconsistent.
    malformed_summary,
    /// The peer summary or detail uses an unknown wire version.
    version_mismatch,
    /// The two sides do not track the same family set. Retained for API
    /// stability: `plan` no longer escalates on it (families present on one
    /// side only are reported in `DeltaDecision.one_sided`, and the shared
    /// families are still reconciled by digest and delta).
    family_set_mismatch,
    /// Shipping the differing units would cost more than the budget allows.
    too_divergent,
    /// A delta carried a same-key, same-version conflicting value.
    equivocation,
    /// A delta does not reproduce the sender's attested digest (tampered,
    /// truncated, or incomplete); nothing was applied.
    post_apply_divergence,
    /// A delta is structurally invalid or names a different family.
    malformed_delta,
};

/// Per-family delta plan.
pub const FamilyDeltaPlan = struct {
    family: []u8,
    /// Strictly ascending bucket indices whose summary roots differ; never
    /// empty. The list a `needs_detail` caller requests from the peer.
    buckets: []u8,
    /// Units `buildDelta` ships; never empty.
    units: UnitMask,
    /// Local rows (tombstones included) in `units`.
    row_count: usize,
    /// `units` is still bucket-coarse and over `Budget`: fetch the peer's
    /// `buildDetail(.., buckets)` and call `refine` before building.
    needs_detail: bool,

    fn deinit(self: *FamilyDeltaPlan, allocator: Allocator) void {
        allocator.free(self.family);
        allocator.free(self.buckets);
        self.* = undefined;
    }
};

/// A family tracked by only one side of the comparison. In a mixed-version
/// mesh this is the steady state while builds differ, so it never escalates
/// the shared families: the caller bootstraps or skips it on its own terms.
pub const OneSided = struct {
    family: []u8,
    side: Side,

    pub const Side = enum {
        /// Only the local side tracks it; the peer has no digest to compare.
        local_only,
        /// Only the peer tracks it; this side has nothing to ship for it.
        remote_only,
    };
};

pub const DeltaDecision = struct {
    allocator: Allocator,
    /// Shared families whose digests differ. Empty when the only difference
    /// is the family set itself (see `one_sided`).
    families: []FamilyDeltaPlan,
    /// Families present on exactly one side, ascending by name.
    one_sided: []OneSided = &.{},

    pub fn deinit(self: *DeltaDecision) void {
        for (self.families) |*f| f.deinit(self.allocator);
        self.allocator.free(self.families);
        for (self.one_sided) |o| self.allocator.free(o.family);
        if (self.one_sided.len != 0) self.allocator.free(self.one_sided);
        self.* = undefined;
    }
};

pub const Decision = union(enum) {
    in_sync,
    delta: DeltaDecision,
    full_repair: FullRepairReason,

    pub fn deinit(self: *Decision) void {
        switch (self.*) {
            .delta => |*d| d.deinit(),
            else => {},
        }
    }
};

pub const RefineOutcome = union(enum) {
    /// The plan now names only the differing units and is within budget.
    delta,
    /// The requested buckets no longer differ; nothing to ship this round.
    in_sync,
    full_repair: FullRepairReason,
};

/// The units of one bucket a delta frame ships whole.
pub const DeltaPart = struct {
    bucket: u8,
    /// Bit `s` set: unit `bucket * subs_per_bucket + s` is in this frame.
    sub_mask: u64,
    /// The sender's 64 unit roots for `bucket`, which hash to
    /// `sender_buckets[bucket]`.
    sub_roots: [subs_per_bucket]Hash,
};

/// One bounded frame: every sender row in the units its `parts` name, plus
/// the sender's complete digest and GC floor at build time. The receiver
/// recomputes each included unit root from `entries` and checks it, each
/// part's bucket root, and the family root, against the attested digest.
pub const FamilyDelta = struct {
    allocator: Allocator,
    family: []u8,
    sender_entry_count: u64,
    sender_tombstone_count: u64,
    sender_buckets: [num_buckets]Hash,
    expected_root: Hash,
    sender_gc_floor: ?u64,
    /// Strictly ascending by bucket, each mask nonzero; never empty.
    parts: []DeltaPart,
    /// Strictly ascending by key; every key's unit is in `parts`.
    entries: []Entry,

    pub fn deinit(self: *FamilyDelta) void {
        for (self.entries) |e| self.allocator.free(e.key);
        self.allocator.free(self.entries);
        self.allocator.free(self.parts);
        self.allocator.free(self.family);
        self.* = undefined;
    }
};

/// The frames of one delta or full snapshot. Each frame verifies and applies
/// independently; any applied subset is a valid partial join.
pub const DeltaFrames = struct {
    allocator: Allocator,
    frames: []FamilyDelta,

    pub fn deinit(self: *DeltaFrames) void {
        for (self.frames) |*f| f.deinit();
        self.allocator.free(self.frames);
        self.* = undefined;
    }
};

pub const ApplyFailure = error{
    Equivocation,
    DigestMismatch,
    MalformedDelta,
    FamilyMismatch,
};
pub const ApplyError = ApplyFailure || Allocator.Error;
pub const BuildError = error{
    InvalidBuckets,
    EmptyUnits,
    /// One unit holds more rows than a frame may carry.
    UnitTooLarge,
} || Allocator.Error;
pub const EncodeError = error{
    TooManyFamilies,
    FamilyNameTooLong,
    EmptyFamilyName,
    InvalidBuckets,
    TooManyEntries,
    KeyTooLong,
} || Allocator.Error;

pub const DecodeError = error{
    Truncated,
    TrailingBytes,
    BadMagic,
    UnsupportedVersion,
    TooManyFamilies,
    EmptyFamilyName,
    FamilyNameTooLong,
    UnsortedFamilies,
    DuplicateFamily,
    InconsistentCounts,
    CountOverflow,
    RootMismatch,
    InvalidBuckets,
    TooManyEntries,
    KeyTooLong,
    UnsortedKeys,
    KeyOutsideUnits,
    BadFlag,
} || Allocator.Error;

// ---------------------------------------------------------------------
// Digest construction
// ---------------------------------------------------------------------

fn hashLenPrefixed(h: *Sha256, bytes: []const u8) void {
    var len_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &len_buf, @intCast(bytes.len), .little);
    h.update(&len_buf);
    h.update(bytes);
}

fn hashU64(h: *Sha256, v: u64) void {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, v, .little);
    h.update(&buf);
}

/// Deterministic key -> unit assignment, independent of entry order.
pub fn unitIndex(family: []const u8, key: []const u8) u16 {
    var h = Sha256.init(.{});
    h.update("onyx-m03-unit-assign-v2");
    hashLenPrefixed(&h, family);
    hashLenPrefixed(&h, key);
    var out: Hash = undefined;
    h.final(&out);
    const unit = @as(usize, out[0] & (num_buckets - 1)) * subs_per_bucket + (out[1] & (subs_per_bucket - 1));
    return @intCast(unit);
}

/// Deterministic key -> bucket assignment (the bucket of its unit).
pub fn bucketIndex(family: []const u8, key: []const u8) u8 {
    return @intCast(unitIndex(family, key) / subs_per_bucket);
}

fn familyRootHash(family: []const u8, entry_count: u64, tombstone_count: u64, buckets: *const [num_buckets]Hash) Hash {
    var h = Sha256.init(.{});
    h.update("onyx-m03-family-root-v1");
    hashLenPrefixed(&h, family);
    hashU64(&h, entry_count);
    hashU64(&h, tombstone_count);
    for (buckets) |b| h.update(&b);
    var out: Hash = undefined;
    h.final(&out);
    return out;
}

/// Root of an empty unit, and of a bucket whose units are all empty. Using a
/// constant keeps digest cost proportional to the rows actually present;
/// every non-empty root is a SHA-256 output, never this value in practice.
const empty_root: Hash = @splat(0);

/// Bucket root = SHA-256(domain || family || bucket || (sub || unit root)
/// for every non-empty unit), or `empty_root` when all 64 units are empty.
fn bucketRoot(family: []const u8, bucket: usize, sub_roots: *const [subs_per_bucket]Hash) Hash {
    for (sub_roots) |*r| {
        if (!std.mem.eql(u8, r, &empty_root)) break;
    } else return empty_root;
    var h = Sha256.init(.{});
    h.update("onyx-m03-bucket-root-v2");
    hashLenPrefixed(&h, family);
    h.update(&[1]u8{@intCast(bucket)});
    for (sub_roots, 0..) |*r, s| {
        if (std.mem.eql(u8, r, &empty_root)) continue;
        h.update(&[1]u8{@intCast(s)});
        h.update(r);
    }
    var out: Hash = undefined;
    h.final(&out);
    return out;
}

/// Unit root = SHA-256(domain || family || unit || each row's (key,
/// version, deleted, value_hash) in key order || count), or `empty_root`
/// for no rows. `rows` indexes `entries` in ascending (key) order.
fn unitRoot(family: []const u8, unit: usize, entries: []const Entry, rows: []const usize) Hash {
    if (rows.len == 0) return empty_root;
    var h = Sha256.init(.{});
    h.update("onyx-m03-unit-root-v2");
    hashLenPrefixed(&h, family);
    var unit_buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &unit_buf, @intCast(unit), .little);
    h.update(&unit_buf);
    for (rows) |i| {
        const e = entries[i];
        hashLenPrefixed(&h, e.key);
        hashU64(&h, e.version);
        h.update(&[1]u8{@intFromBool(e.deleted)});
        h.update(&e.value_hash);
    }
    hashU64(&h, rows.len);
    var out: Hash = undefined;
    h.final(&out);
    return out;
}

/// Scratch index grouping key-sorted rows by unit (a stable counting sort),
/// so rows within a unit stay in key order and unit roots stream in O(n).
const UnitGroups = struct {
    order: []usize,
    /// `order[starts[u]..starts[u + 1]]` indexes unit `u`'s rows.
    starts: []usize,

    fn init(allocator: Allocator, family: []const u8, entries: []const Entry) Allocator.Error!UnitGroups {
        const units = try allocator.alloc(u16, entries.len);
        defer allocator.free(units);
        const starts = try allocator.alloc(usize, num_units + 1);
        errdefer allocator.free(starts);
        const order = try allocator.alloc(usize, entries.len);

        @memset(starts, 0);
        for (entries, units) |e, *u| {
            u.* = unitIndex(family, e.key);
            starts[@as(usize, u.*) + 1] += 1;
        }
        for (1..starts.len) |i| starts[i] += starts[i - 1];
        // `starts[u]` is unit u's first slot: use it as a fill cursor, which
        // leaves it at u's end (= u + 1's start), then shift back by one.
        for (units, 0..) |u, i| {
            order[starts[u]] = i;
            starts[u] += 1;
        }
        var u: usize = num_units;
        while (u > 0) : (u -= 1) starts[u] = starts[u - 1];
        starts[0] = 0;
        return .{ .order = order, .starts = starts };
    }

    fn deinit(self: *UnitGroups, allocator: Allocator) void {
        allocator.free(self.order);
        allocator.free(self.starts);
        self.* = undefined;
    }

    fn rows(self: *const UnitGroups, unit: usize) []const usize {
        return self.order[self.starts[unit]..self.starts[unit + 1]];
    }

    fn bucketRows(self: *const UnitGroups, bucket: usize) usize {
        return self.starts[(bucket + 1) * subs_per_bucket] - self.starts[bucket * subs_per_bucket];
    }

    fn subRoots(self: *const UnitGroups, family: []const u8, entries: []const Entry, bucket: usize, out: *[subs_per_bucket]Hash) void {
        for (out, 0..) |*r, s| {
            const unit = bucket * subs_per_bucket + s;
            r.* = unitRoot(family, unit, entries, self.rows(unit));
        }
    }
};

const RowDigest = struct {
    entry_count: u64,
    tombstone_count: u64,
    buckets: [num_buckets]Hash,
    root: Hash,
};

fn digestGrouped(family: []const u8, entries: []const Entry, groups: *const UnitGroups) RowDigest {
    var out: RowDigest = .{ .entry_count = entries.len, .tombstone_count = 0, .buckets = undefined, .root = undefined };
    for (entries) |e| out.tombstone_count += @intFromBool(e.deleted);
    var subs: [subs_per_bucket]Hash = undefined;
    for (&out.buckets, 0..) |*b, i| {
        groups.subRoots(family, entries, i, &subs);
        b.* = bucketRoot(family, i, &subs);
    }
    out.root = familyRootHash(family, out.entry_count, out.tombstone_count, &out.buckets);
    return out;
}

/// Digest key-sorted rows. Pure function of `family` and the logical row
/// set; the allocation is O(n) scratch only.
fn digestRows(allocator: Allocator, family: []const u8, entries: []const Entry) Allocator.Error!RowDigest {
    var groups = try UnitGroups.init(allocator, family, entries);
    defer groups.deinit(allocator);
    return digestGrouped(family, entries, &groups);
}

fn familyDigestLessThan(_: void, a: FamilyDigest, b: FamilyDigest) bool {
    return std.mem.order(u8, a.family, b.family) == .lt;
}

/// Build a `Summary` over every family's current digest, sorted ascending by
/// family name regardless of `families`' input order, so `encodeSummary` is
/// byte-identical for logically identical state.
pub fn buildSummary(allocator: Allocator, families: []const FamilyState) (Allocator.Error || error{DuplicateFamily})!Summary {
    const digests = try allocator.alloc(FamilyDigest, families.len);
    var filled: usize = 0;
    errdefer {
        for (digests[0..filled]) |*d| d.deinit(allocator);
        allocator.free(digests);
    }
    for (families) |*f| {
        digests[filled] = try f.digest();
        filled += 1;
    }
    std.mem.sort(FamilyDigest, digests, {}, familyDigestLessThan);
    for (1..digests.len) |i| {
        if (std.mem.eql(u8, digests[i - 1].family, digests[i].family)) return error.DuplicateFamily;
    }
    return .{ .allocator = allocator, .families = digests };
}

/// The peer's unit roots for `buckets` (strictly ascending, non-empty, each
/// `< num_buckets`): the answer to a `needs_detail` plan's request.
pub fn buildDetail(allocator: Allocator, local: *const FamilyState, buckets: []const u8) BuildError!FamilyDetail {
    if (bucketMask(buckets) == null) return error.InvalidBuckets;
    var groups = try UnitGroups.init(allocator, local.family, local.entries.items);
    defer groups.deinit(allocator);
    const rows = digestGrouped(local.family, local.entries.items, &groups);

    const family = try allocator.dupe(u8, local.family);
    errdefer allocator.free(family);
    const details = try allocator.alloc(BucketDetail, buckets.len);
    for (details, buckets) |*d, b| {
        d.bucket = b;
        groups.subRoots(local.family, local.entries.items, b, &d.sub_roots);
    }
    return .{
        .allocator = allocator,
        .family = family,
        .entry_count = rows.entry_count,
        .tombstone_count = rows.tombstone_count,
        .root = rows.root,
        .buckets = rows.buckets,
        .details = details,
    };
}

// ---------------------------------------------------------------------
// Wire codec
// ---------------------------------------------------------------------

/// Writes into a buffer sized exactly up front, so each encode performs one
/// allocation and never depends on allocator growth behavior.
const WireWriter = struct {
    buf: []u8,
    pos: usize = 0,

    fn bytes(self: *WireWriter, bs: []const u8) void {
        @memcpy(self.buf[self.pos..][0..bs.len], bs);
        self.pos += bs.len;
    }
    fn byte(self: *WireWriter, v: u8) void {
        self.bytes(&[1]u8{v});
    }
    fn int(self: *WireWriter, comptime T: type, v: T) void {
        std.mem.writeInt(T, self.buf[self.pos..][0..@sizeOf(T)], v, .little);
        self.pos += @sizeOf(T);
    }
    fn header(self: *WireWriter, magic: []const u8, family: []const u8) void {
        self.bytes(magic);
        self.byte(wire_version);
        self.byte(@intCast(family.len));
        self.bytes(family);
    }
    fn digestBody(self: *WireWriter, entry_count: u64, tombstone_count: u64, root: *const Hash, buckets: *const [num_buckets]Hash) void {
        self.int(u64, entry_count);
        self.int(u64, tombstone_count);
        self.bytes(root);
        for (buckets) |*b| self.bytes(b);
    }
    fn subRoots(self: *WireWriter, roots: *const [subs_per_bucket]Hash) void {
        for (roots) |*r| self.bytes(r);
    }
};

const WireReader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn fixed(self: *WireReader, n: usize) DecodeError![]const u8 {
        if (self.buf.len - self.pos < n) return error.Truncated;
        const s = self.buf[self.pos .. self.pos + n];
        self.pos += n;
        return s;
    }
    fn byte(self: *WireReader) DecodeError!u8 {
        return (try self.fixed(1))[0];
    }
    fn int(self: *WireReader, comptime T: type) DecodeError!T {
        return std.mem.readInt(T, (try self.fixed(@sizeOf(T)))[0..@sizeOf(T)], .little);
    }
    fn hash(self: *WireReader) DecodeError!Hash {
        return (try self.fixed(32))[0..32].*;
    }
    fn header(self: *WireReader, magic: []const u8) DecodeError!void {
        if (!std.mem.eql(u8, try self.fixed(magic.len), magic)) return error.BadMagic;
        if (try self.byte() != wire_version) return error.UnsupportedVersion;
    }
    fn familyName(self: *WireReader) DecodeError![]const u8 {
        const name_len = try self.byte();
        if (name_len == 0) return error.EmptyFamilyName;
        if (name_len > max_family_name_len) return error.FamilyNameTooLong;
        return self.fixed(name_len);
    }
    /// Reads a digest body and checks its counts and that its root binds its
    /// buckets, so no inconsistent peer digest ever reaches the planner.
    fn digestBody(self: *WireReader, family: []const u8) DecodeError!RowDigest {
        const entry_count = try self.int(u64);
        const tombstone_count = try self.int(u64);
        if (entry_count > max_family_entries) return error.CountOverflow;
        if (tombstone_count > entry_count) return error.InconsistentCounts;
        const root = try self.hash();
        var out: RowDigest = .{ .entry_count = entry_count, .tombstone_count = tombstone_count, .root = root, .buckets = undefined };
        for (&out.buckets) |*b| b.* = try self.hash();
        if (!std.mem.eql(u8, &out.root, &familyRootHash(family, entry_count, tombstone_count, &out.buckets))) return error.RootMismatch;
        return out;
    }
    fn subRoots(self: *WireReader) DecodeError![subs_per_bucket]Hash {
        var out: [subs_per_bucket]Hash = undefined;
        for (&out) |*r| r.* = try self.hash();
        return out;
    }
    /// Reads a bucket index that must exceed `prev` and be `< num_buckets`.
    fn ascendingBucket(self: *WireReader, prev: ?u8) DecodeError!u8 {
        const b = try self.byte();
        if (b >= num_buckets) return error.InvalidBuckets;
        if (prev) |p| {
            if (b <= p) return error.InvalidBuckets;
        }
        return b;
    }
    /// Reads a 1..`num_buckets` part count.
    fn partCount(self: *WireReader) DecodeError!u8 {
        const n = try self.byte();
        if (n == 0 or n > num_buckets) return error.InvalidBuckets;
        return n;
    }
    fn finish(self: *const WireReader) DecodeError!void {
        if (self.pos != self.buf.len) return error.TrailingBytes;
    }
};

fn checkFamilyName(name: []const u8) EncodeError!void {
    if (name.len == 0) return error.EmptyFamilyName;
    if (name.len > max_family_name_len) return error.FamilyNameTooLong;
}

/// Encode a summary. `summary.families` must already be sorted ascending by
/// name with unique names, the only shape `buildSummary` and `decodeSummary`
/// hand back. Wire bounds are enforced here too: `FamilyState.init` never
/// validates a name, so oversized local input fails closed instead of
/// overflowing a length prefix.
pub fn encodeSummary(allocator: Allocator, summary: *const Summary) EncodeError![]u8 {
    if (summary.families.len > max_families) return error.TooManyFamilies;
    for (summary.families) |fd| try checkFamilyName(fd.family);

    var size: usize = summary_magic.len + 1 + 2;
    for (summary.families) |fd| size += 1 + fd.family.len + digest_body_len;

    var w = WireWriter{ .buf = try allocator.alloc(u8, size) };
    w.bytes(summary_magic);
    w.byte(wire_version);
    w.int(u16, @intCast(summary.families.len));
    for (summary.families) |*fd| {
        w.byte(@intCast(fd.family.len));
        w.bytes(fd.family);
        w.digestBody(fd.entry_count, fd.tombstone_count, &fd.root, &fd.buckets);
    }
    std.debug.assert(w.pos == w.buf.len);
    return w.buf;
}

/// Strict, bounded summary decode. Rejects truncation, trailing bytes,
/// unknown magic/version, unsorted or duplicate families, over-limit or
/// inconsistent counts, and roots that do not bind their buckets. Never
/// panics on hostile input.
pub fn decodeSummary(allocator: Allocator, bytes: []const u8) DecodeError!Summary {
    var r = WireReader{ .buf = bytes };
    try r.header(summary_magic);
    const family_count = try r.int(u16);
    if (family_count > max_families) return error.TooManyFamilies;

    const families = try allocator.alloc(FamilyDigest, family_count);
    var filled: usize = 0;
    errdefer {
        for (families[0..filled]) |*f| f.deinit(allocator);
        allocator.free(families);
    }

    var prev_name: ?[]const u8 = null;
    for (families) |*slot| {
        const name = try r.familyName();
        if (prev_name) |p| switch (std.mem.order(u8, p, name)) {
            .eq => return error.DuplicateFamily,
            .gt => return error.UnsortedFamilies,
            .lt => {},
        };
        prev_name = name;
        const body = try r.digestBody(name);
        slot.* = .{
            .family = try allocator.dupe(u8, name),
            .entry_count = body.entry_count,
            .tombstone_count = body.tombstone_count,
            .root = body.root,
            .buckets = body.buckets,
        };
        filled += 1;
    }
    try r.finish();
    return .{ .allocator = allocator, .families = families };
}

/// Encode a detail. Bounded by `num_buckets` parts of fixed size.
pub fn encodeDetail(allocator: Allocator, detail: *const FamilyDetail) EncodeError![]u8 {
    try checkFamilyName(detail.family);
    if (detail.details.len == 0 or detail.details.len > num_buckets) return error.InvalidBuckets;
    for (detail.details, 0..) |d, i| {
        if (d.bucket >= num_buckets) return error.InvalidBuckets;
        if (i > 0 and d.bucket <= detail.details[i - 1].bucket) return error.InvalidBuckets;
    }
    const size = detail_magic.len + 1 + 1 + detail.family.len + digest_body_len + 1 + detail.details.len * detail_part_len;

    var w = WireWriter{ .buf = try allocator.alloc(u8, size) };
    w.header(detail_magic, detail.family);
    w.digestBody(detail.entry_count, detail.tombstone_count, &detail.root, &detail.buckets);
    w.byte(@intCast(detail.details.len));
    for (detail.details) |*d| {
        w.byte(d.bucket);
        w.subRoots(&d.sub_roots);
    }
    std.debug.assert(w.pos == w.buf.len);
    return w.buf;
}

/// Strict, bounded detail decode. Beyond the summary checks, every bucket's
/// unit roots must hash to the attested bucket root.
pub fn decodeDetail(allocator: Allocator, bytes: []const u8) DecodeError!FamilyDetail {
    var r = WireReader{ .buf = bytes };
    try r.header(detail_magic);
    const name = try r.familyName();
    const body = try r.digestBody(name);
    const count = try r.partCount();

    const details = try allocator.alloc(BucketDetail, count);
    errdefer allocator.free(details);
    var prev: ?u8 = null;
    for (details) |*d| {
        d.bucket = try r.ascendingBucket(prev);
        prev = d.bucket;
        d.sub_roots = try r.subRoots();
        if (!std.mem.eql(u8, &bucketRoot(name, d.bucket, &d.sub_roots), &body.buckets[d.bucket])) return error.RootMismatch;
    }
    try r.finish();
    return .{
        .allocator = allocator,
        .family = try allocator.dupe(u8, name),
        .entry_count = body.entry_count,
        .tombstone_count = body.tombstone_count,
        .root = body.root,
        .buckets = body.buckets,
        .details = details,
    };
}

/// Encode one delta frame. Every frame `buildDelta`/`buildFullSnapshot`
/// returns fits; hand-built oversized frames fail closed.
pub fn encodeDelta(allocator: Allocator, delta: *const FamilyDelta) EncodeError![]u8 {
    try checkFamilyName(delta.family);
    if (partsMask(delta.parts) == null) return error.InvalidBuckets;
    if (delta.entries.len > max_delta_entries) return error.TooManyEntries;
    var size: usize = delta_magic.len + 1 + 1 + delta.family.len + digest_body_len + floor_len + 1 + delta.parts.len * delta_part_len + 2;
    for (delta.entries) |e| {
        if (e.key.len > max_key_len) return error.KeyTooLong;
        size += delta_row_fixed_len + e.key.len;
    }
    std.debug.assert(size <= max_delta_wire_len);

    var w = WireWriter{ .buf = try allocator.alloc(u8, size) };
    w.header(delta_magic, delta.family);
    w.digestBody(delta.sender_entry_count, delta.sender_tombstone_count, &delta.expected_root, &delta.sender_buckets);
    w.byte(@intFromBool(delta.sender_gc_floor != null));
    w.int(u64, delta.sender_gc_floor orelse 0);
    w.byte(@intCast(delta.parts.len));
    for (delta.parts) |*p| {
        w.byte(p.bucket);
        w.int(u64, p.sub_mask);
        w.subRoots(&p.sub_roots);
    }
    w.int(u16, @intCast(delta.entries.len));
    for (delta.entries) |e| {
        w.int(u16, @intCast(e.key.len));
        w.bytes(e.key);
        w.int(u64, e.version);
        w.byte(@intFromBool(e.deleted));
        w.bytes(&e.value_hash);
    }
    std.debug.assert(w.pos == w.buf.len);
    return w.buf;
}

/// Strict, bounded delta decode: the syntax and shape checks only. Content
/// verification against the attested digest happens in `applyDelta` and
/// `fullRepair`, which also guard in-memory frames.
pub fn decodeDelta(allocator: Allocator, bytes: []const u8) DecodeError!FamilyDelta {
    var r = WireReader{ .buf = bytes };
    try r.header(delta_magic);
    const name = try r.familyName();
    const body = try r.digestBody(name);
    const has_floor = try r.byte();
    const floor_value = try r.int(u64);
    const sender_gc_floor: ?u64 = switch (has_floor) {
        0 => if (floor_value == 0) null else return error.BadFlag,
        1 => floor_value,
        else => return error.BadFlag,
    };

    const part_count = try r.partCount();
    const parts = try allocator.alloc(DeltaPart, part_count);
    errdefer allocator.free(parts);
    var table: [num_buckets]u64 = @splat(0);
    var prev: ?u8 = null;
    for (parts) |*p| {
        p.bucket = try r.ascendingBucket(prev);
        prev = p.bucket;
        p.sub_mask = try r.int(u64);
        if (p.sub_mask == 0) return error.InvalidBuckets;
        p.sub_roots = try r.subRoots();
        table[p.bucket] = p.sub_mask;
    }

    const entry_count = try r.int(u16);
    if (entry_count > max_delta_entries) return error.TooManyEntries;
    if (entry_count > body.entry_count) return error.InconsistentCounts;

    const family = try allocator.dupe(u8, name);
    errdefer allocator.free(family);
    const entries = try allocator.alloc(Entry, entry_count);
    var filled: usize = 0;
    errdefer {
        for (entries[0..filled]) |e| allocator.free(e.key);
        allocator.free(entries);
    }

    var prev_key: ?[]const u8 = null;
    for (entries) |*slot| {
        const key_len = try r.int(u16);
        if (key_len > max_key_len) return error.KeyTooLong;
        const key = try r.fixed(key_len);
        if (prev_key) |p| {
            if (std.mem.order(u8, p, key) != .lt) return error.UnsortedKeys;
        }
        prev_key = key;
        if (!unitShipped(&table, unitIndex(name, key))) return error.KeyOutsideUnits;
        const version = try r.int(u64);
        const deleted = switch (try r.byte()) {
            0 => false,
            1 => true,
            else => return error.BadFlag,
        };
        const value_hash = try r.hash();
        slot.* = .{ .key = try allocator.dupe(u8, key), .version = version, .value_hash = value_hash, .deleted = deleted };
        filled += 1;
    }
    try r.finish();
    return .{
        .allocator = allocator,
        .family = family,
        .sender_entry_count = body.entry_count,
        .sender_tombstone_count = body.tombstone_count,
        .sender_buckets = body.buckets,
        .expected_root = body.root,
        .sender_gc_floor = sender_gc_floor,
        .parts = parts,
        .entries = entries,
    };
}

// ---------------------------------------------------------------------
// Planner
// ---------------------------------------------------------------------

/// Membership mask for a strictly ascending, non-empty bucket list, or null.
fn bucketMask(buckets: []const u8) ?[num_buckets]bool {
    if (buckets.len == 0) return null;
    var mask: [num_buckets]bool = @splat(false);
    var prev: ?u8 = null;
    for (buckets) |b| {
        if (b >= num_buckets) return null;
        if (prev) |p| {
            if (b <= p) return null;
        }
        prev = b;
        mask[b] = true;
    }
    return mask;
}

/// Per-bucket unit masks for well-formed `parts` (non-empty, strictly
/// ascending buckets `< num_buckets`, nonzero masks), or null.
fn partsMask(parts: []const DeltaPart) ?[num_buckets]u64 {
    if (parts.len == 0) return null;
    var table: [num_buckets]u64 = @splat(0);
    for (parts, 0..) |p, i| {
        if (p.bucket >= num_buckets or p.sub_mask == 0) return null;
        if (i > 0 and p.bucket <= parts[i - 1].bucket) return null;
        table[p.bucket] = p.sub_mask;
    }
    return table;
}

fn unitShipped(table: *const [num_buckets]u64, unit: u16) bool {
    const sub: u6 = @intCast(unit % subs_per_bucket);
    return (table[unit / subs_per_bucket] >> sub) & 1 == 1;
}

fn overBudget(budget: Budget, local_rows: usize, remote_rows_wire: u64, differing_rows: usize) bool {
    const remote_rows = @min(std.math.lossyCast(usize, remote_rows_wire), std.math.maxInt(usize) - local_rows);
    return anti_entropy.selectStrategy(budget.cfg, .{
        .local_key_count = local_rows,
        .remote_key_count = remote_rows,
        .estimated_differing_keys = differing_rows,
    }) == .full_resync;
}

/// Compare local family state against a peer's encoded summary and decide
/// where on the ladder this pair sits. `local` must be sorted ascending by
/// family name with unique names (see `FamilyState`). Hostile `remote_bytes`
/// always resolve to `full_repair`; only allocation failure is returned as an
/// error (nothing is mutated, so the caller may simply retry).
pub fn plan(allocator: Allocator, local: []const FamilyState, remote_bytes: []const u8, budget: Budget) Allocator.Error!Decision {
    var remote = decodeSummary(allocator, remote_bytes) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.UnsupportedVersion => return .{ .full_repair = .version_mismatch },
        else => return .{ .full_repair = .malformed_summary },
    };
    defer remote.deinit();

    // Both lists are ascending by unique name (local by contract, remote by
    // the decoder), so one merge walk pairs the shared families. A family on
    // one side only is reported, never escalated: in a mixed-version mesh it
    // would otherwise force full repair of every family on every round.
    // One exact allocation per list up front: neither grows, so allocation
    // behavior is independent of allocator resize policy.
    var plans: std.ArrayList(FamilyDeltaPlan) = .empty;
    defer {
        for (plans.items) |*fp| fp.deinit(allocator);
        plans.deinit(allocator);
    }
    try plans.ensureTotalCapacityPrecise(allocator, @min(local.len, remote.families.len));
    var one_sided: std.ArrayList(OneSided) = .empty;
    defer {
        for (one_sided.items) |o| allocator.free(o.family);
        one_sided.deinit(allocator);
    }
    try one_sided.ensureTotalCapacityPrecise(allocator, local.len + remote.families.len);

    var li: usize = 0;
    var ri: usize = 0;
    while (li < local.len or ri < remote.families.len) {
        const order: std.math.Order = if (li == local.len)
            .gt
        else if (ri == remote.families.len)
            .lt
        else
            std.mem.order(u8, local[li].family, remote.families[ri].family);
        switch (order) {
            .lt => {
                one_sided.appendAssumeCapacity(.{ .family = try allocator.dupe(u8, local[li].family), .side = .local_only });
                li += 1;
                continue;
            },
            .gt => {
                one_sided.appendAssumeCapacity(.{ .family = try allocator.dupe(u8, remote.families[ri].family), .side = .remote_only });
                ri += 1;
                continue;
            },
            .eq => {},
        }
        const lf = &local[li];
        const rf = remote.families[ri];
        li += 1;
        ri += 1;
        var groups = try UnitGroups.init(allocator, lf.family, lf.entries.items);
        defer groups.deinit(allocator);
        const ld = digestGrouped(lf.family, lf.entries.items, &groups);
        if (std.mem.eql(u8, &ld.root, &rf.root)) continue;

        var units: UnitMask = .empty;
        var bucket_count: usize = 0;
        var row_count: usize = 0;
        for (ld.buckets, rf.buckets, 0..) |lb, rb, b| {
            if (std.mem.eql(u8, &lb, &rb)) continue;
            bucket_count += 1;
            units.setRangeValue(.{ .start = b * subs_per_bucket, .end = (b + 1) * subs_per_bucket }, true);
            row_count += groups.bucketRows(b);
        }
        // Both roots bind their counts and buckets (decode verified the
        // remote one). Identical buckets commit to identical rows, so a
        // differing root with no differing bucket means the peer advertised
        // counts its own buckets contradict.
        if (bucket_count == 0) return .{ .full_repair = .malformed_summary };

        const family = try allocator.dupe(u8, lf.family);
        errdefer allocator.free(family);
        const buckets = try allocator.alloc(u8, bucket_count);
        var n: usize = 0;
        for (ld.buckets, rf.buckets, 0..) |lb, rb, b| {
            if (std.mem.eql(u8, &lb, &rb)) continue;
            buckets[n] = @intCast(b);
            n += 1;
        }
        plans.appendAssumeCapacity(.{
            .family = family,
            .buckets = buckets,
            .units = units,
            .row_count = row_count,
            .needs_detail = overBudget(budget, lf.len(), rf.entry_count, row_count),
        });
    }

    if (plans.items.len == 0 and one_sided.items.len == 0) return .in_sync;
    const owned = try allocator.dupe(FamilyDeltaPlan, plans.items);
    errdefer allocator.free(owned);
    const owned_sided: []OneSided = if (one_sided.items.len == 0) &.{} else try allocator.dupe(OneSided, one_sided.items);
    // Ownership of every plan and one-sided name moved to the decision.
    plans.clearRetainingCapacity();
    one_sided.clearRetainingCapacity();
    return .{ .delta = .{ .allocator = allocator, .families = owned, .one_sided = owned_sided } };
}

/// Narrow `fp` to the units whose roots differ from the peer's encoded
/// `buildDetail(.., fp.buckets)` answer, then re-apply the budget at unit
/// resolution. `fp` changes only on `.delta`. Hostile bytes resolve to
/// `full_repair`; only allocation failure is an error (`fp` untouched).
pub fn refine(allocator: Allocator, local: *const FamilyState, fp: *FamilyDeltaPlan, remote_detail_bytes: []const u8, budget: Budget) Allocator.Error!RefineOutcome {
    var detail = decodeDetail(allocator, remote_detail_bytes) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.UnsupportedVersion => return .{ .full_repair = .version_mismatch },
        else => return .{ .full_repair = .malformed_summary },
    };
    defer detail.deinit();
    if (!std.mem.eql(u8, detail.family, fp.family) or !std.mem.eql(u8, local.family, fp.family)) return .{ .full_repair = .malformed_summary };
    // The peer must answer exactly the buckets requested.
    if (detail.details.len != fp.buckets.len) return .{ .full_repair = .malformed_summary };
    for (detail.details, fp.buckets) |d, b| {
        if (d.bucket != b) return .{ .full_repair = .malformed_summary };
    }

    var groups = try UnitGroups.init(allocator, local.family, local.entries.items);
    defer groups.deinit(allocator);
    var units: UnitMask = .empty;
    var row_count: usize = 0;
    var local_subs: [subs_per_bucket]Hash = undefined;
    for (detail.details) |*d| {
        groups.subRoots(local.family, local.entries.items, d.bucket, &local_subs);
        for (local_subs, d.sub_roots, 0..) |l, rr, s| {
            if (std.mem.eql(u8, &l, &rr)) continue;
            const unit = @as(usize, d.bucket) * subs_per_bucket + s;
            units.set(unit);
            row_count += groups.rows(unit).len;
        }
    }
    if (units.count() == 0) return .in_sync;
    if (overBudget(budget, local.len(), detail.entry_count, row_count)) return .{ .full_repair = .too_divergent };
    fp.units = units;
    fp.row_count = row_count;
    fp.needs_detail = false;
    return .delta;
}

// ---------------------------------------------------------------------
// Delta build/apply
// ---------------------------------------------------------------------

/// Package every `local` row in `units` together with `local`'s current full
/// digest and GC floor, as frames of at most `max_delta_entries` rows.
pub fn buildDelta(allocator: Allocator, local: *const FamilyState, units: *const UnitMask) BuildError!DeltaFrames {
    if (units.count() == 0) return error.EmptyUnits;
    return buildFrames(allocator, local, units, max_delta_entries);
}

/// A whole-family snapshot: the frames `fullRepair` expects.
pub fn buildFullSnapshot(allocator: Allocator, local: *const FamilyState) (error{UnitTooLarge} || Allocator.Error)!DeltaFrames {
    const all: UnitMask = .full;
    return buildFrames(allocator, local, &all, max_delta_entries) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.UnitTooLarge => error.UnitTooLarge,
        error.InvalidBuckets, error.EmptyUnits => unreachable, // `all` is the full set.
    };
}

/// Greedy packing in unit order: a frame closes when the next unit would
/// push it past `max_rows`. A unit is never split, so each frame verifies on
/// its own; a unit larger than `max_rows` fails closed.
fn buildFrames(allocator: Allocator, local: *const FamilyState, units: *const UnitMask, max_rows: usize) BuildError!DeltaFrames {
    const entries = local.entries.items;
    var groups = try UnitGroups.init(allocator, local.family, entries);
    defer groups.deinit(allocator);
    const rows = digestGrouped(local.family, entries, &groups);

    var frames: std.ArrayList(FamilyDelta) = .empty;
    errdefer {
        for (frames.items) |*f| f.deinit();
        frames.deinit(allocator);
    }
    var parts: std.ArrayList(DeltaPart) = .empty;
    defer parts.deinit(allocator);
    var pending_rows: usize = 0;

    for (0..num_buckets) |b| {
        for (0..subs_per_bucket) |s| {
            const unit = b * subs_per_bucket + s;
            if (!units.isSet(unit)) continue;
            const n = groups.rows(unit).len;
            if (n > max_rows) return error.UnitTooLarge;
            if (pending_rows + n > max_rows) {
                try flushFrame(allocator, local, &groups, &rows, parts.items, &frames);
                parts.clearRetainingCapacity();
                pending_rows = 0;
            }
            if (parts.items.len == 0 or parts.items[parts.items.len - 1].bucket != b) {
                const part = try parts.addOne(allocator);
                part.* = .{ .bucket = @intCast(b), .sub_mask = 0, .sub_roots = undefined };
                groups.subRoots(local.family, entries, b, &part.sub_roots);
            }
            parts.items[parts.items.len - 1].sub_mask |= @as(u64, 1) << @intCast(s);
            pending_rows += n;
        }
    }
    if (parts.items.len > 0) try flushFrame(allocator, local, &groups, &rows, parts.items, &frames);
    return .{ .allocator = allocator, .frames = try frames.toOwnedSlice(allocator) };
}

fn flushFrame(
    allocator: Allocator,
    local: *const FamilyState,
    groups: *const UnitGroups,
    rows: *const RowDigest,
    parts: []const DeltaPart,
    frames: *std.ArrayList(FamilyDelta),
) Allocator.Error!void {
    var count: usize = 0;
    for (parts) |p| {
        for (0..subs_per_bucket) |s| {
            if ((p.sub_mask >> @intCast(s)) & 1 == 1) count += groups.rows(@as(usize, p.bucket) * subs_per_bucket + s).len;
        }
    }
    // Entry index order is key order, so sorting the indices sorts the rows.
    const picked = try allocator.alloc(usize, count);
    defer allocator.free(picked);
    var n: usize = 0;
    for (parts) |p| {
        for (0..subs_per_bucket) |s| {
            if ((p.sub_mask >> @intCast(s)) & 1 == 0) continue;
            const unit_rows = groups.rows(@as(usize, p.bucket) * subs_per_bucket + s);
            @memcpy(picked[n..][0..unit_rows.len], unit_rows);
            n += unit_rows.len;
        }
    }
    std.mem.sort(usize, picked, {}, std.sort.asc(usize));

    try frames.ensureUnusedCapacity(allocator, 1);
    const family = try allocator.dupe(u8, local.family);
    errdefer allocator.free(family);
    const owned_parts = try allocator.dupe(DeltaPart, parts);
    errdefer allocator.free(owned_parts);
    const entries = try allocator.alloc(Entry, count);
    var filled: usize = 0;
    errdefer {
        for (entries[0..filled]) |e| allocator.free(e.key);
        allocator.free(entries);
    }
    for (picked, entries) |i, *slot| {
        const e = local.entries.items[i];
        slot.* = .{ .key = try allocator.dupe(u8, e.key), .version = e.version, .value_hash = e.value_hash, .deleted = e.deleted };
        filled += 1;
    }
    frames.appendAssumeCapacity(.{
        .allocator = allocator,
        .family = family,
        .sender_entry_count = rows.entry_count,
        .sender_tombstone_count = rows.tombstone_count,
        .sender_buckets = rows.buckets,
        .expected_root = rows.root,
        .sender_gc_floor = local.gc_floor,
        .parts = owned_parts,
        .entries = entries,
    });
}

/// Check that `delta` is well-formed for `family` and that its rows are
/// exactly the sender's rows in the included units: every recomputed unit
/// root must equal the attested one, every part's unit roots must hash to
/// the attested bucket root, and the attested buckets and counts must hash
/// to the attested root. Allocates O(frame) scratch only.
fn verifyDelta(allocator: Allocator, family: []const u8, delta: *const FamilyDelta) ApplyError!void {
    if (!std.mem.eql(u8, family, delta.family)) return error.FamilyMismatch;
    const table = partsMask(delta.parts) orelse return error.MalformedDelta;
    if (delta.sender_tombstone_count > delta.sender_entry_count) return error.MalformedDelta;
    for (delta.entries, 0..) |e, i| {
        if (i > 0 and std.mem.order(u8, delta.entries[i - 1].key, e.key) != .lt) return error.MalformedDelta;
        if (!unitShipped(&table, unitIndex(family, e.key))) return error.MalformedDelta;
    }
    const attested = familyRootHash(family, delta.sender_entry_count, delta.sender_tombstone_count, &delta.sender_buckets);
    if (!std.mem.eql(u8, &attested, &delta.expected_root)) return error.DigestMismatch;
    for (delta.parts) |*p| {
        if (!std.mem.eql(u8, &bucketRoot(family, p.bucket, &p.sub_roots), &delta.sender_buckets[p.bucket])) return error.DigestMismatch;
    }
    var groups = try UnitGroups.init(allocator, family, delta.entries);
    defer groups.deinit(allocator);
    for (delta.parts) |*p| {
        for (p.sub_roots, 0..) |want, s| {
            if ((p.sub_mask >> @intCast(s)) & 1 == 0) continue;
            const unit = @as(usize, p.bucket) * subs_per_bucket + s;
            if (!std.mem.eql(u8, &unitRoot(family, unit, delta.entries, groups.rows(unit)), &want)) return error.DigestMismatch;
        }
    }
}

/// LWW total order on `(version, deleted, value_hash)`. A version tie with
/// differing flags is resolved for the tombstone (deletions converge rather
/// than being resurrected by a stale live write). A full tie with differing
/// hashes is an equivocation.
const MergeOutcome = enum { adopt_incoming, keep_existing, equivocation };

fn mergeDecision(existing: Entry, incoming: Entry) MergeOutcome {
    if (incoming.version != existing.version) return if (incoming.version > existing.version) .adopt_incoming else .keep_existing;
    if (incoming.deleted != existing.deleted) return if (incoming.deleted) .adopt_incoming else .keep_existing;
    return switch (std.mem.order(u8, &incoming.value_hash, &existing.value_hash)) {
        .eq => .keep_existing,
        .lt, .gt => .equivocation,
    };
}

const EquivocationPolicy = enum { reject, resolve };

fn keyOrder(a: Entry, b: Entry) std.math.Order {
    return std.mem.order(u8, a.key, b.key);
}

/// Verify one frame, then join it into `target` in place in three passes:
///   1. read-only: classify rows, reject equivocations, count inserts;
///   2. reserve capacity and duplicate every inserted key (the only
///      fallible step after verification);
///   3. infallible commit: update matched rows and prune dead receiver rows
///      in a forward compaction, then merge inserts in from the back.
/// Receiver-only rows in a shipped unit at or below the sender's GC floor
/// are dead (the sender holds every live row up to its floor) and are
/// pruned; incoming-only rows at or below the target's own floor are dead
/// and dropped. Returns the count of resolved equivocations.
fn verifyAndMerge(target: *FamilyState, delta: *const FamilyDelta, policy: EquivocationPolicy) ApplyError!usize {
    const allocator = target.allocator;
    try verifyDelta(allocator, target.family, delta);
    const table = partsMask(delta.parts).?; // verified above
    const incoming = delta.entries;

    var inserts: usize = 0;
    var resolved: usize = 0;
    {
        const existing = target.entries.items;
        var i: usize = 0;
        for (incoming) |inc| {
            while (i < existing.len and keyOrder(existing[i], inc) == .lt) i += 1;
            if (i < existing.len and keyOrder(existing[i], inc) == .eq) {
                if (mergeDecision(existing[i], inc) == .equivocation) switch (policy) {
                    .reject => return error.Equivocation,
                    .resolve => resolved += 1,
                };
                i += 1;
            } else if (!belowFloor(inc.version, target.gc_floor)) {
                inserts += 1;
            }
        }
    }

    try target.entries.ensureTotalCapacity(allocator, target.entries.items.len + inserts);
    const new_keys = try allocator.alloc([]u8, inserts);
    defer allocator.free(new_keys);
    var made: usize = 0;
    errdefer for (new_keys[0..made]) |key| allocator.free(key);
    {
        const existing = target.entries.items;
        var i: usize = 0;
        for (incoming) |inc| {
            while (i < existing.len and keyOrder(existing[i], inc) == .lt) i += 1;
            if (i < existing.len and keyOrder(existing[i], inc) == .eq) {
                i += 1;
            } else if (!belowFloor(inc.version, target.gc_floor)) {
                new_keys[made] = try allocator.dupe(u8, inc.key);
                made += 1;
            }
        }
    }

    // Commit: nothing below can fail.
    var kept: usize = 0;
    {
        const items = target.entries.items;
        var j: usize = 0;
        for (items) |row_in| {
            var row = row_in;
            while (j < incoming.len and keyOrder(incoming[j], row) == .lt) j += 1;
            if (j < incoming.len and keyOrder(incoming[j], row) == .eq) {
                const inc = incoming[j];
                const take = switch (mergeDecision(row, inc)) {
                    .adopt_incoming => true,
                    .keep_existing => false,
                    .equivocation => std.mem.order(u8, &inc.value_hash, &row.value_hash) == .gt,
                };
                if (take) {
                    row.version = inc.version;
                    row.value_hash = inc.value_hash;
                    row.deleted = inc.deleted;
                }
                j += 1;
            } else if (belowFloor(row.version, delta.sender_gc_floor) and unitShipped(&table, unitIndex(target.family, row.key))) {
                allocator.free(row.key);
                continue;
            }
            items[kept] = row;
            kept += 1;
        }
    }
    target.entries.items.len = kept + inserts;
    {
        const all = target.entries.items;
        var r: usize = kept;
        var dst: usize = kept + inserts;
        var k: usize = inserts;
        var jj: usize = incoming.len;
        while (jj > 0) {
            jj -= 1;
            const inc = incoming[jj];
            while (r > 0 and keyOrder(all[r - 1], inc) == .gt) {
                dst -= 1;
                r -= 1;
                all[dst] = all[r];
            }
            if (r > 0 and keyOrder(all[r - 1], inc) == .eq) continue; // merged in place
            if (belowFloor(inc.version, target.gc_floor)) continue; // collected here
            k -= 1;
            dst -= 1;
            all[dst] = .{ .key = new_keys[k], .version = inc.version, .value_hash = inc.value_hash, .deleted = inc.deleted };
        }
        std.debug.assert(k == 0 and dst == r);
    }
    return resolved;
}

/// Verify and LWW-merge one peer frame into `target`. Any error leaves
/// `target` byte-for-byte unchanged: verification and every allocation
/// happen before the first mutation.
pub fn applyDelta(target: *FamilyState, delta: *const FamilyDelta) ApplyError!void {
    _ = try verifyAndMerge(target, delta, .reject);
}

/// `applyDelta`, folding its rejections into the `FullRepairReason`
/// vocabulary `plan()` uses. Returns null when the frame was merged;
/// otherwise the reason to fall back to full repair (target untouched).
pub fn applyDeltaOrEscalate(target: *FamilyState, delta: *const FamilyDelta) Allocator.Error!?FullRepairReason {
    applyDelta(target, delta) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.Equivocation => .equivocation,
        error.DigestMismatch => .post_apply_divergence,
        error.MalformedDelta, error.FamilyMismatch => .malformed_delta,
    };
    return null;
}

/// Full-repair fallback for one snapshot frame (normally from
/// `buildFullSnapshot`; apply every frame): verify and LWW-join it into
/// `target`, resolving equivocations deterministically (the greater
/// `value_hash` wins on both sides, so both replicas converge to the same
/// row). Returns the number of equivocations resolved, for the caller's
/// audit/metrics. Never returns `error.Equivocation`; any error leaves
/// `target` unchanged.
pub fn fullRepair(target: *FamilyState, snapshot: *const FamilyDelta) ApplyError!usize {
    return verifyAndMerge(target, snapshot, .resolve);
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

const testing = std.testing;

fn makeHash(byte: u8) Hash {
    return @splat(byte);
}

fn expectSameRows(a: *const FamilyState, b: *const FamilyState) !void {
    try testing.expectEqualStrings(a.family, b.family);
    try testing.expectEqual(a.len(), b.len());
    for (a.entries.items, b.entries.items) |ea, eb| {
        try testing.expectEqualStrings(ea.key, eb.key);
        try testing.expectEqual(ea.version, eb.version);
        try testing.expectEqual(ea.deleted, eb.deleted);
        try testing.expectEqualSlices(u8, &ea.value_hash, &eb.value_hash);
    }
}

fn expectSameRoot(a: *const FamilyState, b: *const FamilyState) !void {
    const da = try digestRows(testing.allocator, a.family, a.entries.items);
    const db = try digestRows(testing.allocator, b.family, b.entries.items);
    try testing.expectEqualSlices(u8, &da.root, &db.root);
}

fn expectFullRepair(decision: *const Decision, reason: FullRepairReason) !void {
    try testing.expect(decision.* == .full_repair);
    try testing.expectEqual(reason, decision.full_repair);
}

fn putBackground(state: *FamilyState, prefix: []const u8, count: u64) !void {
    var i: u64 = 0;
    while (i < count) : (i += 1) {
        var key_buf: [32]u8 = undefined;
        const key = try std.fmt.bufPrint(&key_buf, "{s}{d}", .{ prefix, i });
        try state.put(key, i, makeHash(@truncate(i)), false);
    }
}

fn entryKeyLessThan(_: void, a: Entry, b: Entry) bool {
    return std.mem.order(u8, a.key, b.key) == .lt;
}

/// `putBackground` for large families: append then sort once instead of
/// paying an O(n) insert per row. `state` must hold no `prefix` keys yet.
fn fillSorted(state: *FamilyState, prefix: []const u8, count: usize) !void {
    try state.entries.ensureUnusedCapacity(state.allocator, count);
    for (0..count) |i| {
        var key_buf: [32]u8 = undefined;
        const key = try state.allocator.dupe(u8, try std.fmt.bufPrint(&key_buf, "{s}{d}", .{ prefix, i }));
        state.entries.appendAssumeCapacity(.{ .key = key, .version = i, .value_hash = makeHash(@truncate(i)), .deleted = false });
    }
    std.mem.sort(Entry, state.entries.items, {}, entryKeyLessThan);
}

fn summaryBytes(allocator: Allocator, families: []const FamilyState) ![]u8 {
    var summary = try buildSummary(allocator, families);
    defer summary.deinit();
    return encodeSummary(allocator, &summary);
}

fn singleUnit(family: []const u8, key: []const u8) UnitMask {
    var mask: UnitMask = .empty;
    mask.set(unitIndex(family, key));
    return mask;
}

/// Encode, decode and apply every frame through the real wire codec.
/// Returns the first escalation, if any.
fn shipFrames(allocator: Allocator, frames: []const FamilyDelta, dst: *FamilyState) !?FullRepairReason {
    for (frames) |*frame| {
        try testing.expect(frame.entries.len <= max_delta_entries);
        const wire = try encodeDelta(allocator, frame);
        defer allocator.free(wire);
        try testing.expect(wire.len <= max_delta_wire_len);
        var received = try decodeDelta(allocator, wire);
        defer received.deinit();
        if (try applyDeltaOrEscalate(dst, &received)) |reason| return reason;
    }
    return null;
}

const ExchangeResult = enum { in_sync, delta_applied, delta_refined, full_repair };

/// One direction of the ladder over the real wire codecs: `src` plans
/// against `dst`'s encoded summary, refines with `dst`'s encoded detail when
/// asked, then every planned frame is encoded, decoded, and applied onto
/// `dst`.
fn exchangeOneWay(allocator: Allocator, src: *const FamilyState, dst: *FamilyState, budget: Budget) !ExchangeResult {
    const dst_bytes = try summaryBytes(allocator, &.{dst.*});
    defer allocator.free(dst_bytes);

    var decision = try plan(allocator, &.{src.*}, dst_bytes, budget);
    defer decision.deinit();
    switch (decision) {
        .in_sync => return .in_sync,
        .full_repair => return .full_repair,
        .delta => |*d| {
            try testing.expectEqual(@as(usize, 1), d.families.len);
            const fp = &d.families[0];
            const refined = fp.needs_detail;
            if (refined) {
                var detail = try buildDetail(allocator, dst, fp.buckets);
                defer detail.deinit();
                const detail_bytes = try encodeDetail(allocator, &detail);
                defer allocator.free(detail_bytes);
                switch (try refine(allocator, src, fp, detail_bytes, budget)) {
                    .delta => try testing.expect(!fp.needs_detail),
                    .in_sync => return .in_sync,
                    .full_repair => return .full_repair,
                }
            }
            var frames = try buildDelta(allocator, src, &fp.units);
            defer frames.deinit();
            var shipped: usize = 0;
            for (frames.frames) |f| shipped += f.entries.len;
            try testing.expectEqual(fp.row_count, shipped);
            if (try shipFrames(allocator, frames.frames, dst)) |_| return .full_repair;
            return if (refined) .delta_refined else .delta_applied;
        },
    }
}

/// Ship `source`'s full snapshot onto `target` through the wire codec.
fn fullRepairFrom(allocator: Allocator, target: *FamilyState, source: *const FamilyState) !usize {
    var frames = try buildFullSnapshot(allocator, source);
    defer frames.deinit();
    var resolved: usize = 0;
    for (frames.frames) |*frame| {
        const wire = try encodeDelta(allocator, frame);
        defer allocator.free(wire);
        try testing.expect(wire.len <= max_delta_wire_len);
        var received = try decodeDelta(allocator, wire);
        defer received.deinit();
        resolved += try fullRepair(target, &received);
    }
    return resolved;
}

const Tally = struct { in_sync: usize = 0, delta: usize = 0, refined: usize = 0, full: usize = 0 };

fn reconcileBothWays(allocator: Allocator, x: *FamilyState, y: *FamilyState, budget: Budget, tally: *Tally) !void {
    for ([_][2]*FamilyState{ .{ y, x }, .{ x, y } }) |pair| {
        switch (try exchangeOneWay(allocator, pair[0], pair[1], budget)) {
            .in_sync => tally.in_sync += 1,
            .delta_applied => tally.delta += 1,
            .delta_refined => {
                tally.delta += 1;
                tally.refined += 1;
            },
            .full_repair => {
                tally.full += 1;
                _ = try fullRepairFrom(allocator, pair[1], pair[0]);
            },
        }
    }
}

test "digest_reconcile: summary encode/decode round-trip is canonical regardless of insertion order" {
    const allocator = testing.allocator;

    var a1 = try FamilyState.init(allocator, "channels");
    defer a1.deinit();
    try a1.put("chan:#ops", 1, makeHash(1), false);
    try a1.put("chan:#dev", 2, makeHash(2), false);
    try a1.put("chan:#qa", 3, makeHash(3), true);

    var a2 = try FamilyState.init(allocator, "channels");
    defer a2.deinit();
    try a2.put("chan:#qa", 3, makeHash(3), true);
    try a2.put("chan:#ops", 1, makeHash(1), false);
    try a2.put("chan:#dev", 2, makeHash(2), false);

    var b1 = try FamilyState.init(allocator, "bans");
    defer b1.deinit();
    try b1.put("ban:1", 9, makeHash(9), false);

    const bytes1 = try summaryBytes(allocator, &.{ a1, b1 });
    defer allocator.free(bytes1);
    const bytes2 = try summaryBytes(allocator, &.{ b1, a2 }); // reversed family order too
    defer allocator.free(bytes2);
    try testing.expectEqualSlices(u8, bytes1, bytes2);

    var decoded = try decodeSummary(allocator, bytes1);
    defer decoded.deinit();
    try testing.expectEqual(@as(usize, 2), decoded.families.len);
    try testing.expectEqualStrings("bans", decoded.families[0].family);
    try testing.expectEqualStrings("channels", decoded.families[1].family);
    try testing.expectEqual(@as(u64, 3), decoded.families[1].entry_count);
    try testing.expectEqual(@as(u64, 1), decoded.families[1].tombstone_count);

    const reencoded = try encodeSummary(allocator, &decoded);
    defer allocator.free(reencoded);
    try testing.expectEqualSlices(u8, bytes1, reencoded);
}

test "digest_reconcile: equal state yields in_sync with zero delta keys" {
    const allocator = testing.allocator;
    var a = try FamilyState.init(allocator, "memberships");
    defer a.deinit();
    try a.put("member:#ops:1", 1, makeHash(1), false);
    try a.put("member:#ops:2", 2, makeHash(2), true);
    var b = try a.clone();
    defer b.deinit();

    const bytes = try summaryBytes(allocator, &.{b});
    defer allocator.free(bytes);
    var decision = try plan(allocator, &.{a}, bytes, .{});
    defer decision.deinit();
    try testing.expect(decision == .in_sync);
    try testing.expectEqual(ExchangeResult.in_sync, try exchangeOneWay(allocator, &a, &b, .{}));
}

test "digest_reconcile: small missing set reconciles via delta with exactly equal roots" {
    const allocator = testing.allocator;
    var a = try FamilyState.init(allocator, "channels");
    defer a.deinit();
    var b = try FamilyState.init(allocator, "channels");
    defer b.deinit();

    // A shared background keeps relative divergence low, so `selectStrategy`
    // picks delta repair rather than its >50%-of-keyspace full resync.
    try putBackground(&a, "chan:#bg", 40);
    try putBackground(&b, "chan:#bg", 40);
    try a.put("chan:#b", 50, makeHash(2), false);
    try a.put("chan:#c", 51, makeHash(3), false);

    try testing.expectEqual(ExchangeResult.delta_applied, try exchangeOneWay(allocator, &a, &b, .{}));
    try expectSameRows(&a, &b);
    try expectSameRoot(&a, &b);
    try testing.expectEqual(ExchangeResult.in_sync, try exchangeOneWay(allocator, &b, &a, .{}));
}

test "digest_reconcile: bidirectional divergence converges by delta in one round without losing writes" {
    const allocator = testing.allocator;
    var a = try FamilyState.init(allocator, "props");
    defer a.deinit();
    var b = try FamilyState.init(allocator, "props");
    defer b.deinit();
    try putBackground(&a, "prop:bg", 40);
    try putBackground(&b, "prop:bg", 40);

    try a.put("prop:only-a", 100, makeHash(0xA1), false);
    try b.put("prop:only-b", 101, makeHash(0xB1), false);
    try a.put("prop:bg3", 200, makeHash(0xA2), false); // a newer on a shared key
    try b.put("prop:bg7", 201, makeHash(0xB2), false); // b newer on another

    var tally: Tally = .{};
    try reconcileBothWays(allocator, &a, &b, .{}, &tally);
    try testing.expectEqual(@as(usize, 2), tally.delta);
    try testing.expectEqual(@as(usize, 0), tally.full);
    try expectSameRows(&a, &b);
    try expectSameRoot(&a, &b);

    // The join kept every side's accepted write.
    try testing.expectEqual(@as(u64, 100), a.get("prop:only-a").?.version);
    try testing.expectEqual(@as(u64, 101), a.get("prop:only-b").?.version);
    try testing.expectEqual(@as(u64, 200), b.get("prop:bg3").?.version);
    try testing.expectEqual(@as(u64, 201), a.get("prop:bg7").?.version);
    try testing.expectEqual(@as(usize, 42), a.len());

    try reconcileBothWays(allocator, &a, &b, .{}, &tally);
    try testing.expectEqual(@as(usize, 2), tally.in_sync);
}

test "digest_reconcile: tombstones converge via delta and are not resurrected by a stale live row" {
    const allocator = testing.allocator;
    var a = try FamilyState.init(allocator, "accounts");
    defer a.deinit();
    var b = try FamilyState.init(allocator, "accounts");
    defer b.deinit();
    try putBackground(&a, "acct:bg", 40);
    try putBackground(&b, "acct:bg", 40);
    try a.put("acct:nick1", 50, makeHash(0), true); // deleted at version 50
    try b.put("acct:nick1", 30, makeHash(3), false); // stale live row from before the delete
    try a.put("acct:nick2", 60, makeHash(0), true); // same-version tie: tombstone wins
    try b.put("acct:nick2", 60, makeHash(6), false);

    // The stale side pushes first: its live rows must not override.
    try testing.expectEqual(ExchangeResult.delta_applied, try exchangeOneWay(allocator, &b, &a, .{}));
    try testing.expect(a.get("acct:nick1").?.deleted);
    try testing.expect(a.get("acct:nick2").?.deleted);

    try testing.expectEqual(ExchangeResult.delta_applied, try exchangeOneWay(allocator, &a, &b, .{}));
    for ([_][]const u8{ "acct:nick1", "acct:nick2" }) |key| {
        try testing.expect(b.get(key).?.deleted);
        try testing.expectEqual(a.get(key).?.version, b.get(key).?.version);
    }
    try expectSameRows(&a, &b);
}

test "digest_reconcile: malformed summaries fall back to full_repair(malformed_summary) without panicking or mutating state" {
    const allocator = testing.allocator;
    var a = try FamilyState.init(allocator, "channels");
    defer a.deinit();
    try a.put("chan:#ops", 1, makeHash(1), false);
    var before = try a.clone();
    defer before.deinit();

    var other = try FamilyState.init(allocator, "channels");
    defer other.deinit();
    try other.put("chan:#dev", 2, makeHash(2), false);
    const good = try summaryBytes(allocator, &.{other});
    defer allocator.free(good);

    const name_len: usize = good[7];
    const entry_off = 8 + name_len;
    const tomb_off = entry_off + 8;
    const Mutation = struct { off: usize, value: u64, width: u8, reason: FullRepairReason, err: anyerror };
    const mutations = [_]Mutation{
        .{ .off = 0, .value = 'X', .width = 1, .reason = .malformed_summary, .err = error.BadMagic },
        .{ .off = 4, .value = 0xFF, .width = 1, .reason = .version_mismatch, .err = error.UnsupportedVersion },
        .{ .off = 4, .value = 1, .width = 1, .reason = .version_mismatch, .err = error.UnsupportedVersion },
        .{ .off = 5, .value = max_families + 1, .width = 2, .reason = .malformed_summary, .err = error.TooManyFamilies },
        .{ .off = 5, .value = 2, .width = 2, .reason = .malformed_summary, .err = error.Truncated },
        .{ .off = 7, .value = 0, .width = 1, .reason = .malformed_summary, .err = error.EmptyFamilyName },
        .{ .off = 7, .value = max_family_name_len + 1, .width = 1, .reason = .malformed_summary, .err = error.FamilyNameTooLong },
        .{ .off = entry_off, .value = max_family_entries + 1, .width = 8, .reason = .malformed_summary, .err = error.CountOverflow },
        .{ .off = tomb_off, .value = 999, .width = 8, .reason = .malformed_summary, .err = error.InconsistentCounts },
        // Forged count with an unchanged root: the root no longer binds it.
        .{ .off = entry_off, .value = 7, .width = 8, .reason = .malformed_summary, .err = error.RootMismatch },
        // A flipped root byte and a flipped bucket byte.
        .{ .off = tomb_off + 8, .value = good[tomb_off + 8] ^ 1, .width = 1, .reason = .malformed_summary, .err = error.RootMismatch },
        .{ .off = tomb_off + 8 + 32, .value = good[tomb_off + 8 + 32] ^ 1, .width = 1, .reason = .malformed_summary, .err = error.RootMismatch },
    };
    for (mutations) |m| {
        const bad = try allocator.dupe(u8, good);
        defer allocator.free(bad);
        switch (m.width) {
            1 => bad[m.off] = @intCast(m.value),
            2 => std.mem.writeInt(u16, bad[m.off..][0..2], @intCast(m.value), .little),
            else => std.mem.writeInt(u64, bad[m.off..][0..8], m.value, .little),
        }
        try testing.expectError(m.err, decodeSummary(allocator, bad));
        var decision = try plan(allocator, &.{a}, bad, .{});
        defer decision.deinit();
        try expectFullRepair(&decision, m.reason);
    }

    // Every strict prefix is truncated; one trailing byte is rejected.
    for (0..good.len) |cut| {
        try testing.expect(std.meta.isError(decodeSummary(allocator, good[0..cut])));
        var decision = try plan(allocator, &.{a}, good[0..cut], .{});
        defer decision.deinit();
        try testing.expect(decision == .full_repair);
    }
    const padded = try std.mem.concat(allocator, u8, &.{ good, "x" });
    defer allocator.free(padded);
    try testing.expectError(error.TrailingBytes, decodeSummary(allocator, padded));

    // Family-set disagreement is reported per family, never escalated.
    var renamed = try FamilyState.init(allocator, "chanmodes");
    defer renamed.deinit();
    const renamed_bytes = try summaryBytes(allocator, &.{renamed});
    defer allocator.free(renamed_bytes);
    var mismatch = try plan(allocator, &.{a}, renamed_bytes, .{});
    defer mismatch.deinit();
    try testing.expect(mismatch == .delta);
    try testing.expectEqual(@as(usize, 0), mismatch.delta.families.len);
    try testing.expectEqual(@as(usize, 2), mismatch.delta.one_sided.len);
    try testing.expectEqualStrings("chanmodes", mismatch.delta.one_sided[0].family);
    try testing.expectEqual(OneSided.Side.remote_only, mismatch.delta.one_sided[0].side);
    try testing.expectEqual(OneSided.Side.local_only, mismatch.delta.one_sided[1].side);

    try expectSameRows(&before, &a);
}

test "digest_reconcile: family-set difference keeps shared families on digest and delta (mixed-version mesh)" {
    const allocator = testing.allocator;
    // Upgraded node tracks [channels, nicks]; the older peer tracks [channels]
    // with byte-identical channels state.
    var channels = try FamilyState.init(allocator, "channels");
    defer channels.deinit();
    try putBackground(&channels, "#c", 200);
    var nicks = try FamilyState.init(allocator, "nicks");
    defer nicks.deinit();
    try putBackground(&nicks, "n", 50);
    var peer_channels = try channels.clone();
    defer peer_channels.deinit();

    const peer_bytes = try summaryBytes(allocator, &.{peer_channels});
    defer allocator.free(peer_bytes);
    for (0..2) |_| {
        // Two rounds with unchanged state: channels is never planned and the
        // decision never escalates to a full snapshot.
        var decision = try plan(allocator, &.{ channels, nicks }, peer_bytes, .{});
        defer decision.deinit();
        try testing.expect(decision == .delta);
        try testing.expectEqual(@as(usize, 0), decision.delta.families.len);
        try testing.expectEqual(@as(usize, 1), decision.delta.one_sided.len);
        try testing.expectEqualStrings("nicks", decision.delta.one_sided[0].family);
        try testing.expectEqual(OneSided.Side.local_only, decision.delta.one_sided[0].side);
    }

    // One divergent shared row still plans exactly that family by delta,
    // with the one-sided family reported alongside.
    try peer_channels.put("#c7", 99, makeHash(0xEE), false);
    const diverged = try summaryBytes(allocator, &.{peer_channels});
    defer allocator.free(diverged);
    var decision = try plan(allocator, &.{ channels, nicks }, diverged, .{});
    defer decision.deinit();
    try testing.expect(decision == .delta);
    try testing.expectEqual(@as(usize, 1), decision.delta.families.len);
    try testing.expectEqualStrings("channels", decision.delta.families[0].family);
    try testing.expectEqual(@as(usize, 1), decision.delta.one_sided.len);

    // The reverse direction: the older side sees "nicks" as remote-only and
    // its identical channels family stays in sync.
    const upgraded_bytes = try summaryBytes(allocator, &.{ channels, nicks });
    defer allocator.free(upgraded_bytes);
    var reverse = try plan(allocator, &.{channels}, upgraded_bytes, .{});
    defer reverse.deinit();
    try testing.expect(reverse == .delta);
    try testing.expectEqual(@as(usize, 0), reverse.delta.families.len);
    try testing.expectEqual(OneSided.Side.remote_only, reverse.delta.one_sided[0].side);

    // Allocation failure at every point leaves no leak and never a
    // partially built decision.
    var fail_index: usize = 0;
    while (true) : (fail_index += 1) {
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = fail_index });
        var attempt = plan(failing.allocator(), &.{ channels, nicks }, diverged, .{}) catch |err| {
            try testing.expectEqual(error.OutOfMemory, err);
            continue;
        };
        attempt.deinit();
        break;
    }
}

test "digest_reconcile: bulk append then normalize is order independent" {
    const allocator = testing.allocator;
    var forward = try FamilyState.init(allocator, "topics");
    defer forward.deinit();
    var backward = try FamilyState.init(allocator, "topics");
    defer backward.deinit();
    const keys = [_][]const u8{ "#b", "#a", "#c", "#a" };
    for (keys, 0..) |k, i| try forward.appendUnsorted(k, i, makeHash(@intCast(i)), false);
    var i: usize = keys.len;
    while (i > 0) {
        i -= 1;
        try backward.appendUnsorted(keys[i], i, makeHash(@intCast(i)), false);
    }
    // The two "#a" rows differ, so both report a conflicting duplicate.
    try testing.expect(!forward.normalize());
    try testing.expect(!backward.normalize());
    try testing.expectEqual(@as(usize, 3), forward.len());
    // Duplicate "#a" collapses to the greater row (version 3).
    try testing.expectEqual(@as(u64, 3), forward.get("#a").?.version);
    try expectSameRows(&forward, &backward);
    try expectSameRoot(&forward, &backward);

    // Byte-identical duplicates collapse without a conflict.
    var same = try FamilyState.init(allocator, "topics");
    defer same.deinit();
    try same.appendUnsorted("#x", 1, makeHash(1), false);
    try same.appendUnsorted("#x", 1, makeHash(1), false);
    try testing.expect(same.normalize());
    try testing.expectEqual(@as(usize, 1), same.len());
}

test "digest_reconcile: self-consistent summary with forged counts and matching buckets is rejected" {
    const allocator = testing.allocator;
    var a = try FamilyState.init(allocator, "nicks");
    defer a.deinit();
    try a.put("nick:x", 1, makeHash(1), false);

    // A hostile peer copies our buckets but advertises different counts and
    // recomputes the root over them, which passes the decode root check.
    var forged = try a.digest();
    defer forged.deinit(allocator);
    forged.entry_count = 9;
    forged.root = familyRootHash(forged.family, forged.entry_count, forged.tombstone_count, &forged.buckets);
    var list = [_]FamilyDigest{forged};
    const summary = Summary{ .allocator = allocator, .families = &list };
    const bytes = try encodeSummary(allocator, &summary);
    defer allocator.free(bytes);

    var decision = try plan(allocator, &.{a}, bytes, .{});
    defer decision.deinit();
    try expectFullRepair(&decision, .malformed_summary);
}

test "digest_reconcile: unsorted and duplicate family summaries are rejected" {
    const allocator = testing.allocator;
    var a = try FamilyState.init(allocator, "aaa");
    defer a.deinit();
    try a.put("k", 1, makeHash(1), false);
    var b = try FamilyState.init(allocator, "bbb");
    defer b.deinit();
    try b.put("k", 1, makeHash(1), false);

    const bytes = try summaryBytes(allocator, &.{ a, b }); // sorted: aaa, bbb
    defer allocator.free(bytes);

    // Swap the two equal-length encoded family bodies.
    const mutable = try allocator.dupe(u8, bytes);
    defer allocator.free(mutable);
    const header_len: usize = 4 + 1 + 2;
    const body_len = (bytes.len - header_len) / 2;
    @memcpy(mutable[header_len..][0..body_len], bytes[header_len + body_len ..]);
    @memcpy(mutable[header_len + body_len ..], bytes[header_len..][0..body_len]);
    try testing.expectError(error.UnsortedFamilies, decodeSummary(allocator, mutable));
    var decision = try plan(allocator, &.{ a, b }, mutable, .{});
    defer decision.deinit();
    try expectFullRepair(&decision, .malformed_summary);

    // Duplicate family name: encode "aaa" twice.
    var fa = try a.digest();
    defer fa.deinit(allocator);
    var fa2 = try a.digest();
    defer fa2.deinit(allocator);
    var dup_list = [_]FamilyDigest{ fa, fa2 };
    const dup_summary = Summary{ .allocator = allocator, .families = &dup_list };
    const dup_bytes = try encodeSummary(allocator, &dup_summary);
    defer allocator.free(dup_bytes);
    try testing.expectError(error.DuplicateFamily, decodeSummary(allocator, dup_bytes));

    try testing.expectError(error.DuplicateFamily, buildSummary(allocator, &.{ a, a }));
}

test "digest_reconcile: equivocation falls back to full_repair(equivocation) and full repair converges deterministically" {
    const allocator = testing.allocator;
    var a = try FamilyState.init(allocator, "props");
    defer a.deinit();
    var b = try FamilyState.init(allocator, "props");
    defer b.deinit();
    try putBackground(&a, "prop:bg", 40);
    try putBackground(&b, "prop:bg", 40);
    try a.put("prop:1", 70, makeHash(0xAA), false);
    try b.put("prop:1", 70, makeHash(0xBB), false); // same key+version, different content

    var a_before = try a.clone();
    defer a_before.deinit();
    var b_before = try b.clone();
    defer b_before.deinit();

    try testing.expectEqual(ExchangeResult.full_repair, try exchangeOneWay(allocator, &a, &b, .{}));
    try testing.expectEqual(ExchangeResult.full_repair, try exchangeOneWay(allocator, &b, &a, .{}));
    try expectSameRows(&a_before, &a);
    try expectSameRows(&b_before, &b);

    var direct = try buildFullSnapshot(allocator, &a);
    defer direct.deinit();
    try testing.expectEqual(@as(usize, 1), direct.frames.len);
    try testing.expectError(error.Equivocation, applyDelta(&b, &direct.frames[0]));
    try testing.expectEqual(FullRepairReason.equivocation, (try applyDeltaOrEscalate(&b, &direct.frames[0])).?);
    try expectSameRows(&b_before, &b);

    // Full repair in both directions picks the same winner on both sides.
    try testing.expectEqual(@as(usize, 1), try fullRepairFrom(allocator, &b, &a));
    try testing.expectEqual(@as(usize, 1), try fullRepairFrom(allocator, &a, &b));
    try expectSameRows(&a, &b);
    try testing.expectEqualSlices(u8, &makeHash(0xBB), &a.get("prop:1").?.value_hash);
}

test "digest_reconcile: divergence above budget at unit resolution falls back to full_repair(too_divergent) and full repair converges exactly" {
    const allocator = testing.allocator;
    var a = try FamilyState.init(allocator, "history");
    defer a.deinit();
    var b = try FamilyState.init(allocator, "history");
    defer b.deinit();
    try putBackground(&a, "k", 40);
    try b.put("only-b", 5, makeHash(5), true);
    const budget: Budget = .{ .cfg = anti_entropy.StrategyConfig.init(2, 8) };

    const bytes_b = try summaryBytes(allocator, &.{b});
    defer allocator.free(bytes_b);
    var decision = try plan(allocator, &.{a}, bytes_b, budget);
    defer decision.deinit();
    try testing.expect(decision == .delta);
    const fp = &decision.delta.families[0];
    try testing.expect(fp.needs_detail);

    var detail = try buildDetail(allocator, &b, fp.buckets);
    defer detail.deinit();
    const detail_bytes = try encodeDetail(allocator, &detail);
    defer allocator.free(detail_bytes);
    const units_before = fp.units;
    const outcome = try refine(allocator, &a, fp, detail_bytes, budget);
    try testing.expect(outcome == .full_repair);
    try testing.expectEqual(FullRepairReason.too_divergent, outcome.full_repair);
    try testing.expect(fp.needs_detail); // untouched on escalation
    try testing.expect(fp.units.eql(units_before));
    try testing.expectEqual(ExchangeResult.full_repair, try exchangeOneWay(allocator, &a, &b, budget));

    _ = try fullRepairFrom(allocator, &b, &a);
    _ = try fullRepairFrom(allocator, &a, &b);
    try expectSameRows(&a, &b);
    try expectSameRoot(&a, &b);
    try testing.expectEqual(@as(usize, 41), b.len());
    try testing.expect(a.get("only-b").?.deleted);
}

test "digest_reconcile: tampered delta whose post-apply root mismatches expected digest yields post_apply_divergence and rolls back" {
    const allocator = testing.allocator;
    var src = try FamilyState.init(allocator, "wards");
    defer src.deinit();
    try putBackground(&src, "ward:", 20);
    var dst = try FamilyState.init(allocator, "wards");
    defer dst.deinit();
    try dst.put("ward:1", 1, makeHash(1), false);
    var before = try dst.clone();
    defer before.deinit();

    const Tamper = enum { row_hash, row_version, row_flag, attested_root, attested_bucket, unit_root, drop_row };
    for (std.meta.tags(Tamper)) |tamper| {
        var frames = try buildFullSnapshot(allocator, &src);
        defer frames.deinit();
        const delta = &frames.frames[0];
        switch (tamper) {
            .row_hash => delta.entries[0].value_hash[0] ^= 1,
            .row_version => delta.entries[1].version += 1,
            .row_flag => delta.entries[2].deleted = true,
            .attested_root => delta.expected_root = makeHash(0xEE),
            .attested_bucket => delta.sender_buckets[0][0] ^= 1,
            .unit_root => delta.parts[0].sub_roots[0][0] ^= 1,
            .drop_row => {
                allocator.free(delta.entries[delta.entries.len - 1].key);
                delta.entries = try allocator.realloc(delta.entries, delta.entries.len - 1);
            },
        }
        try testing.expectError(error.DigestMismatch, applyDelta(&dst, delta));
        try testing.expectEqual(FullRepairReason.post_apply_divergence, (try applyDeltaOrEscalate(&dst, delta)).?);
        try testing.expectError(error.DigestMismatch, fullRepair(&dst, delta));
        try expectSameRows(&before, &dst);
    }
}

test "digest_reconcile: structurally hostile in-memory deltas escalate as malformed_delta" {
    const allocator = testing.allocator;
    var src = try FamilyState.init(allocator, "chanprops");
    defer src.deinit();
    try putBackground(&src, "cp:", 30);
    var dst = try FamilyState.init(allocator, "chanprops");
    defer dst.deinit();
    var before = try dst.clone();
    defer before.deinit();

    const Hostile = enum { family, unsorted_keys, duplicate_key, empty_parts, bucket_range, unsorted_parts, zero_mask, key_outside, counts };
    for (std.meta.tags(Hostile)) |hostile| {
        var frames = try buildFullSnapshot(allocator, &src);
        defer frames.deinit();
        const delta = &frames.frames[0];
        switch (hostile) {
            .family => delta.family[0] = 'X',
            .unsorted_keys => std.mem.swap(Entry, &delta.entries[0], &delta.entries[1]),
            .duplicate_key => {
                allocator.free(delta.entries[1].key);
                delta.entries[1].key = try allocator.dupe(u8, delta.entries[0].key);
            },
            .empty_parts => delta.parts = try allocator.realloc(delta.parts, 0),
            .bucket_range => delta.parts[delta.parts.len - 1].bucket = num_buckets,
            .unsorted_parts => std.mem.swap(DeltaPart, &delta.parts[0], &delta.parts[1]),
            .zero_mask => delta.parts[0].sub_mask = 0,
            .key_outside => {
                // Drop the first row's unit from its part's mask.
                const unit = unitIndex(delta.family, delta.entries[0].key);
                const part = &delta.parts[unit / subs_per_bucket];
                part.sub_mask &= ~(@as(u64, 1) << @intCast(unit % subs_per_bucket));
            },
            .counts => delta.sender_tombstone_count = delta.sender_entry_count + 1,
        }
        const reason = (try applyDeltaOrEscalate(&dst, delta)).?;
        try testing.expectEqual(FullRepairReason.malformed_delta, reason);
        try testing.expect(std.meta.isError(fullRepair(&dst, delta)));
        try expectSameRows(&before, &dst);
    }
    const empty: UnitMask = .empty;
    try testing.expectError(error.EmptyUnits, buildDelta(allocator, &src, &empty));
    try testing.expectError(error.InvalidBuckets, buildDetail(allocator, &src, &.{}));
    try testing.expectError(error.InvalidBuckets, buildDetail(allocator, &src, &.{ 3, 3 }));
    try testing.expectError(error.InvalidBuckets, buildDetail(allocator, &src, &.{num_buckets}));
}

test "digest_reconcile: delta wire codec round-trips and rejects hostile encodings" {
    const allocator = testing.allocator;
    var src = try FamilyState.init(allocator, "topics");
    defer src.deinit();
    try putBackground(&src, "topic:#", 12);
    try src.put("topic:#gone", 99, makeHash(0), true);
    _ = src.gcTombstones(5); // a floor rides the wire too

    var frames = try buildFullSnapshot(allocator, &src);
    defer frames.deinit();
    try testing.expectEqual(@as(usize, 1), frames.frames.len);
    const delta = &frames.frames[0];
    try testing.expectEqual(@as(usize, num_buckets), delta.parts.len);
    const wire = try encodeDelta(allocator, delta);
    defer allocator.free(wire);
    var round = try decodeDelta(allocator, wire);
    defer round.deinit();
    try testing.expectEqual(@as(?u64, 5), round.sender_gc_floor);
    const again = try encodeDelta(allocator, &round);
    defer allocator.free(again);
    try testing.expectEqualSlices(u8, wire, again);

    var dst = try FamilyState.init(allocator, "topics");
    defer dst.deinit();
    try applyDelta(&dst, &round);
    try expectSameRows(&src, &dst);

    const name_len: usize = wire[5];
    const digest_off = 6 + name_len;
    const floor_off = digest_off + digest_body_len;
    const part_count_off = floor_off + floor_len;
    const first_part_off = part_count_off + 1;

    // Every cut outside the fixed-size unit-root block, and a prime stride
    // through it, is truncated.
    var cut: usize = 0;
    while (cut < wire.len) : (cut += if (cut < first_part_off or cut + delta_part_len >= wire.len) 1 else 97) {
        try testing.expect(std.meta.isError(decodeDelta(allocator, wire[0..cut])));
    }
    const padded = try std.mem.concat(allocator, u8, &.{ wire, "\x00" });
    defer allocator.free(padded);
    try testing.expectError(error.TrailingBytes, decodeDelta(allocator, padded));

    const second_part_off = first_part_off + delta_part_len;
    const last_part_off = first_part_off + (num_buckets - 1) * delta_part_len;
    const entry_count_off = first_part_off + num_buckets * delta_part_len;
    const first_entry_off = entry_count_off + 2;
    const first_key_len: usize = std.mem.readInt(u16, wire[first_entry_off..][0..2], .little);
    const first_flag_off = first_entry_off + 2 + first_key_len + 8;
    const Mutation = struct { off: usize, value: u64, width: u8, err: anyerror };
    const mutations = [_]Mutation{
        .{ .off = 0, .value = 'Z', .width = 1, .err = error.BadMagic },
        .{ .off = 4, .value = 9, .width = 1, .err = error.UnsupportedVersion },
        .{ .off = 5, .value = 0, .width = 1, .err = error.EmptyFamilyName },
        .{ .off = digest_off + 16, .value = wire[digest_off + 16] ^ 1, .width = 1, .err = error.RootMismatch },
        .{ .off = floor_off, .value = 2, .width = 1, .err = error.BadFlag },
        .{ .off = floor_off, .value = 0, .width = 1, .err = error.BadFlag }, // absent floor with a nonzero value
        .{ .off = part_count_off, .value = 0, .width = 1, .err = error.InvalidBuckets },
        .{ .off = part_count_off, .value = num_buckets + 1, .width = 1, .err = error.InvalidBuckets },
        .{ .off = second_part_off, .value = 0, .width = 1, .err = error.InvalidBuckets },
        .{ .off = last_part_off, .value = num_buckets, .width = 1, .err = error.InvalidBuckets },
        .{ .off = first_part_off + 1, .value = 0, .width = 8, .err = error.InvalidBuckets },
        .{ .off = entry_count_off, .value = max_delta_entries + 1, .width = 2, .err = error.TooManyEntries },
        .{ .off = entry_count_off, .value = 14, .width = 2, .err = error.InconsistentCounts },
        .{ .off = first_entry_off, .value = max_key_len + 1, .width = 2, .err = error.KeyTooLong },
        .{ .off = first_flag_off, .value = 2, .width = 1, .err = error.BadFlag },
    };
    for (mutations) |m| {
        const bad = try allocator.dupe(u8, wire);
        defer allocator.free(bad);
        switch (m.width) {
            1 => bad[m.off] = @intCast(m.value),
            2 => std.mem.writeInt(u16, bad[m.off..][0..2], @intCast(m.value), .little),
            else => std.mem.writeInt(u64, bad[m.off..][0..8], m.value, .little),
        }
        try testing.expectError(m.err, decodeDelta(allocator, bad));
    }

    // Unsorted keys: swap the first two equal-length rows on the wire.
    {
        const row_len = 2 + first_key_len + 8 + 1 + 32;
        const second_key_len: usize = std.mem.readInt(u16, wire[first_entry_off + row_len ..][0..2], .little);
        try testing.expectEqual(first_key_len, second_key_len);
        const bad = try allocator.dupe(u8, wire);
        defer allocator.free(bad);
        @memcpy(bad[first_entry_off..][0..row_len], wire[first_entry_off + row_len ..][0..row_len]);
        @memcpy(bad[first_entry_off + row_len ..][0..row_len], wire[first_entry_off..][0..row_len]);
        try testing.expectError(error.UnsortedKeys, decodeDelta(allocator, bad));
    }
    // A key outside the advertised units.
    {
        const mask = singleUnit(src.family, "topic:#0");
        var narrow = try buildDelta(allocator, &src, &mask);
        defer narrow.deinit();
        const part = &narrow.frames[0].parts[0];
        part.sub_mask = std.math.rotl(u64, part.sub_mask, 1);
        const narrow_wire = try encodeDelta(allocator, &narrow.frames[0]);
        defer allocator.free(narrow_wire);
        try testing.expectError(error.KeyOutsideUnits, decodeDelta(allocator, narrow_wire));
    }
    // Encode bounds fail closed instead of narrowing a length prefix.
    {
        const long_key = try allocator.alloc(u8, max_key_len + 1);
        @memset(long_key, 'k');
        allocator.free(delta.entries[0].key);
        delta.entries[0].key = long_key;
        try testing.expectError(error.KeyTooLong, encodeDelta(allocator, delta));
    }
}

test "digest_reconcile: detail wire codec round-trips, binds unit roots, and refine rejects mismatched answers" {
    const allocator = testing.allocator;
    var a = try FamilyState.init(allocator, "lists");
    defer a.deinit();
    try putBackground(&a, "l:", 300);
    var b = try a.clone();
    defer b.deinit();
    try a.put("l:7", 900, makeHash(0x77), false);
    // A threshold low enough that the bucket-coarse plan needs detail.
    const budget: Budget = .{ .cfg = anti_entropy.StrategyConfig.init(1, 3) };

    const bytes_b = try summaryBytes(allocator, &.{b});
    defer allocator.free(bytes_b);
    var decision = try plan(allocator, &.{a}, bytes_b, budget);
    defer decision.deinit();
    const fp = &decision.delta.families[0];
    try testing.expect(fp.needs_detail);
    try testing.expectEqualSlices(u8, &.{bucketIndex(a.family, "l:7")}, fp.buckets);

    var detail = try buildDetail(allocator, &b, fp.buckets);
    defer detail.deinit();
    const wire = try encodeDetail(allocator, &detail);
    defer allocator.free(wire);
    var round = try decodeDetail(allocator, wire);
    defer round.deinit();
    const again = try encodeDetail(allocator, &round);
    defer allocator.free(again);
    try testing.expectEqualSlices(u8, wire, again);

    for (0..wire.len) |cut| try testing.expect(std.meta.isError(decodeDetail(allocator, wire[0..cut])));
    const padded = try std.mem.concat(allocator, u8, &.{ wire, "\x00" });
    defer allocator.free(padded);
    try testing.expectError(error.TrailingBytes, decodeDetail(allocator, padded));

    const count_off = 6 + a.family.len + digest_body_len;
    const Mutation = struct { off: usize, value: u8, err: anyerror, reason: FullRepairReason };
    const mutations = [_]Mutation{
        .{ .off = 0, .value = 'Q', .err = error.BadMagic, .reason = .malformed_summary },
        .{ .off = 4, .value = 1, .err = error.UnsupportedVersion, .reason = .version_mismatch },
        .{ .off = count_off, .value = 0, .err = error.InvalidBuckets, .reason = .malformed_summary },
        .{ .off = count_off + 1, .value = num_buckets, .err = error.InvalidBuckets, .reason = .malformed_summary },
        .{ .off = count_off + 2, .value = wire[count_off + 2] ^ 1, .err = error.RootMismatch, .reason = .malformed_summary },
    };
    for (mutations) |m| {
        const bad = try allocator.dupe(u8, wire);
        defer allocator.free(bad);
        bad[m.off] = m.value;
        try testing.expectError(m.err, decodeDetail(allocator, bad));
        const outcome = try refine(allocator, &a, fp, bad, budget);
        try testing.expect(outcome == .full_repair);
        try testing.expectEqual(m.reason, outcome.full_repair);
        try testing.expect(fp.needs_detail);
    }

    // A well-formed answer for the wrong buckets or family is rejected.
    {
        const other_bucket: u8 = if (fp.buckets[0] == 0) 1 else 0;
        var wrong = try buildDetail(allocator, &b, &.{other_bucket});
        defer wrong.deinit();
        const wrong_bytes = try encodeDetail(allocator, &wrong);
        defer allocator.free(wrong_bytes);
        const outcome = try refine(allocator, &a, fp, wrong_bytes, budget);
        try testing.expectEqual(FullRepairReason.malformed_summary, outcome.full_repair);

        var renamed = try FamilyState.init(allocator, "lists2");
        defer renamed.deinit();
        var foreign = try buildDetail(allocator, &renamed, fp.buckets);
        defer foreign.deinit();
        const foreign_bytes = try encodeDetail(allocator, &foreign);
        defer allocator.free(foreign_bytes);
        const outcome2 = try refine(allocator, &a, fp, foreign_bytes, budget);
        try testing.expectEqual(FullRepairReason.malformed_summary, outcome2.full_repair);
    }
    // A detail taken after the peer caught up reports nothing to ship.
    {
        var caught_up = try a.clone();
        defer caught_up.deinit();
        var same = try buildDetail(allocator, &caught_up, fp.buckets);
        defer same.deinit();
        const same_bytes = try encodeDetail(allocator, &same);
        defer allocator.free(same_bytes);
        try testing.expect(try refine(allocator, &a, fp, same_bytes, budget) == .in_sync);
        try testing.expect(fp.needs_detail);
    }

    // The genuine answer narrows the plan to exactly the changed unit.
    try testing.expect(try refine(allocator, &a, fp, wire, budget) == .delta);
    try testing.expect(!fp.needs_detail);
    try testing.expectEqual(@as(usize, 1), fp.units.count());
    try testing.expect(fp.units.isSet(unitIndex(a.family, "l:7")));
}

test "digest_reconcile: replayed stale delta is idempotent and cannot roll state back" {
    const allocator = testing.allocator;
    var src = try FamilyState.init(allocator, "modes");
    defer src.deinit();
    try putBackground(&src, "mode:", 30);
    try src.put("mode:x", 10, makeHash(10), false);

    var old_frames = try buildFullSnapshot(allocator, &src);
    defer old_frames.deinit();
    const old_delta = &old_frames.frames[0];

    var dst = try FamilyState.init(allocator, "modes");
    defer dst.deinit();
    try applyDelta(&dst, old_delta);
    try applyDelta(&dst, old_delta); // exact replay: no change
    try expectSameRows(&src, &dst);

    try src.put("mode:x", 20, makeHash(0), true);
    var new_frames = try buildFullSnapshot(allocator, &src);
    defer new_frames.deinit();
    try applyDelta(&dst, &new_frames.frames[0]);
    try applyDelta(&dst, old_delta); // stale replay after the newer state
    try testing.expect(dst.get("mode:x").?.deleted);
    try testing.expectEqual(@as(u64, 20), dst.get("mode:x").?.version);
    try expectSameRows(&src, &dst);
}

test "digest_reconcile: tombstone GC below stability watermark keeps roots equal across replicas" {
    const allocator = testing.allocator;
    var a = try FamilyState.init(allocator, "nicks");
    defer a.deinit();
    try a.put("nick:bob", 10, makeHash(10), true);
    try a.put("nick:alice", 20, makeHash(20), false);
    try a.put("nick:carol", 30, makeHash(30), true);
    var b = try a.clone();
    defer b.deinit();

    const watermark: u64 = 15; // covers bob's tombstone, not alice (live) or carol (newer)
    try testing.expectEqual(@as(usize, 1), a.gcTombstones(watermark));
    try testing.expectEqual(@as(usize, 1), b.gcTombstones(watermark));
    try expectSameRoot(&a, &b);
    try testing.expect(a.get("nick:bob") == null);
    try testing.expect(a.get("nick:alice") != null);
    try testing.expect(a.get("nick:carol").?.deleted);
    try testing.expectEqual(@as(usize, 0), a.gcTombstones(watermark));
    try testing.expectEqual(@as(?u64, 15), a.gc_floor);
    _ = a.gcTombstones(4); // the floor never moves backwards
    try testing.expectEqual(@as(?u64, 15), a.gc_floor);
}

test "digest_reconcile: GC floor keeps a collected delete from being resurrected by a partitioned peer or a late frame" {
    const allocator = testing.allocator;
    var a = try FamilyState.init(allocator, "nicks");
    defer a.deinit();
    try putBackground(&a, "nick:bg", 40);
    try a.put("nick:k", 10, makeHash(0x10), false);
    var b = try a.clone();
    defer b.deinit();
    var c = try a.clone(); // partitioned before the delete
    defer c.deinit();

    // A frame C built before the partition, delivered late.
    const k_unit = singleUnit(c.family, "nick:k");
    var late = try buildDelta(allocator, &c, &k_unit);
    defer late.deinit();

    try a.put("nick:k", 20, makeHash(0), true);
    try b.put("nick:k", 20, makeHash(0), true);
    // Watermark over live {A, B} only: C never saw the delete.
    try testing.expectEqual(@as(usize, 1), a.gcTombstones(20));
    try testing.expectEqual(@as(usize, 1), b.gcTombstones(20));
    try testing.expect(a.get("nick:k") == null);
    // C keeps writing above the floor while partitioned; that must survive.
    try c.put("nick:fresh", 30, makeHash(0x30), false);

    // The late frame cannot resurrect the collected row.
    try testing.expectEqual(@as(?FullRepairReason, null), try shipFrames(allocator, late.frames, &a));
    try testing.expect(a.get("nick:k") == null);

    var tally: Tally = .{};
    try reconcileBothWays(allocator, &c, &a, .{}, &tally);
    try reconcileBothWays(allocator, &c, &b, .{}, &tally);
    try reconcileBothWays(allocator, &a, &b, .{}, &tally);
    try testing.expectEqual(@as(usize, 0), tally.full);
    try testing.expect(tally.delta >= 2);
    for ([_]*const FamilyState{ &a, &b, &c }) |n| {
        try testing.expect(n.get("nick:k") == null);
        try testing.expectEqual(@as(u64, 30), n.get("nick:fresh").?.version);
    }
    try expectSameRows(&a, &b);
    try expectSameRows(&a, &c);
    try expectSameRoot(&a, &c);

    // Healing C first and then replaying its late frame changes nothing.
    try testing.expectEqual(@as(?FullRepairReason, null), try shipFrames(allocator, late.frames, &b));
    try testing.expect(b.get("nick:k") == null);
    const before = tally;
    try reconcileBothWays(allocator, &c, &a, .{}, &tally);
    try reconcileBothWays(allocator, &c, &b, .{}, &tally);
    try testing.expectEqual(before.in_sync + 4, tally.in_sync);

    // Full repair honours the floor as well.
    var stale = try FamilyState.init(allocator, "nicks");
    defer stale.deinit();
    try stale.put("nick:k", 10, makeHash(0x10), false);
    _ = try fullRepairFrom(allocator, &a, &stale);
    try testing.expect(a.get("nick:k") == null);
    _ = try fullRepairFrom(allocator, &stale, &a);
    try testing.expect(stale.get("nick:k") == null);
}

test "digest_reconcile: deterministic seeded 3-node partition/heal simulation converges to the LWW oracle" {
    const allocator = testing.allocator;
    const seed: u64 = 0xC0FFEE_D16357;
    var rng = std.Random.Pcg.init(seed);
    const random = rng.random();

    var nodes: [3]FamilyState = undefined;
    var inited: usize = 0;
    defer for (nodes[0..inited]) |*n| n.deinit();
    for (&nodes) |*n| {
        n.* = try FamilyState.init(allocator, "sim");
        inited += 1;
        try putBackground(n, "bg", 160);
    }
    // Oracle: every write gets a globally unique version, so the converged
    // value of each hot key is simply its last write.
    var oracle = try FamilyState.init(allocator, "sim");
    defer oracle.deinit();
    try putBackground(&oracle, "bg", 160);

    var version: u64 = 1000;
    var tally: Tally = .{};
    // Phase 1: A-B-C line; A and C only converge transitively through B.
    for (0..80) |_| {
        var key_buf: [16]u8 = undefined;
        const key = try std.fmt.bufPrint(&key_buf, "k{d}", .{random.intRangeAtMost(u32, 0, 15)});
        const writer = &nodes[random.intRangeAtMost(usize, 0, 2)];
        const deleted = random.intRangeAtMost(u8, 0, 3) == 3;
        const value = if (deleted) makeHash(0) else makeHash(@truncate(version));
        try writer.put(key, version, value, deleted);
        try oracle.put(key, version, value, deleted);
        version += 1;
        if (random.boolean()) {
            try reconcileBothWays(allocator, &nodes[0], &nodes[1], .{}, &tally);
        } else {
            try reconcileBothWays(allocator, &nodes[1], &nodes[2], .{}, &tally);
        }
    }

    // Phase 2: triangle heal. One full pass converges the join exactly.
    try reconcileBothWays(allocator, &nodes[0], &nodes[1], .{}, &tally);
    try reconcileBothWays(allocator, &nodes[1], &nodes[2], .{}, &tally);
    try reconcileBothWays(allocator, &nodes[0], &nodes[2], .{}, &tally);
    for (&nodes) |*n| {
        try expectSameRows(&oracle, n);
        try expectSameRoot(&oracle, n);
    }
    // Non-vacuous: the delta rung carried real repairs and full repair was
    // not the common path.
    try testing.expect(tally.delta > 0);
    try testing.expect(tally.full < tally.delta);

    const before = tally;
    try reconcileBothWays(allocator, &nodes[0], &nodes[2], .{}, &tally);
    try testing.expectEqual(before.in_sync + 2, tally.in_sync);
}

test "digest_reconcile: families past 64K rows reconcile over the wire by refined delta and chunked full repair" {
    const allocator = testing.allocator;
    const rows: usize = 70_000;
    var a = try FamilyState.init(allocator, "sim");
    defer a.deinit();
    try fillSorted(&a, "bg", rows);
    var b = try a.clone();
    defer b.deinit();

    // One changed key. Its bucket holds about rows/64 > max_delta_entries
    // rows, past the default threshold, so the plan asks for detail and
    // refine narrows it to one unit instead of escalating.
    try a.put("bg123", 1_000_000, makeHash(0xA5), false);
    {
        const bytes_b = try summaryBytes(allocator, &.{b});
        defer allocator.free(bytes_b);
        var decision = try plan(allocator, &.{a}, bytes_b, .{});
        defer decision.deinit();
        const fp = &decision.delta.families[0];
        try testing.expect(fp.needs_detail);
        try testing.expect(fp.row_count > max_delta_entries);
        var detail = try buildDetail(allocator, &b, fp.buckets);
        defer detail.deinit();
        const detail_bytes = try encodeDetail(allocator, &detail);
        defer allocator.free(detail_bytes);
        try testing.expect(try refine(allocator, &a, fp, detail_bytes, .{}) == .delta);
        try testing.expectEqual(@as(usize, 1), fp.units.count());
        var frames = try buildDelta(allocator, &a, &fp.units);
        defer frames.deinit();
        try testing.expectEqual(@as(?FullRepairReason, null), try shipFrames(allocator, frames.frames, &b));
    }
    try expectSameRows(&a, &b);
    try testing.expectEqual(ExchangeResult.in_sync, try exchangeOneWay(allocator, &b, &a, .{}));

    // A raised threshold ships the whole bucket: more rows than one frame
    // holds, still encodable because frames are chunked.
    try b.put("bg456", 2_000_000, makeHash(0xB6), true);
    const raised: Budget = .{ .cfg = anti_entropy.StrategyConfig.init(8, 100_000) };
    {
        const bytes_a = try summaryBytes(allocator, &.{a});
        defer allocator.free(bytes_a);
        var decision = try plan(allocator, &.{b}, bytes_a, raised);
        defer decision.deinit();
        const fp = &decision.delta.families[0];
        try testing.expect(!fp.needs_detail);
        try testing.expect(fp.row_count > max_delta_entries);
        var frames = try buildDelta(allocator, &b, &fp.units);
        defer frames.deinit();
        try testing.expect(frames.frames.len >= 2);
        try testing.expectEqual(@as(?FullRepairReason, null), try shipFrames(allocator, frames.frames, &a));
    }
    try expectSameRows(&a, &b);
    try testing.expect(a.get("bg456").?.deleted);

    // Full repair of the whole family crosses the wire in bounded frames.
    var empty = try FamilyState.init(allocator, "sim");
    defer empty.deinit();
    {
        var frames = try buildFullSnapshot(allocator, &a);
        defer frames.deinit();
        try testing.expect(frames.frames.len >= rows / max_delta_entries);
        for (frames.frames) |*frame| {
            const wire = try encodeDelta(allocator, frame);
            defer allocator.free(wire);
            var received = try decodeDelta(allocator, wire);
            defer received.deinit();
            try testing.expectEqual(@as(usize, 0), try fullRepair(&empty, &received));
        }
    }
    try expectSameRows(&a, &empty);
    try expectSameRoot(&a, &empty);
}

test "digest_reconcile: a 2000-row same-version hash conflict converges through multi-frame full repair" {
    const allocator = testing.allocator;
    var a = try FamilyState.init(allocator, "memberships");
    defer a.deinit();
    try fillSorted(&a, "m", 2000);
    var b = try a.clone();
    defer b.deinit();
    try a.put("m7", 5000, makeHash(0xAA), false);
    try b.put("m7", 5000, makeHash(0xBB), false);

    try testing.expectEqual(ExchangeResult.full_repair, try exchangeOneWay(allocator, &a, &b, .{}));
    {
        var frames = try buildFullSnapshot(allocator, &a);
        defer frames.deinit();
        try testing.expect(frames.frames.len >= 2);
    }
    try testing.expectEqual(@as(usize, 1), try fullRepairFrom(allocator, &b, &a));
    try testing.expectEqual(@as(usize, 1), try fullRepairFrom(allocator, &a, &b));
    try expectSameRows(&a, &b);
    try expectSameRoot(&a, &b);
    try testing.expectEqualSlices(u8, &makeHash(0xBB), &a.get("m7").?.value_hash);
    try testing.expectEqual(ExchangeResult.in_sync, try exchangeOneWay(allocator, &a, &b, .{}));
}

test "digest_reconcile: frames partition the requested units, apply in any order, and an oversized unit fails closed" {
    const allocator = testing.allocator;
    var src = try FamilyState.init(allocator, "frames");
    defer src.deinit();
    // Maximum-length keys make every frame as large as the format allows.
    for (0..max_delta_entries + 300) |i| {
        var key: [max_key_len]u8 = undefined;
        @memset(&key, 'k');
        _ = try std.fmt.bufPrint(&key, "{d:0>8}", .{i});
        try src.put(&key, i, makeHash(@truncate(i)), i % 5 == 0);
    }

    var frames = try buildFullSnapshot(allocator, &src);
    defer frames.deinit();
    try testing.expect(frames.frames.len >= 2);
    var seen: UnitMask = .empty;
    var total: usize = 0;
    for (frames.frames) |*f| {
        for (f.parts) |p| {
            for (0..subs_per_bucket) |s| {
                if ((p.sub_mask >> @intCast(s)) & 1 == 0) continue;
                const unit = @as(usize, p.bucket) * subs_per_bucket + s;
                try testing.expect(!seen.isSet(unit)); // each unit in exactly one frame
                seen.set(unit);
            }
        }
        total += f.entries.len;
        const wire = try encodeDelta(allocator, f);
        defer allocator.free(wire);
        try testing.expect(wire.len <= max_delta_wire_len);
    }
    try testing.expectEqual(@as(usize, num_units), seen.count());
    try testing.expectEqual(src.len(), total);

    // Frames verify independently: applying them back to front converges.
    var dst = try FamilyState.init(allocator, "frames");
    defer dst.deinit();
    var i: usize = frames.frames.len;
    while (i > 0) {
        i -= 1;
        try applyDelta(&dst, &frames.frames[i]);
    }
    try expectSameRows(&src, &dst);

    // Tiny frame bound: many frames, same result; a unit over the bound is
    // refused instead of producing an unencodable frame.
    var small = try FamilyState.init(allocator, "frames");
    defer small.deinit();
    var collide: [2]usize = undefined;
    var first_of: [num_units]?usize = @splat(null);
    var found = false;
    for (0..4096) |n| {
        var key_buf: [16]u8 = undefined;
        const key = try std.fmt.bufPrint(&key_buf, "c{d}", .{n});
        const u = unitIndex(small.family, key);
        if (first_of[u]) |prev| {
            collide = .{ prev, n };
            found = true;
            break;
        }
        first_of[u] = n;
    }
    try testing.expect(found);
    try putBackground(&small, "s", 40);
    for (collide) |n| {
        var key_buf: [16]u8 = undefined;
        try small.put(try std.fmt.bufPrint(&key_buf, "c{d}", .{n}), 7, makeHash(7), false);
    }
    const all: UnitMask = .full;
    try testing.expectError(error.UnitTooLarge, buildFrames(allocator, &small, &all, 1));
    var chunked = try buildFrames(allocator, &small, &all, 2);
    defer chunked.deinit();
    try testing.expect(chunked.frames.len >= small.len() / 2);
    var rebuilt = try FamilyState.init(allocator, "frames");
    defer rebuilt.deinit();
    try testing.expectEqual(@as(?FullRepairReason, null), try shipFrames(allocator, chunked.frames, &rebuilt));
    try expectSameRows(&small, &rebuilt);
}

test "digest_reconcile: encodeSummary fails closed on an over-length family name instead of overflowing the u8 length prefix" {
    const allocator = testing.allocator;
    var long_buf: [max_family_name_len + 1]u8 = undefined;
    @memset(&long_buf, 'x');
    var long = try FamilyState.init(allocator, &long_buf);
    defer long.deinit();
    try long.put("k", 1, makeHash(1), false);
    var summary = try buildSummary(allocator, &.{long});
    defer summary.deinit();
    try testing.expectError(error.FamilyNameTooLong, encodeSummary(allocator, &summary));

    var frames = try buildFullSnapshot(allocator, &long);
    defer frames.deinit();
    try testing.expectError(error.FamilyNameTooLong, encodeDelta(allocator, &frames.frames[0]));
    var detail = try buildDetail(allocator, &long, &.{0});
    defer detail.deinit();
    try testing.expectError(error.FamilyNameTooLong, encodeDetail(allocator, &detail));

    var max_name_buf: [max_family_name_len]u8 = undefined;
    @memset(&max_name_buf, 'y');
    var at_bound = try FamilyState.init(allocator, &max_name_buf);
    defer at_bound.deinit();
    try at_bound.put("k", 1, makeHash(1), false);
    const bytes = try summaryBytes(allocator, &.{at_bound});
    defer allocator.free(bytes);
    var decoded = try decodeSummary(allocator, bytes);
    defer decoded.deinit();
    try testing.expectEqualStrings(&max_name_buf, decoded.families[0].family);
}

test "digest_reconcile: encodeSummary fails closed on more families than the wire format can address" {
    const allocator = testing.allocator;
    const many = try allocator.alloc(FamilyDigest, max_families + 1);
    var filled: usize = 0;
    defer {
        for (many[0..filled]) |*f| f.deinit(allocator);
        allocator.free(many);
    }
    for (many, 0..) |*slot, i| {
        var name_buf: [8]u8 = undefined;
        var fs = try FamilyState.init(allocator, try std.fmt.bufPrint(&name_buf, "f{d:0>3}", .{i}));
        defer fs.deinit();
        slot.* = try fs.digest();
        filled += 1;
    }
    const too_many = Summary{ .allocator = allocator, .families = many };
    try testing.expectError(error.TooManyFamilies, encodeSummary(allocator, &too_many));
}

test "digest_reconcile: allocation-failure sweep over the full ladder leaves state unchanged and retry succeeds" {
    const Sweep = struct {
        fn run(allocator: Allocator) !void {
            var a = try FamilyState.init(allocator, "sweep");
            defer a.deinit();
            try putBackground(&a, "k", 100);
            try a.put("only-a", 500, makeHash(5), true);
            var b = try FamilyState.init(allocator, "sweep");
            defer b.deinit();
            try putBackground(&b, "k", 100);
            try b.put("only-b", 501, makeHash(6), false);
            try a.put("stale", 1, makeHash(1), false); // dead below b's floor
            _ = b.gcTombstones(2);
            // Low enough that the bucket-coarse plan needs detail.
            const budget: Budget = .{ .cfg = anti_entropy.StrategyConfig.init(1, 3) };

            const bytes_b = try summaryBytes(allocator, &.{b});
            defer allocator.free(bytes_b);
            var decision = try plan(allocator, &.{a}, bytes_b, budget);
            defer decision.deinit();
            try testing.expect(decision == .delta);
            const fp = &decision.delta.families[0];
            try testing.expect(fp.needs_detail);

            var detail = try buildDetail(allocator, &b, fp.buckets);
            defer detail.deinit();
            const detail_bytes = try encodeDetail(allocator, &detail);
            defer allocator.free(detail_bytes);
            try testing.expect(try refine(allocator, &a, fp, detail_bytes, budget) == .delta);

            var frames = try buildDelta(allocator, &a, &fp.units);
            defer frames.deinit();
            for (frames.frames) |*frame| {
                const wire = try encodeDelta(allocator, frame);
                defer allocator.free(wire);
                var received = try decodeDelta(allocator, wire);
                defer received.deinit();
                var b_step = try b.clone();
                defer b_step.deinit();
                applyDelta(&b, &received) catch |err| {
                    try expectSameRows(&b_step, &b);
                    return err;
                };
            }
            try testing.expect(b.get("only-a").?.deleted);
            try testing.expect(b.get("only-b") != null);
            try testing.expect(b.get("stale") == null); // dropped, not adopted

            var snapshot = try buildFullSnapshot(allocator, &b);
            defer snapshot.deinit();
            for (snapshot.frames) |*frame| {
                var a_step = try a.clone();
                defer a_step.deinit();
                _ = fullRepair(&a, frame) catch |err| {
                    try expectSameRows(&a_step, &a);
                    return err;
                };
            }
            // b's floor pruned `stale` from a, so a now matches b exactly.
            try testing.expect(a.get("stale") == null);
            try expectSameRows(&a, &b);
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Sweep.run, .{});
}
