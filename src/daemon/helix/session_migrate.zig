// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! S2S session replication — the capsule a node ships to a peer so clients can
//! attach to the same logical session across the mesh, plus the receiving node's
//! bounded holding area.
//!
//! Unlike a hot UPGRADE (same machine, the socket fd is inherited), an S2S
//! replica crosses processes/machines: the fd CANNOT move, so a client attaches
//! on the target node with the same reusable token. This module is the data layer
//! for that:
//!
//!   * `Capsule` — token + account + a `session_snapshot` blob (nick/account/
//!     hosts/away/oper/channels). The `fd` inside the snapshot is meaningless
//!     across machines and ignored on reclaim.
//!   * `PendingMigrations` — the target node's holding area: token -> (account,
//!     snapshot), inserted when the capsule arrives and borrowed by every client
//!     attaching with that token until bounded TTL expiry. Pairs with
//!     `sessions.SessionStore`, which tracks local logical-session attachments.
//!
//! Transport-agnostic: the capsule rides whatever carries it (S2S relay frame,
//! conduit, ...). Wiring it onto the live S2S link + the reclaim path are later
//! slices.
const std = @import("std");
const session_replica = @import("session_replica.zig");

pub const Token = [16]u8;
pub const Error = error{ Truncated, TooLong, TrailingBytes, InvalidMetadata };

/// Snapshots carry the raw session token (replay authority), so snapshot
/// allocations are secure-zeroed before every free. Split out so the wipe
/// is testable on caller memory before the free.
fn wipeBytes(bytes: []u8) void {
    std.crypto.secureZero(u8, bytes);
}

fn freeSnapshotBytes(allocator: std.mem.Allocator, snapshot: []u8) void {
    wipeBytes(snapshot);
    allocator.free(snapshot);
}

/// Complete, atomic Helix checkpoint for `PendingMigrations`. This is separate
/// from the S2S `Capsule` wire above: a hot upgrade must preserve the holding
/// area's ordering/expiry metadata and consumed-token deny state, not merely
/// re-stage each snapshot as an unordered legacy offer.
pub const upgrade_checkpoint_magic = [_]u8{ 'P', 'M', 'S', 'T' };
pub const upgrade_checkpoint_version: u8 = 2;
const upgrade_checkpoint_checksum_len: usize = 32;
const upgrade_checkpoint_header_len: usize = upgrade_checkpoint_magic.len + 1 + 8 + 4 + 4;

pub const UpgradeCheckpointError = error{
    BadMagic,
    UnsupportedVersion,
    Truncated,
    TrailingBytes,
    ChecksumMismatch,
    CapacityExceeded,
    DuplicateState,
    InvalidMetadata,
    TooLarge,
} || std.mem.Allocator.Error;

/// A migrated session in flight: who it is + its serialized state.
pub const Capsule = struct {
    token: Token,
    account: []const u8,
    /// A `session_snapshot.encode` blob (borrowed on decode).
    snapshot: []const u8,
};

/// Wire: [16 token][u16 account_len][account][u32 snap_len][snapshot]
pub fn encode(allocator: std.mem.Allocator, cap: Capsule) (Error || std.mem.Allocator.Error)![]u8 {
    if (cap.account.len > std.math.maxInt(u16)) return error.TooLong;
    if (cap.snapshot.len > std.math.maxInt(u32)) return error.TooLong;
    var out: std.ArrayList(u8) = .empty;
    errdefer {
        wipeBytes(out.items);
        out.deinit(allocator);
    }
    // Exact capacity: growth or a shrinking `toOwnedSlice` could release an
    // earlier token+snapshot copy without wiping it.
    try out.ensureTotalCapacityPrecise(allocator, 16 + 2 + cap.account.len + 4 + cap.snapshot.len);
    try out.appendSlice(allocator, &cap.token);
    var alen: [2]u8 = undefined;
    std.mem.writeInt(u16, &alen, @intCast(cap.account.len), .little);
    try out.appendSlice(allocator, &alen);
    try out.appendSlice(allocator, cap.account);
    var slen: [4]u8 = undefined;
    std.mem.writeInt(u32, &slen, @intCast(cap.snapshot.len), .little);
    try out.appendSlice(allocator, &slen);
    try out.appendSlice(allocator, cap.snapshot);
    std.debug.assert(out.items.len == out.capacity);
    return out.items;
}

/// Decode a capsule, returning views that borrow `bytes`.
pub fn decode(bytes: []const u8) Error!Capsule {
    if (bytes.len < 16 + 2) return error.Truncated;
    var token: Token = undefined;
    @memcpy(&token, bytes[0..16]);
    var pos: usize = 16;
    const alen = std.mem.readInt(u16, bytes[pos..][0..2], .little);
    pos += 2;
    if (pos + alen + 4 > bytes.len) return error.Truncated;
    const account = bytes[pos .. pos + alen];
    pos += alen;
    const slen = std.mem.readInt(u32, bytes[pos..][0..4], .little);
    pos += 4;
    if (pos + slen > bytes.len) return error.Truncated;
    if (pos + slen != bytes.len) return error.TrailingBytes;
    const snapshot = bytes[pos .. pos + slen];
    return .{ .token = token, .account = account, .snapshot = snapshot };
}

pub const Tombstone = struct {
    token: Token,
    consumed_at_ms: i64,
};

pub const tombstone_wire_len: usize = @sizeOf(Token) + @sizeOf(i64);

pub fn encodeTombstone(tombstone: Tombstone, out: *[tombstone_wire_len]u8) []const u8 {
    @memcpy(out[0..16], &tombstone.token);
    std.mem.writeInt(i64, out[16..24], tombstone.consumed_at_ms, .big);
    return out;
}

pub fn decodeTombstone(bytes: []const u8) Error!Tombstone {
    if (bytes.len != tombstone_wire_len) return error.Truncated;
    var token: Token = undefined;
    @memcpy(&token, bytes[0..16]);
    const consumed_at_ms = std.mem.readInt(i64, bytes[16..24], .big);
    if (consumed_at_ms < 0) return error.InvalidMetadata;
    return .{ .token = token, .consumed_at_ms = consumed_at_ms };
}

/// Target-node holding area: migrated sessions awaiting the client's reconnect.
/// Bounded two ways — a hard entry cap enforced in `put` and a TTL enforced by
/// the server's periodic `sweep` — so a signed-but-hostile (or buggy) peer
/// streaming capsules can never grow this map without bound.
pub const PendingMigrations = struct {
    allocator: std.mem.Allocator,
    map: std.AutoHashMapUnmanaged(Token, Entry) = .empty,
    /// Compatibility tombstones received/carried from legacy one-shot peers.
    /// Modern reusable-session attachment never creates one; a fresh verified
    /// signed offer supersedes one during a rolling upgrade.
    consumed: std.AutoHashMapUnmanaged(Token, i64) = .empty,
    cfg: Config,

    /// Hard ceiling on staged entries. A staged entry is one reusable logical
    /// session replica; even a large mesh stages far fewer than this. On a
    /// full map `put` fails closed (the client's reclaim then falls back to the
    /// legacy redirect path) rather than evicting a legitimate pending entry.
    pub const default_max_entries: usize = 4096;

    pub const Config = struct {
        max_entries: usize = default_max_entries,
        max_per_account: usize = 64,
    };

    pub const PutError = error{
        PendingFull,
        AlreadyConsumed,
        StaleOffer,
        TokenAccountMismatch,
    } || std.mem.Allocator.Error;
    pub const ConsumeError = error{ ConsumedFull, InvalidMetadata } || std.mem.Allocator.Error;

    pub const Entry = struct {
        account: []u8,
        snapshot: []u8,
        /// Monotonic-ms staging time; `sweep` evicts entries older than the TTL.
        staged_at_ms: i64,
        /// Signed relay epoch for this exact session token. Zero denotes legacy
        /// or locally-seeded state without ordering metadata.
        offer_epoch: u64 = 0,
        /// SESSION_REPLICA v2 projection order. Null means the entry came from
        /// the incomparable legacy epoch domain. Once present, a legacy sidecar
        /// can refresh neither nor downgrade this projection.
        replica_revision: ?session_replica.Revision = null,
        /// Absolute mesh-wall expiry copied from the verified signed OFFER.
        /// Present exactly when `replica_revision` is present.
        replica_expires_at_ms: ?i64 = null,
    };

    pub fn init(allocator: std.mem.Allocator) PendingMigrations {
        return initWithConfig(allocator, .{});
    }

    pub fn initWithConfig(allocator: std.mem.Allocator, cfg: Config) PendingMigrations {
        return .{ .allocator = allocator, .cfg = cfg };
    }

    /// Encode the entire live holding area into one integrity-checked blob.
    /// Entries retain their original monotonic staging clock, legacy epoch, v2
    /// revision/lease, and exact account/snapshot bytes. Consumed tombstones are
    /// included in the same transaction so restore cannot expose a replay window.
    pub fn encodeUpgradeCheckpoint(
        self: *const PendingMigrations,
        allocator: std.mem.Allocator,
        captured_at_ms: i64,
    ) UpgradeCheckpointError![]u8 {
        if (captured_at_ms < 0) return error.InvalidMetadata;
        if (self.map.count() > self.cfg.max_entries or
            self.consumed.count() > self.cfg.max_entries or
            self.map.count() > std.math.maxInt(u32) or
            self.consumed.count() > std.math.maxInt(u32))
        {
            return error.CapacityExceeded;
        }

        var total_len: usize = upgrade_checkpoint_header_len;
        var entry_it = @constCast(&self.map).iterator();
        while (entry_it.next()) |slot| {
            const entry = slot.value_ptr;
            if (self.consumed.contains(slot.key_ptr.*)) return error.DuplicateState;
            if (self.countForAccount(entry.account) > self.cfg.max_per_account) return error.CapacityExceeded;
            if (entry.account.len > std.math.maxInt(u16) or entry.snapshot.len > std.math.maxInt(u32))
                return error.TooLarge;
            if (!checkpointEntryMetadataValid(
                entry.staged_at_ms,
                entry.offer_epoch,
                entry.replica_revision,
                entry.replica_expires_at_ms,
            ) or entry.staged_at_ms > captured_at_ms) return error.InvalidMetadata;

            try checkpointAddLen(&total_len, @sizeOf(Token) + 2 + entry.account.len);
            try checkpointAddLen(&total_len, 4 + entry.snapshot.len + 8 + 8 + 1);
            if (entry.replica_revision != null) try checkpointAddLen(&total_len, 8 + 8 + 8 + 8);
        }
        var consumed_it = @constCast(&self.consumed).iterator();
        while (consumed_it.next()) |slot| {
            if (slot.value_ptr.* < 0 or slot.value_ptr.* > captured_at_ms) return error.InvalidMetadata;
            if (self.map.contains(slot.key_ptr.*)) return error.DuplicateState;
            try checkpointAddLen(&total_len, @sizeOf(Token) + 8);
        }
        try checkpointAddLen(&total_len, upgrade_checkpoint_checksum_len);

        const out = try allocator.alloc(u8, total_len);
        errdefer freeSnapshotBytes(allocator, out);
        var writer = UpgradeCheckpointWriter{ .bytes = out };
        writer.writeBytes(&upgrade_checkpoint_magic);
        writer.writeByte(upgrade_checkpoint_version);
        writer.writeI64(captured_at_ms);
        writer.writeU32(@intCast(self.map.count()));
        writer.writeU32(@intCast(self.consumed.count()));

        entry_it = @constCast(&self.map).iterator();
        while (entry_it.next()) |slot| {
            const entry = slot.value_ptr;
            writer.writeBytes(slot.key_ptr);
            writer.writeU16(@intCast(entry.account.len));
            writer.writeBytes(entry.account);
            writer.writeU32(@intCast(entry.snapshot.len));
            writer.writeBytes(entry.snapshot);
            writer.writeI64(entry.staged_at_ms);
            writer.writeU64(entry.offer_epoch);
            if (entry.replica_revision) |revision| {
                writer.writeByte(1);
                writer.writeU64(revision.epoch);
                writer.writeU64(revision.sequence);
                writer.writeU64(revision.origin_node);
                writer.writeI64(entry.replica_expires_at_ms.?);
            } else {
                writer.writeByte(0);
            }
        }
        consumed_it = @constCast(&self.consumed).iterator();
        while (consumed_it.next()) |slot| {
            writer.writeBytes(slot.key_ptr);
            writer.writeI64(slot.value_ptr.*);
        }

        std.debug.assert(writer.pos + upgrade_checkpoint_checksum_len == out.len);
        const checksum = upgradeCheckpointDigest(out[0..writer.pos]);
        writer.writeBytes(&checksum);
        std.debug.assert(writer.pos == out.len);
        return out;
    }

    /// Decode and validate a complete checkpoint into a fresh holding area.
    /// No caller-visible state exists until every entry, tombstone, bound, and
    /// trailing byte has been checked successfully.
    pub fn restoreUpgradeCheckpoint(
        allocator: std.mem.Allocator,
        cfg: Config,
        bytes: []const u8,
        restore_now_ms: i64,
        ttl_ms: u64,
    ) UpgradeCheckpointError!PendingMigrations {
        if (bytes.len < upgrade_checkpoint_header_len + upgrade_checkpoint_checksum_len)
            return error.Truncated;
        if (!std.mem.eql(u8, bytes[0..upgrade_checkpoint_magic.len], &upgrade_checkpoint_magic))
            return error.BadMagic;

        const body_end = bytes.len - upgrade_checkpoint_checksum_len;
        const expected_checksum: [upgrade_checkpoint_checksum_len]u8 =
            bytes[body_end..][0..upgrade_checkpoint_checksum_len].*;
        const actual_checksum = upgradeCheckpointDigest(bytes[0..body_end]);
        if (!std.crypto.timing_safe.eql(
            [upgrade_checkpoint_checksum_len]u8,
            expected_checksum,
            actual_checksum,
        )) return error.ChecksumMismatch;

        var reader = UpgradeCheckpointReader{ .bytes = bytes[0..body_end] };
        _ = try reader.take(upgrade_checkpoint_magic.len);
        if (try reader.readByte() != upgrade_checkpoint_version) return error.UnsupportedVersion;
        const captured_at_ms = try reader.readI64();
        if (captured_at_ms < 0 or restore_now_ms < captured_at_ms) return error.InvalidMetadata;
        const entry_count: usize = try reader.readU32();
        const consumed_count: usize = try reader.readU32();
        if (entry_count > cfg.max_entries or consumed_count > cfg.max_entries)
            return error.CapacityExceeded;
        var minimum_body: usize = 0;
        try checkpointAddProduct(&minimum_body, entry_count, @sizeOf(Token) + 2 + 4 + 8 + 8 + 1);
        try checkpointAddProduct(&minimum_body, consumed_count, @sizeOf(Token) + 8);
        if (minimum_body > reader.bytes.len - reader.pos) return error.Truncated;

        var restored = initWithConfig(allocator, cfg);
        errdefer restored.deinit();
        try restored.map.ensureTotalCapacity(allocator, @intCast(entry_count));
        try restored.consumed.ensureTotalCapacity(allocator, @intCast(consumed_count));

        for (0..entry_count) |_| {
            const token_bytes = try reader.take(@sizeOf(Token));
            const token: Token = token_bytes[0..@sizeOf(Token)].*;
            if (restored.map.contains(token) or restored.consumed.contains(token))
                return error.DuplicateState;

            const account_len: usize = try reader.readU16();
            const account_view = try reader.take(account_len);
            const snapshot_len: usize = try reader.readU32();
            const snapshot_view = try reader.take(snapshot_len);
            const staged_at_ms = try reader.readI64();
            const offer_epoch = try reader.readU64();
            const replica_revision: ?session_replica.Revision = switch (try reader.readByte()) {
                0 => null,
                1 => .{
                    .epoch = try reader.readU64(),
                    .sequence = try reader.readU64(),
                    .origin_node = try reader.readU64(),
                },
                else => return error.InvalidMetadata,
            };
            const replica_expires_at_ms: ?i64 = if (replica_revision != null)
                try reader.readI64()
            else
                null;
            if (!checkpointEntryMetadataValid(
                staged_at_ms,
                offer_epoch,
                replica_revision,
                replica_expires_at_ms,
            ) or staged_at_ms > captured_at_ms) return error.InvalidMetadata;
            if (restored.countForAccount(account_view) >= cfg.max_per_account)
                return error.CapacityExceeded;

            const account = try allocator.dupe(u8, account_view);
            errdefer allocator.free(account);
            const snapshot = try allocator.dupe(u8, snapshot_view);
            errdefer freeSnapshotBytes(allocator, snapshot);
            restored.map.putAssumeCapacityNoClobber(token, .{
                .account = account,
                .snapshot = snapshot,
                .staged_at_ms = staged_at_ms,
                .offer_epoch = offer_epoch,
                .replica_revision = replica_revision,
                .replica_expires_at_ms = replica_expires_at_ms,
            });
        }

        for (0..consumed_count) |_| {
            const token_bytes = try reader.take(@sizeOf(Token));
            const token: Token = token_bytes[0..@sizeOf(Token)].*;
            const consumed_at_ms = try reader.readI64();
            if (consumed_at_ms < 0 or consumed_at_ms > captured_at_ms) return error.InvalidMetadata;
            if (restored.map.contains(token) or restored.consumed.contains(token))
                return error.DuplicateState;
            restored.consumed.putAssumeCapacityNoClobber(token, consumed_at_ms);
        }
        if (reader.pos != reader.bytes.len) return error.TrailingBytes;
        _ = restored.sweep(restore_now_ms, ttl_ms);
        return restored;
    }

    /// Atomically replace this holding area. Any corruption, capacity error, or
    /// allocation failure leaves `self` and all of its owned bytes untouched.
    pub fn replaceFromUpgradeCheckpoint(
        self: *PendingMigrations,
        bytes: []const u8,
        restore_now_ms: i64,
        ttl_ms: u64,
    ) UpgradeCheckpointError!void {
        var replacement = try restoreUpgradeCheckpoint(self.allocator, self.cfg, bytes, restore_now_ms, ttl_ms);
        const previous = self.*;
        self.* = replacement;
        replacement = previous;
        replacement.deinit();
    }

    fn freeEntryBytes(self: *PendingMigrations, entry: Entry) void {
        self.allocator.free(entry.account);
        freeSnapshotBytes(self.allocator, entry.snapshot);
    }

    /// `fetchRemove` plus secure-zero of the token key slot, whose backing
    /// storage stays allocated in the map after removal. The slot pointer
    /// is captured before removal; removal does not move/free storage.
    fn fetchRemoveWipingKey(self: *PendingMigrations, token: Token) ?Entry {
        const key_ptr = self.map.getKeyPtr(token) orelse return null;
        const kv = self.map.fetchRemove(token) orelse return null;
        wipeBytes(key_ptr);
        return kv.value;
    }

    fn removeConsumedWipingKey(self: *PendingMigrations, token: Token) bool {
        const key_ptr = self.consumed.getKeyPtr(token) orelse return false;
        if (!self.consumed.remove(token)) return false;
        wipeBytes(key_ptr);
        return true;
    }

    pub fn deinit(self: *PendingMigrations) void {
        var it = self.map.iterator();
        while (it.next()) |slot| {
            self.allocator.free(slot.value_ptr.account);
            freeSnapshotBytes(self.allocator, slot.value_ptr.snapshot);
            wipeBytes(slot.key_ptr);
        }
        self.map.deinit(self.allocator);
        var consumed_it = self.consumed.keyIterator();
        while (consumed_it.next()) |key| wipeBytes(key);
        self.consumed.deinit(self.allocator);
        self.* = undefined;
    }

    /// Store a freshly-arrived capsule (copies the account + snapshot), stamped
    /// `now_ms` for TTL eviction. Replaces any existing entry for the same token
    /// (freeing the old). Fails closed with `PendingFull` when inserting a NEW
    /// token into a map already at `max_entries` (a replacement always succeeds).
    pub fn put(self: *PendingMigrations, cap: Capsule, now_ms: i64) PutError!void {
        return self.putAtEpoch(cap, now_ms, 0);
    }

    /// Stage a signed offer with token-scoped ordering. The pending map is the
    /// bounded lifecycle authority: a replayed or reordered offer cannot replace
    /// a newer snapshot for the same resume token, while different authenticated
    /// origin peers never collide merely because their local nonce counters match.
    pub fn putAtEpoch(self: *PendingMigrations, cap: Capsule, now_ms: i64, offer_epoch: u64) PutError!void {
        if (now_ms < 0) return error.StaleOffer;
        // Legacy one-shot peers may have converged a consume tombstone during a
        // rolling upgrade. An unsigned/legacy restage must still respect it;
        // only a newly verified, ordered relay offer proves that the reusable
        // logical session is live again and may reactivate the replica.
        if (self.consumed.contains(cap.token) and offer_epoch == 0) return error.AlreadyConsumed;
        const replacing = self.map.contains(cap.token);
        if (replacing) {
            const current = self.map.getPtr(cap.token).?;
            if (!std.ascii.eqlIgnoreCase(current.account, cap.account)) return error.TokenAccountMismatch;
            if (current.replica_revision != null) return error.StaleOffer;
            if (offer_epoch != 0 and current.offer_epoch != 0 and offer_epoch <= current.offer_epoch) return error.StaleOffer;
        }
        if (!replacing and self.map.count() >= self.cfg.max_entries) {
            return error.PendingFull;
        }
        if (!replacing and self.countForAccount(cap.account) >= self.cfg.max_per_account) {
            return error.PendingFull;
        }
        const account = try self.allocator.dupe(u8, cap.account);
        errdefer self.allocator.free(account);
        const snapshot = try self.allocator.dupe(u8, cap.snapshot);
        errdefer freeSnapshotBytes(self.allocator, snapshot);
        if (!replacing) try self.map.ensureUnusedCapacity(self.allocator, 1);
        // v3+ session credentials are reusable multi-attachment capabilities.
        // A freshly verified signed offer reactivates a token tombstoned by an
        // older one-shot peer during a rolling upgrade. Do this only after all
        // bounds/allocation checks pass so a failed stage preserves old state.
        if (offer_epoch != 0) _ = self.removeConsumedWipingKey(cap.token);
        if (replacing) {
            const current = self.map.getPtr(cap.token).?;
            self.allocator.free(current.account);
            freeSnapshotBytes(self.allocator, current.snapshot);
            current.* = .{ .account = account, .snapshot = snapshot, .staged_at_ms = now_ms, .offer_epoch = offer_epoch };
        } else {
            self.map.putAssumeCapacityNoClobber(cap.token, .{
                .account = account,
                .snapshot = snapshot,
                .staged_at_ms = now_ms,
                .offer_epoch = offer_epoch,
            });
        }
    }

    /// Project the Store's already-selected best v2 identity into the token-keyed
    /// reconnect view. V2 always supersedes legacy regardless of their unrelated
    /// numeric clock magnitudes. The Store is the ordering authority: this API
    /// replaces atomically even when its selected best live origin has a lower
    /// revision after a higher origin expires or revokes.
    pub fn putReplica(
        self: *PendingMigrations,
        cap: Capsule,
        now_ms: i64,
        revision: session_replica.Revision,
        expires_at_ms: i64,
    ) PutError!void {
        if (!checkpointEntryMetadataValid(now_ms, 0, revision, expires_at_ms))
            return error.StaleOffer;
        const replacing = self.map.contains(cap.token);
        if (replacing) {
            const current = self.map.getPtr(cap.token).?;
            if (!std.ascii.eqlIgnoreCase(current.account, cap.account)) return error.TokenAccountMismatch;
        }
        if (!replacing and self.map.count() >= self.cfg.max_entries) return error.PendingFull;
        if (!replacing and self.countForAccount(cap.account) >= self.cfg.max_per_account) return error.PendingFull;

        const account = try self.allocator.dupe(u8, cap.account);
        errdefer self.allocator.free(account);
        const snapshot = try self.allocator.dupe(u8, cap.snapshot);
        errdefer freeSnapshotBytes(self.allocator, snapshot);
        if (!replacing) try self.map.ensureUnusedCapacity(self.allocator, 1);

        _ = self.removeConsumedWipingKey(cap.token);
        const replacement = Entry{
            .account = account,
            .snapshot = snapshot,
            .staged_at_ms = now_ms,
            .offer_epoch = 0,
            .replica_revision = revision,
            .replica_expires_at_ms = expires_at_ms,
        };
        if (replacing) {
            const current = self.map.getPtr(cap.token).?;
            self.allocator.free(current.account);
            freeSnapshotBytes(self.allocator, current.snapshot);
            current.* = replacement;
        } else {
            self.map.putAssumeCapacityNoClobber(cap.token, replacement);
        }
    }

    /// Remove only a v2-derived reconnect projection after the Store reports no
    /// surviving signed origin. This is not a consume tombstone: a later valid
    /// v2 OFFER can stage normally, and unrelated rolling-legacy state is left
    /// untouched.
    pub fn removeReplica(self: *PendingMigrations, token: Token) bool {
        const current = self.map.get(token) orelse return false;
        if (current.replica_revision == null) return false;
        const removed = self.fetchRemoveWipingKey(token) orelse return false;
        self.freeEntryBytes(removed);
        return true;
    }

    /// Evict every entry staged at least `ttl_ms` before `now_ms` (freeing its
    /// copies). The bounded repeated scan is allocation-free, so restore-time
    /// expiry and replay protection cannot be postponed by allocator pressure.
    pub fn sweep(self: *PendingMigrations, now_ms: i64, ttl_ms: u64) usize {
        var evicted: usize = 0;
        while (true) {
            var expired: ?Token = null;
            var it = self.map.iterator();
            while (it.next()) |entry| {
                const age = now_ms -| entry.value_ptr.staged_at_ms;
                if (age >= 0 and @as(u64, @intCast(age)) >= ttl_ms) {
                    expired = entry.key_ptr.*;
                    break;
                }
            }
            const token = expired orelse break;
            const entry = self.fetchRemoveWipingKey(token) orelse continue;
            self.freeEntryBytes(entry);
            evicted += 1;
        }
        while (true) {
            var expired: ?Token = null;
            var it = self.consumed.iterator();
            while (it.next()) |entry| {
                const age = now_ms -| entry.value_ptr.*;
                if (age >= 0 and @as(u64, @intCast(age)) >= ttl_ms) {
                    expired = entry.key_ptr.*;
                    break;
                }
            }
            const token = expired orelse break;
            if (self.removeConsumedWipingKey(token)) evicted += 1;
        }
        return evicted;
    }

    /// Whether a migrated session is waiting for `token`.
    pub fn has(self: *const PendingMigrations, token: Token) bool {
        return self.map.contains(token);
    }

    /// Borrow a staged reusable replica without consuming it. Multiple clients
    /// may restore from this view until its bounded TTL expires.
    pub fn get(self: *const PendingMigrations, token: Token) ?*const Entry {
        return self.map.getPtr(token);
    }

    /// Borrow a reconnect projection only while its signed v2 lease is live.
    /// Legacy entries have no signed wall expiry here and preserve their existing
    /// TTL-based compatibility behavior.
    pub fn getLive(self: *const PendingMigrations, token: Token, now_wall_ms: i64) ?*const Entry {
        const entry = self.map.getPtr(token) orelse return null;
        if (entry.replica_expires_at_ms) |expires| if (now_wall_ms > expires) return null;
        return entry;
    }

    pub fn isConsumed(self: *const PendingMigrations, token: Token) bool {
        return self.consumed.contains(token);
    }

    /// Legacy one-shot compatibility: remove a staged copy and retain a bounded
    /// token tombstone. Modern successful attachment deliberately does not call
    /// this because the signed replica is reusable by concurrent clients.
    pub fn markConsumed(self: *PendingMigrations, token: Token, now_ms: i64) ConsumeError!void {
        if (now_ms < 0) return error.InvalidMetadata;
        if (self.consumed.contains(token)) {
            self.removeLiveEntry(token);
            return;
        }
        if (self.cfg.max_entries == 0) return error.ConsumedFull;
        // Reserve before evicting an older tombstone or removing the live
        // snapshot. Once this succeeds, publication and removal are no-fail, so
        // OOM leaves both replay authority and reusable state byte-identical.
        try self.consumed.ensureUnusedCapacity(self.allocator, 1);
        if (self.consumed.count() >= self.cfg.max_entries and !self.evictOldestConsumed())
            return error.ConsumedFull;
        self.consumed.putAssumeCapacityNoClobber(token, now_ms);
        self.removeLiveEntry(token);
    }

    /// Legacy destructive access used by compatibility tests/capsule adoption.
    /// Modern attachment borrows with `get`. Caller owns the returned slices and
    /// releases them with `freeEntry`.
    pub fn take(self: *PendingMigrations, token: Token) ?Entry {
        return self.fetchRemoveWipingKey(token);
    }

    pub fn freeEntry(self: *PendingMigrations, e: Entry) void {
        self.freeEntryBytes(e);
    }

    pub fn count(self: *const PendingMigrations) usize {
        return self.map.count();
    }

    pub fn consumedCount(self: *const PendingMigrations) usize {
        return self.consumed.count();
    }

    fn evictOldestConsumed(self: *PendingMigrations) bool {
        var oldest_token: ?Token = null;
        var oldest_at: i64 = std.math.maxInt(i64);
        var it = self.consumed.iterator();
        while (it.next()) |entry| {
            if (oldest_token == null or entry.value_ptr.* < oldest_at) {
                oldest_at = entry.value_ptr.*;
                oldest_token = entry.key_ptr.*;
            }
        }
        return if (oldest_token) |token| self.removeConsumedWipingKey(token) else false;
    }

    fn removeLiveEntry(self: *PendingMigrations, token: Token) void {
        if (self.fetchRemoveWipingKey(token)) |entry| self.freeEntryBytes(entry);
    }

    fn countForAccount(self: *const PendingMigrations, account: []const u8) usize {
        var matches: usize = 0;
        var it = @constCast(&self.map).valueIterator();
        while (it.next()) |entry| {
            if (std.ascii.eqlIgnoreCase(entry.account, account)) matches += 1;
        }
        return matches;
    }
};

fn checkpointEntryMetadataValid(
    staged_at_ms: i64,
    offer_epoch: u64,
    replica_revision: ?session_replica.Revision,
    replica_expires_at_ms: ?i64,
) bool {
    if (staged_at_ms < 0) return false;
    const revision = replica_revision orelse return replica_expires_at_ms == null;
    const expires_at_ms = replica_expires_at_ms orelse return false;
    return offer_epoch == 0 and
        revision.origin_node != 0 and
        revision.isCanonical() and
        expires_at_ms >= 0;
}

fn checkpointAddLen(total: *usize, amount: usize) UpgradeCheckpointError!void {
    if (amount > std.math.maxInt(usize) - total.*) return error.TooLarge;
    total.* += amount;
}

fn checkpointAddProduct(total: *usize, count: usize, unit: usize) UpgradeCheckpointError!void {
    if (count != 0 and unit > std.math.maxInt(usize) / count) return error.TooLarge;
    try checkpointAddLen(total, count * unit);
}

fn upgradeCheckpointDigest(bytes: []const u8) [upgrade_checkpoint_checksum_len]u8 {
    var digest: [upgrade_checkpoint_checksum_len]u8 = undefined;
    std.crypto.hash.Blake3.hash(bytes, &digest, .{});
    return digest;
}

const UpgradeCheckpointWriter = struct {
    bytes: []u8,
    pos: usize = 0,

    fn writeByte(self: *UpgradeCheckpointWriter, value: u8) void {
        self.bytes[self.pos] = value;
        self.pos += 1;
    }

    fn writeBytes(self: *UpgradeCheckpointWriter, value: []const u8) void {
        @memcpy(self.bytes[self.pos .. self.pos + value.len], value);
        self.pos += value.len;
    }

    fn writeU16(self: *UpgradeCheckpointWriter, value: u16) void {
        std.mem.writeInt(u16, self.bytes[self.pos..][0..2], value, .big);
        self.pos += 2;
    }

    fn writeU32(self: *UpgradeCheckpointWriter, value: u32) void {
        std.mem.writeInt(u32, self.bytes[self.pos..][0..4], value, .big);
        self.pos += 4;
    }

    fn writeU64(self: *UpgradeCheckpointWriter, value: u64) void {
        std.mem.writeInt(u64, self.bytes[self.pos..][0..8], value, .big);
        self.pos += 8;
    }

    fn writeI64(self: *UpgradeCheckpointWriter, value: i64) void {
        std.mem.writeInt(i64, self.bytes[self.pos..][0..8], value, .big);
        self.pos += 8;
    }
};

const UpgradeCheckpointReader = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn take(self: *UpgradeCheckpointReader, len: usize) UpgradeCheckpointError![]const u8 {
        if (len > self.bytes.len -| self.pos) return error.Truncated;
        const result = self.bytes[self.pos .. self.pos + len];
        self.pos += len;
        return result;
    }

    fn readByte(self: *UpgradeCheckpointReader) UpgradeCheckpointError!u8 {
        return (try self.take(1))[0];
    }

    fn readU16(self: *UpgradeCheckpointReader) UpgradeCheckpointError!u16 {
        return std.mem.readInt(u16, (try self.take(2))[0..2], .big);
    }

    fn readU32(self: *UpgradeCheckpointReader) UpgradeCheckpointError!u32 {
        return std.mem.readInt(u32, (try self.take(4))[0..4], .big);
    }

    fn readU64(self: *UpgradeCheckpointReader) UpgradeCheckpointError!u64 {
        return std.mem.readInt(u64, (try self.take(8))[0..8], .big);
    }

    fn readI64(self: *UpgradeCheckpointReader) UpgradeCheckpointError!i64 {
        return std.mem.readInt(i64, (try self.take(8))[0..8], .big);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const migration_relay = @import("migration_relay.zig");

fn rewriteUpgradeCheckpointChecksum(bytes: []u8) void {
    std.debug.assert(bytes.len >= upgrade_checkpoint_checksum_len);
    const body_end = bytes.len - upgrade_checkpoint_checksum_len;
    const checksum = upgradeCheckpointDigest(bytes[0..body_end]);
    @memcpy(bytes[body_end..], &checksum);
}

test "snapshot wipe helper zeroes bytes and wiping removals keep the store usable" {
    var buf = "snapshot-token-bytes".*;
    wipeBytes(&buf);
    for (buf) |b| try testing.expectEqual(@as(u8, 0), b);

    const allocator = testing.allocator;
    const token: Token = @splat(0x5a);
    var pm = PendingMigrations.init(allocator);
    defer pm.deinit();
    try pm.put(.{ .token = token, .account = "alice", .snapshot = "snap-one" }, 100);
    // Replacement wipes+frees the old snapshot; the token stays live.
    try pm.put(.{ .token = token, .account = "alice", .snapshot = "snap-two" }, 200);
    try testing.expectEqualStrings("snap-two", pm.get(token).?.snapshot);
    // Wiping removal (take + freeEntry) must not corrupt the key slot for
    // a later re-stage of the same token.
    const taken = pm.take(token).?;
    pm.freeEntry(taken);
    try testing.expect(!pm.has(token));
    try pm.put(.{ .token = token, .account = "alice", .snapshot = "snap-three" }, 300);
    try testing.expectEqualStrings("snap-three", pm.get(token).?.snapshot);
    // Consumed-tombstone key wipe: tombstone, then a verified re-stage.
    try pm.markConsumed(token, 400);
    try testing.expect(pm.isConsumed(token));
    try pm.putAtEpoch(.{ .token = token, .account = "alice", .snapshot = "snap-four" }, 500, 7);
    try testing.expect(!pm.isConsumed(token));
    try testing.expectEqualStrings("snap-four", pm.get(token).?.snapshot);
}

test "migration capsule encode/decode round-trips" {
    const allocator = testing.allocator;
    const token: Token = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    const cap = Capsule{ .token = token, .account = "alice", .snapshot = "snap-bytes-here" };
    const bytes = try encode(allocator, cap);
    defer allocator.free(bytes);

    const got = try decode(bytes);
    try testing.expectEqualSlices(u8, &token, &got.token);
    try testing.expectEqualStrings("alice", got.account);
    try testing.expectEqualStrings("snap-bytes-here", got.snapshot);

    const trailing = try allocator.alloc(u8, bytes.len + 1);
    defer allocator.free(trailing);
    @memcpy(trailing[0..bytes.len], bytes);
    trailing[bytes.len] = 0xA5;
    try testing.expectError(error.TrailingBytes, decode(trailing));
}

test "migration capsule encoding is leak-free across every allocation failure" {
    const cap = Capsule{
        .token = @splat(0x39),
        .account = "Alice",
        .snapshot = "complete-session-snapshot",
    };
    const Sweep = struct {
        fn run(allocator: std.mem.Allocator, capsule: Capsule) !void {
            const wire = try encode(allocator, capsule);
            defer allocator.free(wire);
            const restored = try decode(wire);
            try testing.expectEqualStrings(capsule.account, restored.account);
            try testing.expectEqualStrings(capsule.snapshot, restored.snapshot);
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Sweep.run, .{cap});
}

test "consumption tombstone wire round-trips exactly" {
    const original = Tombstone{ .token = @splat(0x5A), .consumed_at_ms = 123_456 };
    var buf: [tombstone_wire_len]u8 = undefined;
    const got = try decodeTombstone(encodeTombstone(original, &buf));
    try testing.expectEqualSlices(u8, &original.token, &got.token);
    try testing.expectEqual(original.consumed_at_ms, got.consumed_at_ms);
    try testing.expectError(error.Truncated, decodeTombstone(buf[0 .. buf.len - 1]));
    _ = encodeTombstone(.{ .token = original.token, .consumed_at_ms = -1 }, &buf);
    try testing.expectError(error.InvalidMetadata, decodeTombstone(&buf));
}

test "decode rejects truncated input" {
    try testing.expectError(error.Truncated, decode(&[_]u8{ 1, 2, 3 }));
    // valid token + account-len claiming more than present
    var buf: [20]u8 = @splat(0);
    buf[16] = 50; // account_len = 50, but no bytes follow
    try testing.expectError(error.Truncated, decode(&buf));
}

test "PendingMigrations stores, finds, and consumes by token" {
    const allocator = testing.allocator;
    var pm = PendingMigrations.init(allocator);
    defer pm.deinit();

    const t1: Token = @as([15]u8, @splat(0)) ++ .{1};
    const t2: Token = @as([15]u8, @splat(0)) ++ .{2};
    try pm.put(.{ .token = t1, .account = "alice", .snapshot = "A" }, 1000);
    try pm.put(.{ .token = t2, .account = "bob", .snapshot = "BB" }, 1000);
    try testing.expectEqual(@as(usize, 2), pm.count());
    try testing.expect(pm.has(t1));

    const e = pm.take(t1) orelse return error.TestUnexpectedResult;
    defer pm.freeEntry(e);
    try testing.expectEqualStrings("alice", e.account);
    try testing.expectEqualStrings("A", e.snapshot);
    try testing.expect(!pm.has(t1)); // consumed
    try testing.expect(pm.take(t1) == null);
    try testing.expectEqual(@as(usize, 1), pm.count()); // bob remains
}

test "put replaces an existing token snapshot without leaking" {
    const allocator = testing.allocator;
    var pm = PendingMigrations.init(allocator);
    defer pm.deinit();
    const t: Token = @splat(9);
    try pm.put(.{ .token = t, .account = "alice", .snapshot = "x" }, 1000);
    try pm.put(.{ .token = t, .account = "ALICE", .snapshot = "yy" }, 1000);
    try testing.expectEqual(@as(usize, 1), pm.count());
    const e = pm.take(t).?;
    defer pm.freeEntry(e);
    try testing.expectEqualStrings("ALICE", e.account);
    try testing.expectEqualStrings("yy", e.snapshot);
}

test "put replacement preserves exact prior state at every allocation failure" {
    const Sweep = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var pm = PendingMigrations.init(allocator);
            defer pm.deinit();
            const token: Token = @splat(0x3A);
            try pm.putAtEpoch(.{ .token = token, .account = "Alice", .snapshot = "old" }, 10, 1);

            pm.putAtEpoch(.{ .token = token, .account = "ALICE", .snapshot = "new" }, 20, 2) catch |err| {
                try testing.expectEqual(error.OutOfMemory, err);
                const prior = pm.get(token).?;
                try testing.expectEqualStrings("Alice", prior.account);
                try testing.expectEqualStrings("old", prior.snapshot);
                try testing.expectEqual(@as(i64, 10), prior.staged_at_ms);
                try testing.expectEqual(@as(u64, 1), prior.offer_epoch);
                try pm.putAtEpoch(.{ .token = token, .account = "ALICE", .snapshot = "new" }, 20, 2);
                try testing.expectEqualStrings("new", pm.get(token).?.snapshot);
                return err;
            };
            try testing.expectEqualStrings("new", pm.get(token).?.snapshot);
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Sweep.run, .{});
}

test "signed offer epoch rejects replay and stale replacement per token" {
    const allocator = testing.allocator;
    var pm = PendingMigrations.init(allocator);
    defer pm.deinit();
    const token: Token = @splat(7);

    try pm.putAtEpoch(.{ .token = token, .account = "alice", .snapshot = "new" }, 100, 42);
    try testing.expectError(
        error.StaleOffer,
        pm.putAtEpoch(.{ .token = token, .account = "alice", .snapshot = "replay" }, 101, 42),
    );
    try testing.expectError(
        error.StaleOffer,
        pm.putAtEpoch(.{ .token = token, .account = "alice", .snapshot = "old" }, 102, 41),
    );
    try testing.expectError(
        error.TokenAccountMismatch,
        pm.putAtEpoch(.{ .token = token, .account = "mallory", .snapshot = "splice" }, 103, 43),
    );
    try pm.putAtEpoch(.{ .token = token, .account = "alice", .snapshot = "newer" }, 103, 43);

    const entry = pm.get(token).?;
    try testing.expectEqual(@as(u64, 43), entry.offer_epoch);
    try testing.expectEqualStrings("newer", entry.snapshot);
}

test "staging rejects invalid clocks and replica origins before allocation or mutation" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    var pm = PendingMigrations.init(failing.allocator());
    defer pm.deinit();
    const token: Token = @splat(0x3B);

    try testing.expectError(
        error.StaleOffer,
        pm.putAtEpoch(.{ .token = token, .account = "alice", .snapshot = "state" }, -1, 1),
    );
    try testing.expectError(
        error.StaleOffer,
        pm.putReplica(
            .{ .token = token, .account = "alice", .snapshot = "state" },
            1,
            .{ .epoch = 1, .sequence = 1, .origin_node = 0 },
            10,
        ),
    );
    try testing.expectError(
        error.StaleOffer,
        pm.putReplica(
            .{ .token = token, .account = "alice", .snapshot = "state" },
            1,
            .{ .epoch = 1, .sequence = 1, .origin_node = 7 },
            10,
        ),
    );
    try testing.expectError(
        error.StaleOffer,
        pm.putReplica(
            .{ .token = token, .account = "alice", .snapshot = "state" },
            1,
            .{ .epoch = 1, .sequence = 1, .origin_node = 7 },
            -1,
        ),
    );
    try testing.expectEqual(@as(usize, 0), pm.count());
    try testing.expect(!failing.has_induced_failure);
}

test "put fails closed at max_entries; a replacement of an existing token still succeeds" {
    const allocator = testing.allocator;
    var pm = PendingMigrations.initWithConfig(allocator, .{
        .max_entries = PendingMigrations.default_max_entries,
        .max_per_account = PendingMigrations.default_max_entries,
    });
    defer pm.deinit();

    // Fill to the cap (distinct tokens derived from the loop index).
    var i: usize = 0;
    while (i < PendingMigrations.default_max_entries) : (i += 1) {
        var t: Token = @splat(0);
        std.mem.writeInt(u64, t[0..8], i, .little);
        try pm.put(.{ .token = t, .account = "acct", .snapshot = "s" }, 1);
    }
    try testing.expectEqual(PendingMigrations.default_max_entries, pm.count());

    // A NEW token is rejected — the map never grows past the cap.
    const fresh: Token = @splat(0xFF);
    try testing.expectError(
        error.PendingFull,
        pm.put(.{ .token = fresh, .account = "evil", .snapshot = "x" }, 2),
    );
    try testing.expectEqual(PendingMigrations.default_max_entries, pm.count());
    try testing.expect(!pm.has(fresh));

    // Replacing an EXISTING token at the cap succeeds (count unchanged).
    const t0: Token = @splat(0);
    try pm.put(.{ .token = t0, .account = "acct", .snapshot = "zz" }, 3);
    try testing.expectEqual(PendingMigrations.default_max_entries, pm.count());
    const e = pm.take(t0).?;
    defer pm.freeEntry(e);
    try testing.expectEqualStrings("acct", e.account);

    // Consuming an entry frees a slot; a new token is admitted again.
    try pm.put(.{ .token = fresh, .account = "ok", .snapshot = "y" }, 4);
    try testing.expect(pm.has(fresh));
}

test "per-account staging cap cannot evict another account" {
    var pm = PendingMigrations.initWithConfig(testing.allocator, .{
        .max_entries = 4,
        .max_per_account = 1,
    });
    defer pm.deinit();

    const alice_1: Token = @as([15]u8, @splat(0)) ++ .{1};
    const alice_2: Token = @as([15]u8, @splat(0)) ++ .{2};
    const bob: Token = @as([15]u8, @splat(0)) ++ .{3};
    try pm.put(.{ .token = alice_1, .account = "alice", .snapshot = "a" }, 1);
    try testing.expectError(error.PendingFull, pm.put(.{ .token = alice_2, .account = "ALICE", .snapshot = "b" }, 2));
    try pm.put(.{ .token = bob, .account = "bob", .snapshot = "c" }, 3);
    try testing.expect(pm.has(alice_1));
    try testing.expect(pm.has(bob));
}

test "consumption tombstone blocks late migration resurrection and expires" {
    var pm = PendingMigrations.initWithConfig(testing.allocator, .{
        .max_entries = 4,
        .max_per_account = 4,
    });
    defer pm.deinit();

    const token: Token = @splat(0xAC);
    try pm.put(.{ .token = token, .account = "alice", .snapshot = "state" }, 10);
    try pm.markConsumed(token, 20);
    try testing.expect(!pm.has(token));
    try testing.expect(pm.isConsumed(token));
    try testing.expectError(error.AlreadyConsumed, pm.put(.{ .token = token, .account = "alice", .snapshot = "late" }, 21));

    try testing.expectEqual(@as(usize, 1), pm.sweep(120, 100));
    try testing.expect(!pm.isConsumed(token));
    try pm.put(.{ .token = token, .account = "alice", .snapshot = "new-generation" }, 121);
    try testing.expect(pm.has(token));
}

test "consumption tombstones never exceed their configured capacity" {
    const a: Token = @splat(0xA1);
    const b: Token = @splat(0xB2);
    var disabled = PendingMigrations.initWithConfig(testing.allocator, .{
        .max_entries = 0,
        .max_per_account = 0,
    });
    defer disabled.deinit();
    try testing.expectError(error.ConsumedFull, disabled.markConsumed(a, 1));
    try testing.expectEqual(@as(usize, 0), disabled.consumedCount());

    var bounded = PendingMigrations.initWithConfig(testing.allocator, .{
        .max_entries = 1,
        .max_per_account = 1,
    });
    defer bounded.deinit();
    try bounded.markConsumed(a, std.math.maxInt(i64));
    try bounded.markConsumed(b, std.math.maxInt(i64));
    try testing.expectEqual(@as(usize, 1), bounded.consumedCount());
    try testing.expect(!bounded.isConsumed(a));
    try testing.expect(bounded.isConsumed(b));
    const checkpoint = try bounded.encodeUpgradeCheckpoint(testing.allocator, std.math.maxInt(i64));
    testing.allocator.free(checkpoint);
}

test "verified reusable-session offer supersedes a legacy consumption tombstone" {
    var pm = PendingMigrations.init(testing.allocator);
    defer pm.deinit();

    const token: Token = @splat(0xAD);
    try pm.markConsumed(token, 20);
    try testing.expect(pm.isConsumed(token));

    try pm.putAtEpoch(.{
        .token = token,
        .account = "alice",
        .snapshot = "fresh-signed-state",
    }, 21, 7);
    try testing.expect(pm.has(token));
    try testing.expect(!pm.isConsumed(token));
    try testing.expectEqualStrings("fresh-signed-state", pm.get(token).?.snapshot);

    // A reusable replica is one logical token with any number of physical
    // clients. Repeated attachment reads never consume or tombstone it.
    const first_client = pm.get(token).?;
    const second_client = pm.get(token).?;
    try testing.expectEqual(first_client, second_client);
    try testing.expect(pm.has(token));
    try testing.expect(!pm.isConsumed(token));
}

test "legacy consume and signed reactivation are retryable at every allocation failure" {
    const ConsumeSweep = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var pm = PendingMigrations.initWithConfig(allocator, .{ .max_entries = 8, .max_per_account = 8 });
            defer pm.deinit();
            const token: Token = @splat(0xB1);
            try pm.put(.{ .token = token, .account = "Alice", .snapshot = "live-state" }, 10);
            try testing.expectError(error.InvalidMetadata, pm.markConsumed(token, -1));
            try testing.expect(pm.has(token));
            try testing.expect(!pm.isConsumed(token));

            pm.markConsumed(token, 20) catch |err| {
                try testing.expectEqual(error.OutOfMemory, err);
                try testing.expect(pm.has(token));
                try testing.expect(!pm.isConsumed(token));
                try testing.expectEqualStrings("Alice", pm.get(token).?.account);
                try testing.expectEqualStrings("live-state", pm.get(token).?.snapshot);
                try pm.markConsumed(token, 20);
                try testing.expect(!pm.has(token));
                try testing.expect(pm.isConsumed(token));
                return err;
            };
            try testing.expect(!pm.has(token));
            try testing.expect(pm.isConsumed(token));
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, ConsumeSweep.run, .{});

    const ReactivateSweep = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var pm = PendingMigrations.initWithConfig(allocator, .{ .max_entries = 8, .max_per_account = 8 });
            defer pm.deinit();
            const token: Token = @splat(0xB2);
            try pm.markConsumed(token, 20);

            pm.putAtEpoch(.{
                .token = token,
                .account = "Alice",
                .snapshot = "fresh-signed-state",
            }, 21, 7) catch |err| {
                try testing.expectEqual(error.OutOfMemory, err);
                try testing.expect(!pm.has(token));
                try testing.expect(pm.isConsumed(token));
                try pm.putAtEpoch(.{
                    .token = token,
                    .account = "ALICE",
                    .snapshot = "fresh-signed-state",
                }, 21, 7);
                try testing.expect(pm.has(token));
                try testing.expect(!pm.isConsumed(token));
                return err;
            };
            try testing.expect(pm.has(token));
            try testing.expect(!pm.isConsumed(token));
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, ReactivateSweep.run, .{});
}

test "v2 reconnect projection publication is retryable at every allocation failure" {
    const Sweep = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var pm = PendingMigrations.initWithConfig(allocator, .{ .max_entries = 8, .max_per_account = 8 });
            defer pm.deinit();
            const token: Token = @splat(0xB3);
            try pm.markConsumed(token, 20);
            const revision = session_replica.Revision{
                .epoch = 100,
                .sequence = (@as(u64, 100) << 16) | 1,
                .origin_node = 7,
            };

            pm.putReplica(
                .{ .token = token, .account = "Alice", .snapshot = "replica" },
                21,
                revision,
                10_000,
            ) catch |err| {
                try testing.expectEqual(error.OutOfMemory, err);
                try testing.expect(!pm.has(token));
                try testing.expect(pm.isConsumed(token));
                try pm.putReplica(
                    .{ .token = token, .account = "ALICE", .snapshot = "replica" },
                    21,
                    revision,
                    10_000,
                );
                try testing.expect(pm.has(token));
                try testing.expect(!pm.isConsumed(token));
                return err;
            };
            try testing.expect(pm.has(token));
            try testing.expect(!pm.isConsumed(token));
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Sweep.run, .{});
}

test "sweep evicts entries past the TTL and keeps fresh ones" {
    const allocator = testing.allocator;
    var pm = PendingMigrations.init(allocator);
    defer pm.deinit();

    const stale: Token = @as([15]u8, @splat(0)) ++ .{1};
    const fresh: Token = @as([15]u8, @splat(0)) ++ .{2};
    try pm.put(.{ .token = stale, .account = "old", .snapshot = "a" }, 1_000);
    try pm.put(.{ .token = fresh, .account = "new", .snapshot = "b" }, 9_000);

    // Nothing lapsed yet: age(stale)=4000 < ttl.
    try testing.expectEqual(@as(usize, 0), pm.sweep(5_000, 5_000));
    try testing.expectEqual(@as(usize, 2), pm.count());

    // stale's age hits the TTL exactly (>= evicts); fresh survives.
    try testing.expectEqual(@as(usize, 1), pm.sweep(6_000, 5_000));
    try testing.expect(!pm.has(stale));
    try testing.expect(pm.has(fresh));

    // A re-staged token's clock restarts from its new staged_at.
    try pm.put(.{ .token = stale, .account = "old2", .snapshot = "c" }, 10_000);
    try testing.expectEqual(@as(usize, 0), pm.sweep(11_000, 5_000));
    try testing.expect(pm.has(stale));
}

test "v2 projection supersedes legacy and legacy can never downgrade it" {
    const allocator = testing.allocator;
    var pm = PendingMigrations.init(allocator);
    defer pm.deinit();
    const token: Token = @splat(0x41);
    try pm.putAtEpoch(.{ .token = token, .account = "alice", .snapshot = "legacy-high-clock" }, 1, std.math.maxInt(u64));

    const revision = session_replica.Revision{
        .epoch = 10,
        .sequence = (@as(u64, 10) << 16) | 20,
        .origin_node = 30,
    };
    try pm.putReplica(.{ .token = token, .account = "alice", .snapshot = "v2-authority" }, 2, revision, 10_000);
    try testing.expectEqualStrings("v2-authority", pm.get(token).?.snapshot);
    try testing.expect(pm.get(token).?.replica_revision.?.eql(revision));

    try testing.expectError(error.StaleOffer, pm.putAtEpoch(
        .{ .token = token, .account = "alice", .snapshot = "legacy-downgrade" },
        3,
        std.math.maxInt(u64),
    ));
    try testing.expectEqualStrings("v2-authority", pm.get(token).?.snapshot);
}

test "v2 projection follows Store fallback when a higher origin disappears" {
    const allocator = testing.allocator;
    const token: Token = @splat(0x52);
    const low = session_replica.Revision{
        .epoch = 100,
        .sequence = (@as(u64, 100) << 16) | 200,
        .origin_node = 3,
    };
    const high = session_replica.Revision{
        .epoch = 100,
        .sequence = (@as(u64, 100) << 16) | 200,
        .origin_node = 9,
    };

    var projection = PendingMigrations.init(allocator);
    defer projection.deinit();
    try projection.putReplica(.{ .token = token, .account = "alice", .snapshot = "high" }, 1, high, 9_000);
    // Store.bestLiveIdentity selected the lower origin after the higher lease
    // expired/revoked. Pending must follow that authoritative projection.
    try projection.putReplica(.{ .token = token, .account = "alice", .snapshot = "low" }, 2, low, 10_000);
    try testing.expectEqualStrings("low", projection.get(token).?.snapshot);
    try testing.expect(projection.get(token).?.replica_revision.?.eql(low));

    var low_first = PendingMigrations.init(allocator);
    defer low_first.deinit();
    try low_first.putReplica(.{ .token = token, .account = "alice", .snapshot = "low" }, 1, low, 10_000);
    try low_first.putReplica(.{ .token = token, .account = "alice", .snapshot = "high" }, 2, high, 10_000);
    try testing.expectEqualStrings("high", low_first.get(token).?.snapshot);
    try testing.expect(low_first.get(token).?.replica_revision.?.eql(high));
    try testing.expect(low_first.getLive(token, 10_000) != null);
    try testing.expect(low_first.getLive(token, 10_001) == null);
}

test "pending migration upgrade checkpoint preserves legacy replay and v2 ordering" {
    const cfg = PendingMigrations.Config{ .max_entries = 8, .max_per_account = 4 };
    var source = PendingMigrations.initWithConfig(testing.allocator, cfg);
    defer source.deinit();

    const legacy_token: Token = @splat(0x61);
    const replica_token: Token = @splat(0x62);
    const consumed_token: Token = @splat(0x63);
    try source.putAtEpoch(.{
        .token = legacy_token,
        .account = "Alice",
        .snapshot = "legacy-newest",
    }, 111, 42);
    const revision = session_replica.Revision{
        .epoch = 500,
        .sequence = (@as(u64, 500) << 16) | 7,
        .origin_node = 0xabc,
    };
    try testing.expect(revision.isCanonical());
    try source.putReplica(.{
        .token = replica_token,
        .account = "alice",
        .snapshot = "v2-selected",
    }, 222, revision, 9_999);
    try source.markConsumed(consumed_token, 333);

    const checkpoint = try source.encodeUpgradeCheckpoint(testing.allocator, 333);
    defer testing.allocator.free(checkpoint);
    var restored = try PendingMigrations.restoreUpgradeCheckpoint(testing.allocator, cfg, checkpoint, 333, 10_000);
    defer restored.deinit();

    const legacy = restored.get(legacy_token).?;
    try testing.expectEqualStrings("Alice", legacy.account);
    try testing.expectEqualStrings("legacy-newest", legacy.snapshot);
    try testing.expectEqual(@as(i64, 111), legacy.staged_at_ms);
    try testing.expectEqual(@as(u64, 42), legacy.offer_epoch);
    try testing.expect(legacy.replica_revision == null);
    try testing.expect(legacy.replica_expires_at_ms == null);

    const replica = restored.get(replica_token).?;
    try testing.expectEqualStrings("v2-selected", replica.snapshot);
    try testing.expectEqual(@as(i64, 222), replica.staged_at_ms);
    try testing.expect(replica.replica_revision.?.eql(revision));
    try testing.expectEqual(@as(?i64, 9_999), replica.replica_expires_at_ms);
    try testing.expect(restored.isConsumed(consumed_token));

    // The restored legacy high-water mark still rejects equal and older replay.
    try testing.expectError(error.StaleOffer, restored.putAtEpoch(.{
        .token = legacy_token,
        .account = "alice",
        .snapshot = "equal-replay",
    }, 444, 42));
    try testing.expectError(error.StaleOffer, restored.putAtEpoch(.{
        .token = legacy_token,
        .account = "alice",
        .snapshot = "older-replay",
    }, 444, 41));
    try restored.putAtEpoch(.{
        .token = legacy_token,
        .account = "alice",
        .snapshot = "new-generation",
    }, 444, 43);
    try testing.expectEqualStrings("new-generation", restored.get(legacy_token).?.snapshot);

    // V2 remains in its incomparable authority domain; no legacy epoch can
    // downgrade it, and the consumed deny state remains effective too.
    try testing.expectError(error.StaleOffer, restored.putAtEpoch(.{
        .token = replica_token,
        .account = "alice",
        .snapshot = "legacy-downgrade",
    }, 445, std.math.maxInt(u64)));
    try testing.expectError(error.AlreadyConsumed, restored.put(.{
        .token = consumed_token,
        .account = "alice",
        .snapshot = "late-consumed-replay",
    }, 445));
}

test "pending migration upgrade checkpoint preserves bounded monotonic age" {
    const cfg = PendingMigrations.Config{ .max_entries = 4, .max_per_account = 4 };
    const live_token: Token = @splat(0x68);
    const consumed_token: Token = @splat(0x69);
    var source = PendingMigrations.initWithConfig(testing.allocator, cfg);
    defer source.deinit();
    try source.put(.{ .token = live_token, .account = "alice", .snapshot = "state" }, 100);
    try source.markConsumed(consumed_token, 100);
    const checkpoint = try source.encodeUpgradeCheckpoint(testing.allocator, 150);
    defer testing.allocator.free(checkpoint);

    var before_expiry = try PendingMigrations.restoreUpgradeCheckpoint(
        testing.allocator,
        cfg,
        checkpoint,
        199,
        100,
    );
    defer before_expiry.deinit();
    try testing.expect(before_expiry.has(live_token));
    try testing.expect(before_expiry.isConsumed(consumed_token));

    var at_expiry = try PendingMigrations.restoreUpgradeCheckpoint(
        testing.allocator,
        cfg,
        checkpoint,
        200,
        100,
    );
    defer at_expiry.deinit();
    try testing.expect(!at_expiry.has(live_token));
    try testing.expect(!at_expiry.isConsumed(consumed_token));

    // Future local timestamps cannot be hidden behind a forged capture time,
    // and a capture itself cannot be ahead of the successor's monotonic clock.
    var future = PendingMigrations.initWithConfig(testing.allocator, cfg);
    defer future.deinit();
    try future.put(.{ .token = live_token, .account = "alice", .snapshot = "future" }, 201);
    try testing.expectError(error.InvalidMetadata, future.encodeUpgradeCheckpoint(testing.allocator, 200));

    const future_capture = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(future_capture);
    std.mem.writeInt(
        i64,
        future_capture[upgrade_checkpoint_magic.len + 1 ..][0..8],
        250,
        .big,
    );
    rewriteUpgradeCheckpointChecksum(future_capture);
    try testing.expectError(
        error.InvalidMetadata,
        PendingMigrations.restoreUpgradeCheckpoint(testing.allocator, cfg, future_capture, 249, 100),
    );
}

test "pending migration upgrade checkpoint rejects corruption truncation trailing and duplicate state" {
    const cfg = PendingMigrations.Config{ .max_entries = 4, .max_per_account = 4 };
    var source = PendingMigrations.initWithConfig(testing.allocator, cfg);
    defer source.deinit();
    const live_token: Token = @splat(0x71);
    const consumed_token: Token = @splat(0x72);
    // One-byte account/snapshot keeps the hand-built duplicate offset exact.
    try source.put(.{ .token = live_token, .account = "a", .snapshot = "s" }, 10);
    try source.markConsumed(consumed_token, 20);
    const checkpoint = try source.encodeUpgradeCheckpoint(testing.allocator, 20);
    defer testing.allocator.free(checkpoint);

    try testing.expectError(
        error.Truncated,
        PendingMigrations.restoreUpgradeCheckpoint(
            testing.allocator,
            cfg,
            checkpoint[0 .. upgrade_checkpoint_header_len - 1],
            20,
            1_000,
        ),
    );
    try testing.expectError(
        error.ChecksumMismatch,
        PendingMigrations.restoreUpgradeCheckpoint(testing.allocator, cfg, checkpoint[0 .. checkpoint.len - 1], 20, 1_000),
    );

    const corrupted = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(corrupted);
    corrupted[upgrade_checkpoint_header_len + @sizeOf(Token) + 2] ^= 0x40;
    try testing.expectError(
        error.ChecksumMismatch,
        PendingMigrations.restoreUpgradeCheckpoint(testing.allocator, cfg, corrupted, 20, 1_000),
    );

    const wrong_version = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(wrong_version);
    wrong_version[upgrade_checkpoint_magic.len] +%= 1;
    rewriteUpgradeCheckpointChecksum(wrong_version);
    try testing.expectError(
        error.UnsupportedVersion,
        PendingMigrations.restoreUpgradeCheckpoint(testing.allocator, cfg, wrong_version, 20, 1_000),
    );

    const over_capacity = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(over_capacity);
    std.mem.writeInt(
        u32,
        over_capacity[upgrade_checkpoint_magic.len + 1 + 8 ..][0..4],
        @intCast(cfg.max_entries + 1),
        .big,
    );
    rewriteUpgradeCheckpointChecksum(over_capacity);
    try testing.expectError(
        error.CapacityExceeded,
        PendingMigrations.restoreUpgradeCheckpoint(testing.allocator, cfg, over_capacity, 20, 1_000),
    );

    // Header + one no-v2 entry with one-byte account/snapshot (41) points
    // at the consumed token. Make it equal the live token while keeping a valid
    // checksum; strict cross-map duplicate detection must reject the whole blob.
    const duplicate = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(duplicate);
    const entry_token_offset = upgrade_checkpoint_header_len;
    const consumed_token_offset = entry_token_offset + 41;
    @memcpy(
        duplicate[consumed_token_offset .. consumed_token_offset + @sizeOf(Token)],
        duplicate[entry_token_offset .. entry_token_offset + @sizeOf(Token)],
    );
    rewriteUpgradeCheckpointChecksum(duplicate);
    try testing.expectError(
        error.DuplicateState,
        PendingMigrations.restoreUpgradeCheckpoint(testing.allocator, cfg, duplicate, 20, 1_000),
    );

    // Insert one authenticated extra body byte before a freshly-computed
    // checksum. All declared records decode, then strict EOF validation rejects.
    const with_trailing = try testing.allocator.alloc(u8, checkpoint.len + 1);
    defer testing.allocator.free(with_trailing);
    const old_body_end = checkpoint.len - upgrade_checkpoint_checksum_len;
    @memcpy(with_trailing[0..old_body_end], checkpoint[0..old_body_end]);
    with_trailing[old_body_end] = 0xA5;
    rewriteUpgradeCheckpointChecksum(with_trailing);
    try testing.expectError(
        error.TrailingBytes,
        PendingMigrations.restoreUpgradeCheckpoint(testing.allocator, cfg, with_trailing, 20, 1_000),
    );
}

test "pending migration upgrade checkpoint encode restore and replace survive every allocation failure" {
    const cfg = PendingMigrations.Config{ .max_entries = 8, .max_per_account = 8 };
    var source = PendingMigrations.initWithConfig(testing.allocator, cfg);
    defer source.deinit();
    const live_token: Token = @splat(0x81);
    const replica_token: Token = @splat(0x82);
    const consumed_token: Token = @splat(0x83);
    try source.putAtEpoch(.{ .token = live_token, .account = "alice", .snapshot = "legacy" }, 10, 9);
    const revision = session_replica.Revision{
        .epoch = 700,
        .sequence = (@as(u64, 700) << 16) | 3,
        .origin_node = 7,
    };
    try source.putReplica(.{ .token = replica_token, .account = "bob", .snapshot = "replica" }, 20, revision, 30_000);
    try source.markConsumed(consumed_token, 30);

    const EncodeSweep = struct {
        fn run(allocator: std.mem.Allocator, state: *const PendingMigrations) !void {
            const bytes = try state.encodeUpgradeCheckpoint(allocator, 30);
            defer allocator.free(bytes);
            try testing.expect(bytes.len > upgrade_checkpoint_header_len + upgrade_checkpoint_checksum_len);
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, EncodeSweep.run, .{&source});

    const checkpoint = try source.encodeUpgradeCheckpoint(testing.allocator, 30);
    defer testing.allocator.free(checkpoint);
    const RestoreSweep = struct {
        fn run(allocator: std.mem.Allocator, wire: []const u8, config: PendingMigrations.Config) !void {
            var restored = try PendingMigrations.restoreUpgradeCheckpoint(allocator, config, wire, 30, 1_000);
            defer restored.deinit();
            try testing.expectEqual(@as(usize, 2), restored.count());
            try testing.expectEqual(@as(usize, 1), restored.consumedCount());
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, RestoreSweep.run, .{ checkpoint, cfg });

    const ReplaceSweep = struct {
        fn run(allocator: std.mem.Allocator, wire: []const u8, config: PendingMigrations.Config) !void {
            const sentinel: Token = @splat(0xFE);
            var target = PendingMigrations.initWithConfig(allocator, config);
            defer target.deinit();
            try target.put(.{ .token = sentinel, .account = "sentinel", .snapshot = "old" }, 1);
            target.replaceFromUpgradeCheckpoint(wire, 30, 1_000) catch |err| {
                // Setup completed, so this is a restore allocation failure. The
                // target must still own its exact predecessor state.
                try testing.expect(target.has(sentinel));
                try testing.expectEqualStrings("old", target.get(sentinel).?.snapshot);
                try testing.expectEqual(@as(usize, 1), target.count());
                return err;
            };
            try testing.expect(!target.has(sentinel));
            try testing.expectEqual(@as(usize, 2), target.count());
            try testing.expectEqual(@as(usize, 1), target.consumedCount());
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, ReplaceSweep.run, .{ checkpoint, cfg });
}

test "end-to-end: origin prepare -> session_migrate wrap -> target accept -> PendingMigrations -> reclaim consume" {
    // Exercises exactly the server seam: the origin mints a signed migration
    // capsule, wraps it in a session_migrate.Capsule keyed by the 16-byte session
    // token, the target verifies it (MigrationTarget.accept) and stages it under
    // that key, then a reclaim by the matching token takes + decodes the full
    // restored snapshot (nick/umodes/channels/away/account/host/is_oper).
    const allocator = testing.allocator;
    const Ed25519 = std.crypto.sign.Ed25519;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x7E)));

    // ORIGIN: build the full session snapshot and mint the relay frame.
    const channels = [_][]const u8{ "#onyx", "#helix", "#ops" };
    const snapshot = migration_relay.Snapshot{
        .nick = "kain",
        .umodes = "+iwx",
        .channels = channels[0..],
        .realname = "Kain Example",
        .host = "cloak-ab12.onyx",
        .account = "kain",
        .away = "migrating",
        .is_oper = true,
    };
    var origin = migration_relay.MigrationOrigin.init(allocator, kp);
    defer origin.deinit();
    var prepared = try origin.prepare("kain", snapshot, 0xCAFEBABE, 7);
    defer prepared.deinit(allocator);

    // ORIGIN: wrap the relay frame in a session_migrate capsule keyed by the
    // 16-byte session token (the reclaim-side lookup key) and serialize for S2S.
    const session_token: Token = .{ 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    const wire = try encode(allocator, .{
        .token = session_token,
        .account = "kain",
        .snapshot = prepared.frame_bytes,
    });
    defer allocator.free(wire);

    // TARGET: decode the outer capsule, verify+decode the relay frame, then stage
    // the re-encoded snapshot under the session-token key.
    const outer = try decode(wire);
    try testing.expectEqualSlices(u8, &session_token, &outer.token);

    var pm = PendingMigrations.init(allocator);
    defer pm.deinit();
    {
        var target = migration_relay.MigrationTarget.init(allocator, kp.public_key.toBytes());
        defer target.deinit();
        var capsule = try target.accept(outer.snapshot);
        defer capsule.deinit(allocator);
        try testing.expectEqualStrings("kain", capsule.account);

        const snap_bytes = try capsule.snapshot.encode(allocator);
        defer allocator.free(snap_bytes);
        try pm.put(.{ .token = outer.token, .account = outer.account, .snapshot = snap_bytes }, 1000);
    }
    try testing.expect(pm.has(session_token));

    // RECLAIM: the client reconnects + presents the matching token; consume.
    const entry = pm.take(session_token) orelse return error.TestUnexpectedResult;
    defer pm.freeEntry(entry);
    try testing.expectEqualStrings("kain", entry.account);
    try testing.expect(!pm.has(session_token)); // consumed

    var restored = try migration_relay.Snapshot.decode(allocator, entry.snapshot);
    defer restored.deinit(allocator);
    try testing.expectEqualStrings("kain", restored.nick);
    try testing.expectEqualStrings("+iwx", restored.umodes);
    try testing.expectEqual(@as(usize, 3), restored.channels.len);
    try testing.expectEqualStrings("#onyx", restored.channels[0]);
    try testing.expectEqualStrings("#ops", restored.channels[2]);
    try testing.expectEqualStrings("Kain Example", restored.realname);
    try testing.expectEqualStrings("cloak-ab12.onyx", restored.host);
    try testing.expectEqualStrings("kain", restored.account);
    try testing.expectEqualStrings("migrating", restored.away);
    try testing.expect(restored.is_oper);
}

test "end-to-end: target rejects a capsule signed by the wrong key (no staging)" {
    const allocator = testing.allocator;
    const Ed25519 = std.crypto.sign.Ed25519;
    const real = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x01)));
    const attacker = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x02)));

    const channels = [_][]const u8{"#onyx"};
    const snapshot = migration_relay.Snapshot{ .nick = "kain", .umodes = "+i", .channels = channels[0..] };
    var origin = migration_relay.MigrationOrigin.init(allocator, attacker); // signs with attacker key
    defer origin.deinit();
    var prepared = try origin.prepare("kain", snapshot, 0x1, 1);
    defer prepared.deinit(allocator);

    const session_token: Token = @splat(1);
    const wire = try encode(allocator, .{ .token = session_token, .account = "kain", .snapshot = prepared.frame_bytes });
    defer allocator.free(wire);
    const outer = try decode(wire);

    var pm = PendingMigrations.init(allocator);
    defer pm.deinit();
    var target = migration_relay.MigrationTarget.init(allocator, real.public_key.toBytes()); // pins the REAL key
    defer target.deinit();
    // Verification fails: nothing is staged.
    try testing.expectError(error.BadSignature, target.accept(outer.snapshot));
    try testing.expect(!pm.has(session_token));
    try testing.expectEqual(@as(usize, 0), pm.count());
}

test "a staged entry rides a Helix .pending_migration capsule across USR2 (round-trip)" {
    // Current Helix schema v2 wraps the complete PMST checkpoint in one capsule;
    // the successor atomically replaces its holding area from that exact field.
    const allocator = testing.allocator;
    const helix_capsule = @import("capsule.zig");

    const token: Token = @as([15]u8, @splat(7)) ++ .{1};
    var predecessor = PendingMigrations.init(allocator);
    defer predecessor.deinit();
    try predecessor.putAtEpoch(.{
        .token = token,
        .account = "kain",
        .snapshot = "verified-snapshot-bytes",
    }, 42, 7);
    const checkpoint = try predecessor.encodeUpgradeCheckpoint(allocator, 42);
    defer allocator.free(checkpoint);

    var fields = [_]helix_capsule.Field{.{ .ordinal = 1, .bytes = checkpoint }};
    var capsule = helix_capsule.make(.pending_migration, fields[0..]);
    capsule.header.min_supported = 2;
    const sealed = try helix_capsule.encode(allocator, capsule);
    defer allocator.free(sealed);

    var adopted = try helix_capsule.decode(allocator, sealed);
    defer adopted.deinit(allocator);
    try testing.expectEqual(helix_capsule.CapsuleKind.pending_migration, adopted.header.kind);
    try testing.expectEqual(@as(u16, 2), adopted.header.version);
    try testing.expectEqual(@as(u16, 2), adopted.header.min_supported);
    try testing.expectEqual(@as(usize, 1), adopted.fields.len);

    var successor = PendingMigrations.init(allocator);
    defer successor.deinit();
    try successor.replaceFromUpgradeCheckpoint(adopted.fields[0].bytes, 42, 1_000);
    const got = successor.get(token) orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("kain", got.account);
    try testing.expectEqualStrings("verified-snapshot-bytes", got.snapshot);
    try testing.expectEqual(@as(i64, 42), got.staged_at_ms);
    try testing.expectEqual(@as(u64, 7), got.offer_epoch);
}

test "adopting a truncated .pending_migration payload fails closed (tolerant decode)" {
    // A corrupt inner blob must be a clean skip on the successor, never a crash
    // and never a partially-staged entry.
    const allocator = testing.allocator;
    const token: Token = @splat(3);
    const wire = try encode(allocator, .{ .token = token, .account = "kain", .snapshot = "snapshot" });
    defer allocator.free(wire);

    // Truncate mid-snapshot and mid-header: both reject with Truncated.
    try testing.expectError(error.Truncated, decode(wire[0 .. wire.len - 3]));
    try testing.expectError(error.Truncated, decode(wire[0..10]));
}
