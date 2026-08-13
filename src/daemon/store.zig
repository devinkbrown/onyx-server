// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! OroStore embedded persistence skeleton.
//!
//! This is intentionally small, Zig-native, and standalone: an in-memory typed
//! key/value store backed by a checksummed append-only log, with snapshot
//! compaction and a bounded recent-mutation feed for service sync.
const std = @import("std");
const toml = @import("../proto/toml.zig");

const record_header_len = 8;
const payload_header_len = 10;
const default_max_record_len = 16 * 1024 * 1024;
const default_max_wal_len = 256 * 1024 * 1024;
const default_changefeed_capacity = 64;
const tombstone_len = std.math.maxInt(u32);
const meta_kind_next_seq: u8 = 0xFE;
const meta_next_seq_payload_len = 9;
const meta_kind_snapshot_coverage: u8 = 0xFD;
const meta_kind_wal_epoch: u8 = 0xFC;
const snapshot_coverage_version: u8 = 2;
const wal_epoch_len = 16;
const snapshot_coverage_slot_len = 8 + wal_epoch_len + std.crypto.hash.Blake3.digest_length;
const snapshot_coverage_v1_payload_len = 1 + 1 + 1 + 8 + wal_epoch_len + std.crypto.hash.Blake3.digest_length;
const snapshot_coverage_payload_len = 1 + 1 + 1 + 2 * snapshot_coverage_slot_len;
const wal_epoch_payload_len = 1 + wal_epoch_len;
const legacy_wal_epoch = std.mem.zeroes([wal_epoch_len]u8);

pub const StoreError = error{
    BadRecord,
    ChecksumMismatch,
    UnknownFamily,
    UnknownRecordKind,
    RecordTooLarge,
    PreparedMutationActive,
    PreparedAlreadyConsumed,
    StorePoisoned,
    IoAmbiguous,
    SnapshotSyncFailed,
    TruncateFailed,
    SequenceExhausted,
    SnapshotCoverageMismatch,
};

/// Narrow fault-injection seam for the prepared-write lane. This is kept on
/// OroStore rather than faking `std.Io`, so tests exercise the exact write and
/// sync boundary used in production. A `.short` write writes a strict prefix
/// and then reports `IoAmbiguous`; `.failed` reports before writing any bytes.
/// A prepared sync fault is injected after the complete record write but before
/// the publication cut. Those prepared write/sync failures poison the store
/// because the durable boundary is no longer knowable. Snapshot sync faults
/// are injected before snapshot replacement and are reported without poisoning.
pub const PreparedIoFault = struct {
    write: WriteFault = .none,
    sync: bool = false,
    snapshot_sync: bool = false,
    wal_truncate: WriteFault = .none,
    wal_sync: bool = false,

    pub const WriteFault = enum {
        none,
        short,
        failed,
    };
};

/// Runtime-tunable storage limits. Defaults preserve the historical hardcoded
/// behaviour; the orchestrator overlays the `[storage]` TOML section via
/// `Config.applyToml` before opening the store.
pub const Config = struct {
    /// Max single WAL/snapshot record payload size (bytes).
    max_record_bytes: usize = default_max_record_len,
    /// Max WAL file size accepted on replay (bytes); oversize logs are rejected.
    max_wal_bytes: usize = default_max_wal_len,
    /// Bounded recent-mutation changefeed ring size (entries).
    changefeed_capacity: usize = default_changefeed_capacity,

    /// Overlay `[storage]` keys from a parsed TOML document onto `cfg`. Missing
    /// keys leave the current value untouched. Pure: no I/O, never fails.
    pub fn applyToml(cfg: *Config, doc: *const toml.Document) void {
        if (doc.getUint("storage.max_record_bytes")) |v| {
            if (v >= 1 and v <= std.math.maxInt(u32)) cfg.max_record_bytes = @intCast(v);
        }
        if (doc.getUint("storage.max_wal_bytes")) |v| {
            if (v >= 1) cfg.max_wal_bytes = @intCast(v);
        }
        if (doc.getUint("storage.changefeed_capacity")) |v| {
            if (v >= 1) cfg.changefeed_capacity = @intCast(v);
        }
    }
};

/// Immutable storage ceilings used by callers to validate whether a durable
/// payload can be admitted by this opened store. This deliberately omits
/// mutable/runtime-only configuration such as changefeed capacity.
pub const AdmissionLimits = struct {
    max_record_bytes: usize,
    max_wal_bytes: usize,
};

pub const Family = enum(u8) {
    accounts,
    nicks,
    chanregs,
    bans,
    memos,
    vhosts,
    props,
    history,
};

pub const MutationKind = enum(u8) {
    put,
    delete,
};

pub const Mutation = struct {
    seq: u64,
    family: Family,
    kind: MutationKind,
    key: []const u8,
    value: ?[]const u8,
};

pub fn ColumnFamily(comptime store_family: Family) type {
    return struct {
        store: *OroStore,

        pub fn put(self: @This(), key: []const u8, value: []const u8) !void {
            try self.store.put(store_family, key, value);
        }

        pub fn get(self: @This(), key: []const u8) ?[]const u8 {
            return self.store.get(store_family, key);
        }

        pub fn delete(self: @This(), key: []const u8) !void {
            try self.store.delete(store_family, key);
        }
    };
}

const prepared_retirement_capacity = 4;

fn initRetirements() [prepared_retirement_capacity]?Retirement {
    var slots: [prepared_retirement_capacity]?Retirement = undefined;
    for (&slots) |*slot| slot.* = null;
    return slots;
}

const Retirement = union(enum) {
    bytes: []u8,
    mutation: OwnedMutation,
};

const SnapshotCoverage = struct {
    slots: [2]CoverageSlot,
    count: usize,
};

const CoverageSlot = struct {
    covered_len: u64,
    epoch: [wal_epoch_len]u8,
    digest: [std.crypto.hash.Blake3.digest_length]u8,
};

/// All prepared allocations live in the store until publication or abort. The
/// public token deliberately contains no slices or owned state, so copying a
/// token cannot duplicate ownership or accidentally release a newer prepare.
const ActivePrepared = struct {
    generation: u64,
    store_family: Family,
    key: ?[]u8,
    value: ?[]u8,
    record: ?[]u8,
    change: ?OwnedMutation,
    final_wal_offset: u64,
    next_seq_after: u64,
    sequence: u64,
    existing: bool,
};

/// A single opaque reservation token. The owner must keep the parent OroStore
/// alive until `commit`, `abort`, or `deinit` returns. Tokens are single-use;
/// copied or stale tokens are inert and never touch a newer reservation.
pub const PreparedPut = struct {
    store: *OroStore,
    generation: u64,

    pub fn commit(self: *PreparedPut) !void {
        return self.store.commitPrepared(self.generation);
    }

    pub fn abort(self: *PreparedPut) void {
        self.store.abortPrepared(self.generation);
    }

    pub fn deinit(self: *PreparedPut) void {
        self.abort();
    }
};

pub const OroStore = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    wal_path: []u8,
    snapshot_path: []u8,
    wal_file: ?std.Io.File = null,
    wal_offset: u64 = 0,
    // Headerless WALs predate epoch records. Give that format a deterministic
    // identity so snapshot coverage never serializes undefined bytes and can
    // still authenticate an intact legacy prefix after a truncate fault.
    wal_epoch: [wal_epoch_len]u8 = legacy_wal_epoch,
    wal_epoch_known: bool = false,
    snapshot_coverage: ?SnapshotCoverage = null,
    maps: [family_count]KvMap,
    changefeed: ChangeFeed,
    next_seq: u64 = 1,
    cfg: Config = .{},
    active_prepared: ?ActivePrepared = null,
    next_prepared_generation: u64 = 1,
    prepared_poisoned: bool = false,
    prepared_io_fault: PreparedIoFault = .{},
    retirements: [prepared_retirement_capacity]?Retirement = initRetirements(),
    retirement_count: usize = 0,

    /// Opens `wal_path` under `dir`, replays `<wal_path>.snap` first, then WAL.
    pub fn open(
        allocator: std.mem.Allocator,
        io: std.Io,
        dir: std.Io.Dir,
        wal_path: []const u8,
    ) !OroStore {
        return openWithConfig(allocator, io, dir, wal_path, .{});
    }

    /// Like `open`, but with explicit storage limits (see `Config`).
    pub fn openWithConfig(
        allocator: std.mem.Allocator,
        io: std.Io,
        dir: std.Io.Dir,
        wal_path: []const u8,
        cfg: Config,
    ) !OroStore {
        const owned_wal = try allocator.dupe(u8, wal_path);
        const owned_snapshot = std.mem.concat(allocator, u8, &.{ wal_path, ".snap" }) catch |err| {
            allocator.free(owned_wal);
            return err;
        };

        const changefeed = ChangeFeed.init(allocator, cfg.changefeed_capacity) catch |err| {
            allocator.free(owned_wal);
            allocator.free(owned_snapshot);
            return err;
        };
        var store = OroStore{
            .allocator = allocator,
            .io = io,
            .dir = dir,
            .wal_path = owned_wal,
            .snapshot_path = owned_snapshot,
            .maps = initMaps(allocator),
            .changefeed = changefeed,
            .cfg = cfg,
        };
        errdefer store.deinit();

        try store.ensureWal();
        _ = try store.replayFile(store.snapshot_path, .snapshot, 0);
        if (store.wal_offset == 0) try store.initializeEmptyWalAfterSnapshot();
        try store.loadWalEpoch();
        const wal_start = try store.coveredWalReplayStart();
        const wal_good = try store.replayFile(store.wal_path, .wal, wal_start);
        // A torn/corrupt WAL tail was tolerated by replay (crash mid-append).
        // Truncate it away NOW: appending after the garbage would poison the
        // log — on the NEXT open the bad bytes are no longer the final record,
        // the tail tolerance no longer applies, and the store would refuse to
        // open at all (live impact: the SASL account store silently disabled).
        if (wal_good < store.wal_offset) {
            const wal = store.wal_file.?;
            try wal.setLength(store.io, wal_good);
            try wal.sync(store.io);
            store.wal_offset = wal_good;
            try store.syncDir();
        }
        // Replay refuses a WAL larger than max_wal_bytes, so an uncompacted log
        // eventually bricks the store at reboot — compact at open when the WAL
        // has crossed the threshold (also bounds replay time).
        try store.maybeCompact();
        return store;
    }

    /// Returns the authoritative admission ceilings captured when this store
    /// was opened. The returned value cannot mutate the store configuration.
    pub fn admissionLimits(self: *const OroStore) AdmissionLimits {
        return .{
            .max_record_bytes = self.cfg.max_record_bytes,
            .max_wal_bytes = self.cfg.max_wal_bytes,
        };
    }

    pub fn deinit(self: *OroStore) void {
        self.discardActivePrepared();
        self.reclaimRetirements();
        if (self.wal_file) |file| file.close(self.io);
        for (&self.maps) |*map| map.deinit();
        self.changefeed.deinit();
        self.allocator.free(self.wal_path);
        self.allocator.free(self.snapshot_path);
        self.* = undefined;
    }

    /// Returns the comptime-typed API for one column family.
    pub fn family(self: *OroStore, comptime store_family: Family) ColumnFamily(store_family) {
        return .{ .store = self };
    }

    /// Install or clear the narrow prepared-write I/O seam. Production code
    /// leaves this at `.{};` tests use it to prove ambiguous short-write,
    /// failed-write, and sync boundaries poison the store.
    pub fn setPreparedIoFault(self: *OroStore, fault: PreparedIoFault) void {
        self.prepared_io_fault = fault;
    }

    /// True after a prepared write crossed an ambiguous write/sync boundary.
    /// The store must be reopened before any further mutation is admitted.
    pub fn preparedWritesPoisoned(self: *const OroStore) bool {
        return self.prepared_poisoned;
    }

    /// Reserve one put through a fallible pre-admission phase. Ensuring the WAL
    /// and compacting a projected over-limit log may perform I/O before the
    /// candidate append. All bytes, map capacity, changefeed storage, and
    /// final WAL/sequence scalars are captured in a store-owned bundle. The
    /// returned value is only a token.
    pub fn preparePut(
        self: *OroStore,
        store_family: Family,
        key: []const u8,
        value: []const u8,
    ) !PreparedPut {
        if (self.prepared_poisoned) return StoreError.StorePoisoned;
        if (self.active_prepared != null) return StoreError.PreparedMutationActive;
        if (self.next_prepared_generation == std.math.maxInt(u64)) return StoreError.SequenceExhausted;
        const sequence = try self.reserveSequence();

        const payload_len = try checkedPayloadLen(.put, key, value, self.cfg.max_record_bytes);
        const record_len = std.math.add(usize, record_header_len, payload_len) catch return StoreError.RecordTooLarge;
        const final_wal_offset = try self.preflightWalForRecord(record_len);
        self.reclaimRetirements();

        const generation = self.next_prepared_generation;
        self.next_prepared_generation += 1;
        self.active_prepared = .{
            .generation = generation,
            .store_family = store_family,
            .key = null,
            .value = null,
            .record = null,
            .change = null,
            .final_wal_offset = final_wal_offset,
            .next_seq_after = try checkedNextSequence(sequence),
            .sequence = sequence,
            .existing = false,
        };
        errdefer self.discardActivePrepared();

        const map = &self.maps[familyIndex(store_family)];
        const existing = map.map.getEntry(key) != null;
        if (!existing) try map.map.ensureUnusedCapacity(1);

        self.active_prepared.?.existing = existing;

        const record = try self.allocator.alloc(u8, record_len);
        self.active_prepared.?.record = record;
        writeU32(record[0..4], @intCast(payload_len));
        const payload = record[record_header_len..];
        payload[0] = @intFromEnum(MutationKind.put);
        payload[1] = @intFromEnum(store_family);
        writeU32(payload[2..][0..4], @intCast(key.len));
        writeU32(payload[6..][0..4], @intCast(value.len));
        @memcpy(payload[payload_header_len..][0..key.len], key);
        @memcpy(payload[payload_header_len + key.len ..][0..value.len], value);
        writeU32(record[4..][0..4], checksum(payload));

        const owned_key = try self.allocator.dupe(u8, key);
        self.active_prepared.?.key = owned_key;
        const owned_value = try self.allocator.dupe(u8, value);
        self.active_prepared.?.value = owned_value;

        if (self.changefeed.entries.len != 0) {
            const change = try OwnedMutation.from(self.allocator, .{
                .seq = sequence,
                .family = store_family,
                .kind = .put,
                .key = key,
                .value = value,
            });
            self.active_prepared.?.change = change;
        }
        return .{ .store = self, .generation = generation };
    }

    pub fn put(self: *OroStore, store_family: Family, key: []const u8, value: []const u8) !void {
        if (self.prepared_poisoned) return StoreError.StorePoisoned;
        if (self.active_prepared != null) return StoreError.PreparedMutationActive;
        const sequence = try self.reserveSequence();
        const record_len = try recordSize(.put, key, value, self.cfg.max_record_bytes);
        _ = try self.preflightWalForRecord(record_len);
        try self.appendRecord(.put, store_family, key, value);
        try self.applyPut(store_family, key, value);
        try self.recordMutation(sequence, store_family, .put, key, value);
    }

    pub fn get(self: *const OroStore, store_family: Family, key: []const u8) ?[]const u8 {
        return self.maps[familyIndex(store_family)].get(key);
    }

    pub fn delete(self: *OroStore, store_family: Family, key: []const u8) !void {
        if (self.prepared_poisoned) return StoreError.StorePoisoned;
        if (self.active_prepared != null) return StoreError.PreparedMutationActive;
        const sequence = try self.reserveSequence();
        const record_len = try recordSize(.delete, key, "", self.cfg.max_record_bytes);
        _ = try self.preflightWalForRecord(record_len);
        try self.appendRecord(.delete, store_family, key, "");
        try self.applyDelete(store_family, key);
        try self.recordMutation(sequence, store_family, .delete, key, null);
    }

    /// Writes current state to a snapshot and truncates the WAL.
    pub fn snapshotAndTruncate(self: *OroStore) !void {
        if (self.prepared_poisoned) return StoreError.StorePoisoned;
        if (self.active_prepared != null) return StoreError.PreparedMutationActive;
        try self.ensureWal();
        var coverage_digest: [std.crypto.hash.Blake3.digest_length]u8 = undefined;
        try self.hashWalPrefix(self.wal_offset, &coverage_digest);
        const old_coverage = CoverageSlot{ .covered_len = self.wal_offset, .epoch = self.wal_epoch, .digest = coverage_digest };
        var next_epoch: [wal_epoch_len]u8 = undefined;
        self.io.random(&next_epoch);
        var next_epoch_record: [record_header_len + wal_epoch_payload_len]u8 = undefined;
        writeU32(next_epoch_record[0..4], wal_epoch_payload_len);
        next_epoch_record[record_header_len] = meta_kind_wal_epoch;
        @memcpy(next_epoch_record[record_header_len + 1 ..], &next_epoch);
        writeU32(next_epoch_record[4..8], checksum(next_epoch_record[record_header_len..]));
        var next_digest: [std.crypto.hash.Blake3.digest_length]u8 = undefined;
        std.crypto.hash.Blake3.hash(&next_epoch_record, &next_digest, .{});
        const rotated_coverage = CoverageSlot{ .covered_len = next_epoch_record.len, .epoch = next_epoch, .digest = next_digest };
        const coverage = SnapshotCoverage{ .slots = .{ old_coverage, rotated_coverage }, .count = 2 };
        var snapshot = try self.dir.createFileAtomic(self.io, self.snapshot_path, .{ .replace = true });
        defer snapshot.deinit(self.io);

        var offset: u64 = 0;
        offset = try writeNextSeqRecordAt(self.io, snapshot.file, offset, self.allocator, self.next_seq);
        for (families) |store_family| {
            var it = self.maps[familyIndex(store_family)].map.iterator();
            while (it.next()) |entry| {
                offset = try writeRecordAt(
                    self.io,
                    snapshot.file,
                    offset,
                    self.allocator,
                    .put,
                    store_family,
                    entry.key_ptr.*,
                    entry.value_ptr.*,
                    self.cfg.max_record_bytes,
                );
            }
        }
        offset = try writeSnapshotCoverageRecordAt(self.io, snapshot.file, offset, self.allocator, &coverage);
        if (self.prepared_io_fault.snapshot_sync) return StoreError.SnapshotSyncFailed;
        try snapshot.file.sync(self.io);
        try snapshot.replace(self.io);
        self.syncDir() catch {
            // The snapshot path may already be replaced while its directory
            // entry is not known durable; the old WAL must not be appended to
            // until a reopen resolves that boundary.
            self.poisonPreparedStore();
            return StoreError.IoAmbiguous;
        };

        const wal = self.wal_file.?;
        if (self.prepared_io_fault.wal_sync) {
            // Inject before the truncate boundary so reopen can validate the
            // intact old WAL prefix against the snapshot coverage slot.
            self.poisonPreparedStore();
            return StoreError.IoAmbiguous;
        }
        switch (self.prepared_io_fault.wal_truncate) {
            .none => wal.setLength(self.io, 0) catch {
                self.poisonPreparedStore();
                return StoreError.IoAmbiguous;
            },
            .failed => {
                // The snapshot has already replaced the prior snapshot path;
                // whether the WAL truncate reached the filesystem is now
                // unknowable, so refuse all further appends until reopen.
                self.poisonPreparedStore();
                return StoreError.IoAmbiguous;
            },
            .short => {
                // Inject a short/truncate refusal before changing the WAL;
                // the snapshot's old-epoch coverage can then prove the intact
                // prefix during reopen. A real partial truncate remains
                // fail-closed through coveredWalReplayStart.
                self.poisonPreparedStore();
                return StoreError.IoAmbiguous;
            },
        }
        wal.sync(self.io) catch {
            self.poisonPreparedStore();
            return StoreError.IoAmbiguous;
        };
        self.wal_offset = self.rotateWalEpoch(wal, next_epoch) catch {
            self.poisonPreparedStore();
            return StoreError.IoAmbiguous;
        };
        self.snapshot_coverage = coverage;
        self.syncDir() catch {
            // WAL bytes were truncated and the in-memory offset moved, but
            // directory durability is uncertain. Reopen before appending.
            self.poisonPreparedStore();
            return StoreError.IoAmbiguous;
        };
    }

    /// Compact once the WAL crosses half its replay limit. Admission callers
    /// invoke this before appending; open invokes it after replay.
    fn maybeCompact(self: *OroStore) !void {
        if (self.wal_offset < self.cfg.max_wal_bytes / 2) return;
        try self.snapshotAndTruncate();
    }

    pub fn changeCount(self: *const OroStore) usize {
        return self.changefeed.count;
    }

    /// Returns recent mutations oldest-first. The returned slices are owned by
    /// the store and remain valid until the changefeed overwrites them.
    pub fn changeAt(self: *const OroStore, index: usize) ?Mutation {
        return self.changefeed.at(index);
    }

    fn ensureWal(self: *OroStore) !void {
        if (self.wal_file) |_| return;
        const file = try self.dir.createFile(self.io, self.wal_path, .{ .read = true, .truncate = false });
        self.wal_file = file;
        self.wal_offset = (try file.stat(self.io)).size;
    }

    fn initializeEmptyWalAfterSnapshot(self: *OroStore) !void {
        const file = self.wal_file orelse return StoreError.SnapshotCoverageMismatch;
        if (self.snapshot_coverage) |coverage| {
            const epoch_record_len = record_header_len + wal_epoch_payload_len;
            for (coverage.slots[0..coverage.count]) |slot| {
                if (slot.covered_len != epoch_record_len) continue;
                var record: [epoch_record_len]u8 = undefined;
                writeU32(record[0..4], wal_epoch_payload_len);
                record[record_header_len] = meta_kind_wal_epoch;
                @memcpy(record[record_header_len + 1 ..], &slot.epoch);
                writeU32(record[4..8], checksum(record[record_header_len..]));
                var digest: [std.crypto.hash.Blake3.digest_length]u8 = undefined;
                std.crypto.hash.Blake3.hash(&record, &digest, .{});
                if (!std.mem.eql(u8, &digest, &slot.digest)) continue;
                self.wal_epoch = slot.epoch;
                self.wal_epoch_known = true;
                self.wal_offset = try writeWalEpochRecordAt(self.io, file, 0, self.allocator, &self.wal_epoch);
                try file.sync(self.io);
                try self.syncDir();
                return;
            }
            return StoreError.SnapshotCoverageMismatch;
        }
        self.io.random(&self.wal_epoch);
        self.wal_epoch_known = true;
        self.wal_offset = try writeWalEpochRecordAt(self.io, file, 0, self.allocator, &self.wal_epoch);
        try file.sync(self.io);
        try self.syncDir();
    }

    fn loadWalEpoch(self: *OroStore) !void {
        self.wal_epoch = legacy_wal_epoch;
        self.wal_epoch_known = false;
        const file = self.wal_file orelse return;
        const stat = try file.stat(self.io);
        if (stat.size < record_header_len) return;
        var header: [record_header_len]u8 = undefined;
        const header_len = try file.readPositionalAll(self.io, &header, 0);
        if (header_len != header.len) return;
        const payload_len = readU32(header[0..4]);
        if (payload_len != wal_epoch_payload_len) {
            self.wal_epoch_known = true;
            return;
        }
        var payload: [wal_epoch_payload_len]u8 = undefined;
        const read_len = try file.readPositionalAll(self.io, &payload, record_header_len);
        if (read_len != payload.len) return;
        // A genuine legacy mutation may happen to have the same payload width
        // as an epoch record. Its kind byte, not its length, distinguishes it.
        if (payload[0] != meta_kind_wal_epoch) {
            self.wal_epoch_known = true;
            return;
        }
        if (checksum(&payload) != readU32(header[4..8])) return StoreError.ChecksumMismatch;
        self.wal_epoch = try parseWalEpoch(&payload);
        self.wal_epoch_known = true;
    }

    fn coveredWalReplayStart(self: *OroStore) !u64 {
        const coverage = self.snapshot_coverage orelse return 0;
        if (!self.wal_epoch_known) return StoreError.SnapshotCoverageMismatch;
        for (coverage.slots[0..coverage.count]) |slot| {
            if (slot.covered_len > self.wal_offset) continue;
            if (!std.mem.eql(u8, &slot.epoch, &self.wal_epoch)) continue;
            var digest: [std.crypto.hash.Blake3.digest_length]u8 = undefined;
            try self.hashWalPrefix(slot.covered_len, &digest);
            if (std.mem.eql(u8, &digest, &slot.digest)) return slot.covered_len;
        }
        return StoreError.SnapshotCoverageMismatch;
    }

    fn hashWalPrefix(self: *OroStore, length: u64, out: *[std.crypto.hash.Blake3.digest_length]u8) !void {
        const file = self.wal_file orelse return StoreError.SnapshotCoverageMismatch;
        var hasher = std.crypto.hash.Blake3.init(.{});
        var buffer: [4096]u8 = undefined;
        var offset: u64 = 0;
        while (offset < length) {
            const remaining = length - offset;
            const take: usize = @intCast(@min(remaining, buffer.len));
            const read_len = try file.readPositionalAll(self.io, buffer[0..take], offset);
            if (read_len != take) return StoreError.SnapshotCoverageMismatch;
            hasher.update(buffer[0..take]);
            offset += take;
        }
        hasher.final(out);
    }

    fn rotateWalEpoch(self: *OroStore, wal: std.Io.File, epoch: [wal_epoch_len]u8) !u64 {
        self.wal_epoch = epoch;
        self.wal_epoch_known = true;
        const offset = try writeWalEpochRecordAt(self.io, wal, 0, self.allocator, &self.wal_epoch);
        wal.sync(self.io) catch {
            self.poisonPreparedStore();
            return StoreError.IoAmbiguous;
        };
        return offset;
    }

    fn preflightWalForRecord(self: *OroStore, record_len: usize) !u64 {
        if (record_len > self.cfg.max_wal_bytes) return StoreError.RecordTooLarge;
        try self.ensureWal();

        const record_len_u64 = std.math.cast(u64, record_len) orelse return StoreError.RecordTooLarge;
        const max_wal = std.math.cast(u64, self.cfg.max_wal_bytes) orelse return StoreError.RecordTooLarge;
        var projected = std.math.add(u64, self.wal_offset, record_len_u64) catch return StoreError.RecordTooLarge;
        if (projected > max_wal or projected >= max_wal / 2) {
            // Compaction is part of admission. If it fails, the caller returns
            // before any candidate bytes are appended.
            try self.snapshotAndTruncate();
            projected = std.math.add(u64, self.wal_offset, record_len_u64) catch return StoreError.RecordTooLarge;
        }
        if (projected > max_wal) return StoreError.RecordTooLarge;
        return projected;
    }

    fn commitPrepared(self: *OroStore, generation: u64) !void {
        const active = self.active_prepared orelse return StoreError.PreparedAlreadyConsumed;
        if (active.generation != generation) return StoreError.PreparedAlreadyConsumed;
        if (self.prepared_poisoned) return StoreError.StorePoisoned;

        const file = self.wal_file orelse {
            self.poisonPreparedStore();
            return StoreError.IoAmbiguous;
        };
        const record = active.record.?;
        const append_offset = active.final_wal_offset - record.len;

        if (self.prepared_io_fault.write == .failed) {
            self.poisonPreparedStore();
            return StoreError.IoAmbiguous;
        }
        if (self.prepared_io_fault.write == .short) {
            const prefix_len = @max(@as(usize, 1), record.len / 2);
            file.writePositionalAll(self.io, record[0..prefix_len], append_offset) catch {};
            self.poisonPreparedStore();
            return StoreError.IoAmbiguous;
        }
        file.writePositionalAll(self.io, record, append_offset) catch {
            self.poisonPreparedStore();
            return StoreError.IoAmbiguous;
        };
        if (self.prepared_io_fault.sync) {
            self.poisonPreparedStore();
            return StoreError.IoAmbiguous;
        }
        file.sync(self.io) catch {
            self.poisonPreparedStore();
            return StoreError.IoAmbiguous;
        };

        // Durable publication is deliberately scalar/pointer-only. All
        // retirement slots were made available before admission, and no
        // allocator or fallible call is permitted below this line.
        var prepared = active;
        const map = &self.maps[familyIndex(prepared.store_family)];
        const key = prepared.key.?;
        const value = prepared.value.?;
        const gop = map.map.getOrPutAssumeCapacity(key);
        if (gop.found_existing) {
            self.retireBytes(key);
            self.retireBytes(gop.value_ptr.*);
        } else {
            gop.key_ptr.* = key;
        }
        gop.value_ptr.* = value;
        prepared.key = null;
        prepared.value = null;

        if (prepared.change) |change| {
            if (self.changefeed.publishPrepared(change)) |evicted| self.retireMutation(evicted);
            prepared.change = null;
        }
        self.retireBytes(prepared.record.?);
        prepared.record = null;
        self.wal_offset = prepared.final_wal_offset;
        self.next_seq = prepared.next_seq_after;
        self.active_prepared = null;
    }

    fn abortPrepared(self: *OroStore, generation: u64) void {
        const active = self.active_prepared orelse return;
        if (active.generation != generation) return;
        self.discardActivePrepared();
    }

    fn discardActivePrepared(self: *OroStore) void {
        if (self.active_prepared) |*active| {
            if (active.key) |key| self.allocator.free(key);
            if (active.value) |value| self.allocator.free(value);
            if (active.record) |record| self.allocator.free(record);
            if (active.change) |*change| change.deinit(self.allocator);
            self.active_prepared = null;
        }
    }

    fn retireBytes(self: *OroStore, bytes: []u8) void {
        std.debug.assert(self.retirement_count < self.retirements.len);
        self.retirements[self.retirement_count] = .{ .bytes = bytes };
        self.retirement_count += 1;
    }

    fn retireMutation(self: *OroStore, mutation: OwnedMutation) void {
        std.debug.assert(self.retirement_count < self.retirements.len);
        self.retirements[self.retirement_count] = .{ .mutation = mutation };
        self.retirement_count += 1;
    }

    fn reclaimRetirements(self: *OroStore) void {
        while (self.retirement_count != 0) {
            self.retirement_count -= 1;
            const slot = self.retirements[self.retirement_count].?;
            self.retirements[self.retirement_count] = null;
            switch (slot) {
                .bytes => |bytes| self.allocator.free(bytes),
                .mutation => |mutation| {
                    var owned = mutation;
                    owned.deinit(self.allocator);
                },
            }
        }
    }

    fn poisonPreparedStore(self: *OroStore) void {
        self.prepared_poisoned = true;
        self.discardActivePrepared();
    }

    const ReplayKind = enum {
        snapshot,
        wal,
    };

    /// Replay a snapshot or WAL file into the in-memory maps. Returns the
    /// offset one past the LAST FULLY-APPLIED record: for a clean file that is
    /// the file size; for a WAL with a tolerated torn/corrupt tail it is where
    /// the bad tail starts, so the caller can truncate it away before
    /// appending (appending after garbage would poison the log for the next
    /// open, where the tail tolerance no longer applies).
    fn replayFile(self: *OroStore, path: []const u8, replay_kind: ReplayKind, start_offset: u64) !u64 {
        var file = self.dir.openFile(self.io, path, .{ .mode = .read_only, .allow_directory = false }) catch |err| switch (err) {
            error.FileNotFound => return 0,
            else => return err,
        };
        defer file.close(self.io);

        const stat = try file.stat(self.io);
        if (stat.size == 0) return 0;
        if (replay_kind == .wal and stat.size > self.cfg.max_wal_bytes) return StoreError.RecordTooLarge;

        if (start_offset > stat.size) return StoreError.SnapshotCoverageMismatch;
        var offset: u64 = start_offset;
        var header: [record_header_len]u8 = undefined;
        while (offset < stat.size) {
            const record_offset = offset;
            const header_len = try file.readPositionalAll(self.io, &header, offset);
            if (header_len != header.len) {
                if (replay_kind == .wal) return record_offset;
                return StoreError.BadRecord;
            }
            offset += record_header_len;

            const payload_len = readU32(header[0..4]);
            const expected_sum = readU32(header[4..8]);
            const record_end = std.math.add(u64, offset, payload_len) catch return StoreError.BadRecord;

            if (payload_len > self.cfg.max_record_bytes and !isAllowedMetaPayloadLen(payload_len)) {
                // A length that overruns the file is a torn header from a crash
                // mid-append: only the final record can be in-flight (appendRecord
                // fsyncs one record at a time), so truncate the trailing region
                // exactly like the short-payload path below. A fully-present
                // oversize record is a real limit violation and stays fatal.
                if (replay_kind == .wal and record_end > stat.size) return record_offset;
                return StoreError.RecordTooLarge;
            }
            if (stat.size - offset < payload_len) {
                if (replay_kind == .wal) return record_offset;
                return StoreError.BadRecord;
            }

            const payload = try self.allocator.alloc(u8, payload_len);
            defer self.allocator.free(payload);
            const read_len = try file.readPositionalAll(self.io, payload, offset);
            if (read_len != payload.len) {
                if (replay_kind == .wal) return record_offset;
                return StoreError.BadRecord;
            }
            if (checksum(payload) != expected_sum) {
                // A checksum failure with too little room after it for even
                // another record header is the final in-flight record (crash
                // mid-append): truncate the torn tail. Records are written
                // gaplessly and each appendRecord fsyncs one record, so only the
                // last write can be in-flight and any 1..7 trailing bytes are its
                // torn remnant — a real following record needs a full header plus
                // payload. If a full record COULD still follow (>= record_header_len
                // bytes remain), this is interior corruption and truncating would
                // silently discard the committed records after it, so fail closed.
                // `record_end == stat.size` (nothing follows) is the historical
                // at-EOF case, subsumed here.
                if (replay_kind == .wal and stat.size - record_end < record_header_len)
                    return record_offset;
                return StoreError.ChecksumMismatch;
            }
            if (payload.len == 0) return StoreError.BadRecord;
            if (payload[0] == meta_kind_snapshot_coverage) {
                if (replay_kind != .snapshot) return StoreError.BadRecord;
                self.snapshot_coverage = try parseSnapshotCoverage(payload);
                offset = record_end;
                continue;
            }
            if (payload[0] == meta_kind_wal_epoch) {
                if (replay_kind != .wal or record_offset != 0) return StoreError.BadRecord;
                self.wal_epoch = try parseWalEpoch(payload);
                self.wal_epoch_known = true;
                offset = record_end;
                continue;
            }
            self.applyPayload(payload) catch |err| switch (err) {
                StoreError.BadRecord,
                StoreError.UnknownFamily,
                StoreError.UnknownRecordKind,
                => if (replay_kind == .wal and record_end == stat.size) return record_offset else return err,
                else => return err,
            };
            if (replay_kind == .wal and isMutationPayload(payload)) {
                self.next_seq = try checkedNextSequence(self.next_seq);
            }
            offset = record_end;
            if (offset <= record_offset) return StoreError.BadRecord;
        }
        return offset;
    }

    fn appendRecord(
        self: *OroStore,
        kind: MutationKind,
        store_family: Family,
        key: []const u8,
        value: []const u8,
    ) !void {
        try self.ensureWal();
        const file = self.wal_file.?;
        const next_offset = try writeRecordAt(self.io, file, self.wal_offset, self.allocator, kind, store_family, key, value, self.cfg.max_record_bytes);
        try file.sync(self.io);
        self.wal_offset = next_offset;
    }

    fn applyPayload(self: *OroStore, payload: []const u8) !void {
        if (payload.len == 0) return StoreError.BadRecord;

        if (payload[0] == meta_kind_next_seq) {
            if (payload.len != meta_next_seq_payload_len) return StoreError.BadRecord;
            self.next_seq = readU64(payload[1..9]);
            return;
        }

        if (payload.len < payload_header_len) return StoreError.BadRecord;

        const kind: MutationKind = switch (payload[0]) {
            @intFromEnum(MutationKind.put) => .put,
            @intFromEnum(MutationKind.delete) => .delete,
            else => return StoreError.UnknownRecordKind,
        };
        const store_family = decodeFamily(payload[1]) orelse return StoreError.UnknownFamily;
        const key_len = readU32(payload[2..][0..4]);
        const value_len = readU32(payload[6..][0..4]);

        const needed = payload_header_len + @as(usize, key_len) +
            if (value_len == tombstone_len) 0 else @as(usize, value_len);
        if (payload.len != needed) return StoreError.BadRecord;

        const key = payload[payload_header_len..][0..key_len];
        if (kind == .delete) {
            if (value_len != tombstone_len) return StoreError.BadRecord;
            try self.applyDelete(store_family, key);
            return;
        }
        if (value_len == tombstone_len) return StoreError.BadRecord;
        const value = payload[payload_header_len + key_len ..][0..value_len];
        try self.applyPut(store_family, key, value);
    }

    fn applyPut(self: *OroStore, store_family: Family, key: []const u8, value: []const u8) !void {
        try self.maps[familyIndex(store_family)].put(key, value);
    }

    fn applyDelete(self: *OroStore, store_family: Family, key: []const u8) !void {
        self.maps[familyIndex(store_family)].delete(key);
    }

    fn recordMutation(
        self: *OroStore,
        sequence: u64,
        store_family: Family,
        kind: MutationKind,
        key: []const u8,
        value: ?[]const u8,
    ) !void {
        if (sequence != self.next_seq) return StoreError.SequenceExhausted;
        try self.changefeed.push(.{
            .seq = sequence,
            .family = store_family,
            .kind = kind,
            .key = key,
            .value = value,
        });
        self.next_seq = try checkedNextSequence(sequence);
    }

    fn reserveSequence(self: *const OroStore) !u64 {
        if (self.next_seq == std.math.maxInt(u64)) return StoreError.SequenceExhausted;
        return self.next_seq;
    }

    fn checkedNextSequence(sequence: u64) !u64 {
        if (sequence == std.math.maxInt(u64)) return StoreError.SequenceExhausted;
        return sequence + 1;
    }

    fn syncDir(self: *OroStore) !void {
        var dir_file = try self.dir.openFile(self.io, ".", .{ .mode = .read_only, .allow_directory = true });
        defer dir_file.close(self.io);
        try dir_file.sync(self.io);
    }
};

const family_count = @typeInfo(Family).@"enum".field_names.len;
const families = std.enums.values(Family);

fn familyIndex(store_family: Family) usize {
    return @intFromEnum(store_family);
}

fn decodeFamily(value: u8) ?Family {
    return std.enums.fromInt(Family, value);
}

fn initMaps(allocator: std.mem.Allocator) [family_count]KvMap {
    var maps: [family_count]KvMap = undefined;
    for (&maps) |*map| map.* = KvMap.init(allocator);
    return maps;
}

const KvMap = struct {
    allocator: std.mem.Allocator,
    map: std.StringHashMap([]u8),

    fn init(allocator: std.mem.Allocator) KvMap {
        return .{
            .allocator = allocator,
            .map = std.StringHashMap([]u8).init(allocator),
        };
    }

    fn deinit(self: *KvMap) void {
        var it = self.map.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.map.deinit();
    }

    fn put(self: *KvMap, key: []const u8, value: []const u8) !void {
        const gop = try self.map.getOrPut(key);
        if (gop.found_existing) {
            const next_value = try self.allocator.dupe(u8, value);
            self.allocator.free(gop.value_ptr.*);
            gop.value_ptr.* = next_value;
            return;
        }

        const owned_key = self.allocator.dupe(u8, key) catch |err| {
            _ = self.map.remove(key);
            return err;
        };
        gop.key_ptr.* = owned_key;
        errdefer {
            // `remove` invalidates `gop.key_ptr`; retain the owned slice and
            // free it only after unlinking the entry. The previous order could
            // read freed map storage during an allocation-failure sweep.
            _ = self.map.removeByPtr(gop.key_ptr);
            self.allocator.free(owned_key);
        }
        gop.value_ptr.* = try self.allocator.dupe(u8, value);
    }

    fn get(self: *const KvMap, key: []const u8) ?[]const u8 {
        return self.map.get(key);
    }

    fn delete(self: *KvMap, key: []const u8) void {
        if (self.map.getEntry(key)) |entry| {
            const owned_key = entry.key_ptr.*;
            const owned_value = entry.value_ptr.*;
            self.map.removeByPtr(entry.key_ptr);
            self.allocator.free(owned_key);
            self.allocator.free(owned_value);
        }
    }
};

const ChangeFeed = struct {
    allocator: std.mem.Allocator,
    entries: []?OwnedMutation,
    start: usize = 0,
    count: usize = 0,

    fn init(allocator: std.mem.Allocator, capacity: usize) !ChangeFeed {
        const entries = try allocator.alloc(?OwnedMutation, capacity);
        @memset(entries, null);
        return .{ .allocator = allocator, .entries = entries };
    }

    fn deinit(self: *ChangeFeed) void {
        for (self.entries) |*entry| {
            if (entry.*) |*mutation| mutation.deinit(self.allocator);
        }
        self.allocator.free(self.entries);
    }

    fn push(self: *ChangeFeed, mutation: Mutation) !void {
        if (self.entries.len == 0) return;

        const owned = try OwnedMutation.from(self.allocator, mutation);

        if (self.count < self.entries.len) {
            const index = (self.start + self.count) % self.entries.len;
            self.entries[index] = owned;
            self.count += 1;
        } else {
            const index = self.start;
            if (self.entries[index]) |*old| old.deinit(self.allocator);
            self.entries[index] = null;
            self.entries[index] = owned;
            self.start = (self.start + 1) % self.entries.len;
        }
    }

    /// Publish an already-owned entry. `PreparedPut.prepare` allocates the
    /// entry before I/O, so this path only swaps pointers and returns an
    /// evicted entry for the store's bounded deferred-retirement queue.
    fn publishPrepared(self: *ChangeFeed, owned: OwnedMutation) ?OwnedMutation {
        if (self.entries.len == 0) {
            return owned;
        }
        if (self.count < self.entries.len) {
            const index = (self.start + self.count) % self.entries.len;
            self.entries[index] = owned;
            self.count += 1;
            return null;
        } else {
            const index = self.start;
            const old = self.entries[index];
            self.entries[index] = owned;
            self.start = (self.start + 1) % self.entries.len;
            return old;
        }
    }

    fn at(self: *const ChangeFeed, index: usize) ?Mutation {
        if (index >= self.count) return null;
        const real_index = (self.start + index) % self.entries.len;
        return self.entries[real_index].?.view();
    }
};

const OwnedMutation = struct {
    seq: u64,
    family: Family,
    kind: MutationKind,
    key: []u8,
    value: ?[]u8,

    fn from(allocator: std.mem.Allocator, mutation: Mutation) !OwnedMutation {
        const owned_key = try allocator.dupe(u8, mutation.key);
        errdefer allocator.free(owned_key);
        const owned_value = if (mutation.value) |value| try allocator.dupe(u8, value) else null;
        return .{
            .seq = mutation.seq,
            .family = mutation.family,
            .kind = mutation.kind,
            .key = owned_key,
            .value = owned_value,
        };
    }

    fn deinit(self: *OwnedMutation, allocator: std.mem.Allocator) void {
        allocator.free(self.key);
        if (self.value) |value| allocator.free(value);
    }

    fn view(self: *const OwnedMutation) Mutation {
        return .{
            .seq = self.seq,
            .family = self.family,
            .kind = self.kind,
            .key = self.key,
            .value = self.value,
        };
    }
};

fn writeRecordAt(
    io: std.Io,
    file: std.Io.File,
    offset: u64,
    allocator: std.mem.Allocator,
    kind: MutationKind,
    store_family: Family,
    key: []const u8,
    value: []const u8,
    max_record_bytes: usize,
) !u64 {
    const payload_len = try checkedPayloadLen(kind, key, value, max_record_bytes);
    const record_len = std.math.add(usize, record_header_len, payload_len) catch return StoreError.RecordTooLarge;

    const record = try allocator.alloc(u8, record_len);
    defer allocator.free(record);

    writeU32(record[0..4], @intCast(payload_len));
    const payload = record[record_header_len..];
    payload[0] = @intFromEnum(kind);
    payload[1] = @intFromEnum(store_family);
    writeU32(payload[2..][0..4], @intCast(key.len));
    writeU32(payload[6..][0..4], if (kind == .delete) tombstone_len else @as(u32, @intCast(value.len)));
    @memcpy(payload[payload_header_len..][0..key.len], key);
    if (kind == .put)
        @memcpy(payload[payload_header_len + key.len ..][0..value.len], value);
    writeU32(record[4..][0..4], checksum(payload));

    try file.writePositionalAll(io, record, offset);
    return offset + record.len;
}

fn isAllowedMetaPayloadLen(payload_len: u32) bool {
    return payload_len == meta_next_seq_payload_len or
        payload_len == wal_epoch_payload_len or
        payload_len == snapshot_coverage_payload_len or
        payload_len == snapshot_coverage_v1_payload_len;
}

fn parseWalEpoch(payload: []const u8) ![wal_epoch_len]u8 {
    if (payload.len != wal_epoch_payload_len or payload[0] != meta_kind_wal_epoch)
        return StoreError.BadRecord;
    var epoch: [wal_epoch_len]u8 = undefined;
    @memcpy(&epoch, payload[1..]);
    return epoch;
}

fn parseSnapshotCoverage(payload: []const u8) !SnapshotCoverage {
    if ((payload.len != snapshot_coverage_payload_len and payload.len != snapshot_coverage_v1_payload_len) or payload[0] != meta_kind_snapshot_coverage)
        return StoreError.BadRecord;
    var coverage = SnapshotCoverage{ .slots = undefined, .count = 0 };
    if (payload.len == snapshot_coverage_v1_payload_len) {
        if (payload[1] != 1 or payload[2] != 1) return StoreError.SnapshotCoverageMismatch;
        var slot = CoverageSlot{ .covered_len = readU64(payload[3..11]), .epoch = undefined, .digest = undefined };
        @memcpy(&slot.epoch, payload[11..27]);
        @memcpy(&slot.digest, payload[27..]);
        coverage.slots[0] = slot;
        coverage.count = 1;
        return coverage;
    }
    if (payload[1] != snapshot_coverage_version or payload[2] == 0 or payload[2] > 2) {
        return StoreError.SnapshotCoverageMismatch;
    }
    var i: usize = 0;
    while (i < payload[2]) : (i += 1) {
        const start = 3 + i * snapshot_coverage_slot_len;
        var covered_bytes: [8]u8 = undefined;
        @memcpy(&covered_bytes, payload[start .. start + 8]);
        var slot = CoverageSlot{ .covered_len = readU64(&covered_bytes), .epoch = undefined, .digest = undefined };
        @memcpy(&slot.epoch, payload[start + 8 .. start + 8 + wal_epoch_len]);
        @memcpy(&slot.digest, payload[start + 8 + wal_epoch_len .. start + snapshot_coverage_slot_len]);
        coverage.slots[i] = slot;
    }
    coverage.count = payload[2];
    return coverage;
}

fn checkedPayloadLen(
    kind: MutationKind,
    key: []const u8,
    value: []const u8,
    max_record_bytes: usize,
) !usize {
    if (key.len > std.math.maxInt(u32) or (kind == .put and value.len > std.math.maxInt(u32)))
        return StoreError.RecordTooLarge;
    var payload_len = std.math.add(usize, payload_header_len, key.len) catch return StoreError.RecordTooLarge;
    if (kind == .put) payload_len = std.math.add(usize, payload_len, value.len) catch return StoreError.RecordTooLarge;
    if (payload_len > max_record_bytes) return StoreError.RecordTooLarge;
    return payload_len;
}

fn recordSize(kind: MutationKind, key: []const u8, value: []const u8, max_record_bytes: usize) !usize {
    const payload_len = try checkedPayloadLen(kind, key, value, max_record_bytes);
    return std.math.add(usize, record_header_len, payload_len) catch StoreError.RecordTooLarge;
}

fn writeNextSeqRecordAt(
    io: std.Io,
    file: std.Io.File,
    offset: u64,
    allocator: std.mem.Allocator,
    next_seq: u64,
) !u64 {
    const record = try allocator.alloc(u8, record_header_len + meta_next_seq_payload_len);
    defer allocator.free(record);

    writeU32(record[0..4], meta_next_seq_payload_len);
    const payload = record[record_header_len..];
    payload[0] = meta_kind_next_seq;
    writeU64(payload[1..9], next_seq);
    writeU32(record[4..][0..4], checksum(payload));

    try file.writePositionalAll(io, record, offset);
    return offset + record.len;
}

fn writeWalEpochRecordAt(
    io: std.Io,
    file: std.Io.File,
    offset: u64,
    allocator: std.mem.Allocator,
    epoch: *const [wal_epoch_len]u8,
) !u64 {
    const record_len = record_header_len + wal_epoch_payload_len;
    const record = try allocator.alloc(u8, record_len);
    defer allocator.free(record);
    writeU32(record[0..4], wal_epoch_payload_len);
    const payload = record[record_header_len..];
    payload[0] = meta_kind_wal_epoch;
    @memcpy(payload[1..], epoch);
    writeU32(record[4..8], checksum(payload));
    try file.writePositionalAll(io, record, offset);
    return offset + record.len;
}

fn writeSnapshotCoverageRecordAt(
    io: std.Io,
    file: std.Io.File,
    offset: u64,
    allocator: std.mem.Allocator,
    coverage: *const SnapshotCoverage,
) !u64 {
    const record_len = record_header_len + snapshot_coverage_payload_len;
    const record = try allocator.alloc(u8, record_len);
    defer allocator.free(record);
    writeU32(record[0..4], snapshot_coverage_payload_len);
    const payload = record[record_header_len..];
    payload[0] = meta_kind_snapshot_coverage;
    payload[1] = snapshot_coverage_version;
    payload[2] = @intCast(coverage.count);
    for (coverage.slots[0..coverage.count], 0..) |slot, i| {
        const start = 3 + i * snapshot_coverage_slot_len;
        var covered_bytes: [8]u8 = undefined;
        writeU64(&covered_bytes, slot.covered_len);
        @memcpy(payload[start .. start + 8], &covered_bytes);
        @memcpy(payload[start + 8 .. start + 8 + wal_epoch_len], &slot.epoch);
        @memcpy(payload[start + 8 + wal_epoch_len .. start + snapshot_coverage_slot_len], &slot.digest);
    }
    writeU32(record[4..8], checksum(payload));
    try file.writePositionalAll(io, record, offset);
    return offset + record.len;
}

fn isMutationPayload(payload: []const u8) bool {
    if (payload.len == 0) return false;
    return payload[0] == @intFromEnum(MutationKind.put) or
        payload[0] == @intFromEnum(MutationKind.delete);
}

fn checksum(payload: []const u8) u32 {
    return std.hash.Fnv1a_32.hash(payload);
}

fn readU32(bytes: *const [4]u8) u32 {
    return std.mem.readInt(u32, bytes, .little);
}

fn readU64(bytes: *const [8]u8) u64 {
    return std.mem.readInt(u64, bytes, .little);
}

fn writeU32(bytes: *[4]u8, value: u32) void {
    std.mem.writeInt(u32, bytes, value, .little);
}

fn writeU64(bytes: *[8]u8, value: u64) void {
    std.mem.writeInt(u64, bytes, value, .little);
}

fn openTestStore(tmp: std.testing.TmpDir, name: []const u8) !OroStore {
    return OroStore.open(std.testing.allocator, std.testing.io, tmp.dir, name);
}

fn readWalForTest(tmp: std.testing.TmpDir, name: []const u8) ![]u8 {
    return tmp.dir.readFileAlloc(std.testing.io, name, std.testing.allocator, .unlimited);
}

fn rewriteTestFile(tmp: std.testing.TmpDir, name: []const u8, bytes: []const u8) !void {
    var file = try tmp.dir.createFile(std.testing.io, name, .{ .truncate = true, .read = true });
    defer file.close(std.testing.io);
    try file.writePositionalAll(std.testing.io, bytes, 0);
    try file.sync(std.testing.io);
}

fn refreshRecordChecksum(bytes: []u8, payload_start: usize) void {
    const payload_len = readU32(bytes[payload_start - record_header_len ..][0..4]);
    var sum_bytes: [4]u8 = undefined;
    writeU32(&sum_bytes, checksum(bytes[payload_start .. payload_start + payload_len]));
    @memcpy(bytes[payload_start - 4 .. payload_start], &sum_bytes);
}

fn findRecordPayloadByKind(bytes: []const u8, kind: u8) ?usize {
    var offset: usize = 0;
    while (bytes.len - offset >= record_header_len) {
        const payload_len: usize = readU32(bytes[offset..][0..4]);
        const payload_start = offset + record_header_len;
        const record_end = std.math.add(usize, payload_start, payload_len) catch return null;
        if (record_end > bytes.len) return null;
        if (payload_len != 0 and bytes[payload_start] == kind) return payload_start;
        offset = record_end;
    }
    return null;
}

test "put/get round-trip per family" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "roundtrip.wal");
    defer store.deinit();

    try store.family(.accounts).put("alice", "account:alice");
    try store.family(.nicks).put("Alice", "alice");
    try store.family(.chanregs).put("#zig", "founder=alice");
    try store.family(.bans).put("kline:test", "bad.host");
    try store.family(.memos).put("memo:1", "hello");
    try store.family(.vhosts).put("alice", "staff.example");
    try store.family(.props).put("#zig:title", "Zig");
    try store.family(.history).put("#zig:1", "message");

    try std.testing.expectEqualStrings("account:alice", store.family(.accounts).get("alice").?);
    try std.testing.expectEqualStrings("alice", store.family(.nicks).get("Alice").?);
    try std.testing.expectEqualStrings("founder=alice", store.family(.chanregs).get("#zig").?);
    try std.testing.expectEqualStrings("bad.host", store.family(.bans).get("kline:test").?);
    try std.testing.expectEqualStrings("hello", store.family(.memos).get("memo:1").?);
    try std.testing.expectEqualStrings("staff.example", store.family(.vhosts).get("alice").?);
    try std.testing.expectEqualStrings("Zig", store.family(.props).get("#zig:title").?);
    try std.testing.expectEqualStrings("message", store.family(.history).get("#zig:1").?);
}

test "WAL replay reconstructs state after reopen" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "replay.wal");
        defer store.deinit();
        try store.family(.accounts).put("alice", "v1");
        try store.family(.accounts).put("alice", "v2");
        try store.family(.history).put("#z:1", "hi");
    }
    {
        var store = try openTestStore(tmp, "replay.wal");
        defer store.deinit();
        try std.testing.expectEqualStrings("v2", store.family(.accounts).get("alice").?);
        try std.testing.expectEqualStrings("hi", store.family(.history).get("#z:1").?);
    }
}

test "checksum mismatch is detected and rejected" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "bad.wal");
        defer store.deinit();
        try store.family(.accounts).put("alice", "ok");
        try store.family(.accounts).put("bob", "still-ok");
    }

    var file = try tmp.dir.openFile(std.testing.io, "bad.wal", .{ .mode = .read_write, .allow_directory = false });
    defer file.close(std.testing.io);
    try file.writePositionalAll(std.testing.io, &.{0xAA}, 6);

    try std.testing.expectError(StoreError.ChecksumMismatch, openTestStore(tmp, "bad.wal"));
}

test "torn final WAL record is ignored after replaying valid prefix" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "torn.wal");
        defer store.deinit();
        try store.family(.accounts).put("alice", "ok");
    }

    var file = try tmp.dir.openFile(std.testing.io, "torn.wal", .{ .mode = .read_write, .allow_directory = false });
    defer file.close(std.testing.io);
    const stat = try file.stat(std.testing.io);
    try file.writePositionalAll(std.testing.io, &.{ 1, 0, 0, 0 }, stat.size);
    try file.sync(std.testing.io);

    var store = try openTestStore(tmp, "torn.wal");
    defer store.deinit();
    try std.testing.expectEqualStrings("ok", store.family(.accounts).get("alice").?);
}

test "checksum-bad final WAL record is ignored after replaying valid prefix" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "final-checksum.wal");
        defer store.deinit();
        try store.family(.accounts).put("alice", "ok");
    }

    var file = try tmp.dir.openFile(std.testing.io, "final-checksum.wal", .{ .mode = .read_write, .allow_directory = false });
    defer file.close(std.testing.io);
    const stat = try file.stat(std.testing.io);
    _ = try writeRecordAt(std.testing.io, file, stat.size, std.testing.allocator, .put, .accounts, "bob", "bad", default_max_record_len);
    try file.writePositionalAll(std.testing.io, &.{0xAA}, stat.size + 6);
    try file.sync(std.testing.io);

    var store = try openTestStore(tmp, "final-checksum.wal");
    defer store.deinit();
    try std.testing.expectEqualStrings("ok", store.family(.accounts).get("alice").?);
    try std.testing.expect(store.family(.accounts).get("bob") == null);
}

test "torn WAL tail is truncated at open so a later append cannot poison the log" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "poison.wal");
        defer store.deinit();
        try store.family(.accounts).put("alice", "ok");
    }

    // Crash mid-append: a garbage torn tail lands after the valid prefix.
    {
        var file = try tmp.dir.openFile(std.testing.io, "poison.wal", .{ .mode = .read_write, .allow_directory = false });
        defer file.close(std.testing.io);
        const stat = try file.stat(std.testing.io);
        try file.writePositionalAll(std.testing.io, &.{ 9, 0, 0, 0, 0xDE, 0xAD }, stat.size);
        try file.sync(std.testing.io);
    }

    // First reopen tolerates the tail — and must TRUNCATE it before serving,
    // otherwise the append below lands after the garbage and the SECOND
    // reopen fails outright (the bad bytes are then no longer the final
    // record, so the tail tolerance no longer applies). This exact sequence
    // used to brick the live SASL account store after a power loss.
    {
        var store = try openTestStore(tmp, "poison.wal");
        defer store.deinit();
        try store.family(.accounts).put("bob", "also-ok");
    }

    var store = try openTestStore(tmp, "poison.wal");
    defer store.deinit();
    try std.testing.expectEqualStrings("ok", store.family(.accounts).get("alice").?);
    try std.testing.expectEqualStrings("also-ok", store.family(.accounts).get("bob").?);
}

test "zero-filled final WAL tail is truncated at open (in-flight torn tail)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "zerotail.wal");
        defer store.deinit();
        try store.family(.accounts).put("alice", "ok");
    }

    // Crash mid-append leaves a short run of zero bytes (a partial header +
    // partial payload) after the valid prefix. A zero header decodes to a
    // 0-length record whose empty-payload checksum (0x811c9dc5) never matches
    // the zero sum, and record_end lands BEFORE EOF because trailing zeros
    // remain — the exact asymmetry that used to hard-fail replay.
    {
        var file = try tmp.dir.openFile(std.testing.io, "zerotail.wal", .{ .mode = .read_write, .allow_directory = false });
        defer file.close(std.testing.io);
        const stat = try file.stat(std.testing.io);
        const zeros = std.mem.zeroes([12]u8);
        try file.writePositionalAll(std.testing.io, &zeros, stat.size);
        try file.sync(std.testing.io);
    }

    // First reopen tolerates AND truncates the torn tail; a later append must
    // land on the valid prefix, so the second reopen sees both records (an
    // untruncated log would refuse to open on the second pass).
    {
        var store = try openTestStore(tmp, "zerotail.wal");
        defer store.deinit();
        try std.testing.expectEqualStrings("ok", store.family(.accounts).get("alice").?);
        try store.family(.accounts).put("bob", "also-ok");
    }

    var store = try openTestStore(tmp, "zerotail.wal");
    defer store.deinit();
    try std.testing.expectEqualStrings("ok", store.family(.accounts).get("alice").?);
    try std.testing.expectEqualStrings("also-ok", store.family(.accounts).get("bob").?);
}

test "oversize final WAL header is truncated at open (in-flight torn tail)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "oversize.wal");
        defer store.deinit();
        try store.family(.accounts).put("alice", "ok");
    }

    // Crash mid-append leaves a header whose declared length overruns the file
    // (here max_record_bytes+1) with no payload behind it.
    {
        var file = try tmp.dir.openFile(std.testing.io, "oversize.wal", .{ .mode = .read_write, .allow_directory = false });
        defer file.close(std.testing.io);
        const stat = try file.stat(std.testing.io);
        var header: [record_header_len]u8 = undefined;
        writeU32(header[0..4], default_max_record_len + 1);
        writeU32(header[4..8], 0);
        try file.writePositionalAll(std.testing.io, &header, stat.size);
        try file.sync(std.testing.io);
    }

    {
        var store = try openTestStore(tmp, "oversize.wal");
        defer store.deinit();
        try std.testing.expectEqualStrings("ok", store.family(.accounts).get("alice").?);
        try store.family(.accounts).put("bob", "also-ok");
    }

    var store = try openTestStore(tmp, "oversize.wal");
    defer store.deinit();
    try std.testing.expectEqualStrings("ok", store.family(.accounts).get("alice").?);
    try std.testing.expectEqualStrings("also-ok", store.family(.accounts).get("bob").?);
}

test "WAL compacts into the snapshot once it crosses half the replay limit" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Tiny WAL budget so a few puts cross the max_wal_bytes/2 threshold.
    {
        var store = try OroStore.openWithConfig(
            std.testing.allocator,
            std.testing.io,
            tmp.dir,
            "compact.wal",
            .{ .max_wal_bytes = 256 },
        );
        defer store.deinit();
        var i: u8 = 0;
        while (i < 8) : (i += 1) {
            var key: [4]u8 = .{ 'k', '0' + i, 0, 0 };
            try store.family(.accounts).put(key[0..2], "value-payload");
        }
        // The log must have been folded into the snapshot at least once —
        // an uncompacted WAL here would exceed the whole 256-byte budget and
        // the NEXT open would refuse to replay it (RecordTooLarge).
        try std.testing.expect(store.wal_offset < 256);
    }

    var store = try OroStore.openWithConfig(
        std.testing.allocator,
        std.testing.io,
        tmp.dir,
        "compact.wal",
        .{ .max_wal_bytes = 256 },
    );
    defer store.deinit();
    var i: u8 = 0;
    while (i < 8) : (i += 1) {
        var key: [4]u8 = .{ 'k', '0' + i, 0, 0 };
        try std.testing.expectEqualStrings("value-payload", store.family(.accounts).get(key[0..2]).?);
    }
}

test "snapshot+truncate preserves data" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "snapshot.wal");
        defer store.deinit();
        try store.family(.accounts).put("alice", "v1");
        try store.family(.nicks).put("Alice", "alice");
        try store.snapshotAndTruncate();
        try store.family(.accounts).put("bob", "v2");
    }
    {
        var store = try openTestStore(tmp, "snapshot.wal");
        defer store.deinit();
        try std.testing.expectEqualStrings("v1", store.family(.accounts).get("alice").?);
        try std.testing.expectEqualStrings("alice", store.family(.nicks).get("Alice").?);
        try std.testing.expectEqualStrings("v2", store.family(.accounts).get("bob").?);
    }
}

test "changefeed sequence persists across snapshot reopen" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "seq.wal");
        defer store.deinit();
        try store.family(.accounts).put("alice", "v1");
        try store.snapshotAndTruncate();
    }
    {
        var store = try openTestStore(tmp, "seq.wal");
        defer store.deinit();
        try store.family(.accounts).put("bob", "v2");
        const mutation = store.changeAt(0).?;
        try std.testing.expectEqual(@as(u64, 2), mutation.seq);
        try std.testing.expectEqualStrings("bob", mutation.key);
    }
}

test "changefeed records mutations" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "changes.wal");
    defer store.deinit();

    try store.family(.accounts).put("alice", "v1");
    try store.family(.accounts).put("bob", "v2");
    try store.family(.accounts).delete("alice");

    try std.testing.expectEqual(@as(usize, 3), store.changeCount());
    const first = store.changeAt(0).?;
    try std.testing.expectEqual(@as(u64, 1), first.seq);
    try std.testing.expectEqual(Family.accounts, first.family);
    try std.testing.expectEqual(MutationKind.put, first.kind);
    try std.testing.expectEqualStrings("alice", first.key);
    try std.testing.expectEqualStrings("v1", first.value.?);

    const last = store.changeAt(2).?;
    try std.testing.expectEqual(@as(u64, 3), last.seq);
    try std.testing.expectEqual(MutationKind.delete, last.kind);
    try std.testing.expectEqualStrings("alice", last.key);
    try std.testing.expect(last.value == null);
    try std.testing.expect(store.family(.accounts).get("alice") == null);
}

test "storage Config defaults preserve historical limits" {
    const cfg = Config{};
    try std.testing.expectEqual(@as(usize, default_max_record_len), cfg.max_record_bytes);
    try std.testing.expectEqual(@as(usize, default_max_wal_len), cfg.max_wal_bytes);
    try std.testing.expectEqual(@as(usize, default_changefeed_capacity), cfg.changefeed_capacity);
}

test "storage Config.applyToml overlays [storage] keys" {
    var doc = try toml.parse(
        std.testing.allocator,
        "[storage]\nmax_record_bytes = 65536\nmax_wal_bytes = 1048576\nchangefeed_capacity = 128\n",
    );
    defer doc.deinit(std.testing.allocator);

    var cfg = Config{};
    cfg.applyToml(&doc);
    try std.testing.expectEqual(@as(usize, 65536), cfg.max_record_bytes);
    try std.testing.expectEqual(@as(usize, 1048576), cfg.max_wal_bytes);
    try std.testing.expectEqual(@as(usize, 128), cfg.changefeed_capacity);
}

test "storage Config.applyToml leaves defaults when section absent" {
    var doc = try toml.parse(std.testing.allocator, "[other]\nx = 1\n");
    defer doc.deinit(std.testing.allocator);

    var cfg = Config{};
    cfg.applyToml(&doc);
    try std.testing.expectEqual(@as(usize, default_max_record_len), cfg.max_record_bytes);
    try std.testing.expectEqual(@as(usize, default_max_wal_len), cfg.max_wal_bytes);
    try std.testing.expectEqual(@as(usize, default_changefeed_capacity), cfg.changefeed_capacity);
}

test "opened store exposes authoritative default admission limits" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "admission-defaults.wal");
    defer store.deinit();
    const limits = store.admissionLimits();
    try std.testing.expectEqual(@as(usize, default_max_record_len), limits.max_record_bytes);
    try std.testing.expectEqual(@as(usize, default_max_wal_len), limits.max_wal_bytes);
}

test "opened store exposes exact custom admission limits" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try OroStore.openWithConfig(
        std.testing.allocator,
        std.testing.io,
        tmp.dir,
        "admission-custom.wal",
        .{
            .max_record_bytes = 128,
            .max_wal_bytes = 1024,
            .changefeed_capacity = 7,
        },
    );
    defer store.deinit();
    const limits = store.admissionLimits();
    try std.testing.expectEqual(@as(usize, 128), limits.max_record_bytes);
    try std.testing.expectEqual(@as(usize, 1024), limits.max_wal_bytes);
}

test "openWithConfig honours a smaller record limit" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try OroStore.openWithConfig(
        std.testing.allocator,
        std.testing.io,
        tmp.dir,
        "cfg-limit.wal",
        .{ .max_record_bytes = 16 },
    );
    defer store.deinit();

    try std.testing.expectError(
        StoreError.RecordTooLarge,
        store.family(.accounts).put("alice", "this value is definitely longer than sixteen bytes"),
    );
}

test "STORE prepared put reserves then commits insert and replacement" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "prepared-roundtrip.wal");
    defer store.deinit();

    var insert = try store.preparePut(.accounts, "alice", "v1");
    defer insert.deinit();
    try std.testing.expect(store.family(.accounts).get("alice") == null);
    try std.testing.expectEqual(@as(usize, 0), store.changeCount());
    try insert.commit();
    try std.testing.expectEqualStrings("v1", store.family(.accounts).get("alice").?);
    try std.testing.expectEqual(@as(usize, 1), store.changeCount());
    try std.testing.expectEqual(@as(u64, 2), store.next_seq);
    try std.testing.expectError(StoreError.PreparedAlreadyConsumed, insert.commit());

    var replace = try store.preparePut(.accounts, "alice", "v2");
    defer replace.deinit();
    try std.testing.expectEqualStrings("v1", store.family(.accounts).get("alice").?);
    try replace.commit();
    try std.testing.expectEqualStrings("v2", store.family(.accounts).get("alice").?);
    try std.testing.expectEqual(@as(usize, 2), store.changeCount());
    try std.testing.expectEqual(@as(u64, 3), store.next_seq);
}

test "STORE prepared put abort and deinit are byte inert" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "prepared-abort.wal");
    defer store.deinit();
    try store.family(.accounts).put("alice", "old");
    const before_wal = try readWalForTest(tmp, "prepared-abort.wal");
    defer std.testing.allocator.free(before_wal);
    const before_offset = store.wal_offset;
    const before_seq = store.next_seq;
    const before_changes = store.changeCount();

    var aborted = try store.preparePut(.accounts, "alice", "new");
    aborted.abort();
    aborted.deinit();
    try std.testing.expectEqualStrings("old", store.family(.accounts).get("alice").?);
    try std.testing.expectEqual(before_offset, store.wal_offset);
    const after_abort_wal = try readWalForTest(tmp, "prepared-abort.wal");
    defer std.testing.allocator.free(after_abort_wal);
    try std.testing.expectEqualSlices(u8, before_wal, after_abort_wal);
    try std.testing.expectEqual(before_seq, store.next_seq);
    try std.testing.expectEqual(before_changes, store.changeCount());

    {
        var dropped = try store.preparePut(.accounts, "bob", "never-published");
        dropped.deinit();
    }
    try std.testing.expect(store.family(.accounts).get("bob") == null);
    try std.testing.expectEqual(before_offset, store.wal_offset);
    try std.testing.expectEqual(before_seq, store.next_seq);
    try std.testing.expectEqual(before_changes, store.changeCount());
}

test "STORE prepared lane serializes ordinary and second prepared mutations" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "prepared-serial.wal");
    defer store.deinit();

    var held = try store.preparePut(.accounts, "alice", "v1");
    defer held.deinit();
    try std.testing.expectError(StoreError.PreparedMutationActive, store.preparePut(.accounts, "bob", "v2"));
    try std.testing.expectError(StoreError.PreparedMutationActive, store.put(.accounts, "bob", "v2"));
    try std.testing.expectError(StoreError.PreparedMutationActive, store.delete(.accounts, "alice"));
    try held.commit();
    try store.family(.accounts).put("bob", "v2");
    try std.testing.expectEqualStrings("v2", store.family(.accounts).get("bob").?);
}

test "STORE prepared put write and sync ambiguity poison without publication" {
    const FaultCase = struct {
        fault: PreparedIoFault,
        name: []const u8,
    };
    const cases = [_]FaultCase{
        .{ .fault = .{ .write = .failed }, .name = "prepared-failed.wal" },
        .{ .fault = .{ .write = .short }, .name = "prepared-short.wal" },
        .{ .fault = .{ .sync = true }, .name = "prepared-sync.wal" },
    };

    for (cases) |case| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var store = try openTestStore(tmp, case.name);
        defer store.deinit();
        store.setPreparedIoFault(case.fault);

        var prepared = try store.preparePut(.accounts, "alice", "v1");
        defer prepared.deinit();
        try std.testing.expectError(StoreError.IoAmbiguous, prepared.commit());
        try std.testing.expect(store.preparedWritesPoisoned());
        try std.testing.expect(store.family(.accounts).get("alice") == null);
        try std.testing.expectEqual(@as(usize, 0), store.changeCount());
        try std.testing.expectEqual(@as(u64, 1), store.next_seq);
        try std.testing.expectError(StoreError.StorePoisoned, store.put(.accounts, "bob", "blocked"));
        try std.testing.expectError(StoreError.StorePoisoned, store.preparePut(.accounts, "bob", "blocked"));
    }
}

test "STORE ambiguous prepared outcomes are resolved only by durable reopen" {
    const FaultCase = struct {
        fault: PreparedIoFault,
        name: []const u8,
        durable: bool,
    };
    const cases = [_]FaultCase{
        .{ .fault = .{ .write = .failed }, .name = "prepared-reopen-failed.wal", .durable = false },
        .{ .fault = .{ .write = .short }, .name = "prepared-reopen-short.wal", .durable = false },
        .{ .fault = .{ .sync = true }, .name = "prepared-reopen-sync.wal", .durable = true },
    };

    for (cases) |case| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        {
            var store = try openTestStore(tmp, case.name);
            defer store.deinit();
            store.setPreparedIoFault(case.fault);
            var prepared = try store.preparePut(.props, "dprop1:snapshot", "snapshot-v1");
            defer prepared.deinit();
            try std.testing.expectError(StoreError.IoAmbiguous, prepared.commit());
            try std.testing.expect(store.family(.props).get("dprop1:snapshot") == null);
        }
        var reopened = try openTestStore(tmp, case.name);
        defer reopened.deinit();
        if (case.durable) {
            try std.testing.expectEqualStrings("snapshot-v1", reopened.family(.props).get("dprop1:snapshot").?);
        } else {
            try std.testing.expect(reopened.family(.props).get("dprop1:snapshot") == null);
        }
    }
}

test "DPROP prepared put durable reopen matches successful publication" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var store = try openTestStore(tmp, "dprop1-reopen.wal");
        defer store.deinit();
        var prepared = try store.preparePut(.props, "dprop1:snapshot", "snapshot-v1");
        defer prepared.deinit();
        try prepared.commit();
    }
    var reopened = try openTestStore(tmp, "dprop1-reopen.wal");
    defer reopened.deinit();
    try std.testing.expectEqualStrings("snapshot-v1", reopened.family(.props).get("dprop1:snapshot").?);
    // Changefeed is intentionally process-local; durable reopen proves the
    // reported committed value, while a fresh feed starts empty.
    try std.testing.expectEqual(@as(usize, 0), reopened.changeCount());
}

test "DPROP prepared admission compacts before commit when projected WAL is due" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try OroStore.openWithConfig(
        std.testing.allocator,
        std.testing.io,
        tmp.dir,
        "dprop1-compact.wal",
        .{ .max_wal_bytes = 256 },
    );
    defer store.deinit();
    var prepared = try store.preparePut(.props, "dprop1:snapshot", "snapshot-v1");
    defer prepared.deinit();
    try prepared.commit();
    try std.testing.expectEqualStrings("snapshot-v1", store.family(.props).get("dprop1:snapshot").?);
    var reopened = try OroStore.openWithConfig(
        std.testing.allocator,
        std.testing.io,
        tmp.dir,
        "dprop1-compact.wal",
        .{ .max_wal_bytes = 256 },
    );
    defer reopened.deinit();
    try std.testing.expectEqualStrings("snapshot-v1", reopened.family(.props).get("dprop1:snapshot").?);
}

test "STORE prepared put enforces record and WAL capacity before admission" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try OroStore.openWithConfig(
        std.testing.allocator,
        std.testing.io,
        tmp.dir,
        "prepared-limits.wal",
        .{ .max_record_bytes = 16, .max_wal_bytes = 128 },
    );
    defer store.deinit();
    try std.testing.expectError(StoreError.RecordTooLarge, store.preparePut(.accounts, "alice", "0123456789abcdef"));
    try std.testing.expectEqual(@as(u64, 1), store.next_seq);
    try std.testing.expectEqual(@as(usize, 0), store.changeCount());
}

test "STORE prepared put reserves every allocation atomically" {
    const Sweep = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var tmp = std.testing.tmpDir(.{});
            defer tmp.cleanup();
            var store = try OroStore.open(allocator, std.testing.io, tmp.dir, "prepared-oom.wal");
            defer store.deinit();
            try store.family(.accounts).put("stable", "before");
            const before_wal = try readWalForTest(tmp, "prepared-oom.wal");
            defer std.testing.allocator.free(before_wal);
            const before_offset = store.wal_offset;
            const before_seq = store.next_seq;
            const before_changes = store.changeCount();

            var prepared = store.preparePut(.accounts, "candidate", "value") catch |err| {
                if (err != error.OutOfMemory) return err;
                try std.testing.expectEqualStrings("before", store.family(.accounts).get("stable").?);
                try std.testing.expect(store.family(.accounts).get("candidate") == null);
                try std.testing.expectEqual(before_offset, store.wal_offset);
                const after_wal = try readWalForTest(tmp, "prepared-oom.wal");
                defer std.testing.allocator.free(after_wal);
                try std.testing.expectEqualSlices(u8, before_wal, after_wal);
                try std.testing.expectEqual(before_seq, store.next_seq);
                try std.testing.expectEqual(before_changes, store.changeCount());
                return err;
            };
            defer prepared.deinit();
            try prepared.commit();
            try std.testing.expectEqualStrings("value", store.family(.accounts).get("candidate").?);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Sweep.run, .{});
}

test "STORE prepared token owns stable key after caller mutation and free" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "prepared-stable-key.wal");
    const caller_key = try std.testing.allocator.dupe(u8, "stable-key");
    var prepared = try store.preparePut(.accounts, caller_key, "value");
    @memset(@constCast(caller_key), 'x');
    std.testing.allocator.free(caller_key);
    try prepared.commit();
    prepared.deinit();
    try std.testing.expectEqualStrings("value", store.family(.accounts).get("stable-key").?);
    store.deinit();

    var reopened = try openTestStore(tmp, "prepared-stable-key.wal");
    defer reopened.deinit();
    try std.testing.expectEqualStrings("value", reopened.family(.accounts).get("stable-key").?);
}

test "STORE copied and stale prepared tokens cannot affect a newer reservation" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "prepared-generation.wal");
    defer store.deinit();

    var first = try store.preparePut(.accounts, "first", "one");
    var copied = first;
    try copied.commit();
    try std.testing.expectError(StoreError.PreparedAlreadyConsumed, first.commit());

    var second = try store.preparePut(.accounts, "second", "two");
    try std.testing.expectError(StoreError.PreparedAlreadyConsumed, copied.commit());
    first.abort();
    try std.testing.expect(store.family(.accounts).get("second") == null);
    try second.commit();
    try std.testing.expectEqualStrings("one", store.family(.accounts).get("first").?);
    try std.testing.expectEqualStrings("two", store.family(.accounts).get("second").?);
    try std.testing.expectError(StoreError.PreparedAlreadyConsumed, copied.commit());
    copied.deinit();
    first.deinit();
    second.deinit();
}

test "STORE prepared publication performs no allocator work" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = std.math.maxInt(usize) });
    var store = try OroStore.open(failing.allocator(), std.testing.io, tmp.dir, "prepared-no-alloc.wal");
    defer store.deinit();

    var prepared = try store.preparePut(.accounts, "alice", "v1");
    const allocs_before = failing.alloc_index;
    const frees_before = failing.deallocations;
    try prepared.commit();
    try std.testing.expectEqual(allocs_before, failing.alloc_index);
    try std.testing.expectEqual(frees_before, failing.deallocations);
    prepared.deinit();
}

test "STORE prepared sequence exhaustion is rejected before WAL I/O" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "prepared-seq-exhausted.wal");
    defer store.deinit();
    try store.family(.accounts).put("seed", "v");
    const before_wal = try readWalForTest(tmp, "prepared-seq-exhausted.wal");
    defer std.testing.allocator.free(before_wal);
    store.next_seq = std.math.maxInt(u64);
    try std.testing.expectError(StoreError.SequenceExhausted, store.preparePut(.accounts, "alice", "v1"));
    const after_wal = try readWalForTest(tmp, "prepared-seq-exhausted.wal");
    defer std.testing.allocator.free(after_wal);
    try std.testing.expectEqualSlices(u8, before_wal, after_wal);
}

test "STORE prepared admission compacts projected WAL before append" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try OroStore.openWithConfig(
        std.testing.allocator,
        std.testing.io,
        tmp.dir,
        "prepared-projected.wal",
        .{ .max_wal_bytes = 256 },
    );
    defer store.deinit();
    try store.family(.accounts).put("seed", "0123456789012345678901234567890123456789");
    try std.testing.expect(store.wal_offset < 128);
    var prepared = try store.preparePut(.accounts, "next", "0123456789012345678901234567890123456789");
    defer prepared.deinit();
    // Candidate projected size crossed half the hard cap, so compaction ran
    // before the token was admitted. The fresh WAL epoch header is the only
    // prefix left before the candidate reservation.
    try std.testing.expectEqual(@as(u64, record_header_len + wal_epoch_payload_len), store.wal_offset);
    try prepared.commit();
    try std.testing.expect(store.wal_offset <= 256);

    var too_small = try OroStore.openWithConfig(
        std.testing.allocator,
        std.testing.io,
        tmp.dir,
        "prepared-too-small.wal",
        .{ .max_wal_bytes = 32 },
    );
    defer too_small.deinit();
    try std.testing.expectError(StoreError.RecordTooLarge, too_small.preparePut(.accounts, "key", "01234567890123456789"));
}

test "STORE snapshot truncate faults never permit stale append" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var store = try openTestStore(tmp, "prepared-truncate-faults.wal");
        defer store.deinit();
        try store.family(.accounts).put("seed", "v");
        const before_offset = store.wal_offset;

        store.setPreparedIoFault(.{ .snapshot_sync = true });
        try std.testing.expectError(StoreError.SnapshotSyncFailed, store.snapshotAndTruncate());
        try std.testing.expectEqual(before_offset, store.wal_offset);
        store.setPreparedIoFault(.{});
        try store.family(.accounts).put("after-snapshot-fault", "v");

        store.setPreparedIoFault(.{ .wal_truncate = .failed });
        try std.testing.expectError(StoreError.IoAmbiguous, store.snapshotAndTruncate());
        try std.testing.expect(store.preparedWritesPoisoned());
        try std.testing.expectError(StoreError.StorePoisoned, store.put(.accounts, "after-truncate-fault", "v"));
        try std.testing.expectError(StoreError.StorePoisoned, store.preparePut(.accounts, "blocked", "v"));
    }
    var reopened = try openTestStore(tmp, "prepared-truncate-faults.wal");
    defer reopened.deinit();
    try std.testing.expectEqualStrings("v", reopened.family(.accounts).get("seed").?);
    try std.testing.expectEqualStrings("v", reopened.family(.accounts).get("after-snapshot-fault").?);
    try reopened.family(.accounts).put("after-reopen", "v");
}

test "STORE short prepared write reopens and ordinary append remains valid" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var store = try openTestStore(tmp, "prepared-short-recover.wal");
        store.setPreparedIoFault(.{ .write = .short });
        var prepared = try store.preparePut(.accounts, "torn", "value");
        try std.testing.expectError(StoreError.IoAmbiguous, prepared.commit());
        prepared.deinit();
        store.deinit();
    }
    var reopened = try openTestStore(tmp, "prepared-short-recover.wal");
    try std.testing.expect(reopened.family(.accounts).get("torn") == null);
    try reopened.family(.accounts).put("ordinary", "after-reopen");
    try std.testing.expectEqualStrings("after-reopen", reopened.family(.accounts).get("ordinary").?);
    reopened.deinit();
}

test "STORE covered snapshot recovery preserves exact sequence across truncate faults" {
    const FaultCase = struct {
        fault: PreparedIoFault,
        name: []const u8,
    };
    const cases = [_]FaultCase{
        .{ .fault = .{ .wal_truncate = .failed }, .name = "coverage-truncate-failed.wal" },
        .{ .fault = .{ .wal_truncate = .short }, .name = "coverage-truncate-short.wal" },
        .{ .fault = .{ .wal_sync = true }, .name = "coverage-wal-sync.wal" },
    };

    for (cases) |case| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        {
            var store = try openTestStore(tmp, case.name);
            try store.family(.accounts).put("seed", "v1");
            try std.testing.expectEqual(@as(u64, 2), store.next_seq);
            store.setPreparedIoFault(case.fault);
            try std.testing.expectError(StoreError.IoAmbiguous, store.snapshotAndTruncate());
            store.deinit();
        }
        var reopened = try openTestStore(tmp, case.name);
        defer reopened.deinit();
        try std.testing.expectEqual(@as(u64, 2), reopened.next_seq);
        try std.testing.expectEqualStrings("v1", reopened.family(.accounts).get("seed").?);
        try reopened.family(.accounts).put("after-recovery", "v2");
        try std.testing.expectEqual(@as(u64, 3), reopened.next_seq);
        try std.testing.expectEqual(@as(u64, 2), reopened.changeAt(0).?.seq);
    }
}

test "STORE covered snapshot mismatch is fatal for shorter WAL" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var store = try openTestStore(tmp, "coverage-shorter.wal");
        try store.family(.accounts).put("seed", "v");
        try store.snapshotAndTruncate();
        store.deinit();
    }
    var wal = try tmp.dir.openFile(std.testing.io, "coverage-shorter.wal", .{ .mode = .read_write, .allow_directory = false });
    try wal.setLength(std.testing.io, 4);
    wal.close(std.testing.io);
    try std.testing.expectError(
        StoreError.SnapshotCoverageMismatch,
        OroStore.open(std.testing.allocator, std.testing.io, tmp.dir, "coverage-shorter.wal"),
    );
}

test "STORE covered snapshot mismatch is fatal for digest and epoch changes" {
    const Case = enum { digest, epoch };
    for ([_]Case{ .digest, .epoch }) |which| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        {
            var store = try openTestStore(tmp, if (which == .digest) "coverage-digest.wal" else "coverage-epoch.wal");
            try store.family(.accounts).put("seed", "v");
            try store.snapshotAndTruncate();
            store.deinit();
        }
        const name = if (which == .digest) "coverage-digest.wal" else "coverage-epoch.wal";
        if (which == .digest) {
            var snap = try tmp.dir.readFileAlloc(std.testing.io, "coverage-digest.wal.snap", std.testing.allocator, .unlimited);
            defer std.testing.allocator.free(snap);
            const kind_index = findRecordPayloadByKind(snap, meta_kind_snapshot_coverage).?;
            snap[kind_index + 3 + snapshot_coverage_slot_len + 24] ^= 0x01;
            refreshRecordChecksum(snap, kind_index);
            try rewriteTestFile(tmp, "coverage-digest.wal.snap", snap);
        } else {
            var wal = try tmp.dir.readFileAlloc(std.testing.io, name, std.testing.allocator, .unlimited);
            defer std.testing.allocator.free(wal);
            wal[record_header_len + 1] ^= 0x01;
            refreshRecordChecksum(wal, record_header_len);
            try rewriteTestFile(tmp, name, wal);
        }
        try std.testing.expectError(
            StoreError.SnapshotCoverageMismatch,
            OroStore.open(std.testing.allocator, std.testing.io, tmp.dir, name),
        );
    }
}

test "STORE legacy snapshot without coverage replays WAL from zero" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var store = try openTestStore(tmp, "legacy-coverage.wal");
        try store.family(.accounts).put("legacy", "v");
        try store.snapshotAndTruncate();
        store.deinit();
    }
    var snap = try tmp.dir.readFileAlloc(std.testing.io, "legacy-coverage.wal.snap", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(snap);
    const kind_index = findRecordPayloadByKind(snap, meta_kind_snapshot_coverage).?;
    try rewriteTestFile(tmp, "legacy-coverage.wal.snap", snap[0 .. kind_index - record_header_len]);

    var reopened = try openTestStore(tmp, "legacy-coverage.wal");
    defer reopened.deinit();
    try std.testing.expectEqualStrings("v", reopened.family(.accounts).get("legacy").?);
    try std.testing.expectEqual(@as(u64, 2), reopened.next_seq);
}

test "STORE empty WAL crash window recovers rotated coverage epoch" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var store = try openTestStore(tmp, "coverage-empty-crash.wal");
        try store.family(.accounts).put("seed", "v");
        try store.snapshotAndTruncate();
        store.deinit();
    }
    var wal = try tmp.dir.openFile(std.testing.io, "coverage-empty-crash.wal", .{ .mode = .read_write, .allow_directory = false });
    try wal.setLength(std.testing.io, 0);
    wal.close(std.testing.io);

    var reopened = try openTestStore(tmp, "coverage-empty-crash.wal");
    defer reopened.deinit();
    try std.testing.expectEqualStrings("v", reopened.family(.accounts).get("seed").?);
    try std.testing.expectEqual(@as(u64, 2), reopened.next_seq);
    try reopened.family(.accounts).put("after-crash", "v2");
    try std.testing.expectEqual(@as(u64, 3), reopened.next_seq);
    try std.testing.expectEqual(@as(u64, 2), reopened.changeAt(0).?.seq);
}

test "STORE genuine headerless WAL survives snapshot truncate failure" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var wal = try tmp.dir.createFile(std.testing.io, "coverage-legacy-headerless.wal", .{ .truncate = true, .read = true });
        defer wal.close(std.testing.io);
        const end = try writeRecordAt(
            std.testing.io,
            wal,
            0,
            std.testing.allocator,
            .put,
            .accounts,
            "key",
            "1234",
            default_max_record_len,
        );
        // payload_header_len + key.len + value.len deliberately equals the
        // epoch payload width; the kind byte must still identify legacy data.
        try std.testing.expectEqual(@as(u64, record_header_len + wal_epoch_payload_len), end);
        try wal.sync(std.testing.io);
    }
    {
        var store = try openTestStore(tmp, "coverage-legacy-headerless.wal");
        try std.testing.expectEqualStrings("1234", store.family(.accounts).get("key").?);
        try std.testing.expectEqual(@as(u64, 2), store.next_seq);
        store.setPreparedIoFault(.{ .wal_truncate = .failed });
        try std.testing.expectError(StoreError.IoAmbiguous, store.snapshotAndTruncate());
        store.deinit();
    }
    var reopened = try openTestStore(tmp, "coverage-legacy-headerless.wal");
    defer reopened.deinit();
    try std.testing.expectEqualStrings("1234", reopened.family(.accounts).get("key").?);
    try std.testing.expectEqual(@as(u64, 2), reopened.next_seq);
    try reopened.family(.accounts).put("after", "recovery");
    try std.testing.expectEqual(@as(u64, 3), reopened.next_seq);
}

test "STORE checksum-valid zero-length record is rejected without panic" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var record: [record_header_len]u8 = undefined;
    writeU32(record[0..4], 0);
    writeU32(record[4..8], checksum(""));
    try rewriteTestFile(tmp, "zero-payload.wal", &record);
    try std.testing.expectError(
        StoreError.BadRecord,
        OroStore.open(std.testing.allocator, std.testing.io, tmp.dir, "zero-payload.wal"),
    );
}

test "STORE torn equal-width legacy tail is not misclassified as epoch" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var wal = try tmp.dir.createFile(std.testing.io, "legacy-torn-equal-width.wal", .{ .truncate = true, .read = true });
    const end = try writeRecordAt(
        std.testing.io,
        wal,
        0,
        std.testing.allocator,
        .put,
        .accounts,
        "key",
        "1234",
        default_max_record_len,
    );
    try std.testing.expectEqual(@as(u64, record_header_len + wal_epoch_payload_len), end);
    var bad_checksum: [4]u8 = undefined;
    writeU32(&bad_checksum, 0);
    try wal.writePositionalAll(std.testing.io, &bad_checksum, 4);
    try wal.sync(std.testing.io);
    wal.close(std.testing.io);

    var reopened = try openTestStore(tmp, "legacy-torn-equal-width.wal");
    defer reopened.deinit();
    try std.testing.expect(reopened.family(.accounts).get("key") == null);
    try std.testing.expectEqual(@as(u64, 0), reopened.wal_offset);
}

test "STORE ordinary sequence exhaustion is pre-WAL and byte inert" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "ordinary-sequence-exhausted.wal");
    defer store.deinit();
    const before = try readWalForTest(tmp, "ordinary-sequence-exhausted.wal");
    defer std.testing.allocator.free(before);

    store.next_seq = std.math.maxInt(u64);
    try std.testing.expectError(StoreError.SequenceExhausted, store.put(.accounts, "put", "v"));
    const after_put = try readWalForTest(tmp, "ordinary-sequence-exhausted.wal");
    defer std.testing.allocator.free(after_put);
    try std.testing.expectEqualSlices(u8, before, after_put);
    try std.testing.expectError(StoreError.SequenceExhausted, store.delete(.accounts, "delete"));
    const after_delete = try readWalForTest(tmp, "ordinary-sequence-exhausted.wal");
    defer std.testing.allocator.free(after_delete);
    try std.testing.expectEqualSlices(u8, before, after_delete);
}

test "STORE replay sequence exhaustion fails cleanly" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var store = try openTestStore(tmp, "replay-sequence-exhausted.wal");
        try store.ensureWal();
        const file = store.wal_file.?;
        var offset = store.wal_offset;
        offset = try writeNextSeqRecordAt(std.testing.io, file, offset, std.testing.allocator, std.math.maxInt(u64));
        const record_offset = offset;
        offset = try writeRecordAt(
            std.testing.io,
            file,
            offset,
            std.testing.allocator,
            .put,
            .accounts,
            "replay",
            "value",
            store.cfg.max_record_bytes,
        );
        try file.sync(std.testing.io);
        store.wal_offset = offset;
        try std.testing.expect(offset > record_offset);
        store.deinit();
    }
    try std.testing.expectError(
        StoreError.SequenceExhausted,
        OroStore.open(std.testing.allocator, std.testing.io, tmp.dir, "replay-sequence-exhausted.wal"),
    );
}

test "STORE prepared replacement retires all four slots without publication allocation" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = std.math.maxInt(usize) });
    var store = try OroStore.openWithConfig(
        failing.allocator(),
        std.testing.io,
        tmp.dir,
        "prepared-four-retirements.wal",
        .{ .changefeed_capacity = 1 },
    );
    defer store.deinit();
    try store.family(.accounts).put("alice", "old");

    var prepared = try store.preparePut(.accounts, "alice", "new");
    const allocs_before = failing.alloc_index;
    const frees_before = failing.deallocations;
    try prepared.commit();
    try std.testing.expectEqual(allocs_before, failing.alloc_index);
    try std.testing.expectEqual(frees_before, failing.deallocations);
    try std.testing.expectEqual(@as(usize, prepared_retirement_capacity), store.retirement_count);
    try std.testing.expectEqualStrings("new", store.family(.accounts).get("alice").?);

    var next = try store.preparePut(.accounts, "bob", "next");
    try std.testing.expectEqual(@as(usize, 0), store.retirement_count);
    next.abort();
    prepared.deinit();
}
