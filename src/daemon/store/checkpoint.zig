// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Detached first provisioning and cold recovery transactions.

const EngineAccess = @import("engine.zig").Internal;
const std = @import("std");
const cold_identity = @import("../mesh_presence_lease.zig");
const cold_runtime = @import("../os_runtime.zig");
const ChangeFeed = @import("changefeed.zig").ChangeFeed;
const BatchMutation = @import("contracts.zig").BatchMutation;
const Config = @import("contracts.zig").Config;
const CoverageSlot = @import("contracts.zig").CoverageSlot;
const PreparedIoFault = @import("contracts.zig").PreparedIoFault;
const SnapshotCoverage = @import("contracts.zig").SnapshotCoverage;
const StoreError = @import("contracts.zig").StoreError;
const batch_guard_len = @import("contracts.zig").batch_guard_len;
const cold_epoch_record_len = @import("contracts.zig").cold_epoch_record_len;
const families = @import("contracts.zig").families;
const familyIndex = @import("contracts.zig").familyIndex;
const record_header_len = @import("contracts.zig").record_header_len;
const wal_epoch_len = @import("contracts.zig").wal_epoch_len;
const OroStore = @import("engine.zig").OroStore;
const PreparedBatch = @import("engine.zig").PreparedBatch;
const encodeColdSnapshot = @import("engine.zig").encodeColdSnapshot;
const ColdFile = @import("native_files.zig").ColdFile;
const coldDirectoryIdentity = @import("native_files.zig").coldDirectoryIdentity;
const coldOpenParent = @import("native_files.zig").coldOpenParent;
const deinitColdAtomic = @import("native_files.zig").deinitColdAtomic;
const makeColdAtomicReadable = @import("native_files.zig").makeColdAtomicReadable;
const openColdExisting = @import("native_files.zig").openColdExisting;
const renameHeldColdAtomicWindows = @import("native_files.zig").renameHeldColdAtomicWindows;
const requireColdWriteThroughVolumeWindows = @import("native_files.zig").requireColdWriteThroughVolumeWindows;
const validateColdAtomicName = @import("native_files.zig").validateColdAtomicName;
const validateColdLease = @import("native_files.zig").validateColdLease;
const validateColdParent = @import("native_files.zig").validateColdParent;
const validateColdPreparedFile = @import("native_files.zig").validateColdPreparedFile;
const validateColdPreparedRange = @import("native_files.zig").validateColdPreparedRange;
const initMaps = @import("table.zig").initMaps;
const batchPayloadLen = @import("wal.zig").batchPayloadLen;
const coldDigest = @import("wal.zig").coldDigest;
const coldEpoch = @import("wal.zig").coldEpoch;
const parseWalEpoch = @import("wal.zig").parseWalEpoch;

/// Detached explicit first provisioning. Every allocator request precedes WAL
/// publication; OOM can leave only the stable lock and owned private temps.
pub const FirstProvisionStage = struct {
    allocator: std.mem.Allocator,
    store: ?*OroStore,
    lease: std.Io.File,
    identity: cold_identity.Identity,
    lock_path: []u8,
    directory: std.Io.File,
    directory_identity: cold_identity.Identity,
    io: std.Io,
    atomic: ?std.Io.File.Atomic = null,
    atomic_identity: ?cold_identity.Identity = null,
    epoch: [cold_epoch_record_len]u8,
    committed: bool = false,
    consumed: bool = false,

    pub fn init(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, path: []const u8, lease: std.Io.File, config: Config) !FirstProvisionStage {
        const lock_path = try std.mem.concat(allocator, u8, &.{ path, ".lock" });
        errdefer allocator.free(lock_path);
        if (comptime @import("builtin").os.tag == .windows)
            try cold_runtime.requireInheritedPrivateFileWindows(lease);
        const identity = try cold_identity.statRegular(lease.handle);
        try validateColdLease(io, dir, lease, lock_path, identity);
        const owned_path = try allocator.dupe(u8, path);
        errdefer allocator.free(owned_path);
        const snapshot_path = try std.mem.concat(allocator, u8, &.{ path, ".snap" });
        errdefer allocator.free(snapshot_path);
        var feed = try ChangeFeed.init(allocator, config.changefeed_capacity);
        errdefer feed.deinit();
        const store = try allocator.create(OroStore);
        errdefer allocator.destroy(store);
        var epoch: [wal_epoch_len]u8 = undefined;
        io.random(&epoch);
        store.* = .{ .allocator = allocator, .io = io, .dir = dir, .wal_path = owned_path, .snapshot_path = snapshot_path, .maps = initMaps(allocator), .changefeed = feed, .cfg = config, .wal_epoch = epoch, .wal_epoch_known = true, .staged_read_only = true, .private_windows_files = @import("builtin").os.tag == .windows, .wal_offset = cold_epoch_record_len };
        const directory = try coldOpenParent(io, dir, path);
        errdefer directory.close(io);
        if (comptime @import("builtin").os.tag == .windows)
            _ = try cold_runtime.requirePrivateDirectoryHandleWindows(.{ .handle = directory.handle });
        const directory_identity = try coldDirectoryIdentity(directory.handle);
        return .{ .allocator = allocator, .store = store, .lease = lease, .identity = identity, .lock_path = lock_path, .directory = directory, .directory_identity = directory_identity, .io = io, .epoch = coldEpoch(epoch) };
    }

    pub fn prepareBatch(self: *FirstProvisionStage, mutations: []const BatchMutation) !void {
        const store = self.store orelse return StoreError.PreparedAlreadyConsumed;
        if (self.consumed or store.active_batch != null) return StoreError.PreparedMutationActive;
        if (store.next_prepared_generation == std.math.maxInt(u64)) return StoreError.SequenceExhausted;
        const payload = try batchPayloadLen(mutations, store.cfg.max_record_bytes);
        const record = std.math.add(usize, batch_guard_len + record_header_len, payload) catch return StoreError.RecordTooLarge;
        const end = std.math.add(u64, cold_epoch_record_len, record) catch return StoreError.RecordTooLarge;
        if (end > store.cfg.max_wal_bytes) return StoreError.RecordTooLarge;
        const next = std.math.add(u64, store.next_seq, @intCast(mutations.len)) catch return StoreError.SequenceExhausted;
        var batch = try EngineAccess.prepareBatchAt(store, mutations, payload, record, end, next);
        errdefer batch.abort();
        if (comptime @import("builtin").os.tag == .windows) {
            try validateColdLease(store.io, store.dir, self.lease, self.lock_path, self.identity);
            _ = try cold_runtime.requirePrivateDirectoryHandleWindows(.{ .handle = self.directory.handle });
        }
        try validateColdParent(store.io, store.dir, store.wal_path, self.directory, self.directory_identity, null);
        var atomic = if (comptime @import("builtin").os.tag == .windows)
            try (std.Io.Dir{ .handle = self.directory.handle }).createFileAtomic(store.io, std.fs.path.basename(store.wal_path), .{ .replace = false })
        else
            try store.dir.createFileAtomic(store.io, store.wal_path, .{ .replace = false });
        errdefer deinitColdAtomic(store.io, &atomic, null);
        try validateColdParent(store.io, store.dir, store.wal_path, self.directory, self.directory_identity, &atomic);
        if (comptime @import("builtin").os.tag == .windows) {
            if (!atomic.file_exists or !atomic.file_open) return StoreError.SnapshotCoverageMismatch;
        }
        if (atomic.file_exists) {
            if (comptime @import("builtin").os.tag == .windows)
                try EngineAccess.secureColdAtomicWindows(store, &atomic)
            else
                try makeColdAtomicReadable(store.io, &atomic);
        }
        try atomic.file.writePositionalAll(store.io, &self.epoch, 0);
        try atomic.file.writePositionalAll(store.io, store.active_batch.?.record.?, cold_epoch_record_len);
        try atomic.file.sync(store.io);
        const writer = try cold_runtime.duplicateFile(atomic.file);
        errdefer writer.close(store.io);
        const atomic_identity = try cold_identity.statRegular(writer.handle);
        if (!std.meta.eql(atomic_identity, try cold_identity.statRegular(atomic.file.handle))) return StoreError.SnapshotCoverageMismatch;
        store.wal_file = writer;
        self.atomic_identity = atomic_identity;
        self.atomic = atomic;
    }

    pub fn commit(self: *FirstProvisionStage) !void {
        const store = self.store orelse return StoreError.PreparedAlreadyConsumed;
        const active = store.active_batch orelse return StoreError.PreparedAlreadyConsumed;
        if (self.consumed) return StoreError.PreparedAlreadyConsumed;
        EngineAccess.validateBatchTables(store) catch |err| switch (err) {
            StoreError.InvalidTablePlan => return StoreError.SnapshotCoverageMismatch,
            else => return err,
        };
        try validateColdLease(store.io, store.dir, self.lease, self.lock_path, self.identity);
        // Snapshot absence is mandatory even if no application key exists.
        if (openColdExisting(store.io, store.dir, store.snapshot_path, .read_only)) |file| {
            file.close(store.io);
            return StoreError.SnapshotCoverageMismatch;
        } else |err| if (err != error.FileNotFound) return err;
        const file = store.wal_file.?;
        if ((try file.stat(store.io)).size != active.final_wal_offset) return StoreError.SnapshotCoverageMismatch;
        var epoch_bytes: [cold_epoch_record_len]u8 = undefined;
        if (try file.readPositionalAll(store.io, &epoch_bytes, 0) != epoch_bytes.len or !std.mem.eql(u8, &epoch_bytes, &self.epoch)) return StoreError.SnapshotCoverageMismatch;
        try validateColdPreparedRange(store.io, file, active.record.?, cold_epoch_record_len);
        if (!std.meta.eql(try cold_identity.statRegular(file.handle), try cold_identity.statRegular(self.atomic.?.file.handle))) return StoreError.SnapshotCoverageMismatch;
        if (comptime @import("builtin").os.tag == .windows) {
            if (!self.atomic.?.file_exists or !self.atomic.?.file_open) return StoreError.SnapshotCoverageMismatch;
            try requireColdWriteThroughVolumeWindows(self.directory);
        } else try validateColdAtomicName(store.io, &self.atomic.?, self.atomic_identity.?);
        try validateColdParent(store.io, store.dir, store.wal_path, self.directory, self.directory_identity, &self.atomic.?);
        self.consumed = true;
        errdefer EngineAccess.poisonPreparedStore(store);
        if (comptime @import("builtin").os.tag == .windows) {
            try renameHeldColdAtomicWindows(store.io, &self.atomic.?, store.dir, store.wal_path, self.directory, self.directory_identity, self.atomic_identity.?, false);
        } else {
            try self.atomic.?.link(store.io);
            try self.directory.sync(store.io);
        }
        store.staged_read_only = false;
        EngineAccess.publishBatch(store, active.generation);
        self.committed = true;
    }

    pub fn takeCommittedStore(self: *FirstProvisionStage) OroStore {
        std.debug.assert(self.committed);
        const owned = self.store.?;
        const result = owned.*;
        self.allocator.destroy(owned);
        self.store = null;
        return result;
    }

    pub fn deinit(self: *FirstProvisionStage) void {
        if (self.store) |store| {
            store.deinit();
            self.allocator.destroy(store);
        }
        if (self.atomic) |*file| deinitColdAtomic(self.io, file, self.atomic_identity);
        self.directory.close(self.io);
        self.allocator.free(self.lock_path);
        self.store = null;
    }
};

// Replay only this captured immutable transcript. Parsing and receipt hashing
// share bytes, never independently reopened paths or mutable decoded caches.
pub const ColdTranscript = struct {
    bytes: []const u8,
    pub fn stat(self: ColdTranscript, _: std.Io) !struct { size: u64 } {
        return .{ .size = self.bytes.len };
    }
    pub fn readPositionalAll(self: ColdTranscript, _: std.Io, buffer: []u8, offset: u64) !usize {
        if (offset >= self.bytes.len) return 0;
        const take = @min(buffer.len, self.bytes.len - @as(usize, @intCast(offset)));
        @memcpy(buffer[0..take], self.bytes[@intCast(offset)..][0..take]);
        return take;
    }
};

pub const ColdPlan = struct {
    batch: PreparedBatch,
    writer: std.Io.File,
    writer_owned: bool = true,
    writer_identity: cold_identity.Identity,
    directory: std.Io.File,
    directory_identity: cold_identity.Identity,
    wal_atomic: ?std.Io.File.Atomic = null,
    snapshot_atomic: ?std.Io.File.Atomic = null,
    snapshot_bytes: ?[]u8 = null,
    snapshot_identity: ?cold_identity.Identity = null,
    epoch: [cold_epoch_record_len]u8,
    coverage: ?SnapshotCoverage = null,
    prepared_digest: [32]u8 = undefined,
    rotate: bool,
    complete_epoch: bool = false,
    complete_record: ?[]u8 = null,
    snapshot_installed: bool = false,
    wal_replaced: bool = false,

    fn deinit(self: *ColdPlan, allocator: std.mem.Allocator, io: std.Io, owner: *OroStore) void {
        // Cleanup is grounded in the stage's owned store, never a potentially
        // corrupted/copy-edited generic token's store pointer.
        EngineAccess.discardActiveBatch(owner);
        if (self.writer_owned) self.writer.close(io);
        if (self.wal_atomic) |*file| deinitColdAtomic(io, file, self.writer_identity);
        if (self.snapshot_atomic) |*file| deinitColdAtomic(io, file, self.snapshot_identity);
        self.directory.close(io);
        if (self.snapshot_bytes) |bytes| allocator.free(bytes);
        if (self.complete_record) |bytes| allocator.free(bytes);
    }
};

/// Narrow recovery publication faults: each seam reports failure at the actual
/// source-owned syscall boundary. Prepared batch write/sync faults retain the
/// existing OroStore seam; these phases never affect generic or hot loaders.
pub const ColdPublicationFault = enum { none, snapshot_replace, snapshot_dir_sync, wal_replace, wal_dir_sync, truncate, truncate_sync };

pub const ColdBacking = struct {
    store: OroStore,
    lease: std.Io.File,
    lease_identity: cold_identity.Identity,
    lock_path: []u8,
    wal: ColdFile,
    snapshot: ?ColdFile,
    valid_end: u64,
    replay_start: u64,
    selected_epoch: ?usize,
    cut_digest: [32]u8 = undefined,
    plan: ?ColdPlan = null,
    committed: bool = false,
    consumed: bool = false,
    publication_fault: ColdPublicationFault = .none,
};

/// Existing cold storage capture, without creation/repair/compaction. Caller
/// MUST hold the existing stable exclusive lease before entry and throughout.
/// The const maps are structural evidence only. Authority strictly authenticates
/// its complete package before preparing any temporary or recovery publication.
/// This API is distinct from strict hot staging and ordinary writable recovery.
pub const ColdRecoveryStage = struct {
    allocator: std.mem.Allocator,
    backing: ?*ColdBacking,

    pub fn open(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, path: []const u8, lease: std.Io.File, config: Config) !ColdRecoveryStage {
        // A Windows private parent can hold account, delivery, or mesh secrets.
        // Reject inherited/broad file ACLs before capturing any WAL or snapshot
        // bytes. Generic read-only inspection of a nonprivate parent remains
        // available, but publication later requires a private NTFS parent.
        const private_windows_parent = if (comptime @import("builtin").os.tag == .windows) blk: {
            const parent = try coldOpenParent(io, dir, path);
            defer parent.close(io);
            _ = cold_runtime.requirePrivateDirectoryHandleWindows(.{ .handle = parent.handle }) catch |err| switch (err) {
                error.InsecurePermissions => break :blk false,
                else => return err,
            };
            break :blk true;
        } else false;
        const lock_path = try std.mem.concat(allocator, u8, &.{ path, ".lock" });
        errdefer allocator.free(lock_path);
        const lease_identity = try cold_identity.statRegular(lease.handle);
        try validateColdLease(io, dir, lease, lock_path, lease_identity);
        const wal_path = try allocator.dupe(u8, path);
        errdefer allocator.free(wal_path);
        const snapshot_path = try std.mem.concat(allocator, u8, &.{ path, ".snap" });
        errdefer allocator.free(snapshot_path);
        var feed = try ChangeFeed.init(allocator, config.changefeed_capacity);
        errdefer feed.deinit();
        var wal = try ColdFile.captureWithPrivateAcl(allocator, io, dir, path, config.max_wal_bytes, private_windows_parent);
        errdefer wal.deinit(allocator, io);
        // `ColdFile.capture` funnels through `openColdExisting`. Keep the
        // optional snapshot absent only for an actual missing namespace entry.
        var snapshot: ?ColdFile = ColdFile.captureWithPrivateAcl(allocator, io, dir, snapshot_path, null, private_windows_parent) catch |err| blk: {
            if (err != error.FileNotFound) return err;
            break :blk null;
        };
        errdefer if (snapshot) |*file| file.deinit(allocator, io);
        const owned = try allocator.create(ColdBacking);
        errdefer allocator.destroy(owned);
        owned.* = .{ .store = .{ .allocator = allocator, .io = io, .dir = dir, .wal_path = wal_path, .snapshot_path = snapshot_path, .maps = initMaps(allocator), .changefeed = feed, .cfg = config, .staged_read_only = true }, .lease = lease, .lease_identity = lease_identity, .lock_path = lock_path, .wal = wal, .snapshot = snapshot, .valid_end = 0, .replay_start = 0, .selected_epoch = null };
        // Ownership transfers after this point; close/free exactly once on error.
        errdefer {
            for (&owned.store.maps) |*map| map.deinit();
        }
        const store = &owned.store;
        if (snapshot) |file| _ = try EngineAccess.replaySource(store, ColdTranscript{ .bytes = file.bytes }, .snapshot, 0);
        try EngineAccess.loadWalEpochFrom(store, ColdTranscript{ .bytes = wal.bytes });
        if (store.snapshot_coverage) |coverage| {
            if (wal.bytes.len == 0) {
                for (coverage.slots[0..coverage.count], 0..) |slot, i| {
                    const record = coldEpoch(slot.epoch);
                    if (slot.covered_len == record.len and std.mem.eql(u8, &slot.digest, &coldDigest(&record))) {
                        owned.selected_epoch = i;
                        store.wal_epoch = slot.epoch;
                        store.wal_epoch_known = true;
                        break;
                    }
                }
                if (owned.selected_epoch == null) return StoreError.SnapshotCoverageMismatch;
            } else {
                if (!store.wal_epoch_known) return StoreError.SnapshotCoverageMismatch;
                var found = false;
                for (coverage.slots[0..coverage.count]) |slot| {
                    if (slot.covered_len > wal.bytes.len or !std.mem.eql(u8, &slot.epoch, &store.wal_epoch)) continue;
                    if (std.mem.eql(u8, &slot.digest, &coldDigest(wal.bytes[0..@intCast(slot.covered_len)]))) {
                        owned.replay_start = slot.covered_len;
                        found = true;
                        break;
                    }
                }
                if (!found) return StoreError.SnapshotCoverageMismatch;
            }
        }
        owned.valid_end = try EngineAccess.replaySource(store, ColdTranscript{ .bytes = wal.bytes }, .wal, owned.replay_start);
        store.wal_offset = owned.valid_end;
        owned.cut_digest = try coldCutDigest(owned);
        try wal.validate(io, dir, path);
        if (snapshot) |file| try file.validate(io, dir, snapshot_path);
        return .{ .allocator = allocator, .backing = owned };
    }

    pub fn setPublicationFault(self: *ColdRecoveryStage, fault: ColdPublicationFault) void {
        self.backing.?.publication_fault = fault;
    }
    pub fn setPreparedIoFault(self: *ColdRecoveryStage, fault: PreparedIoFault) void {
        self.backing.?.store.setPreparedIoFault(fault);
    }

    pub fn view(self: *const ColdRecoveryStage) *const OroStore {
        return &self.backing.?.store;
    }

    /// Revalidate the exact captured descriptor/transcript/namespace; no new
    /// replay or independently valid replacement head authorizes this stage.
    pub fn validate(self: *const ColdRecoveryStage) !void {
        const owned = self.backing orelse return StoreError.PreparedAlreadyConsumed;
        if (owned.consumed) return StoreError.PreparedAlreadyConsumed;
        if (!owned.store.staged_read_only or owned.store.wal_file != null or owned.store.active_prepared != null) return StoreError.ReadOnlyStore;
        if (!std.mem.eql(u8, &owned.cut_digest, &try coldCutDigest(owned))) return StoreError.SnapshotCoverageMismatch;
        try validateColdLease(owned.store.io, owned.store.dir, owned.lease, owned.lock_path, owned.lease_identity);
        try owned.wal.validate(owned.store.io, owned.store.dir, owned.store.wal_path);
        if (owned.snapshot) |file| {
            try file.validate(owned.store.io, owned.store.dir, owned.store.snapshot_path);
        } else {
            if (openColdExisting(owned.store.io, owned.store.dir, owned.store.snapshot_path, .read_only)) |file| {
                file.close(owned.store.io);
                return StoreError.SnapshotCoverageMismatch;
            } else |err| if (err != error.FileNotFound) return err;
        }
    }

    /// AUTHENTICATION PRECONDITION: caller has verified the whole application
    /// schema/key/realm/cut and selected successor rows against this const view.
    /// Generic persistence grants no presence authority. Every reservation and
    /// encoded snapshot/batch allocation precedes authoritative repair I/O.
    pub fn prepareBatch(self: *ColdRecoveryStage, mutations: []const BatchMutation) !PreparedColdRecovery {
        return self.prepareBatchMode(mutations, false);
    }

    /// Prepare the entire successor epoch and batch in a synced private file
    /// before publication. Application schema/lease authority is still required;
    /// this mechanism does not authenticate Mail intent or authorize unknown-tail
    /// repair. Unlike ordinary cold recovery, it refuses incomplete transcripts.
    /// Snapshot/whole-file capture costs belong to the caller's funding plan.
    pub fn prepareCompleteBatch(self: *ColdRecoveryStage, mutations: []const BatchMutation) !PreparedColdRecovery {
        return self.prepareBatchMode(mutations, true);
    }

    fn prepareBatchMode(self: *ColdRecoveryStage, mutations: []const BatchMutation, complete_epoch: bool) !PreparedColdRecovery {
        // Windows always prepares a whole successor: it can retire an unknown
        // old tail without appending into a captured file after publication.
        // The explicit complete API still requires a complete source cut.
        const whole_successor = complete_epoch or @import("builtin").os.tag == .windows;
        try self.validate();
        const owned = self.backing.?;
        const store = &owned.store;
        if (owned.plan != null or store.active_batch != null) return StoreError.PreparedMutationActive;
        if (complete_epoch and owned.valid_end != owned.wal.bytes.len) return StoreError.SnapshotCoverageMismatch;
        if (store.next_prepared_generation == std.math.maxInt(u64)) return StoreError.SequenceExhausted;
        const payload_len = try batchPayloadLen(mutations, store.cfg.max_record_bytes);
        const record_len = std.math.add(usize, batch_guard_len + record_header_len, payload_len) catch return StoreError.RecordTooLarge;
        const projected = std.math.add(u64, owned.valid_end, record_len) catch return StoreError.RecordTooLarge;
        const rotate = whole_successor or owned.selected_epoch != null or owned.wal.bytes.len == 0 or projected > store.cfg.max_wal_bytes or projected >= store.cfg.max_wal_bytes / 2;
        const offset: u64 = if (rotate) cold_epoch_record_len else owned.valid_end;
        const final = std.math.add(u64, offset, record_len) catch return StoreError.RecordTooLarge;
        if (final > store.cfg.max_wal_bytes) return StoreError.RecordTooLarge;
        const next = std.math.add(u64, store.next_seq, @intCast(mutations.len)) catch return StoreError.SequenceExhausted;
        var batch = try EngineAccess.prepareBatchAt(store, mutations, payload_len, record_len, final, next);
        errdefer batch.abort();
        // Retain an independent canonical packet after publication ambiguity
        // poisons/frees the ordinary active batch. The held full successor and
        // this private witness belong to the stage until explicit cleanup.
        const complete_record: ?[]u8 = if (whole_successor) try self.allocator.dupe(u8, store.active_batch.?.record.?) else null;
        errdefer if (complete_record) |bytes| self.allocator.free(bytes);
        var epoch = store.wal_epoch;
        if (rotate and owned.selected_epoch == null) store.io.random(&epoch);
        const record = coldEpoch(epoch);
        const rotated: CoverageSlot = .{ .covered_len = record.len, .epoch = epoch, .digest = coldDigest(&record) };
        // Windows cannot publish a snapshot ahead of a malformed nonempty
        // WAL with no authenticated old epoch: an interrupted two-file cut
        // would leave that old namespace unreopenable. Keep POSIX coverage
        // behavior unchanged in this Windows portability slice.
        const coverage: ?SnapshotCoverage = if (rotate and owned.selected_epoch == null and owned.wal.bytes.len != 0 and
            (@import("builtin").os.tag != .windows or owned.valid_end != 0)) .{ .count = 2, .slots = .{ .{ .covered_len = owned.valid_end, .epoch = store.wal_epoch, .digest = coldDigest(owned.wal.bytes[0..@intCast(owned.valid_end)]) }, rotated } } else null;
        const snapshot_bytes: ?[]u8 = if (coverage) |*proof| try encodeColdSnapshot(store, proof) else null;
        errdefer if (snapshot_bytes) |bytes| self.allocator.free(bytes);
        const directory = try coldOpenParent(store.io, store.dir, store.wal_path);
        errdefer directory.close(store.io);
        const directory_identity = try coldDirectoryIdentity(directory.handle);
        if (comptime @import("builtin").os.tag == .windows) {
            _ = try cold_runtime.requirePrivateDirectoryHandleWindows(.{ .handle = directory.handle });
            try requireColdWriteThroughVolumeWindows(directory);
            try validateColdParent(store.io, store.dir, store.wal_path, directory, directory_identity, null);
            try owned.wal.pinDeleteShareWindows(store.io, .{ .handle = directory.handle }, std.fs.path.basename(store.wal_path));
            if (owned.snapshot) |*file| try file.pinDeleteShareWindows(store.io, .{ .handle = directory.handle }, std.fs.path.basename(store.snapshot_path));
            try self.validate();
        }
        var snapshot_atomic: ?std.Io.File.Atomic = null;
        errdefer if (snapshot_atomic) |*file| deinitColdAtomic(store.io, file, null);
        if (snapshot_bytes) |bytes| {
            snapshot_atomic = if (comptime @import("builtin").os.tag == .windows)
                try (std.Io.Dir{ .handle = directory.handle }).createFileAtomic(store.io, std.fs.path.basename(store.snapshot_path), .{ .replace = true })
            else
                try store.dir.createFileAtomic(store.io, store.snapshot_path, .{ .replace = true });
            if (comptime @import("builtin").os.tag == .windows)
                try EngineAccess.secureColdAtomicWindows(store, &snapshot_atomic.?)
            else
                try makeColdAtomicReadable(store.io, &snapshot_atomic.?);
            try snapshot_atomic.?.file.writePositionalAll(store.io, bytes, 0);
            try snapshot_atomic.?.file.sync(store.io);
        }
        var wal_atomic: ?std.Io.File.Atomic = null;
        errdefer if (wal_atomic) |*file| deinitColdAtomic(store.io, file, null);
        const writer: std.Io.File = if (rotate) block: {
            wal_atomic = if (comptime @import("builtin").os.tag == .windows)
                try (std.Io.Dir{ .handle = directory.handle }).createFileAtomic(store.io, std.fs.path.basename(store.wal_path), .{ .replace = true })
            else
                try store.dir.createFileAtomic(store.io, store.wal_path, .{ .replace = true });
            if (comptime @import("builtin").os.tag == .windows)
                try EngineAccess.secureColdAtomicWindows(store, &wal_atomic.?)
            else
                try makeColdAtomicReadable(store.io, &wal_atomic.?);
            try wal_atomic.?.file.writePositionalAll(store.io, &record, 0);
            if (complete_record) |bytes| try wal_atomic.?.file.writePositionalAll(store.io, bytes, cold_epoch_record_len);
            try wal_atomic.?.file.sync(store.io);
            // Atomic.replace closes its descriptor. Reserve a duplicate now;
            // the exact same replacement OFD receives the successor batch.
            break :block if (comptime @import("builtin").os.tag == .windows)
                try cold_runtime.duplicateFile(wal_atomic.?.file)
            else
                .{ .handle = try cold_runtime.duplicate(wal_atomic.?.file.handle), .flags = wal_atomic.?.file.flags };
        } else try openColdExisting(store.io, store.dir, store.wal_path, .read_write);
        errdefer writer.close(store.io);
        const writer_identity = try cold_identity.statRegular(writer.handle);
        if (!rotate and !std.meta.eql(writer_identity, owned.wal.identity)) return StoreError.SnapshotCoverageMismatch;
        owned.plan = .{ .batch = batch, .writer = writer, .writer_identity = writer_identity, .directory = directory, .directory_identity = directory_identity, .wal_atomic = wal_atomic, .snapshot_atomic = snapshot_atomic, .snapshot_bytes = snapshot_bytes, .snapshot_identity = if (snapshot_atomic) |file| try cold_identity.statRegular(file.file.handle) else null, .epoch = record, .coverage = coverage, .rotate = rotate, .complete_epoch = whole_successor, .complete_record = complete_record };
        errdefer owned.plan = null;
        owned.plan.?.prepared_digest = try coldPreparedDigest(owned);
        return .{ .stage = self, .owner = owned, .generation = batch.generation };
    }

    pub fn deinit(self: *ColdRecoveryStage) void {
        const owned = self.backing orelse return;
        if (owned.plan) |*plan| plan.deinit(self.allocator, owned.store.io, &owned.store);
        owned.wal.deinit(self.allocator, owned.store.io);
        if (owned.snapshot) |*file| file.deinit(self.allocator, owned.store.io);
        owned.store.deinit();
        self.allocator.free(owned.lock_path);
        self.allocator.destroy(owned);
        self.backing = null;
    }

    /// Consumes only a successfully committed stage; all cleanup closes happen
    /// before its caller's final no-fail Authority publication.
    pub fn takeCommittedStore(self: *ColdRecoveryStage) OroStore {
        const owned = self.backing.?;
        std.debug.assert(owned.committed and owned.plan == null);
        owned.wal.deinit(self.allocator, owned.store.io);
        if (owned.snapshot) |*file| file.deinit(self.allocator, owned.store.io);
        const result = owned.store;
        self.allocator.free(owned.lock_path);
        self.allocator.destroy(owned);
        self.backing = null;
        return result;
    }
};

pub const PreparedColdRecovery = struct {
    stage: *ColdRecoveryStage,
    owner: *const ColdBacking,
    generation: u64,

    pub fn abort(self: *PreparedColdRecovery) void {
        const owned = self.stage.backing orelse return;
        if (owned != self.owner) return;
        if (owned.plan) |*plan| {
            if (plan.batch.generation != self.generation) return;
            plan.deinit(self.stage.allocator, owned.store.io, &owned.store);
            owned.plan = null;
        }
    }

    /// Caller reaffirms its lease and exact authenticated application cut
    /// immediately before entry. All private file/phase/ticket checks are here.
    pub fn commit(self: *PreparedColdRecovery) !void {
        const owned = self.stage.backing orelse return StoreError.PreparedAlreadyConsumed;
        if (owned != self.owner) return StoreError.PreparedAlreadyConsumed;
        const plan = if (owned.plan) |*value| value else return StoreError.PreparedAlreadyConsumed;
        const active = owned.store.active_batch orelse return StoreError.PreparedAlreadyConsumed;
        if (owned.consumed or active.generation != self.generation or plan.batch.generation != self.generation) return StoreError.PreparedAlreadyConsumed;
        try self.stage.validate();
        EngineAccess.validateBatchTables(&owned.store) catch |err| switch (err) {
            StoreError.InvalidTablePlan => return StoreError.SnapshotCoverageMismatch,
            else => return err,
        };
        if (plan.batch.store != &owned.store or !std.mem.eql(u8, &plan.prepared_digest, &try coldPreparedDigest(owned))) return StoreError.SnapshotCoverageMismatch;
        if (comptime @import("builtin").os.tag == .windows) return self.commitWindows(owned, plan, active.generation);
        const store = &owned.store;
        try validateColdParent(store.io, store.dir, store.wal_path, plan.directory, plan.directory_identity, if (plan.wal_atomic) |*file| file else null);
        if (plan.snapshot_atomic) |*file| try validateColdParent(store.io, store.dir, store.snapshot_path, plan.directory, plan.directory_identity, file);
        if (!std.meta.eql(plan.writer_identity, try cold_identity.statRegular(plan.writer.handle))) return StoreError.SnapshotCoverageMismatch;
        if (plan.rotate) try validateColdPreparedWal(owned);
        if (plan.snapshot_atomic) |*file| {
            try validateColdPreparedFile(store.io, file.file, plan.snapshot_bytes.?, plan.snapshot_identity.?);
            try validateColdAtomicName(store.io, file, plan.snapshot_identity.?);
        }
        if (plan.wal_atomic) |*file| try validateColdAtomicName(store.io, file, plan.writer_identity);
        // Once publication may start, any error consumes and poisons this stage.
        owned.consumed = true;
        errdefer EngineAccess.poisonPreparedStore(store);
        if (plan.snapshot_atomic) |*file| {
            try validateColdPreparedFile(store.io, file.file, plan.snapshot_bytes.?, plan.snapshot_identity.?);
            try validateColdAtomicName(store.io, file, plan.snapshot_identity.?);
            try validateColdParent(store.io, store.dir, store.snapshot_path, plan.directory, plan.directory_identity, file);
            if (owned.publication_fault == .snapshot_replace) return StoreError.IoAmbiguous;
            try file.replace(store.io);
            plan.snapshot_installed = true;
            if (owned.publication_fault == .snapshot_dir_sync) return StoreError.IoAmbiguous;
            try plan.directory.sync(store.io);
        }
        // Authorized snapshot transition only; the original WAL must still be
        // the exact captured file/transcript before its replacement.
        try owned.wal.validate(store.io, store.dir, store.wal_path);
        try validateColdLease(store.io, store.dir, owned.lease, owned.lock_path, owned.lease_identity);
        if (plan.snapshot_installed) {
            const file = try openColdExisting(store.io, store.dir, store.snapshot_path, .read_only);
            defer file.close(store.io);
            try validateColdPreparedFile(store.io, file, plan.snapshot_bytes.?, plan.snapshot_identity.?);
        } else if (owned.snapshot) |file| try file.validate(store.io, store.dir, store.snapshot_path);
        if (plan.wal_atomic) |*file| {
            try validateColdPreparedWal(owned);
            try validateColdAtomicName(store.io, file, plan.writer_identity);
            try validateColdParent(store.io, store.dir, store.wal_path, plan.directory, plan.directory_identity, file);
            if (owned.publication_fault == .wal_replace) return StoreError.IoAmbiguous;
            try file.replace(store.io);
            plan.wal_replaced = true;
            if (owned.publication_fault == .wal_dir_sync) return StoreError.IoAmbiguous;
            try plan.directory.sync(store.io);
            store.wal_epoch = try parseWalEpoch(plan.epoch[record_header_len..]);
            store.wal_epoch_known = true;
            store.wal_offset = cold_epoch_record_len;
            if (plan.coverage) |coverage| store.snapshot_coverage = coverage;
        } else {
            if (owned.publication_fault == .truncate) return StoreError.TruncateFailed;
            try plan.writer.setLength(store.io, owned.valid_end);
            if (owned.publication_fault == .truncate_sync) return StoreError.IoAmbiguous;
            try plan.writer.sync(store.io);
            try plan.directory.sync(store.io);
        }
        // Bind configured locator to the prepared writer; an external rename
        // after our own replacement cannot redirect the appended authority.
        const configured = try openColdExisting(store.io, store.dir, store.wal_path, .read_only);
        defer configured.close(store.io);
        if (!std.meta.eql(plan.writer_identity, try cold_identity.statRegular(configured.handle))) return StoreError.SnapshotCoverageMismatch;
        store.wal_file = plan.writer;
        plan.writer_owned = false;
        store.staged_read_only = false;
        // Source-owned ownership transfer; every descriptor was reserved before
        // authoritative publication. No dup/open/allocation after this point.
        if (plan.complete_epoch) {
            // The exact full batch was synced before either namespace change.
            // Rewriting it here would reintroduce an authoritative torn append.
            EngineAccess.publishBatch(store, active.generation);
        } else try plan.batch.commit();
        owned.committed = true;
        plan.deinit(self.stage.allocator, store.io, store);
        owned.plan = null;
    }

    fn commitWindows(self: *PreparedColdRecovery, owned: *ColdBacking, plan: *ColdPlan, generation: u64) !void {
        if (comptime @import("builtin").os.tag != .windows) return error.Unsupported;
        const store = &owned.store;
        if (!plan.complete_epoch or !plan.rotate or plan.wal_atomic == null) return StoreError.SnapshotCoverageMismatch;
        _ = try cold_runtime.requirePrivateDirectoryHandleWindows(.{ .handle = plan.directory.handle });
        try requireColdWriteThroughVolumeWindows(plan.directory);
        try cold_runtime.requireOwnerOnlyPrivateFileHandleWindows(owned.wal.file);
        if (owned.snapshot) |file| try cold_runtime.requireOwnerOnlyPrivateFileHandleWindows(file.file);
        try cold_runtime.requireExistingPrivateFileHandleWindows(plan.wal_atomic.?.file);
        try cold_runtime.requireExistingPrivateFileHandleWindows(plan.writer);
        if (plan.snapshot_atomic) |file|
            try cold_runtime.requireExistingPrivateFileHandleWindows(file.file)
        else if (owned.snapshot) |file|
            try cold_runtime.requireOwnerOnlyPrivateFileHandleWindows(file.file);
        try validateColdParent(store.io, store.dir, store.wal_path, plan.directory, plan.directory_identity, &plan.wal_atomic.?);
        if (plan.snapshot_atomic) |*file| try validateColdParent(store.io, store.dir, store.snapshot_path, plan.directory, plan.directory_identity, file);
        if (!std.meta.eql(plan.writer_identity, try cold_identity.statRegular(plan.writer.handle))) return StoreError.SnapshotCoverageMismatch;
        try validateColdPreparedWal(owned);
        if (plan.snapshot_atomic) |*file| try validateColdPreparedFile(store.io, file.file, plan.snapshot_bytes.?, plan.snapshot_identity.?);
        const new_epoch = try parseWalEpoch(plan.epoch[record_header_len..]);

        // The snapshot can cover either the captured WAL or the prepared
        // successor. Its held, write-through rename precedes the WAL cut.
        owned.consumed = true;
        errdefer EngineAccess.poisonPreparedStore(store);
        if (plan.snapshot_atomic) |*file| {
            try validateColdPreparedFile(store.io, file.file, plan.snapshot_bytes.?, plan.snapshot_identity.?);
            if (owned.publication_fault == .snapshot_replace) return StoreError.IoAmbiguous;
            try renameHeldColdAtomicWindows(store.io, file, store.dir, store.snapshot_path, plan.directory, plan.directory_identity, plan.snapshot_identity.?, true);
            plan.snapshot_installed = true;
            if (owned.publication_fault == .snapshot_dir_sync) return StoreError.IoAmbiguous;
        }
        try owned.wal.validate(store.io, store.dir, store.wal_path);
        try validateColdLease(store.io, store.dir, owned.lease, owned.lock_path, owned.lease_identity);
        if (plan.snapshot_installed) {
            try validateColdPreparedFile(store.io, plan.snapshot_atomic.?.file, plan.snapshot_bytes.?, plan.snapshot_identity.?);
            try validateColdParent(store.io, store.dir, store.snapshot_path, plan.directory, plan.directory_identity, null);
        } else if (owned.snapshot) |file| try file.validate(store.io, store.dir, store.snapshot_path);
        try validateColdPreparedWal(owned);
        if (owned.publication_fault == .wal_replace) return StoreError.IoAmbiguous;
        try renameHeldColdAtomicWindows(store.io, &plan.wal_atomic.?, store.dir, store.wal_path, plan.directory, plan.directory_identity, plan.writer_identity, true);
        plan.wal_replaced = true;
        if (owned.publication_fault == .wal_dir_sync) return StoreError.IoAmbiguous;

        // Every fallible operation has completed. Keep the exact published
        // writer and transfer the already-synced full batch into live state.
        store.wal_file = plan.writer;
        plan.writer_owned = false;
        store.private_windows_files = true;
        store.staged_read_only = false;
        store.wal_epoch = new_epoch;
        store.wal_epoch_known = true;
        store.wal_offset = cold_epoch_record_len;
        if (plan.coverage) |coverage| store.snapshot_coverage = coverage;
        EngineAccess.publishBatch(store, generation);
        owned.committed = true;
        plan.deinit(self.stage.allocator, store.io, store);
        owned.plan = null;
    }
};

pub fn coldHashInt(hasher: *std.crypto.hash.Blake3, value: u64) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .big);
    hasher.update(&bytes);
}

pub fn coldHashBytes(hasher: *std.crypto.hash.Blake3, value: []const u8) void {
    coldHashInt(hasher, value.len);
    hasher.update(value);
}

pub fn coldHashIdentity(hasher: *std.crypto.hash.Blake3, identity: cold_identity.Identity) void {
    coldHashInt(hasher, identity.device);
    coldHashInt(hasher, identity.inode);
    // Windows FILE_ID_INFO has 128 identifier bits. Preserve existing POSIX
    // receipt bytes while authenticating the high half on Windows.
    if (comptime @import("builtin").os.tag == .windows) coldHashInt(hasher, identity.inode_high);
}

pub fn coldHashCoverage(hasher: *std.crypto.hash.Blake3, coverage: ?SnapshotCoverage) !void {
    coldHashInt(hasher, if (coverage) |proof| proof.count else 0);
    if (coverage) |proof| {
        if (proof.count == 0 or proof.count > proof.slots.len) return StoreError.SnapshotCoverageMismatch;
        for (proof.slots[0..proof.count]) |slot| {
            coldHashInt(hasher, slot.covered_len);
            hasher.update(&slot.epoch);
            hasher.update(&slot.digest);
        }
    }
}

// Private replay receipt. Map capacity reservations can reorder buckets, so
// authenticate a framed per-entry digest set rather than iteration order.
// This detects accidental/ticket mutation; application signatures still decide
// authority, and arbitrary memory corruption is outside the custody contract.
pub fn coldCutDigest(owned: *const ColdBacking) ![32]u8 {
    const store = &owned.store;
    var hash = std.crypto.hash.Blake3.init(.{});
    coldHashBytes(&hash, store.wal_path);
    coldHashBytes(&hash, store.snapshot_path);
    coldHashBytes(&hash, owned.lock_path);
    coldHashIdentity(&hash, owned.wal.identity);
    coldHashInt(&hash, owned.wal.bytes.len);
    hash.update(&owned.wal.digest);
    coldHashInt(&hash, @intFromBool(owned.snapshot != null));
    if (owned.snapshot) |snapshot| {
        coldHashIdentity(&hash, snapshot.identity);
        coldHashInt(&hash, snapshot.bytes.len);
        hash.update(&snapshot.digest);
    }
    coldHashInt(&hash, owned.valid_end);
    coldHashInt(&hash, owned.replay_start);
    coldHashInt(&hash, @intFromBool(owned.selected_epoch != null));
    if (owned.selected_epoch) |chosen| coldHashInt(&hash, chosen);
    coldHashInt(&hash, store.next_seq);
    coldHashInt(&hash, store.wal_offset);
    coldHashInt(&hash, @intFromBool(store.wal_epoch_known));
    hash.update(&store.wal_epoch);
    coldHashInt(&hash, @intFromBool(store.batch_format_required));
    coldHashInt(&hash, store.cfg.max_record_bytes);
    coldHashInt(&hash, store.cfg.max_wal_bytes);
    coldHashInt(&hash, store.cfg.changefeed_capacity);
    try coldHashCoverage(&hash, store.snapshot_coverage);
    for (families) |family| {
        const map = &store.maps[familyIndex(family)].map;
        coldHashInt(&hash, map.count());
        var accumulator: [32]u8 = @splat(0);
        var it = map.iterator();
        while (it.next()) |entry| {
            var item = std.crypto.hash.Blake3.init(.{});
            coldHashInt(&item, @backingInt(family));
            coldHashBytes(&item, entry.key_ptr.*);
            coldHashBytes(&item, entry.value_ptr.*);
            var digest: [32]u8 = undefined;
            item.final(&digest);
            for (&accumulator, digest) |*byte, part| byte.* ^= part;
        }
        hash.update(&accumulator);
    }
    var result: [32]u8 = undefined;
    hash.final(&result);
    return result;
}

pub fn coldPreparedDigest(owned: *const ColdBacking) ![32]u8 {
    const plan = owned.plan orelse return StoreError.PreparedAlreadyConsumed;
    const batch = owned.store.active_batch orelse return StoreError.PreparedAlreadyConsumed;
    if (batch.count == 0 or batch.count > batch.entries.len) return StoreError.SnapshotCoverageMismatch;
    var hash = std.crypto.hash.Blake3.init(.{});
    coldHashInt(&hash, plan.batch.generation);
    coldHashIdentity(&hash, plan.directory_identity);
    coldHashInt(&hash, batch.generation);
    coldHashInt(&hash, batch.final_wal_offset);
    coldHashInt(&hash, batch.next_seq_after);
    coldHashBytes(&hash, batch.record orelse return StoreError.SnapshotCoverageMismatch);
    for (batch.entries[0..batch.count]) |entry| {
        coldHashInt(&hash, @backingInt(entry.family));
        coldHashInt(&hash, @backingInt(entry.kind));
        coldHashBytes(&hash, entry.key orelse return StoreError.SnapshotCoverageMismatch);
        coldHashInt(&hash, @intFromBool(entry.value != null));
        if (entry.value) |value| coldHashBytes(&hash, value);
        coldHashInt(&hash, @intFromBool(entry.change != null));
        if (entry.change) |change| {
            coldHashInt(&hash, change.seq);
            coldHashInt(&hash, @backingInt(change.family));
            coldHashInt(&hash, @backingInt(change.kind));
            coldHashBytes(&hash, change.key);
            coldHashInt(&hash, @intFromBool(change.value != null));
            if (change.value) |value| coldHashBytes(&hash, value);
        }
    }
    coldHashInt(&hash, @intFromBool(plan.rotate));
    coldHashInt(&hash, @intFromBool(plan.complete_epoch));
    coldHashInt(&hash, @intFromBool(plan.complete_record != null));
    if (plan.complete_record) |bytes| coldHashBytes(&hash, bytes);
    hash.update(&plan.epoch);
    try coldHashCoverage(&hash, plan.coverage);
    if (plan.snapshot_bytes) |bytes| coldHashBytes(&hash, bytes);
    if (plan.wal_atomic) |file| {
        coldHashInt(&hash, file.file_basename_hex);
        coldHashBytes(&hash, file.dest_sub_path);
    }
    if (plan.snapshot_atomic) |file| {
        coldHashInt(&hash, file.file_basename_hex);
        coldHashBytes(&hash, file.dest_sub_path);
    }
    var result: [32]u8 = undefined;
    hash.final(&result);
    return result;
}

pub fn validateColdPreparedWal(owned: *const ColdBacking) !void {
    const plan = owned.plan orelse return StoreError.SnapshotCoverageMismatch;
    const store = &owned.store;
    if (!plan.complete_epoch) return validateColdPreparedFile(store.io, plan.writer, &plan.epoch, plan.writer_identity);
    const active = store.active_batch orelse return StoreError.SnapshotCoverageMismatch;
    const bytes = plan.complete_record orelse return StoreError.SnapshotCoverageMismatch;
    if (!std.mem.eql(u8, bytes, active.record orelse return StoreError.SnapshotCoverageMismatch)) return StoreError.SnapshotCoverageMismatch;
    const length = std.math.add(u64, cold_epoch_record_len, bytes.len) catch return StoreError.SnapshotCoverageMismatch;
    if (!plan.rotate or !std.meta.eql(plan.writer_identity, try cold_identity.statRegular(plan.writer.handle)) or
        (try plan.writer.stat(store.io)).size != length or active.final_wal_offset != length) return StoreError.SnapshotCoverageMismatch;
    try validateColdPreparedRange(store.io, plan.writer, &plan.epoch, 0);
    try validateColdPreparedRange(store.io, plan.writer, bytes, cold_epoch_record_len);
}
