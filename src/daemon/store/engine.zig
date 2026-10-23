// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Live OroStore ownership and single/batch mutation publication.
//! Candidate allocation and validation precede the durable publication cut.

const std = @import("std");
const cold_identity = @import("../mesh_presence_lease.zig");
const cold_runtime = @import("../os_runtime.zig");
const ChangeFeed = @import("changefeed.zig").ChangeFeed;
const OwnedMutation = @import("changefeed.zig").OwnedMutation;
const AdmissionLimits = @import("contracts.zig").AdmissionLimits;
const BatchMutation = @import("contracts.zig").BatchMutation;
const Config = @import("contracts.zig").Config;
const CoverageSlot = @import("contracts.zig").CoverageSlot;
const Family = @import("contracts.zig").Family;
const Mutation = @import("contracts.zig").Mutation;
const MutationKind = @import("contracts.zig").MutationKind;
const PreparedIoFault = @import("contracts.zig").PreparedIoFault;
const SnapshotCoverage = @import("contracts.zig").SnapshotCoverage;
const StoreError = @import("contracts.zig").StoreError;
const batch_format_version = @import("contracts.zig").batch_format_version;
const batch_guard_len = @import("contracts.zig").batch_guard_len;
const cold_epoch_record_len = @import("contracts.zig").cold_epoch_record_len;
const decodeFamily = @import("contracts.zig").decodeFamily;
const families = @import("contracts.zig").families;
const familyIndex = @import("contracts.zig").familyIndex;
const family_count = @import("contracts.zig").family_count;
const legacy_wal_epoch = @import("contracts.zig").legacy_wal_epoch;
const max_batch_mutations = @import("contracts.zig").max_batch_mutations;
const meta_kind_batch = @import("contracts.zig").meta_kind_batch;
const meta_kind_batch_format = @import("contracts.zig").meta_kind_batch_format;
const meta_kind_next_seq = @import("contracts.zig").meta_kind_next_seq;
const meta_kind_snapshot_coverage = @import("contracts.zig").meta_kind_snapshot_coverage;
const meta_kind_wal_epoch = @import("contracts.zig").meta_kind_wal_epoch;
const meta_next_seq_payload_len = @import("contracts.zig").meta_next_seq_payload_len;
const payload_header_len = @import("contracts.zig").payload_header_len;
const prepared_retirement_capacity = @import("contracts.zig").prepared_retirement_capacity;
const record_header_len = @import("contracts.zig").record_header_len;
const snapshot_coverage_payload_len = @import("contracts.zig").snapshot_coverage_payload_len;
const snapshot_coverage_slot_len = @import("contracts.zig").snapshot_coverage_slot_len;
const snapshot_coverage_version = @import("contracts.zig").snapshot_coverage_version;
const tombstone_len = @import("contracts.zig").tombstone_len;
const wal_epoch_len = @import("contracts.zig").wal_epoch_len;
const wal_epoch_payload_len = @import("contracts.zig").wal_epoch_payload_len;
const ColdFile = @import("native_files.zig").ColdFile;
const DuplicateHandle = @import("native_files.zig").DuplicateHandle;
const GetCurrentProcess = @import("native_files.zig").GetCurrentProcess;
const GetCurrentProcessId = @import("native_files.zig").GetCurrentProcessId;
const GetProcessId = @import("native_files.zig").GetProcessId;
const WindowsWalDescriptor = @import("native_files.zig").WindowsWalDescriptor;
const WindowsWalTransfer = @import("native_files.zig").WindowsWalTransfer;
const WindowsWalWitness = @import("native_files.zig").WindowsWalWitness;
const coldDirectoryIdentity = @import("native_files.zig").coldDirectoryIdentity;
const coldOpenParent = @import("native_files.zig").coldOpenParent;
const cold_posix = @import("native_files.zig").cold_posix;
const deinitColdAtomic = @import("native_files.zig").deinitColdAtomic;
const makeColdAtomicReadable = @import("native_files.zig").makeColdAtomicReadable;
const openColdAtomicWindows = @import("native_files.zig").openColdAtomicWindows;
const openColdExisting = @import("native_files.zig").openColdExisting;
const openExistingPersistenceFile = @import("native_files.zig").openExistingPersistenceFile;
const renameHeldColdAtomicWindows = @import("native_files.zig").renameHeldColdAtomicWindows;
const requireColdWriteThroughVolumeWindows = @import("native_files.zig").requireColdWriteThroughVolumeWindows;
const syncDirectory = @import("native_files.zig").syncDirectory;
const validateColdAtomicName = @import("native_files.zig").validateColdAtomicName;
const validateColdParent = @import("native_files.zig").validateColdParent;
const validateColdPreparedFile = @import("native_files.zig").validateColdPreparedFile;
const windowsColdAtomicIdentity = @import("native_files.zig").windowsColdAtomicIdentity;
const windowsWalWitness = @import("native_files.zig").windowsWalWitness;
const windows_duplicate_same_access = @import("native_files.zig").windows_duplicate_same_access;
const KvMap = @import("table.zig").KvMap;
const KvTable = @import("table.zig").KvTable;
const initMaps = @import("table.zig").initMaps;
const batchPayloadLen = @import("wal.zig").batchPayloadLen;
const checkedPayloadLen = @import("wal.zig").checkedPayloadLen;
const checksum = @import("wal.zig").checksum;
const coldDigest = @import("wal.zig").coldDigest;
const coldEpoch = @import("wal.zig").coldEpoch;
const decodeBatch = @import("wal.zig").decodeBatch;
const encodeBatchGuard = @import("wal.zig").encodeBatchGuard;
const encodeMutation = @import("wal.zig").encodeMutation;
const isAllowedMetaPayloadLen = @import("wal.zig").isAllowedMetaPayloadLen;
const isMutationPayload = @import("wal.zig").isMutationPayload;
const parseSnapshotCoverage = @import("wal.zig").parseSnapshotCoverage;
const parseWalEpoch = @import("wal.zig").parseWalEpoch;
const readU32 = @import("wal.zig").readU32;
const readU64 = @import("wal.zig").readU64;
const recordSize = @import("wal.zig").recordSize;
const writeNextSeqRecordAt = @import("wal.zig").writeNextSeqRecordAt;
const writeRecordAt = @import("wal.zig").writeRecordAt;
const writeSnapshotCoverageRecordAt = @import("wal.zig").writeSnapshotCoverageRecordAt;
const writeU32 = @import("wal.zig").writeU32;
const writeU64 = @import("wal.zig").writeU64;
const writeWalEpochRecordAt = @import("wal.zig").writeWalEpochRecordAt;

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

pub const BatchEntry = struct {
    family: Family,
    kind: MutationKind,
    key: ?[]u8 = null,
    value: ?[]u8 = null,
    change: ?OwnedMutation = null,
    old_key: ?[]u8 = null,
    old_value: ?[]u8 = null,
};

pub const ActiveBatch = struct {
    generation: u64,
    entries: [max_batch_mutations]BatchEntry = undefined,
    count: usize = 0,
    record: ?[]u8 = null,
    final_wal_offset: u64,
    next_seq_after: u64,
    table_plans: [family_count]?KvTable.Plan = @splat(null),
};

/// Copyable single-use reservation, with ownership retained by its store.
pub const PreparedBatch = struct {
    store: *OroStore,
    generation: u64,

    pub fn commit(self: *PreparedBatch) !void {
        try self.store.commitBatch(self.generation);
    }

    pub fn abort(self: *PreparedBatch) void {
        const active = self.store.active_batch orelse return;
        if (active.generation == self.generation) self.store.discardActiveBatch();
    }

    pub fn deinit(self: *PreparedBatch) void {
        self.abort();
    }
};

pub fn initRetirements() [prepared_retirement_capacity]?Retirement {
    var slots: [prepared_retirement_capacity]?Retirement = undefined;
    for (&slots) |*slot| slot.* = null;
    return slots;
}

pub const Retirement = union(enum) {
    bytes: []u8,
    mutation: OwnedMutation,
    table_slots: []KvTable.Slot,
};

/// All prepared allocations live in the store until publication or abort. The
/// public token deliberately contains no slices or owned state, so copying a
/// token cannot duplicate ownership or accidentally release a newer prepare.
pub const ActivePrepared = struct {
    generation: u64,
    store_family: Family,
    kind: MutationKind,
    key: ?[]u8,
    value: ?[]u8,
    record: ?[]u8,
    change: ?OwnedMutation,
    final_wal_offset: u64,
    next_seq_after: u64,
    sequence: u64,
    old_key: ?[]u8 = null,
    old_value: ?[]u8 = null,
    table_plan: ?KvTable.Plan = null,
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
    staged_read_only: bool = false,
    /// Daemon account stores require private native custody; generic stores
    /// retain their existing cross-platform storage policy.
    private_windows_files: bool = false,
    owned_private_directory: bool = false,
    staged_write_file: ?std.Io.File = null,
    transferred_windows_wal: ?WindowsWalWitness = null,
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
    active_batch: ?ActiveBatch = null,
    batch_format_required: bool = false,
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
        return openImpl(allocator, io, dir, wal_path, cfg, false, false, null);
    }

    /// Windows account-store lane. The parent directory must already have an
    /// inheritable private ACL; every existing file is acquired exclusively and
    /// hardened before replay, and new files are protected before any write.
    pub fn openPrivateWindowsWithConfig(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, wal_path: []const u8, cfg: Config) !OroStore {
        if (comptime @import("builtin").os.tag != .windows) return error.Unsupported;
        const name = std.fs.path.basename(wal_path);
        if (name.len == 0 or std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return error.InvalidPath;
        const parent_path = std.fs.path.dirname(wal_path) orelse ".";
        const private_dir = try cold_runtime.openPrivateDirectoryWindows(io, dir, parent_path);
        errdefer private_dir.close(io);
        var store = try openImpl(allocator, io, private_dir, name, cfg, false, true, null);
        store.owned_private_directory = true;
        return store;
    }

    /// Native Helix staging: replay existing files without creation, repair,
    /// truncation, epoch writes or compaction. Every mutation remains refused.
    pub fn openReadOnlyWithConfig(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, wal_path: []const u8, cfg: Config) !OroStore {
        return openImpl(allocator, io, dir, wal_path, cfg, true, false, null);
    }

    /// Parent-side transfer of the already-open private account WAL. The
    /// returned duplicate lives in `target_process` and is rolled back by
    /// WindowsWalTransfer.deinit until its descriptor is authenticated/sent.
    /// The process HANDLE is borrowed and must stay valid until that cut.
    pub fn duplicatePrivateWalToWindowsProcess(self: *OroStore, target_process: usize) !WindowsWalTransfer {
        if (comptime @import("builtin").os.tag != .windows) return error.Unsupported;
        if (!self.private_windows_files or self.staged_read_only or self.staged_write_file != null)
            return StoreError.ReadOnlyStore;
        if (self.active_prepared != null or self.active_batch != null)
            return StoreError.PreparedMutationActive;
        const source = self.wal_file orelse return StoreError.SnapshotCoverageMismatch;
        try cold_runtime.requireExistingPrivateFileHandleWindows(source);
        const witness = try windowsWalWitness(self.io, source, self.dir, self.wal_path);
        if (witness.length != self.wal_offset) return StoreError.SnapshotCoverageMismatch;
        const pid = GetProcessId(target_process);
        if (pid == 0) return error.InvalidWindowsProcess;
        var copy: usize = 0;
        if (DuplicateHandle(GetCurrentProcess(), @intFromPtr(source.handle), target_process, &copy, 0, 0, windows_duplicate_same_access) == 0 or copy == 0)
            return error.DuplicateFailed;
        var transfer = WindowsWalTransfer{ .target_process = target_process, .descriptor = .{ .handle = copy, .destination_pid = pid, .witness = witness } };
        errdefer transfer.deinit();
        if (!std.meta.eql(witness, try windowsWalWitness(self.io, source, self.dir, self.wal_path))) return StoreError.SnapshotCoverageMismatch;
        return transfer;
    }

    /// Candidate-side read-only replay through the transferred WAL HANDLE.
    /// The caller owns `descriptor` until this succeeds; every failure closes
    /// its received duplicate. Snapshot replay remains rooted in a validated
    /// private directory and is covered by the WAL epoch/digest checks.
    pub fn openTransferredPrivateWindowsWithConfig(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, wal_path: []const u8, cfg: Config, descriptor: *WindowsWalDescriptor) !OroStore {
        if (comptime @import("builtin").os.tag != .windows) return error.Unsupported;
        if (descriptor.handle == 0 or descriptor.destination_pid != GetCurrentProcessId()) return error.InvalidWindowsTransfer;
        errdefer descriptor.deinitReceived();
        const file = std.Io.File{ .handle = @ptrFromInt(descriptor.handle), .flags = .{ .nonblocking = false } };
        try cold_runtime.requireExistingPrivateFileHandleWindows(file);
        const name = std.fs.path.basename(wal_path);
        if (name.len == 0 or std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return error.InvalidPath;
        const parent_path = std.fs.path.dirname(wal_path) orelse ".";
        const private_dir = try cold_runtime.openPrivateDirectoryWindows(io, dir, parent_path);
        errdefer private_dir.close(io);
        if (!std.meta.eql(descriptor.witness, try windowsWalWitness(io, file, private_dir, name)))
            return StoreError.SnapshotCoverageMismatch;
        var stage = try openImpl(allocator, io, private_dir, name, cfg, true, true, file);
        errdefer {
            stage.wal_file = null; // descriptor still owns the received HANDLE
            stage.deinit();
        }
        if (stage.wal_offset != descriptor.witness.length or
            !std.meta.eql(descriptor.witness, try windowsWalWitness(io, file, private_dir, name)))
            return StoreError.SnapshotCoverageMismatch;
        stage.transferred_windows_wal = descriptor.witness;
        stage.owned_private_directory = true;
        descriptor.handle = 0;
        return stage;
    }

    /// Replay one exact value through the retained exclusive Windows WAL
    /// descriptor. Mail's ambiguous-append reconciliation compares file cuts
    /// before and after this call; a path reopen would break that custody.
    pub fn replayHeldPrivateWindowsValueAlloc(self: *OroStore, allocator: std.mem.Allocator, family_name: Family, key: []const u8) !?[]u8 {
        if (comptime @import("builtin").os.tag != .windows) return error.Unsupported;
        if (!self.private_windows_files or self.staged_read_only) return error.Unsupported;
        const wal = self.wal_file orelse return StoreError.BadRecord;
        var replay = try openImpl(allocator, self.io, self.dir, self.wal_path, self.cfg, true, true, wal);
        defer {
            replay.wal_file = null; // borrowed; the writer keeps exclusive custody
            replay.deinit();
        }
        return if (replay.get(family_name, key)) |value| try allocator.dupe(u8, value) else null;
    }

    fn openImpl(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, wal_path: []const u8, cfg: Config, read_only: bool, private_windows_files: bool, borrowed_wal: ?std.Io.File) !OroStore {
        std.debug.assert(borrowed_wal == null or read_only);
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
            .staged_read_only = read_only,
            .private_windows_files = private_windows_files,
        };
        errdefer store.deinit();
        errdefer {
            if (borrowed_wal != null) store.wal_file = null;
        }

        if (read_only) {
            const file = borrowed_wal orelse try openExistingPersistenceFile(io, dir, wal_path, .read_only);
            store.wal_file = file;
            store.wal_offset = (try file.stat(io)).size;
        } else try store.ensureWal();
        _ = try store.replayFile(store.snapshot_path, .snapshot, 0);
        if (store.wal_offset == 0 and !read_only) try store.initializeEmptyWalAfterSnapshot();
        try store.loadWalEpoch();
        const wal_start = try store.coveredWalReplayStart();
        const wal_good = if (read_only or private_windows_files) try store.replaySource(store.wal_file.?, .wal, wal_start) else try store.replayFile(store.wal_path, .wal, wal_start);
        // A torn/corrupt WAL tail was tolerated by replay (crash mid-append).
        // Truncate it away NOW: appending after the garbage would poison the
        // log — on the NEXT open the bad bytes are no longer the final record,
        // the tail tolerance no longer applies, and the store would refuse to
        // open at all (live impact: the SASL account store silently disabled).
        if (wal_good < store.wal_offset) {
            if (read_only) return StoreError.BadRecord;
            const wal = store.wal_file.?;
            try wal.setLength(store.io, wal_good);
            try wal.sync(store.io);
            store.wal_offset = wal_good;
            try store.syncDir();
        }
        // Replay refuses a WAL larger than max_wal_bytes, so an uncompacted log
        // eventually bricks the store at reboot — compact at open when the WAL
        // has crossed the threshold (also bounds replay time).
        if (!read_only) try store.maybeCompact();
        return store;
    }

    pub fn isReadOnly(self: *const OroStore) bool {
        return self.staged_read_only;
    }

    /// Reserve the existing WAL handle without creating/truncating/writing it.
    /// All fallible work precedes READY; the parent is already quiesced.
    pub fn preparePromotion(self: *OroStore) !void {
        if (!self.staged_read_only or self.staged_write_file != null) return StoreError.ReadOnlyStore;
        const original = self.wal_file orelse return StoreError.BadRecord;
        if (comptime @import("builtin").os.tag == .windows) {
            if (self.transferred_windows_wal) |expected| {
                if (!self.private_windows_files or !std.meta.eql(expected, try windowsWalWitness(self.io, original, self.dir, self.wal_path)) or self.wal_offset != expected.length)
                    return StoreError.SnapshotCoverageMismatch;
                var copy: usize = 0;
                const process = GetCurrentProcess();
                if (DuplicateHandle(process, @intFromPtr(original.handle), process, &copy, 0, 0, windows_duplicate_same_access) == 0 or copy == 0)
                    return error.DuplicateFailed;
                const prepared = std.Io.File{ .handle = @ptrFromInt(copy), .flags = original.flags };
                errdefer prepared.close(self.io);
                if (!std.meta.eql(expected, try windowsWalWitness(self.io, prepared, self.dir, self.wal_path))) return StoreError.SnapshotCoverageMismatch;
                self.staged_write_file = prepared;
                return;
            }
        }
        const file = try openExistingPersistenceFile(self.io, self.dir, self.wal_path, .read_write);
        errdefer file.close(self.io);
        if (comptime cold_posix) if (!std.meta.eql(try cold_identity.statRegular(original.handle), try cold_identity.statRegular(file.handle))) return StoreError.SnapshotCoverageMismatch;
        const before = try original.stat(self.io);
        const after = try file.stat(self.io);
        if (before.inode != after.inode or before.size != after.size or before.size != self.wal_offset) return StoreError.SnapshotCoverageMismatch;
        self.staged_write_file = file;
    }

    /// Close the read-only replay descriptor BEFORE READY, after the writable
    /// existing handle has been validated and prepared. This explicit staging
    /// cut lets hot authority activation use promotePrepared without even a
    /// close syscall. Abort still closes the reserved writer in deinit().
    pub fn releaseReadHandleForPreparedPromotion(self: *OroStore) StoreError!void {
        if (!self.staged_read_only or self.staged_write_file == null or self.wal_file == null) return StoreError.ReadOnlyStore;
        self.wal_file.?.close(self.io);
        self.wal_file = null;
    }

    /// Ownership changes only after authenticated COMMIT. This does no I/O,
    /// allocation, log repair or compaction; normal mutations resume afterward.
    pub fn promotePrepared(self: *OroStore) void {
        std.debug.assert(self.staged_read_only and self.staged_write_file != null);
        if (self.wal_file) |file| file.close(self.io);
        self.wal_file = self.staged_write_file;
        self.staged_write_file = null;
        self.staged_read_only = false;
        self.transferred_windows_wal = null;
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
        self.discardActiveBatch();
        self.reclaimRetirements();
        if (self.wal_file) |file| file.close(self.io);
        if (self.staged_write_file) |file| file.close(self.io);
        for (&self.maps) |*map| map.deinit();
        self.changefeed.deinit();
        self.allocator.free(self.wal_path);
        self.allocator.free(self.snapshot_path);
        if (self.owned_private_directory) self.dir.close(self.io);
        self.* = undefined;
    }

    /// Read a compacted account snapshot through the validated Windows parent
    /// HANDLE. The exclusive open verifies its private DACL before any bytes
    /// are returned to a backup writer.
    pub fn readPrivateSnapshotAllocWindows(self: *OroStore, allocator: std.mem.Allocator, limit: usize) ![]u8 {
        if (comptime @import("builtin").os.tag != .windows) return error.Unsupported;
        if (!self.private_windows_files) return error.Unsupported;
        const file = try cold_runtime.openExistingPrivateWindows(self.dir, self.snapshot_path, .verify_only);
        defer file.close(self.io);
        const stat = try file.stat(self.io);
        if (stat.size > limit) return error.FileTooBig;
        const bytes = try allocator.alloc(u8, @intCast(stat.size));
        errdefer {
            std.crypto.secureZero(u8, bytes);
            allocator.free(bytes);
        }
        if (try file.readPositionalAll(self.io, bytes, 0) != bytes.len) return error.UnexpectedEndOfFile;
        return bytes;
    }

    /// Returns the comptime-typed API for one column family.
    pub fn family(self: *OroStore, comptime store_family: Family) ColumnFamily(store_family) {
        return .{ .store = self };
    }

    /// Install or clear the shared mutation I/O seam. Production code
    /// leaves this at `.{};` tests use it to prove ambiguous short-write,
    /// failed-write, and sync boundaries poison the store.
    pub fn setPreparedIoFault(self: *OroStore, fault: PreparedIoFault) void {
        self.prepared_io_fault = fault;
    }

    /// True after any mutation crossed an ambiguous write/sync boundary.
    /// The store must be reopened before any further mutation is admitted.
    /// Reads retain the prior published rows, which may differ from durable
    /// bytes. Authentication callers must refuse authority while this is true.
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
        return self.prepareMutation(store_family, .put, key, value);
    }

    /// Ordinary deletes share the single-record reservation and publication
    /// boundary with puts; they never introduce the batch WAL format.
    fn prepareMutation(
        self: *OroStore,
        store_family: Family,
        kind: MutationKind,
        key: []const u8,
        value: ?[]const u8,
    ) !PreparedPut {
        std.debug.assert((kind == .put) == (value != null));
        if (self.staged_read_only) return StoreError.ReadOnlyStore;
        if (self.prepared_poisoned) return StoreError.StorePoisoned;
        if (self.active_prepared != null or self.active_batch != null) return StoreError.PreparedMutationActive;
        if (self.next_prepared_generation == std.math.maxInt(u64)) return StoreError.SequenceExhausted;
        const sequence = try self.reserveSequence();

        const payload_len = try checkedPayloadLen(kind, key, value orelse "", self.cfg.max_record_bytes);
        const record_len = std.math.add(usize, record_header_len, payload_len) catch return StoreError.RecordTooLarge;
        const map = &self.maps[familyIndex(store_family)];
        // An absent delete still appends a mutation and advances the feed, but
        // leaves the table (including an exhausted revision) unchanged.
        if (kind == .put or map.map.getEntry(key) != null) try map.map.checkRevision();
        const final_wal_offset = try self.preflightWalForRecord(record_len);
        self.reclaimRetirements();

        const generation = self.next_prepared_generation;
        self.next_prepared_generation += 1;
        self.active_prepared = .{
            .generation = generation,
            .store_family = store_family,
            .kind = kind,
            .key = null,
            .value = null,
            .record = null,
            .change = null,
            .final_wal_offset = final_wal_offset,
            .next_seq_after = try checkedNextSequence(sequence),
            .sequence = sequence,
        };
        errdefer self.discardActivePrepared();

        if (map.map.getEntry(key)) |old| {
            self.active_prepared.?.old_key = @constCast(old.key_ptr.*);
            self.active_prepared.?.old_value = old.value_ptr.*;
        }

        const record = try self.allocator.alloc(u8, record_len);
        self.active_prepared.?.record = record;
        writeU32(record[0..4], @intCast(payload_len));
        const payload = record[record_header_len..];
        encodeMutation(payload, .{ .family = store_family, .kind = kind, .key = key, .value = value });
        writeU32(record[4..][0..4], checksum(payload));

        const owned_key = try self.allocator.dupe(u8, key);
        self.active_prepared.?.key = owned_key;
        if (value) |bytes| self.active_prepared.?.value = try self.allocator.dupe(u8, bytes);

        if (self.changefeed.entries.len != 0) {
            const change = try OwnedMutation.from(self.allocator, .{
                .seq = sequence,
                .family = store_family,
                .kind = kind,
                .key = key,
                .value = value,
            });
            self.active_prepared.?.change = change;
        }
        if (kind == .put or self.active_prepared.?.old_key != null)
            self.active_prepared.?.table_plan = try map.map.prepare(&.{.{ .key = owned_key, .value = self.active_prepared.?.value }}, std.math.maxInt(u64));
        return .{ .store = self, .generation = generation };
    }

    /// Reserve all memory, map slots, sequence numbers and deferred retirement
    /// slots before writing. One checksum covers the entire group. A mandatory
    /// format guard precedes it in the same append, making a committed batch
    /// an interior unknown record for older readers (which must refuse it).
    /// Callers serialize access until commit or abort, as for preparePut.
    pub fn prepareBatch(self: *OroStore, mutations: []const BatchMutation) !PreparedBatch {
        if (self.staged_read_only) return StoreError.ReadOnlyStore;
        if (self.prepared_poisoned) return StoreError.StorePoisoned;
        if (self.active_prepared != null or self.active_batch != null) return StoreError.PreparedMutationActive;
        if (self.next_prepared_generation == std.math.maxInt(u64)) return StoreError.SequenceExhausted;
        const payload_len = try batchPayloadLen(mutations, self.cfg.max_record_bytes);
        const next_seq_after = std.math.add(u64, self.next_seq, @intCast(mutations.len)) catch return StoreError.SequenceExhausted;
        const record_len = std.math.add(usize, batch_guard_len + record_header_len, payload_len) catch return StoreError.RecordTooLarge;
        for (mutations) |mutation| try self.maps[familyIndex(mutation.family)].map.checkRevision();
        const final_wal_offset = try self.preflightWalForRecord(record_len);
        return self.prepareBatchAt(mutations, payload_len, record_len, final_wal_offset, next_seq_after);
    }

    // Allocation-only shared reservation. Cold recovery alone may call this on
    // its detached readonly store after whole-cut authentication by Authority.
    fn prepareBatchAt(self: *OroStore, mutations: []const BatchMutation, payload_len: usize, record_len: usize, final_wal_offset: u64, next_seq_after: u64) !PreparedBatch {
        self.reclaimRetirements();
        const generation = self.next_prepared_generation;
        self.next_prepared_generation += 1;
        self.active_batch = .{ .generation = generation, .final_wal_offset = final_wal_offset, .next_seq_after = next_seq_after };
        errdefer self.discardActiveBatch();

        const record = try self.allocator.alloc(u8, record_len);
        self.active_batch.?.record = record;
        encodeBatchGuard(record[0..batch_guard_len]);
        const outer = record[batch_guard_len..];
        writeU32(outer[0..4], @intCast(payload_len));
        const payload = outer[record_header_len..];
        payload[0] = meta_kind_batch;
        payload[1] = batch_format_version;
        payload[2] = @intCast(mutations.len);
        var offset: usize = 3;
        for (mutations, 0..) |mutation, i| {
            const part_len = try checkedPayloadLen(mutation.kind, mutation.key, mutation.value orelse "", self.cfg.max_record_bytes);
            writeU32(payload[offset..][0..4], @intCast(part_len));
            offset += 4;
            encodeMutation(payload[offset..][0..part_len], mutation);
            offset += part_len;
            self.active_batch.?.entries[i] = .{ .family = mutation.family, .kind = mutation.kind };
            self.active_batch.?.count += 1;
            const entry = &self.active_batch.?.entries[i];
            if (self.maps[familyIndex(mutation.family)].map.getEntry(mutation.key)) |old| {
                entry.old_key = @constCast(old.key_ptr.*);
                entry.old_value = old.value_ptr.*;
            }
            entry.key = try self.allocator.dupe(u8, mutation.key);
            if (mutation.value) |value| entry.value = try self.allocator.dupe(u8, value);
            if (self.changefeed.entries.len != 0) entry.change = try OwnedMutation.from(self.allocator, .{
                .seq = self.next_seq + @as(u64, @intCast(i)),
                .family = mutation.family,
                .kind = mutation.kind,
                .key = mutation.key,
                .value = mutation.value,
            });
        }
        for (0..family_count) |family_index| {
            var edits: [max_batch_mutations]KvTable.Edit = undefined;
            var edit_count: usize = 0;
            for (self.active_batch.?.entries[0..mutations.len]) |entry| if (familyIndex(entry.family) == family_index) {
                edits[edit_count] = .{ .key = entry.key.?, .value = entry.value };
                edit_count += 1;
            };
            if (edit_count != 0) self.active_batch.?.table_plans[family_index] = try self.maps[family_index].map.prepare(edits[0..edit_count], std.math.maxInt(u64));
        }
        writeU32(outer[4..8], checksum(payload));
        return .{ .store = self, .generation = generation };
    }

    fn commitBatch(self: *OroStore, generation: u64) !void {
        const active = self.active_batch orelse return StoreError.PreparedAlreadyConsumed;
        if (active.generation != generation) return StoreError.PreparedAlreadyConsumed;
        if (self.prepared_poisoned) return StoreError.StorePoisoned;
        try self.validateBatchTables();
        try self.writePreparedBytes(active.record.?, active.final_wal_offset);
        self.publishBatch(generation);
    }

    fn publishBatch(self: *OroStore, generation: u64) void {
        const active = self.active_batch.?;
        std.debug.assert(active.generation == generation);
        // Prepared exact slots; no lookup, allocation, free or failure after sync.
        for (&self.active_batch.?.table_plans) |*plan| if (plan.*) |*value| {
            if (value.publish()) |slots| self.retireTable(slots);
        };
        for (self.active_batch.?.entries[0..active.count]) |*entry| {
            switch (entry.kind) {
                .put => {
                    if (entry.old_key != null) self.retireBytes(entry.key.?);
                    if (entry.old_value) |value| self.retireBytes(value);
                    entry.value = null;
                },
                .delete => {
                    if (entry.old_key) |key| self.retireBytes(key);
                    if (entry.old_value) |value| self.retireBytes(value);
                    self.retireBytes(entry.key.?);
                },
            }
            entry.key = null;
            if (entry.change) |change| {
                if (self.changefeed.publishPrepared(change)) |evicted| self.retireMutation(evicted);
                entry.change = null;
            }
        }
        self.retireBytes(active.record.?);
        self.wal_offset = active.final_wal_offset;
        self.next_seq = active.next_seq_after;
        self.batch_format_required = true;
        self.active_batch = null;
    }

    fn validateBatchTables(self: *OroStore) !void {
        const active = if (self.active_batch) |*value| value else return StoreError.PreparedAlreadyConsumed;
        // Publication selectors must describe the COMPLETE prepared ownership
        // set, not merely a subset whose individual rows happen to match.
        if (active.count == 0 or active.count > max_batch_mutations) return StoreError.InvalidTablePlan;
        var edit_count: usize = 0;
        var seen: [family_count]u8 = @splat(0);
        for (&active.table_plans, 0..) |*plan, i| if (plan.*) |*value| {
            if (value.owner != &self.maps[i].map or value.edit_count == 0 or value.edit_count > max_batch_mutations) return StoreError.InvalidTablePlan;
            try value.validate();
            edit_count += value.edit_count;
        };
        if (edit_count != active.count) return StoreError.InvalidTablePlan;
        for (active.entries[0..active.count]) |entry| {
            const index = familyIndex(entry.family);
            const plan = &(active.table_plans[index] orelse return StoreError.InvalidTablePlan);
            if (entry.key == null or (entry.kind == .put) != (entry.value != null)) return StoreError.InvalidTablePlan;
            const matched = plan.editIndex(entry.key.?, entry.value) orelse return StoreError.InvalidTablePlan;
            const bit = @as(u8, 1) << @as(u3, @intCast(matched));
            if (seen[index] & bit != 0) return StoreError.InvalidTablePlan;
            seen[index] |= bit;
            if (self.maps[index].map.getEntry(entry.key.?)) |old| {
                if (entry.old_key == null or entry.old_value == null or entry.old_key.?.ptr != old.key_ptr.*.ptr or entry.old_key.?.len != old.key_ptr.*.len or entry.old_value.?.ptr != old.value_ptr.*.ptr or entry.old_value.?.len != old.value_ptr.*.len) return StoreError.InvalidTablePlan;
            } else if (entry.old_key != null or entry.old_value != null) return StoreError.InvalidTablePlan;
        }
        for (active.table_plans, 0..) |plan, i| if (plan) |value| {
            const complete = (@as(u16, 1) << @as(u4, @intCast(value.edit_count))) - 1;
            if (seen[i] != complete) return StoreError.InvalidTablePlan;
        };
    }

    fn discardActiveBatch(self: *OroStore) void {
        if (self.active_batch) |*active| {
            for (&active.table_plans) |*plan| if (plan.*) |*value| value.abort();
            for (active.entries[0..active.count]) |*entry| {
                if (entry.key) |key| self.allocator.free(key);
                if (entry.value) |value| self.allocator.free(value);
                if (entry.change) |*change| change.deinit(self.allocator);
            }
            if (active.record) |record| self.allocator.free(record);
            self.active_batch = null;
        }
    }

    fn writePreparedBytes(self: *OroStore, record: []const u8, final_offset: u64) !void {
        const file = self.wal_file orelse {
            self.poisonPreparedStore();
            return StoreError.IoAmbiguous;
        };
        const offset = final_offset - record.len;
        switch (self.prepared_io_fault.write) {
            .failed => {
                self.poisonPreparedStore();
                return StoreError.IoAmbiguous;
            },
            .short => {
                file.writePositionalAll(self.io, record[0..@max(@as(usize, 1), record.len / 2)], offset) catch {};
                self.poisonPreparedStore();
                return StoreError.IoAmbiguous;
            },
            .none => {},
        }
        file.writePositionalAll(self.io, record, offset) catch {
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
    }

    pub fn put(self: *OroStore, store_family: Family, key: []const u8, value: []const u8) !void {
        var prepared = try self.preparePut(store_family, key, value);
        defer prepared.deinit();
        try prepared.commit();
    }

    pub fn get(self: *const OroStore, store_family: Family, key: []const u8) ?[]const u8 {
        return self.maps[familyIndex(store_family)].get(key);
    }

    pub fn delete(self: *OroStore, store_family: Family, key: []const u8) !void {
        var prepared = try self.prepareMutation(store_family, .delete, key, null);
        defer prepared.deinit();
        try prepared.commit();
    }

    /// Writes current state to a snapshot and truncates the WAL.
    fn validateLiveWal(self: *const OroStore, identity: cold_identity.Identity, size: u64, digest: [32]u8) !void {
        const file = self.wal_file orelse return StoreError.SnapshotCoverageMismatch;
        if (!std.meta.eql(identity, try cold_identity.statRegular(file.handle)) or (try file.stat(self.io)).size != size or self.wal_offset != size) return StoreError.SnapshotCoverageMismatch;
        try self.validateConfiguredWal();
        var actual: [32]u8 = undefined;
        try self.hashWalPrefix(size, &actual);
        if (!std.mem.eql(u8, &digest, &actual)) return StoreError.SnapshotCoverageMismatch;
    }

    /// Native live compaction changes layout only. Prepare every complete file,
    /// buffer and writer reservation before publication; the stable application
    /// lease and graph serialization remain the caller's ownership obligation.
    fn snapshotAndReplaceEpoch(self: *OroStore) !void {
        if (self.staged_read_only) return StoreError.ReadOnlyStore;
        if (self.prepared_poisoned) return StoreError.StorePoisoned;
        if (self.active_prepared != null or self.active_batch != null) return StoreError.PreparedMutationActive;
        try self.ensureWal();
        const old = self.wal_file.?;
        const old_identity = try cold_identity.statRegular(old.handle);
        const old_size = self.wal_offset;
        var old_digest: [32]u8 = undefined;
        try self.hashWalPrefix(old_size, &old_digest);
        try self.validateLiveWal(old_identity, old_size, old_digest);
        const directory = try self.openSyncParent();
        defer directory.close(self.io);
        const directory_identity = try coldDirectoryIdentity(directory.handle);
        try validateColdParent(self.io, self.dir, self.snapshot_path, directory, directory_identity, null);
        var previous_snapshot: ?ColdFile = ColdFile.capture(self.allocator, self.io, self.dir, self.snapshot_path, null) catch |err| switch (err) {
            error.FileNotFound => null,
            else => return err,
        };
        defer if (previous_snapshot) |*file| file.deinit(self.allocator, self.io);
        var next_epoch: [wal_epoch_len]u8 = undefined;
        self.io.random(&next_epoch);
        const epoch_bytes = coldEpoch(next_epoch);
        const coverage: SnapshotCoverage = .{ .count = 2, .slots = .{
            .{ .covered_len = old_size, .epoch = self.wal_epoch, .digest = old_digest },
            .{ .covered_len = epoch_bytes.len, .epoch = next_epoch, .digest = coldDigest(&epoch_bytes) },
        } };
        const snapshot_bytes = try encodeColdSnapshot(self, &coverage);
        defer self.allocator.free(snapshot_bytes);
        var snapshot = try self.dir.createFileAtomic(self.io, self.snapshot_path, .{ .replace = true });
        defer deinitColdAtomic(self.io, &snapshot, null);
        try makeColdAtomicReadable(self.io, &snapshot);
        const snapshot_identity = try cold_identity.statRegular(snapshot.file.handle);
        try validateColdParent(self.io, self.dir, self.snapshot_path, directory, directory_identity, &snapshot);
        try snapshot.file.writePositionalAll(self.io, snapshot_bytes, 0);
        if (self.prepared_io_fault.snapshot_sync) return StoreError.SnapshotSyncFailed;
        try snapshot.file.sync(self.io);
        var epoch = try self.dir.createFileAtomic(self.io, self.wal_path, .{ .replace = true });
        defer deinitColdAtomic(self.io, &epoch, null);
        try makeColdAtomicReadable(self.io, &epoch);
        const epoch_identity = try cold_identity.statRegular(epoch.file.handle);
        try validateColdParent(self.io, self.dir, self.wal_path, directory, directory_identity, &epoch);
        try epoch.file.writePositionalAll(self.io, &epoch_bytes, 0);
        try epoch.file.sync(self.io);
        const writer: std.Io.File = .{ .handle = try cold_runtime.duplicate(epoch.file.handle), .flags = epoch.file.flags };
        var writer_owned = true;
        defer if (writer_owned) writer.close(self.io);
        try cold_runtime.setCloexec(writer.handle, true);
        // C0: exact original transcript, namespaces and complete private bytes.
        try self.validateLiveWal(old_identity, old_size, old_digest);
        if (previous_snapshot) |file| try file.validate(self.io, self.dir, self.snapshot_path) else {
            if (openColdExisting(self.io, self.dir, self.snapshot_path, .read_only)) |file| {
                file.close(self.io);
                return StoreError.SnapshotCoverageMismatch;
            } else |err| if (err != error.FileNotFound) return err;
        }
        try validateColdParent(self.io, self.dir, self.snapshot_path, directory, directory_identity, &snapshot);
        try validateColdParent(self.io, self.dir, self.wal_path, directory, directory_identity, &epoch);
        try validateColdPreparedFile(self.io, snapshot.file, snapshot_bytes, snapshot_identity);
        try validateColdPreparedFile(self.io, writer, &epoch_bytes, epoch_identity);
        try validateColdAtomicName(self.io, &snapshot, snapshot_identity);
        try validateColdAtomicName(self.io, &epoch, epoch_identity);
        // Every subsequent failure can follow an authoritative namespace change.
        errdefer self.poisonPreparedStore();
        snapshot.replace(self.io) catch return StoreError.IoAmbiguous;
        if (self.prepared_io_fault.compaction_boundary == .after_snapshot_replace) return StoreError.IoAmbiguous;
        self.syncHeldParent(directory, directory_identity) catch return StoreError.IoAmbiguous;
        if (self.prepared_io_fault.compaction_boundary == .after_snapshot_dir_sync) return StoreError.IoAmbiguous;
        self.validateLiveWal(old_identity, old_size, old_digest) catch return StoreError.IoAmbiguous;
        const installed = openColdExisting(self.io, self.dir, self.snapshot_path, .read_only) catch return StoreError.IoAmbiguous;
        defer installed.close(self.io);
        validateColdPreparedFile(self.io, installed, snapshot_bytes, snapshot_identity) catch return StoreError.IoAmbiguous;
        validateColdParent(self.io, self.dir, self.wal_path, directory, directory_identity, &epoch) catch return StoreError.IoAmbiguous;
        validateColdPreparedFile(self.io, writer, &epoch_bytes, epoch_identity) catch return StoreError.IoAmbiguous;
        validateColdAtomicName(self.io, &epoch, epoch_identity) catch return StoreError.IoAmbiguous;
        // Preserve the historical fault API: these faults stop before the WAL
        // publication boundary, which now replaces a complete inode.
        if (self.prepared_io_fault.wal_sync or self.prepared_io_fault.wal_truncate != .none) return StoreError.IoAmbiguous;
        epoch.replace(self.io) catch return StoreError.IoAmbiguous;
        if (self.prepared_io_fault.compaction_boundary == .after_wal_replace) return StoreError.IoAmbiguous;
        self.syncHeldParent(directory, directory_identity) catch return StoreError.IoAmbiguous;
        if (self.prepared_io_fault.compaction_boundary == .after_wal_dir_sync) return StoreError.IoAmbiguous;
        const configured = openColdExisting(self.io, self.dir, self.wal_path, .read_only) catch return StoreError.IoAmbiguous;
        defer configured.close(self.io);
        validateColdPreparedFile(self.io, configured, &epoch_bytes, epoch_identity) catch return StoreError.IoAmbiguous;
        // C4: no-fail ownership transfer. No allocation or pathname reservation
        // follows this cut. Other readers may still hold the old complete inode.
        self.wal_file = writer;
        writer_owned = false;
        self.wal_epoch = next_epoch;
        self.wal_epoch_known = true;
        self.wal_offset = cold_epoch_record_len;
        self.snapshot_coverage = coverage;
        old.close(self.io);
    }

    pub fn snapshotAndTruncate(self: *OroStore) !void {
        if (comptime cold_posix) return self.snapshotAndReplaceEpoch();
        if (self.staged_read_only) return StoreError.ReadOnlyStore;
        if (self.prepared_poisoned) return StoreError.StorePoisoned;
        if (self.active_prepared != null or self.active_batch != null) return StoreError.PreparedMutationActive;
        try self.ensureWal();
        const directory = try self.openSyncParent();
        defer directory.close(self.io);
        const private_windows = @import("builtin").os.tag == .windows and self.private_windows_files;
        const directory_identity: ?cold_identity.Identity = if (cold_posix or private_windows) try coldDirectoryIdentity(directory.handle) else null;
        if (comptime cold_posix) try self.validateConfiguredWal();
        if (private_windows) {
            _ = try cold_runtime.requirePrivateDirectoryHandleWindows(.{ .handle = directory.handle });
            try requireColdWriteThroughVolumeWindows(directory);
        }
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
        var snapshot = if (private_windows)
            try (std.Io.Dir{ .handle = directory.handle }).createFileAtomic(self.io, std.fs.path.basename(self.snapshot_path), .{ .replace = true })
        else
            try self.dir.createFileAtomic(self.io, self.snapshot_path, .{ .replace = true });
        var snapshot_identity: ?cold_identity.Identity = null;
        defer if (cold_posix or private_windows) deinitColdAtomic(self.io, &snapshot, snapshot_identity) else snapshot.deinit(self.io);
        snapshot_identity = if (private_windows)
            try windowsColdAtomicIdentity(snapshot.file.handle)
        else if (cold_posix)
            try cold_identity.statRegular(snapshot.file.handle)
        else
            null;
        if (cold_posix or private_windows) try validateColdParent(self.io, self.dir, self.snapshot_path, directory, directory_identity.?, &snapshot);
        if (comptime @import("builtin").os.tag == .windows) {
            if (self.private_windows_files) try self.secureColdAtomicWindows(&snapshot);
        }

        var offset: u64 = 0;
        offset = try writeNextSeqRecordAt(self.io, snapshot.file, offset, self.allocator, self.next_seq);
        if (self.batch_format_required) {
            var guard: [batch_guard_len]u8 = undefined;
            encodeBatchGuard(&guard);
            try snapshot.file.writePositionalAll(self.io, &guard, offset);
            offset += guard.len;
        }
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
        if (cold_posix or private_windows) {
            try validateColdParent(self.io, self.dir, self.snapshot_path, directory, directory_identity.?, &snapshot);
            if (comptime cold_posix) try validateColdAtomicName(self.io, &snapshot, snapshot_identity.?);
        }
        if (private_windows) {
            renameHeldColdAtomicWindows(self.io, &snapshot, self.dir, self.snapshot_path, directory, directory_identity.?, snapshot_identity.?, true) catch {
                self.poisonPreparedStore();
                return StoreError.IoAmbiguous;
            };
        } else try snapshot.replace(self.io);
        self.syncHeldParent(directory, directory_identity) catch {
            // The snapshot path may already be replaced while its directory
            // entry is not known durable; the old WAL must not be appended to
            // until a reopen resolves that boundary.
            self.poisonPreparedStore();
            return StoreError.IoAmbiguous;
        };

        if (comptime cold_posix) self.validateConfiguredWal() catch {
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
        self.syncHeldParent(directory, directory_identity) catch {
            // WAL bytes were truncated and the in-memory offset moved, but
            // directory durability is uncertain. Reopen before appending.
            self.poisonPreparedStore();
            return StoreError.IoAmbiguous;
        };
    }

    fn secureColdAtomicWindows(self: *OroStore, snapshot: *std.Io.File.Atomic) !void {
        if (comptime @import("builtin").os.tag != .windows) return error.Unsupported;
        if (!snapshot.file_exists or !snapshot.file_open) return error.Unsupported;
        const original = try windowsColdAtomicIdentity(snapshot.file.handle);
        // Verify the newly created temp has either the exact inherited private
        // ACL or Zig's exact protected private ACL. No secret bytes exist yet;
        // close the generic handle and reacquire exclusively to protect its
        // DACL, then reopen with write-through and DELETE access for the held
        // rename. Compare full file identities across both reopen boundaries.
        try cold_runtime.requireInheritedPrivateFileWindows(snapshot.file);
        snapshot.file.close(self.io);
        snapshot.file_open = false;
        const name = std.fmt.hex(snapshot.file_basename_hex);
        {
            const remediated = try cold_runtime.openExistingPrivateWindows(snapshot.dir, &name, .remediate_read_write);
            defer remediated.close(self.io);
            if (!std.meta.eql(original, try windowsColdAtomicIdentity(remediated.handle))) return StoreError.SnapshotCoverageMismatch;
        }
        const through = try openColdAtomicWindows(self.io, snapshot);
        errdefer through.close(self.io);
        if (!std.meta.eql(original, try windowsColdAtomicIdentity(through.handle))) return StoreError.SnapshotCoverageMismatch;
        try cold_runtime.requireExistingPrivateFileHandleWindows(through);
        snapshot.file = through;
        snapshot.file_open = true;
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
        if (self.staged_read_only) return StoreError.ReadOnlyStore;
        if (self.wal_file) |_| return;
        const file = if (comptime @import("builtin").os.tag == .windows) blk: {
            if (self.private_windows_files) {
                break :blk cold_runtime.openExistingPrivateWindows(self.dir, self.wal_path, .remediate_read_write) catch |err| switch (err) {
                    error.FileNotFound => try cold_runtime.createPrivateExclusiveWindows(self.dir, self.wal_path),
                    else => return err,
                };
            }
            break :blk try self.dir.createFile(self.io, self.wal_path, .{ .read = true, .truncate = false });
        } else try self.dir.createFile(self.io, self.wal_path, .{ .read = true, .truncate = false });
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
        try self.loadWalEpochFrom(file);
    }

    fn loadWalEpochFrom(self: *OroStore, file: anytype) !void {
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

    fn hashWalPrefix(self: *const OroStore, length: u64, out: *[std.crypto.hash.Blake3.digest_length]u8) !void {
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

        const table = &self.maps[familyIndex(active.store_family)].map;
        if (active.key == null or (active.kind == .put) != (active.value != null)) return StoreError.InvalidTablePlan;
        if (self.active_prepared.?.table_plan) |*plan| {
            if (plan.owner != table or !plan.matchesEdit(active.key.?, active.value)) return StoreError.InvalidTablePlan;
            try plan.validate();
        } else if (active.kind != .delete or active.old_key != null) return StoreError.InvalidTablePlan;
        if (table.getEntry(active.key.?)) |old| {
            if (active.old_key == null or active.old_value == null or active.old_key.?.ptr != old.key_ptr.*.ptr or active.old_key.?.len != old.key_ptr.*.len or active.old_value.?.ptr != old.value_ptr.*.ptr or active.old_value.?.len != old.value_ptr.*.len) return StoreError.InvalidTablePlan;
        } else if (active.old_key != null or active.old_value != null) return StoreError.InvalidTablePlan;
        try self.writePreparedBytes(active.record.?, active.final_wal_offset);

        // Durable publication is deliberately scalar/pointer-only. All
        // retirement slots were made available before admission, and no
        // allocator or fallible call is permitted below this line.
        var prepared = active;
        if (self.active_prepared.?.table_plan) |*plan| if (plan.publish()) |slots| self.retireTable(slots);
        if (prepared.kind == .delete) {
            if (prepared.old_key) |key| self.retireBytes(key);
            self.retireBytes(prepared.key.?);
        } else if (prepared.old_key != null) self.retireBytes(prepared.key.?);
        if (prepared.old_value) |value| self.retireBytes(value);
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
            if (active.table_plan) |*plan| plan.abort();
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

    fn retireTable(self: *OroStore, slots: []KvTable.Slot) void {
        std.debug.assert(self.retirement_count < self.retirements.len);
        self.retirements[self.retirement_count] = .{ .table_slots = slots };
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
                .table_slots => |slots| self.allocator.free(slots),
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
        self.discardActiveBatch();
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
        const opened = if (comptime @import("builtin").os.tag == .windows) blk: {
            if (self.private_windows_files) break :blk cold_runtime.openExistingPrivateWindows(self.dir, path, if (self.staged_read_only) .verify_only else .remediate);
            break :blk openExistingPersistenceFile(self.io, self.dir, path, .read_only);
        } else openExistingPersistenceFile(self.io, self.dir, path, .read_only);
        var file = opened catch |err| switch (err) {
            error.FileNotFound => return 0,
            else => return err,
        };
        defer file.close(self.io);
        return self.replaySource(file, replay_kind, start_offset);
    }

    fn replaySource(self: *OroStore, file: anytype, replay_kind: ReplayKind, start_offset: u64) !u64 {
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
            if (payload[0] == meta_kind_batch_format) {
                if (payload.len != 2 or payload[1] != batch_format_version) return StoreError.BadRecord;
                self.batch_format_required = true;
                offset = record_end;
                continue;
            }
            if (payload[0] == meta_kind_batch) {
                if (replay_kind != .wal or !self.batch_format_required) return StoreError.BadRecord;
                var decoded: [max_batch_mutations]BatchMutation = undefined;
                const count = try decodeBatch(payload, &decoded);
                const next = std.math.add(u64, self.next_seq, @intCast(count)) catch return StoreError.SequenceExhausted;
                // Validate every component before applying any component. An
                // allocation failure during replay aborts open entirely.
                for (decoded[0..count]) |mutation| switch (mutation.kind) {
                    .put => try self.applyPut(mutation.family, mutation.key, mutation.value.?),
                    .delete => try self.applyDelete(mutation.family, mutation.key),
                };
                self.next_seq = next;
                offset = record_end;
                continue;
            }
            self.applyPayload(payload) catch |err| switch (err) {
                StoreError.BadRecord,
                StoreError.UnknownFamily,
                StoreError.UnknownRecordKind,
                // Guarded stores require checksum-valid records to decode
                // strictly, including an unknown outer kind at EOF. Physical
                // truncation and checksum failures remain recoverable above.
                => if (!self.batch_format_required and replay_kind == .wal and record_end == stat.size) return record_offset else return err,
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

    fn applyPayload(self: *OroStore, payload: []const u8) !void {
        if (payload.len == 0) return StoreError.BadRecord;

        if (payload[0] == meta_kind_next_seq) {
            if (payload.len != meta_next_seq_payload_len) return StoreError.BadRecord;
            self.next_seq = readU64(payload[1..9]);
            return;
        }

        if (payload.len < payload_header_len) return StoreError.BadRecord;

        const kind: MutationKind = switch (payload[0]) {
            @backingInt(MutationKind.put) => .put,
            @backingInt(MutationKind.delete) => .delete,
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

    fn reserveSequence(self: *const OroStore) !u64 {
        if (self.next_seq == std.math.maxInt(u64)) return StoreError.SequenceExhausted;
        return self.next_seq;
    }

    fn checkedNextSequence(sequence: u64) !u64 {
        if (sequence == std.math.maxInt(u64)) return StoreError.SequenceExhausted;
        return sequence + 1;
    }

    fn openSyncParent(self: *const OroStore) !std.Io.File {
        if (comptime cold_posix or @import("builtin").os.tag == .windows) {
            if (cold_posix or self.private_windows_files) return coldOpenParent(self.io, self.dir, self.wal_path);
        }
        return self.dir.openFile(self.io, std.fs.path.dirname(self.wal_path) orelse ".", .{ .mode = .read_only, .allow_directory = true });
    }

    fn validateConfiguredWal(self: *const OroStore) !void {
        const held = self.wal_file orelse return StoreError.SnapshotCoverageMismatch;
        const configured = try openExistingPersistenceFile(self.io, self.dir, self.wal_path, .read_only);
        defer configured.close(self.io);
        if (!std.meta.eql(try cold_identity.statRegular(held.handle), try cold_identity.statRegular(configured.handle))) return StoreError.SnapshotCoverageMismatch;
    }

    fn syncHeldParent(self: *OroStore, directory: std.Io.File, identity: ?cold_identity.Identity) !void {
        if (comptime cold_posix) try validateColdParent(self.io, self.dir, self.wal_path, directory, identity.?, null);
        try syncDirectory(self.io, directory);
    }

    fn syncDir(self: *OroStore) !void {
        const directory = try self.openSyncParent();
        defer directory.close(self.io);
        if (comptime cold_posix) {
            try self.validateConfiguredWal();
            try self.syncHeldParent(directory, try coldDirectoryIdentity(directory.handle));
        } else try syncDirectory(self.io, directory);
    }
};

pub fn encodeColdSnapshot(store: *const OroStore, coverage: *const SnapshotCoverage) ![]u8 {
    var size: usize = record_header_len + meta_next_seq_payload_len + record_header_len + snapshot_coverage_payload_len;
    if (store.batch_format_required) size = std.math.add(usize, size, batch_guard_len) catch return StoreError.RecordTooLarge;
    for (families) |family| {
        var it = store.maps[familyIndex(family)].map.iterator();
        while (it.next()) |entry| size = std.math.add(usize, size, try recordSize(.put, entry.key_ptr.*, entry.value_ptr.*, store.cfg.max_record_bytes)) catch return StoreError.RecordTooLarge;
    }
    const out = try store.allocator.alloc(u8, size);
    errdefer store.allocator.free(out);
    var pos: usize = 0;
    const seq = out[0 .. record_header_len + meta_next_seq_payload_len];
    writeU32(seq[0..4], meta_next_seq_payload_len);
    seq[record_header_len] = meta_kind_next_seq;
    writeU64(seq[record_header_len + 1 ..][0..8], store.next_seq);
    writeU32(seq[4..8], checksum(seq[record_header_len..]));
    pos += seq.len;
    if (store.batch_format_required) {
        encodeBatchGuard(out[pos..][0..batch_guard_len]);
        pos += batch_guard_len;
    }
    for (families) |family| {
        var it = store.maps[familyIndex(family)].map.iterator();
        while (it.next()) |entry| {
            const length = try recordSize(.put, entry.key_ptr.*, entry.value_ptr.*, store.cfg.max_record_bytes);
            const record = out[pos..][0..length];
            writeU32(record[0..4], @intCast(length - record_header_len));
            encodeMutation(record[record_header_len..], .{ .family = family, .kind = .put, .key = entry.key_ptr.*, .value = entry.value_ptr.* });
            writeU32(record[4..8], checksum(record[record_header_len..]));
            pos += length;
        }
    }
    const record = out[pos..];
    writeU32(record[0..4], snapshot_coverage_payload_len);
    const payload = record[record_header_len..];
    @memset(payload, 0);
    payload[0] = meta_kind_snapshot_coverage;
    payload[1] = snapshot_coverage_version;
    payload[2] = @intCast(coverage.count);
    for (coverage.slots[0..coverage.count], 0..) |slot, i| {
        const start = 3 + i * snapshot_coverage_slot_len;
        writeU64(payload[start..][0..8], slot.covered_len);
        @memcpy(payload[start + 8 ..][0..wal_epoch_len], &slot.epoch);
        @memcpy(payload[start + 8 + wal_epoch_len ..][0..32], &slot.digest);
    }
    writeU32(record[4..8], checksum(payload));
    return out;
}

/// Internal transaction/replay access for checkpoint, custody and regression
/// modules. These operations are intentionally absent from the public facade
/// and do not add methods to the public OroStore API.
pub const Internal = struct {
    pub const discardActiveBatch = OroStore.discardActiveBatch;
    pub const ensureWal = OroStore.ensureWal;
    pub const loadWalEpochFrom = OroStore.loadWalEpochFrom;
    pub const poisonPreparedStore = OroStore.poisonPreparedStore;
    pub const prepareBatchAt = OroStore.prepareBatchAt;
    pub const prepareMutation = OroStore.prepareMutation;
    pub const publishBatch = OroStore.publishBatch;
    pub const replayFile = OroStore.replayFile;
    pub const replaySource = OroStore.replaySource;
    pub const retireBytes = OroStore.retireBytes;
    pub const retireMutation = OroStore.retireMutation;
    pub const retireTable = OroStore.retireTable;
    pub const secureColdAtomicWindows = OroStore.secureColdAtomicWindows;
    pub const validateBatchTables = OroStore.validateBatchTables;
};
